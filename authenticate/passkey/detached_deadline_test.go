package passkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/eventsink"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
)

// seen is what a double saw of the context one call was made with.
type seen struct {
	called   bool
	deadline time.Time
	has      bool
	err      error
}

// probes records, by name, the context each double was called with.
type probes struct {
	mu   sync.Mutex
	byID map[string]seen
}

func (p *probes) see(ctx context.Context, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.byID == nil {
		p.byID = map[string]seen{}
	}

	dl, ok := ctx.Deadline()
	p.byID[name] = seen{called: true, deadline: dl, has: ok, err: ctx.Err()}
}

func (p *probes) get(name string) seen {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.byID[name]
}

// outcome is what a case's call left behind, beyond the probes.
type outcome struct {
	err    error
	logs   *logBuffer
	events []event.Event
}

// TestPasskeys_DetachedCallsCarryDeadline pins the bound on every call this
// package makes under a context the caller cannot cancel. A write carries
// detach.WriteTimeout and a revocation detach.RevocationTimeout, each call its
// own. The sender is class 1 and the limiter's RecordFailure class 5: the
// callee owns its bound, so the library puts none on them. The caller's
// context never has a deadline, so one a double sees is the library's own.
// A call that exceeds its bound keeps the outcome a store error has always
// had at that site.
func TestPasskeys_DetachedCallsCarryDeadline(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, ctx context.Context, p *probes) outcome
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, p *probes, out outcome)
	}

	// within asserts the named call carried a live deadline no later than
	// bound from now. A revocation bound is also longer than a write bound, so
	// a revocation given the write bound is caught.
	within := func(t *testing.T, p *probes, name string, bound time.Duration) {
		s := p.get(name)
		require.True(t, s.called, "%s was not called", name)
		require.True(t, s.has, "%s carries no deadline", name)
		require.NoError(t, s.err)

		remaining := time.Until(s.deadline)
		assert.Positive(t, remaining, "%s", name)
		assert.LessOrEqual(t, remaining, bound, "%s", name)

		if bound == detach.RevocationTimeout {
			assert.Greater(t, remaining, detach.WriteTimeout, "%s", name)
		}
	}
	unbounded := func(t *testing.T, p *probes, name string) {
		s := p.get(name)
		require.True(t, s.called, "%s was not called", name)
		assert.False(t, s.has, "%s: the library must not put a deadline on it", name)
		assert.NoError(t, s.err)
	}

	// removeRun removes a passkey; the second revocation pass answers secondErr.
	removeRun := func(secondErr error) func(*testing.T, context.Context, *probes) outcome {
		return func(t *testing.T, ctx context.Context, p *probes) outcome {
			e := newManageEnv(t) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()
			r := e.mockRevoker()
			first := r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").Return(1, nil)
			r.EXPECT().DeleteByUserExcept(gomock.Any(), identity.UserID("u-1"), "sess-1").
				DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) (int, error) {
					p.see(ctx, "second-pass")

					return 0, secondErr
				}).After(first.Call)

			m := e.manager(t)
			err := m.Remove(ctx, fullSession("sess-1", "u-1"), e.cred.ID, passkey.RegistrationContext{})

			return outcome{err: err, logs: e.logs}
		}
	}

	type cloneFaults struct{ find, suspend, deleteByUser, grants error }

	// cloneRun makes a counter-refused assertion that suspends the credential,
	// the doubles answering as faults say.
	cloneRun := func(faults cloneFaults) func(*testing.T, context.Context, *probes) outcome {
		return func(t *testing.T, ctx context.Context, p *probes) outcome {
			var (
				mu     sync.Mutex
				events []event.Event
			)

			ctx = eventsink.With(ctx, func(_ context.Context, ev event.Event) {
				mu.Lock()
				defer mu.Unlock()

				events = append(events, ev)
			})

			e := newLoginEnv(t, nil) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()
			e.f.deps.Credentials = &findProbe{spyCredentials: e.creds, p: p, err: faults.find}
			e.creds.suspendHook = func(ctx context.Context, _ id.ID) (bool, error) {
				p.see(ctx, "suspend")

				return faults.suspend == nil, faults.suspend
			}

			r := e.f.mockRevoker()
			r.EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).AnyTimes().
				DoAndReturn(func(ctx context.Context, _ identity.UserID) error {
					p.see(ctx, "delete-by-user")

					return faults.deleteByUser
				})

			g := NewMockGrantRevoker(gomock.NewController(t))
			g.EXPECT().RevokeUserGrants(gomock.Any(), identity.UserID("u-1"), "passkey_clone").AnyTimes().
				DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) error {
					p.see(ctx, "revoke-grants")

					return faults.grants
				})

			e.manager(t, passkey.WithGrantRevoker(g))

			challenge := e.begin(t) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()
			_, err := e.m.Authenticate(ctx, assertion(challenge, func(b *assertionBody) { b.Count = 41 }), e.binding)

			mu.Lock()
			defer mu.Unlock()

			return outcome{err: err, logs: e.logs, events: events}
		}
	}

	type notifyFaults struct{ load, resolve error }

	// notifyRun queues the removal notice, the loader and resolver answering as
	// faults say.
	notifyRun := func(faults notifyFaults) func(*testing.T, context.Context, *probes) outcome {
		return func(t *testing.T, ctx context.Context, p *probes) outcome {
			f := newFixture(t)
			logs := &logBuffer{}

			users := NewMockUserLoader(f.ctrl)
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).AnyTimes().
				DoAndReturn(func(ctx context.Context, u identity.UserID) (*identity.Details, error) {
					p.see(ctx, "load-user")
					// Later than the resolver's own bound could start at, were the two
					// to share one, so the two deadlines tell them apart.
					time.Sleep(2 * time.Millisecond)

					if faults.load != nil {
						return nil, faults.load
					}

					return &identity.Details{ID: u, Username: "ana@example.com", Active: true}, nil
				})
			f.deps.Users = users

			sender := NewMockSender(f.ctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(ctx context.Context, _ notify.Message) error {
					p.see(ctx, "send")

					return nil
				})
			f.deps.Sender = nonBlocking{sender}

			m := f.manager(t, passkey.WithLogger(logs.logger()),
				passkey.WithContactResolver(func(ctx context.Context, d *identity.Details) (string, error) {
					p.see(ctx, "resolve-contact")

					if faults.resolve != nil {
						return "", faults.resolve
					}

					return d.Username, nil
				}))

			m.NotifyRemoved(ctx, &passkey.Credential{ID: id.ID{}, User: "u-1", Name: "Security key"}, false)

			return outcome{logs: logs}
		}
	}

	// confirmRun refuses an emailed code, the confirmation limiter's
	// RecordFailure answering recordErr.
	confirmRun := func(recordErr error) func(*testing.T, context.Context, *probes) outcome {
		return func(t *testing.T, ctx context.Context, p *probes) outcome {
			l := NewMockLimiter(gomock.NewController(t))
			l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
			l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ string) error {
					p.see(ctx, "record-failure")

					return recordErr
				})

			f := newFixture(t)
			logs := &logBuffer{}
			m := f.manager(t, passkey.WithLogger(logs.logger()))
			s := enrolmentSession("sess-a", "u-1")
			rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: l}

			challenge := f.begin(t, m, s)                                                        //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()
			_, err := m.FinishRegistration(t.Context(), s, regBody(challenge, "cred-a", ""), rc) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()
			require.NoError(t, err)

			_, err = m.ConfirmEmailCode(ctx, s, wrongCode(emailedCode(t, f)), rc)

			return outcome{err: err, logs: logs}
		}
	}

	timedOut := context.DeadlineExceeded

	cases := []testCase{
		{
			name: "removal's second revocation pass carries the revocation deadline",
			run:  removeRun(nil),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.NoError(t, out.err)
				within(t, p, "second-pass", detach.RevocationTimeout)
			},
		},
		{
			name: "removal's second pass out of time is logged and the removal stands",
			run:  removeRun(timedOut),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.NoError(t, out.err)
				require.True(t, p.get("second-pass").called)
				assert.Equal(t, 1, countRecords(out.logs, "passkey: the user's sessions could not all be ended"))
				assert.Contains(t, out.logs.String(), `"level":"ERROR"`)
			},
		},
		{
			name: "clone read-back carries the write deadline",
			run:  cloneRun(cloneFaults{}),
			assert: func(t *testing.T, p *probes, _ outcome) {
				within(t, p, "find", detach.WriteTimeout)
			},
		},
		{
			name: "clone read-back out of time is the could-not-read-back error",
			run:  cloneRun(cloneFaults{find: timedOut}),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("find").called)
				require.Error(t, out.err)
				assert.ErrorIs(t, out.err, timedOut)
				assert.Contains(t, out.err.Error(), "could not read the credential back")
				assert.NotErrorIs(t, out.err, passkey.ErrCloneSuspected)
			},
		},
		{
			name: "clone suspension carries the revocation deadline",
			run:  cloneRun(cloneFaults{}),
			assert: func(t *testing.T, p *probes, _ outcome) {
				within(t, p, "suspend", detach.RevocationTimeout)
			},
		},
		{
			name: "clone suspension out of time still refuses as a suspected clone",
			run:  cloneRun(cloneFaults{suspend: timedOut}),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("suspend").called)
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				assert.ErrorIs(t, out.err, timedOut)
				assert.Contains(t, out.err.Error(), "could not suspend the credential")
			},
		},
		{
			name: "clone session end carries the revocation deadline",
			run:  cloneRun(cloneFaults{}),
			assert: func(t *testing.T, p *probes, _ outcome) {
				within(t, p, "delete-by-user", detach.RevocationTimeout)
			},
		},
		{
			name: "clone session end out of time is logged and the refusal stands",
			run:  cloneRun(cloneFaults{deleteByUser: timedOut}),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("delete-by-user").called)
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				assert.Equal(t, 1, countRecords(out.logs, "passkey: the user's sessions could not all be ended"))
				assert.Contains(t, out.logs.String(), `"level":"ERROR"`)
			},
		},
		{
			name: "clone grant revocation carries the revocation deadline",
			run:  cloneRun(cloneFaults{}),
			assert: func(t *testing.T, p *probes, _ outcome) {
				within(t, p, "revoke-grants", detach.RevocationTimeout)
			},
		},
		{
			name: "clone grant revocation out of time is logged, reported, and the refusal stands",
			run:  cloneRun(cloneFaults{grants: timedOut}),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("revoke-grants").called)
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				assert.Equal(t, 1, countRecords(out.logs, "passkey: the user's application grants could not be revoked"))
				assert.Contains(t, out.logs.String(), `"level":"ERROR"`)
				require.Len(t, out.events, 1)
				assert.Equal(t, event.GrantRevokeFailed, out.events[0].Name)
			},
		},
		{
			name: "notice's user load and contact resolution each carry their own write deadline",
			run:  notifyRun(notifyFaults{}),
			assert: func(t *testing.T, p *probes, _ outcome) {
				within(t, p, "load-user", detach.WriteTimeout)
				within(t, p, "resolve-contact", detach.WriteTimeout)
				assert.True(t, p.get("resolve-contact").deadline.After(p.get("load-user").deadline),
					"the resolver must not run on what is left of the loader's bound")
			},
		},
		{
			name: "notice's sender is left to bound itself",
			run:  notifyRun(notifyFaults{}),
			assert: func(t *testing.T, p *probes, _ outcome) {
				unbounded(t, p, "send")
			},
		},
		{
			name: "notice's sender stays live when the caller is cancelled",
			run:  notifyRun(notifyFaults{}),
			ctx:  cancelledCtx,
			assert: func(t *testing.T, p *probes, _ outcome) {
				unbounded(t, p, "send")
				within(t, p, "load-user", detach.WriteTimeout)
			},
		},
		{
			name: "notice's user load out of time is logged, nothing is sent",
			run:  notifyRun(notifyFaults{load: timedOut}),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("load-user").called)
				assert.False(t, p.get("send").called)
				assert.Equal(t, 1, countRecords(out.logs, "passkey: a notice was not queued"))
				assert.Contains(t, out.logs.String(), `"level":"ERROR"`)
			},
		},
		{
			name: "notice's contact resolution out of time is logged, nothing is sent",
			run:  notifyRun(notifyFaults{resolve: timedOut}),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("resolve-contact").called)
				assert.False(t, p.get("send").called)
				assert.Equal(t, 1, countRecords(out.logs, "passkey: a notice was not queued"))
				assert.Contains(t, out.logs.String(), `"level":"ERROR"`)
			},
		},
		{
			name: "confirmation limiter's RecordFailure carries no library deadline",
			run:  confirmRun(nil),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.ErrorIs(t, out.err, mfa.ErrEmailCodeInvalid)
				unbounded(t, p, "record-failure")
			},
		},
		{
			name: "confirmation limiter's RecordFailure stays live when the caller is cancelled",
			run:  confirmRun(nil),
			ctx:  cancelledCtx,
			assert: func(t *testing.T, p *probes, _ outcome) {
				unbounded(t, p, "record-failure")
			},
		},
		{
			name: "confirmation limiter out of time is logged and the refusal stands",
			run:  confirmRun(timedOut),
			assert: func(t *testing.T, p *probes, out outcome) {
				require.True(t, p.get("record-failure").called)
				require.ErrorIs(t, out.err, mfa.ErrEmailCodeInvalid)
				assert.Equal(t, 1, countRecords(out.logs, "passkey: a failed confirmation was not counted"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			p := &probes{}
			out := tc.run(t, ctx, p)
			tc.assert(t, p, out)
		})
	}
}

// cancelledCtx returns ctx already cancelled, with no deadline of its own.
func cancelledCtx(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// findProbe records the context of the credential read-back, and fails it
// with err when set.
type findProbe struct {
	*spyCredentials
	p   *probes
	err error
}

func (f *findProbe) Find(ctx context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	f.p.see(ctx, "find")

	if f.err != nil {
		return nil, f.err
	}

	return f.spyCredentials.Find(ctx, user, cid)
}
