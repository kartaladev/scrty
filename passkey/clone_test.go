package passkey_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
)

// countRecords counts the log records whose message is msg.
func countRecords(logs *logBuffer, msg string) int {
	n := 0

	for _, r := range logs.records() {
		if strings.Contains(r, `"msg":"`+msg+`"`) {
			n++
		}
	}

	return n
}

const msgCloneRecord = "passkey: suspected clone"

func TestClone(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []passkey.Option
		seed    func(c *passkey.Credential)
		count   uint32 // the presented counter, over a stored 42 unless seeded
		adjust  func(b *assertionBody)
		spy     func(e *loginEnv) // adjusts the credential spy; nil leaves it
		sendErr error
		// prepare runs before the manager is built, and may seed sessions
		// into sids or wire a revoker.
		prepare func(t *testing.T, e *loginEnv, sids map[string]string)
		// cancelOnClone cancels the request's context as the clone is
		// decided, before any suspension, through a clone policy that
		// suspends.
		cancelOnClone bool
		ctx           func(ctx context.Context) context.Context
		assert        func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error)
	}

	suspendedWithNotice := func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, passkey.ErrCloneSuspected)
		require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
		assert.Nil(t, res)

		c := e.stored(t)
		assert.Equal(t, passkey.StateSuspended, c.State)
		assert.Equal(t, uint32(42), c.SignCount)

		msgs := e.f.messages()
		require.Len(t, msgs, 1)
		assert.Equal(t, "ana@example.com", msgs[0].To)
		assert.Contains(t, msgs[0].TextBody, "Security key")
		assert.Contains(t, msgs[0].TextBody, "help@example.com")
		assert.Contains(t, msgs[0].TextBody, "register a new passkey")
		assert.Equal(t, 1, countRecords(e.logs, msgCloneRecord))
	}
	allowed := func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, passkey.StateActive, e.stored(t).State)
		assert.Empty(t, e.f.messages())
	}

	recordedUse := func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error) {
		t.Helper()
		allowed(t, e, res, err)

		c := e.stored(t)
		assert.Equal(t, uint32(42), c.SignCount)
		assert.True(t, c.BackupState, "backup state recorded on an accepted assertion")
		assert.Equal(t, regStart, c.LastUsedAt)
	}

	var (
		signalMu sync.Mutex
		signals  []passkey.CloneSignal
	)

	adminsOnly := func(_ context.Context, s passkey.CloneSignal) passkey.CloneAction {
		signalMu.Lock()
		signals = append(signals, s)
		signalMu.Unlock()

		if s.User == "admin" {
			return passkey.CloneRefuseSuspend
		}

		return passkey.CloneAllow
	}

	ignoreSessions := func(
		fn func(t *testing.T, e *loginEnv, res *passkey.LoginResult, err error),
	) func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error) {
		return func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
			t.Helper()
			fn(t, e, res, err)
		}
	}
	seeded := func(t *testing.T, e *loginEnv, sids map[string]string) {
		t.Helper()

		for device, sid := range e.f.seedSessions(t) {
			sids[device] = sid
		}
	}
	// everyLoads asserts that every seeded session still loads.
	everyLoads := func(t *testing.T, e *loginEnv, sids map[string]string) {
		t.Helper()

		for device, sid := range sids {
			assert.True(t, e.f.loads(t, sid), "the %s session must still load", device)
		}
	}
	// endedAll asserts that none of u-1's seeded sessions loads, and u-2's
	// still does.
	endedAll := func(t *testing.T, e *loginEnv, sids map[string]string) {
		t.Helper()

		for _, device := range []string{"laptop", "phone", "tablet"} {
			assert.False(t, e.f.loads(t, sids[device]), "the %s session must no longer load", device)
		}

		assert.True(t, e.f.loads(t, sids["theirs"]), "another user's session must survive")
	}
	refusePolicy := func(context.Context, passkey.CloneSignal) passkey.CloneAction { return passkey.CloneRefuse }
	allowPolicy := func(context.Context, passkey.CloneSignal) passkey.CloneAction { return passkey.CloneAllow }

	cases := []testCase{
		{
			name:    "a suspected clone suspends, ends every session of the user, and says so",
			count:   41,
			prepare: seeded,
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				suspendedWithNotice(t, e, res, err)
				endedAll(t, e, sids)
				assert.Contains(t, e.f.messages()[0].TextBody, "All your sessions were signed out.")
			},
		},
		{
			name:          "a client disconnecting before the suspension still suspends the credential and ends the sessions",
			count:         41,
			prepare:       seeded,
			cancelOnClone: true,
			spy: func(e *loginEnv) {
				e.creds.suspendHook = func(ctx context.Context, cid id.ID) (bool, error) {
					if err := ctx.Err(); err != nil {
						return false, err
					}

					return e.creds.MemoryCredentialStore.Suspend(ctx, cid)
				}
			},
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Nil(t, res)
				assert.Equal(t, passkey.StateSuspended, e.stored(t).State, "credential should be suspended")
				endedAll(t, e, sids)
			},
		},
		{
			name:  "a suspension that reports none ends no session and queues no notice",
			count: 41,
			spy: func(e *loginEnv) {
				e.creds.suspendHook = func(context.Context, id.ID) (bool, error) { return false, nil }
			},
			prepare: func(_ *testing.T, e *loginEnv, _ map[string]string) {
				e.f.mockRevoker() // no expectation: any revocation fails the test
			},
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Nil(t, res)
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name:          "the sessions end on a context the cancelled request cannot cancel",
			count:         41,
			cancelOnClone: true,
			prepare: func(t *testing.T, e *loginEnv, _ map[string]string) {
				e.f.mockRevoker().EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).
					DoAndReturn(func(ctx context.Context, _ identity.UserID) error {
						assert.NoError(t, ctx.Err(), "revocation must not run on the cancelled context")
						return nil
					})
			},
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, _ *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Contains(t, e.f.messages()[0].TextBody, "All your sessions were signed out.")
			},
		},
		{
			name:  "a failed revocation is logged without the dependency's text and the refusal stands",
			count: 41,
			prepare: func(_ *testing.T, e *loginEnv, _ map[string]string) {
				e.f.mockRevoker().EXPECT().DeleteByUser(gomock.Any(), gomock.Any()).
					Return(errors.New("db down: secret-host"))
			},
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
				assert.Nil(t, res)
				assert.Equal(t, passkey.StateSuspended, e.stored(t).State)

				out := e.logs.String()
				assert.Equal(t, 1, countRecords(e.logs, "passkey: the user's sessions could not all be ended"))
				assert.Contains(t, out, `"key":"clone|sessions-not-ended"`)
				assert.Contains(t, out, `"level":"ERROR"`)
				assert.NotContains(t, out, "secret-host")

				msgs := e.f.messages()
				require.Len(t, msgs, 1)
				assert.NotContains(t, msgs[0].TextBody, "signed out")
			},
		},
		{
			name:    "with clone revocation off the credential is suspended and every session still loads",
			opts:    []passkey.Option{passkey.WithoutSessionRevocationOnClone()},
			count:   41,
			prepare: seeded,
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				suspendedWithNotice(t, e, res, err)
				everyLoads(t, e, sids)
				assert.NotContains(t, e.f.messages()[0].TextBody, "signed out")
			},
		},
		{
			name:    "signal only ends no session",
			opts:    []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
			count:   41,
			prepare: seeded,
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)
				everyLoads(t, e, sids)
			},
		},
		{
			name:    "a policy that allows ends no session",
			opts:    []passkey.Option{passkey.WithClonePolicy(allowPolicy)},
			count:   41,
			prepare: seeded,
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)
				everyLoads(t, e, sids)
			},
		},
		{
			name:    "a policy that only refuses ends no session",
			opts:    []passkey.Option{passkey.WithClonePolicy(refusePolicy)},
			count:   41,
			prepare: seeded,
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, _ *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
				everyLoads(t, e, sids)
			},
		},
		{
			name:    "a context cancelled before the login ends no session and changes nothing",
			count:   41,
			prepare: seeded,
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()

				return c
			},
			assert: func(t *testing.T, e *loginEnv, sids map[string]string, _ *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
				everyLoads(t, e, sids)
			},
		},
		{
			name:   "a counter going backwards is refused, suspended and notified",
			count:  41,
			assert: ignoreSessions(suspendedWithNotice),
		},
		{
			name:   "an equal non-zero counter is refused, suspended and notified",
			count:  42,
			assert: ignoreSessions(suspendedWithNotice),
		},
		{
			name:  "a counter that stays zero is never a clone",
			seed:  func(c *passkey.Credential) { c.SignCount = 0 },
			count: 0,
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)
				assert.Equal(t, regStart, e.stored(t).LastUsedAt)
				assert.Zero(t, countRecords(e.logs, msgCloneRecord))
			},
		},
		{
			name:  "signal only allows the login, keeps the counter and warns",
			opts:  []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
			count: 41,
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)
				assert.Equal(t, uint32(42), e.stored(t).SignCount)

				out := e.logs.String()
				assert.Equal(t, 1, countRecords(e.logs, msgCloneRecord))
				assert.Contains(t, out, `"level":"WARN"`)
				assert.Contains(t, out, e.cred.ID.String())
			},
		},
		{
			name:  "a consumer policy allowing non-administrators lets the login proceed",
			opts:  []passkey.Option{passkey.WithClonePolicy(adminsOnly)},
			count: 41,
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				allowed(t, e, res, err)

				signalMu.Lock()
				defer signalMu.Unlock()

				require.NotEmpty(t, signals)
				assert.Contains(t, signals, passkey.CloneSignal{
					User: "u-1", Credential: e.cred.ID, Stored: 42, Presented: 41,
				})
			},
		},
		{
			name:   "signal only still records backup state and last use, keeping the counter",
			opts:   []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
			count:  41,
			adjust: func(b *assertionBody) { b.BS = true },
			assert: ignoreSessions(recordedUse),
		},
		{
			name: "an allowing policy still records backup state and last use, keeping the counter",
			opts: []passkey.Option{passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
				return passkey.CloneAllow
			})},
			count:  41,
			adjust: func(b *assertionBody) { b.BS = true },
			assert: ignoreSessions(recordedUse),
		},
		{
			name:  "an allowed clone whose credential was suspended meanwhile is refused as suspended",
			opts:  []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
			count: 41,
			spy: func(e *loginEnv) {
				e.creds.useHook = func(ctx context.Context, cid id.ID) (bool, error) {
					_, err := e.creds.Suspend(ctx, cid)
					return false, err
				}
			},
			assert: func(t *testing.T, _ *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrSuspended)
				assert.Nil(t, res)
			},
		},
		{
			name:  "an allowed clone whose use cannot be recorded returns the store error",
			opts:  []passkey.Option{passkey.WithCloneResponse(passkey.CloneSignalOnly)},
			count: 41,
			spy: func(e *loginEnv) {
				e.creds.useHook = func(context.Context, id.ID) (bool, error) {
					return false, errors.New("store down")
				}
			},
			assert: func(t *testing.T, _ *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.Error(t, err)
				assert.ErrorContains(t, err, "could not record the assertion")
				assert.Nil(t, res)
			},
		},
		{
			name: "a consumer policy refusing without suspending refuses only",
			opts: []passkey.Option{passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
				return passkey.CloneRefuse
			})},
			count: 41,
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Nil(t, res)
				assert.Equal(t, passkey.StateActive, e.stored(t).State)
				assert.Empty(t, e.f.messages())
			},
		},
		{
			name: "a consumer policy decides over the response",
			opts: []passkey.Option{
				passkey.WithCloneResponse(passkey.CloneSignalOnly),
				passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
					return passkey.CloneRefuseSuspend
				}),
			},
			count:  41,
			assert: ignoreSessions(suspendedWithNotice),
		},
		{
			name:    "a refused suspension notice leaves the credential suspended",
			count:   41,
			sendErr: errors.New("queue full"),
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, passkey.ErrCloneSuspected)
				assert.Nil(t, res)
				assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
				assert.Equal(t, 1, countRecords(e.logs, "passkey: a notice was not queued"))
			},
		},
		{
			name:   "a changed backup-eligible flag is refused as authentication failed",
			count:  43,
			adjust: func(b *assertionBody) { b.BE = true },
			assert: func(t *testing.T, e *loginEnv, _ map[string]string, res *passkey.LoginResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Nil(t, res)

				c := e.stored(t)
				assert.Equal(t, passkey.StateActive, c.State)
				assert.Equal(t, uint32(42), c.SignCount)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newLoginEnv(t, tc.seed)
			e.f.sendErr = tc.sendErr
			if tc.spy != nil {
				tc.spy(e)
			}

			sids := map[string]string{}
			if tc.prepare != nil {
				tc.prepare(t, e, sids)
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			opts := tc.opts
			if tc.cancelOnClone {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				t.Cleanup(cancel)
				opts = append(opts, passkey.WithClonePolicy(func(context.Context, passkey.CloneSignal) passkey.CloneAction {
					cancel()
					return passkey.CloneRefuseSuspend
				}))
			}

			e.manager(t, opts...)

			challenge := e.begin(t)
			body := assertion(challenge, func(b *assertionBody) {
				b.Count = tc.count
				if tc.adjust != nil {
					tc.adjust(b)
				}
			})

			res, err := e.m.Authenticate(ctx, body, e.binding)
			tc.assert(t, e, sids, res, err)
		})
	}
}

// TestCloneConcurrentAssertionsWithOneCounter pins the specification's choice:
// two assertions from two tabs, both carrying 43 over a stored 42, give one
// login and one suspected clone, which suspends the credential.
func TestCloneConcurrentAssertionsWithOneCounter(t *testing.T) {
	t.Parallel()

	e := newLoginEnv(t, nil)
	e.manager(t)

	type attempt struct {
		binding string
		body    []byte
	}

	attempts := make([]attempt, 2)
	for i := range attempts {
		e.binding = []string{"tab-1", "tab-2"}[i]
		attempts[i] = attempt{binding: e.binding, body: assertion(e.begin(t), nil)}
	}

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, len(attempts))
	)

	for i, a := range attempts {
		wg.Go(func() {
			<-start
			_, errs[i] = e.m.Authenticate(t.Context(), a.body, a.binding)
		})
	}

	close(start)
	wg.Wait()

	var ok, clone int

	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, passkey.ErrCloneSuspected):
			clone++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}

	assert.Equal(t, 1, ok, "exactly one login")
	assert.Equal(t, 1, clone, "exactly one suspected clone")
	assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
	assert.Equal(t, uint32(43), e.stored(t).SignCount)
}

// TestCloneRacingAssertionsSuspendOnce pins that two concurrent clone
// assertions for one credential, both carrying 41 over a stored 42, suspend
// it once: the user's sessions are ended, and the Suspended notice is queued
// once.
func TestCloneRacingAssertionsSuspendOnce(t *testing.T) {
	t.Parallel()

	e := newLoginEnv(t, nil)

	var ended atomic.Int32

	e.f.mockRevoker().EXPECT().DeleteByUser(gomock.Any(), identity.UserID("u-1")).
		DoAndReturn(func(context.Context, identity.UserID) error {
			ended.Add(1)
			return nil
		}).Times(1)
	e.manager(t)

	type attempt struct {
		binding string
		body    []byte
	}

	attempts := make([]attempt, 2)
	for i := range attempts {
		e.binding = []string{"tab-1", "tab-2"}[i]
		attempts[i] = attempt{
			binding: e.binding,
			body:    assertion(e.begin(t), func(b *assertionBody) { b.Count = 41 }),
		}
	}

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, len(attempts))
	)

	for i, a := range attempts {
		wg.Go(func() {
			<-start
			_, errs[i] = e.m.Authenticate(t.Context(), a.body, a.binding)
		})
	}

	close(start)
	wg.Wait()

	clone := 0

	for _, err := range errs {
		switch {
		case errors.Is(err, passkey.ErrCloneSuspected):
			clone++
		case errors.Is(err, passkey.ErrSuspended):
		default:
			t.Errorf("unexpected result: %v", err)
		}
	}

	assert.GreaterOrEqual(t, clone, 1, "at least one suspected clone")
	assert.Equal(t, passkey.StateSuspended, e.stored(t).State)
	assert.Equal(t, int32(1), ended.Load(), "the sessions were ended once")

	msgs := e.f.messages()
	require.Len(t, msgs, 1, "the Suspended notice is queued once")
	assert.Contains(t, msgs[0].TextBody, "All your sessions were signed out.")
}

// gatedSender blocks every Send until release is closed, then records the
// message on delivered.
type gatedSender struct {
	release   chan struct{}
	delivered chan notify.Message
}

func (g *gatedSender) Send(_ context.Context, m notify.Message) error {
	<-g.release
	g.delivered <- m

	return nil
}

// TestCloneRefusalDoesNotWaitForDelivery pins that the suspension notice is
// queued, not delivered inline: the refusal returns while the sender is still
// blocked, and the notice is delivered once it is released.
func TestCloneRefusalDoesNotWaitForDelivery(t *testing.T) {
	t.Parallel()

	gate := &gatedSender{release: make(chan struct{}), delivered: make(chan notify.Message, 1)}
	q, err := notify.NewQueuedSender(gate)
	require.NoError(t, err)

	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}

		assert.NoError(t, q.Close(context.WithoutCancel(t.Context())))
	})

	e := newLoginEnv(t, nil)
	e.f.deps.Sender = q
	e.manager(t)

	type outcome struct {
		res *passkey.LoginResult
		err error
	}

	body := assertion(e.begin(t), func(b *assertionBody) { b.Count = 41 })
	done := make(chan outcome, 1)

	go func() {
		res, err := e.m.Authenticate(t.Context(), body, e.binding)
		done <- outcome{res, err}
	}()

	select {
	case got := <-done:
		require.ErrorIs(t, got.err, passkey.ErrCloneSuspected)
		assert.Nil(t, got.res)
	case <-time.After(5 * time.Second):
		t.Fatal("the clone refusal waited for the notice to be delivered")
	}

	assert.Equal(t, passkey.StateSuspended, e.stored(t).State)

	select {
	case m := <-gate.delivered:
		t.Fatalf("notice delivered while the sender was blocked: %+v", m)
	default:
	}

	close(gate.release)

	select {
	case m := <-gate.delivered:
		assert.Equal(t, "ana@example.com", m.To)
		assert.Contains(t, m.TextBody, "Security key")
	case <-time.After(5 * time.Second):
		t.Fatal("the suspension notice was not delivered after the sender was released")
	}
}
