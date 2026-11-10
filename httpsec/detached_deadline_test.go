package httpsec_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// deadlineProbe records what the doubles below saw of the context of every call
// under test. Every case's caller context carries no deadline, so a deadline a
// double sees comes from the library.
type deadlineProbe struct {
	mu    sync.Mutex
	calls []ctxCall
}

type ctxCall struct {
	deadline time.Time
	has      bool
	err      error
}

func (p *deadlineProbe) see(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	dl, ok := ctx.Deadline()
	p.calls = append(p.calls, ctxCall{deadline: dl, has: ok, err: ctx.Err()})
}

func (p *deadlineProbe) seen() []ctxCall {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]ctxCall(nil), p.calls...)
}

// detachedOutcome is what a case's run observed: the answer it got, as a served
// exchange or a bare status, and every record the chain logged.
type detachedOutcome struct {
	s       served
	status  int
	records []slog.Record
}

// cancelled returns ctx already cancelled, with no deadline of its own: the
// caller has hung up before the detached work starts.
func cancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// probedFamilies is a session store whose family delete records its context and
// can be made to fail.
type probedFamilies struct {
	session.Store

	p    *deadlineProbe
	fail error
}

func (s probedFamilies) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	s.p.see(ctx)

	if s.fail != nil {
		return 0, s.fail
	}

	return s.Store.DeleteFamily(ctx, family)
}

// probedEnroller is the TOTP method with its emailed-code redemption recording
// its context and failing on request: the call a void is made of.
type probedEnroller struct {
	*mfa.TOTP

	p    *deadlineProbe
	fail error
}

func (m probedEnroller) RedeemEmailCode(ctx context.Context, user identity.UserID, gen id.ID, code string) error {
	m.p.see(ctx)

	if m.fail != nil {
		return m.fail
	}

	return m.TOTP.RedeemEmailCode(ctx, user, gen, code)
}

// TestChain_DetachedCallsCarryDeadline pins the bound on the calls this package
// makes under a context the caller cannot cancel. A write carries
// detach.WriteTimeout and a revocation carries detach.RevocationTimeout. The
// limiter calls and a notice's sender are left to their owners and carry no
// deadline of the library's making. Each bounded site also keeps today's
// outcome when its call fails with the deadline.
func TestChain_DetachedCallsCarryDeadline(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run makes the call under test with ctx, arming the callee's failure
		// when fail is set.
		run    func(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome
		fail   error
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, p *deadlineProbe, o detachedOutcome)
	}

	// assertBounded asserts every call the probe saw carries a deadline within
	// bound (a revocation's also beyond a write's), and that at least n calls were
	// made.
	assertBounded := func(bound time.Duration, n int) func(*testing.T, *deadlineProbe, detachedOutcome) {
		return func(t *testing.T, p *deadlineProbe, _ detachedOutcome) {
			t.Helper()

			calls := p.seen()
			require.GreaterOrEqual(t, len(calls), n, "the call under test was not made")

			for _, c := range calls {
				require.True(t, c.has, "the detached call has no deadline")
				remaining := time.Until(c.deadline)
				assert.Positive(t, remaining)
				assert.LessOrEqual(t, remaining, bound)

				if bound == detach.RevocationTimeout {
					assert.Greater(t, remaining, detach.WriteTimeout, "a revocation is bounded at a write's timeout")
				}
				assert.NoError(t, c.err, "the detached call's context was already done")
			}
		}
	}

	// assertUnbounded asserts the call was made and carries no deadline.
	assertUnbounded := func(t *testing.T, p *deadlineProbe, _ detachedOutcome) {
		t.Helper()

		calls := p.seen()
		require.NotEmpty(t, calls, "the call under test was not made")

		for _, c := range calls {
			assert.False(t, c.has, "the library bounded a call its owner bounds")
		}
	}

	refusedWith := func(cause error) func(*testing.T, *deadlineProbe, detachedOutcome) {
		return func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
			t.Helper()

			require.NotEmpty(t, p.seen(), "the call under test was not made")
			require.ErrorIs(t, o.s.err, cause)
			assert.False(t, o.s.handlerRan)
		}
	}

	backchannelFailed := func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
		t.Helper()

		require.NotEmpty(t, p.seen(), "the call under test was not made")
		failedAsServer(t, o.s, context.DeadlineExceeded)
	}

	loggedAt := func(level slog.Level, msg string) func(*testing.T, *deadlineProbe, detachedOutcome) {
		return func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
			t.Helper()

			require.NotEmpty(t, p.seen(), "the call under test was not made")
			_, ok := recordAt(o.records, level, msg)
			assert.True(t, ok, "no %s record %q", level, msg)
		}
	}

	failedLogin := func(level slog.Level, msg string) func(*testing.T, *deadlineProbe, detachedOutcome) {
		return func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
			t.Helper()

			loggedAt(level, msg)(t, p, o)
			require.ErrorIs(t, o.s.err, authenticate.ErrAuthenticationFailed, "a broken ledger must not change the refusal")
		}
	}

	cases := []testCase{
		{
			name:   "logout: the family revocation carries the revocation deadline",
			run:    runLogout,
			assert: assertBounded(detach.RevocationTimeout, 1),
		},
		{
			name: "logout: a hung-up caller still gets a live, bounded revocation",
			run:  runLogout,
			ctx:  cancelled,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				assertBounded(detach.RevocationTimeout, 1)(t, p, o)
			},
		},
		{
			name:   "logout: a revocation that hits its deadline refuses the logout",
			run:    runLogout,
			fail:   context.DeadlineExceeded,
			assert: refusedWith(context.DeadlineExceeded),
		},
		{
			name:   "end session: the family revocation carries the revocation deadline",
			run:    runEndSession,
			assert: assertBounded(detach.RevocationTimeout, 1),
		},
		{
			name: "end session: a revocation that hits its deadline answers a server error",
			run:  runEndSession,
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				require.NotEmpty(t, p.seen(), "the call under test was not made")
				assert.Equal(t, http.StatusInternalServerError, o.status)
			},
		},
		{
			name:   "back-channel: the delete by provider session carries the revocation deadline",
			run:    runBackchannel(backchannelBySession),
			assert: assertBounded(detach.RevocationTimeout, 1),
		},
		{
			name:   "back-channel: a delete by provider session that hits its deadline is a server failure",
			run:    runBackchannel(backchannelBySession),
			fail:   context.DeadlineExceeded,
			assert: backchannelFailed,
		},
		{
			name:   "back-channel: the delete by subject carries the revocation deadline",
			run:    runBackchannel(backchannelBySubject),
			assert: assertBounded(detach.RevocationTimeout, 1),
		},
		{
			name:   "back-channel: a delete by subject that hits its deadline is a server failure",
			run:    runBackchannel(backchannelBySubject),
			fail:   context.DeadlineExceeded,
			assert: backchannelFailed,
		},
		{
			name:   "back-channel: the delete of all the user's sessions carries the revocation deadline",
			run:    runBackchannel(backchannelAll),
			assert: assertBounded(detach.RevocationTimeout, 1),
		},
		{
			name:   "back-channel: a delete of all sessions that hits its deadline is a server failure",
			run:    runBackchannel(backchannelAll),
			fail:   context.DeadlineExceeded,
			assert: backchannelFailed,
		},
		{
			name:   "back-channel: the link lookup carries the write deadline",
			run:    runBackchannel(backchannelLink),
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name:   "back-channel: a link lookup that hits its deadline is a server failure",
			run:    runBackchannel(backchannelLink),
			fail:   context.DeadlineExceeded,
			assert: backchannelFailed,
		},
		{
			name:   "session touch: the activity write carries the write deadline",
			run:    runTouch,
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name: "session touch: a hung-up caller still gets a live, bounded write",
			run:  runTouch,
			ctx:  cancelled,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				assertBounded(detach.WriteTimeout, 1)(t, p, o)
			},
		},
		{
			name: "session touch: a write that hits its deadline is logged at DEBUG and discarded",
			run:  runTouch,
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				require.NoError(t, o.s.err, "bookkeeping must not turn a served request into a fault")
				loggedAt(slog.LevelDebug, "httpsec: session activity could not be recorded")(t, p, o)
			},
		},
		{
			name:   "Basic: the failed-attempt record carries the write deadline",
			run:    runBasicRecord,
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name:   "Basic: a record that hits its deadline is logged and the refusal stands",
			run:    runBasicRecord,
			fail:   context.DeadlineExceeded,
			assert: failedLogin(slog.LevelError, "httpsec: a failed login attempt could not be recorded"),
		},
		{
			name:   "form login: the failed-attempt record carries the write deadline",
			run:    runLoginRecord,
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name:   "form login: a record that hits its deadline is logged and the refusal stands",
			run:    runLoginRecord,
			fail:   context.DeadlineExceeded,
			assert: failedLogin(slog.LevelError, "httpsec: a failed login attempt could not be recorded"),
		},
		{
			name:   "enrolment: voiding the emailed code carries the write deadline",
			run:    runVoid,
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name: "enrolment: a void that hits its deadline is logged and the send failure is what answers",
			run:  runVoid,
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				require.NotEmpty(t, p.seen(), "the call under test was not made")
				require.ErrorIs(t, o.s.err, notify.ErrQueueFull)
				assert.NotErrorIs(t, o.s.err, context.DeadlineExceeded)

				_, ok := recordAt(o.records, slog.LevelError, "httpsec: an undelivered enrolment code could not be voided")
				assert.True(t, ok, "the voiding failure is logged")
			},
		},
		{
			name:   "enrolment notice: the user loader carries the write deadline",
			run:    runNotice(noticeLoader),
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name: "enrolment notice: a loader that hits its deadline is logged and the enrolment stands",
			run:  runNotice(noticeLoader),
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				assertNotNotified(t, p, o)
			},
		},
		{
			name:   "enrolment notice: the contact resolver carries the write deadline",
			run:    runNotice(noticeResolver),
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name: "enrolment notice: a resolver that hits its deadline is logged and the enrolment stands",
			run:  runNotice(noticeResolver),
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				assertNotNotified(t, p, o)
			},
		},
		{
			name:   "enrolment notice: the sender owns its bound, so the send carries no library deadline",
			run:    runNotice(noticeSend),
			assert: assertUnbounded,
		},
		{
			name:   "password change: every store's clearing carries the write deadline",
			run:    runPasswordChange,
			assert: assertBounded(detach.WriteTimeout, 2),
		},
		{
			name: "password change: a clearing that hits its deadline is logged and the next store is still cleared",
			run:  runPasswordChange,
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				require.NoError(t, o.s.err)
				assert.Len(t, p.seen(), 2, "the second store was not cleared")

				_, ok := recordAt(o.records, slog.LevelError,
					"httpsec: lockout failures could not be cleared after a password change")
				assert.True(t, ok)
			},
		},
		{
			name:   "rehash: the consumer's write carries the write deadline",
			run:    runRehash,
			assert: assertBounded(detach.WriteTimeout, 1),
		},
		{
			name: "rehash: a write that hits its deadline is logged and the login stands",
			run:  runRehash,
			fail: context.DeadlineExceeded,
			assert: func(t *testing.T, p *deadlineProbe, o detachedOutcome) {
				t.Helper()

				require.NotEmpty(t, p.seen(), "the call under test was not made")
				require.NoError(t, o.s.err)
				assert.Equal(t, http.StatusOK, o.s.rec.Code)

				_, ok := recordAt(o.records, slog.LevelError, "httpsec: an upgraded password hash could not be stored")
				assert.True(t, ok)
			},
		},
		{
			name:   "source guard: the limiter's failure record is the limiter's to bound",
			run:    runGuardRecord,
			assert: assertUnbounded,
		},
		{
			name:   "renewal limiter: the charge is the limiter's to bound",
			run:    runRenewalCharge,
			assert: assertUnbounded,
		},
		{
			name:   "enrolment limiter: the failure record is the limiter's to bound",
			run:    runEnrolmentRecord,
			assert: assertUnbounded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			p := &deadlineProbe{}
			o := tc.run(ctx, t, p, tc.fail)
			tc.assert(t, p, o)
		})
	}
}

// assertNotNotified asserts the notice's failure was logged once and the
// enrolment it reports stood.
func assertNotNotified(t *testing.T, p *deadlineProbe, o detachedOutcome) {
	t.Helper()

	require.NotEmpty(t, p.seen(), "the call under test was not made")
	require.NoError(t, o.s.err, "the enrolment is complete before the notice")
	assert.Equal(t, http.StatusNoContent, o.s.rec.Code)

	var found int

	for _, r := range o.records {
		if r.Message == "httpsec: the user could not be notified of a completed enrolment" {
			found++
		}
	}

	assert.Equal(t, 1, found, "the failed notice is logged once")
}

func runLogout(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	h := newAuthHarness(t)
	h.expectVerified()
	h.users.EXPECT().LoadByUserID(gomock.Any(), testUserID).Return(storedUser(), nil).AnyTimes()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(familiedSession(), nil).AnyTimes()
	h.acceptsActivityWriteBack()
	h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).
		DoAndReturn(func(ctx context.Context, _ id.ID) (int, error) {
			p.see(ctx)

			if fail != nil {
				return 0, fail
			}

			return 1, nil
		}).Times(1)

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBearerToken(h.bearerTokenDeps()),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}))
	require.NoError(t, err)

	s := serveContext(ctx, t, chain, logoutRequest(ctx, http.MethodPost, httpsec.DefaultLogoutPath, true))

	return detachedOutcome{s: s, records: h.logs.records()}
}

func runEndSession(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	store := &probedFamilies{Store: must.Must(session.NewMemoryStore()), p: p, fail: fail}
	f := newSignInEnds(t, endsSetup{sessions: store}) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	s := f.signIn(t)                                  //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	grant := f.grantFrom(t, s, endsOnlineScope)       //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	send := logoutPaths()[0].prepare(t, f, s, grant.browser)
	a := send(func(r *http.Request) { *r = *r.WithContext(ctx) })

	return detachedOutcome{status: a.status}
}

// Which back-channel call a case exercises.
const (
	backchannelBySession = "by-session"
	backchannelBySubject = "by-subject"
	backchannelAll       = "all"
	backchannelLink      = "link"
)

// runBackchannel serves a verified logout token whose handling reaches the call
// kind names, over a double that records that call's context.
func runBackchannel(kind string) func(context.Context, *testing.T, *deadlineProbe, error) detachedOutcome {
	return func(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
		t.Helper()

		h := newBackchannelHarness(t) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		h.ctx = ctx

		var (
			opts  []httpsec.OIDCOption
			token string
		)

		store := NewMockStore(gomock.NewController(t))

		sessions := func() {
			m, err := session.New(session.WithStore(store))
			require.NoError(t, err)

			opts = append(opts, httpsec.WithOIDCSessions(m))
		}

		switch kind {
		case backchannelBySession:
			store.EXPECT().DeleteByExternalSession(gomock.Any(), gomock.Any(), "abc").
				DoAndReturn(func(ctx context.Context, _, _ string) (int, error) {
					p.see(ctx)

					return 1, fail
				})
			sessions()

			token = h.provider.logoutToken(t, oidcTestSubject, "abc")
		case backchannelBySubject:
			store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), oidcTestUserID, gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) (int, error) {
					p.see(ctx)

					return 1, fail
				})
			sessions()

			token = h.provider.logoutToken(t, oidcTestSubject, "")
		case backchannelAll:
			store.EXPECT().DeleteByUser(gomock.Any(), oidcTestUserID).
				DoAndReturn(func(ctx context.Context, _ identity.UserID) error {
					p.see(ctx)

					return fail
				})
			sessions()

			opts = append(opts, httpsec.WithOIDCBackchannelLogoutScope(httpsec.BackchannelLogoutScopeAll))
			token = h.provider.logoutToken(t, oidcTestSubject, "")
		case backchannelLink:
			ctrl := gomock.NewController(t)
			links := NewMockLinkStore(ctrl)
			links.EXPECT().FindByExternal(gomock.Any(), testOIDCProvider, h.issuer(), oidcTestSubject).
				DoAndReturn(func(ctx context.Context, _, _, _ string) (*oidc.Link, error) {
					p.see(ctx)

					if fail != nil {
						return nil, fail
					}

					return nil, oidc.ErrLinkNotFound
				})

			broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
			require.NoError(t, err)

			h.manager = h.managerWith(t, broker, nil, oidc.WithClock(h.clock))
			token = h.provider.logoutToken(t, oidcTestSubject, "")
		}

		h.chain = h.oidcHarness.chain(t, opts...)

		return detachedOutcome{s: h.post(t, token)} //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	}
}

func runTouch(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	h := newAuthHarness(t)
	h.expectVerified()
	h.expectResolvedSession(touchableSession())
	h.store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _, _, _ time.Time) error {
			p.see(ctx)

			return fail
		})

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBearerToken(h.bearerTokenDeps()))
	require.NoError(t, err)

	s := serveContext(ctx, t, chain, bearerRequest(ctx, "Bearer a-token"))

	return detachedOutcome{s: s, records: h.logs.records()}
}

func runBasicRecord(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	h := newAuthHarness(t)
	h.expectAuthenticationFailed()
	h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ time.Time) error {
			p.see(ctx)

			return fail
		})

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBasicAuth(h.basicAuthDeps()))
	require.NoError(t, err)

	s := serveContext(ctx, t, chain, basicRequest(ctx, "ada", "wrong"))

	return detachedOutcome{s: s, records: h.logs.records()}
}

func runLoginRecord(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	h := newAuthHarness(t)
	h.expectAuthenticationFailed()
	h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ time.Time) error {
			p.see(ctx)

			return fail
		})

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableFormLogin(h.formLoginDeps()))
	require.NoError(t, err)

	s := serveContext(ctx, t, chain,
		formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=wrong"))

	return detachedOutcome{s: s, records: h.logs.records()}
}

func runVoid(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	h := newEnrolHarness(t)
	o := &outbox{}
	o.accepting(h, notify.ErrQueueFull)

	logs := &capturingHandler{}
	h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))
	h.method = probedEnroller{TOTP: h.totp, p: p, fail: fail}

	c := h.chain(t, h.enrolmentOnly(t, factor.Password)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	secret := h.beginDoc(t, c).Secret                    //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	s := serveContext(ctx, t, c, post(ctx, enrolConfirmPath, "code="+h.codeFor(t, secret)))

	return detachedOutcome{s: s, records: logs.records()}
}

// Which call of the completed-enrolment notice a case probes.
const (
	noticeLoader   = "loader"
	noticeResolver = "resolver"
	noticeSend     = "send"
)

// runNotice completes an enrolment through the emailed code, probing op's call
// in the notice that follows, and failing it when fail is set.
func runNotice(op string) func(context.Context, *testing.T, *deadlineProbe, error) detachedOutcome {
	return func(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
		t.Helper()

		h := newEnrolHarness(t)
		o := &outbox{}
		logs := &capturingHandler{}

		// armed turns the probe on for the request that completes the enrolment:
		// the calls before it are the ones that email the code.
		var armed atomic.Bool

		probe := func(which string, ctx context.Context) error {
			if which != op || !armed.Load() {
				return nil
			}

			p.see(ctx)

			return fail
		}

		users := NewMockUserLoader(gomock.NewController(t))
		users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
			DoAndReturn(func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
				if err := probe(noticeLoader, ctx); err != nil {
					return nil, err
				}

				return &identity.Details{ID: testMFAUser, Name: "Ana", Username: h.username, Active: true}, nil
			})
		h.users = users

		h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentContactResolver(
			func(ctx context.Context, _ *identity.Details) (string, error) {
				if err := probe(noticeResolver, ctx); err != nil {
					return "", err
				}

				return enrolUsername, nil
			}))

		h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(ctx context.Context, m notify.Message) error {
				o.mu.Lock()
				o.sent = append(o.sent, m)
				o.mu.Unlock()

				return probe(noticeSend, ctx)
			})
		h.extra = append(h.extra, httpsec.WithLogger(slog.New(logs)))

		s := h.enrolmentOnly(t, factor.Password)             //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		c := h.chain(t, s)                                   //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		emailed := h.prove(t, c, o, h.beginDoc(t, c).Secret) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

		armed.Store(true)

		out := serveContext(ctx, t, c, emailCodeRequest(ctx, emailed))

		return detachedOutcome{s: out, records: logs.records()}
	}
}

func runPasswordChange(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	h := newAuthHarness(t)
	h.expectVerified()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
	h.users.EXPECT().LoadByUserID(gomock.Any(), testUserID).Return(storedUser(), nil).AnyTimes()
	h.expectSaved(&savedSessions{}, nil)
	h.acceptsActivityWriteBack()

	// The first store's clearing is the one that fails, so the second one shows
	// the failure of one store leaves the next still cleared.
	other := NewMockAttemptStore(gomock.NewController(t))
	h.attempts.EXPECT().Reset(gomock.Any(), testUsername).
		DoAndReturn(func(ctx context.Context, _ string) error {
			p.see(ctx)

			return fail
		})
	other.EXPECT().Reset(gomock.Any(), testUsername).
		DoAndReturn(func(ctx context.Context, _ string) error {
			p.see(ctx)

			return nil
		})

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBearerToken(h.bearerTokenDeps()),
		httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithPasswordChangeEndpoint(testChangePasswordPath, func(ex *httpsec.Exchange) error {
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			})),
		httpsec.EnableFormLogin(h.formLoginDeps()),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: other}))
	require.NoError(t, err)

	s := serveContext(ctx, t, chain, changePasswordRequest(ctx, http.MethodPost, true))

	return detachedOutcome{s: s, records: h.logs.records()}
}

func runRehash(ctx context.Context, t *testing.T, p *deadlineProbe, fail error) detachedOutcome {
	t.Helper()

	r := newRehashRig(t, rehashOldMemory)
	r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
	r.h.expectSessionOpened("issued-token")

	write := func(ctx context.Context, _ *identity.Details, _, _ []byte) error {
		p.see(ctx)

		return fail
	}

	chain, err := httpsec.New(
		httpsec.WithLogger(r.h.logger()),
		httpsec.EnableFormLogin(r.loginDeps(), httpsec.WithLoginRehash(write)))
	require.NoError(t, err)

	s := serveContext(ctx, t, chain,
		formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password="+rehashPassword))

	return detachedOutcome{s: s, records: r.h.logs.records()}
}

func runGuardRecord(ctx context.Context, t *testing.T, p *deadlineProbe, _ error) detachedOutcome {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, _ string) error {
			p.see(ctx)

			return nil
		})

	h := newLoginGuardHarness(t)
	c := h.chain(t, []httpsec.LoginOption{httpsec.WithLoginLimiter(l)}, nil)

	s := serveContext(ctx, t, c, fromSource(formRequest(ctx, httpsec.DefaultLoginPath,
		"username=ada&password=wrong"), loginGuardSource))

	return detachedOutcome{s: s}
}

func runRenewalCharge(ctx context.Context, t *testing.T, p *deadlineProbe, _ error) detachedOutcome {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string) error {
			p.see(ctx)

			return nil
		})

	f := newRenewalFixture(t, renewalSetup{opts: []httpsec.SessionRenewalOption{httpsec.WithRenewalLimiter(l)}}) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultSessionRenewalPath, nil)
	req.Header.Set("Authorization", "Bearer "+f.old)

	return detachedOutcome{s: serveContext(ctx, t, f.chain, req)}
}

func runEnrolmentRecord(ctx context.Context, t *testing.T, p *deadlineProbe, _ error) detachedOutcome {
	t.Helper()

	h := newEnrolHarness(t)

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, _ string) error {
			p.see(ctx)

			return nil
		})

	h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentConfirmLimiter(l))

	c := h.chain(t, h.enrolmentOnly(t, factor.Password)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	h.beginDoc(t, c)                                     //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	// A wrong code, which the confirmation limiter records.
	s := serveContext(ctx, t, c, post(ctx, enrolConfirmPath, "code=000000"))

	return detachedOutcome{s: s}
}
