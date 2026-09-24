package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// testMFAUser is who the second factor is being verified for. It is the
// consumer's own reference, and the throttle's bucket key is composed from it.
const testMFAUser identity.UserID = "u-1"

// testMFACode is the code these tests post. What it means is the method's
// business: the double is told to accept it or to refuse it, and the endpoint
// never looks at it.
const testMFACode = "123456"

// mfaHarness is what an MFA chain is wired to: a real session manager, so a
// rotation genuinely moves a session between handles, and doubles for the two
// collaborators whose calls are the requirement — the method, which must not be
// asked to verify a code the endpoint should have refused first, and the
// limiter the throttle counts failures through.
type mfaHarness struct {
	sessions *session.Manager
	method   *MockMethod
	limiter  *MockLimiter

	// tokens issues the credential a caller carries away from a successful
	// verification, and verifies the one it arrived with. It is one double
	// because token.Generator is a Verifier too, and because the point of
	// these tests is that the two agree about which session a token names.
	tokens *MockGenerator
	users  *MockUserLoader

	// issuedFor is the session identifier the last token was issued against,
	// which after a successful verification is the rotated one.
	issuedFor atomic.Value

	// mfaOpts and logoutOpts are what a case wants configured differently. They
	// are fields rather than arguments so every case assembles the chain the
	// same way and only the configuration under test varies.
	mfaOpts    []httpsec.MFAOption
	logoutOpts []httpsec.LogoutOption

	// resolved is the session the chain published by the time the request left
	// it, which on a successful verification is the rotated one. It is how a
	// test learns the new handle, because the endpoint answers the request and
	// no downstream handler runs to read it.
	resolved *session.Session
}

func newMFAHarness(t *testing.T) *mfaHarness {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	m := NewMockMethod(ctrl)
	m.EXPECT().Name().Return("test-method").AnyTimes()

	h := &mfaHarness{
		sessions: sessions,
		method:   m,
		limiter:  NewMockLimiter(ctrl),
		tokens:   NewMockGenerator(ctrl),
		users:    NewMockUserLoader(ctrl),
	}

	// A token names the session it was issued for, exactly as a real one does
	// through its jti. That is the whole mechanism this group is about: a
	// token issued before a rotation names a session that no longer exists.
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			h.issuedFor.Store(id)

			return mfaTokenFor(id), nil
		})

	h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(mfaUsername, id), nil
		})

	h.users.EXPECT().LoadByUsername(gomock.Any(), mfaUsername).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) {
			return &identity.Details{
				ID:       testMFAUser,
				Name:     "Ada Lovelace",
				Username: mfaUsername,
				Active:   true,
			}, nil
		})

	return h
}

// The shape of a token in these tests: the session identifier it was issued
// for, which is what a real token carries as its jti.
const (
	//nolint:gosec // G101: a prefix a test double puts in front of a session identifier, not a credential
	mfaTokenPrefix = "mfa-token-for:"
	mfaUsername    = "ada"
)

func mfaTokenFor(sessionID string) string { return mfaTokenPrefix + sessionID }

// errMFATokenUnreadable is what the verifier double refuses a token it did not
// issue with.
var errMFATokenUnreadable = errors.New("mfaverify_test: not a token this verifier issued")

// mfaMethod is a method double reporting channel and nothing else, for the
// cases that never reach a verification.
func mfaMethod(t *testing.T, channel factor.Channel) *MockMethod {
	t.Helper()

	m := NewMockMethod(gomock.NewController(t))
	m.EXPECT().Name().Return("test-method").AnyTimes()
	m.EXPECT().Channel().Return(channel).AnyTimes()

	return m
}

// channel fixes what the harness's method reports for its whole lifetime, as
// the port requires.
func (h *mfaHarness) channel(c factor.Channel) *mfaHarness {
	h.method.EXPECT().Channel().Return(c).AnyTimes()

	return h
}

// accepts wires the method to accept the code these tests post.
func (h *mfaHarness) accepts() *mfaHarness {
	h.method.EXPECT().Verify(gomock.Any(), testMFAUser, testMFACode).Return(nil)

	return h
}

// refuses wires the method to refuse the code these tests post.
func (h *mfaHarness) refuses() *mfaHarness {
	h.method.EXPECT().Verify(gomock.Any(), testMFAUser, testMFACode).Return(mfa.ErrInvalidCode)

	return h
}

// neverVerifies pins that the code is not read, let alone checked.
func (h *mfaHarness) neverVerifies() *mfaHarness {
	h.method.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	return h
}

// allows wires the limiter to report the user under their allowance.
func (h *mfaHarness) allows() *mfaHarness {
	h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil)

	return h
}

// throttles wires the limiter to report the user at their limit.
func (h *mfaHarness) throttles() *mfaHarness {
	h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(true, nil)

	return h
}

// neverChecked pins that the throttle is not consulted at all.
func (h *mfaHarness) neverChecked() *mfaHarness {
	h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Times(0)

	return h
}

// recordsFailure pins that exactly one failed verification is counted against
// the user.
func (h *mfaHarness) recordsFailure() *mfaHarness {
	h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(nil)

	return h
}

// recordsNoFailure pins that nothing is counted against the user.
func (h *mfaHarness) recordsNoFailure() *mfaHarness {
	h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Times(0)

	return h
}

// pendingSession is a live session owing a second factor, established by first.
func (h *mfaHarness) pendingSession(t *testing.T, first factor.Kind) *session.Session {
	t.Helper()

	return h.newSession(t, first, session.MFAPending)
}

// newSession creates a live session in state, as a first factor would have.
func (h *mfaHarness) newSession(
	t *testing.T,
	first factor.Kind,
	state session.MFAState,
) *session.Session {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(first))
	require.NoError(t, err)

	s.MFA = state
	require.NoError(t, h.sessions.Save(t.Context(), s))

	return s
}

// stored reloads a session by handle, so a test asserts on what the store holds
// rather than on the object the chain happened to be handed.
func (h *mfaHarness) stored(t *testing.T, handle string) *session.Session {
	t.Helper()

	s, err := h.sessions.Load(t.Context(), handle)
	require.NoError(t, err)

	return s
}

// chain assembles the chain under test: the second factor, a logout to be
// exempt from it, and the session s carried as a first factor would have
// carried it.
func (h *mfaHarness) chain(t *testing.T, s *session.Session) *httpsec.Chain {
	t.Helper()

	mfaOpts := append([]httpsec.MFAOption{
		httpsec.WithMFAVerifyLimiter(h.limiter),
		httpsec.WithMFATokens(h.tokens),
	}, h.mfaOpts...)

	c, err := httpsec.New(
		h.carries(s),
		httpsec.EnableMFA(h.method, mfaOpts...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, h.logoutOpts...),
	)
	require.NoError(t, err)

	return c
}

// carries publishes s on every exchange, standing in for the first factor that
// resolved it, and records what the chain published by the time the request
// left. It is registered immediately outside the MFA slot, which is where a
// first factor would have run.
func (h *mfaHarness) carries(s *session.Session) httpsec.Option {
	carrier := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if s != nil {
			ex.Authentication = &authenticate.Authentication{
				Principal: testPrincipal(),
				Time:      time.Now(),
			}
			ex.Session = s
			ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), s))
		}

		err := next(ex)
		h.resolved = ex.Session

		return err
	})

	return httpsec.RegisterInterceptor(carrier, httpsec.Before(httpsec.OrderMFAChallenge))
}

// postCode is a code submission to path, as a browser form would send it.
func postCode(ctx context.Context, path string) *http.Request {
	return formRequest(ctx, path, "code="+testMFACode)
}

// TestEnableMFA pins what the chain refuses to be built with. Every one of
// these is a wiring mistake whose symptom would otherwise appear far from its
// cause: a method with no channel refuses every verification as same-channel,
// and a limiter that is not there counts no guesses at all.
func TestEnableMFA(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		method func(t *testing.T) mfa.Method
		opts   []httpsec.MFAOption
		// noTokens leaves the token generator out entirely, which is how a
		// case pins what happens to a chain that was never given one.
		noTokens bool
		build    func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error)
		assert   func(t *testing.T, c *httpsec.Chain, err error)
	}

	// withSessions is the ordinary chain: one wired to a session manager, which
	// is what every deployment running a first factor has.
	withSessions := func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error) {
		t.Helper()

		sessions, err := session.NewManager()
		require.NoError(t, err)

		return httpsec.New(opt, httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	}

	authenticator := func(t *testing.T) mfa.Method { return mfaMethod(t, factor.AuthenticatorApp) }

	configError := func(t *testing.T, c *httpsec.Chain, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, c, "a chain that cannot be configured is not half-built")
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name:   "a method with a channel, and nothing else configured",
			method: authenticator,
			assert: built,
		},
		{
			name:   "a consumer's limiter, path and log interval",
			method: authenticator,
			opts: []httpsec.MFAOption{
				httpsec.WithMFAVerifyPath("/auth/second-factor"),
				httpsec.WithMFAVerifyLimiter(NewMockLimiter(gomock.NewController(t))),
				httpsec.WithMFALogInterval(5 * time.Minute),
			},
			assert: built,
		},
		{
			name:   "an empty channel",
			method: func(t *testing.T) mfa.Method { return mfaMethod(t, "") },
			assert: configError,
		},
		{
			name:   "a nil method",
			method: func(*testing.T) mfa.Method { return nil },
			assert: configError,
		},
		{
			name:   "a typed-nil method",
			method: func(*testing.T) mfa.Method { return (*MockMethod)(nil) },
			assert: configError,
		},
		{
			name:   "a nil limiter",
			method: authenticator,
			opts:   []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(nil)},
			assert: configError,
		},
		{
			name:   "a limiter interface holding a nil pointer",
			method: authenticator,
			opts:   []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert: configError,
		},
		{
			name:   "an empty verify path",
			method: authenticator,
			opts:   []httpsec.MFAOption{httpsec.WithMFAVerifyPath("")},
			assert: configError,
		},
		{
			name:     "no token generator",
			method:   authenticator,
			noTokens: true,
			assert:   configError,
		},
		{
			name:   "a nil token generator",
			method: authenticator,
			opts:   []httpsec.MFAOption{httpsec.WithMFATokens(nil)},
			assert: configError,
		},
		{
			name:   "a token generator interface holding a nil pointer",
			method: authenticator,
			opts:   []httpsec.MFAOption{httpsec.WithMFATokens((*MockGenerator)(nil))},
			assert: configError,
		},
		{
			name:   "a chain with no session manager",
			method: authenticator,
			build: func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error) {
				t.Helper()

				return httpsec.New(opt)
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			build := tc.build
			if build == nil {
				build = withSessions
			}

			// Every chain that is expected to build needs a generator, because
			// a rotated handle has to be handed back as a credential. A row
			// that configures the generator itself still applies after this
			// one, so its own refusal is what the case sees.
			opts := tc.opts
			if !tc.noTokens {
				opts = append([]httpsec.MFAOption{
					httpsec.WithMFATokens(NewMockGenerator(gomock.NewController(t))),
				}, opts...)
			}

			c, err := build(t, httpsec.EnableMFA(tc.method(t), opts...))
			tc.assert(t, c, err)
		})
	}
}

// TestMFAVerifyOrdering pins the order the endpoint judges a code submission
// in. The order is the requirement, so each case asserts what the step it stops
// at did and what the steps behind it did not do: a refusal that has already
// read the code, or counted it against the user, has leaked something the
// caller never had to earn.
func TestMFAVerifyOrdering(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		channel factor.Channel
		session func(t *testing.T, h *mfaHarness) *session.Session
		wire    func(t *testing.T, h *mfaHarness)
		assert  func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	noSession := func(*testing.T, *mfaHarness) *session.Session { return nil }

	pendingAfter := func(first factor.Kind) func(*testing.T, *mfaHarness) *session.Session {
		return func(t *testing.T, h *mfaHarness) *session.Session {
			t.Helper()

			return h.pendingSession(t, first)
		}
	}

	cases := []testCase{
		{
			name:    "no session",
			channel: factor.AuthenticatorApp,
			session: noSession,
			wire: func(_ *testing.T, h *mfaHarness) {
				// Nothing is read and nothing is counted: there is no session
				// to add a second factor to, and no user to count against.
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, _ *mfaHarness, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:    "the method's channel is the first factor's",
			channel: factor.Email,
			session: pendingAfter(factor.MagicLink),
			wire: func(_ *testing.T, h *mfaHarness) {
				// The code is not read, let alone verified, and no failure is
				// recorded: the user has not failed anything, the deployment
				// has.
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA,
					"the challenge stays pending")
			},
		},
		{
			name:    "the user is throttled",
			channel: factor.AuthenticatorApp,
			session: pendingAfter(factor.Password),
			wire: func(_ *testing.T, h *mfaHarness) {
				// A throttled user's code is not checked: guessing costs
				// attempts, not time.
				h.throttles().neverVerifies().recordsNoFailure()
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name:    "a wrong code records a failure",
			channel: factor.AuthenticatorApp,
			session: pendingAfter(factor.Password),
			wire: func(_ *testing.T, h *mfaHarness) {
				h.allows().refuses().recordsFailure()
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode,
					"the method's own sentinel reaches the consumer unchanged")
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name:    "a valid code records no failure",
			channel: factor.AuthenticatorApp,
			session: pendingAfter(factor.Password),
			wire: func(_ *testing.T, h *mfaHarness) {
				// A user who gets it right has not guessed, so nothing is spent.
				h.allows().accepts().recordsNoFailure()
			},
			assert: func(t *testing.T, _ *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.False(t, out.handlerRan,
					"the endpoint is this library's own, so the application never sees it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(tc.channel)

			s := tc.session(t, h)
			tc.wire(t, h)

			out := serve(t, h.chain(t, s), postCode(t.Context(), httpsec.DefaultMFAVerifyPath))
			tc.assert(t, h, s, out)
		})
	}
}

// TestMFAVerifySameChannel pins the rule that has no override: a code arriving
// the way the first factor did is not a second factor, whoever configured it.
// The two cases differ only in the method's channel, which is the whole point.
func TestMFAVerifySameChannel(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		channel factor.Channel
		wire    func(t *testing.T, h *mfaHarness)
		assert  func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	cases := []testCase{
		{
			name:    "an email code after a magic-link login is refused",
			channel: factor.Email,
			wire: func(_ *testing.T, h *mfaHarness) {
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
		{
			name:    "an authenticator code after a magic-link login proceeds",
			channel: factor.AuthenticatorApp,
			wire: func(_ *testing.T, h *mfaHarness) {
				h.allows().accepts().recordsNoFailure()
			},
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				require.NotNil(t, h.resolved)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(tc.channel)

			s := h.pendingSession(t, factor.MagicLink)
			tc.wire(t, h)

			out := serve(t, h.chain(t, s), postCode(t.Context(), httpsec.DefaultMFAVerifyPath))
			tc.assert(t, h, s, out)
		})
	}
}

// TestMFAVerifySuccess pins what a valid code changes: the challenge is
// resolved with the time it was resolved at, and the handle the caller reached
// the endpoint with no longer works. A handle obtained before the second factor
// must not survive it.
func TestMFAVerifySuccess(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

	s := h.pendingSession(t, factor.Password)
	previous := s.ID

	out := serve(t, h.chain(t, s), postCode(t.Context(), httpsec.DefaultMFAVerifyPath))

	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.False(t, out.handlerRan, "the request does not reach later handlers")

	require.NotNil(t, h.resolved, "the new handle is published on the exchange")
	assert.NotEqual(t, previous, h.resolved.ID)

	_, err := h.sessions.Load(t.Context(), previous)
	require.Error(t, err, "the previous handle no longer loads")

	rotated := h.stored(t, h.resolved.ID)
	assert.Equal(t, session.MFASatisfied, rotated.MFA)
	assert.False(t, rotated.MFASatisfiedAt.IsZero(), "the satisfied time is recorded")
	assert.Equal(t, testMFAUser, rotated.UserID, "everything else is carried over")
	assert.Equal(t, factor.Password, rotated.FirstFactor)
}

// TestMFAVerifyFailure pins that a refusal leaves everything as it was, and
// that only a POST is a verification.
func TestMFAVerifyFailure(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		session func(t *testing.T, h *mfaHarness) *session.Session
		request func(ctx context.Context) *http.Request
		wire    func(t *testing.T, h *mfaHarness)
		assert  func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	cases := []testCase{
		{
			name: "a wrong code changes nothing",
			session: func(t *testing.T, h *mfaHarness) *session.Session {
				t.Helper()

				return h.pendingSession(t, factor.Password)
			},
			request: func(ctx context.Context) *http.Request {
				return postCode(ctx, httpsec.DefaultMFAVerifyPath)
			},
			wire: func(_ *testing.T, h *mfaHarness) { h.allows().refuses().recordsFailure() },
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)

				still := h.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, still.MFA, "the challenge stays pending")
				assert.True(t, still.MFASatisfiedAt.IsZero())
				assert.Equal(t, s.ID, h.resolved.ID, "the handle is unchanged")
			},
		},
		{
			// The session here owes nothing, because a GET made by a session
			// that does owe a second factor is held by the gate — which is the
			// gate's own requirement, pinned in TestMFAGate. What this case
			// pins is narrower: a GET is not a verification.
			name: "a GET to the verify path passes through",
			session: func(t *testing.T, h *mfaHarness) *session.Session {
				t.Helper()

				return h.newSession(t, factor.Password, session.MFANone)
			},
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(
					ctx, http.MethodGet, httpsec.DefaultMFAVerifyPath, nil)
			},
			wire: func(_ *testing.T, h *mfaHarness) {
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, _ *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the request continues to the application")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			s := tc.session(t, h)
			tc.wire(t, h)

			out := serve(t, h.chain(t, s), tc.request(t.Context()))
			tc.assert(t, h, s, out)
		})
	}
}

// TestMFAVerifyConsumerPath pins that the endpoint moves when the consumer
// moves it — and that it moves rather than being copied: the default path is
// then an ordinary route, gated like any other.
func TestMFAVerifyConsumerPath(t *testing.T) {
	t.Parallel()

	const consumerPath = "/auth/second-factor"

	type testCase struct {
		name   string
		path   string
		wire   func(t *testing.T, h *mfaHarness)
		assert func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	cases := []testCase{
		{
			name: "a code posted to the consumer's path resolves the challenge",
			path: consumerPath,
			wire: func(_ *testing.T, h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				require.NotNil(t, h.resolved)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
		{
			name: "the default path is no longer the endpoint",
			path: httpsec.DefaultMFAVerifyPath,
			wire: func(_ *testing.T, h *mfaHarness) {
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch, "it is an ordinary route, held by the gate")
				assert.False(t, out.handlerRan)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAVerifyPath(consumerPath)}

			s := h.pendingSession(t, factor.Password)
			tc.wire(t, h)

			out := serve(t, h.chain(t, s), postCode(t.Context(), tc.path))
			tc.assert(t, h, s, out)
		})
	}
}
