package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// testMFAUser is who the second factor is being verified for. It is the
// consumer's own reference, and the throttle's bucket key is composed from it.
const testMFAUser identity.UserID = "u-1"

// testMFAVerifyPath is where the harness's method, named "totp" as the
// built-in TOTP method is, is verified under the default prefix.
const testMFAVerifyPath = httpsec.DefaultMFAVerifyPrefix + "/totp"

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

	// response is the format the method declares: TOTP's form field unless a
	// case declares another.
	response mfa.ResponseFormat

	// extra are methods configured after the harness's own, in order.
	extra []mfa.Method

	// totpUnenrolled makes the harness's method report the user not enrolled,
	// as after an operator removed the enrolment. It is set before the chain
	// serves anything.
	totpUnenrolled bool

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

	// chainOpts are chain options the bearer chain is also built with, such
	// as a logger a case reads back.
	chainOpts []httpsec.Option

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
	m.EXPECT().Name().Return("totp").AnyTimes()

	h := &mfaHarness{
		sessions: sessions,
		method:   m,
		response: mfa.FormField("code", 4<<10),
		limiter:  NewMockLimiter(ctrl),
		tokens:   NewMockGenerator(ctrl),
		users:    NewMockUserLoader(ctrl),
	}

	// The format is read when the chain is built and on every request, so a
	// case that declares another sets h.response before building the chain.
	m.EXPECT().Response().AnyTimes().DoAndReturn(func() mfa.ResponseFormat { return h.response })

	// The user is enrolled on the harness's method, so it is usable whenever
	// its channel differs from the first factor's. A case about enrolment
	// configures a method of its own in h.extra.
	m.EXPECT().Enrolled(gomock.Any(), testMFAUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (bool, error) { return !h.totpUnenrolled, nil })

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
	m.EXPECT().Name().Return("totp").AnyTimes()
	m.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	m.EXPECT().Channel().Return(channel).AnyTimes()

	return m
}

// emailCodeMethod is a second method double: an emailed one-time code named
// "email-code", on the email channel, read from the same form field TOTP is.
// Whether the user is enrolled on it, and what it answers, is each case's own.
func emailCodeMethod(t *testing.T) *MockMethod {
	t.Helper()

	m := NewMockMethod(gomock.NewController(t))
	m.EXPECT().Name().Return("email-code").AnyTimes()
	m.EXPECT().Channel().Return(factor.Email).AnyTimes()
	m.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()

	return m
}

// unreadBody is a request body that fails the test the moment anything reads
// it, for the refusals that must be decided before the body is touched.
type unreadBody struct{ t *testing.T }

func (b unreadBody) Read([]byte) (int, error) {
	b.t.Error("the request body was read before the request was refused")

	return 0, io.EOF
}

// postUnread is a POST to target whose body must never be read.
func postUnread(ctx context.Context, t *testing.T, target string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, target, unreadBody{t: t})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

// channel fixes what the harness's method reports for its whole lifetime, as
// the port requires.
func (h *mfaHarness) channel(c factor.Channel) *mfaHarness {
	h.method.EXPECT().Channel().Return(c).AnyTimes()

	return h
}

// accepts wires the method to accept the code these tests post.
func (h *mfaHarness) accepts() *mfaHarness {
	h.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)

	return h
}

// refuses wires the method to refuse the code these tests post.
func (h *mfaHarness) refuses() *mfaHarness {
	h.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(mfa.ErrInvalidCode)

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
		httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extra...), mfaOpts...),
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
		name    string
		methods func(t *testing.T) []mfa.Method
		opts    []httpsec.MFAOption
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

	// one is a set of the single method m makes.
	one := func(m func(t *testing.T) mfa.Method) func(t *testing.T) []mfa.Method {
		return func(t *testing.T) []mfa.Method { return []mfa.Method{m(t)} }
	}

	authenticator := one(func(t *testing.T) mfa.Method { return mfaMethod(t, factor.AuthenticatorApp) })

	// authenticatorAnd is the authenticator plus a second method named name.
	authenticatorAnd := func(name string) func(t *testing.T) []mfa.Method {
		return func(t *testing.T) []mfa.Method {
			second := NewMockMethod(gomock.NewController(t))
			second.EXPECT().Name().Return(name).AnyTimes()
			second.EXPECT().Channel().Return(factor.Email).AnyTimes()
			second.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()

			return []mfa.Method{mfaMethod(t, factor.AuthenticatorApp), second}
		}
	}

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
			name:    "a method with a channel, and nothing else configured",
			methods: authenticator,
			assert:  built,
		},
		{
			name:    "a consumer's limiter, prefix and log interval",
			methods: authenticator,
			opts: []httpsec.MFAOption{
				httpsec.WithMFAVerifyPrefix("/auth/second-factor"),
				httpsec.WithMFAVerifyLimiter(NewMockLimiter(gomock.NewController(t))),
				httpsec.WithMFALogInterval(5 * time.Minute),
			},
			assert: built,
		},
		{
			name:    "an empty channel",
			methods: one(func(t *testing.T) mfa.Method { return mfaMethod(t, "") }),
			assert:  configError,
		},
		{
			name:    "a nil method",
			methods: one(func(*testing.T) mfa.Method { return nil }),
			assert:  configError,
		},
		{
			name:    "a typed-nil method",
			methods: one(func(*testing.T) mfa.Method { return (*MockMethod)(nil) }),
			assert:  configError,
		},
		{
			name:    "a nil limiter",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(nil)},
			assert:  configError,
		},
		{
			name:    "a limiter interface holding a nil pointer",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter((*ratelimit.MemoryLimiter)(nil))},
			assert:  configError,
		},
		{
			name:    "two methods on different paths",
			methods: authenticatorAnd("email-code"),
			assert:  built,
		},
		{
			name:    "no methods",
			methods: func(*testing.T) []mfa.Method { return nil },
			assert:  configError,
		},
		{
			name:    "two methods sharing a name",
			methods: authenticatorAnd("totp"),
			assert:  configError,
		},
		{
			// A format with no room for a response could never be read, so
			// every verification on the method would be refused as too large.
			name: "a method declaring a malformed response format",
			methods: one(func(t *testing.T) mfa.Method {
				m := NewMockMethod(gomock.NewController(t))
				m.EXPECT().Name().Return("totp").AnyTimes()
				m.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
				m.EXPECT().Response().Return(mfa.FormField("code", 0)).AnyTimes()

				return m
			}),
			assert: configError,
		},
		{
			name:    "an empty verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("")},
			assert:  configError,
		},
		{
			name:    "the root as the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("/")},
			assert:  configError,
		},
		{
			name:    "a verify prefix without a leading slash",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix("mfa")},
			assert:  configError,
		},
		{
			// The verify endpoint would answer the logout request first, so a
			// pending session could never log out.
			name:    "a verify prefix that is the logout path",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(httpsec.DefaultLogoutPath)},
			assert:  configError,
		},
		{
			name:    "a logout path under the verify prefix",
			methods: authenticator,
			build: func(t *testing.T, opt httpsec.Option) (*httpsec.Chain, error) {
				t.Helper()

				sessions, err := session.NewManager()
				require.NoError(t, err)

				return httpsec.New(opt, httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions},
					httpsec.WithLogoutRequestPath(httpsec.DefaultMFAVerifyPrefix+"/logout")))
			},
			assert: configError,
		},
		{
			name:    "a consumer's begin prefix, challenge lifetime, store and responder",
			methods: authenticator,
			opts: []httpsec.MFAOption{
				httpsec.WithMFABeginPrefix("/auth/second-factor/begin"),
				httpsec.WithMFAChallengeTTL(2 * time.Minute),
				httpsec.WithMFAChallengeStore(onetime.NewMemoryStore()),
				httpsec.WithMFABeginResponder(func(*httpsec.Exchange, json.RawMessage) error { return nil }),
			},
			assert: built,
		},
		{
			name:    "an empty begin prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("")},
			assert:  configError,
		},
		{
			name:    "the root as the begin prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("/")},
			assert:  configError,
		},
		{
			name:    "a begin prefix without a leading slash",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("mfa/begin")},
			assert:  configError,
		},
		{
			// Every POST under the verify prefix is the verify endpoint's, so
			// no begin could ever be reached.
			name:    "a begin prefix equal to the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultMFAVerifyPrefix + "/")},
			assert:  configError,
		},
		{
			name:    "a verify prefix moved onto the begin prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(httpsec.DefaultMFABeginPrefix)},
			assert:  configError,
		},
		{
			name:    "a begin prefix under the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultMFAVerifyPrefix + "/begin")},
			assert:  configError,
		},
		{
			// The verify prefix sits under this one, so every begin POST
			// there would be the verify endpoint's.
			name:    "a begin prefix above the verify prefix",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix("/mfa")},
			assert:  configError,
		},
		{
			name:    "a begin prefix that is the logout path",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginPrefix(httpsec.DefaultLogoutPath)},
			assert:  configError,
		},
		{
			name:    "a consumer challenge limit",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(3)},
			assert:  built,
		},
		{
			name:    "a challenge limit of zero",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(0)},
			assert:  configError,
		},
		{
			name:    "a negative challenge limit",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(-1)},
			assert:  configError,
		},
		{
			name:    "a challenge lifetime of zero",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeTTL(0)},
			assert:  configError,
		},
		{
			name:    "a negative challenge lifetime",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeTTL(-time.Minute)},
			assert:  configError,
		},
		{
			name:    "a nil challenge store",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeStore(nil)},
			assert:  configError,
		},
		{
			name:    "a challenge store interface holding a nil pointer",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFAChallengeStore((*onetime.MemoryStore)(nil))},
			assert:  configError,
		},
		{
			name:    "a nil begin responder",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFABeginResponder(nil)},
			assert:  configError,
		},
		{
			name:     "no token generator",
			methods:  authenticator,
			noTokens: true,
			assert:   configError,
		},
		{
			name:    "a nil token generator",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFATokens(nil)},
			assert:  configError,
		},
		{
			name:    "a token generator interface holding a nil pointer",
			methods: authenticator,
			opts:    []httpsec.MFAOption{httpsec.WithMFATokens((*MockGenerator)(nil))},
			assert:  configError,
		},
		{
			name:    "a chain with no session manager",
			methods: authenticator,
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

			c, err := build(t, httpsec.EnableMFA(tc.methods(t), opts...))
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
		// unread posts a body that fails the test if it is read, for the
		// refusals decided before the body is touched.
		unread bool
		assert func(t *testing.T, h *mfaHarness, s *session.Session, out served)
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
			unread:  true,
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

			req := postCode(t.Context(), testMFAVerifyPath)
			if tc.unread {
				req = postUnread(t.Context(), t, testMFAVerifyPath)
			}

			out := serve(t, h.chain(t, s), req)
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

			out := serve(t, h.chain(t, s), postCode(t.Context(), testMFAVerifyPath))
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

	out := serve(t, h.chain(t, s), postCode(t.Context(), testMFAVerifyPath))

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
				return postCode(ctx, testMFAVerifyPath)
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
					ctx, http.MethodGet, testMFAVerifyPath, nil)
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

// TestMFAVerify pins the verify endpoint over a method set: TOTP (the
// harness's method) and an emailed code, each at its own path under the
// prefix. The method is read from the path and nowhere else, and every refusal
// that can be decided from the path and the session is decided before the body
// is read and without counting anything against the user.
func TestMFAVerify(t *testing.T) {
	t.Parallel()

	const consumerPrefix = "/auth/second-factor"

	errLookup := errors.New("mfaverify_test: enrolment store unavailable for alice@example.com")

	type testCase struct {
		name string
		// first is the session's first factor; zero means a password.
		first factor.Kind
		// owesNothing starts the session with no MFA challenge pending.
		owesNothing bool
		mfaOpts     []httpsec.MFAOption
		request     func(ctx context.Context, t *testing.T) *http.Request
		wire        func(h *mfaHarness, email *MockMethod)
		assert      func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	postTo := func(target string) func(ctx context.Context, t *testing.T) *http.Request {
		return func(ctx context.Context, _ *testing.T) *http.Request { return postCode(ctx, target) }
	}

	unread := func(target string) func(ctx context.Context, t *testing.T) *http.Request {
		return func(ctx context.Context, t *testing.T) *http.Request { return postUnread(ctx, t, target) }
	}

	// untouched is the wiring of every refusal decided before the body: no
	// method verifies, the throttle is not consulted and nothing is counted.
	untouched := func(h *mfaHarness, email *MockMethod) {
		h.neverVerifies().neverChecked().recordsNoFailure()
		email.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	}

	enrolledOnEmail := func(email *MockMethod, enrolled bool) {
		email.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(enrolled, nil).AnyTimes()
	}

	resolved := func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)
		assert.False(t, out.handlerRan, "the endpoint answers the request itself")
		require.NotNil(t, h.resolved)
		assert.NotEqual(t, s.ID, h.resolved.ID, "the handle is rotated")
		assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)

		_, err := h.sessions.Load(t.Context(), s.ID)
		require.Error(t, err, "the previous handle no longer loads")
	}

	refusedAs := func(sentinel error, status int) func(*testing.T, *mfaHarness, *session.Session, served) {
		return func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, sentinel)
			assert.Equal(t, status, httpsec.StatusForError(out.err))
			assert.False(t, out.handlerRan)
			assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
		}
	}

	unknown := refusedAs(httpsec.ErrUnknownMFAMethod, http.StatusNotFound)

	cases := []testCase{
		{
			name:    "a valid code to TOTP's path",
			request: postTo(httpsec.DefaultMFAVerifyPrefix + "/totp"),
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, false)
				h.allows().accepts().recordsNoFailure()
				email.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			assert: resolved,
		},
		{
			name:    "a valid code to the emailed code's path",
			request: postTo(httpsec.DefaultMFAVerifyPrefix + "/email-code"),
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, true)
				h.allows().neverVerifies().recordsNoFailure()
				email.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)
			},
			assert: resolved,
		},
		{
			name:    "a method no one configured",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/sms"),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "a method named in another case",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/TOTP"),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "the bare prefix",
			request: unread(httpsec.DefaultMFAVerifyPrefix),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "an empty segment",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/"),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "a trailing slash after the method",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/totp/"),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "an extra segment after the method",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/totp/x"),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "an empty segment before the method",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "//totp"),
			wire:    untouched,
			assert:  unknown,
		},
		{
			name:    "a method the user is not enrolled on",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/email-code"),
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, false)
				untouched(h, email)
			},
			assert: refusedAs(httpsec.ErrMFAMethodNotUsable, http.StatusForbidden),
		},
		{
			name:    "the emailed code after a magic-link login",
			first:   factor.MagicLink,
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/email-code"),
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, true)
				untouched(h, email)
			},
			assert: refusedAs(mfa.ErrSameChannel, http.StatusForbidden),
		},
		{
			name:    "an enrolment lookup that fails",
			request: unread(httpsec.DefaultMFAVerifyPrefix + "/email-code"),
			wire: func(h *mfaHarness, email *MockMethod) {
				email.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(false, errLookup).AnyTimes()
				untouched(h, email)
			},
			// The dependency's text stays out of the refusal; its error stays
			// reachable.
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				refusedAs(errLookup, http.StatusInternalServerError)(t, h, s, out)
				assert.NotContains(t, out.err.Error(), "alice@example.com")
			},
		},
		{
			name: "a method named in the query or the body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return formRequest(ctx, httpsec.DefaultMFAVerifyPrefix+"/totp?method=email-code",
					"code="+testMFACode+"&method=email-code")
			},
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, true)
				h.allows().accepts().recordsNoFailure()
				email.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
			},
			assert: resolved,
		},
		{
			// The session owes nothing, because a GET from one that does is held
			// by the gate, which is the gate's own requirement. What this pins
			// is narrower: a GET is not a verification.
			name:        "a GET to a verify path",
			owesNothing: true,
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet,
					httpsec.DefaultMFAVerifyPrefix+"/totp", nil)
			},
			wire: untouched,
			assert: func(t *testing.T, _ *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the request continues to the application")
			},
		},
		{
			name:    "a valid code under the consumer's prefix",
			mfaOpts: []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(consumerPrefix)},
			request: postTo(consumerPrefix + "/totp"),
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, false)
				h.allows().accepts().recordsNoFailure()
			},
			assert: resolved,
		},
		{
			name:    "a consumer's prefix given with a trailing slash",
			mfaOpts: []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(consumerPrefix + "/")},
			request: postTo(consumerPrefix + "/totp"),
			wire: func(h *mfaHarness, email *MockMethod) {
				enrolledOnEmail(email, false)
				h.allows().accepts().recordsNoFailure()
			},
			assert: resolved,
		},
		{
			// The endpoint moves rather than being copied: the default path
			// is then an ordinary route, held by the gate like any other.
			name:    "the default prefix once the consumer has moved it",
			mfaOpts: []httpsec.MFAOption{httpsec.WithMFAVerifyPrefix(consumerPrefix)},
			request: postTo(httpsec.DefaultMFAVerifyPrefix + "/totp"),
			wire: func(h *mfaHarness, email *MockMethod) {
				untouched(h, email)
				// The gate's challenge lists the methods the user can use.
				enrolledOnEmail(email, false)
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
			h.mfaOpts = tc.mfaOpts

			email := emailCodeMethod(t)
			h.extra = []mfa.Method{email}

			first := tc.first
			if first == "" {
				first = factor.Password
			}

			state := session.MFAPending
			if tc.owesNothing {
				state = session.MFANone
			}

			s := h.newSession(t, first, state)
			tc.wire(h, email)

			out := serve(t, h.chain(t, s), tc.request(t.Context(), t))
			tc.assert(t, h, s, out)
		})
	}
}

// TestMFAVerifyThrottleAcrossMethods pins that the verification throttle is
// one count per user, whichever method the guesses were made against: a
// throttle per method would multiply an attacker's guesses by the number of
// methods configured.
func TestMFAVerifyThrottleAcrossMethods(t *testing.T) {
	t.Parallel()

	limiter, err := ratelimit.NewMemoryLimiter(5, 15*time.Minute)
	require.NoError(t, err)

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp)
	h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(limiter)}

	email := emailCodeMethod(t)
	email.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
	email.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).Return(mfa.ErrInvalidCode).Times(2)
	h.extra = []mfa.Method{email}

	// Three wrong answers to TOTP; the valid code that follows is never
	// checked, because by then the user is at the limit.
	h.method.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).Return(mfa.ErrInvalidCode).Times(3)

	s := h.pendingSession(t, factor.Password)
	c := h.chain(t, s)

	for _, path := range []string{"/totp", "/totp", "/totp", "/email-code", "/email-code"} {
		out := serve(t, c, postCode(t.Context(), httpsec.DefaultMFAVerifyPrefix+path))
		require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
	}

	out := serve(t, c, postCode(t.Context(), httpsec.DefaultMFAVerifyPrefix+"/totp"))

	require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
	assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
}
