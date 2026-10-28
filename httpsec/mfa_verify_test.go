package httpsec_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/onetime"
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
	// clock is the time the harness's sessions and its chain share. A case
	// that moves time advances it; no case sleeps.
	clock *clockwork.FakeClock
	// systemClock builds the chain without WithClock, for the one case about
	// what a chain reads by default.
	systemClock bool
	sessions    *session.Sessions
	method      *MockMethod
	limiter     *MockLimiter

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

	// It starts at the present, so a session is as fresh on it as it would be
	// on the system clock.
	clk := clockwork.NewFakeClockAt(time.Now().Truncate(time.Minute))

	sessions, err := session.New(session.WithClock(clk))
	require.NoError(t, err)

	m := NewMockMethod(ctrl)
	m.EXPECT().Name().Return("totp").AnyTimes()

	h := &mfaHarness{
		clock:    clk,
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
//
// Its own table: its rows build the chain from bare methods and options,
// without the MFA harness the other tables here use.
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

		sessions, err := session.New()
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

				sessions, err := session.New()
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
//
// Not rows of TestMFAVerify: its rows run one method at the harness's channel
// and may post a body that must stay unread, where that table's run a method
// set.
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
//
// Its own table: its two rows differ only in the method's channel, and kept
// side by side they are the proof of the rule.
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
//
// Not a row of TestMFAVerifyFailure: it compares the session after the request
// with its state before it, which the chain rewrites, and that table's rows see
// only the session after.
func TestMFAVerifySuccess(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

	s := h.pendingSession(t, factor.Password)
	previous := s.ID
	signedIn := s.AuthenticatedAt

	h.clock.Advance(5 * time.Minute)
	out := serve(t, h.chain(t, s), postCode(t.Context(), testMFAVerifyPath))

	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
	assert.False(t, out.handlerRan, "the request does not reach later handlers")

	require.NotNil(t, h.resolved, "the new handle is published on the exchange")
	assert.NotEqual(t, previous, h.resolved.ID)

	_, err := h.sessions.Load(t.Context(), previous)
	require.Error(t, err, "the previous handle no longer loads")

	rotated := h.stored(t, h.resolved.ID)
	assert.Equal(t, session.MFASatisfied, rotated.MFA)
	assert.False(t, rotated.MFASatisfiedAt.IsZero(), "the satisfied time is recorded")
	// This chain reads the system clock, which is past the harness's
	// minute-truncated sign-in time, so the two are told apart.
	assert.True(t, rotated.AuthenticatedAt.Equal(rotated.MFASatisfiedAt),
		"satisfying the second factor refreshes the authentication time: got %s, satisfied %s",
		rotated.AuthenticatedAt, rotated.MFASatisfiedAt)
	assert.True(t, rotated.AuthenticatedAt.After(signedIn), "the authentication time moved on from the sign-in's")
	// The successor is a record written at the rotation: its creation time
	// is the rotation's, while the sign-in's time lives in AuthenticatedAt
	// (refreshed above) and MFASatisfiedAt.
	assert.True(t, rotated.CreatedAt.Equal(h.clock.Now()),
		"the successor's creation time is when it was written: got %s, rotated at %s", rotated.CreatedAt, h.clock.Now())
	assert.True(t, rotated.CreatedAt.After(s.CreatedAt), "the successor is a newer record than the one it replaced")
	assert.Equal(t, testMFAUser, rotated.UserID, "everything else is carried over")
	assert.Equal(t, factor.Password, rotated.FirstFactor)
}

// TestMFAVerifyFailure pins that a refusal leaves everything as it was, and
// that only a POST is a verification.
//
// Not rows of TestMFAVerifyOrdering: its rows choose their own request, a GET
// among them, where that table's always post a code.
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
//
// Not a row of TestMFAVerify: it serves six requests through one chain, where
// that table's rows serve one each.
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

// TestMFAVerifyRotationRefusals pins what a second factor verified on a
// session that a renewal has already superseded is answered with. Inside the
// renewal's window the strict rotation refuses it as a lost renewal race, a
// 409 the client retries with the credential it now holds; after the window
// it is reuse, a 401. A session that vanished from the store between the
// endpoint's load and the rotation, its family revoked in between, is a
// session the caller no longer holds: a 401 too. None is a server fault.
//
// Its own table: each row races a renewal against the verification before the
// request, which no other verify table sets up.
func TestMFAVerifyRotationRefusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		after time.Duration

		// vanishes deletes the session from the store once the endpoint holds
		// it, before the rotation.
		vanishes bool
		assert   func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:     "the session vanished before the rotation",
			vanishes: true,
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, out.err, session.ErrNotFound)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name:  "inside the renewal's window",
			after: 10 * time.Second,
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
				require.ErrorIs(t, out.err, session.ErrRenewalConflict)
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))
			},
		},
		{
			name:  "after the renewal's window",
			after: 31 * time.Second,
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, out.err, session.ErrReused)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

			s := h.pendingSession(t, factor.Password)

			// A renewal of the same session, racing the verification: the
			// verification still holds the session as it was before.
			if tc.vanishes {
				require.NoError(t, h.sessions.Delete(t.Context(), s.ID))
			} else {
				racing := *s
				_, _, err := h.sessions.RotateWithGrace(t.Context(), &racing, 30*time.Second)
				require.NoError(t, err)
			}

			h.clock.Advance(tc.after)

			was := *s
			tc.assert(t, serve(t, h.chain(t, s), postCode(t.Context(), testMFAVerifyPath)))

			// A refused rotation leaves the session the caller holds as it
			// was: the second factor is not recorded on it.
			assert.Equal(t, was.MFA, s.MFA, "the second-factor state is rolled back")
			assert.True(t, s.MFASatisfiedAt.Equal(was.MFASatisfiedAt), "the satisfied time is rolled back: got %s", s.MFASatisfiedAt)
			assert.True(t, s.AuthenticatedAt.Equal(was.AuthenticatedAt), "the authentication time is rolled back: got %s", s.AuthenticatedAt)
		})
	}
}

// TestMFAGate pins what a session owing a second factor may still do. It may
// not reach the application, and the refusal carries the session so a consumer
// can prompt on it.
func TestMFAGate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		state session.MFAState
		// noSession carries no session at all.
		noSession bool
		request   func(ctx context.Context) *http.Request
		assert    func(t *testing.T, s *session.Session, out served)
	}

	get := func(path string) func(ctx context.Context) *http.Request {
		return func(ctx context.Context) *http.Request {
			return httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		}
	}

	challenged := func(t *testing.T, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeMFA, ch.Kind)
		require.NotNil(t, ch.Session, "the consumer prompting for the code reads who is challenged")
		assert.Equal(t, s.ID, ch.Session.ID)
		assert.Empty(t, ch.Token,
			"a gate challenges a session that already exists, so it issues nothing")
		assert.False(t, out.handlerRan, "the route's handler is not called")
	}

	passedThrough := func(t *testing.T, _ *session.Session, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the request continues to the application untouched")
	}

	cases := []testCase{
		{
			name:    "a pending session requesting a protected route",
			state:   session.MFAPending,
			request: get("/invoices"),
			assert:  challenged,
		},
		{
			name:  "a pending session posting to a protected route",
			state: session.MFAPending,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/invoices", "amount=10")
			},
			assert: challenged,
		},
		{
			// The exemption is the POST that submits a code, not the path. A
			// consumer serving their own page there serves it to sessions that
			// owe nothing; a session that owes one is held here like anywhere
			// else.
			name:    "a pending session reading the verify path",
			state:   session.MFAPending,
			request: get(testMFAVerifyPath),
			assert:  challenged,
		},
		{
			name:    "a session owing nothing",
			state:   session.MFANone,
			request: get("/invoices"),
			assert:  passedThrough,
		},
		{
			name:    "a session that has already satisfied its second factor",
			state:   session.MFASatisfied,
			request: get("/invoices"),
			assert:  passedThrough,
		},
		{
			// The gate guards sessions and nothing else: a request carrying
			// none is the business of the authentication interceptors outside
			// it, and refusing it here would report a challenge nobody owes.
			name:      "anonymous",
			noSession: true,
			request:   get("/invoices"),
			assert: func(t *testing.T, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

			var s *session.Session
			if !tc.noSession {
				s = h.newSession(t, factor.Password, tc.state)
			}

			tc.assert(t, s, serve(t, h.chain(t, s), tc.request(t.Context())))
		})
	}
}

// TestMFAGateLogoutExempt pins the one request a pending session may always
// make besides the code submission.
//
// The gate's slot is outside logout's, so without the exemption a caller
// stranded mid-challenge could not end their own session — on a device that is
// not theirs, the one thing they most need to do. The path comes from the
// chain's own logout configuration, so a consumer who moves the endpoint moves
// the exemption with it and the two cannot drift apart.
//
// Not rows of TestMFAGate: its rows move logout's path, and every row asserts
// the session ended.
func TestMFAGateLogoutExempt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		logoutOpts []httpsec.LogoutOption
		path       string
	}

	cases := []testCase{
		{name: "the default logout path", path: httpsec.DefaultLogoutPath},
		{
			name:       "a consumer logout path",
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			path:       "/auth/sign-out",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()
			h.logoutOpts = tc.logoutOpts

			s := h.pendingSession(t, factor.Password)

			out := serve(t, h.chain(t, s), formRequest(t.Context(), tc.path, ""))

			require.NoError(t, out.err, "a pending session must always be able to log out")
			assert.Equal(t, http.StatusOK, out.rec.Code)

			_, err := h.sessions.Load(t.Context(), s.ID)
			require.Error(t, err, "the session is ended, pending challenge included")
		})
	}
}

// TestMFAGateVerifyExempt pins that the gate never refuses a code submission
// to any configured method, whatever slot either half is placed at: they are
// one interceptor, so the challenge cannot be made unsatisfiable by ordering.
// A path under the verify prefix naming no method is the endpoint's to refuse
// as unknown, never the gate's to answer with the challenge.
//
// Not rows of TestMFAGate: its rows post a code to a method set, where that
// table's carry one method and send their own request.
func TestMFAGateVerifyExempt(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		wire   func(h *mfaHarness, email *MockMethod)
		assert func(t *testing.T, h *mfaHarness, out served)
	}

	resolved := func(t *testing.T, h *mfaHarness, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.NotErrorAs(t, out.err, &ch, "the gate does not refuse the request that resolves it")
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)

		require.NotNil(t, h.resolved)
		assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
	}

	cases := []testCase{
		{
			name: "TOTP's verify path",
			path: httpsec.DefaultMFAVerifyPrefix + "/totp",
			wire: func(h *mfaHarness, _ *MockMethod) {
				h.allows().accepts().recordsNoFailure()
			},
			assert: resolved,
		},
		{
			name: "the emailed code's verify path",
			path: httpsec.DefaultMFAVerifyPrefix + "/email-code",
			wire: func(h *mfaHarness, email *MockMethod) {
				h.allows().neverVerifies().recordsNoFailure()
				email.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)
			},
			assert: resolved,
		},
		{
			name: "a verify path naming no method",
			path: httpsec.DefaultMFAVerifyPrefix + "/sms",
			wire: func(h *mfaHarness, _ *MockMethod) {
				h.neverVerifies().neverChecked().recordsNoFailure()
			},
			assert: func(t *testing.T, _ *mfaHarness, out served) {
				var ch *httpsec.ChallengeError
				require.NotErrorAs(t, out.err, &ch, "the endpoint refuses it, not the gate")
				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			email := emailCodeMethod(t)
			email.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
			h.extra = []mfa.Method{email}

			tc.wire(h, email)

			s := h.pendingSession(t, factor.Password)

			tc.assert(t, h, serve(t, h.chain(t, s), postCode(t.Context(), tc.path)))
		})
	}
}

// TestMFAGateMethods pins what the gate's challenge tells the consumer: the
// methods this session's user can answer it with, as the policies decide
// usability, in configuration order — or, when that cannot be decided, no
// challenge at all.
//
// Not rows of TestMFAGate: its rows wire a second, stub method that the gate's
// challenge lists.
func TestMFAGateMethods(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		wire func(h *mfaHarness, passkey *challengeStub)
		// first is the factor the session was established by: password
		// unless a case needs another.
		first  factor.Kind
		assert func(t *testing.T, s *session.Session, out served)
	}

	totp := httpsec.MFAMethod{Name: "totp", Channel: factor.AuthenticatorApp}
	passkey := httpsec.MFAMethod{Name: "passkey", Channel: testDeviceChannel, Begins: true}

	challengedWith := func(want ...httpsec.MFAMethod) func(*testing.T, *session.Session, served) {
		return func(t *testing.T, s *session.Session, out served) {
			t.Helper()

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			assert.Equal(t, policy.ChallengeMFA, ch.Kind)
			require.NotNil(t, ch.Session)
			assert.Equal(t, s.ID, ch.Session.ID)
			if len(want) == 0 {
				assert.Empty(t, ch.Methods)
			} else {
				assert.Equal(t, want, ch.Methods)
			}
			assert.False(t, out.handlerRan)
		}
	}

	errLookup := errors.New("mfagate_test: enrolment store unavailable")

	cases := []testCase{
		{
			name:   "the challenge carries every usable method, in configuration order",
			wire:   func(*mfaHarness, *challengeStub) {},
			assert: challengedWith(totp, passkey),
		},
		{
			name:   "the challenge omits a method the user is not enrolled on",
			wire:   func(_ *mfaHarness, p *challengeStub) { p.enrolled = false },
			assert: challengedWith(totp),
		},
		{
			// An email method is on a magic link's own channel, so it is no
			// second factor after one.
			name:   "the challenge omits a method on the first factor's channel",
			first:  factor.MagicLink,
			wire:   func(_ *mfaHarness, p *challengeStub) { p.channel = factor.Email },
			assert: challengedWith(totp),
		},
		{
			// The lookups answered, and the answer is that nothing is left:
			// the challenge still holds the session, and the client can only
			// log out.
			name: "no usable method left after the enrolments were removed",
			wire: func(h *mfaHarness, p *challengeStub) {
				h.totpUnenrolled = true
				p.enrolled = false
			},
			assert: challengedWith(),
		},
		{
			name: "a failed lookup never yields an empty list",
			wire: func(_ *mfaHarness, p *challengeStub) { p.enrolledErr = errLookup },
			assert: func(t *testing.T, _ *session.Session, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, errLookup)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch, "the failure replaces the challenge")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), errLookup.Error(),
					"the dependency's text stays out of the refusal")
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

			stub := newChallengeStub()
			h.extra = []mfa.Method{stub}
			tc.wire(h, stub)

			first := tc.first
			if first == "" {
				first = factor.Password
			}

			s := h.pendingSession(t, first)

			tc.assert(t, s, serve(t, h.chain(t, s),
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)))
		})
	}
}

// defaultListing is the document the listing answers with by default when the
// user can use TOTP alone.
const defaultListing = `{"methods":[{"name":"totp","channel":"authenticator-app","begins":false}]}`

// TestMFAMethodListing pins the opt-in endpoint a session owing a second
// factor asks which methods it can answer with: whom it answers, what it
// answers with, and what it leaves alone.
func TestMFAMethodListing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// wire configures the chain: the listing option, and what the second
		// method — "email-code", on the email channel, not enrolled unless a
		// case enrols it — answers.
		wire func(h *mfaHarness, email *challengeStub)

		// state is the MFA state of the carried session; noSession carries
		// none at all.
		state     session.MFAState
		noSession bool

		request func(r *http.Request) *http.Request
		assert  func(t *testing.T, out served)
	}

	listing := func(settings ...httpsec.ListingSetting) func(*mfaHarness, *challengeStub) {
		return func(h *mfaHarness, _ *challengeStub) {
			h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAMethodListing(settings...)}
		}
	}

	get := func(target string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return httptest.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		}
	}

	to := func(method, target string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return httptest.NewRequestWithContext(r.Context(), method, target, nil)
		}
	}

	lists := func(want string) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			require.NoError(t, out.err)
			assert.False(t, out.handlerRan, "the endpoint answers the request itself")
			assert.Equal(t, http.StatusOK, out.rec.Code)
			assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
			assert.JSONEq(t, want, out.rec.Body.String())
		}
	}

	// challenged is the gate's refusal, which a request the listing does not
	// answer meets when its session owes a second factor.
	challenged := func(t *testing.T, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch, "the gate, not the listing, answered")
		assert.Equal(t, policy.ChallengeMFA, ch.Kind)
		assert.False(t, out.handlerRan)
		assert.Zero(t, out.rec.Body.Len(), "no listing was written")
	}

	// passed is a request the listing does not answer reaching the
	// application.
	passed := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the request passed through to the application")
		assert.Zero(t, out.rec.Body.Len(), "no listing was written")
	}

	refusedWith := func(want error) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, want)
			assert.False(t, out.handlerRan)
			assert.Zero(t, out.rec.Body.Len(), "no listing was written")
		}
	}

	errLookup := errors.New("mfalisting_test: enrolment store unavailable for ana@example.com")

	cases := []testCase{
		{
			name:    "off by default: a pending session meets the gate",
			wire:    func(*mfaHarness, *challengeStub) {},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			name:    "off by default: another session reaches the application",
			wire:    func(*mfaHarness, *challengeStub) {},
			state:   session.MFASatisfied,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  passed,
		},
		{
			name:    "a pending session lists the methods its user can use",
			wire:    listing(),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: func(t *testing.T, out served) {
				t.Helper()

				lists(defaultListing)(t, out)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"),
					"the default listing carries the user's usable methods, which no cache may keep")
			},
		},
		{
			name: "a method with a begin step is listed as one, in configuration order",
			wire: func(h *mfaHarness, email *challengeStub) {
				listing()(h, email)
				email.enrolled = true
			},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: lists(`{"methods":[` +
				`{"name":"totp","channel":"authenticator-app","begins":false},` +
				`{"name":"email-code","channel":"email","begins":true}]}`),
		},
		{
			// The lookups answered, and nothing is left: an empty list, never
			// null, and never a refusal.
			name: "no usable method left",
			wire: func(h *mfaHarness, email *challengeStub) {
				listing()(h, email)
				h.totpUnenrolled = true
			},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  lists(`{"methods":[]}`),
		},
		{
			name:    "a full session is refused",
			wire:    listing(),
			state:   session.MFASatisfied,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: func(t *testing.T, out served) {
				t.Helper()

				refusedWith(httpsec.ErrNoMFAChallengePending)(t, out)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			name:    "a single-factor session is refused",
			wire:    listing(),
			state:   session.MFANone,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  refusedWith(httpsec.ErrNoMFAChallengePending),
		},
		{
			name:      "no session",
			wire:      listing(),
			noSession: true,
			request:   get(httpsec.DefaultMFAMethodListingPath),
			assert:    refusedWith(httpsec.ErrAuthenticationRequired),
		},
		{
			name: "a failed lookup is a refusal, never a shorter list",
			wire: func(h *mfaHarness, email *challengeStub) {
				listing()(h, email)
				email.enrolledErr = errLookup
			},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: func(t *testing.T, out served) {
				t.Helper()

				refusedWith(errLookup)(t, out)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch)
				assert.NotContains(t, out.err.Error(), "ana@example.com",
					"the dependency's text stays out of the refusal")
			},
		},
		{
			name: "consumer path and responder",
			wire: listing(
				httpsec.ListingPath("/account/mfa/methods"),
				httpsec.ListingResponder(func(ex *httpsec.Exchange, methods []httpsec.MFAMethod) error {
					names := make([]string, 0, len(methods))
					for _, m := range methods {
						names = append(names, m.Name+"@"+string(m.Channel))
					}

					body, err := json.Marshal(map[string][]string{"offered": names})
					if err != nil {
						return err
					}

					ex.Writer.SetHeader("Content-Type", "application/json")
					ex.Writer.WriteHeader(http.StatusOK)
					_, err = ex.Writer.Write(body)

					return err
				}),
			),
			state:   session.MFAPending,
			request: get("/account/mfa/methods"),
			assert:  lists(`{"offered":["totp@authenticator-app"]}`),
		},
		{
			name:    "a consumer path moves the endpoint off the default",
			wire:    listing(httpsec.ListingPath("/account/mfa/methods")),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			name:    "the query is not read",
			wire:    listing(),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath + "?user=u-2&method=email-code"),
			assert:  lists(defaultListing),
		},
		{
			name:    "only the exact path is the listing",
			wire:    listing(),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath + "/"),
			assert:  challenged,
		},
		{
			name:    "a POST from a pending session is not answered by the listing",
			wire:    listing(),
			state:   session.MFAPending,
			request: to(http.MethodPost, httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			name:    "a HEAD from a pending session is not answered by the listing",
			wire:    listing(),
			state:   session.MFAPending,
			request: to(http.MethodHead, httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			// The listing would refuse a full session; passing through shows it
			// never looked at the request.
			name:    "a POST from a full session passes through",
			wire:    listing(),
			state:   session.MFASatisfied,
			request: to(http.MethodPost, httpsec.DefaultMFAMethodListingPath),
			assert:  passed,
		},
		{
			name:    "a HEAD from a full session passes through",
			wire:    listing(),
			state:   session.MFASatisfied,
			request: to(http.MethodHead, httpsec.DefaultMFAMethodListingPath),
			assert:  passed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

			email := newChallengeStub()
			email.name, email.channel, email.enrolled = "email-code", factor.Email, false
			h.extra = []mfa.Method{email}

			tc.wire(h, email)

			var s *session.Session
			if !tc.noSession {
				s = h.newSession(t, factor.Password, tc.state)
			}

			base := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			out := serve(t, h.chain(t, s), tc.request(base))

			tc.assert(t, out)
			assert.Zero(t, email.verifyCalls.Load(), "nothing is verified")
		})
	}
}

// TestMFAMethodListingConstruction pins the listing's wiring mistakes: a
// setting given explicitly with no value, and a path another endpoint of the
// chain already answers.
//
// Not rows of TestMFAMethodListing: its rows only build the chain, with
// logout's options beside MFA's, and serve nothing; nor of TestEnableMFA, which
// builds without the MFA harness.
func TestMFAMethodListingConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		mfaOpts    []httpsec.MFAOption
		logoutOpts []httpsec.LogoutOption
		assert     func(t *testing.T, c *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)

			for _, n := range names {
				assert.ErrorContains(t, err, n, "the error names what is at fault")
			}
		}
	}

	assembles := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	with := func(settings ...httpsec.ListingSetting) []httpsec.MFAOption {
		return []httpsec.MFAOption{httpsec.WithMFAMethodListing(settings...)}
	}

	cases := []testCase{
		{
			name:    "every default",
			mfaOpts: with(),
			assert:  assembles,
		},
		{
			name:    "an explicitly empty path",
			mfaOpts: with(httpsec.ListingPath("")),
			assert:  refused("ListingPath"),
		},
		{
			name:    "a path that matches no request",
			mfaOpts: with(httpsec.ListingPath("mfa/methods")),
			assert:  refused("ListingPath"),
		},
		{
			name:    "an absent responder",
			mfaOpts: with(httpsec.ListingResponder(nil)),
			assert:  refused("ListingResponder"),
		},
		{
			name:    "a path under the verify prefix",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix + "/totp")),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFAVerifyPrefix),
		},
		{
			name:    "the verify prefix itself",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix)),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFAVerifyPrefix),
		},
		{
			name:    "a path under the begin prefix",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFABeginPrefix + "/passkey")),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFABeginPrefix),
		},
		{
			name: "a path under a consumer's verify prefix",
			mfaOpts: append(with(httpsec.ListingPath("/2fa/check/totp")),
				httpsec.WithMFAVerifyPrefix("/2fa/check")),
			assert: refused("WithMFAMethodListing", "/2fa/check"),
		},
		{
			name: "the default verify path once the verify prefix has moved",
			mfaOpts: append(with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix+"/totp")),
				httpsec.WithMFAVerifyPrefix("/2fa/check")),
			assert: assembles,
		},
		{
			name:    "the logout path",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultLogoutPath)),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultLogoutPath),
		},
		{
			name:       "a consumer's logout path",
			mfaOpts:    with(httpsec.ListingPath("/auth/sign-out")),
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			assert:     refused("WithMFAMethodListing", "/auth/sign-out"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			c, err := httpsec.New(
				httpsec.EnableMFA([]mfa.Method{h.method}, append([]httpsec.MFAOption{
					httpsec.WithMFAVerifyLimiter(h.limiter),
					httpsec.WithMFATokens(h.tokens),
				}, tc.mfaOpts...)...),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, tc.logoutOpts...),
			)

			tc.assert(t, c, err)
		})
	}
}

// TestMFAMethodListingEnrolmentOnly pins that an enrolment-only session never
// reaches the listing: the enrolment gate refuses it first, like any other
// route. Its setup is the enrolment harness's, not the MFA harness's, so it
// stands apart from the table above.
func TestMFAMethodListingEnrolmentOnly(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAMethodListing()}

	s := h.enrolmentOnly(t, factor.Password)

	out := serve(t, h.chain(t, s),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultMFAMethodListingPath, nil))

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch)
	assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
	assert.False(t, out.handlerRan)
	assert.Zero(t, out.rec.Body.Len(), "no listing was written")
}

// clockOpt gives the chain the harness's clock, which its sessions share, so a
// case moves one time for both. The options that follow it, h.chainOpts among
// them, may replace it.
func (h *mfaHarness) clockOpt() []httpsec.Option {
	if h.systemClock {
		return nil
	}

	return []httpsec.Option{httpsec.WithClock(h.clock)}
}

// bearerChain is the chain a real deployment runs: a bearer first factor that
// resolves the session a token names, and the second factor behind it. It is
// what makes rotation observable end to end — the credential a caller holds
// names a session, and rotation moves the session out from under it.
func (h *mfaHarness) bearerChain(t *testing.T) *httpsec.Chain {
	t.Helper()

	mfaOpts := append([]httpsec.MFAOption{
		httpsec.WithMFAVerifyLimiter(h.limiter),
		httpsec.WithMFATokens(h.tokens),
	}, h.mfaOpts...)

	c, err := httpsec.New(append(append(h.clockOpt(),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extra...), mfaOpts...),
	), h.chainOpts...)...)
	require.NoError(t, err)

	return c
}

// buildChain is bearerChain without the assertion, for the cases that are
// about the construction error itself.
func (h *mfaHarness) buildChain(t *testing.T) (*httpsec.Chain, error) {
	t.Helper()

	mfaOpts := append([]httpsec.MFAOption{
		httpsec.WithMFAVerifyLimiter(h.limiter),
		httpsec.WithMFATokens(h.tokens),
	}, h.mfaOpts...)

	return httpsec.New(append(h.clockOpt(),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extra...), mfaOpts...),
	)...)
}

// bearerRequestTo is a request carrying an access token, as a client that has
// logged in makes.
func bearerRequestTo(ctx context.Context, method, path, token, body string) *http.Request {
	var req *http.Request

	if method == http.MethodPost {
		req = formRequest(ctx, path, body)
	} else {
		req = httptest.NewRequestWithContext(ctx, method, path, nil)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// verifyBody is the response document a successful verification answers with,
// read back the way a client would.
type verifyBody struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ValidUntil   time.Time `json:"valid_until"`
}

// TestMFAVerifyDoesNotStrandCaller pins the defect that made the responder
// necessary.
//
// The session identifier is the token's jti, so rotating the handle kills the
// token the caller arrived with. An endpoint that answers a bare 200 therefore
// signs a user out for passing their second factor, and the caller has no way
// to learn the handle that replaced theirs.
//
// Stands alone: it serves a sequence of requests through one chain, each
// depending on the response before.
func TestMFAVerifyDoesNotStrandCaller(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

	c := h.bearerChain(t)

	s := h.pendingSession(t, factor.Password)
	loginToken := mfaTokenFor(s.ID)

	out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
		testMFAVerifyPath, loginToken, "code="+testMFACode))
	require.NoError(t, out.err)

	var got verifyBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &got),
		"the verify response carries a credential for the rotated session")
	require.NotEmpty(t, got.AccessToken)
	assert.NotEqual(t, loginToken, got.AccessToken,
		"the pre-MFA token named the session that rotation deleted")
	assert.False(t, got.ValidUntil.IsZero(), "and says how long it is good for")

	// The credential the response returned works on a protected route.
	reached := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		got.AccessToken, ""))
	require.NoError(t, reached.err,
		"a caller that completed its second factor is not signed out")
	assert.True(t, reached.handlerRan)

	// And the credential it arrived with is genuinely dead, which is the
	// symptom this test exists to pin.
	stranded := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		loginToken, ""))
	require.ErrorIs(t, stranded.err, httpsec.ErrAuthenticationRequired,
		"the handle the caller arrived with no longer loads")
	assert.False(t, stranded.handlerRan)
}

// TestMFAVerifySatisfiedSessionPassesTheGate pins the other half of not being
// stranded: the rotated session carries its satisfied second factor, so the
// gate lets it through rather than challenging it again.
//
// Stands alone: it serves a sequence of requests through one chain, each
// depending on the response before.
func TestMFAVerifySatisfiedSessionPassesTheGate(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

	c := h.bearerChain(t)
	s := h.pendingSession(t, factor.Password)

	// Before: the gate holds every other request this session makes.
	held := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		mfaTokenFor(s.ID), ""))

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, held.err, &ch)

	out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
		testMFAVerifyPath, mfaTokenFor(s.ID), "code="+testMFACode))
	require.NoError(t, out.err)

	var got verifyBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &got))

	after := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		got.AccessToken, ""))
	require.NoError(t, after.err)
	assert.True(t, after.handlerRan)

	rotated := h.stored(t, h.rotatedID(t))
	assert.Equal(t, session.MFASatisfied, rotated.MFA)
}

// rotatedID is the identifier the last access token was issued against.
func (h *mfaHarness) rotatedID(t *testing.T) string {
	t.Helper()

	id, _ := h.issuedFor.Load().(string)
	require.NotEmpty(t, id, "no token was issued, so no handle was published")

	return id
}

// errMFAResponder is what a consumer's responder refuses with, so a test can
// assert the chain returned that error and not one of its own.
var errMFAResponder = errors.New("mfaresponder_test: the client cannot be answered")

// TestMFAVerifyResponder pins what writes the response to a successful second
// factor, and what happens when it will not.
func TestMFAVerifyResponder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MFAOption
		assert func(t *testing.T, h *mfaHarness, previous string, out served, buildErr error)
	}

	// seen is what the consumer's responder of the "consumer responder" row
	// was handed.
	var seen httpsec.MFAResult

	cases := []testCase{
		{
			name: "the default names the rotated session and not the previous one",
			assert: func(t *testing.T, h *mfaHarness, previous string, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.NoError(t, out.err)

				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))

				var body verifyBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

				rotated := h.rotatedID(t)
				assert.NotEqual(t, previous, rotated, "the handle moved")
				assert.Equal(t, mfaTokenFor(rotated), body.AccessToken,
					"the credential names the session that now exists")
				assert.Empty(t, body.RefreshToken,
					"the field is present and empty, as a login's is")
				assert.False(t, body.ValidUntil.IsZero())
			},
		},
		{
			name: "a responder error refuses the request",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(
				func(*httpsec.Exchange, httpsec.MFAResult) error { return errMFAResponder },
			)},
			assert: func(t *testing.T, _ *mfaHarness, _ string, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.ErrorIs(t, out.err, errMFAResponder,
					"the consumer's error is the refusal, unchanged")
			},
		},
		{
			name: "a nil responder is a configuration error",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(nil)},
			assert: func(t *testing.T, _ *mfaHarness, _ string, _ served, buildErr error) {
				require.ErrorIs(t, buildErr, httpsec.ErrConfig,
					"a responder that is not there would leave the caller with no credential")
			},
		},
		{
			// A consumer's responder replaces the default entirely and is
			// handed the rotated session, which is the only place the new
			// handle is available.
			name: "consumer responder",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(
				func(ex *httpsec.Exchange, r httpsec.MFAResult) error {
					seen = r
					ex.Writer.SetCookie(&http.Cookie{
						Name:     "session",
						Value:    r.Token,
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteLaxMode,
					})

					return nil
				})},
			assert: func(t *testing.T, h *mfaHarness, previous string, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.NoError(t, out.err)

				assert.Empty(t, out.rec.Body.String(), "the consumer's responder replaces the default entirely")

				require.NotNil(t, seen.Session)
				assert.Equal(t, h.rotatedID(t), seen.Session.ID, "the responder receives the rotated session")
				assert.NotEqual(t, previous, seen.Session.ID)
				assert.Equal(t, mfaTokenFor(seen.Session.ID), seen.Token)

				cookie := cookieNamed(out.rec, "session")
				require.NotNil(t, cookie, "and its own response reached the client")
				assert.Equal(t, seen.Token, cookie.Value)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			h.mfaOpts = tc.opts

			c, buildErr := h.buildChain(t)
			if buildErr != nil {
				tc.assert(t, h, "", served{}, buildErr)

				return
			}

			h.allows().accepts().recordsNoFailure()

			s := h.pendingSession(t, factor.Password)

			out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
				testMFAVerifyPath, mfaTokenFor(s.ID), "code="+testMFACode))

			tc.assert(t, h, s.ID, out, nil)
		})
	}
}

// TestMFAVerifyWithoutResolvedCaller pins that a session alone is not enough.
// The response hands back a credential issued for somebody, so a session whose
// first factor published no caller is refused before the code is read — rather
// than reaching the point where there is nobody to issue a token to.
//
// Not a row of TestMFAVerifyResponder: it builds its own chain around an
// interceptor that publishes a session without a caller.
func TestMFAVerifyWithoutResolvedCaller(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

	s := h.pendingSession(t, factor.Password)

	sessionOnly := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.Session = s
		ex.SetContext(httpsec.WithSession(ex.Context(), s))

		return next(ex)
	})

	c, err := httpsec.New(
		httpsec.RegisterInterceptor(sessionOnly, httpsec.Before(httpsec.OrderMFAChallenge)),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
		httpsec.EnableMFA([]mfa.Method{h.method},
			httpsec.WithMFAVerifyLimiter(h.limiter),
			httpsec.WithMFATokens(h.tokens)),
	)
	require.NoError(t, err)

	// The body must not be read: this refusal is decided from the session
	// alone, before anything the caller posted is touched.
	out := serve(t, c, postUnread(t.Context(), t, testMFAVerifyPath))

	require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
}

// barrierLimiter holds every Exceeded call until n callers have checked, so
// every request passes the endpoint's throttle before any failure is recorded:
// the interleaving a limiter that checks and records in two steps admits.
type barrierLimiter struct {
	wg sync.WaitGroup
}

func newBarrierLimiter(n int) *barrierLimiter {
	l := &barrierLimiter{}
	l.wg.Add(n)

	return l
}

func (l *barrierLimiter) Exceeded(context.Context, string) (bool, error) {
	l.wg.Done()
	l.wg.Wait()

	return false, nil
}

func (l *barrierLimiter) RecordFailure(context.Context, string) error { return nil }

// TestMFAVerify_RefusedChargeIsNotRecorded pins that a method refusing a
// verification because its attempt charge was refused compared nothing, so the
// endpoint returns the refusal unchanged and records no failed verification. A
// wrong code that was compared still is recorded.
//
// Its own table: its rows count the failures the limiter records, through a
// mocked limiter the other verify tables do not wire.
func TestMFAVerify_RefusedChargeIsNotRecorded(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		verifyErr error
		// assert receives the response and how many failed verifications the
		// limiter recorded.
		assert func(t *testing.T, s served, recorded int)
	}

	cases := []testCase{
		{
			name:      "a refused attempt charge is returned unchanged and not recorded",
			verifyErr: mfa.ErrVerifyAttemptsExhausted,
			assert: func(t *testing.T, s served, recorded int) {
				require.ErrorIs(t, s.err, mfa.ErrVerifyAttemptsExhausted)
				assert.Zero(t, recorded, "a refused charge compared nothing")
				require.ErrorIs(t, s.err, mfa.ErrVerifyThrottled)
				assert.NotErrorIs(t, s.err, mfa.ErrInvalidCode)
				assert.Equal(t, 401, httpsec.StatusForError(s.err))
			},
		},
		{
			name:      "a compared wrong code is still recorded",
			verifyErr: mfa.ErrInvalidCode,
			assert: func(t *testing.T, s served, recorded int) {
				require.ErrorIs(t, s.err, mfa.ErrInvalidCode)
				assert.Equal(t, 1, recorded, "a compared wrong code is recorded")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			h.method.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).Return(tc.verifyErr)
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil)

			var recorded atomic.Int32

			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				DoAndReturn(func(context.Context, string) error {
					recorded.Add(1)
					return nil
				}).AnyTimes()

			s := h.pendingSession(t, factor.Password)
			c := h.chain(t, s)

			out := serve(t, c, postCode(t.Context(), testMFAVerifyPath))
			tc.assert(t, out, int(recorded.Load()))
			assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
		})
	}
}

// TestMFAVerify_ConcurrentWrongCodesComparedExactlyTheLimit pins that however
// many wrong codes race through the endpoint's throttle at once, a real TOTP
// compares exactly its attempt limit of them, and refuses the rest as
// throttled.
//
// Stands alone: it races concurrent requests through one chain.
func TestMFAVerify_ConcurrentWrongCodesComparedExactlyTheLimit(t *testing.T) {
	t.Parallel()

	const racers = 20

	secret := []byte(rfc6238Secret)
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC))

	store := mfa.NewMemoryEnrolmentStore()
	gen := id.MustParse("01920000-0000-7000-8000-0000000000f1")
	require.NoError(t, store.PutPending(t.Context(), mfa.Enrolment{User: testMFAUser, Secret: secret, Generation: gen}))
	ok, err := store.Confirm(t.Context(), testMFAUser, gen, 0, clk.Now())
	require.NoError(t, err)
	require.True(t, ok)

	method, err := mfa.NewTOTP(store, "scrty-test", mfa.WithClock(clk))
	require.NoError(t, err)

	h := newMFAHarness(t)

	// The harness's own method double is not in this chain; the real method
	// is, and it is named "totp" as the default verify path expects.
	s := h.pendingSession(t, factor.Password)
	c, err := httpsec.New(
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA([]mfa.Method{method},
			httpsec.WithMFAVerifyLimiter(newBarrierLimiter(racers)),
			httpsec.WithMFATokens(h.tokens)),
	)
	require.NoError(t, err)

	wrong := wrongTOTPCode(t, secret, clk.Now())

	var compared, throttled atomic.Int32

	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			req := formRequest(t.Context(), testMFAVerifyPath, "code="+wrong)
			req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

			out := serve(t, c, req)

			switch {
			case errors.Is(out.err, mfa.ErrInvalidCode):
				compared.Add(1)
			case errors.Is(out.err, mfa.ErrVerifyThrottled):
				throttled.Add(1)
			}
		})
	}

	wg.Wait()

	assert.Equal(t, mfa.DefaultVerifyAttemptLimit, int(compared.Load()),
		"wrong codes compared against one enrolment")
	assert.Equal(t, int32(racers), compared.Load()+throttled.Load(),
		"every request is either compared or refused as throttled")
}

// rfc6238Secret is the ASCII seed RFC 6238 Appendix B uses for HMAC-SHA-1.
const rfc6238Secret = "12345678901234567890"

// wrongTOTPCode returns a well-formed code that none of the steps a
// verification at at accepts would match. It computes the accepted codes
// through pquerna/otp directly, so the expectation shares no code with mfa.
func wrongTOTPCode(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()

	key := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	accepted := map[string]bool{}

	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := totp.GenerateCodeCustom(key, at.Add(d), totp.ValidateOpts{
			Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		require.NoError(t, err)

		accepted[code] = true
	}

	for _, c := range []string{"000000", "111111", "222222", "333333"} {
		if !accepted[c] {
			return c
		}
	}

	t.Fatal("no wrong code found")

	return ""
}

// testMFAWrongCode is a code the method double refuses, posted beside a valid
// one elsewhere in the request.
const testMFAWrongCode = "000000"

// verifyRequest is a POST to the default verify path with the given query,
// content type and body.
func verifyRequest(ctx context.Context, query, contentType, body string) *http.Request {
	target := testMFAVerifyPath
	if query != "" {
		target += "?" + query
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return req
}

// multipartVerifyRequest is a POST to the default verify path carrying the
// code as a multipart/form-data field.
func multipartVerifyRequest(ctx context.Context, t *testing.T) *http.Request {
	t.Helper()

	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	require.NoError(t, w.WriteField("code", testMFACode))
	require.NoError(t, w.Close())

	return verifyRequest(ctx, "", w.FormDataContentType(), buf.String())
}

// TestVerifyReadsBodyOnly pins where the verify endpoint reads the code from:
// the "code" field of a URL-encoded POST body, and nowhere else. A code in the
// URL has already reached access logs, proxy logs and the Referer header, so it
// is never read; a body the endpoint cannot read is a code that was not
// presented, so it is refused before it is judged and is not counted against
// the user.
//
// Its own table: its rows vary the method's response format and the request's
// body, which the other verify tables fix.
func TestVerifyReadsBodyOnly(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// format is what the method declares; the zero format keeps TOTP's
		// "code" form field of up to 4 KiB.
		format  mfa.ResponseFormat
		request func(ctx context.Context, t *testing.T) *http.Request
		wire    func(h *mfaHarness)
		assert  func(t *testing.T, h *mfaHarness, s *session.Session, out served)
	}

	// missing and missingUncounted are the wiring and the answer for every
	// request whose code the endpoint cannot read: the throttle is still
	// checked first, nothing is verified, nothing is counted, and the refusal
	// is missing credentials with the challenge still pending.
	missing := func(h *mfaHarness) { h.allows().neverVerifies().recordsNoFailure() }
	missingUncounted := func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(out.err))
		assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
	}

	cases := []testCase{
		{
			name: "a valid code in the query only",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "code="+testMFACode,
					"application/x-www-form-urlencoded", "")
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "a wrong code in the body and a valid one in the query",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "code="+testMFACode,
					"application/x-www-form-urlencoded", "code="+testMFAWrongCode)
			},
			wire: func(h *mfaHarness) {
				h.allows().recordsFailure()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFAWrongCode)).
					Return(mfa.ErrInvalidCode)
			},
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			name:    "a valid code in a multipart body",
			request: multipartVerifyRequest,
			wire:    missing,
			assert:  missingUncounted,
		},
		{
			name: "a valid code in a JSON body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/json", `{"code":"`+testMFACode+`"}`)
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "an empty body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "")
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "a body without the code field",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "otp="+testMFACode)
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			// It parses only in part: the code before the broken escape is not
			// read out of a body the client did not send whole.
			name: "a body that does not parse",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded",
					"code="+testMFACode+"&junk=%zz")
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name: "a body over the limit",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded",
					"code="+testMFACode+"&pad="+strings.Repeat("a", 8<<10))
			},
			wire: missing,
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(out.err))
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			name: "a 5 KiB body to TOTP's 4 KiB field",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				body := "code=" + testMFACode + "&pad="
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded",
					body+strings.Repeat("a", 5<<10-len(body)))
			},
			wire: missing,
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			name:   "a JSON method receives exactly the document posted",
			format: mfa.JSONBody(16 << 10),
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/json", jsonDocument(6<<10))
			},
			wire: func(h *mfaHarness) {
				h.allows().recordsNoFailure()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(jsonDocument(6<<10))).Return(nil)
			},
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
		{
			name:   "a URL-encoded body to a JSON method",
			format: mfa.JSONBody(16 << 10),
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "code="+testMFACode)
			},
			wire:   missing,
			assert: missingUncounted,
		},
		{
			name:   "a JSON body over the method's declared limit",
			format: mfa.JSONBody(1 << 10),
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/json", jsonDocument(2<<10))
			},
			wire: missing,
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			// The throttle's check runs before the code is read, so a user
			// already locked out learns nothing new from an unreadable body.
			name: "a throttled user posting an empty body",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "", "application/x-www-form-urlencoded", "")
			},
			wire: func(h *mfaHarness) { h.throttles().neverVerifies().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, s *session.Session, out served) {
				require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				assert.NotErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
			},
		},
		{
			name: "a valid URL-encoded code",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return postCode(ctx, testMFAVerifyPath)
			},
			wire: func(h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
		{
			// A guard against a regression to a plain string comparison of the
			// content type: a real client that names its charset must not be
			// refused as if it declared no form at all.
			name: "a valid code with a charset parameter on the content type",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "",
					"application/x-www-form-urlencoded; charset=utf-8", "code="+testMFACode)
			},
			wire: func(h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
		{
			name: "a valid code with an upper-case media type",
			request: func(ctx context.Context, _ *testing.T) *http.Request {
				return verifyRequest(ctx, "",
					"APPLICATION/X-WWW-FORM-URLENCODED", "code="+testMFACode)
			},
			wire: func(h *mfaHarness) { h.allows().accepts().recordsNoFailure() },
			assert: func(t *testing.T, h *mfaHarness, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, session.MFASatisfied, h.stored(t, h.resolved.ID).MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			if tc.format.Kind() != 0 {
				h.response = tc.format
			}

			s := h.pendingSession(t, factor.Password)
			tc.wire(h)

			out := serve(t, h.chain(t, s), tc.request(t.Context(), t))
			tc.assert(t, h, s, out)
		})
	}
}

// TestMFAVerify_AuthenticatorRefusedUncounted pins that a method refusing the
// authenticator itself — a suspected clone, a suspended credential — is not a
// wrong guess: the refusal comes back unchanged and nothing is counted against
// the user. Every other refusal still is. Either way the challenge stays
// pending and the handle does not move.
//
// Its own table: each row begins a challenge and answers it, two requests
// through one chain.
func TestMFAVerify_AuthenticatorRefusedUncounted(t *testing.T) {
	t.Parallel()

	errClone := fmt.Errorf("%w: suspected clone", mfa.ErrAuthenticatorRefused)

	type testCase struct {
		name      string
		verifyErr error
		// failures is how many failed verifications the limiter must record.
		failures int
		assert   func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:      "a refused authenticator is returned unchanged and not counted",
			verifyErr: errClone,
			failures:  0,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, mfa.ErrAuthenticatorRefused)
				require.ErrorIs(t, err, errClone, "the method's refusal is returned as it was")
				assert.NotErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(err))
			},
		},
		{
			name:      "an invalid response is still counted",
			verifyErr: mfa.ErrInvalidCode,
			failures:  1,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies()
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil).AnyTimes()
			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(nil).Times(tc.failures)

			stub := newChallengeStub()
			stub.verifyErr = tc.verifyErr
			h.extra = []mfa.Method{stub}

			s := h.pendingSession(t, factor.Password)
			c := h.bearerChain(t)

			begun := serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))
			require.NoError(t, begun.err, "the begin succeeds")

			out := serve(t, c, bearerJSON(t.Context(), testPasskeyVerifyPath, mfaTokenFor(s.ID),
				answer(issuedChallenge(t, begun))))

			require.Equal(t, int32(1), stub.verifyCalls.Load(), "the method is asked to verify")
			assert.False(t, out.handlerRan)
			tc.assert(t, out.err)

			still := h.stored(t, s.ID)
			assert.Equal(t, s.ID, still.ID, "the handle is unchanged")
			assert.Equal(t, session.MFAPending, still.MFA, "the challenge stays pending")
			assert.True(t, still.MFASatisfiedAt.IsZero())
		})
	}
}
