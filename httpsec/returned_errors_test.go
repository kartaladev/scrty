package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// errorSink is the consumer's error handler: it records what the chain
// refused with and the status the library maps it to, which is everything a
// consumer rendering a refusal has to go on.
type errorSink struct {
	called bool
	err    error
	status int
}

// option installs the sink as the chain's error handler.
func (s *errorSink) option() httpsec.Option {
	return httpsec.WithErrorHandler(s.handle)
}

// guardOption installs the sink as a guard's error handler.
func (s *errorSink) guardOption() httpsec.GuardOption {
	return httpsec.WithGuardErrorHandler(s.handle)
}

func (s *errorSink) handle(w http.ResponseWriter, _ *http.Request, err error) {
	s.called = true
	s.err = err
	s.status = httpsec.StatusForError(err)
	w.WriteHeader(s.status)
}

// refusedBy builds a chain from opts with the sink as its error handler,
// mounts it as net/http middleware and runs req through it.
func refusedBy(t *testing.T, req *http.Request, opts ...httpsec.Option) *errorSink {
	t.Helper()

	sink := &errorSink{}

	c, err := httpsec.New(append(opts, sink.option())...)
	require.NoError(t, err)

	return throughMiddleware(t, c, sink, req)
}

// throughMiddleware runs req through c's net/http middleware; c must have been
// built with sink's option.
func throughMiddleware(t *testing.T, c *httpsec.Chain, sink *errorSink, req *http.Request) *errorSink {
	t.Helper()

	c.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the downstream handler ran for a request the chain should have refused")
	})).ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, sink.called, "the consumer's error handler was never called")

	return sink
}

// carrying publishes s and a caller on every exchange, standing in for the
// first factor that resolved them, immediately outside the MFA slot.
func carrying(s *session.Session) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.Authentication = &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}
		ex.Session = s
		ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), s))

		return next(ex)
	}), httpsec.Before(httpsec.OrderMFAChallenge))
}

// allowingVerifyLimiter is a verification limiter that never throttles and
// accepts every failure it is asked to count.
func allowingVerifyLimiter(t *testing.T) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return l
}

// oidcManagerOver builds a manager for testOIDCProvider, whose endpoints are
// pinned so nothing is fetched, keeping its login flows in flows.
func oidcManagerOver(t *testing.T, flows oidc.FlowStore) *oidc.Manager {
	t.Helper()

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                "https://idp.example.com",
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider,
		RedirectURL:           "https://app.example.com/login/oauth2/callback/" + testOIDCProvider,
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "https://idp.example.com/jwks",
	})
	require.NoError(t, err)

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	m, err := oidc.NewManager(registry, broker, oidc.WithFlowStore(flows))
	require.NoError(t, err)

	return m
}

// oidcLoginOver is the chain options of a federated login over m, with a
// token generator and a session manager that are never reached.
func oidcLoginOver(t *testing.T, m *oidc.Manager) httpsec.Option {
	t.Helper()

	sessions, err := session.NewManager()
	require.NoError(t, err)

	return httpsec.EnableOIDCLogin(m, newTestHandoffManager(t),
		httpsec.WithOIDCTokens(NewMockGenerator(gomock.NewController(t))),
		httpsec.WithOIDCSessions(sessions))
}

// failingSessionsOn is a session manager over a store double, wired by wire.
func failingSessionsOn(t *testing.T, wire func(store *MockStore)) *session.Manager {
	t.Helper()

	store := NewMockStore(gomock.NewController(t))
	wire(store)

	m, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)

	return m
}

// backchannelRefusal delivers a logout token naming sub and sid to the
// harness's chain, built with opts, and returns what the consumer's handler
// saw.
func backchannelRefusal(t *testing.T, h *oidcHarness, sub, sid string, opts ...httpsec.OIDCOption) *errorSink {
	t.Helper()

	sink := &errorSink{}
	h.chainOpts = append(h.chainOpts, sink.option())

	req := backchannelRequest(t.Context(), testOIDCProvider, "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"logout_token": {h.provider.logoutToken(t, sub, sid)}}.Encode()))

	return throughMiddleware(t, h.chain(t, opts...), sink, req)
}

// sentinelsNotMatched are the library sentinels a refusal caused by a
// dependency must not newly match: every one the status table answers, and the
// ones a session store or an OIDC flow names. A fixture error wraps none of
// them, so the refusal must not either.
var sentinelsNotMatched = []error{
	httpsec.ErrAuthenticationRequired,
	httpsec.ErrCredentialsMissing,
	httpsec.ErrRequestTooLarge,
	authorize.ErrAuthenticationRequired,
	authorize.ErrAccessDenied,
	authenticate.ErrAuthenticationFailed,
	policy.ErrSessionIdle,
	policy.ErrAccountLocked,
	policy.ErrTooManySessions,
	policy.ErrPolicyDenied,
	policy.ErrMFARequired,
	policy.ErrMFAEnrollmentRequired,
	ratelimit.ErrThrottled,
	mfa.ErrInvalidCode,
	mfa.ErrVerifyThrottled,
	mfa.ErrSameChannel,
	mfa.ErrAlreadyEnrolled,
	oidc.ErrInvalidLogoutToken,
	oidc.ErrUnknownProvider,
	oidc.ErrInvalidState,
	oidc.ErrFlowUnspent,
	session.ErrSessionNotFound,
	session.ErrSessionExpired,
	session.ErrSessionUnreadable,
}

// failingRoleLoader is an identity.RoleLoader whose every lookup fails with
// err, standing in for the store behind the library's own PrivilegeAuthorizer.
type failingRoleLoader struct{ err error }

func (l failingRoleLoader) LoadPrivileges(context.Context, string) ([]*identity.ResourcePrivileges, error) {
	return nil, l.err
}

// activeRolePrincipal is a principal whose active role is name, which is the
// only thing the library's PrivilegeAuthorizer reads about a caller.
func activeRolePrincipal(name string) *identity.Principal {
	role := &identity.AssignedRole{ID: "r-1", Name: name, Primary: true}

	return &identity.Principal{
		ID:         "u-1",
		Username:   "ada",
		Roles:      []*identity.AssignedRole{role},
		ActiveRole: role,
	}
}

// TestReturnedErrorsCarryFixedText is the reproduction for task 6.1: one row
// per path on which an httpsec interceptor returns an error a consumer-supplied
// dependency caused. The dependency fails with errFixtureFailure, whose text
// quotes an address and a user reference, and the consumer's error handler
// records what it was handed. The refusal it reads must carry neither value,
// must still match the dependency's error, must match no library sentinel the
// dependency's error did not, and must map to the status it mapped to before
// the text was fixed.
//
// The consumer's own words — a magic-link check, a guard's authorizer, a
// policy's reason — and a store's bare library sentinel are the other side of
// the rule: they come back as themselves, compared by identity.
func TestReturnedErrorsCarryFixedText(t *testing.T) {
	t.Parallel()

	errTermsNotAccepted := errors.New("terms not accepted for alice@example.com")
	errRolesOnHold := errors.New("roles: alice@example.com (u-123) is on hold")
	errPolicyHold := errors.New("policy: alice@example.com is under review")

	// fixedText is the assertion every dependency row makes.
	fixedText := func(status int) func(t *testing.T, s *errorSink) {
		return func(t *testing.T, s *errorSink) {
			t.Helper()

			require.Error(t, s.err)

			text := s.err.Error()
			assert.NotContains(t, text, leakedAddress, "the refusal's text quotes the dependency")
			assert.NotContains(t, text, leakedUserRef, "the refusal's text quotes the dependency")
			require.ErrorIs(t, s.err, errFixtureFailure, "the dependency's error is no longer reachable")
			assert.Equal(t, status, s.status, "the refusal maps to a different status than it did")

			for _, sentinel := range sentinelsNotMatched {
				assert.NotErrorIs(t, s.err, sentinel, "the refusal newly matches %v", sentinel)
			}
		}
	}

	// unchanged is the assertion for an error that is the consumer's own, or a
	// bare library sentinel: it is returned as itself, text included.
	unchanged := func(want error, status int) func(t *testing.T, s *errorSink) {
		return func(t *testing.T, s *errorSink) {
			t.Helper()

			require.Error(t, s.err)
			assert.Same(t, want, s.err, "the error was rewritten; it must come back as itself")
			assert.Equal(t, want.Error(), s.err.Error(), "the text must be returned byte for byte")
			assert.Equal(t, status, s.status)
		}
	}

	type testCase struct {
		name   string
		act    func(t *testing.T) *errorSink
		assert func(t *testing.T, s *errorSink)
	}

	loginRequest := func(t *testing.T) *http.Request {
		t.Helper()

		return formRequest(t.Context(), "/login", "username=carol&password=s3cret")
	}

	// formLogin wires h for a login that authenticates and reaches the tail.
	formLogin := func(h *authHarness) {
		h.expectAuthenticated(testPrincipal())
		h.attempts.EXPECT().Reset(gomock.Any(), "carol").Return(nil)
	}

	// mfaVerify runs a code submission for a pending session held by sessions,
	// verified by method, issuing through tokens.
	mfaVerify := func(
		t *testing.T, s *session.Session, sessions *session.Manager, method mfa.Method, tokens *MockGenerator,
	) *errorSink {
		t.Helper()

		return refusedBy(t, postCode(t.Context(), testMFAVerifyPath),
			carrying(s),
			httpsec.EnableMFA([]mfa.Method{method},
				httpsec.WithMFAVerifyLimiter(allowingVerifyLimiter(t)),
				httpsec.WithMFATokens(tokens)),
			httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	}

	// pendingIn creates a password session owing a second factor in sessions.
	pendingIn := func(t *testing.T, sessions *session.Manager) *session.Session {
		t.Helper()

		s, err := sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		s.MFA = session.MFAPending
		require.NoError(t, sessions.Save(t.Context(), s))

		return s
	}

	acceptingMethod := func(t *testing.T) *MockMethod {
		t.Helper()

		m := mfaMethod(t, factor.AuthenticatorApp)
		m.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
		m.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)

		return m
	}

	issuing := func(t *testing.T) *MockGenerator {
		t.Helper()

		g := NewMockGenerator(gomock.NewController(t))
		g.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil).AnyTimes()

		return g
	}

	cases := []testCase{
		{
			name: "login completion: the session could not be created",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errFixtureFailure)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "login completion: the challenged session could not be saved",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errFixtureFailure)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
					httpsec.EnableGateForTest(policy.ChallengeMFA))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			// Review Focus 3: a store answering with the sentinel its contract
			// names gets that same value back.
			name: "login completion: a store's bare ErrSessionNotFound is returned as itself",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(session.ErrSessionNotFound)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
					httpsec.EnableGateForTest(policy.ChallengeMFA))
			},
			assert: unchanged(session.ErrSessionNotFound, http.StatusInternalServerError),
		},
		{
			name: "login completion: the token could not be generated",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("", errFixtureFailure)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "login: a consumer policy's reason is returned as itself",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(denyingEngine(t, errPolicyHold)))
			},
			assert: unchanged(errPolicyHold, http.StatusInternalServerError),
		},
		{
			// The scenario spec's own pin ("Dependency text stays out of the
			// refusal"): pre-authentication is denied because the lockout
			// policy's attempt store could not say how often carol has
			// failed. This matches policy.ErrPolicyDenied on purpose, so it
			// gets its own assert rather than the shared fixedText, which
			// asserts the opposite of every sentinel in sentinelsNotMatched.
			name: "login: denied because the lockout policy's attempt store could not be consulted",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				h.attempts.EXPECT().FailureCount(gomock.Any(), "carol", gomock.Any()).
					Return(0, errFixtureFailure)

				lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(h.attempts))
				require.NoError(t, err)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(engineOf(t, lockout)))
			},
			assert: func(t *testing.T, s *errorSink) {
				t.Helper()

				require.Error(t, s.err)

				text := s.err.Error()
				assert.NotContains(t, text, leakedAddress, "the refusal's text quotes the dependency")
				assert.NotContains(t, text, leakedUserRef, "the refusal's text quotes the dependency")
				assert.ErrorIs(t, s.err, errFixtureFailure, "the dependency's error is no longer reachable")
				assert.ErrorIs(t, s.err, policy.ErrPolicyDenied,
					"the refusal must still match the policy's own reason")
				assert.Equal(t, http.StatusForbidden, s.status)
			},
		},
		{
			name: "bearer: the per-request enrolment mark could not be saved",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(liveSession())
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errFixtureFailure).AnyTimes()

				return refusedBy(t, bearerRequest(t.Context(), "Bearer a-token"),
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
					httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "verify endpoint: the TOTP enrolment could not be read",
			act: func(t *testing.T) *errorSink {
				enrolments := NewMockEnrolmentStore(gomock.NewController(t))
				enrolments.EXPECT().Get(gomock.Any(), testMFAUser).Return(mfa.Enrolment{}, false, errFixtureFailure)

				totp, err := mfa.NewTOTP(enrolments, "Example")
				require.NoError(t, err)

				sessions, err := session.NewManager()
				require.NoError(t, err)

				return mfaVerify(t, pendingIn(t, sessions), sessions, totp, issuing(t))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "verify endpoint: the session could not be rotated",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, errFixtureFailure)
					store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				})

				s := liveSession()
				s.MFA = session.MFAPending

				return mfaVerify(t, s, sessions, acceptingMethod(t), issuing(t))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "verify endpoint: the token could not be generated",
			act: func(t *testing.T) *errorSink {
				sessions, err := session.NewManager()
				require.NoError(t, err)

				tokens := NewMockGenerator(gomock.NewController(t))
				tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("", errFixtureFailure)

				return mfaVerify(t, pendingIn(t, sessions), sessions, acceptingMethod(t), tokens)
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "logout: the session could not be deleted",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.acceptsActivityWriteBack()
				h.store.EXPECT().Delete(gomock.Any(), testJTI).Return(errFixtureFailure)

				return refusedBy(t, logoutFormRequest(t.Context(), nil),
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "oidc authorize: the login flow could not be begun",
			act: func(t *testing.T) *errorSink {
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Begin(gomock.Any(), gomock.Any()).Return("", errFixtureFailure)

				return refusedBy(t,
					httptest.NewRequestWithContext(t.Context(), http.MethodGet,
						httpsec.DefaultOIDCAuthorizePath+testOIDCProvider, nil),
					oidcLoginOver(t, oidcManagerOver(t, flows)))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "oidc callback: the flow the provider refused could not be ended",
			act: func(t *testing.T) *errorSink {
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), "h-1", testOIDCProvider, "s-1").
					Return(oidc.Flow{}, errFixtureFailure)

				return refusedBy(t,
					callbackRequest(t.Context(), "error=access_denied&state=s-1", "h-1"),
					oidcLoginOver(t, oidcManagerOver(t, flows)))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "oidc callback: the handoff code could not be issued",
			act: func(t *testing.T) *errorSink {
				h := newOIDCHarness(t)

				handoffs, err := oidc.NewHandoffManager(
					failingHandoffStore{err: errFixtureFailure}, NewMockUserLoader(gomock.NewController(t)))
				require.NoError(t, err)

				sink := &errorSink{}

				c, err := httpsec.New(sink.option(),
					httpsec.EnableOIDCLogin(h.manager, handoffs,
						httpsec.WithOIDCTokens(h.tokens),
						httpsec.WithOIDCSessions(h.sessions)))
				require.NoError(t, err)

				login := startLogin(t, c, "")

				return throughMiddleware(t, c, sink,
					callbackRequest(t.Context(), login.genuineCallback(), login.handle))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: the subject's link could not be looked up",
			act: func(t *testing.T) *errorSink {
				h := newOIDCHarness(t)

				ctrl := gomock.NewController(t)
				links := NewMockLinkStore(ctrl)
				links.EXPECT().FindByExternal(gomock.Any(), testOIDCProvider, gomock.Any(), oidcTestSubject).
					Return(nil, errFixtureFailure)

				broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
				require.NoError(t, err)

				h.manager = h.managerWith(t, broker, nil)

				return backchannelRefusal(t, h, oidcTestSubject, "")
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: the provider session's sessions could not be deleted",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().DeleteByExternalSession(gomock.Any(), gomock.Any(), "abc").
						Return(0, errFixtureFailure)
				})

				return backchannelRefusal(t, newOIDCHarness(t), oidcTestSubject, "abc",
					httpsec.WithOIDCSessions(sessions))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: the subject's sessions from the issuer could not be deleted",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), oidcTestUserID, gomock.Any()).
						Return(0, errFixtureFailure)
				})

				return backchannelRefusal(t, newOIDCHarness(t), oidcTestSubject, "",
					httpsec.WithOIDCSessions(sessions))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: every session of the subject could not be deleted",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().DeleteByUser(gomock.Any(), oidcTestUserID).Return(errFixtureFailure)
				})

				return backchannelRefusal(t, newOIDCHarness(t), oidcTestSubject, "",
					httpsec.WithOIDCSessions(sessions),
					httpsec.WithBackchannelLogoutScope(httpsec.AllSessions))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "jwks endpoint: the public key set could not be read",
			act: func(t *testing.T) *errorSink {
				keys := NewMockKeySetProvider(gomock.NewController(t))
				keys.EXPECT().JWKS().Return(nil, errFixtureFailure)

				return refusedBy(t,
					httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultJWKSPath, nil),
					httpsec.EnableJWKSEndpoint(keys))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			// Review Focus 4: the consumer's own check, in the consumer's own
			// words, even when those words quote an address.
			name: "magic link: a consumer check's refusal is returned byte for byte",
			act: func(t *testing.T) *errorSink {
				h := newMagicLinkHarness(t)
				token, nonce := h.link(t, h.chain(t))

				sink := &errorSink{}
				h.chainOpts = append(h.chainOpts, sink.option())
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkChecks(
					func(context.Context, identity.Principal, time.Time) error { return errTermsNotAccepted }))

				req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, magicLinkSource,
					url.Values{"token": {token}})
				if nonce != "" {
					req.AddCookie(bindingCookie(nonce))
				}

				return throughMiddleware(t, h.chain(t), sink, req)
			},
			assert: func(t *testing.T, s *errorSink) {
				t.Helper()

				require.ErrorIs(t, s.err, errTermsNotAccepted)
				assert.Equal(t, errTermsNotAccepted.Error(), s.err.Error(),
					"the consumer's words must reach them unchanged")
				assert.NotErrorIs(t, s.err, magiclink.ErrInvalidLink)
				assert.Equal(t, http.StatusInternalServerError, s.status)
			},
		},
		{
			name: "guard: a consumer authorizer's refusal is returned as itself",
			act: func(t *testing.T) *errorSink {
				sink := &errorSink{}
				g := httpsec.NewGuards(refusingAuthorizer(t, errRolesOnHold), sink.guardOption())

				runGuard(t, g.ResourcePrivileges("admin", "user").RequireOne("read"),
					guardRequest(t, testPrincipal(), nil))
				require.True(t, sink.called, "the guard's error handler was never called")

				return sink
			},
			assert: unchanged(errRolesOnHold, http.StatusInternalServerError),
		},
		{
			// Task 5.8's own path, one level up: the library's
			// PrivilegeAuthorizer wraps a failing role loader's error with
			// fixed text before a guard built over it ever sees it.
			name: "guard: a ResourcePrivileges guard over the library's own PrivilegeAuthorizer",
			act: func(t *testing.T) *errorSink {
				authorizer, err := authorize.NewPrivilegeAuthorizer(failingRoleLoader{err: errFixtureFailure})
				require.NoError(t, err)

				sink := &errorSink{}
				g := httpsec.NewGuards(authorizer, sink.guardOption())

				runGuard(t, g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					guardRequest(t, activeRolePrincipal("editor"), nil))
				require.True(t, sink.called, "the guard's error handler was never called")

				return sink
			},
			assert: fixedText(http.StatusInternalServerError),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t))
		})
	}
}
