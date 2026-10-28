package httpsec_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// TestExchangePublishSession pins that a session a consumer interceptor
// publishes is the one the handler reads, with its caller, and that its
// activity is recorded after the handler as for a built-in authenticator.
func TestExchangePublishSession(t *testing.T) {
	t.Parallel()

	f := newResolveFixture(t)

	chain, err := httpsec.New(
		httpsec.WithSessions(f.sessions),
		httpsec.RegisterInterceptor(consumerAuthenticating(f, false), httpsec.OrderBearerToken),
	)
	require.NoError(t, err)

	var (
		seen     *session.Session
		seenOK   bool
		caller   *identity.Principal
		callerOK bool
	)

	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		seen, seenOK = httpsec.SessionFromContext(ex.Context())
		caller, callerOK = identity.PrincipalFromContext(ex.Context())

		return nil
	})

	ex := httpsec.NewExchange(t.Context(),
		httpsec.NewHTTPRequest(bearerRequest(t.Context(), "")), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	require.NoError(t, run(ex))

	require.True(t, seenOK, "the handler reads the published session")
	assert.Equal(t, f.session.ID, seen.ID)
	assert.Same(t, seen, ex.Session, "the exchange carries the same session")

	require.True(t, callerOK, "the caller is published with it")
	assert.Equal(t, identity.UserID("u-1"), caller.ID)
	require.NotNil(t, ex.Authentication)

	stored, err := f.sessions.Load(t.Context(), f.session.ID)
	require.NoError(t, err)
	assert.True(t, stored.LastAccessedAt.Equal(f.clk.Now()),
		"activity is recorded after the handler, got last access %s, want %s",
		stored.LastAccessedAt, f.clk.Now())
	assert.True(t, stored.IdleExpiresAt.After(f.session.IdleExpiresAt),
		"the idle deadline moves with the recorded activity")
}

// TestExchangeEvaluatePerRequest pins that a consumer interceptor running the
// per-request phase gets the challenge handling the signed bearer applies:
// for an enrolment challenge the session is stored enrolment-pending with its
// deadlines lowered, and the gate enforcing enrolment refuses the request with
// the same challenge error, in both cases.
func TestExchangeEvaluatePerRequest(t *testing.T) {
	t.Parallel()

	// confining stands in for the enrolment gate, as in
	// TestBearerMarksEnrolment: it refuses an enrolment-pending session before
	// anything inside it runs.
	confining := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if ex.Session != nil && ex.Session.MFA == session.MFAEnrolmentPending {
			return &httpsec.ChallengeError{Kind: policy.ChallengeMFAEnrolment, Session: ex.Session}
		}

		return next(ex)
	})

	type testCase struct {
		name string

		// authenticating is the option that authenticates the request and runs
		// the per-request phase, built over the fixture.
		authenticating func(t *testing.T, f resolveFixture) httpsec.Option

		// header is the request's Authorization header.
		header string

		assert func(t *testing.T, f resolveFixture, out served)
	}

	// refusedAndMarked is what both authenticators must produce.
	refusedAndMarked := func(t *testing.T, f resolveFixture, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
		require.NotNil(t, ch.Session)
		assert.Equal(t, f.session.ID, ch.Session.ID)
		assert.False(t, out.handlerRan)

		stored, err := f.sessions.Load(t.Context(), f.session.ID)
		require.NoError(t, err)
		assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the mark is stored")
		assert.True(t, stored.AbsoluteExpiresAt.Equal(f.clk.Now().Add(15*time.Minute)),
			"the deadline is lowered to the enrolment lifetime from the mark, got %s",
			stored.AbsoluteExpiresAt)
		assert.True(t, stored.EnrolmentOriginDeadline.Equal(f.start.Add(f.sessions.AbsoluteTimeout())),
			"the marker records the full session's deadline")
	}

	cases := []testCase{
		{
			name: "signed bearer",
			authenticating: func(t *testing.T, f resolveFixture) httpsec.Option {
				t.Helper()

				ctrl := gomock.NewController(t)
				verifier := NewMockVerifier(ctrl)
				verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).
					Return(token.NewClaims(testSubject, f.session.ID), nil)

				users := NewMockUserLoader(ctrl)
				users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)

				return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: verifier, Sessions: f.sessions, Users: users,
				})
			},
			header: "Bearer abc.def.ghi",
			assert: refusedAndMarked,
		},
		{
			name: "consumer interceptor",
			authenticating: func(t *testing.T, f resolveFixture) httpsec.Option {
				t.Helper()

				return httpsec.RegisterInterceptor(consumerAuthenticating(f, true), httpsec.OrderBearerToken)
			},
			assert: refusedAndMarked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			chain, err := httpsec.New(
				httpsec.WithSessions(f.sessions),
				tc.authenticating(t, f),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				httpsec.RegisterInterceptor(confining, httpsec.OrderMFAEnrolment),
			)
			require.NoError(t, err)

			tc.assert(t, f, serve(t, chain, bearerRequest(t.Context(), tc.header)))
		})
	}
}

// TestExchangeEvaluatePerRequest_FailsClosed pins that the phase judges only
// what PublishSession published: a call for a session or caller that is not
// the published pair is refused before any policy runs.
func TestExchangeEvaluatePerRequest_FailsClosed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// run is the consumer interceptor's body, given the fixture's session
		// and caller.
		run func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) error
	}

	publish := func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) {
		require.NoError(t, ex.PublishSession(&authenticate.Authentication{Principal: p, Time: f.clk.Now()}, s))
	}

	cases := []testCase{
		{
			name: "nothing published",
			run: func(ex *httpsec.Exchange, _ resolveFixture, s *session.Session, p *identity.Principal) error {
				return ex.EvaluatePerRequest(s, p)
			},
		},
		{
			name: "a different session published",
			run: func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) error {
				other := *s
				publish(ex, f, &other, p)

				return ex.EvaluatePerRequest(s, p)
			},
		},
		{
			name: "a different principal published",
			run: func(ex *httpsec.Exchange, f resolveFixture, s *session.Session, p *identity.Principal) error {
				other := *p
				publish(ex, f, s, &other)

				return ex.EvaluatePerRequest(s, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			consumer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				s, err := f.sessions.Load(ex.Context(), f.session.ID)
				if err != nil {
					return err
				}

				if err := tc.run(ex, f, s, identity.PrincipalFromDetails(storedUser())); err != nil {
					return err
				}

				return next(ex)
			})

			// The engine challenges every per-request phase it runs, so a phase
			// that ran would mark the session or report a configuration error.
			chain, err := httpsec.New(
				httpsec.WithSessions(f.sessions),
				httpsec.RegisterInterceptor(consumer, httpsec.OrderBearerToken),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
				httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
			)
			require.NoError(t, err)

			out := serve(t, chain, bearerRequest(t.Context(), ""))
			require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
			assert.False(t, out.handlerRan)

			stored, err := f.sessions.Load(t.Context(), f.session.ID)
			require.NoError(t, err)
			assert.NotEqual(t, session.MFAEnrolmentPending, stored.MFA, "no policy ran, so nothing was marked")
		})
	}
}
