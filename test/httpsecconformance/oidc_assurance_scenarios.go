package httpsecconformance

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// assuranceOptions is the wiring the assurance scenarios share: a user who is
// required to use a second factor and is enrolled on TOTP, the OIDC manager as
// the source of provider assurance, and the requirement policy in mode.
func assuranceOptions(t *testing.T, e *Effects, mode policy.FederatedAssuranceMode) []httpsec.Option {
	t.Helper()

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example")
	require.NoError(t, err)

	provisioning, err := method.BeginEnrolment(t.Context(), UserID, Username)
	require.NoError(t, err)

	code, err := totp.GenerateCode(provisioning.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, method.ConfirmEnrolment(t.Context(), UserID, code))

	lookups, err := mfa.LookupsFor(method)
	require.NoError(t, err)

	source := policy.WithFederatedAssuranceSource(e.OIDC.Manager)

	challenge, err := policy.NewMFAPolicy(lookups, source)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(nil, lookups,
		policy.WithMFARequiredForAll(), policy.WithFederatedAssurance(mode), source)
	require.NoError(t, err)

	engine, err := policy.NewEngine(challenge, requirement)
	require.NoError(t, err)

	return append(append(oidcOptions(e), bearerOptions(e)...),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(fixtureTokens{})),
	)
}

// assertedLogin is completeLogin for a provider that asserts claims beside the
// subject.
func assertedLogin(claims map[string]any) func(t *testing.T, e *Effects) {
	return func(t *testing.T, e *Effects) {
		t.Helper()

		fx := e.OIDC

		auth, err := fx.Manager.Authorize(t.Context(), OIDCProvider, "")
		require.NoError(t, err)

		all := map[string]any{"sub": OIDCSubject}
		for k, v := range claims {
			all[k] = v
		}

		fx.FlowHandle = auth.Handle
		fx.CallbackPath = fx.IDP.Login(t, auth.RedirectURL, all)

		q := callbackQuery(t, fx.CallbackPath)

		res, err := fx.Manager.Callback(t.Context(), OIDCProvider, q.Get("code"), q.Get("state"), fx.FlowHandle)
		require.NoError(t, err)

		fx.HandoffCode, err = fx.Handoffs.Issue(t.Context(), res)
		require.NoError(t, err)
	}
}

// assuranceRedemption is a scenario that redeems the handoff of a login the
// provider asserted claims for, with the requirement policy in mode.
func assuranceRedemption(
	name string, mode policy.FederatedAssuranceMode, claims map[string]any, assert func(t *testing.T, res Result),
) Scenario {
	return Scenario{
		Name: name,
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			newOIDCFixture(t, effects)
			assertedLogin(claims)(t, effects)

			return ChainSpec{Options: assuranceOptions(t, effects, mode), Effects: effects, NoRoute: true}
		},
		Request: func(spec ChainSpec) RequestSpec {
			return postForm(httpsec.DefaultOIDCHandoffPath,
				url.Values{httpsec.DefaultOIDCHandoffParam: {spec.Effects.OIDC.HandoffCode}})
		},
		Assert: assert,
	}
}

// assuranceRequest is a scenario that makes a request as a federated session
// whose login the provider asserted amr for, with the requirement policy in
// mode. The assurance is evaluated again on this request, not carried over.
func assuranceRequest(
	name string, mode policy.FederatedAssuranceMode, amr []string, assert func(t *testing.T, res Result),
) Scenario {
	return Scenario{
		Name: name,
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			newOIDCFixture(t, effects)

			s, err := effects.Sessions.Create(t.Context(), UserID,
				session.WithFirstFactor(factor.OIDC),
				session.WithExternalSession(OIDCProvider, effects.OIDC.IDP.Issuer(), OIDCSessionID, OIDCIDToken),
				session.WithFederatedAssurance(amr, ""))
			require.NoError(t, err)

			effects.SessionID = s.ID

			return ChainSpec{
				Options: assuranceOptions(t, effects, mode),
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Request: authenticatedRequest(http.MethodGet, RoutePath),
		Assert:  assert,
	}
}

func oidcAssuranceScenarios() []Scenario {
	met := map[string]any{"amr": []string{"mfa"}}

	return []Scenario{
		assuranceRedemption("OIDC redemption with met assurance opens a session without a challenge",
			policy.FederatedAssuranceChallenge, met, func(t *testing.T, res Result) {
				require.NoError(t, res.Refusal)
				assert.Equal(t, http.StatusOK, res.Status)
				assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
				assert.Equal(t, 1, res.Effects.ActiveSessions(t))
			}),
		assuranceRedemption("OIDC redemption with unmet assurance is challenged for the local second factor",
			policy.FederatedAssuranceChallenge, nil, func(t *testing.T, res Result) {
				assert.Equal(t, http.StatusUnauthorized, res.Status)

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, res.Refusal, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.NotEmpty(t, challenge.Token)
				require.Len(t, challenge.Methods, 1)
				assert.Equal(t, "totp", challenge.Methods[0].Name)
				assert.Equal(t, 1, res.Effects.ActiveSessions(t))
				assert.Equal(t, session.MFAPending, res.Effects.LoadSession(t, challenge.Session.ID).MFA)
			}),
		assuranceRedemption("OIDC redemption with unmet assurance is refused in refuse mode",
			policy.FederatedAssuranceRefuse, nil, func(t *testing.T, res Result) {
				assert.Equal(t, http.StatusForbidden, res.Status)
				require.ErrorIs(t, res.Refusal, policy.ErrFederatedAssuranceNotMet)
				assert.Zero(t, res.Effects.ActiveSessions(t), "a refusal opens no session")
			}),
		assuranceRequest("a federated session with met assurance reaches the route",
			policy.FederatedAssuranceChallenge, []string{"mfa"}, func(t *testing.T, res Result) {
				require.NoError(t, res.Refusal)
				assert.True(t, res.RouteRan)
			}),
		assuranceRequest("a federated session with unmet assurance is challenged on the request",
			policy.FederatedAssuranceChallenge, nil, func(t *testing.T, res Result) {
				assert.Equal(t, http.StatusUnauthorized, res.Status)

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, res.Refusal, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.False(t, res.RouteRan)
			}),
		assuranceRequest("a federated session with unmet assurance is refused on the request in refuse mode",
			policy.FederatedAssuranceRefuse, nil, func(t *testing.T, res Result) {
				assert.Equal(t, http.StatusForbidden, res.Status)
				require.ErrorIs(t, res.Refusal, policy.ErrFederatedAssuranceNotMet)
				assert.False(t, res.RouteRan)
			}),
	}
}
