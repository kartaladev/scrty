package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
)

// challengingPolicy is a consumer's per-request policy raising kind for every caller.
type challengingPolicy struct{ kind policy.ChallengeKind }

func (challengingPolicy) Name() string           { return "consumer-challenge" }
func (challengingPolicy) Phases() []policy.Phase { return []policy.Phase{policy.PerRequest} }
func (p challengingPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Challenge, Challenge: p.kind}
}

// failingAssurance is an assurance source that cannot answer, with err.
type failingAssurance struct{ err error }

func (s failingAssurance) MeetsAssurance(context.Context, identity.UserID, policy.FederatedAssurance) (bool, error) {
	return false, s.err
}

// failingRequirement is a requirement lookup that cannot answer, with err.
type failingRequirement struct{ err error }

func (l failingRequirement) Required(context.Context, identity.UserID) (bool, error) {
	return false, l.err
}

// undeclaredFederated is undeclared, still reporting whether it needs a federated-assurance source.
type undeclaredFederated struct {
	undeclared

	u policy.FederatedAssuranceUser
}

func (p undeclaredFederated) NeedsFederatedAssuranceSource() bool {
	return p.u.NeedsFederatedAssuranceSource()
}

// policyEngine is a chain option running ps, hiding their challenge declarations.
func policyEngine(t *testing.T, ps ...policy.Policy) httpsec.Option {
	t.Helper()

	wrapped := make([]policy.Policy, 0, len(ps))
	for _, p := range ps {
		if u, ok := p.(policy.FederatedAssuranceUser); ok {
			wrapped = append(wrapped, undeclaredFederated{undeclared{p}, u})

			continue
		}

		wrapped = append(wrapped, undeclared{p})
	}

	engine, err := policy.NewEngine(wrapped...)
	require.NoError(t, err)

	return httpsec.WithPolicyEngine(engine)
}

// TestResourceServer_PerRequestPolicy pins how the per-request policy phase is answered for an
// access-token caller: any challenge is refused as insufficient user authentication, since no
// session can hold it, and an assurance source or requirement lookup that fails is a dependency
// failure (500), never a 401 sending the client round a sign-in loop.
func TestResourceServer_PerRequestPolicy(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())

	federated := func(s *oidcprovider.SignIn) {
		s.ExternalProvider, s.ExternalIssuer, s.ExternalAMR = "corp", "https://idp.example", []string{"mfa"}
	}

	requirement := func(t *testing.T, lookup identity.MFARequirementLookup, opts ...policy.MFARequirementOption) policy.Policy {
		t.Helper()

		p, err := policy.NewMFARequirement(lookup, []policy.MFAMethodLookup{asMethod{}}, opts...)
		require.NoError(t, err)

		return p
	}

	insufficient := func(t *testing.T, out psCall, failure error) {
		t.Helper()
		assert.Equal(t, http.StatusUnauthorized, out.status)
		assert.False(t, out.passedOn)
		assert.Equal(t, []string{`DPoP error="insufficient_user_authentication", algs="ES256"`},
			out.header.Values("WWW-Authenticate"))
		require.ErrorIs(t, failure, httpsec.ErrInsufficientUserAuthentication)

		var ch *httpsec.ChallengeError
		assert.False(t, errors.As(failure, &ch), "a challenge no session can hold is never answered as one")
	}

	dependency := func(t *testing.T, out psCall, failure error) {
		t.Helper()
		assert.Equal(t, http.StatusInternalServerError, out.status)
		assert.False(t, out.passedOn)
		assert.Empty(t, out.header.Values("WWW-Authenticate"))
		require.Error(t, failure)
		// The dependency's own error stays reachable beneath the fixed text, whatever it wraps; the
		// answer is the dependency failure's.
		status, recognised := httpsec.LookupStatus(failure)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.True(t, recognised, "the library claims the dependency failure as its own")
		assert.NotContains(t, failure.Error(), "secret text")
	}

	type testCase struct {
		name   string
		engine func(t *testing.T) httpsec.Option
		signIn func(*oidcprovider.SignIn)
		assert func(t *testing.T, out psCall, failure error)
	}

	cases := []testCase{
		{
			name: "a consumer's password-change challenge is refused as insufficient user authentication",
			engine: func(t *testing.T) httpsec.Option {
				return policyEngine(t, challengingPolicy{kind: policy.ChallengePasswordChange})
			},
			assert: insufficient,
		},
		{
			name: "a consumer's own challenge kind is refused as insufficient user authentication",
			engine: func(t *testing.T) httpsec.Option {
				return policyEngine(t, challengingPolicy{kind: policy.ChallengeKind(100)})
			},
			assert: insufficient,
		},
		{
			name: "an assurance source that fails is a dependency failure",
			engine: func(t *testing.T) httpsec.Option {
				return policyEngine(t, requirement(t, nil, policy.WithMFARequiredForAll(),
					policy.WithFederatedAssuranceSource(failingAssurance{err: errors.New("assurance secret text")})))
			},
			signIn: federated,
			assert: dependency,
		},
		{
			name: "an assurance source whose error wraps a refusal is still a dependency failure",
			engine: func(t *testing.T) httpsec.Option {
				return policyEngine(t, requirement(t, nil, policy.WithMFARequiredForAll(),
					policy.WithFederatedAssuranceSource(failingAssurance{
						err: fmt.Errorf("secret text: %w", policy.ErrInsufficientUserAuthentication),
					})))
			},
			signIn: federated,
			assert: dependency,
		},
		{
			name: "a requirement lookup that fails is a dependency failure",
			engine: func(t *testing.T) httpsec.Option {
				return policyEngine(t, requirement(t, failingRequirement{err: errors.New("lookup secret text")}))
			},
			assert: dependency,
		},
		{
			name: "a requirement lookup whose error wraps an invalid token is still a dependency failure",
			engine: func(t *testing.T) httpsec.Option {
				return policyEngine(t, requirement(t, failingRequirement{
					err: fmt.Errorf("secret text: %w", httpsec.ErrInvalidToken),
				}))
			},
			assert: dependency,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			failure := &atomic.Pointer[error]{}
			w := newPSWorld(t, psSetup{failure: failure, chain: []httpsec.Option{tc.engine(t)}})
			w.signIn = tc.signIn

			out := w.call(t, w.token(t, psJWTClient, &k, forAPI), &k, "j-1")

			var err error
			if f := failure.Load(); f != nil {
				err = *f
			}

			tc.assert(t, out, err)
		})
	}
}

// TestResourceServer_AssuranceSourceWiring pins that a chain whose MFA requirement policy judges
// external access tokens refuses to build when a source resolves local users from them (linked users
// or a claims mapper) and the policy has no federated-assurance source, which would judge every such
// caller as unmet; and that exempt mode, an oidc exemption, or a given source builds.
func TestResourceServer_AssuranceSourceWiring(t *testing.T) {
	t.Parallel()

	const iss = "https://sso.example"

	mapper := func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
		return httpsec.MappedCaller{}, nil
	}

	requirement := func(opts ...policy.MFARequirementOption) func(t *testing.T) httpsec.Option {
		return func(t *testing.T) httpsec.Option {
			t.Helper()

			p, err := policy.NewMFARequirement(nil, []policy.MFAMethodLookup{asMethod{}},
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)...)
			require.NoError(t, err)

			return policyEngine(t, p)
		}
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "FromIssuer("+iss+")")
		assert.Contains(t, err.Error(), "WithFederatedAssuranceSource")
	}

	built := func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) }

	type testCase struct {
		name     string
		engine   func(t *testing.T) httpsec.Option
		strategy func(t *testing.T) httpsec.SourceOption
		assert   func(t *testing.T, err error)
	}

	linked := func(t *testing.T) httpsec.SourceOption {
		return httpsec.WithLinkedUsers(isLinks(t, iss, false), "corp", isUsers(t, false))
	}
	mapped := func(*testing.T) httpsec.SourceOption { return httpsec.WithClaimsMapper("corp", mapper) }
	claimsOnly := func(*testing.T) httpsec.SourceOption { return httpsec.WithClaimsOnly() }

	cases := []testCase{
		{name: "linked users with no assurance source", engine: requirement(), strategy: linked, assert: refused},
		{name: "a claims mapper with no assurance source", engine: requirement(), strategy: mapped, assert: refused},
		{
			name:     "refuse mode with no assurance source",
			engine:   requirement(policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)),
			strategy: linked, assert: refused,
		},
		{name: "claims only needs no assurance source", engine: requirement(), strategy: claimsOnly, assert: built},
		{
			name:     "exempt mode needs no assurance source",
			engine:   requirement(policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)),
			strategy: linked, assert: built,
		},
		{
			name:     "a policy given an assurance source builds",
			engine:   requirement(policy.WithFederatedAssuranceSource(asSource{})),
			strategy: linked, assert: built,
		},
		{
			name:     "no policy engine judges nothing",
			strategy: linked, assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []httpsec.Option{
				httpsec.EnableResourceServer("urn:orders",
					httpsec.FromIssuer(iss, httpsec.WithUnboundTokens(), tc.strategy(t))),
			}
			if tc.engine != nil {
				opts = append([]httpsec.Option{tc.engine(t)}, opts...)
			}

			_, err := httpsec.New(opts...)
			tc.assert(t, err)
		})
	}
}

// TestResourceServer_LinkedUserAssurance pins that a linked user's external token asserting amr mfa
// meets the requirement through the policy's assurance source, and one asserting pwd is refused.
func TestResourceServer_LinkedUserAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		amr    []string
		assert func(t *testing.T, out riCall)
	}

	cases := []testCase{
		{
			name: "amr mfa meets the requirement",
			amr:  []string{"mfa"},
			assert: func(t *testing.T, out riCall) {
				require.Equal(t, http.StatusOK, out.status, out.body)
				assert.True(t, out.ran)
			},
		},
		{
			name: "amr pwd is insufficient user authentication",
			amr:  []string{"pwd"},
			assert: func(t *testing.T, out riCall) {
				assert.Equal(t, http.StatusUnauthorized, out.status)
				assert.False(t, out.ran)
				assert.Equal(t, []string{`Bearer error="insufficient_user_authentication"`},
					out.header.Values("WWW-Authenticate"))
				require.ErrorIs(t, out.failure, httpsec.ErrInsufficientUserAuthentication)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewMFARequirement(nil, []policy.MFAMethodLookup{asMethod{}},
				policy.WithMFARequiredForAll(), policy.WithFederatedAssuranceSource(asSource{}))
			require.NoError(t, err)

			w := newRIWorld(t, riSetup{
				chain: []httpsec.Option{policyEngine(t, p)},
				opts: func(w *riWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithLinkedUsers(isLinks(t, w.issuers[0].iss, true), "corp", isUsers(t, true))}
				},
			})

			tok := w.token(t, w.issuers[0], w.issuers[0].keys[0], func(tok *riToken) { tok.claims["amr"] = tc.amr })
			tc.assert(t, w.call(t, tok, nil))
		})
	}
}
