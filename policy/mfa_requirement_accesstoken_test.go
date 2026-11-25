package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
)

// TestMFARequirementPolicy_AccessTokens pins how the requirement policy judges an access-token
// caller: by the library-minted assurance and re-matched federated evidence, never by a challenge.
func TestMFARequirementPolicy_AccessTokens(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		required func(t *testing.T) identity.MFARequirementLookup
		source   func(t *testing.T) policy.FederatedAssuranceSource
		opts     []policy.MFARequirementOption
		phase    policy.Phase
		in       func() *policy.Input
		assert   func(t *testing.T, d policy.Decision)
	}

	requiredUser := func(t *testing.T) identity.MFARequirementLookup {
		return mfaRequirementLookup(t, true, true, nil)
	}
	notLookedUp := func(t *testing.T) identity.MFARequirementLookup {
		return mfaRequirementLookup(t, false, false, nil)
	}
	source := func(asked, met bool, err error) func(t *testing.T) policy.FederatedAssuranceSource {
		return func(t *testing.T) policy.FederatedAssuranceSource { return assuranceSource(t, asked, met, err) }
	}

	// token is an access-token caller of kind with assurance a and evidence ev.
	token := func(kind factor.Kind, a policy.AccessTokenAssurance, ev policy.FederatedAssurance) func() *policy.Input {
		return func() *policy.Input {
			in := federatedInput(kind, ev)
			in.AccessTokenAssurance = a

			return in
		}
	}
	local := policy.MintAccessTokenAssuranceForTest(true, false)
	localWithSecondFactor := policy.MintAccessTokenAssuranceForTest(true, true)
	external := policy.MintAccessTokenAssuranceForTest(false, false)

	allowed := func(t *testing.T, d policy.Decision) {
		t.Helper()
		assert.Equal(t, policy.Allow, d.Outcome, "reason: %v", d.Reason)
	}
	insufficient := deniedWith(policy.ErrInsufficientUserAuthentication)

	cases := []testCase{
		{
			name:     "the zero assurance of a provider token is denied as insufficient",
			required: requiredUser,
			in:       token(factor.AccessToken, policy.AccessTokenAssurance{}, policy.FederatedAssurance{}),
			assert:   insufficient,
		},
		{
			name:     "a provider token whose grant has no library marker is denied as insufficient",
			required: requiredUser,
			in:       token(factor.AccessToken, local, policy.FederatedAssurance{}),
			assert:   insufficient,
		},
		{
			name:     "a provider token whose grant has the library marker is allowed",
			required: requiredUser,
			in:       token(factor.AccessToken, localWithSecondFactor, policy.FederatedAssurance{}),
			assert:   allowed,
		},
		{
			name:     "a provider token from a federated grant whose evidence is met is allowed",
			required: requiredUser,
			source:   source(true, true, nil),
			in:       token(factor.AccessToken, local, federatedEvidence("mfa")),
			assert:   allowed,
		},
		{
			name:     "a provider token from a federated grant after assurance is tightened is denied as insufficient",
			required: requiredUser,
			source:   source(true, false, nil),
			in:       token(factor.AccessToken, local, federatedEvidence("mfa")),
			assert:   insufficient,
		},
		{
			name:     "a provider token from a federated grant is allowed in exempt mode without a lookup",
			required: notLookedUp,
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			in:       token(factor.AccessToken, local, federatedEvidence()),
			assert:   allowed,
		},
		{
			name:     "a provider token from a password grant is not exempted by exempt mode",
			required: requiredUser,
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			in:       token(factor.AccessToken, local, policy.FederatedAssurance{}),
			assert:   insufficient,
		},
		{
			name:     "a provider token from a federated grant is allowed by an exemption rule for oidc",
			required: notLookedUp,
			opts: []policy.MFARequirementOption{policy.WithMFAExemption(func(k factor.Kind) bool {
				return k == factor.OIDC || k.MFAExempt()
			})},
			in:     token(factor.AccessToken, local, federatedEvidence()),
			assert: allowed,
		},
		{
			name:     "a provider token whose evidence source fails is denied, not as insufficient",
			required: requiredUser,
			source:   source(true, false, errAssuranceSource),
			in:       token(factor.AccessToken, local, federatedEvidence("mfa")),
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()
				require.Equal(t, policy.Deny, d.Outcome)
				require.ErrorIs(t, d.Reason, errAssuranceSource)
				assert.NotErrorIs(t, d.Reason, policy.ErrInsufficientUserAuthentication)
			},
		},
		{
			name:     "a caller naming no local user is allowed without a lookup",
			required: notLookedUp,
			opts:     []policy.MFARequirementOption{},
			in:       token(factor.ExternalAccessToken, external, federatedEvidence("pwd")),
			assert:   allowed,
		},
		{
			name:     "a password-only external token of a local user is denied as insufficient in challenge mode",
			required: requiredUser,
			source:   source(true, false, nil),
			in:       token(factor.ExternalAccessToken, local, federatedEvidence("pwd")),
			assert:   insufficient,
		},
		{
			name:     "a password-only external token of a local user is denied as insufficient in refuse mode",
			required: requiredUser,
			source:   source(true, false, nil),
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)},
			in:       token(factor.ExternalAccessToken, local, federatedEvidence("pwd")),
			assert:   insufficient,
		},
		{
			name:     "an external token of a local user whose evidence is met is allowed",
			required: requiredUser,
			source:   source(true, true, nil),
			in:       token(factor.ExternalAccessToken, local, federatedEvidence("mfa")),
			assert:   allowed,
		},
		{
			name:     "an external token is allowed in exempt mode",
			required: notLookedUp,
			opts:     []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			in:       token(factor.ExternalAccessToken, local, federatedEvidence("pwd")),
			assert:   allowed,
		},
		{
			name:     "an external token is allowed by an exemption rule for oidc",
			required: notLookedUp,
			opts: []policy.MFARequirementOption{policy.WithMFAExemption(func(k factor.Kind) bool {
				return k == factor.OIDC || k.MFAExempt()
			})},
			in:     token(factor.ExternalAccessToken, local, federatedEvidence("pwd")),
			assert: allowed,
		},
		{
			name:     "a provider token of a user not required is allowed",
			required: func(t *testing.T) identity.MFARequirementLookup { return mfaRequirementLookup(t, true, false, nil) },
			in:       token(factor.AccessToken, local, policy.FederatedAssurance{}),
			assert:   allowed,
		},
		{
			name:     "a provider token in the stateless phase is denied as required",
			required: requiredUser,
			phase:    policy.StatelessAuthentication,
			in:       token(factor.AccessToken, local, policy.FederatedAssurance{}),
			assert:   deniedWith(policy.ErrMFARequired),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			if tc.source != nil {
				opts = append(opts, policy.WithFederatedAssuranceSource(tc.source(t)))
			}

			p := mfaRequirementPolicyOver(t, tc.required(t),
				mfaMethods(mfaMethod(t, factor.AuthenticatorApp, true, nil)), opts...)

			phase := tc.phase
			if phase == 0 {
				phase = policy.PerRequest
			}

			tc.assert(t, p.Evaluate(mfaPhaseContext(t, phase), tc.in()))
		})
	}
}
