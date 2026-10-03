package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// TestEngine_UnwiredFederatedAssurance pins which registered policies report
// that they decide federated logins on provider assurance with no source to
// decide by: the requirement policy, unless it is given a source or exempts
// federated logins outright, and never a policy that decides nothing on it.
func TestEngine_UnwiredFederatedAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		policies func(t *testing.T) []policy.Policy
		assert   func(t *testing.T, unwired []string)
	}

	requirement := func(opts ...policy.MFARequirementOption) func(t *testing.T) []policy.Policy {
		return func(t *testing.T) []policy.Policy {
			p, err := policy.NewMFARequirementPolicy(nil,
				mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp))),
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)...)
			require.NoError(t, err)

			return []policy.Policy{p}
		}
	}

	unwired := func(t *testing.T, got []string) {
		t.Helper()
		assert.Equal(t, []string{"mfa-requirement"}, got)
	}
	wired := func(t *testing.T, got []string) {
		t.Helper()
		assert.Empty(t, got)
	}

	cases := []testCase{
		{
			name:     "the requirement policy in the default mode without a source",
			policies: requirement(),
			assert:   unwired,
		},
		{
			name:     "the requirement policy in refuse mode without a source",
			policies: requirement(policy.WithFederatedAssurance(policy.FederatedAssuranceRefuse)),
			assert:   unwired,
		},
		{
			name: "the requirement policy with a source",
			policies: func(t *testing.T) []policy.Policy {
				return requirement(policy.WithFederatedAssuranceSource(assuranceSource(t, false, false, nil)))(t)
			},
			assert: wired,
		},
		{
			name:     "the requirement policy in exempt mode needs no source",
			policies: requirement(policy.WithFederatedAssurance(policy.FederatedAssuranceExempt)),
			assert:   wired,
		},
		{
			name: "the requirement policy under an exemption rule exempting oidc needs no source",
			policies: requirement(policy.WithMFAExemption(func(k factor.Kind) bool {
				return k == factor.OIDC || k.MFAExempt()
			})),
			assert: wired,
		},
		{
			name: "the challenge policy without its opt-in needs no source",
			policies: func(t *testing.T) []policy.Policy {
				p, err := policy.NewMFAPolicy(mfaMethods(idleMFAMethod(t, mfaMethodName(factor.AuthenticatorApp))))
				require.NoError(t, err)

				return []policy.Policy{p}
			},
			assert: wired,
		},
		{
			name: "every unwired registration is reported, in registration order",
			policies: func(t *testing.T) []policy.Policy {
				return append(requirement()(t), requirement()(t)...)
			},
			assert: func(t *testing.T, got []string) {
				assert.Equal(t, []string{"mfa-requirement", "mfa-requirement"}, got,
					"one entry per registered policy, so two registrations are both reported")
			},
		},
		{
			name:     "an engine with no policies reports none",
			policies: func(*testing.T) []policy.Policy { return nil },
			assert:   wired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policies(t)...)
			require.NoError(t, err)

			tc.assert(t, e.UnwiredFederatedAssurance())
		})
	}
}
