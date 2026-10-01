package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// TestMFAPolicies_HonourSecondFactorProof pins that both MFA policies honour
// the library's proof that a login met its second factor at the first, that
// the zero proof is judged like any other login, and that a replaced
// exemption rule does not hide the proof.
func TestMFAPolicies_HonourSecondFactorProof(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	exemptNothing := policy.WithMFAExemption(func(factor.Kind) bool { return false })

	// totpEnrolled is a user enrolled on TOTP, whose channel a passkey login
	// does not share, so without the proof they are challenged.
	totpEnrolled := func(t *testing.T) policy.MFAMethodLookup {
		return mfaMethod(t, factor.AuthenticatorApp, true, nil)
	}
	// passkeyOnly is a user whose only enrolment is on the passkey's own
	// channel, so without the proof they have no usable second factor.
	passkeyOnly := func(t *testing.T) policy.MFAMethodLookup {
		return namedMFAMethod(t, "passkey", factor.PublicKey, true, nil)
	}
	challengePolicy := func(lookup func(*testing.T) policy.MFAMethodLookup, opts ...policy.MFAOption) func(*testing.T) policy.Policy {
		return func(t *testing.T) policy.Policy { return mfaPolicyFor(t, lookup(t), opts...) }
	}
	requiredForAll := func(lookup func(*testing.T) policy.MFAMethodLookup, opts ...policy.MFARequirementOption) func(*testing.T) policy.Policy {
		return func(t *testing.T) policy.Policy {
			return mfaRequirementPolicyFor(t, nil, lookup(t),
				append([]policy.MFARequirementOption{policy.WithMFARequiredForAll()}, opts...)...)
		}
	}
	withProof := policy.Input{
		User: mfaUser, FirstFactor: factor.Passkey,
		SecondFactorAtLogin: policy.MintProofForTest(factor.Passkey, at), Now: at,
	}
	withoutProof := policy.Input{User: mfaUser, FirstFactor: factor.Passkey, Now: at}

	type testCase struct {
		name   string
		build  func(t *testing.T) policy.Policy
		in     policy.Input
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name:  "challenge policy allows on a holding proof",
			build: challengePolicy(totpEnrolled),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "challenge policy challenges on a zero proof",
			build: challengePolicy(totpEnrolled),
			in:    withoutProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Challenge, d.Outcome)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			name:  "challenge policy with an exemption rule exempting nothing still allows on the proof",
			build: challengePolicy(totpEnrolled, exemptNothing),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "requirement policy allows a required passkey-only user on the proof in post-authentication",
			build: requiredForAll(passkeyOnly),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:  "requirement policy denies the same user without it",
			build: requiredForAll(passkeyOnly),
			in:    withoutProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrMFAEnrollmentRequired)
			},
		},
		{
			name:  "requirement policy with an exemption rule exempting nothing still allows on the proof",
			build: requiredForAll(passkeyOnly, exemptNothing),
			in:    withProof,
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.build(t))
			require.NoError(t, err)

			in := tc.in
			tc.assert(t, e.EvaluatePhase(t.Context(), policy.PostAuthentication, &in))
		})
	}
}
