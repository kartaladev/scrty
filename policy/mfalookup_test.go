package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
)

// TestMFAMethodLookupContract drives a method lookup through each of the three
// answers its contract names — enrolled, not enrolled, and an error — and
// records what each of the two MFA policies does with it.
//
// The rows are the contract: a confirmed enrolment whose secret opens is
// enrolled; an enrolment that was started and never confirmed is not; a store
// failure and a secret that will not decrypt are errors. The assertions are
// what the contract is for: neither policy may read an error as "this user has
// no second factor", because that would let a lost row or an unreadable secret
// downgrade the users who had enrolled.
func TestMFAMethodLookupContract(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		enrolled  bool
		lookupErr error
		assert    func(t *testing.T, challenge, requirement policy.Decision)
	}

	refusesOnError := func(t *testing.T, challenge, requirement policy.Decision, cause error) {
		t.Helper()

		require.Equal(t, policy.Deny, challenge.Outcome,
			"the challenge policy read a failed lookup as a user with no second factor")
		assert.ErrorIs(t, challenge.Reason, cause,
			"the challenge policy's refusal does not say what failed")

		require.Equal(t, policy.Deny, requirement.Outcome,
			"the requirement policy read a failed lookup as a user with no second factor")
		assert.ErrorIs(t, requirement.Reason, cause,
			"the requirement policy's refusal does not say what failed")
	}

	cases := []testCase{
		{
			name:     "a confirmed enrolment whose secret opens is enrolled",
			enrolled: true,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Challenge, challenge.Outcome,
					"an enrolled user was not challenged at login")
				assert.Equal(t, policy.Challenge, requirement.Outcome,
					"a required, enrolled user was not challenged")
			},
		},
		{
			name:     "an enrolment that was never confirmed is not an enrolment",
			enrolled: false,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				assert.Equal(t, policy.Allow, challenge.Outcome,
					"an unconfirmed enrolment was challenged for, which nobody could answer")
				require.Equal(t, policy.Deny, requirement.Outcome)
				assert.ErrorIs(t, requirement.Reason, policy.ErrMFAEnrollmentRequired,
					"a required user with no confirmed enrolment was not asked to enrol")
			},
		},
		{
			name:      "a store failure is an error, never a user with no second factor",
			lookupErr: errEnrolmentStore,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				refusesOnError(t, challenge, requirement, errEnrolmentStore)
			},
		},
		{
			name:      "a secret that will not decrypt is an error, never a user with no second factor",
			lookupErr: errSecretUnreadable,
			assert: func(t *testing.T, challenge, requirement policy.Decision) {
				refusesOnError(t, challenge, requirement, errSecretUnreadable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			method := mfaMethod(t, factor.AuthenticatorApp, tc.enrolled, tc.lookupErr)
			in := mfaInput(factor.Password)

			challenge := mfaPolicyFor(t, method).Evaluate(t.Context(), in)

			requirement := mfaRequirementPolicyFor(t,
				mfaRequirementLookup(t, true, true, nil), method).
				Evaluate(mfaPhaseContext(t, policy.PerRequest), in)

			tc.assert(t, challenge, requirement)
		})
	}
}
