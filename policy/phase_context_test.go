package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestEngineTellsPolicyItsPhase pins that a policy whose answer depends on the
// phase learns the phase from the engine that is asking, with nothing added to
// the context by the consumer.
//
// The real MFA requirement policy is driven through a real Engine here, rather
// than evaluated directly as the requirement policy's own table does, because
// what is under test is the engine's side of the arrangement: Input carries no
// phase, so an engine that passed its context through unchanged would leave
// every phase-sensitive policy unable to tell a login from a stateless request
// — and that policy fails closed, refusing users the phase says to challenge or
// allow.
func TestEngineTellsPolicyItsPhase(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		phase  policy.Phase
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			// The "Flagged mid-session" scenario: a user becomes required
			// during a session that has not satisfied a second factor, and is
			// enrolled on a usable method.
			name:  "a required, enrolled user is challenged in the per-request phase",
			phase: policy.PerRequest,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Challenge, d.Outcome,
					"a required user the engine could have challenged answered %v (%v)",
					d.Outcome, d.Reason)
				assert.Equal(t, policy.ChallengeMFA, d.Challenge)
			},
		},
		{
			// Post-authentication leaves the login challenge to the
			// second-factor challenge policy, so this one raises no objection.
			name:  "a required, enrolled user is allowed in the post-authentication phase",
			phase: policy.PostAuthentication,
			assert: func(t *testing.T, d policy.Decision) {
				require.Equal(t, policy.Allow, d.Outcome,
					"a login the challenge policy owns answered %v (%v)", d.Outcome, d.Reason)
				assert.NoError(t, d.Reason)
				assert.Equal(t, policy.ChallengeNone, d.Challenge)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := mfaRequirementPolicyFor(t,
				mfaRequirementLookup(t, true, true, nil),
				mfaMethod(t, factor.AuthenticatorApp, true, nil))

			e, err := policy.NewEngine(p)
			require.NoError(t, err)

			in := &policy.Input{
				User:         mfaUser,
				Session:      &session.Session{ID: "s-1", UserID: mfaUser},
				FirstFactor:  factor.Password,
				MFASatisfied: false,
				Now:          mfaNow,
			}

			// A plain context: a consumer that registered the policy with an
			// engine has said which phase it is evaluating by calling
			// EvaluatePhase, and should not have to say it twice.
			tc.assert(t, e.EvaluatePhase(t.Context(), tc.phase, in))
		})
	}
}
