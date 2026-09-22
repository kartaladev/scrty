package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestTimeoutPolicyConfigurationErrors pins that a value which would make one
// of these policies fire on everything, or on nothing, is refused while the
// application is being wired rather than discovered from its traffic.
func TestTimeoutPolicyConfigurationErrors(t *testing.T) {
	t.Parallel()

	// A counter held by a nil pointer: what an unchecked constructor result
	// hands over, and what `if counter == nil` fails to catch.
	var absentStore *session.MemoryStore

	type testCase struct {
		name        string
		construct   func() (policy.Policy, error)
		names       string // the part of the message that says what is wrong
		consequence string // the part that says what it would have done
	}

	cases := []testCase{
		{
			name: "an idle timeout of zero",
			construct: func() (policy.Policy, error) {
				return policy.NewIdleTimeoutPolicy(policy.WithIdlePolicyTimeout(0))
			},
			names:       "idle timeout must be positive",
			consequence: "refuse every request",
		},
		{
			name: "a negative idle timeout",
			construct: func() (policy.Policy, error) {
				return policy.NewIdleTimeoutPolicy(policy.WithIdlePolicyTimeout(-time.Minute))
			},
			names:       "idle timeout must be positive",
			consequence: "refuse every request",
		},
		{
			name: "an absolute timeout of zero",
			construct: func() (policy.Policy, error) {
				return policy.NewIdleTimeoutPolicy(policy.WithIdlePolicyAbsoluteTimeout(0))
			},
			names:       "absolute timeout must be positive",
			consequence: "already past its final deadline",
		},
		{
			name: "a maximum password age of zero",
			construct: func() (policy.Policy, error) {
				return policy.NewPasswordAgePolicy(policy.WithMaxPasswordAge(0))
			},
			names:       "maximum password age must be positive",
			consequence: "challenge every login",
		},
		{
			name: "a negative maximum password age",
			construct: func() (policy.Policy, error) {
				return policy.NewPasswordAgePolicy(policy.WithMaxPasswordAge(-time.Hour))
			},
			names:       "maximum password age must be positive",
			consequence: "challenge every login",
		},
		{
			// A mode from outside the enumeration would otherwise fall to
			// whichever branch the implementation happens to end in, which is
			// not a decision anybody made.
			name: "an unknown-change-time mode naming neither choice",
			construct: func() (policy.Policy, error) {
				return policy.NewPasswordAgePolicy(policy.WithUnknownPasswordAge(policy.UnknownPasswordAge(7)))
			},
			names:       "unknown-password-age mode",
			consequence: "AllowUnknown nor ChallengeUnknown",
		},
		{
			// "Zero maximum": a cap of zero refuses every login, since every
			// user already holds at least none.
			name: "a maximum of zero sessions",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessionPolicy(session.NewMemoryStore(), 0)
			},
			names:       "maximum number of sessions must be positive",
			consequence: "refuse every login",
		},
		{
			name: "a negative maximum of sessions",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessionPolicy(session.NewMemoryStore(), -1)
			},
			names:       "maximum number of sessions must be positive",
			consequence: "refuse every login",
		},
		{
			name: "no session counter at all",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessionPolicy(nil, 3)
			},
			names:       "session counter must not be nil",
			consequence: "no count can be made",
		},
		{
			name: "a session counter held by a nil pointer",
			construct: func() (policy.Policy, error) {
				return policy.NewConcurrentSessionPolicy(absentStore, 3)
			},
			names:       "session counter must not be nil",
			consequence: "no count can be made",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := tc.construct()

			require.ErrorIs(t, err, policy.ErrConfig,
				"a wiring mistake was not reported as a configuration error")
			assert.ErrorContains(t, err, tc.names, "the error does not say what was rejected")
			assert.ErrorContains(t, err, tc.consequence,
				"the error does not say what the policy would have done")
			assert.Nil(t, p, "a refused configuration handed back a policy to register")
		})
	}
}
