package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/policy"
)

func TestPhaseString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		phase  policy.Phase
		assert func(t *testing.T, got string)
	}

	named := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()

			assert.Equal(t, want, got, "a log line would not name the phase it reports")
		}
	}

	cases := []testCase{
		{name: "pre-authentication", phase: policy.PreAuthentication, assert: named("PreAuthentication")},
		{name: "post-authentication", phase: policy.PostAuthentication, assert: named("PostAuthentication")},
		{name: "per-request", phase: policy.PerRequest, assert: named("PerRequest")},
		{name: "post-handler", phase: policy.PostHandler, assert: named("PostHandler")},
		{
			name:   "stateless authentication",
			phase:  policy.StatelessAuthentication,
			assert: named("StatelessAuthentication"),
		},
		{
			// A value from outside the enumeration must not read in a log as
			// one of the five phases the library actually evaluates.
			name:   "a value naming no phase prints its number",
			phase:  policy.Phase(7),
			assert: named("Phase(7)"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.phase.String())
		})
	}
}

func TestOutcomeString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		outcome policy.Outcome
		assert  func(t *testing.T, got string)
	}

	named := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()

			assert.Equal(t, want, got, "a log line would not name the outcome it reports")
		}
	}

	cases := []testCase{
		{name: "allow", outcome: policy.Allow, assert: named("Allow")},
		{name: "deny", outcome: policy.Deny, assert: named("Deny")},
		{name: "challenge", outcome: policy.Challenge, assert: named("Challenge")},
		{
			name:    "a value naming no outcome prints its number",
			outcome: policy.Outcome(9),
			assert:  named("Outcome(9)"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.outcome.String())
		})
	}
}

func TestChallengeKindString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		challenge policy.ChallengeKind
		assert    func(t *testing.T, got string)
	}

	named := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()

			assert.Equal(t, want, got, "a log line would not name the challenge it reports")
		}
	}

	cases := []testCase{
		{name: "none", challenge: policy.ChallengeNone, assert: named("ChallengeNone")},
		{name: "mfa", challenge: policy.ChallengeMFA, assert: named("ChallengeMFA")},
		{
			name:      "password change",
			challenge: policy.ChallengePasswordChange,
			assert:    named("ChallengePasswordChange"),
		},
		{
			name:      "a value naming no challenge prints its number",
			challenge: policy.ChallengeKind(4),
			assert:    named("ChallengeKind(4)"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.challenge.String())
		})
	}
}
