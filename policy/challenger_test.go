package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
)

// challengingStub is a policy that declares the challenges it can raise. It
// stands in for a consumer's own rule, which is the case the optional interface
// exists for.
type challengingStub struct {
	stubPolicy

	kinds []policy.ChallengeKind
}

func (c challengingStub) Challenges() []policy.ChallengeKind { return c.kinds }

// TestEngineCanChallenge pins what an engine will say about the challenges its
// policies can raise, which is what a chain checks its own wiring against: a
// challenge nothing enforces is a session marked pending forever and a caller
// served anyway.
func TestEngineCanChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		policies func(t *testing.T) []policy.Policy
		assert   func(t *testing.T, e *policy.Engine)
	}

	secondFactor := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewMFAPolicy([]policy.MFAMethodLookup{idleMFAMethod(t, "totp")})
		require.NoError(t, err)

		return p
	}

	requirement := func(t *testing.T) policy.Policy {
		t.Helper()

		ctrl := gomock.NewController(t)

		p, err := policy.NewMFARequirementPolicy(
			NewMockMFARequirementLookup(ctrl), mfaMethods(idleMFAMethod(t, "totp")))
		require.NoError(t, err)

		return p
	}

	passwordAge := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewPasswordAgePolicy()
		require.NoError(t, err)

		return p
	}

	cases := []testCase{
		{
			name:     "an engine with no policies",
			policies: func(*testing.T) []policy.Policy { return nil },
			assert: func(t *testing.T, e *policy.Engine) {
				assert.False(t, e.CanChallenge(policy.ChallengeMFA))
				assert.False(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			name: "the second-factor challenge policy",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{secondFactor(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.False(t, e.CanChallenge(policy.ChallengePasswordChange),
					"it raises one kind, and says so")
			},
		},
		{
			name: "the requirement policy",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{requirement(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.False(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			name: "the password-age policy",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{passwordAge(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengePasswordChange))
				assert.False(t, e.CanChallenge(policy.ChallengeMFA),
					"a password change is not a second factor")
			},
		},
		{
			name: "several policies, one of which challenges for a second factor",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				return []policy.Policy{passwordAge(t), secondFactor(t)}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.True(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			name: "a consumer's policy that declares the challenges it raises",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{challengingStub{
					stubPolicy: stubPolicy{
						name:     "consumer rule",
						phases:   []policy.Phase{policy.PostAuthentication},
						decision: policy.Decision{Outcome: policy.Allow},
					},
					kinds: []policy.ChallengeKind{
						policy.ChallengePasswordChange,
						policy.ChallengeMFA,
					},
				}}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.True(t, e.CanChallenge(policy.ChallengeMFA))
				assert.True(t, e.CanChallenge(policy.ChallengePasswordChange))
			},
		},
		{
			// The documented limit of the answer: a policy that does not
			// declare its challenges is taken to raise none, so a consumer
			// whose own rule challenges has to implement Challenger for a
			// chain to be able to check their wiring.
			name: "a policy that challenges without declaring it",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{stubPolicy{
					name:   "undeclared",
					phases: []policy.Phase{policy.PostAuthentication},
					decision: policy.Decision{
						Outcome:   policy.Challenge,
						Challenge: policy.ChallengeMFA,
					},
				}}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.False(t, e.CanChallenge(policy.ChallengeMFA),
					"silence is read as raising nothing, not as raising anything")
			},
		},
		{
			name: "a policy registered in no phase at all",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{challengingStub{
					stubPolicy: stubPolicy{name: "never asked"},
					kinds:      []policy.ChallengeKind{policy.ChallengeMFA},
				}}
			},
			assert: func(t *testing.T, e *policy.Engine) {
				assert.False(t, e.CanChallenge(policy.ChallengeMFA),
					"a policy no phase asks cannot raise anything")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e, err := policy.NewEngine(tc.policies(t)...)
			require.NoError(t, err)

			tc.assert(t, e)
		})
	}
}

// TestChallengesDoesNotAliasPolicyState pins that a caller cannot write into a
// policy's own state through what it reported.
func TestChallengesDoesNotAliasPolicyState(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		policy func(t *testing.T) policy.Challenger
	}

	cases := []testCase{
		{
			name: "the second-factor challenge policy",
			policy: func(t *testing.T) policy.Challenger {
				t.Helper()

				p, err := policy.NewMFAPolicy([]policy.MFAMethodLookup{idleMFAMethod(t, "totp")})
				require.NoError(t, err)

				c, ok := p.(policy.Challenger)
				require.True(t, ok)

				return c
			},
		},
		{
			name: "the requirement policy",
			policy: func(t *testing.T) policy.Challenger {
				t.Helper()

				ctrl := gomock.NewController(t)

				p, err := policy.NewMFARequirementPolicy(
					NewMockMFARequirementLookup(ctrl), mfaMethods(idleMFAMethod(t, "totp")))
				require.NoError(t, err)

				c, ok := p.(policy.Challenger)
				require.True(t, ok)

				return c
			},
		},
		{
			name: "the password-age policy",
			policy: func(t *testing.T) policy.Challenger {
				t.Helper()

				p, err := policy.NewPasswordAgePolicy()
				require.NoError(t, err)

				return p
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := tc.policy(t)

			reported := p.Challenges()
			require.NotEmpty(t, reported)

			before := reported[0]
			reported[0] = policy.ChallengeNone

			assert.Equal(t, before, p.Challenges()[0],
				"what a policy reports is a copy, not a way into its own state")
		})
	}
}

// Compile-time proof that the stub satisfies both ports it stands in for.
var (
	_ policy.Policy     = challengingStub{}
	_ policy.Challenger = challengingStub{}
)
