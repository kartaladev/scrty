package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// concurrentUser is the user every login in this file belongs to. The reference is
// opaque and is matched byte-for-byte, so the same value goes to the counter.
const concurrentUser identity.UserID = "user-7"

// errCountUnavailable stands for whatever went wrong inside a counter: a
// database that will not answer is the case the policy has to have an answer
// for.
var errCountUnavailable = errors.New("the session store is unreachable")

func TestConcurrentSessionPolicyEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		count  int
		err    error
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, d policy.Decision)
	}

	deniesAsTooMany := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Deny, d.Outcome, "a user at the cap was given another session")
		require.ErrorIs(t, d.Reason, policy.ErrTooManySessions,
			"a caller reporting the reason could not tell why the login was refused")
		assert.Equal(t, policy.ChallengeNone, d.Challenge, "a deny challenges for nothing")
	}

	cases := []testCase{
		{
			name:  "a user under the cap is allowed another session",
			count: 2,
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				assert.Equal(t, policy.Allow, d.Outcome)
				assert.NoError(t, d.Reason)
			},
		},
		{
			// "At the cap": a maximum of 3 and a user already holding 3.
			name:   "a user at the cap is denied",
			count:  3,
			assert: deniesAsTooMany,
		},
		{
			// A cap lowered after the sessions were established leaves users
			// above it, who must be refused rather than counted as under.
			name:   "a user above the cap is denied",
			count:  4,
			assert: deniesAsTooMany,
		},
		{
			// "Count failure": the reason wraps the error, so a caller can
			// tell an outage from a user who really is at the cap.
			name: "a count that fails denies, carrying the cause",
			err:  errCountUnavailable,
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				require.Equal(t, policy.Deny, d.Outcome,
					"a login was let through although nothing could say how many sessions the user holds")
				assert.ErrorIs(t, d.Reason, errCountUnavailable, "the cause of the refusal was lost")
				assert.ErrorIs(t, d.Reason, policy.ErrTooManySessions,
					"a caller matching the policy's own error could not tell which policy refused")
			},
		},
		{
			name: "a request whose context has ended denies",
			err:  context.Canceled,
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				require.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			counter := NewMockSessionCounter(gomock.NewController(t))
			counter.EXPECT().CountActiveByUser(gomock.Any(), concurrentUser).Return(tc.count, tc.err)

			p, err := policy.NewConcurrentSessionPolicy(counter, 3)
			require.NoError(t, err)

			tc.assert(t, p.Evaluate(ctx, &policy.Input{User: concurrentUser}))
		})
	}
}

func TestConcurrentSessionPolicyPhases(t *testing.T) {
	t.Parallel()

	p, err := policy.NewConcurrentSessionPolicy(NewMockSessionCounter(gomock.NewController(t)), 1)
	require.NoError(t, err)

	assert.Equal(t, []policy.Phase{policy.PostAuthentication}, p.Phases(),
		"the cap has to be applied before the session that would break it is established")
	assert.NotEmpty(t, p.Name(), "a policy with no name cannot be told apart in a log")
}

// TestConcurrentSessionPolicyTakesASessionStore pins the reason the port is
// declared here with exactly one method: a session.Store satisfies it as it
// stands, so a consumer wires the store they already have and neither package
// has to import the other.
func TestConcurrentSessionPolicyTakesASessionStore(t *testing.T) {
	t.Parallel()

	var store session.Store = session.NewMemoryStore()

	p, err := policy.NewConcurrentSessionPolicy(store, 1)
	require.NoError(t, err)

	d := p.Evaluate(t.Context(), &policy.Input{User: concurrentUser})
	assert.Equal(t, policy.Allow, d.Outcome, "a user holding no sessions was refused another")
}
