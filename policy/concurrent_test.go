package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
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
		name  string
		count int
		err   error
		// reauthenticating marks the input as the re-authentication of a
		// session the user already holds.
		reauthenticating bool
		ctx              func(ctx context.Context) context.Context
		assert           func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason)
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
			name:   "a user under the cap is allowed another session",
			count:  2,
			assert: allows,
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
			// "A re-proof at the cap": the re-proved session is one of the
			// three counted, and a re-proof adds none.
			name:             "a re-authentication by a user at the cap is allowed",
			count:            3,
			reauthenticating: true,
			assert:           allows,
		},
		{
			name:             "a re-authentication by a user above the cap is denied",
			count:            4,
			reauthenticating: true,
			assert:           deniesAsTooMany,
		},
		{
			name:             "a re-authentication under the cap is allowed",
			count:            2,
			reauthenticating: true,
			assert:           allows,
		},
		{
			name:             "a re-authentication whose count fails denies, carrying the cause",
			err:              errCountUnavailable,
			reauthenticating: true,
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				require.Equal(t, policy.Deny, d.Outcome, "a re-proof was let through on a count nobody made")
				assert.ErrorIs(t, d.Reason, errCountUnavailable)
				assert.ErrorIs(t, d.Reason, policy.ErrTooManySessions)
			},
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

			p, err := policy.NewConcurrentSessions(counter, 3)
			require.NoError(t, err)

			tc.assert(t, p.Evaluate(ctx, &policy.Input{User: concurrentUser, Reauthenticating: tc.reauthenticating}))
		})
	}
}

func TestConcurrentSessionPolicyPhases(t *testing.T) {
	t.Parallel()

	p, err := policy.NewConcurrentSessions(NewMockSessionCounter(gomock.NewController(t)), 1)
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

	var store session.Store = must.Must(session.NewMemoryStore())

	p, err := policy.NewConcurrentSessions(store, 1)
	require.NoError(t, err)

	d := p.Evaluate(t.Context(), &policy.Input{User: concurrentUser})
	assert.Equal(t, policy.Allow, d.Outcome, "a user holding no sessions was refused another")
}

// TestConcurrentSessionPolicyCountsEnrolmentOnlySessionsUntilTheyExpire pins
// the scenario "Enrolment-only sessions count until they expire" through the
// policy, over the session manager that does the counting: a user holding one
// enrolment-only session, with a cap of one, is refused another while the
// session's lowered deadline has not passed, and allowed one after.
func TestConcurrentSessionPolicyCountsEnrolmentOnlySessionsUntilTheyExpire(t *testing.T) {
	t.Parallel()

	// enrolmentLifetime is the default enrolment lifetime.
	const enrolmentLifetime = 15 * time.Minute

	started := time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name string
		// at is when the login is judged.
		at     time.Time
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name: "a login before the lowered deadline is denied as too many sessions",
			at:   started.Add(10 * time.Minute),
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				require.Equal(t, policy.Deny, d.Outcome, "the enrolment-only session was not counted")
				require.ErrorIs(t, d.Reason, policy.ErrTooManySessions)
			},
		},
		{
			name: "a login after the lowered deadline is allowed",
			at:   started.Add(16 * time.Minute),
			assert: func(t *testing.T, d policy.Decision) {
				t.Helper()

				assert.Equal(t, policy.Allow, d.Outcome, "an expired enrolment-only session was still counted")
				assert.NoError(t, d.Reason)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(started)

			store, err := session.NewMemoryStore(session.WithMemoryStoreClock(clk))
			require.NoError(t, err)

			sessions, err := session.New(session.WithStore(store), session.WithClock(clk))
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), concurrentUser, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			sessions.MarkEnrolmentPending(s, enrolmentLifetime)
			require.NoError(t, sessions.Save(t.Context(), s))

			p, err := policy.NewConcurrentSessions(sessions, 1)
			require.NoError(t, err)

			clk.Advance(tc.at.Sub(clk.Now()))

			tc.assert(t, p.Evaluate(t.Context(), &policy.Input{User: concurrentUser}))
		})
	}
}
