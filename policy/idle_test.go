package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// idleLastAccess is the instant every session in this file was last used at. Every
// other instant in the file is derived from it, so no case reads the wall
// clock and no case can pass because a test machine was slow.
var idleLastAccess = time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)

func TestIdleTimeoutPolicyEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []policy.IdleOption
		session *session.Session
		now     time.Time
		assert  func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome, "a session that is not idle was refused")
		assert.NoError(t, d.Reason, "an allow carries no reason")
	}

	deniesAsIdle := func(t *testing.T, d policy.Decision) {
		t.Helper()

		require.Equal(t, policy.Deny, d.Outcome, "an idle session was not refused")
		require.ErrorIs(t, d.Reason, policy.ErrSessionIdle,
			"a caller reporting the reason could not tell why the request was refused")
		assert.Equal(t, policy.ChallengeNone, d.Challenge, "a deny challenges for nothing")
	}

	cases := []testCase{
		{
			name:    "a session used inside the idle timeout allows",
			session: &session.Session{LastAccessedAt: idleLastAccess},
			now:     idleLastAccess.Add(29 * time.Minute),
			assert:  allows,
		},
		{
			// "Idle too long": last accessed at 09:00, evaluated at 09:31.
			name:    "a session idle past the timeout is denied",
			session: &session.Session{LastAccessedAt: idleLastAccess},
			now:     idleLastAccess.Add(31 * time.Minute),
			assert:  deniesAsIdle,
		},
		{
			// The comparison is strictly greater: the session is idle once it
			// is past the timeout, not on reaching it.
			name:    "a session exactly at the idle timeout allows",
			session: &session.Session{LastAccessedAt: idleLastAccess},
			now:     idleLastAccess.Add(30 * time.Minute),
			assert:  allows,
		},
		{
			// A session nothing has recorded activity on has no idleness to
			// measure, and inventing one would refuse every request.
			name:    "a zero last-access time allows",
			session: &session.Session{},
			now:     idleLastAccess.Add(24 * time.Hour),
			assert:  allows,
		},
		{
			name:    "a request carrying no session allows",
			session: nil,
			now:     idleLastAccess.Add(24 * time.Hour),
			assert:  allows,
		},
		{
			// "Consumer idle timeout": 10 minutes, evaluated at 09:11.
			name:    "a consumer's shorter idle timeout denies where the default would allow",
			opts:    []policy.IdleOption{policy.WithIdlePolicyTimeout(10 * time.Minute)},
			session: &session.Session{LastAccessedAt: idleLastAccess},
			now:     idleLastAccess.Add(11 * time.Minute),
			assert:  deniesAsIdle,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewIdleTimeoutPolicy(tc.opts...)
			require.NoError(t, err)

			tc.assert(t, p.Evaluate(t.Context(), &policy.Input{Session: tc.session, Now: tc.now}))
		})
	}
}

func TestIdleTimeoutPolicyThresholds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		opts      []policy.IdleOption
		createdAt time.Time
		now       time.Time
		assert    func(t *testing.T, idle, absolute time.Time)
	}

	cases := []testCase{
		{
			name:      "a session created now gets the default deadlines",
			createdAt: idleLastAccess,
			now:       idleLastAccess,
			assert: func(t *testing.T, idle, absolute time.Time) {
				t.Helper()

				assert.Equal(t, idleLastAccess.Add(30*time.Minute), idle)
				assert.Equal(t, idleLastAccess.Add(12*time.Hour), absolute)
			},
		},
		{
			name: "a consumer's timeouts replace both deadlines",
			opts: []policy.IdleOption{
				policy.WithIdlePolicyTimeout(10 * time.Minute),
				policy.WithIdlePolicyAbsoluteTimeout(2 * time.Hour),
			},
			createdAt: idleLastAccess,
			now:       idleLastAccess,
			assert: func(t *testing.T, idle, absolute time.Time) {
				t.Helper()

				assert.Equal(t, idleLastAccess.Add(10*time.Minute), idle)
				assert.Equal(t, idleLastAccess.Add(2*time.Hour), absolute)
			},
		},
		{
			// The absolute deadline is the one nothing extends, so activity
			// near it must not hand the caller an idle deadline beyond it.
			name:      "the idle deadline never reaches past the absolute one",
			createdAt: idleLastAccess,
			now:       idleLastAccess.Add(11*time.Hour + 50*time.Minute),
			assert: func(t *testing.T, idle, absolute time.Time) {
				t.Helper()

				assert.Equal(t, idleLastAccess.Add(12*time.Hour), absolute)
				assert.Equal(t, absolute, idle, "an idle deadline outlived the deadline nothing extends")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewIdleTimeoutPolicy(tc.opts...)
			require.NoError(t, err)

			idle, absolute := p.Thresholds(tc.createdAt, tc.now)
			tc.assert(t, idle, absolute)
		})
	}
}

func TestIdleTimeoutPolicyPhases(t *testing.T) {
	t.Parallel()

	p, err := policy.NewIdleTimeoutPolicy()
	require.NoError(t, err)

	assert.Equal(t, []policy.Phase{policy.PerRequest}, p.Phases(),
		"a rule written for every request must be asked on every request, and nowhere else")
	assert.NotEmpty(t, p.Name(), "a policy with no name cannot be told apart in a log")
}
