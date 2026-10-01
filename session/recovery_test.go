package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/session"
)

// recoveryLifetime is the default recovery session lifetime the spec's
// scenarios use.
const recoveryLifetime = 15 * time.Minute

// TestManager_MarkRecoveryPending pins how a recovery confines a session: the
// state and the recovery time are set, the deadlines are lowered and the
// confinement marker set exactly as the enrolment path does, activity cannot
// extend the state, a later binding restores the deadlines while keeping the
// recovery time, and rotation carries the recovery time over. Each case runs
// on a session created at 09:00 with the default timeouts, and asserts on the
// session as the store holds it.
func TestManager_MarkRecoveryPending(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// steps acts on the created session and returns the session to
		// assert on.
		steps  func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session) *session.Session
		assert func(t *testing.T, s *session.Session)
	}

	// markAndReload marks s at 09:00, saves it and reads it back.
	markAndReload := func(t *testing.T, m *session.Manager, s *session.Session) *session.Session {
		t.Helper()

		m.MarkRecoveryPending(s, recoveryLifetime, at(9, 0))
		require.NoError(t, m.Save(t.Context(), s))

		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)

		return loaded
	}

	cases := []testCase{
		{
			name: "entered at recovery",
			steps: func(t *testing.T, m *session.Manager, _ *clockwork.FakeClock, s *session.Session) *session.Session {
				return markAndReload(t, m, s)
			},
			assert: func(t *testing.T, s *session.Session) {
				assert.Equal(t, session.MFARecoveryPending, s.MFA)
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(9, 15), s.IdleExpiresAt)
				assert.Equal(t, at(9, 0), s.RecoveredAt)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline,
					"the confinement marker records the deadline held before the mark")
			},
		},
		{
			name: "a session already confined keeps its recorded deadline",
			steps: func(t *testing.T, m *session.Manager, _ *clockwork.FakeClock, s *session.Session) *session.Session {
				m.MarkEnrolmentPending(s, enrolmentLifetime)
				return markAndReload(t, m, s)
			},
			assert: func(t *testing.T, s *session.Session) {
				assert.Equal(t, session.MFARecoveryPending, s.MFA)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline)
			},
		},
		{
			name: "activity cannot extend the state",
			steps: func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session) *session.Session {
				loaded := markAndReload(t, m, s)
				clk.Advance(14 * time.Minute)
				require.NoError(t, m.Touch(t.Context(), loaded))

				reloaded, err := m.Load(t.Context(), s.ID)
				require.NoError(t, err)

				return reloaded
			},
			assert: func(t *testing.T, s *session.Session) {
				assert.Equal(t, at(9, 14), s.LastAccessedAt)
				assert.Equal(t, at(9, 15), s.IdleExpiresAt)
			},
		},
		{
			name: "restored by a later binding keeps the recovery time",
			steps: func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session) *session.Session {
				loaded := markAndReload(t, m, s)
				clk.Advance(5 * time.Minute)
				require.NoError(t, m.RestoreEnrolmentDeadlines(loaded))

				return loaded
			},
			assert: func(t *testing.T, s *session.Session) {
				assert.Equal(t, at(21, 0), s.AbsoluteExpiresAt)
				assert.True(t, s.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")
				assert.Equal(t, at(9, 0), s.RecoveredAt)
			},
		},
		{
			name: "past its lowered deadline it is not restored",
			steps: func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session) *session.Session {
				loaded := markAndReload(t, m, s)
				clk.Advance(recoveryLifetime)
				require.ErrorIs(t, m.RestoreEnrolmentDeadlines(loaded), session.ErrSessionExpired)

				return loaded
			},
			assert: func(t *testing.T, s *session.Session) {
				assert.Equal(t, at(9, 15), s.AbsoluteExpiresAt)
				assert.Equal(t, at(21, 0), s.EnrolmentOriginDeadline)
			},
		},
		{
			name: "recovery time survives rotation",
			steps: func(t *testing.T, m *session.Manager, _ *clockwork.FakeClock, s *session.Session) *session.Session {
				loaded := markAndReload(t, m, s)
				rotated, err := m.Rotate(t.Context(), loaded)
				require.NoError(t, err)

				reloaded, err := m.Load(t.Context(), rotated.ID)
				require.NoError(t, err)

				return reloaded
			},
			assert: func(t *testing.T, s *session.Session) {
				assert.Equal(t, at(9, 0), s.RecoveredAt)
				assert.Equal(t, session.MFARecoveryPending, s.MFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(at(9, 0))
			m, _ := managerOnClock(t, clk)
			s, err := m.Create(t.Context(), testUser, session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)

			tc.assert(t, tc.steps(t, m, clk, s))
		})
	}
}

// TestRecoveryStateRoundTrip pins the recovery-pending state and the recovery
// time as library-owned fields the memory store keeps, which no consumer data
// entry can set or clear.
func TestRecoveryStateRoundTrip(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mutate func(s *session.Session)
		assert func(t *testing.T, loaded *session.Session)
	}

	cases := []testCase{
		{
			name: "round-trips through the store",
			mutate: func(s *session.Session) {
				s.MFA = session.MFARecoveryPending
				s.EnrolmentOriginDeadline = at(21, 0)
				s.RecoveredAt = at(9, 0)
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFARecoveryPending, loaded.MFA)
				assert.True(t, at(21, 0).Equal(loaded.EnrolmentOriginDeadline))
				assert.True(t, at(9, 0).Equal(loaded.RecoveredAt), "want 09:00, got %s", loaded.RecoveredAt)
			},
		},
		{
			name: "a consumer data entry cannot record a recovery",
			mutate: func(s *session.Session) {
				s.Data = map[string]string{"recovered_at": "2026-01-01T00:00:00Z", "RecoveredAt": "2026-01-01T00:00:00Z"}
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.True(t, loaded.RecoveredAt.IsZero())
				assert.Equal(t, session.MFANone, loaded.MFA)
				assert.Equal(t, map[string]string{"recovered_at": "2026-01-01T00:00:00Z", "RecoveredAt": "2026-01-01T00:00:00Z"},
					loaded.Data, "consumer data is returned unchanged")
			},
		},
		{
			name: "a consumer data entry cannot clear a recovery",
			mutate: func(s *session.Session) {
				s.MFA = session.MFARecoveryPending
				s.RecoveredAt = at(9, 0)
				s.Data = map[string]string{"mfa": "none", "recovered_at": ""}
			},
			assert: func(t *testing.T, loaded *session.Session) {
				assert.Equal(t, session.MFARecoveryPending, loaded.MFA)
				assert.True(t, at(9, 0).Equal(loaded.RecoveredAt))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			m := managerFor(t)
			s, err := m.Create(ctx, testUser, session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)

			tc.mutate(s)
			require.NoError(t, m.Save(ctx, s))

			loaded, err := m.Load(ctx, s.ID)
			require.NoError(t, err)
			tc.assert(t, loaded)
		})
	}
}
