package session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
)

// every returns the moments step, 2*step, ... up to and including last, for a
// case that keeps a session alive by using it.
func every(step, last time.Duration) []time.Duration {
	var moments []time.Duration
	for at := step; at <= last; at += step {
		moments = append(moments, at)
	}

	return moments
}

func TestManagerTouch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// activity is every moment activity is recorded, relative to creation
		// at 09:00. The assertion sees the result of the last one.
		activity []time.Duration
		opts     []session.ManagerOption
		assert   func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			// 09:00 + 30m idle, activity at 09:20 → 09:50.
			name:     "activity moves the idle deadline to now plus the idle timeout",
			activity: []time.Duration{20 * time.Minute},
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, createdAt.Add(50*time.Minute), s.IdleExpiresAt)
				assert.Equal(t, createdAt.Add(20*time.Minute), s.LastAccessedAt)
			},
		},
		{
			// A session in constant use: activity every 20 minutes keeps it
			// alive to 20:50, where the absolute deadline is 21:00 and an
			// unclamped 30-minute extension would reach 21:20.
			name:     "the idle deadline never moves past the absolute one",
			activity: every(20*time.Minute, 11*time.Hour+50*time.Minute),
			assert: func(t *testing.T, s *session.Session, err error) {
				require.NoError(t, err)
				assert.Equal(t, s.AbsoluteExpiresAt, s.IdleExpiresAt,
					"the idle deadline was allowed past the absolute one, so a session in constant use never ends")
				assert.Equal(t, createdAt.Add(12*time.Hour), s.IdleExpiresAt)
			},
		},
		{
			name:     "activity on a session past its idle deadline is refused",
			activity: []time.Duration{31 * time.Minute},
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
		{
			name:     "activity on a session past its absolute deadline is refused",
			activity: []time.Duration{13 * time.Hour},
			opts:     []session.ManagerOption{session.WithIdleTimeout(24 * time.Hour)},
			assert: func(t *testing.T, _ *session.Session, err error) {
				require.ErrorIs(t, err, session.ErrSessionExpired)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := newTestClock(createdAt)
			m, _ := managerOnClock(t, clk, tc.opts...)

			s, err := m.Create(t.Context(), testUser)
			require.NoError(t, err)

			for _, at := range tc.activity {
				clk.Set(createdAt.Add(at))
				err = m.Touch(t.Context(), s)
			}
			tc.assert(t, s, err)
		})
	}

	t.Run("the extension is persisted, not only applied in memory", func(t *testing.T) {
		t.Parallel()

		clk := newTestClock(createdAt)
		m, _ := managerOnClock(t, clk)

		s, err := m.Create(t.Context(), testUser)
		require.NoError(t, err)

		clk.Set(createdAt.Add(20 * time.Minute))
		require.NoError(t, m.Touch(t.Context(), s))

		// Past the original 09:30 deadline: this loads only because the
		// extension reached the store.
		clk.Set(createdAt.Add(40 * time.Minute))
		loaded, err := m.Load(t.Context(), s.ID)
		require.NoError(t, err)
		assert.Equal(t, createdAt.Add(50*time.Minute), loaded.IdleExpiresAt)
	})
}
