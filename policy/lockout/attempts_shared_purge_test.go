package lockout_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy/lockout"
)

// TestMemoryAttemptStore_SharedPurgeKeepsLongestRetention pins the promise a
// shared in-memory store makes: one policy's purge, run with its own shorter
// cutoff, never removes what a longer-retaining policy on the same store still
// counts.
func TestMemoryAttemptStore_SharedPurgeKeepsLongestRetention(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, s *lockout.MemoryAttemptStore, clk *clockwork.FakeClock)
		assert func(t *testing.T, s *lockout.MemoryAttemptStore, clk *clockwork.FakeClock)
	}

	cases := []testCase{
		{
			name: "a short-window purge leaves the failures a long-window policy still counts",
			run: func(t *testing.T, s *lockout.MemoryAttemptStore, clk *clockwork.FakeClock) {
				short, err := lockout.New(lockout.WithAttemptStore(s),
					lockout.WithClock(clk), lockout.WithWindow(15*time.Minute))
				require.NoError(t, err)
				long, err := lockout.New(lockout.WithAttemptStore(s), lockout.WithClock(clk))
				require.NoError(t, err)

				for range 100 {
					require.NoError(t, long.RecordFailure(t.Context(), "ada"))
				}
				clk.Advance(time.Hour)
				_, err = short.PurgeExpired(t.Context())
				require.NoError(t, err)
			},
			assert: func(t *testing.T, s *lockout.MemoryAttemptStore, clk *clockwork.FakeClock) {
				n, err := s.FailureCount(t.Context(), "ada", clk.Now().Add(-24*time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 100, n, "the 24h policy's failures were purged by the 15m policy")
			},
		},
		{
			name: "a shorter cap retention purge leaves the counts a longer one still holds",
			run: func(t *testing.T, s *lockout.MemoryAttemptStore, clk *clockwork.FakeClock) {
				short, err := lockout.New(lockout.WithAttemptStore(s), lockout.WithClock(clk),
					lockout.WithCap(10), lockout.WithCapRetention(48*time.Hour))
				require.NoError(t, err)
				long, err := lockout.New(lockout.WithAttemptStore(s), lockout.WithClock(clk),
					lockout.WithCap(10))
				require.NoError(t, err)

				require.NoError(t, long.RecordFailure(t.Context(), "ada"))
				clk.Advance(72 * time.Hour)
				_, err = short.PurgeExpired(t.Context())
				require.NoError(t, err)
			},
			assert: func(t *testing.T, s *lockout.MemoryAttemptStore, clk *clockwork.FakeClock) {
				st, err := s.FailureStreak(t.Context(), "ada", clk.Now().Add(-30*24*time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 1, st.Failures, "the 30d policy's count was purged by the 48h policy")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
			s := lockout.NewMemoryAttemptStore()
			tc.run(t, s, clk)
			tc.assert(t, s, clk)
		})
	}
}
