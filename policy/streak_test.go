package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

func TestMemoryAttemptStoreStreak(t *testing.T) {
	t.Parallel()

	const retention = 30 * 24 * time.Hour

	at := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	since := at.Add(-retention)

	// old is a failure that was recent when it was added, judged against the
	// cutoff of its own instant, and is behind since now.
	old := since.Add(-time.Hour)
	oldSince := old.Add(-retention)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore)
	}

	cases := []testCase{
		{
			name: "counts from one",
			assert: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
				got, set, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{Failures: 1, Newest: at}, got)
				assert.False(t, set)
			},
		},
		{
			name: "a write reaching the limit sets the hold once",
			assert: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
				var sets int
				for i := range 4 {
					got, set, err := s.AddStreakFailure(ctx, "ada", at.Add(time.Duration(i)*time.Second), since, 3)
					require.NoError(t, err)
					if set {
						sets++
						assert.Equal(t, 3, got.Failures, "the hold is set by the write reaching the limit")
					}
				}
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, 1, sets)
				assert.Equal(t, 4, got.Failures)
				assert.True(t, got.Held())
				assert.Equal(t, at.Add(2*time.Second), got.HeldAt)
			},
		},
		{
			name: "an inactive streak restarts and reads as empty",
			assert: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
				for range 2 {
					_, _, err := s.AddStreakFailure(ctx, "ada", old, oldSince, 3)
					require.NoError(t, err)
				}
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{}, got)

				added, set, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{Failures: 1, Newest: at}, added)
				assert.False(t, set)
			},
		},
		{
			name: "Reset clears the streak and the hold",
			assert: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
				for range 3 {
					_, _, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
					require.NoError(t, err)
				}
				require.NoError(t, s.Reset(ctx, "ada"))
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{}, got)
			},
		},
		{
			name: "a purge removes inactive streaks, keeps holds, and refuses a zero cutoff",
			assert: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
				_, _, err := s.AddStreakFailure(ctx, "old", old, oldSince, 3)
				require.NoError(t, err)
				for range 3 {
					_, _, err = s.AddStreakFailure(ctx, "held", old, oldSince, 3)
					require.NoError(t, err)
				}

				n, err := s.DeleteStreaksBefore(ctx, time.Time{})
				require.ErrorIs(t, err, policy.ErrRetainSinceRequired)
				assert.Zero(t, n)

				n, err = s.DeleteStreaksBefore(ctx, since)
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				held, err := s.FailureStreak(ctx, "held", since)
				require.NoError(t, err)
				assert.True(t, held.Held())
				assert.Equal(t, 3, held.Failures)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), policy.NewMemoryAttemptStore())
		})
	}
}
