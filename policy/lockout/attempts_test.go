package lockout_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy/lockout"
)

func TestMemoryAttemptStoreCounts(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		record   func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore)
		username string // empty means "ada"
		since    time.Time
		assert   func(t *testing.T, count int, err error)
	}

	cases := []testCase{
		{
			name:  "a store with nothing recorded counts nothing",
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Zero(t, count)
			},
		},
		{
			name: "failures inside the window are counted",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutNow.Add(-time.Minute)))
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutNow.Add(-2*time.Minute)))
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutNow.Add(-14*time.Minute)))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, count)
			},
		},
		{
			name: "a failure exactly at the cutoff is outside the window",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutCutoff))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Zero(t, count, "the window counted a failure that is exactly as old as the window")
			},
		},
		{
			name: "a failure one nanosecond after the cutoff is inside the window",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutCutoff.Add(time.Nanosecond)))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, count)
			},
		},
		{
			name: "failures older than the window are not counted",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutNow.Add(-time.Hour)))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Zero(t, count)
			},
		},
		{
			name: "one identifier's failures are not another's",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.RecordFailure(ctx, "grace", lockoutNow.Add(-time.Minute)))
				require.NoError(t, s.RecordFailure(ctx, "grace", lockoutNow.Add(-2*time.Minute)))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Zero(t, count, "a failure recorded for one identifier was counted against another")
			},
		},
		{
			name: "a reset clears the identifier's failures",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				for range 4 {
					require.NoError(t, s.RecordFailure(ctx, "ada", lockoutNow.Add(-time.Minute)))
				}
				require.NoError(t, s.Reset(ctx, "ada"))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Zero(t, count, "a successful authentication did not clear the failures before it")
			},
		},
		{
			name: "a reset leaves every other identifier alone",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.RecordFailure(ctx, "ada", lockoutNow.Add(-time.Minute)))
				require.NoError(t, s.RecordFailure(ctx, "grace", lockoutNow.Add(-time.Minute)))
				require.NoError(t, s.Reset(ctx, "ada"))
			},
			username: "grace",
			since:    lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, count, "resetting one identifier cleared another's failures")
			},
		},
		{
			name: "resetting an identifier that never failed is not an error",
			record: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				require.NoError(t, s.Reset(ctx, "ada"))
			},
			since: lockoutCutoff,
			assert: func(t *testing.T, count int, err error) {
				require.NoError(t, err)
				assert.Zero(t, count)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			store := lockout.NewMemoryAttemptStore()
			if tc.record != nil {
				tc.record(t, ctx, store)
			}

			username := tc.username
			if username == "" {
				username = "ada"
			}

			count, err := store.FailureCount(ctx, username, tc.since)
			tc.assert(t, count, err)
		})
	}
}

// Standalone: it races concurrent writers against one store.
func TestMemoryAttemptStoreIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := lockout.NewMemoryAttemptStore()

	const writers = 8
	const perWriter = 50

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := range perWriter {
				if err := store.RecordFailure(ctx, "ada", lockoutNow.Add(-time.Duration(i+1)*time.Millisecond)); err != nil {
					assert.NoError(t, err)

					return
				}
				if _, err := store.FailureCount(ctx, "ada", lockoutCutoff); err != nil {
					assert.NoError(t, err)

					return
				}
				if w == 0 && i == perWriter-1 {
					assert.NoError(t, store.Reset(ctx, "grace"))
				}
			}
		}()
	}
	wg.Wait()

	count, err := store.FailureCount(ctx, "ada", lockoutCutoff)
	require.NoError(t, err)
	assert.Equal(t, writers*perWriter, count)
}

// TestMemoryAttemptStore_ConsumerCapacity pins WithAttemptStoreCapacity: the
// consumer's capacity replaces the default in both directions, and one that
// holds nothing is a wiring mistake.
func TestMemoryAttemptStore_ConsumerCapacity(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func() *lockout.MemoryAttemptStore
		assert func(t *testing.T, build func() *lockout.MemoryAttemptStore)
	}

	record := func(t *testing.T, s *lockout.MemoryAttemptStore, n int) error {
		t.Helper()

		for i := range n {
			if err := s.RecordFailure(t.Context(), fmt.Sprintf("user-%d", i), lockoutNow); err != nil {
				return err
			}
		}

		return nil
	}

	cases := []testCase{
		{
			name: "a capacity above the default holds more than 100,000 identifiers",
			build: func() *lockout.MemoryAttemptStore {
				return lockout.NewMemoryAttemptStore(lockout.WithAttemptStoreCapacity(1_000_000))
			},
			assert: func(t *testing.T, build func() *lockout.MemoryAttemptStore) {
				s := build()
				require.NoError(t, record(t, s, 100_001))
				assert.Equal(t, 100_001, s.IdentifiersForTest())
			},
		},
		{
			name: "a capacity below the default refuses the identifier past it",
			build: func() *lockout.MemoryAttemptStore {
				return lockout.NewMemoryAttemptStore(lockout.WithAttemptStoreCapacity(3))
			},
			assert: func(t *testing.T, build func() *lockout.MemoryAttemptStore) {
				s := build()
				require.NoError(t, record(t, s, 3))
				require.ErrorIs(t, record(t, s, 4), lockout.ErrAttemptStoreFull)
				assert.Equal(t, 3, s.IdentifiersForTest())
				require.NoError(t, s.RecordFailure(t.Context(), "user-0", lockoutNow),
					"a full store refused an identifier it already holds")
			},
		},
		{
			name: "the default capacity is 100,000",
			build: func() *lockout.MemoryAttemptStore {
				return lockout.NewMemoryAttemptStore()
			},
			assert: func(t *testing.T, build func() *lockout.MemoryAttemptStore) {
				s := build()
				require.NoError(t, record(t, s, 100_000))
				require.ErrorIs(t, s.RecordFailure(t.Context(), "one-more", lockoutNow), lockout.ErrAttemptStoreFull)
			},
		},
		{
			name: "a capacity of zero is a wiring mistake",
			build: func() *lockout.MemoryAttemptStore {
				return lockout.NewMemoryAttemptStore(lockout.WithAttemptStoreCapacity(0))
			},
			assert: func(t *testing.T, build func() *lockout.MemoryAttemptStore) {
				assert.Panics(t, func() { build() })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build)
		})
	}
}

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
		assert func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore)
	}

	cases := []testCase{
		{
			name: "counts from one",
			assert: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				got, set, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
				require.NoError(t, err)
				assert.Equal(t, lockout.FailureStreak{Failures: 1, Newest: at}, got)
				assert.False(t, set)
			},
		},
		{
			name: "a write reaching the limit sets the hold once",
			assert: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
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
			assert: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				for range 2 {
					_, _, err := s.AddStreakFailure(ctx, "ada", old, oldSince, 3)
					require.NoError(t, err)
				}
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, lockout.FailureStreak{}, got)

				added, set, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
				require.NoError(t, err)
				assert.Equal(t, lockout.FailureStreak{Failures: 1, Newest: at}, added)
				assert.False(t, set)
			},
		},
		{
			name: "Reset clears the streak and the hold",
			assert: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				for range 3 {
					_, _, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
					require.NoError(t, err)
				}
				require.NoError(t, s.Reset(ctx, "ada"))
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, lockout.FailureStreak{}, got)
			},
		},
		{
			name: "a purge removes inactive streaks, keeps holds, and refuses a zero cutoff",
			assert: func(t *testing.T, ctx context.Context, s *lockout.MemoryAttemptStore) {
				_, _, err := s.AddStreakFailure(ctx, "old", old, oldSince, 3)
				require.NoError(t, err)
				for range 3 {
					_, _, err = s.AddStreakFailure(ctx, "held", old, oldSince, 3)
					require.NoError(t, err)
				}

				n, err := s.DeleteStreaksBefore(ctx, time.Time{})
				require.ErrorIs(t, err, lockout.ErrRetainSinceRequired)
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

			tc.assert(t, t.Context(), lockout.NewMemoryAttemptStore())
		})
	}
}
