package policy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// lockoutNow is the instant every lockout test judges against, so a case can
// name a failure's age rather than a wall-clock time.
var lockoutNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// lockoutCutoff is the cutoff a 15-minute window puts behind lockoutNow, which
// is where the strictness of the window is decided.
var lockoutCutoff = lockoutNow.Add(-15 * time.Minute)

func TestMemoryAttemptStoreCounts(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		record   func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore)
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			record: func(t *testing.T, ctx context.Context, s *policy.MemoryAttemptStore) {
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
			store := policy.NewMemoryAttemptStore()
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

func TestMemoryAttemptStoreIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := policy.NewMemoryAttemptStore()

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

func TestMemoryAttemptStoreCannotReap(t *testing.T) {
	t.Parallel()

	// The limit is stated in the store's godoc, and a consumer who needs
	// sweeping supplies a store that can: a silent zero from a sweep that never
	// ran is exactly what ErrReapUnsupported exists to prevent.
	_, reaps := any(policy.NewMemoryAttemptStore()).(policy.AttemptReaper)
	assert.False(t, reaps, "the in-memory store claims it can purge, so a sweep over it would report a silent zero")
}
