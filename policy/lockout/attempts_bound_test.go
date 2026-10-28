package lockout_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// defaultStoreOf returns the in-memory store a policy built for itself.
func defaultStoreOf(t *testing.T, p *lockout.Policy) *lockout.MemoryAttemptStore {
	t.Helper()

	store, ok := p.StoreForTest().(*lockout.MemoryAttemptStore)
	require.True(t, ok, "the policy's default store is not the in-memory store")

	return store
}

// failOnce records one failure through the policy's own view for each of n
// distinct identifiers named prefix-0 to prefix-(n-1).
func failOnce(t *testing.T, p *lockout.Policy, prefix string, n int) {
	t.Helper()

	for i := range n {
		if err := p.RecordFailure(t.Context(), fmt.Sprintf("%s-%d", prefix, i)); err != nil {
			require.NoError(t, err, "failure %d of %d was not recorded", i, n)
		}
	}
}

// TestDefaultLockoutStore_ReleasesIdentifiersOutsideWindow pins the bound on
// the store a policy builds for itself: failures the policy no longer needs
// are forgotten as the store is written to, and nothing the policy still
// needs, a hold above all, is forgotten early.
func TestDefaultLockoutStore_ReleasesIdentifiersOutsideWindow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		run    func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock)
		assert func(t *testing.T, p *lockout.Policy, store *lockout.MemoryAttemptStore, clk *clockwork.FakeClock)
	}

	cases := []testCase{
		{
			name: "identifiers that failed once are released after the window passes",
			run: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				failOnce(t, p, "spray", 50_000)
				clk.Advance(24*time.Hour + time.Second)
				require.NoError(t, p.RecordFailure(t.Context(), "late"))
			},
			assert: func(t *testing.T, _ *lockout.Policy, store *lockout.MemoryAttemptStore, _ *clockwork.FakeClock) {
				assert.LessOrEqual(t, store.IdentifiersForTest(), 1,
					"the store still holds identifiers whose failures left the window")
			},
		},
		{
			name: "a hold is kept after its retention passes",
			opts: []lockout.Option{lockout.WithCap(lockout.NISTCap)},
			run: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				failDaily(t, p, clk, "bob", lockout.NISTCap)
				clk.Advance(defaultCapRetention + 24*time.Hour)
				require.NoError(t, p.RecordFailure(t.Context(), "late"))
			},
			assert: func(t *testing.T, p *lockout.Policy, store *lockout.MemoryAttemptStore, _ *clockwork.FakeClock) {
				deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("bob")), lockout.NISTCap)
				assert.Equal(t, 2, store.IdentifiersForTest(), "the sweep did not release only what it may")
			},
		},
		{
			name: "under a cap a count inside its retention outlives the window",
			opts: []lockout.Option{lockout.WithCap(lockout.NISTCap)},
			run: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				failDaily(t, p, clk, "ada", 10)
				clk.Advance(48 * time.Hour)
				require.NoError(t, p.RecordFailure(t.Context(), "late"))
			},
			assert: func(t *testing.T, _ *lockout.Policy, store *lockout.MemoryAttemptStore, clk *clockwork.FakeClock) {
				streak, err := store.FailureStreak(t.Context(), "ada", clk.Now().Add(-defaultCapRetention))
				require.NoError(t, err)
				assert.Equal(t, 10, streak.Failures, "a count the cap still needs was forgotten")
			},
		},
		{
			name: "identifiers longer than 256 bytes are counted apart however long their shared prefix",
			run: func(t *testing.T, p *lockout.Policy, _ *clockwork.FakeClock) {
				long := strings.Repeat("a", 1024)
				for range 3 {
					require.NoError(t, p.RecordFailure(t.Context(), long+"-one"))
				}
				require.NoError(t, p.RecordFailure(t.Context(), long+"-two"))
			},
			assert: func(t *testing.T, _ *lockout.Policy, store *lockout.MemoryAttemptStore, clk *clockwork.FakeClock) {
				long := strings.Repeat("a", 1024)
				since := clk.Now().Add(-time.Hour)

				one, err := store.FailureCount(t.Context(), long+"-one", since)
				require.NoError(t, err)
				two, err := store.FailureCount(t.Context(), long+"-two", since)
				require.NoError(t, err)
				assert.Equal(t, 3, one)
				assert.Equal(t, 1, two)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(lockoutNow)
			p, err := lockout.New(append([]lockout.Option{
				lockout.WithClock(clk),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.run(t, p, clk)
			tc.assert(t, p, defaultStoreOf(t, p), clk)
		})
	}
}

// TestDefaultLockoutStore_FullStoreDeniesNewIdentifier is the spec scenario
// "Store full of live failures": a new identifier is neither recorded nor
// let through to guess, and the identifiers already held keep being counted.
func TestDefaultLockoutStore_FullStoreDeniesNewIdentifier(t *testing.T) {
	t.Parallel()

	const capacity = 100_000

	clk := clockwork.NewFakeClockAt(lockoutNow)
	p, err := lockout.New(lockout.WithClock(clk))
	require.NoError(t, err)
	store := defaultStoreOf(t, p)

	failOnce(t, p, "held", capacity)
	clk.Advance(time.Hour)

	err = p.RecordFailure(t.Context(), "newcomer")
	require.ErrorIs(t, err, lockout.ErrAttemptStoreFull, "a full store recorded a new identifier")

	d := p.Evaluate(t.Context(), lockoutInput("newcomer"))
	require.Equal(t, policy.Deny, d.Outcome, "a full store let an uncounted guess through")
	require.ErrorIs(t, d.Reason, policy.ErrDenied)
	require.ErrorIs(t, d.Reason, lockout.ErrAttemptStoreFull)

	assert.Equal(t, capacity, store.IdentifiersForTest(), "the full store grew")

	require.NoError(t, p.RecordFailure(t.Context(), "held-0"), "an identifier already held stopped being counted")
	assert.Equal(t, policy.Allow, p.Evaluate(t.Context(), lockoutInput("held-0")).Outcome)

	clk.Advance(24 * time.Hour)
	require.NoError(t, p.RecordFailure(t.Context(), "newcomer"),
		"the store stayed full after its failures left the window")
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

// TestDefaultLockoutStore_PurgesOldFailures is the spec scenario "The default
// store purges": the in-memory store is a reaper, and a purge through the
// policy removes exactly what left the window.
func TestDefaultLockoutStore_PurgesOldFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, s *lockout.MemoryAttemptStore) (int, error)
		assert func(t *testing.T, s *lockout.MemoryAttemptStore, removed int, err error)
	}

	seed := func(t *testing.T, s policy.AttemptStore) {
		t.Helper()

		require.NoError(t, s.RecordFailure(t.Context(), "ada", lockoutNow.Add(-5*time.Minute)))
		require.NoError(t, s.RecordFailure(t.Context(), "ada", lockoutNow.Add(-20*time.Minute)))
	}

	cases := []testCase{
		{
			name: "a policy over the default store removes only what left its window",
			run: func(t *testing.T, s *lockout.MemoryAttemptStore) (int, error) {
				p := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithWindow(15*time.Minute))
				seed(t, s)

				return p.PurgeExpired(t.Context())
			},
			assert: func(t *testing.T, s *lockout.MemoryAttemptStore, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				count, err := s.FailureCount(t.Context(), "ada", lockoutCutoff)
				require.NoError(t, err)
				assert.Equal(t, 1, count, "the purge took a failure the window still counts")
			},
		},
		{
			name: "the store refuses a zero cutoff and deletes nothing",
			run: func(t *testing.T, s *lockout.MemoryAttemptStore) (int, error) {
				seed(t, s)
				reaper, ok := any(s).(lockout.AttemptReaper)
				require.True(t, ok, "the in-memory store cannot purge")

				return reaper.DeleteAttemptsBefore(t.Context(), time.Time{})
			},
			assert: func(t *testing.T, s *lockout.MemoryAttemptStore, removed int, err error) {
				require.ErrorIs(t, err, lockout.ErrRetainSinceRequired)
				assert.Zero(t, removed)
				count, err := s.FailureCount(t.Context(), "ada", lockoutNow.Add(-time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 2, count)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := lockout.NewMemoryAttemptStore()
			removed, err := tc.run(t, s)
			tc.assert(t, s, removed, err)
		})
	}
}
