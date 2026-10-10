package policy_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
)

// TestLockoutObserverDefaults pins that a policy with no observer adds
// nothing to the store's work: its view records and nothing else.
func TestLockoutObserverDefaults(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockAttemptStore(ctrl)
	store.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil).Times(1)

	p := lockoutWith(t, policy.WithAttemptStore(store))

	require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	assert.Equal(t, p.Attempts(), p.Attempts(),
		"two calls must hand out the same view, so the chain can deduplicate it")
}

// TestLockoutObserverViewIsOneValue pins that an observed policy hands out one
// view, by identity: a chain that deduplicates the stores it was given must
// see form login's and Basic's as the same store, or a reset is reported twice.
func TestLockoutObserverViewIsOneValue(t *testing.T) {
	t.Parallel()

	p := lockoutWith(t, policy.WithLockoutObserver(func(context.Context, policy.LockoutReport) {}))

	first, second := p.Attempts(), p.Attempts()
	assert.Same(t, first, second, "two calls handed out different views")
	assert.True(t, first == second, "the views must compare equal as interface values")
}

// reportLog collects what an observer is told, safe for concurrent reports.
type reportLog struct {
	mu  sync.Mutex
	got []policy.LockoutReport
}

func (l *reportLog) observe(_ context.Context, r policy.LockoutReport) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.got = append(l.got, r)
}

func (l *reportLog) all() []policy.LockoutReport {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.got)
}

// countKind counts the reports of kind k.
func countKind(r []policy.LockoutReport, k policy.LockoutReportKind) int {
	var n int
	for _, rep := range r {
		if rep.Kind == k {
			n++
		}
	}

	return n
}

// cappedFailures records n failures for id, a second apart and ending a second
// before lockoutNow, through the view of a policy with a cap of limit over the
// store and no observer, so they reach the log and the streak and are not
// reported.
func cappedFailures(id string, limit, n int) func(*testing.T, policy.AttemptStore) {
	return func(t *testing.T, s policy.AttemptStore) {
		t.Helper()

		seeder := lockoutWith(t, policy.WithAttemptStore(s), policy.WithLockoutCap(limit))
		for i := range n {
			require.NoError(t, seeder.Attempts().RecordFailure(t.Context(), id, lockoutNow.Add(-time.Duration(n-i)*time.Second)))
		}
	}
}

// heldStreak holds id with n consecutive failures written straight to the
// store's streak, which leaves its failure log empty: a hold whose failures
// have all left the window.
func heldStreak(id string, n int) func(*testing.T, policy.AttemptStore) {
	return func(t *testing.T, s policy.AttemptStore) {
		t.Helper()

		streaks, ok := s.(policy.FailureStreakStore)
		require.True(t, ok, "the store keeps no streaks")
		for i := range n {
			at := lockoutNow.Add(-time.Duration(n-i) * time.Hour)
			_, _, err := streaks.AddStreakFailure(t.Context(), id, at, at.Add(-defaultCapRetention), n)
			require.NoError(t, err)
		}
	}
}

func TestLockoutObserver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		store  func(t *testing.T) policy.AttemptStore // nil: a fresh in-memory store
		before func(t *testing.T, store policy.AttemptStore)
		act    func(t *testing.T, p *policy.AccountLockoutPolicy) error
		assert func(t *testing.T, reports []policy.LockoutReport, err error, logs string)
	}

	record := func(id string) func(*testing.T, *policy.AccountLockoutPolicy) error {
		return func(t *testing.T, p *policy.AccountLockoutPolicy) error {
			return p.Attempts().RecordFailure(t.Context(), id, lockoutNow)
		}
	}
	prior := func(id string, n int) func(*testing.T, policy.AttemptStore) {
		return func(t *testing.T, s policy.AttemptStore) {
			for i := range n {
				require.NoError(t, s.RecordFailure(t.Context(), id, lockoutNow.Add(-time.Duration(i+1)*time.Second)))
			}
		}
	}

	cases := []testCase{
		{
			name:   "four failures report nothing",
			before: prior("ada", 3),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			name:   "the fifth failure reports the identifier locked",
			before: prior("ada", 4),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutLocked, Failures: 5, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "each further locking failure is reported",
			before: prior("ada", 5),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutLocked, Failures: 6, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "the hundredth failure reports the ceiling",
			before: prior("ada", 99),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 1)
				assert.Equal(t, policy.LockoutAtCeiling, r[0].Kind)
				assert.Equal(t, 100, r[0].Failures)
			},
		},
		{
			name:   "under a sliding lock a locking failure is locked, never at the ceiling",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(3, 15*time.Minute)},
			before: prior("ada", 2),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutLocked, Failures: 3, At: lockoutNow},
				}, r)
			},
		},
		{
			name: "under a sliding lock failures older than its window do not count",
			opts: []policy.LockoutOption{policy.WithSlidingLockout(3, 15*time.Minute)},
			before: func(t *testing.T, s policy.AttemptStore) {
				for i := range 3 {
					require.NoError(t, s.RecordFailure(t.Context(), "ada", lockoutNow.Add(-20*time.Minute-time.Duration(i)*time.Second)))
				}
			},
			act: record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r, "failures outside the sliding window were counted")
			},
		},
		{
			name:   "an unknown identifier is reported exactly like a known one",
			before: func(t *testing.T, s policy.AttemptStore) { prior("ada", 4)(t, s); prior("nobody", 4)(t, s) },
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return errors.Join(record("ada")(t, p), record("nobody")(t, p))
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 2)
				r[1].Identifier = r[0].Identifier
				assert.Equal(t, r[0], r[1], "the reports differ in something other than the identifier")
			},
		},
		{
			name: "a failure the store could not record is not reported",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				// Without a cap there is no streak write to join: the store's own
				// error comes back, not a wrapper around it.
				assert.True(t, err == errAttemptStoreDown, "got %T, want the store's own error", err) //nolint:errorlint // identity is the point
				assert.Empty(t, r)
			},
		},
		{
			name:   "clearing an identifier with failures reports it cleared",
			before: prior("ada", 3),
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutCleared, Failures: 3, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "an administrator's reset through the policy is reported too",
			before: prior("ada", 3),
			act:    func(t *testing.T, p *policy.AccountLockoutPolicy) error { return p.Reset(t.Context(), "ada") },
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 1)
				assert.Equal(t, policy.LockoutCleared, r[0].Kind)
			},
		},
		{
			name: "clearing nothing is not reported",
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			// Only failures the window still counts are reported: one older
			// than the window is not what a lock was holding.
			name: "clearing only failures outside the window is not reported",
			before: func(t *testing.T, s policy.AttemptStore) {
				require.NoError(t, s.RecordFailure(t.Context(), "ada", lockoutNow.Add(-25*time.Hour)))
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			name: "a reset the store refused is not reported",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(2, nil)
				s.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

				return s
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Empty(t, r)
			},
		},
		{
			name: "a reset whose failures could not be counted loses only its report",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)
				s.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

				return s
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, logs string) {
				require.NoError(t, err, "the reset succeeded, so clearing succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "policy: a lockout report was lost"))
				assert.NotContains(t, logs, "ada")
			},
		},
		{
			name: "a reset the store refused after an uncountable read logs nothing",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)
				s.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

				return s
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, logs string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Empty(t, r)
				assert.Empty(t, logs)
			},
		},
		{
			name: "a nil lockout logger leaves the logger in place",
			opts: []policy.LockoutOption{policy.WithLockoutLogger(nil)},
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, _ []policy.LockoutReport, err error, logs string) {
				require.NoError(t, err)
				assert.Contains(t, logs, "policy: a lockout report was lost")
			},
		},
		{
			// Only the report is lost: recording the failure is what the caller
			// asked for, and a count that cannot be read must not undo it.
			name: "a failure recorded but not countable loses only its report",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, logs string) {
				require.NoError(t, err, "the failure is recorded, so recording succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "policy: a lockout report was lost"))
				assert.NotContains(t, logs, "ada")
			},
		},
		{
			// Spec: "Held". The twentieth write is reported as the hold, and
			// not also as a windowed lock.
			name: "the failure that reaches the cap reports the hold once",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				for range 20 {
					require.NoError(t, record("ada")(t, p))
				}

				return nil
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.NotEmpty(t, r)
				assert.Equal(t, policy.LockoutReport{
					Identifier: "ada", Kind: policy.LockoutHeld, Failures: 20, At: lockoutNow,
				}, r[len(r)-1])
				assert.Equal(t, 1, countKind(r, policy.LockoutHeld), "the hold was not reported exactly once")
				for _, rep := range r[:len(r)-1] {
					assert.NotEqual(t, 20, rep.Failures, "the write that set the hold was also reported as %v", rep.Kind)
				}
			},
		},
		{
			// Review Focus 1: the count passed a cap it was never held at, so
			// the hold is set by the next write, at 71, not at the cap.
			name:   "a cap lowered below an existing count reports the hold on the next failure",
			opts:   []policy.LockoutOption{policy.WithLockoutCap(50)},
			before: cappedFailures("ada", 100, 70),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutHeld, Failures: 71, At: lockoutNow},
				}, r)
			},
		},
		{
			// Only the write that set the hold reports it; later failures are
			// reported by the window, as before.
			name:   "a failure after the hold is reported by the window",
			opts:   []policy.LockoutOption{policy.WithLockoutCap(20)},
			before: cappedFailures("ada", 20, 20),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutLocked, Failures: 21, At: lockoutNow},
				}, r)
			},
		},
		{
			// The hold is in the streak, which the store accepted: losing its
			// report because the log failed would lose it for good, since no
			// later write sets it again.
			name: "a hold set while the log could not record is still reported",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 20).
					Return(policy.FailureStreak{Failures: 20, Newest: lockoutNow, HeldAt: lockoutNow}, true, nil)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutHeld, Failures: 20, At: lockoutNow},
				}, r)
			},
		},
		{
			// Spec: "Hold lifted", through the administrator's unlock.
			name:   "a reset of a held identifier reports the hold lifted in place of cleared",
			opts:   []policy.LockoutOption{policy.WithLockoutCap(20)},
			before: cappedFailures("ada", 20, 20),
			act:    func(t *testing.T, p *policy.AccountLockoutPolicy) error { return p.Reset(t.Context(), "ada") },
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutReleased, Failures: 20, At: lockoutNow},
				}, r)
			},
		},
		{
			// A hold outlives the window, so its release is reported even when
			// the window holds nothing to clear.
			name:   "a hold with nothing in the window is still reported lifted",
			opts:   []policy.LockoutOption{policy.WithLockoutCap(20)},
			before: heldStreak("ada", 20),
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutReleased, Failures: 20, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "with a cap a reset of failures that are not held reports them cleared",
			opts:   []policy.LockoutOption{policy.WithLockoutCap(20)},
			before: cappedFailures("ada", 20, 3),
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutCleared, Failures: 3, At: lockoutNow},
				}, r)
			},
		},
		{
			name: "with a cap clearing nothing is not reported",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			// Without the streak the policy cannot tell a release from a
			// clearing, so it reports neither rather than the wrong one.
			name: "a reset whose streak could not be read loses only its report",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakAttemptStore(t)
				s.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(3, nil)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(policy.FailureStreak{}, errAttemptStoreDown)
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

				return s
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, logs string) {
				require.NoError(t, err, "the reset succeeded, so clearing succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "policy: a lockout report was lost"))
				assert.NotContains(t, logs, "ada")
			},
		},
		{
			name: "a reset of a held identifier the store refused is not reported",
			opts: []policy.LockoutOption{policy.WithLockoutCap(20)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakAttemptStore(t)
				s.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(20, nil)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", gomock.Any()).
					Return(policy.FailureStreak{Failures: 20, Newest: lockoutNow, HeldAt: lockoutNow}, nil)
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

				return s
			},
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Empty(t, r)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var store policy.AttemptStore = policy.NewMemoryAttemptStore()
			if tc.store != nil {
				store = tc.store(t)
			}
			if tc.before != nil {
				tc.before(t, store)
			}

			var logs bytes.Buffer
			got := &reportLog{}
			p := lockoutWith(t, append([]policy.LockoutOption{
				policy.WithAttemptStore(store),
				policy.WithLockoutObserver(got.observe),
				policy.WithLockoutLogger(slog.New(slog.NewTextHandler(&logs, nil))),
			}, tc.opts...)...)

			err := tc.act(t, p)
			tc.assert(t, got.all(), err, logs.String())
		})
	}
}

// TestLockoutObserverReportsEveryConcurrentLockingFailure pins why reports
// are per failure: a burst whose failures all read a count past the
// threshold would lose a crossing report, and must lose none of these.
func TestLockoutObserverReportsEveryConcurrentLockingFailure(t *testing.T) {
	t.Parallel()

	store := policy.NewMemoryAttemptStore()
	failuresEndingAt("ada", 5, time.Minute)(t, store)

	got := &reportLog{}
	p := lockoutWith(t, policy.WithAttemptStore(store), policy.WithLockoutObserver(got.observe))

	const burst = 32
	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() {
			assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
		})
	}
	wg.Wait()

	reports := got.all()
	assert.Len(t, reports, burst, "a burst of locking failures lost reports")
	for _, r := range reports {
		assert.Equal(t, policy.LockoutLocked, r.Kind)
	}
}

// TestLockoutObserverDefaultLoggerIsSlogDefault pins that without
// WithLockoutLogger the lost-report record goes to slog.Default. It swaps the
// process-wide default, so it must not run in parallel.
func TestLockoutObserverDefaultLoggerIsSlogDefault(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := NewMockAttemptStore(gomock.NewController(t))
	s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
	s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)

	p := lockoutWith(t,
		policy.WithAttemptStore(s),
		policy.WithLockoutObserver(func(context.Context, policy.LockoutReport) {}),
	)

	require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	assert.Equal(t, 1, strings.Count(logs.String(), "policy: a lockout report was lost"))
}

func TestLockoutObserverPanicChangesNothing(t *testing.T) {
	t.Parallel()

	store := policy.NewMemoryAttemptStore()
	failuresEndingAt("ada", 4, time.Second)(t, store)

	var logs bytes.Buffer
	p := lockoutWith(t,
		policy.WithAttemptStore(store),
		policy.WithLockoutObserver(func(context.Context, policy.LockoutReport) { panic("observer bug") }),
		policy.WithLockoutLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)

	require.NotPanics(t, func() {
		assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	})
	assert.Equal(t, 1, strings.Count(logs.String(), "policy: the lockout observer panicked"))
	assert.NotContains(t, logs.String(), "ada", "the record must not carry the submitted identifier")
}

func TestLockoutObserverReportKindString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   policy.LockoutReportKind
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(*testing.T, string) {
		return func(t *testing.T, got string) { assert.Equal(t, want, got) }
	}

	cases := []testCase{
		{name: "locked", kind: policy.LockoutLocked, assert: is("locked")},
		{name: "at the ceiling", kind: policy.LockoutAtCeiling, assert: is("at-ceiling")},
		{name: "cleared", kind: policy.LockoutCleared, assert: is("cleared")},
		{name: "held", kind: policy.LockoutHeld, assert: is("held")},
		{name: "released", kind: policy.LockoutReleased, assert: is("released")},
		{name: "the zero value is no kind", kind: 0, assert: is("unknown")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.kind.String())
		})
	}
}
