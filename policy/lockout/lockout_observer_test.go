package lockout_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// TestLockoutObserverDefaults pins that a policy with no observer adds
// nothing to the store's work: its view records and nothing else.
func TestLockoutObserverDefaults(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockAttemptStore(ctrl)
	store.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil).Times(1)

	p := lockoutWith(t, lockout.WithAttemptStore(store))

	require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	assert.Equal(t, p.Attempts(), p.Attempts(),
		"two calls must hand out the same view, so the chain can deduplicate it")
}

// TestLockoutObserverViewIsOneValue pins that an observed policy hands out one
// view, by identity: a chain that deduplicates the stores it was given must
// see form login's and Basic's as the same store, or a reset is reported twice.
func TestLockoutObserverViewIsOneValue(t *testing.T) {
	t.Parallel()

	p := lockoutWith(t, lockout.WithObserver(func(context.Context, lockout.Report) {}))

	first, second := p.Attempts(), p.Attempts()
	assert.Same(t, first, second, "two calls handed out different views")
	assert.True(t, first == second, "the views must compare equal as interface values")
}

// countKind counts the reports of kind k.
func countKind(r []lockout.Report, k lockout.ReportKind) int {
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

		seeder := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(limit))
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

		streaks, ok := s.(lockout.FailureStreakStore)
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
		opts   []lockout.Option
		store  func(t *testing.T) policy.AttemptStore // nil: a fresh in-memory store
		before func(t *testing.T, store policy.AttemptStore)
		act    func(t *testing.T, p *lockout.Policy) error
		assert func(t *testing.T, reports []lockout.Report, err error, logs string)
	}

	record := func(id string) func(*testing.T, *lockout.Policy) error {
		return func(t *testing.T, p *lockout.Policy) error {
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
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			name:   "the fifth failure reports the identifier locked",
			before: prior("ada", 4),
			act:    record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 5, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "each further locking failure is reported",
			before: prior("ada", 5),
			act:    record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 6, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "the hundredth failure reports the ceiling",
			before: prior("ada", 99),
			act:    record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 1)
				assert.Equal(t, lockout.ReportAtWindowFailureLimit, r[0].Kind)
				assert.Equal(t, 100, r[0].Failures)
			},
		},
		{
			name:   "under a sliding lock a locking failure is locked, never at the ceiling",
			opts:   []lockout.Option{lockout.WithSliding(3, 15*time.Minute)},
			before: prior("ada", 2),
			act:    record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 3, At: lockoutNow},
				}, r)
			},
		},
		{
			name: "under a sliding lock failures older than its window do not count",
			opts: []lockout.Option{lockout.WithSliding(3, 15*time.Minute)},
			before: func(t *testing.T, s policy.AttemptStore) {
				for i := range 3 {
					require.NoError(t, s.RecordFailure(t.Context(), "ada", lockoutNow.Add(-20*time.Minute-time.Duration(i)*time.Second)))
				}
			},
			act: record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r, "failures outside the sliding window were counted")
			},
		},
		{
			name:   "an unknown identifier is reported exactly like a known one",
			before: func(t *testing.T, s policy.AttemptStore) { prior("ada", 4)(t, s); prior("nobody", 4)(t, s) },
			act: func(t *testing.T, p *lockout.Policy) error {
				return errors.Join(record("ada")(t, p), record("nobody")(t, p))
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
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
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
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
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportCleared, Failures: 3, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "an administrator's reset through the policy is reported too",
			before: prior("ada", 3),
			act:    func(t *testing.T, p *lockout.Policy) error { return p.Reset(t.Context(), "ada") },
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 1)
				assert.Equal(t, lockout.ReportCleared, r[0].Kind)
			},
		},
		{
			name: "clearing nothing is not reported",
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
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
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
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
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
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
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, logs string) {
				require.NoError(t, err, "the reset succeeded, so clearing succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "lockout: a lockout report was lost"))
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
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, logs string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Empty(t, r)
				assert.Empty(t, logs)
			},
		},
		{
			name: "a nil lockout logger leaves the logger in place",
			opts: []lockout.Option{lockout.WithLogger(nil)},
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, _ []lockout.Report, err error, logs string) {
				require.NoError(t, err)
				assert.Contains(t, logs, "lockout: a lockout report was lost")
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
			assert: func(t *testing.T, r []lockout.Report, err error, logs string) {
				require.NoError(t, err, "the failure is recorded, so recording succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "lockout: a lockout report was lost"))
				assert.NotContains(t, logs, "ada")
			},
		},
		{
			// Spec: "Held". The twentieth write is reported as the hold, and
			// not also as a windowed lock.
			name: "the failure that reaches the cap reports the hold once",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			act: func(t *testing.T, p *lockout.Policy) error {
				for range 20 {
					require.NoError(t, record("ada")(t, p))
				}

				return nil
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				require.NotEmpty(t, r)
				assert.Equal(t, lockout.Report{
					Identifier: "ada", Kind: lockout.ReportHeld, Failures: 20, At: lockoutNow,
				}, r[len(r)-1])
				assert.Equal(t, 1, countKind(r, lockout.ReportHeld), "the hold was not reported exactly once")
				for _, rep := range r[:len(r)-1] {
					assert.NotEqual(t, 20, rep.Failures, "the write that set the hold was also reported as %v", rep.Kind)
				}
			},
		},
		{
			// Review Focus 1: the count passed a cap it was never held at, so
			// the hold is set by the next write, at 71, not at the cap.
			name:   "a cap lowered below an existing count reports the hold on the next failure",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(50)},
			before: cappedFailures("ada", 100, 70),
			act:    record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportHeld, Failures: 71, At: lockoutNow},
				}, r)
			},
		},
		{
			// Only the write that set the hold reports it; later failures are
			// reported by the window, as before.
			name:   "a failure after the hold is reported by the window",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(20)},
			before: cappedFailures("ada", 20, 20),
			act:    record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 21, At: lockoutNow},
				}, r)
			},
		},
		{
			// The hold is in the streak, which the store accepted: losing its
			// report because the log failed would lose it for good, since no
			// later write sets it again.
			name: "a hold set while the log could not record is still reported",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					AddStreakFailure(gomock.Any(), "ada", lockoutNow, gomock.Any(), 20).
					Return(lockout.FailureStreak{Failures: 20, Newest: lockoutNow, HeldAt: lockoutNow}, true, nil)
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportHeld, Failures: 20, At: lockoutNow},
				}, r)
			},
		},
		{
			// Spec: "Hold lifted", through the administrator's unlock.
			name:   "a reset of a held identifier reports the hold lifted in place of cleared",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(20)},
			before: cappedFailures("ada", 20, 20),
			act:    func(t *testing.T, p *lockout.Policy) error { return p.Reset(t.Context(), "ada") },
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportReleased, Failures: 20, At: lockoutNow},
				}, r)
			},
		},
		{
			// A hold outlives the window, so its release is reported even when
			// the window holds nothing to clear.
			name:   "a hold with nothing in the window is still reported lifted",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(20)},
			before: heldStreak("ada", 20),
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportReleased, Failures: 20, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "with a cap a reset of failures that are not held reports them cleared",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(20)},
			before: cappedFailures("ada", 20, 3),
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportCleared, Failures: 3, At: lockoutNow},
				}, r)
			},
		},
		{
			name: "with a cap clearing nothing is not reported",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			// Without the streak the policy cannot tell a release from a
			// clearing, so it reports neither rather than the wrong one.
			name: "a reset whose streak could not be read loses only its report",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakAttemptStore(t)
				s.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(3, nil)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(lockout.FailureStreak{}, errAttemptStoreDown)
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

				return s
			},
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, logs string) {
				require.NoError(t, err, "the reset succeeded, so clearing succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "lockout: a lockout report was lost"))
				assert.NotContains(t, logs, "ada")
			},
		},
		{
			name: "a reset of a held identifier the store refused is not reported",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakAttemptStore(t)
				s.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(20, nil)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", gomock.Any()).
					Return(lockout.FailureStreak{Failures: 20, Newest: lockoutNow, HeldAt: lockoutNow}, nil)
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

				return s
			},
			act: func(t *testing.T, p *lockout.Policy) error {
				return p.Attempts().Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, r []lockout.Report, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Empty(t, r)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var store policy.AttemptStore = lockout.NewMemoryAttemptStore()
			if tc.store != nil {
				store = tc.store(t)
			}
			if tc.before != nil {
				tc.before(t, store)
			}

			var logs bytes.Buffer
			got := &reportLog{}
			p := lockoutWith(t, append([]lockout.Option{
				lockout.WithAttemptStore(store),
				lockout.WithObserver(got.observe),
				lockout.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
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

	store := lockout.NewMemoryAttemptStore()
	failuresEndingAt("ada", 5, time.Minute)(t, store)

	got := &reportLog{}
	p := lockoutWith(t, lockout.WithAttemptStore(store), lockout.WithObserver(got.observe))

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
		assert.Equal(t, lockout.ReportLocked, r.Kind)
	}
}

// TestLockoutObserverDefaultLoggerIsSlogDefault pins that without
// WithLogger the lost-report record goes to slog.Default. It swaps the
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
		lockout.WithAttemptStore(s),
		lockout.WithObserver(func(context.Context, lockout.Report) {}),
	)

	require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	assert.Equal(t, 1, strings.Count(logs.String(), "lockout: a lockout report was lost"))
}

func TestLockoutObserverPanicChangesNothing(t *testing.T) {
	t.Parallel()

	store := lockout.NewMemoryAttemptStore()
	failuresEndingAt("ada", 4, time.Second)(t, store)

	var logs bytes.Buffer
	p := lockoutWith(t,
		lockout.WithAttemptStore(store),
		lockout.WithObserver(func(context.Context, lockout.Report) { panic("observer bug") }),
		lockout.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)

	require.NotPanics(t, func() {
		assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	})
	assert.Equal(t, 1, strings.Count(logs.String(), "lockout: the lockout observer panicked"))
	assert.NotContains(t, logs.String(), "ada", "the record must not carry the submitted identifier")
}

func TestLockoutObserverReportKindString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   lockout.ReportKind
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(*testing.T, string) {
		return func(t *testing.T, got string) { assert.Equal(t, want, got) }
	}

	cases := []testCase{
		{name: "locked", kind: lockout.ReportLocked, assert: is("locked")},
		{name: "at the ceiling", kind: lockout.ReportAtWindowFailureLimit, assert: is("at-ceiling")},
		{name: "cleared", kind: lockout.ReportCleared, assert: is("cleared")},
		{name: "held", kind: lockout.ReportHeld, assert: is("held")},
		{name: "released", kind: lockout.ReportReleased, assert: is("released")},
		{name: "the zero value is no kind", kind: 0, assert: is("unknown")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.kind.String())
		})
	}
}
