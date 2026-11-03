package lockout_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/internal/secevent"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/security"
)

// eventLog is a security-event sink that keeps what it receives.
type eventLog struct {
	mu     sync.Mutex
	events []security.Event
}

func (l *eventLog) sink(_ context.Context, e security.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.events = append(l.events, e)
}

func (l *eventLog) all() []security.Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]security.Event(nil), l.events...)
}

// lockEvents is what one lock reports: authn_login_fail_max, then
// authn_login_lock, at at, carrying kind and nothing the policy cannot know.
func lockEvents(at time.Time, kind factor.Kind) []security.Event {
	return []security.Event{
		{Name: security.AuthnLoginFailMax, Outcome: security.OutcomeFailure, At: at, Factor: kind},
		{Name: security.AuthnLoginLock, Outcome: security.OutcomeFailure, At: at, Factor: kind},
	}
}

// priorAged records n failures for id into s, the newest newest before
// lockoutNow and each earlier one a second before the next.
func priorAged(id string, n int, newest time.Duration) func(*testing.T, policy.AttemptStore) {
	return func(t *testing.T, s policy.AttemptStore) {
		for i := range n {
			require.NoError(t, s.RecordFailure(t.Context(), id, lockoutNow.Add(-newest-time.Duration(i)*time.Second)))
		}
	}
}

// countingAttemptStore is an attempt store that forwards every call to under,
// counts the FailureCount calls it answers, and answers the failOn-th of them,
// when failOn is not zero, with errAttemptStoreDown.
func countingAttemptStore(t *testing.T, under policy.AttemptStore, failOn int32) (*MockAttemptStore, *atomic.Int32) {
	t.Helper()

	reads := &atomic.Int32{}
	store := NewMockAttemptStore(gomock.NewController(t))
	store.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(under.RecordFailure).AnyTimes()
	store.EXPECT().Reset(gomock.Any(), gomock.Any()).DoAndReturn(under.Reset).AnyTimes()
	store.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, username string, since time.Time) (int, error) {
			if reads.Add(1) == failOn {
				return 0, errAttemptStoreDown
			}

			return under.FailureCount(ctx, username, since)
		})

	return store, reads
}

// streakFailures records failures for id through a policy whose failure-streak
// limit is 6: old of them first, an hour apart with the newest 47 hours before
// lockoutNow, so outside the default 24-hour window, then inWindow of them a
// minute apart with the newest a minute before lockoutNow. Six or more in all
// set a hold on the sixth, however few the window holds.
func streakFailures(id string, old, inWindow int) func(*testing.T, policy.AttemptStore) {
	return func(t *testing.T, s policy.AttemptStore) {
		t.Helper()

		seeder := lockoutWith(t, lockout.WithAttemptStore(s), lockout.WithFailureStreakLimit(6))
		ctx := t.Context()

		for i := range old {
			require.NoError(t, seeder.Attempts().RecordFailure(ctx, id, lockoutNow.Add(-time.Duration(47+old-1-i)*time.Hour)))
		}
		for i := range inWindow {
			require.NoError(t, seeder.Attempts().RecordFailure(ctx, id, lockoutNow.Add(-time.Duration(inWindow-i)*time.Minute)))
		}
	}
}

// streakStoreFaults says which calls of a countingStreakStore fail.
type streakStoreFaults struct {
	// streakRead makes every FailureStreak read fail.
	streakRead bool

	// logWrite makes RecordFailure fail, without recording.
	logWrite bool
}

// readCounts is how many reads of each kind a countingStreakStore answered.
type readCounts struct {
	window, streak atomic.Int32
}

// countingStreakStore is an attempt store that also keeps consecutive
// failures: it forwards every call to under, counts the FailureCount and
// FailureStreak reads it answers, and fails the calls faults names with
// errAttemptStoreDown.
func countingStreakStore(
	t *testing.T, under *lockout.MemoryAttemptStore, faults streakStoreFaults,
) (*streakAttemptStore, *readCounts) {
	t.Helper()

	reads := &readCounts{}
	store := newStreakAttemptStore(t)
	store.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, username string, at time.Time) error {
			if faults.logWrite {
				return errAttemptStoreDown
			}

			return under.RecordFailure(ctx, username, at)
		})
	store.MockAttemptStore.EXPECT().Reset(gomock.Any(), gomock.Any()).DoAndReturn(under.Reset).AnyTimes()
	store.MockAttemptStore.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, username string, since time.Time) (int, error) {
			reads.window.Add(1)

			return under.FailureCount(ctx, username, since)
		})
	store.MockFailureStreakStore.EXPECT().AddStreakFailure(
		gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).DoAndReturn(under.AddStreakFailure).AnyTimes()
	store.MockFailureStreakStore.EXPECT().FailureStreak(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, username string, since time.Time) (lockout.FailureStreak, error) {
			reads.streak.Add(1)
			if faults.streakRead {
				return lockout.FailureStreak{}, errAttemptStoreDown
			}

			return under.FailureStreak(ctx, username, since)
		})

	return store, reads
}

// TestSecurityEvents_LockoutReports pins that the lockout reports a lock where
// it decides it, through its own view: the failure that takes an identifier
// to a lock reports authn_login_fail_max and authn_login_lock once, to the
// chain's delivery on a chain's request and to the policy's own sink
// otherwise, and the observer keeps being told as before.
func TestSecurityEvents_LockoutReports(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// ownSink gives the policy a sink of its own; observe gives it an
		// observer.
		ownSink, observe bool

		// opts are further options.
		opts []lockout.Option

		// before records into the store the policy counts in.
		before func(t *testing.T, s policy.AttemptStore)

		// ctx stands for the request: chain is the chain's delivery.
		ctx func(ctx context.Context, chain secevent.Emitter) context.Context

		// failCount, when not zero, makes the store's failCount-th
		// FailureCount fail: the first is the count before the write, the
		// second the recency the escalating wait reads, when it is read.
		failCount int32

		// failStreak makes the store's every read of an identifier's streak
		// fail.
		failStreak bool

		// act records the failure under test; nil records one through the view.
		act func(t *testing.T, ctx context.Context, p *lockout.Policy) error

		assert func(t *testing.T, own, chain []security.Event, reports []lockout.Report)
	}

	prior := func(id string, n int) func(*testing.T, policy.AttemptStore) {
		return func(t *testing.T, s policy.AttemptStore) {
			for i := range n {
				require.NoError(t, s.RecordFailure(t.Context(), id, lockoutNow.Add(-time.Duration(i+1)*time.Second)))
			}
		}
	}
	onChain := func(ctx context.Context, chain secevent.Emitter) context.Context {
		return secevent.With(ctx, chain)
	}

	// locksAgain records a failure through the view and requires that it took
	// the identifier from allowed to locked by the policy's own rule.
	locksAgain := func(t *testing.T, ctx context.Context, p *lockout.Policy) error {
		require.Equal(t, policy.Allow, p.Evaluate(ctx, lockoutInput("ada")).Outcome, "allowed before the failure")
		err := p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
		require.ErrorIs(t, p.Evaluate(ctx, lockoutInput("ada")).Reason, lockout.ErrAccountLocked, "locked after it")

		return err
	}
	// staysLocked records a failure through the view and requires that the
	// identifier was locked before it and still is after.
	staysLocked := func(t *testing.T, ctx context.Context, p *lockout.Policy) error {
		require.ErrorIs(t, p.Evaluate(ctx, lockoutInput("ada")).Reason, lockout.ErrAccountLocked, "locked before the failure")
		err := p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
		require.ErrorIs(t, p.Evaluate(ctx, lockoutInput("ada")).Reason, lockout.ErrAccountLocked, "locked after it")

		return err
	}

	// staysHeld records a failure through the view and requires that the
	// identifier was held before it and still is after.
	staysHeld := func(t *testing.T, ctx context.Context, p *lockout.Policy) error {
		require.ErrorIs(t, p.Evaluate(ctx, lockoutInput("ada")).Reason, lockout.ErrAccountHeld, "held before the failure")
		err := p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
		require.ErrorIs(t, p.Evaluate(ctx, lockoutInput("ada")).Reason, lockout.ErrAccountHeld, "held after it")

		return err
	}
	// setsHold records a failure through the view and requires that it took
	// the identifier from allowed to held.
	setsHold := func(t *testing.T, ctx context.Context, p *lockout.Policy) error {
		require.Equal(t, policy.Allow, p.Evaluate(ctx, lockoutInput("ada")).Outcome, "allowed before the failure")
		err := p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
		require.ErrorIs(t, p.Evaluate(ctx, lockoutInput("ada")).Reason, lockout.ErrAccountHeld, "held after it")

		return err
	}

	cases := []testCase{
		{
			name:    "failures below the threshold report nothing",
			ownSink: true,
			before:  prior("ada", 3),
			assert: func(t *testing.T, own, chain []security.Event, _ []lockout.Report) {
				assert.Empty(t, own)
				assert.Empty(t, chain)
			},
		},
		{
			name:    "the failure that reaches the threshold reports the lock once",
			ownSink: true,
			before:  prior("ada", 4),
			assert: func(t *testing.T, own, chain []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
				assert.Empty(t, chain)
			},
		},
		{
			name:    "a failure on an identifier already at its threshold reports nothing more",
			ownSink: true,
			before:  prior("ada", 5),
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own)
			},
		},
		{
			name:    "the failure that reaches the window failure limit reports that lock",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithWindowFailureLimit(8)},
			before:  prior("ada", 7),
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
			},
		},
		{
			name:    "the failure that sets a hold reports that lock",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithFailureStreakLimit(6)},
			before:  cappedFailures("ada", 6, 5),
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
			},
		},
		{
			name:    "a configured observer is still told beside the sink",
			ownSink: true,
			observe: true,
			before:  prior("ada", 4),
			assert: func(t *testing.T, own, _ []security.Event, reports []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 5, At: lockoutNow},
				}, reports)
			},
		},
		{
			name:    "without a sink the observer alone is told",
			observe: true,
			before:  prior("ada", 4),
			assert: func(t *testing.T, own, chain []security.Event, reports []lockout.Report) {
				assert.Empty(t, own)
				assert.Empty(t, chain)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 5, At: lockoutNow},
				}, reports)
			},
		},
		{
			name:    "on a chain's request the lock reports through the chain, not the policy's own sink",
			ownSink: true,
			before:  prior("ada", 4),
			ctx:     onChain,
			assert: func(t *testing.T, own, chain []security.Event, _ []lockout.Report) {
				assert.Empty(t, own, "one lock is reported once")
				assert.Equal(t, lockEvents(lockoutNow, ""), chain)
			},
		},
		{
			name:   "on a chain's request a policy with no sink of its own reports through the chain",
			before: prior("ada", 4),
			ctx:    onChain,
			assert: func(t *testing.T, _, chain []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), chain)
			},
		},
		{
			name:    "the first factor the request names is carried",
			ownSink: true,
			before:  prior("ada", 4),
			ctx: func(ctx context.Context, _ secevent.Emitter) context.Context {
				return secevent.WithFactor(ctx, factor.Password)
			},
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, factor.Password), own)
			},
		},
		{
			name:    "the policy's own RecordFailure reports the lock at its clock's instant",
			ownSink: true,
			before:  prior("ada", 4),
			act: func(_ *testing.T, ctx context.Context, p *lockout.Policy) error {
				return p.RecordFailure(ctx, "ada")
			},
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
			},
		},
		{
			name:    "a failure recorded straight into the store, not through the view, is not reported",
			ownSink: true,
			before:  prior("ada", 4),
			act: func(_ *testing.T, ctx context.Context, p *lockout.Policy) error {
				return p.StoreForTest().RecordFailure(ctx, "ada", lockoutNow)
			},
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own)
			},
		},
		{
			name:    "a failure after the escalating wait has run out locks again, longer, and reports again",
			ownSink: true,
			observe: true,
			before:  priorAged("ada", 5, time.Hour),
			act:     locksAgain,
			assert: func(t *testing.T, own, _ []security.Event, reports []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
				assert.Equal(t, []lockout.Report{
					{Identifier: "ada", Kind: lockout.ReportLocked, Failures: 6, At: lockoutNow},
				}, reports)
			},
		},
		{
			name:    "a failure while an escalated wait still runs reports nothing more",
			ownSink: true,
			// Six failures owe a minute, twice the first wait; the newest is
			// 45 seconds old, past the first wait but not past the minute.
			before: priorAged("ada", 6, 45*time.Second),
			act:    staysLocked,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own)
			},
		},
		{
			name:    "under the sliding lock a failure on an identifier at its threshold reports nothing more, however old its failures",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithSliding(5, 24*time.Hour)},
			before:  priorAged("ada", 5, time.Hour),
			act:     staysLocked,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own)
			},
		},
		{
			name:    "the failure that reaches the window failure limit while a wait still runs reports that lock",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithWindowFailureLimit(8)},
			before:  priorAged("ada", 7, time.Second),
			act:     staysLocked,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
			},
		},
		{
			// The hold is set while the window holds two failures, so the
			// window never reaches the threshold on this failure.
			name:    "the failure that sets a hold while its window is below the threshold reports that lock",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithFailureStreakLimit(6)},
			before:  streakFailures("ada", 4, 1),
			act:     setsHold,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
			},
		},
		{
			name:    "a failure that brings a held identifier's window to the threshold reports nothing more",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithFailureStreakLimit(6)},
			before:  streakFailures("ada", 4, 4),
			act:     staysHeld,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own, "a held identifier reported a second lock")
			},
		},
		{
			name:    "a failure that brings a held identifier's window to the window failure limit reports nothing more",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithFailureStreakLimit(6), lockout.WithWindowFailureLimit(8)},
			before:  streakFailures("ada", 4, 7),
			act:     staysHeld,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own, "a held identifier reported reaching the window failure limit")
			},
		},
		{
			name:       "a failure whose streak could not be read before the write reports no lock",
			ownSink:    true,
			opts:       []lockout.Option{lockout.WithFailureStreakLimit(6)},
			before:     prior("ada", 4),
			failStreak: true,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own, "an unknown streak is not taken for an identifier that is not held")
			},
		},
		{
			// Six failures owe a minute. The newest is 90 seconds old, so that
			// wait has run out, though the two minutes seven would owe, or the
			// hour of the longest wait, have not.
			name:    "a failure after the wait its count owes has run out locks again, though a longer wait would still run",
			ownSink: true,
			before:  priorAged("ada", 6, 90*time.Second),
			act:     locksAgain,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Equal(t, lockEvents(lockoutNow, ""), own)
			},
		},
		{
			name:      "a failure whose window could not be counted before the write reports no lock",
			ownSink:   true,
			before:    prior("ada", 4),
			failCount: 1,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own, "an unknown count before the write is not taken for zero")
			},
		},
		{
			name:      "a failure whose recency could not be read before the write reports no lock",
			ownSink:   true,
			before:    priorAged("ada", 5, time.Hour),
			failCount: 2,
			assert: func(t *testing.T, own, _ []security.Event, _ []lockout.Report) {
				assert.Empty(t, own, "an unknown recency is not taken for an allowed identifier")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := lockout.NewMemoryAttemptStore()
			require.NoError(t, err)

			if tc.before != nil {
				tc.before(t, store)
			}

			var counted policy.AttemptStore = store
			if tc.failCount != 0 {
				counted, _ = countingAttemptStore(t, store, tc.failCount)
			}
			if tc.failStreak {
				counted, _ = countingStreakStore(t, store, streakStoreFaults{streakRead: true})
			}

			var (
				own, chain eventLog
				mu         sync.Mutex
				reports    []lockout.Report
			)

			opts := append([]lockout.Option{lockout.WithAttemptStore(counted)}, tc.opts...)
			if tc.ownSink {
				opts = append(opts, lockout.WithSecurityEvents(own.sink))
			}
			if tc.observe {
				opts = append(opts, lockout.WithObserver(func(_ context.Context, r lockout.Report) {
					mu.Lock()
					defer mu.Unlock()

					reports = append(reports, r)
				}))
			}

			p := lockoutWith(t, opts...)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx, chain.sink)
			}

			act := tc.act
			if act == nil {
				act = func(_ *testing.T, ctx context.Context, p *lockout.Policy) error {
					return p.Attempts().RecordFailure(ctx, "ada", lockoutNow)
				}
			}
			require.NoError(t, act(t, ctx, p))

			mu.Lock()
			defer mu.Unlock()

			tc.assert(t, own.all(), chain.all(), reports)
		})
	}
}

// TestSecurityEvents_LockoutConfig pins that the policy's own sink is one
// sink: none given is the default, and a nil sink or the option twice is a
// configuration error.
func TestSecurityEvents_LockoutConfig(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		assert func(t *testing.T, p *lockout.Policy, err error)
	}

	sink := func(context.Context, security.Event) {}

	cases := []testCase{
		{
			name: "no sink is the default",
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "one sink",
			opts: []lockout.Option{lockout.WithSecurityEvents(sink)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "a nil sink is a configuration error",
			opts: []lockout.Option{lockout.WithSecurityEvents(nil)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
		{
			name: "the option twice is a configuration error",
			opts: []lockout.Option{lockout.WithSecurityEvents(sink), lockout.WithSecurityEvents(sink)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.ErrorIs(t, err, policy.ErrConfig)
				assert.Nil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := lockout.New(tc.opts...)
			tc.assert(t, p, err)
		})
	}
}

// barrierStore is an attempt store whose RecordFailure waits until arrivals
// callers are inside it at once, or until a short wait passes, so every
// caller that can run concurrently is made to.
type barrierStore struct {
	policy.AttemptStore

	arrived chan struct{}
	release chan struct{}
	once    sync.Once
	want    int
}

func newBarrierStore(t *testing.T, want int) *barrierStore {
	t.Helper()

	inner, err := lockout.NewMemoryAttemptStore()
	require.NoError(t, err)

	b := &barrierStore{AttemptStore: inner, arrived: make(chan struct{}, want), release: make(chan struct{}), want: want}

	go func() {
		for range want {
			select {
			case <-b.arrived:
			case <-time.After(5 * time.Second):
			}
		}
		b.once.Do(func() { close(b.release) })
	}()

	return b
}

func (b *barrierStore) RecordFailure(ctx context.Context, username string, at time.Time) error {
	b.arrived <- struct{}{}

	select {
	case <-b.release:
	case <-time.After(100 * time.Millisecond):
	}

	return b.AttemptStore.RecordFailure(ctx, username, at)
}

// TestSecurityEvents_LockReportedOnce pins that one lock is reported once:
// failures recorded at the same moment that together take an identifier past
// its threshold report authn_login_fail_max and authn_login_lock once between
// them, while the observer is still told of every failure that leaves the
// identifier locked.
func TestSecurityEvents_LockReportedOnce(t *testing.T) {
	t.Parallel()

	const concurrent = 4

	store := newBarrierStore(t, concurrent)
	for i := range 4 {
		require.NoError(t, store.AttemptStore.RecordFailure(t.Context(), "ada", lockoutNow.Add(-time.Duration(i+1)*time.Second)))
	}

	var (
		own     eventLog
		mu      sync.Mutex
		reports int
	)

	p := lockoutWith(t, lockout.WithAttemptStore(store), lockout.WithSecurityEvents(own.sink),
		lockout.WithObserver(func(context.Context, lockout.Report) {
			mu.Lock()
			defer mu.Unlock()

			reports++
		}))

	var wg sync.WaitGroup
	for range concurrent {
		wg.Go(func() {
			assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
		})
	}
	wg.Wait()

	assert.Equal(t, lockEvents(lockoutNow, ""), own.all(), "one lock, reported once")

	mu.Lock()
	defer mu.Unlock()

	assert.Equal(t, concurrent, reports, "the observer is told of every failure that leaves the identifier locked")
}

// TestSecurityEvents_LockoutStoreReads pins what deciding a lock costs the
// store: nothing beyond the count the observer already reads when no sink
// watches, the count before the write as well while one does, and the
// recency the escalating wait reads only for an identifier the count alone
// cannot tell locked from allowed.
func TestSecurityEvents_LockoutStoreReads(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name             string
		ownSink, observe bool
		opts             []lockout.Option
		before           func(t *testing.T, s policy.AttemptStore)
		assert           func(t *testing.T, reads int32)
	}

	cases := []testCase{
		{
			name:   "with no sink and no observer the failure is only written",
			before: priorAged("ada", 5, time.Hour),
			assert: func(t *testing.T, reads int32) { assert.Zero(t, reads) },
		},
		{
			name:    "with an observer and no sink the window is counted once, after the write",
			observe: true,
			before:  priorAged("ada", 5, time.Hour),
			assert:  func(t *testing.T, reads int32) { assert.Equal(t, int32(1), reads) },
		},
		{
			name:    "with a sink, below the threshold, the window is counted before and after",
			ownSink: true,
			before:  priorAged("ada", 3, time.Hour),
			assert:  func(t *testing.T, reads int32) { assert.Equal(t, int32(2), reads) },
		},
		{
			name:    "with a sink and an observer, below the threshold, the observer shares the count after",
			ownSink: true,
			observe: true,
			before:  priorAged("ada", 3, time.Hour),
			assert:  func(t *testing.T, reads int32) { assert.Equal(t, int32(2), reads) },
		},
		{
			name:    "with a sink, between the threshold and the window failure limit, the recency is read too",
			ownSink: true,
			before:  priorAged("ada", 5, time.Hour),
			assert:  func(t *testing.T, reads int32) { assert.Equal(t, int32(3), reads) },
		},
		{
			name:    "with a sink, at the window failure limit, no recency is read",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithWindowFailureLimit(8)},
			before:  priorAged("ada", 8, time.Hour),
			assert:  func(t *testing.T, reads int32) { assert.Equal(t, int32(2), reads) },
		},
		{
			name:    "with a sink, under the sliding lock, no recency is read",
			ownSink: true,
			opts:    []lockout.Option{lockout.WithSliding(5, 24*time.Hour)},
			before:  priorAged("ada", 5, time.Hour),
			assert:  func(t *testing.T, reads int32) { assert.Equal(t, int32(2), reads) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			under, err := lockout.NewMemoryAttemptStore()
			require.NoError(t, err)
			tc.before(t, under)

			store, reads := countingAttemptStore(t, under, 0)

			opts := append([]lockout.Option{lockout.WithAttemptStore(store)}, tc.opts...)
			if tc.ownSink {
				opts = append(opts, lockout.WithSecurityEvents(func(context.Context, security.Event) {}))
			}
			if tc.observe {
				opts = append(opts, lockout.WithObserver(func(context.Context, lockout.Report) {}))
			}

			p := lockoutWith(t, opts...)
			require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))

			tc.assert(t, reads.Load())
		})
	}
}

// TestSecurityEvents_LockoutStreakReads pins what a failure reads under a
// failure-streak limit and on the paths that skip a read: the streak once
// while a sink watches, no window count before the write for a held
// identifier, and no count after one for the failure that sets a hold or
// whose write failed.
func TestSecurityEvents_LockoutStreakReads(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name             string
		ownSink, observe bool
		opts             []lockout.Option
		before           func(t *testing.T, s policy.AttemptStore)
		faults           streakStoreFaults
		assert           func(t *testing.T, reads *readCounts, err error)
	}

	streakLimit := []lockout.Option{lockout.WithFailureStreakLimit(6)}
	reads := func(window, streak int32) func(*testing.T, *readCounts, error) {
		return func(t *testing.T, got *readCounts, err error) {
			require.NoError(t, err)
			assert.Equal(t, window, got.window.Load(), "window counts")
			assert.Equal(t, streak, got.streak.Load(), "streak reads")
		}
	}
	readsAfterLogFailure := func(window, streak int32) func(*testing.T, *readCounts, error) {
		return func(t *testing.T, got *readCounts, err error) {
			require.ErrorIs(t, err, errAttemptStoreDown)
			assert.Equal(t, window, got.window.Load(), "window counts")
			assert.Equal(t, streak, got.streak.Load(), "streak reads")
		}
	}

	cases := []testCase{
		{
			name:    "with a sink and a streak limit, below the threshold, the streak is read once and the window before and after",
			ownSink: true,
			opts:    streakLimit,
			before:  streakFailures("ada", 0, 3),
			assert:  reads(2, 1),
		},
		{
			name:    "with a sink and a streak limit, between the threshold and the window failure limit, the recency is read too",
			ownSink: true,
			// A limit of 7, so that the sixth failure sets no hold.
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(7)},
			before: streakFailures("ada", 0, 5),
			assert: reads(3, 1),
		},
		{
			name:    "with a sink, a held identifier's window is counted only after the write",
			ownSink: true,
			opts:    streakLimit,
			before:  streakFailures("ada", 4, 2),
			assert:  reads(1, 1),
		},
		{
			name:    "with a sink, the failure that sets a hold counts the window before the write and not after",
			ownSink: true,
			opts:    streakLimit,
			before:  streakFailures("ada", 4, 1),
			assert:  reads(1, 1),
		},
		{
			name:    "with only an observer, the failure that sets a hold reads nothing",
			observe: true,
			opts:    streakLimit,
			before:  streakFailures("ada", 4, 1),
			assert:  reads(0, 0),
		},
		{
			name:    "with only an observer, a failure on a held identifier counts the window once, after the write",
			observe: true,
			opts:    streakLimit,
			before:  streakFailures("ada", 4, 2),
			assert:  reads(1, 0),
		},
		{
			name:    "with a sink, a failure whose log write failed counts the window once before it, below the threshold",
			ownSink: true,
			before:  priorAged("ada", 3, time.Hour),
			faults:  streakStoreFaults{logWrite: true},
			assert:  readsAfterLogFailure(1, 0),
		},
		{
			name:    "with a sink, a failure whose log write failed reads the recency too, between the threshold and the window failure limit",
			ownSink: true,
			before:  priorAged("ada", 5, time.Hour),
			faults:  streakStoreFaults{logWrite: true},
			assert:  readsAfterLogFailure(2, 0),
		},
		{
			name:    "with a sink and a streak limit, a failure whose log write failed reads the streak and the window before it",
			ownSink: true,
			opts:    streakLimit,
			before:  streakFailures("ada", 0, 3),
			faults:  streakStoreFaults{logWrite: true},
			assert:  readsAfterLogFailure(1, 1),
		},
		{
			name:    "with only an observer, a failure whose log write failed reads nothing",
			observe: true,
			before:  priorAged("ada", 5, time.Hour),
			faults:  streakStoreFaults{logWrite: true},
			assert:  readsAfterLogFailure(0, 0),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			under, err := lockout.NewMemoryAttemptStore()
			require.NoError(t, err)
			tc.before(t, under)

			store, counts := countingStreakStore(t, under, tc.faults)
			counts.window.Store(0)
			counts.streak.Store(0)

			opts := append([]lockout.Option{lockout.WithAttemptStore(store)}, tc.opts...)
			if tc.ownSink {
				opts = append(opts, lockout.WithSecurityEvents(func(context.Context, security.Event) {}))
			}
			if tc.observe {
				opts = append(opts, lockout.WithObserver(func(context.Context, lockout.Report) {}))
			}

			p := lockoutWith(t, opts...)
			err = p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow)

			tc.assert(t, counts, err)
		})
	}
}

// panickingAttemptStore is an attempt store whose first RecordFailure panics,
// as a consumer's store with a defect might, and whose every other call is
// forwarded to under.
func panickingAttemptStore(t *testing.T, under policy.AttemptStore) *MockAttemptStore {
	t.Helper()

	var calls atomic.Int32
	store := NewMockAttemptStore(gomock.NewController(t))
	store.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, username string, at time.Time) error {
			if calls.Add(1) == 1 {
				panic("the consumer's store failed")
			}

			return under.RecordFailure(ctx, username, at)
		})
	store.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(under.FailureCount).AnyTimes()

	return store
}

// TestSecurityEvents_LockoutIdentifierLocks pins that the per-identifier
// serialisation a watching sink needs never outlives the failures it
// serialises: an identifier is released when its failure is done, even when
// the consumer's store panicked, so no later failure for it waits forever and
// no identifier is kept once nothing is recorded for it.
func TestSecurityEvents_LockoutIdentifierLocks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// store wraps the policy's in-memory store.
		store func(t *testing.T, under policy.AttemptStore) policy.AttemptStore

		// act records the case's failures through p's view.
		act func(t *testing.T, ctx context.Context, p *lockout.Policy)
	}

	cases := []testCase{
		{
			name: "a store that panics does not leave the identifier held",
			store: func(t *testing.T, under policy.AttemptStore) policy.AttemptStore {
				return panickingAttemptStore(t, under)
			},
			act: func(t *testing.T, ctx context.Context, p *lockout.Policy) {
				assert.Panics(t, func() { _ = p.Attempts().RecordFailure(ctx, "ada", lockoutNow) },
					"the consumer's panic is the consumer's to see")

				done := make(chan error, 1)
				go func() { done <- p.Attempts().RecordFailure(ctx, "ada", lockoutNow) }()

				select {
				case err := <-done:
					assert.NoError(t, err)
				case <-time.After(2 * time.Second):
					require.FailNow(t, "a later failure for the identifier is blocked behind the panicked one")
				}
			},
		},
		{
			name: "failures for many identifiers leave none held once they are done",
			act: func(t *testing.T, ctx context.Context, p *lockout.Policy) {
				var wg sync.WaitGroup
				for i := range 50 {
					wg.Go(func() {
						assert.NoError(t, p.Attempts().RecordFailure(ctx, fmt.Sprintf("user-%d", i), lockoutNow))
					})
				}
				wg.Wait()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			under, err := lockout.NewMemoryAttemptStore()
			require.NoError(t, err)

			var store policy.AttemptStore = under
			if tc.store != nil {
				store = tc.store(t, under)
			}

			p := lockoutWith(t, lockout.WithAttemptStore(store),
				lockout.WithSecurityEvents(func(context.Context, security.Event) {}))

			tc.act(t, t.Context(), p)

			assert.Zero(t, p.IdentifiersLockedForTest(), "an identifier is held after its failures are done")
		})
	}
}

// longRetentionStore is an in-memory store that keeps failures for 48 hours,
// longer than the 15-minute windows these tests lock on, as a store shared with
// a policy of a longer window does. The policy that made it keep that long is
// dropped: only the store's retention matters.
func longRetentionStore(t *testing.T) *lockout.MemoryAttemptStore {
	t.Helper()

	store, err := lockout.NewMemoryAttemptStore()
	require.NoError(t, err)
	lockoutWith(t, lockout.WithAttemptStore(store), lockout.WithFailureWindow(48*time.Hour))

	return store
}

// TestAttempts_CountsZeroInstantFailuresAtThePolicyClock pins that a failure
// recorded through the policy's view with a zero instant counts as a failure
// now, whether or not the policy keeps a failure streak, an observer or a
// sink: Evaluate treats a zero instant as the policy clock, so three such
// failures must lock a sliding lock of three.
func TestAttempts_CountsZeroInstantFailuresAtThePolicyClock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts func(l *eventLog) []lockout.Option
	}{
		{
			name: "NoStreakStoreNoObserverNoSink",
			opts: func(*eventLog) []lockout.Option { return nil },
		},
		{
			name: "NoStreakStoreWithObserver",
			opts: func(*eventLog) []lockout.Option {
				return []lockout.Option{lockout.WithObserver(func(context.Context, lockout.Report) {})}
			},
		},
		{
			name: "NoStreakStoreWithSink",
			opts: func(l *eventLog) []lockout.Option {
				return []lockout.Option{lockout.WithSecurityEvents(l.sink)}
			},
		},
		{
			name: "WithStreakStore",
			opts: func(*eventLog) []lockout.Option {
				return []lockout.Option{lockout.WithFailureStreakLimit(10)}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := lockoutWith(t, append([]lockout.Option{lockout.WithSliding(3, 15*time.Minute)}, tt.opts(&eventLog{})...)...)
			for range 3 {
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Time{}))
			}

			d := p.Evaluate(t.Context(), &policy.Input{Username: "ada"})
			assert.Equal(t, policy.Deny, d.Outcome,
				"three failures recorded with a zero instant left the identifier unlocked: they were stored at year 1, outside the window")
		})
	}
}

// TestAttempts_ReportsLockOnceOnTheZeroInstantFailureThatLocks pins that, with
// failures inside the store's retention but outside the lock's window, the lock
// events are reported once, by the failure that brings the window to the
// threshold, and carry the policy clock's instant, when the failures that lock
// are recorded with a zero instant.
func TestAttempts_ReportsLockOnceOnTheZeroInstantFailureThatLocks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		assert func(t *testing.T, afterEach [][]string, all []string)
	}{
		{
			name: "OneLockEventPairOnTheThirdFailure",
			assert: func(t *testing.T, afterEach [][]string, all []string) {
				t.Helper()

				assert.Empty(t, afterEach[0], "failure 1 reported a lock with one failure in the window, below the threshold of 3")
				assert.Empty(t, afterEach[1], "failure 2 reported a lock with two failures in the window, below the threshold of 3")
				assert.Equal(t, []string{"authn_login_fail_max", "authn_login_lock"}, afterEach[2],
					"the failure that brought the window to 3 did not report the lock")
				assert.Len(t, all, 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := longRetentionStore(t)
			// Three failures two hours ago: inside the 48-hour retention, outside
			// the 15-minute window, so none is a failure the lock counts.
			failuresAt(t, store, "ada",
				lockoutNow.Add(-2*time.Hour), lockoutNow.Add(-2*time.Hour+time.Second), lockoutNow.Add(-2*time.Hour+2*time.Second))

			events := &eventLog{}
			p := lockoutWith(t,
				lockout.WithAttemptStore(store),
				lockout.WithSliding(3, 15*time.Minute),
				lockout.WithSecurityEvents(events.sink),
			)

			var afterEach [][]string
			seen := 0
			for range 3 {
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Time{}))

				var names []string
				for _, e := range events.all()[seen:] {
					names = append(names, e.Name)
					assert.Equal(t, lockoutNow, e.At, "the lock event did not carry the policy clock's instant")
				}
				seen = len(events.all())
				afterEach = append(afterEach, names)
			}

			var all []string
			for _, e := range events.all() {
				all = append(all, e.Name)
			}
			tt.assert(t, afterEach, all)
		})
	}
}

// TestAttempts_ReportsLockedToTheObserverOnlyWhenTheWindowReachesTheThreshold
// pins the same sequence for the observer: a failure recorded with a zero
// instant is reported as locking only when the window holds the threshold's
// worth of failures, counted from the policy clock.
func TestAttempts_ReportsLockedToTheObserverOnlyWhenTheWindowReachesTheThreshold(t *testing.T) {
	t.Parallel()

	store := longRetentionStore(t)
	failuresAt(t, store, "ada",
		lockoutNow.Add(-2*time.Hour), lockoutNow.Add(-2*time.Hour+time.Second), lockoutNow.Add(-2*time.Hour+2*time.Second))

	var reports []lockout.Report
	p := lockoutWith(t,
		lockout.WithAttemptStore(store),
		lockout.WithSliding(3, 15*time.Minute),
		lockout.WithObserver(func(_ context.Context, r lockout.Report) { reports = append(reports, r) }),
	)

	for i := range 2 {
		require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Time{}))
		assert.Empty(t, reports, "failure %d reported a lock with %d failure(s) in the window, below the threshold of 3", i+1, i+1)
	}
	require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Time{}))

	require.Len(t, reports, 1)
	assert.Equal(t, lockout.ReportLocked, reports[0].Kind)
	assert.Equal(t, 3, reports[0].Failures, "the report counted failures outside the window")
	assert.Equal(t, lockoutNow, reports[0].At)
}

// TestAttempts_KeepsAGivenFailureInstant pins that a failure recorded with an
// instant is counted at that instant, not at the policy clock.
func TestAttempts_KeepsAGivenFailureInstant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		opts   []lockout.Option
		assert func(t *testing.T, store *lockout.MemoryAttemptStore)
	}{
		{
			name: "NoStreakStore",
			assert: func(t *testing.T, store *lockout.MemoryAttemptStore) {
				t.Helper()

				n, err := store.FailureCount(t.Context(), "ada", lockoutNow.Add(-5*time.Minute))
				require.NoError(t, err)
				assert.Zero(t, n, "a failure given at now-10m was counted at the policy clock")
				n, err = store.FailureCount(t.Context(), "ada", lockoutNow.Add(-15*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, n)
			},
		},
		{
			name: "WithStreakStore",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(10)},
			assert: func(t *testing.T, store *lockout.MemoryAttemptStore) {
				t.Helper()

				n, err := store.FailureCount(t.Context(), "ada", lockoutNow.Add(-5*time.Minute))
				require.NoError(t, err)
				assert.Zero(t, n, "a failure given at now-10m was counted at the policy clock")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := longRetentionStore(t)
			p := lockoutWith(t, append([]lockout.Option{
				lockout.WithAttemptStore(store), lockout.WithSliding(3, 15*time.Minute),
			}, tt.opts...)...)

			require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow.Add(-10*time.Minute)))
			tt.assert(t, store)
		})
	}
}
