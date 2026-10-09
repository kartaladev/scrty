package policy_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
)

// errAttemptStoreDown is what a store that cannot answer reports, so a test can
// follow the cause through the decision it produced.
var errAttemptStoreDown = errors.New("the attempt store is unreachable")

// lockoutWith builds a policy over a fresh in-memory store and the tests'
// fixed clock, with opts applied after both, so a case can replace either.
func lockoutWith(t *testing.T, opts ...policy.LockoutOption) *policy.AccountLockoutPolicy {
	t.Helper()

	all := append([]policy.LockoutOption{policy.WithLockoutClock(clockwork.NewFakeClockAt(lockoutNow))}, opts...)
	p, err := policy.NewAccountLockoutPolicy(all...)
	require.NoError(t, err)

	return p
}

// lockoutInput is a pre-authentication input naming username and nothing else:
// before credentials are checked, the submitted identifier is all there is.
func lockoutInput(username string) *policy.Input {
	return &policy.Input{Username: username}
}

// recordFailures records n failures for username through the policy, which is
// how a consumer's login flow reports them.
func recordFailures(t *testing.T, p *policy.AccountLockoutPolicy, username string, n int) {
	t.Helper()

	for range n {
		require.NoError(t, p.RecordFailure(t.Context(), username))
	}
}

// lockoutDefaultCutoff is the cutoff the default 24-hour window puts behind
// lockoutNow.
var lockoutDefaultCutoff = lockoutNow.Add(-24 * time.Hour)

// failuresEndingAt records n failures for username, the newest exactly newest
// before lockoutNow and each earlier one a second before the next, so a case
// pins both the count and the age of the newest failure.
func failuresEndingAt(username string, n int, newest time.Duration) func(*testing.T, *policy.MemoryAttemptStore) {
	return func(t *testing.T, store *policy.MemoryAttemptStore) {
		t.Helper()

		for i := range n {
			failuresAt(t, store, username, lockoutNow.Add(-newest-time.Duration(i)*time.Second))
		}
	}
}

// failuresAt records one failure per instant directly in the store, for the
// cases that pin a failure to the edge of the window.
func failuresAt(t *testing.T, store *policy.MemoryAttemptStore, username string, at ...time.Time) {
	t.Helper()

	for _, instant := range at {
		require.NoError(t, store.RecordFailure(t.Context(), username, instant))
	}
}

func TestAccountLockoutPolicyDefaults(t *testing.T) {
	t.Parallel()

	p, err := policy.NewAccountLockoutPolicy()
	require.NoError(t, err)

	assert.Equal(t, 5, p.Threshold(), "the default threshold is not five")
	assert.Equal(t, 24*time.Hour, p.Window(), "the default window is not twenty-four hours")
	assert.Equal(t, []policy.Phase{policy.PreAuthentication}, p.Phases(),
		"the lockout rule must apply whether or not the submitted secret is correct, which is the pre-authentication phase")
	assert.NotEmpty(t, p.Name())

	// No store was configured, so the default in-memory one is what these
	// failures land in and what the decision is made from.
	recordFailures(t, p, "ada", 5)
	d := p.Evaluate(t.Context(), lockoutInput("ada"))
	assert.Equal(t, policy.Deny, d.Outcome, "the default store did not count the failures recorded through it")
	assert.ErrorIs(t, d.Reason, policy.ErrAccountLocked)
}

func TestAccountLockoutPolicyEvaluates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		record func(t *testing.T, store *policy.MemoryAttemptStore)
		input  func() *policy.Input // nil means the pre-authentication input for "ada"
		assert func(t *testing.T, d policy.Decision)
	}

	allows := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Allow, d.Outcome)
		assert.NoError(t, d.Reason)
	}
	denies := func(t *testing.T, d policy.Decision) {
		t.Helper()

		assert.Equal(t, policy.Deny, d.Outcome)
		assert.ErrorIs(t, d.Reason, policy.ErrAccountLocked)
	}

	cases := []testCase{
		{
			name:   "an identifier with no failures is allowed",
			assert: allows,
		},
		{
			name:   "one failure short of the threshold is allowed",
			record: failuresEndingAt("ada", 4, time.Second),
			assert: allows,
		},
		{
			name:   "at the threshold the first wait is owed",
			record: failuresEndingAt("ada", 5, 10*time.Second),
			assert: denies,
		},
		{
			name:   "the first wait is still owed one second before it ends",
			record: failuresEndingAt("ada", 5, 29*time.Second),
			assert: denies,
		},
		{
			name:   "once the first wait is served the next attempt is allowed",
			record: failuresEndingAt("ada", 5, 31*time.Second),
			assert: allows,
		},
		{
			// FailureCount counts strictly after its cutoff, so a newest
			// failure exactly as old as the wait has served it.
			name:   "a newest failure exactly as old as the wait is allowed",
			record: failuresEndingAt("ada", 5, 30*time.Second),
			assert: allows,
		},
		{
			name:   "a newest failure one nanosecond inside the wait is denied",
			record: failuresEndingAt("ada", 5, 30*time.Second-time.Nanosecond),
			assert: denies,
		},
		{
			// Seven failures are two beyond the threshold: 30s doubled twice.
			name:   "the wait doubles for each failure beyond the threshold",
			record: failuresEndingAt("ada", 7, 100*time.Second),
			assert: denies,
		},
		{
			name:   "a doubled wait once served is allowed",
			record: failuresEndingAt("ada", 7, 121*time.Second),
			assert: allows,
		},
		{
			name:   "the wait never exceeds the longest wait",
			record: failuresEndingAt("ada", 20, 61*time.Minute),
			assert: allows,
		},
		{
			name:   "the longest wait is owed until it ends",
			record: failuresEndingAt("ada", 20, 59*time.Minute),
			assert: denies,
		},
		{
			// 30s doubled 65 times overflows time.Duration; the wait must cap
			// at the longest wait rather than wrap to a short or negative one.
			name:   "a huge exponent caps at the longest wait rather than overflowing",
			record: failuresEndingAt("ada", 70, 59*time.Minute),
			assert: denies,
		},
		{
			name:   "a huge exponent once the longest wait is served is allowed",
			record: failuresEndingAt("ada", 70, 61*time.Minute),
			assert: allows,
		},
		{
			name:   "at the ceiling the account is refused however old its newest failure",
			record: failuresEndingAt("ada", 100, 2*time.Hour),
			assert: denies,
		},
		{
			name:   "one failure short of the ceiling is still only a wait",
			record: failuresEndingAt("ada", 99, 2*time.Hour),
			assert: allows,
		},
		{
			name:   "a consumer ceiling refuses at its own count",
			opts:   []policy.LockoutOption{policy.WithLockoutCeiling(20)},
			record: failuresEndingAt("ada", 20, 2*time.Hour),
			assert: denies,
		},
		{
			name:   "a consumer's own first wait is owed",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(5*time.Minute, time.Hour)},
			record: failuresEndingAt("ada", 5, 4*time.Minute),
			assert: denies,
		},
		{
			name:   "a consumer's own longest wait caps the escalation",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(30*time.Second, 2*time.Minute)},
			record: failuresEndingAt("ada", 10, 3*time.Minute),
			assert: allows,
		},
		{
			name: "a failure exactly at the window edge does not count",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresEndingAt("ada", 4, 10*time.Second)(t, store)
				failuresAt(t, store, "ada", lockoutDefaultCutoff)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome,
					"a failure exactly as old as the window was counted, which locks the account one instant longer than configured")
			},
		},
		{
			name: "a failure one nanosecond inside the window counts",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresEndingAt("ada", 4, 10*time.Second)(t, store)
				failuresAt(t, store, "ada", lockoutDefaultCutoff.Add(time.Nanosecond))
			},
			assert: denies,
		},
		{
			name: "failures older than the window have fallen out of it",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				for i := range 10 {
					failuresAt(t, store, "ada", lockoutNow.Add(-25*time.Hour-time.Duration(i)*time.Minute))
				}
			},
			assert: allows,
		},
		{
			name:   "a consumer threshold of three owes a wait at three failures",
			opts:   []policy.LockoutOption{policy.WithLockoutThreshold(3)},
			record: failuresEndingAt("ada", 3, 10*time.Second),
			assert: denies,
		},
		{
			name: "a consumer window of one hour drops a failure the default would still count",
			opts: []policy.LockoutOption{policy.WithLockoutWindow(time.Hour)},
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresEndingAt("ada", 4, 10*time.Second)(t, store)
				failuresAt(t, store, "ada", lockoutNow.Add(-2*time.Hour))
			},
			assert: allows,
		},
		{
			// A sliding lock owes no wait: it holds for as long as the window
			// counts the threshold, however old the newest failure.
			name:   "a sliding lock denies at its threshold however old the newest failure",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 10*time.Minute),
			assert: denies,
		},
		{
			name:   "a sliding lock lifts once the failures leave its window",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 16*time.Minute),
			assert: allows,
		},
		{
			// Failures spread across the window: only the oldest is outside it,
			// so four remain and the sliding lock has already lifted.
			name: "a sliding lock lifts as soon as its oldest failure leaves the window",
			opts: []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-15*time.Minute-time.Second),
					lockoutNow.Add(-14*time.Minute),
					lockoutNow.Add(-10*time.Minute),
					lockoutNow.Add(-5*time.Minute),
					lockoutNow.Add(-time.Minute))
			},
			assert: allows,
		},
		{
			name: "a sliding lock holds while its oldest failure is still inside the window",
			opts: []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-15*time.Minute+time.Second),
					lockoutNow.Add(-14*time.Minute),
					lockoutNow.Add(-10*time.Minute),
					lockoutNow.Add(-5*time.Minute),
					lockoutNow.Add(-time.Minute))
			},
			assert: denies,
		},
		{
			name:   "a sliding lock allows below its threshold",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 4, 10*time.Second),
			assert: allows,
		},
		{
			// The escalating default's ceiling of 100 has no meaning under a
			// sliding lock, whose own threshold is the only count that locks.
			name:   "a sliding lock ignores the escalating ceiling",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(200, 24*time.Hour)},
			record: failuresEndingAt("ada", 150, 2*time.Hour),
			assert: allows,
		},
		{
			name:   "another identifier's failures do not lock this one",
			record: failuresEndingAt("grace", 5, 10*time.Second),
			assert: allows,
		},
		{
			// By the policy's own clock the newest failure is 10 seconds old
			// and the wait is owed; by the phase's instant it is 70 seconds
			// old and served.
			name:   "the instant the phase is being evaluated at wins over the policy's own clock",
			record: failuresEndingAt("ada", 5, 10*time.Second),
			input: func() *policy.Input {
				return &policy.Input{Username: "ada", Now: lockoutNow.Add(time.Minute)}
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome,
					"the policy judged the wait against its own clock rather than the instant the phase carried")
			},
		},
		{
			name:  "a request the policy is told nothing about is refused rather than let through",
			input: func() *policy.Input { return nil },
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrPolicyDenied)
			},
		},
		{
			// FailureCount counts strictly after its cutoff, so the lock is lifted
			// at the instant the fifteen minutes have passed.
			name:   "a flat fifteen-minute wait is served exactly at its end",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(15*time.Minute, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 15*time.Minute),
			assert: allows,
		},
		{
			name:   "six failures under a flat wait are allowed once it ends",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(15*time.Minute, 15*time.Minute)},
			record: failuresEndingAt("ada", 6, 15*time.Minute),
			assert: allows,
		},
		{
			// 24 failures a day is what the default waits let a patient guesser
			// make. Five days of it is 120 failures, but the ceiling counts only
			// the window, so it never refuses.
			name: "failures outside the window do not count toward the ceiling",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				for day := range 5 {
					for i := range 24 {
						failuresAt(t, store, "ada", lockoutNow.Add(
							-2*time.Hour-time.Duration(day)*24*time.Hour-time.Duration(i)*time.Minute))
					}
				}
			},
			assert: allows,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := policy.NewMemoryAttemptStore()
			if tc.record != nil {
				tc.record(t, store)
			}

			p := lockoutWith(t, append([]policy.LockoutOption{policy.WithAttemptStore(store)}, tc.opts...)...)

			in := lockoutInput("ada")
			if tc.input != nil {
				in = tc.input()
			}

			tc.assert(t, p.Evaluate(t.Context(), in))
		})
	}
}

func TestAccountLockoutPolicyResetsOnSuccess(t *testing.T) {
	t.Parallel()

	p := lockoutWith(t)

	recordFailures(t, p, "ada", 4)
	require.NoError(t, p.Reset(t.Context(), "ada"), "a successful authentication could not clear the failures before it")
	recordFailures(t, p, "ada", 1)

	d := p.Evaluate(t.Context(), lockoutInput("ada"))
	assert.Equal(t, policy.Allow, d.Outcome,
		"the failures before a successful authentication were still counted against the account")
}

func TestAccountLockoutPolicyRecordsAndResetsThroughTheStore(t *testing.T) {
	t.Parallel()

	t.Run("a failure is recorded at the policy's own instant", func(t *testing.T) {
		t.Parallel()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)

		p := lockoutWith(t, policy.WithAttemptStore(store))
		require.NoError(t, p.RecordFailure(t.Context(), "ada"))
	})

	t.Run("a store that cannot record says so", func(t *testing.T) {
		t.Parallel()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(errAttemptStoreDown)

		p := lockoutWith(t, policy.WithAttemptStore(store))
		require.ErrorIs(t, p.RecordFailure(t.Context(), "ada"), errAttemptStoreDown,
			"a failure that was never recorded was reported as recorded, so the count never reaches the threshold")
	})

	t.Run("a store that cannot reset says so", func(t *testing.T) {
		t.Parallel()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

		p := lockoutWith(t, policy.WithAttemptStore(store))
		require.ErrorIs(t, p.Reset(t.Context(), "ada"), errAttemptStoreDown)
	})
}

func TestAccountLockoutPolicyRunsInPreAuthenticationOnly(t *testing.T) {
	t.Parallel()

	p := lockoutWith(t)
	recordFailures(t, p, "ada", 5)

	engine, err := policy.NewEngine(p)
	require.NoError(t, err)

	locked := engine.EvaluatePhase(t.Context(), policy.PreAuthentication, lockoutInput("ada"))
	require.Equal(t, policy.Deny, locked.Outcome)
	assert.ErrorIs(t, locked.Reason, policy.ErrAccountLocked)

	for _, phase := range []policy.Phase{
		policy.PostAuthentication,
		policy.PerRequest,
		policy.PostHandler,
		policy.StatelessAuthentication,
	} {
		d := engine.EvaluatePhase(t.Context(), phase, lockoutInput("ada"))
		assert.Equal(t, policy.Allow, d.Outcome, "the lockout policy ran in %s, which it did not declare", phase)
	}
}

func TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means t.Context() unchanged
		expect func(store *MockAttemptStore)
		assert func(t *testing.T, d policy.Decision)
	}

	cases := []testCase{
		{
			name: "a store that cannot count refuses the request rather than letting it through",
			expect: func(store *MockAttemptStore) {
				store.EXPECT().
					FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).
					Return(0, errAttemptStoreDown)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome,
					"a broken attempt store let the request through, so breaking the store disables lockout")
				assert.ErrorIs(t, d.Reason, errAttemptStoreDown, "the cause was collapsed")
				assert.NotErrorIs(t, d.Reason, policy.ErrAccountLocked,
					"an outage was reported to the caller as a locked account")
			},
		},
		{
			name: "a count the store could not stand behind is not counted as below the threshold",
			expect: func(store *MockAttemptStore) {
				store.EXPECT().
					FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).
					Return(0, errAttemptStoreDown)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
			},
		},
		{
			name: "a context that has already ended denies, carrying its own cause",
			ctx: func(ctx context.Context) context.Context {
				ended, cancel := context.WithCancel(ctx)
				cancel()

				return ended
			},
			expect: func(store *MockAttemptStore) {
				store.EXPECT().
					FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).
					DoAndReturn(func(ctx context.Context, _ string, _ time.Time) (int, error) {
						return 0, ctx.Err()
					})
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, context.Canceled)
			},
		},
		{
			// Below the threshold no wait can be owed, so the policy must not
			// spend a second query finding out: the strict mock fails the case
			// on any further call.
			name: "below the threshold the window is the only query",
			expect: func(store *MockAttemptStore) {
				store.EXPECT().
					FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).
					Return(4, nil)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name: "at the threshold the second query asks about the first wait exactly",
			expect: func(store *MockAttemptStore) {
				gomock.InOrder(
					store.EXPECT().FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).Return(5, nil),
					store.EXPECT().FailureCount(gomock.Any(), "ada", lockoutNow.Add(-30*time.Second)).Return(0, nil),
				)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			// The ceiling is reached on the window's count alone, so no wait is
			// asked about.
			name: "at the ceiling the window is the only query",
			expect: func(store *MockAttemptStore) {
				store.EXPECT().
					FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).
					Return(100, nil)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, policy.ErrAccountLocked)
			},
		},
		{
			// The window says a wait is owed; a store that then cannot say
			// whether it has been served must not be read as "served".
			name: "a store that cannot count the wait refuses rather than letting it through",
			expect: func(store *MockAttemptStore) {
				gomock.InOrder(
					store.EXPECT().FailureCount(gomock.Any(), "ada", lockoutDefaultCutoff).Return(7, nil),
					store.EXPECT().
						FailureCount(gomock.Any(), "ada", lockoutNow.Add(-120*time.Second)).
						Return(0, errAttemptStoreDown),
				)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome,
					"a store that failed on the wait query let the request through")
				assert.ErrorIs(t, d.Reason, errAttemptStoreDown, "the cause was collapsed")
				assert.ErrorIs(t, d.Reason, policy.ErrPolicyDenied)
				assert.NotErrorIs(t, d.Reason, policy.ErrAccountLocked,
					"an outage was reported to the caller as a locked account")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockAttemptStore(gomock.NewController(t))
			tc.expect(store)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			p := lockoutWith(t, policy.WithAttemptStore(store))
			tc.assert(t, p.Evaluate(ctx, lockoutInput("ada")))
		})
	}
}

// reapableAttemptStore is a store that can also purge, assembled from the
// in-memory store and the generated reaper mock so a test can drive the sweep
// without giving up a real store to count in.
type reapableAttemptStore struct {
	*policy.MemoryAttemptStore
	reaper *MockAttemptReaper
}

func newReapableAttemptStore(t *testing.T) *reapableAttemptStore {
	t.Helper()

	return &reapableAttemptStore{
		MemoryAttemptStore: policy.NewMemoryAttemptStore(),
		reaper:             NewMockAttemptReaper(gomock.NewController(t)),
	}
}

func (s *reapableAttemptStore) DeleteAttemptsBefore(ctx context.Context, retainSince time.Time) (int, error) {
	return s.reaper.DeleteAttemptsBefore(ctx, retainSince)
}

// sweepingAttemptStore implements the AttemptReaper contract as a consumer's
// own store would, because no store in this package does: MemoryAttemptStore
// deliberately cannot purge. It exists to exercise the contract end to end —
// what a sweep removes and what it leaves — not to stand in for a mock.
type sweepingAttemptStore struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newSweepingAttemptStore() *sweepingAttemptStore {
	return &sweepingAttemptStore{failures: make(map[string][]time.Time)}
}

func (s *sweepingAttemptStore) RecordFailure(_ context.Context, username string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failures[username] = append(s.failures[username], at)

	return nil
}

func (s *sweepingAttemptStore) Reset(_ context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.failures, username)

	return nil
}

func (s *sweepingAttemptStore) FailureCount(_ context.Context, username string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	for _, at := range s.failures[username] {
		if at.After(since) {
			count++
		}
	}

	return count, nil
}

func (s *sweepingAttemptStore) DeleteAttemptsBefore(_ context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, policy.ErrRetainSinceRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	for username, instants := range s.failures {
		kept := instants[:0]
		for _, at := range instants {
			if at.Before(retainSince) {
				removed++

				continue
			}
			kept = append(kept, at)
		}
		s.failures[username] = kept
	}

	return removed, nil
}

// held reports how many failures the store still holds for username, whatever
// their age, so a test can tell "not counted" from "deleted".
func (s *sweepingAttemptStore) held(username string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.failures[username])
}

func TestAccountLockoutPolicyPurgeExpired(t *testing.T) {
	t.Parallel()

	t.Run("the cutoff is the policy's own window and nothing else", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutDefaultCutoff).
			Return(3, nil)

		p := lockoutWith(t, policy.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 3, removed)
	})

	t.Run("a consumer's own window moves the cutoff with it", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutNow.Add(-time.Hour)).
			Return(0, nil)

		p := lockoutWith(t, policy.WithAttemptStore(store), policy.WithLockoutWindow(time.Hour))

		_, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
	})

	t.Run("a sliding lock's own window is the cutoff", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutCutoff).
			Return(0, nil)

		p := lockoutWith(t, policy.WithAttemptStore(store), policy.WithSlidingLockout(5, 15*time.Minute))

		_, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
	})

	t.Run("a purge does not free a failure the window still counts", func(t *testing.T) {
		t.Parallel()

		// A sliding lock of one failure per 15 minutes: the failure locks for as
		// long as the window counts it, so a purge that took it would unlock.
		store := newSweepingAttemptStore()
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-5*time.Minute)))

		p := lockoutWith(t, policy.WithAttemptStore(store), policy.WithSlidingLockout(1, 15*time.Minute))

		removed, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Zero(t, removed, "a sweep removed a failure that is still inside the window")

		d := p.Evaluate(t.Context(), lockoutInput("ada"))
		assert.Equal(t, policy.Deny, d.Outcome, "a purge freed a failure the window still counts")
	})

	t.Run("recent attempts survive a purge and stale ones do not", func(t *testing.T) {
		t.Parallel()

		store := newSweepingAttemptStore()
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-5*time.Minute)))
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-25*time.Hour)))

		p := lockoutWith(t, policy.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, removed, "the sweep did not remove exactly the failure that had aged out")
		assert.Equal(t, 1, store.held("ada"), "the sweep took a failure the 24-hour window still counts")
	})

	t.Run("the default in-memory store reports unsupported rather than a silent zero", func(t *testing.T) {
		t.Parallel()

		p := lockoutWith(t)

		removed, err := p.PurgeExpired(t.Context())
		require.ErrorIs(t, err, policy.ErrReapUnsupported,
			"a store that cannot purge reported a successful sweep that never happened")
		assert.Zero(t, removed)
	})

	t.Run("a reaper that refuses the zero cutoff deletes nothing", func(t *testing.T) {
		t.Parallel()

		store := newSweepingAttemptStore()
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-time.Hour)))

		removed, err := store.DeleteAttemptsBefore(t.Context(), time.Time{})
		require.ErrorIs(t, err, policy.ErrRetainSinceRequired)
		assert.Zero(t, removed)
		assert.Equal(t, 1, store.held("ada"), "a sweep with no cutoff deleted what it was asked to retain")
	})

	t.Run("a reaper that cannot answer is reported", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutDefaultCutoff).
			Return(0, errAttemptStoreDown)

		p := lockoutWith(t, policy.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.ErrorIs(t, err, errAttemptStoreDown)
		assert.Zero(t, removed)
	})
}
