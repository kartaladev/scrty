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
	assert.Equal(t, 15*time.Minute, p.Window(), "the default window is not fifteen minutes")
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
			name: "one failure short of the threshold is allowed",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-time.Minute),
					lockoutNow.Add(-2*time.Minute),
					lockoutNow.Add(-3*time.Minute),
					lockoutNow.Add(-4*time.Minute))
			},
			assert: allows,
		},
		{
			name: "at the threshold the account is locked",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-time.Minute),
					lockoutNow.Add(-2*time.Minute),
					lockoutNow.Add(-3*time.Minute),
					lockoutNow.Add(-4*time.Minute),
					lockoutNow.Add(-5*time.Minute))
			},
			assert: denies,
		},
		{
			name: "above the threshold the account is locked",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				for i := range 9 {
					failuresAt(t, store, "ada", lockoutNow.Add(-time.Duration(i+1)*time.Minute))
				}
			},
			assert: denies,
		},
		{
			name: "a failure exactly at the window edge does not count",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-time.Minute),
					lockoutNow.Add(-2*time.Minute),
					lockoutNow.Add(-3*time.Minute),
					lockoutNow.Add(-4*time.Minute),
					lockoutCutoff)
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome,
					"a failure exactly as old as the window was counted, which locks the account one instant longer than configured")
			},
		},
		{
			name: "a failure one nanosecond inside the window counts",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-time.Minute),
					lockoutNow.Add(-2*time.Minute),
					lockoutNow.Add(-3*time.Minute),
					lockoutNow.Add(-4*time.Minute),
					lockoutCutoff.Add(time.Nanosecond))
			},
			assert: denies,
		},
		{
			name: "failures older than the window have fallen out of it",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				for i := range 5 {
					failuresAt(t, store, "ada", lockoutNow.Add(-20*time.Minute-time.Duration(i)*time.Minute))
				}
			},
			assert: allows,
		},
		{
			name: "a consumer threshold of three locks at three failures",
			opts: []policy.LockoutOption{policy.WithLockoutThreshold(3)},
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada",
					lockoutNow.Add(-time.Minute),
					lockoutNow.Add(-2*time.Minute),
					lockoutNow.Add(-3*time.Minute))
			},
			assert: denies,
		},
		{
			name: "a consumer window of one hour still counts a failure the default would have dropped",
			opts: []policy.LockoutOption{policy.WithLockoutWindow(time.Hour), policy.WithLockoutThreshold(1)},
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				failuresAt(t, store, "ada", lockoutNow.Add(-45*time.Minute))
			},
			assert: denies,
		},
		{
			name: "another identifier's failures do not lock this one",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				for i := range 5 {
					failuresAt(t, store, "grace", lockoutNow.Add(-time.Duration(i+1)*time.Minute))
				}
			},
			assert: allows,
		},
		{
			name: "the instant the phase is being evaluated at wins over the policy's own clock",
			record: func(t *testing.T, store *policy.MemoryAttemptStore) {
				for i := range 5 {
					failuresAt(t, store, "ada", lockoutNow.Add(-time.Duration(i+1)*time.Minute))
				}
			},
			input: func() *policy.Input {
				return &policy.Input{Username: "ada", Now: lockoutNow.Add(30 * time.Minute)}
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome,
					"the policy judged the window against its own clock rather than the instant the phase carried")
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
					FailureCount(gomock.Any(), "ada", lockoutCutoff).
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
					FailureCount(gomock.Any(), "ada", lockoutCutoff).
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
					FailureCount(gomock.Any(), "ada", lockoutCutoff).
					DoAndReturn(func(ctx context.Context, _ string, _ time.Time) (int, error) {
						return 0, ctx.Err()
					})
			},
			assert: func(t *testing.T, d policy.Decision) {
				assert.Equal(t, policy.Deny, d.Outcome)
				assert.ErrorIs(t, d.Reason, context.Canceled)
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
			DeleteAttemptsBefore(gomock.Any(), lockoutCutoff).
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

	t.Run("a purge does not free a failure the window still counts", func(t *testing.T) {
		t.Parallel()

		store := newSweepingAttemptStore()
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-5*time.Minute)))

		p := lockoutWith(t, policy.WithAttemptStore(store), policy.WithLockoutThreshold(1))

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
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-20*time.Minute)))

		p := lockoutWith(t, policy.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, removed, "the sweep did not remove exactly the failure that had aged out")
		assert.Equal(t, 1, store.held("ada"), "the sweep took a failure the fifteen-minute window still counts")
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
			DeleteAttemptsBefore(gomock.Any(), lockoutCutoff).
			Return(0, errAttemptStoreDown)

		p := lockoutWith(t, policy.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.ErrorIs(t, err, errAttemptStoreDown)
		assert.Zero(t, removed)
	})
}
