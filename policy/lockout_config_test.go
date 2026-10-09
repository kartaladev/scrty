package policy_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

func TestNewAccountLockoutPolicy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		assert func(t *testing.T, p *policy.AccountLockoutPolicy, err error)
	}

	var absentStore *policy.MemoryAttemptStore

	// consumerClockAt is what a consumer's own read-only clock reports, for
	// the "consumer clock" row below. consumerClockStore is its own store, so
	// the row can read back the instant RecordFailure stamped through it.
	consumerClockAt := time.Date(2032, time.April, 4, 4, 4, 4, 0, time.UTC)
	consumerClockStore := policy.NewMemoryAttemptStore()

	refused := func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig)
		assert.Nil(t, p, "a refused configuration handed back a policy anyway")
	}

	cases := []testCase{
		{
			name:   "a nil lockout observer is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutObserver(nil)},
			assert: refused,
		},
		{
			name: "a nil lockout logger is ignored",
			opts: []policy.LockoutOption{policy.WithLockoutLogger(nil)},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "no options construct the documented defaults",
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 5, p.Threshold())
				assert.Equal(t, 24*time.Hour, p.Window())
			},
		},
		{
			// A first wait of zero is no wait at all, so the escalation would
			// never start and every account would get unlimited guesses.
			name:   "a zero first wait is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(0, time.Hour)},
			assert: refused,
		},
		{
			name:   "a negative first wait is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(-time.Second, time.Hour)},
			assert: refused,
		},
		{
			name:   "a longest wait shorter than the first is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutWait(time.Minute, time.Second)},
			assert: refused,
		},
		{
			name: "a longest wait equal to the first is a flat wait, and allowed",
			opts: []policy.LockoutOption{policy.WithLockoutWait(time.Minute, time.Minute)},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			// The ceiling is where waiting stops lifting the lock, so it must
			// leave at least one escalated wait between it and the threshold.
			name:   "a ceiling equal to the default threshold is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutCeiling(5)},
			assert: refused,
		},
		{
			name: "a ceiling below a consumer threshold is refused",
			opts: []policy.LockoutOption{
				policy.WithLockoutThreshold(10),
				policy.WithLockoutCeiling(8),
			},
			assert: refused,
		},
		{
			name:   "a consumer threshold at the default ceiling is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutThreshold(100)},
			assert: refused,
		},
		{
			// NIST caps consecutive failures at 100; a higher ceiling is the
			// consumer's documented departure, not a wiring mistake.
			name: "a ceiling above one hundred is allowed",
			opts: []policy.LockoutOption{policy.WithLockoutCeiling(150)},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			name: "a sliding lock keeps its own threshold and window",
			opts: []policy.LockoutOption{policy.WithSlidingLockout(3, 15*time.Minute)},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 3, p.Threshold())
				assert.Equal(t, 15*time.Minute, p.Window(), "Window did not report the sliding lock's window")
			},
		},
		{
			// A sliding lock has no ceiling, so a threshold at or above the
			// escalating default's ceiling is still a sliding lock.
			name: "a sliding lock above the escalating ceiling is allowed",
			opts: []policy.LockoutOption{policy.WithSlidingLockout(200, 24*time.Hour)},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			name:   "a sliding lock with a zero window is refused",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(5, 0)},
			assert: refused,
		},
		{
			name:   "a sliding lock with a zero threshold is refused",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(0, 15*time.Minute)},
			assert: refused,
		},
		{
			name: "a sliding lock with a wait option is refused",
			opts: []policy.LockoutOption{
				policy.WithSlidingLockout(5, 15*time.Minute),
				policy.WithLockoutWait(time.Second, time.Minute),
			},
			assert: refused,
		},
		{
			name: "a conflicting option names the sliding lock it conflicts with",
			opts: []policy.LockoutOption{
				policy.WithSlidingLockout(5, 15*time.Minute),
				policy.WithLockoutWait(time.Minute, time.Hour),
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				refused(t, p, err)
				assert.ErrorContains(t, err, "WithSlidingLockout")
				assert.NotContains(t, err.Error(), "WithFixedLockout")
			},
		},
		{
			name: "a sliding lock with a ceiling option is refused",
			opts: []policy.LockoutOption{
				policy.WithSlidingLockout(5, 15*time.Minute),
				policy.WithLockoutCeiling(50),
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				refused(t, p, err)
				assert.Contains(t, err.Error(), "WithLockoutCeiling")
				assert.NotContains(t, err.Error(), "WithLockoutWait", "the error named an option that was not combined")
				assert.NotContains(t, err.Error(), "WithLockoutThreshold", "the error named an option that was not combined")
				assert.NotContains(t, err.Error(), "WithLockoutWindow", "the error named an option that was not combined")
			},
		},
		{
			name: "a sliding lock with several conflicting options names each of them",
			opts: []policy.LockoutOption{
				policy.WithSlidingLockout(5, 15*time.Minute),
				policy.WithLockoutThreshold(3),
				policy.WithLockoutWait(time.Second, time.Minute),
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				refused(t, p, err)
				assert.Contains(t, err.Error(), "WithLockoutThreshold")
				assert.Contains(t, err.Error(), "WithLockoutWait")
				assert.NotContains(t, err.Error(), "WithLockoutCeiling")
			},
		},
		{
			// The order of the options must not matter: a threshold set
			// before the sliding lock would otherwise be silently overwritten.
			name: "a threshold option before a sliding lock is refused",
			opts: []policy.LockoutOption{
				policy.WithLockoutThreshold(3),
				policy.WithSlidingLockout(5, 15*time.Minute),
			},
			assert: refused,
		},
		{
			name: "a window option after a sliding lock is refused",
			opts: []policy.LockoutOption{
				policy.WithSlidingLockout(5, 15*time.Minute),
				policy.WithLockoutWindow(time.Hour),
			},
			assert: refused,
		},
		{
			name: "a consumer's own threshold and window are kept",
			opts: []policy.LockoutOption{
				policy.WithLockoutThreshold(3),
				policy.WithLockoutWindow(time.Hour),
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 3, p.Threshold())
				assert.Equal(t, time.Hour, p.Window())
			},
		},
		{
			name: "a consumer's own store is used instead of the in-memory one",
			opts: []policy.LockoutOption{policy.WithAttemptStore(policy.NewMemoryAttemptStore())},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			// A window of zero contains no failure at all, so lockout is
			// disabled while every call site still reads like a lockout.
			name:   "a zero window is refused rather than silently disabling lockout",
			opts:   []policy.LockoutOption{policy.WithLockoutWindow(0)},
			assert: refused,
		},
		{
			name:   "a negative window is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutWindow(-time.Minute)},
			assert: refused,
		},
		{
			// Zero failures are at or above a threshold of zero, so every
			// account is locked, including one that has never failed.
			name:   "a zero threshold is refused rather than locking every account",
			opts:   []policy.LockoutOption{policy.WithLockoutThreshold(0)},
			assert: refused,
		},
		{
			name:   "a negative threshold is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutThreshold(-1)},
			assert: refused,
		},
		{
			name:   "a nil attempt store is refused rather than quietly counting in memory",
			opts:   []policy.LockoutOption{policy.WithAttemptStore(nil)},
			assert: refused,
		},
		{
			// What an unchecked constructor result hands over: the interface is
			// not nil, so a plain nil comparison misses it and the first login
			// panics.
			name:   "an attempt store that is a typed nil is refused",
			opts:   []policy.LockoutOption{policy.WithAttemptStore(absentStore)},
			assert: refused,
		},
		{
			name:   "a nil clock is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutClock(nil)},
			assert: refused,
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first failure or purge reads from a
			// nil receiver.
			name:   "a typed-nil clock is refused",
			opts:   []policy.LockoutOption{policy.WithLockoutClock((*clockwork.FakeClock)(nil))},
			assert: refused,
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and RecordFailure
			// stamps the failure with the consumer's clock: the store counts
			// it as after an instant a nanosecond earlier and not as after
			// the instant itself, which pins the recorded time exactly.
			name: "a consumer's own read-only clock is the policy's time source",
			opts: []policy.LockoutOption{
				policy.WithAttemptStore(consumerClockStore),
				policy.WithLockoutClock(fixedClock{at: consumerClockAt}),
			},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, p)

				require.NoError(t, p.RecordFailure(t.Context(), "consumer-clock-user"))

				notAfter, countErr := consumerClockStore.FailureCount(
					t.Context(), "consumer-clock-user", consumerClockAt)
				require.NoError(t, countErr)
				assert.Zero(t, notAfter,
					"the failure was recorded at an instant after the consumer clock's own time")

				after, countErr := consumerClockStore.FailureCount(
					t.Context(), "consumer-clock-user", consumerClockAt.Add(-time.Nanosecond))
				require.NoError(t, countErr)
				assert.Equal(t, 1, after,
					"the failure was not stamped with the consumer clock's time")
			},
		},
		{
			name: "a nil option is ignored",
			opts: []policy.LockoutOption{nil},
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 5, p.Threshold())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.NewAccountLockoutPolicy(tc.opts...)
			tc.assert(t, p, err)
		})
	}
}
