package lockout_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

func TestNewAccountLockoutPolicy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		assert func(t *testing.T, p *lockout.Policy, err error)
	}

	var absentStore *lockout.MemoryAttemptStore

	// consumerClockAt is what a consumer's own read-only clock reports, for
	// the "consumer clock" row below. consumerClockStore is its own store, so
	// the row can read back the instant RecordFailure stamped through it.
	consumerClockAt := time.Date(2032, time.April, 4, 4, 4, 4, 0, time.UTC)
	consumerClockStore := lockout.NewMemoryAttemptStore()

	refused := func(t *testing.T, p *lockout.Policy, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig)
		assert.Nil(t, p, "a refused configuration handed back a policy anyway")
	}

	// refusedNaming is a refusal whose error contains fragment, which names the
	// option at fault so a consumer reading it knows which line of wiring to
	// change. A cap fragment carries the words after the name, so that an error
	// naming WithCapRetention does not satisfy it.
	refusedNaming := func(fragment string) func(t *testing.T, p *lockout.Policy, err error) {
		return func(t *testing.T, p *lockout.Policy, err error) {
			t.Helper()

			refused(t, p, err)
			assert.ErrorContains(t, err, fragment)
		}
	}

	// streaklessStore is an attempt store that keeps no consecutive failures:
	// it implements policy.AttemptStore and nothing else. No call is expected on it,
	// since a cap over it must be refused before any traffic.
	streaklessStore := NewMockAttemptStore(gomock.NewController(t))

	cases := []testCase{
		{
			name: "no cap by default",
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Zero(t, p.Cap(), "a policy with default options holds identifiers")
			},
		},
		{
			name: "a cap takes the default retention of thirty days",
			opts: []lockout.Option{lockout.WithCap(lockout.NISTCap)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 100, p.Cap())
				assert.Equal(t, 30*24*time.Hour, p.CapRetention())
			},
		},
		{
			name: "a consumer retention replaces the default",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithCapRetention(7 * 24 * time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 7*24*time.Hour, p.CapRetention())
			},
		},
		{
			name: "a retention given before the cap is accepted",
			opts: []lockout.Option{
				lockout.WithCapRetention(7 * 24 * time.Hour),
				lockout.WithCap(lockout.NISTCap),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 7*24*time.Hour, p.CapRetention())
			},
		},
		{
			name: "a retention shorter than the window is refused whatever the option order",
			opts: []lockout.Option{
				lockout.WithCapRetention(time.Hour),
				lockout.WithCap(lockout.NISTCap),
			},
			assert: refusedNaming("WithLockoutCapRetention"),
		},
		{
			name: "a store that keeps streaks given after the cap is accepted",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithAttemptStore(lockout.NewMemoryAttemptStore()),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 100, p.Cap())
			},
		},
		{
			name: "a store that keeps no streaks given after the cap is refused",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithAttemptStore(streaklessStore),
			},
			assert: refusedNaming("WithLockoutCap needs"),
		},
		{
			// NIST's 100 is an upper bound; a higher cap is the consumer's
			// documented departure, not a wiring mistake.
			name: "a cap above NIST's limit is accepted",
			opts: []lockout.Option{lockout.WithCap(150)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 150, p.Cap())
			},
		},
		{
			name: "a consumer cap just above a consumer threshold is accepted",
			opts: []lockout.Option{
				lockout.WithThreshold(3),
				lockout.WithCap(4),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 4, p.Cap())
			},
		},
		{
			// Spec: "Store without consecutive counts".
			name: "a cap with a store that keeps no streaks is refused",
			opts: []lockout.Option{
				lockout.WithAttemptStore(streaklessStore),
				lockout.WithCap(lockout.NISTCap),
			},
			assert: refusedNaming("WithLockoutCap needs"),
		},
		{
			// Spec: "Cap at the threshold": the first lock would already be a
			// hold.
			name:   "a cap at the threshold is refused",
			opts:   []lockout.Option{lockout.WithCap(5)},
			assert: refusedNaming("WithLockoutCap must be above"),
		},
		{
			name: "a cap below a consumer threshold is refused",
			opts: []lockout.Option{
				lockout.WithThreshold(10),
				lockout.WithCap(8),
			},
			assert: refusedNaming("WithLockoutCap must be above"),
		},
		{
			name:   "a cap of zero is refused",
			opts:   []lockout.Option{lockout.WithCap(0)},
			assert: refusedNaming("WithLockoutCap must be positive"),
		},
		{
			name:   "a negative cap is refused",
			opts:   []lockout.Option{lockout.WithCap(-1)},
			assert: refusedNaming("WithLockoutCap must be positive"),
		},
		{
			// Spec: "Retention without a cap".
			name:   "a retention without a cap is refused",
			opts:   []lockout.Option{lockout.WithCapRetention(30 * 24 * time.Hour)},
			assert: refusedNaming("WithLockoutCapRetention"),
		},
		{
			name: "a retention of zero is refused",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithCapRetention(0),
			},
			assert: refusedNaming("WithLockoutCapRetention"),
		},
		{
			name: "a negative retention is refused",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithCapRetention(-time.Hour),
			},
			assert: refusedNaming("WithLockoutCapRetention"),
		},
		{
			// A count would expire while the window still counts its failures.
			name: "a retention shorter than the window is refused",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithCapRetention(time.Hour),
			},
			assert: refusedNaming("WithLockoutCapRetention"),
		},
		{
			name: "a retention equal to the window is accepted",
			opts: []lockout.Option{
				lockout.WithCap(lockout.NISTCap),
				lockout.WithCapRetention(24 * time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 24*time.Hour, p.CapRetention())
			},
		},
		{
			name:   "a nil lockout observer is refused",
			opts:   []lockout.Option{lockout.WithObserver(nil)},
			assert: refused,
		},
		{
			name: "a nil lockout logger is ignored",
			opts: []lockout.Option{lockout.WithLogger(nil)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "no options construct the documented defaults",
			assert: func(t *testing.T, p *lockout.Policy, err error) {
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
			opts:   []lockout.Option{lockout.WithWait(0, time.Hour)},
			assert: refused,
		},
		{
			name:   "a negative first wait is refused",
			opts:   []lockout.Option{lockout.WithWait(-time.Second, time.Hour)},
			assert: refused,
		},
		{
			name:   "a longest wait shorter than the first is refused",
			opts:   []lockout.Option{lockout.WithWait(time.Minute, time.Second)},
			assert: refused,
		},
		{
			name: "a longest wait equal to the first is a flat wait, and allowed",
			opts: []lockout.Option{lockout.WithWait(time.Minute, time.Minute)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			// The ceiling is where waiting stops lifting the lock, so it must
			// leave at least one escalated wait between it and the threshold.
			name:   "a ceiling equal to the default threshold is refused",
			opts:   []lockout.Option{lockout.WithCeiling(5)},
			assert: refused,
		},
		{
			name: "a ceiling below a consumer threshold is refused",
			opts: []lockout.Option{
				lockout.WithThreshold(10),
				lockout.WithCeiling(8),
			},
			assert: refused,
		},
		{
			name:   "a consumer threshold at the default ceiling is refused",
			opts:   []lockout.Option{lockout.WithThreshold(100)},
			assert: refused,
		},
		{
			// NIST caps consecutive failures at 100; a higher ceiling is the
			// consumer's documented departure, not a wiring mistake.
			name: "a ceiling above one hundred is allowed",
			opts: []lockout.Option{lockout.WithCeiling(150)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			name: "a sliding lock keeps its own threshold and window",
			opts: []lockout.Option{lockout.WithSliding(3, 15*time.Minute)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
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
			opts: []lockout.Option{lockout.WithSliding(200, 24*time.Hour)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			name:   "a sliding lock with a zero window is refused",
			opts:   []lockout.Option{lockout.WithSliding(5, 0)},
			assert: refused,
		},
		{
			name:   "a sliding lock with a zero threshold is refused",
			opts:   []lockout.Option{lockout.WithSliding(0, 15*time.Minute)},
			assert: refused,
		},
		{
			name: "a sliding lock with a wait option is refused",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithWait(time.Second, time.Minute),
			},
			assert: refused,
		},
		{
			name: "a conflicting option names the sliding lock it conflicts with",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithWait(time.Minute, time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				refused(t, p, err)
				assert.ErrorContains(t, err, "WithSlidingLockout")
				assert.NotContains(t, err.Error(), "WithFixedLockout")
			},
		},
		{
			name: "a sliding lock with a ceiling option is refused",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithCeiling(50),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				refused(t, p, err)
				assert.Contains(t, err.Error(), "WithLockoutCeiling")
				assert.NotContains(t, err.Error(), "WithLockoutWait", "the error named an option that was not combined")
				assert.NotContains(t, err.Error(), "WithLockoutThreshold", "the error named an option that was not combined")
				assert.NotContains(t, err.Error(), "WithLockoutWindow", "the error named an option that was not combined")
			},
		},
		{
			name: "a sliding lock with several conflicting options names each of them",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithThreshold(3),
				lockout.WithWait(time.Second, time.Minute),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
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
			opts: []lockout.Option{
				lockout.WithThreshold(3),
				lockout.WithSliding(5, 15*time.Minute),
			},
			assert: refused,
		},
		{
			name: "a window option after a sliding lock is refused",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithWindow(time.Hour),
			},
			assert: refused,
		},
		{
			name: "a consumer's own threshold and window are kept",
			opts: []lockout.Option{
				lockout.WithThreshold(3),
				lockout.WithWindow(time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 3, p.Threshold())
				assert.Equal(t, time.Hour, p.Window())
			},
		},
		{
			name: "a consumer's own store is used instead of the in-memory one",
			opts: []lockout.Option{lockout.WithAttemptStore(lockout.NewMemoryAttemptStore())},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			// A window of zero contains no failure at all, so lockout is
			// disabled while every call site still reads like a lockout.
			name:   "a zero window is refused rather than silently disabling lockout",
			opts:   []lockout.Option{lockout.WithWindow(0)},
			assert: refused,
		},
		{
			name:   "a negative window is refused",
			opts:   []lockout.Option{lockout.WithWindow(-time.Minute)},
			assert: refused,
		},
		{
			// Zero failures are at or above a threshold of zero, so every
			// account is locked, including one that has never failed.
			name:   "a zero threshold is refused rather than locking every account",
			opts:   []lockout.Option{lockout.WithThreshold(0)},
			assert: refused,
		},
		{
			name:   "a negative threshold is refused",
			opts:   []lockout.Option{lockout.WithThreshold(-1)},
			assert: refused,
		},
		{
			name:   "a nil attempt store is refused rather than quietly counting in memory",
			opts:   []lockout.Option{lockout.WithAttemptStore(nil)},
			assert: refused,
		},
		{
			// What an unchecked constructor result hands over: the interface is
			// not nil, so a plain nil comparison misses it and the first login
			// panics.
			name:   "an attempt store that is a typed nil is refused",
			opts:   []lockout.Option{lockout.WithAttemptStore(absentStore)},
			assert: refused,
		},
		{
			name:   "a nil clock is refused",
			opts:   []lockout.Option{lockout.WithClock(nil)},
			assert: refused,
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver,
			// so a nil one is an interface holding a nil pointer: `== nil`
			// misses it, and only the reflect-based check the constructor now
			// uses catches it before the first failure or purge reads from a
			// nil receiver.
			name:   "a typed-nil clock is refused",
			opts:   []lockout.Option{lockout.WithClock((*clockwork.FakeClock)(nil))},
			assert: refused,
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and RecordFailure
			// stamps the failure with the consumer's clock: the store counts
			// it as after an instant a nanosecond earlier and not as after
			// the instant itself, which pins the recorded time exactly.
			name: "a consumer's own read-only clock is the policy's time source",
			opts: []lockout.Option{
				lockout.WithAttemptStore(consumerClockStore),
				lockout.WithClock(fixedClock{at: consumerClockAt}),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
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
			opts: []lockout.Option{nil},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 5, p.Threshold())
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
