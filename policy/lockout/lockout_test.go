package lockout_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// Policy hands out the view failures must be recorded through, so the engine's
// attempt-view check can read it.
var _ policy.AttemptViewRequirer = (*lockout.Policy)(nil)

// recordFailures records n failures for username through the policy, which is
// how a consumer's login flow reports them.
func recordFailures(t *testing.T, p *lockout.Policy, username string, n int) {
	t.Helper()

	for range n {
		require.NoError(t, p.RecordFailure(t.Context(), username))
	}
}

// lockoutDefaultCutoff is the cutoff the default 24-hour window puts behind
// lockoutNow.
var lockoutDefaultCutoff = lockoutNow.Add(-24 * time.Hour)

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
	consumerClockStore := must.Must(lockout.NewMemoryAttemptStore())

	refused := func(t *testing.T, p *lockout.Policy, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig)
		assert.Nil(t, p, "a refused configuration handed back a policy anyway")
	}

	// refusedNaming is a refusal whose error contains fragment, which names the
	// option at fault so a consumer reading it knows which line of wiring to
	// change. A cap fragment carries the words after the name, so that an error
	// naming WithFailureStreakRetention does not satisfy it.
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
				assert.Zero(t, p.FailureStreakLimit(), "a policy with default options holds identifiers")
			},
		},
		{
			name: "a cap takes the default retention of thirty days",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 100, p.FailureStreakLimit())
				assert.Equal(t, 30*24*time.Hour, p.FailureStreakRetention())
			},
		},
		{
			name: "a consumer retention replaces the default",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(7 * 24 * time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 7*24*time.Hour, p.FailureStreakRetention())
			},
		},
		{
			name: "a retention given before the cap is accepted",
			opts: []lockout.Option{
				lockout.WithFailureStreakRetention(7 * 24 * time.Hour),
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 7*24*time.Hour, p.FailureStreakRetention())
			},
		},
		{
			name: "a retention shorter than the window is refused whatever the option order",
			opts: []lockout.Option{
				lockout.WithFailureStreakRetention(time.Hour),
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
			},
			assert: refusedNaming("WithFailureStreakRetention"),
		},
		{
			name: "a store that keeps streaks given after the cap is accepted",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithAttemptStore(must.Must(lockout.NewMemoryAttemptStore())),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 100, p.FailureStreakLimit())
			},
		},
		{
			name: "a store that keeps no streaks given after the cap is refused",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithAttemptStore(streaklessStore),
			},
			assert: refusedNaming("WithFailureStreakLimit needs"),
		},
		{
			// NIST's 100 is an upper bound; a higher cap is the consumer's
			// documented departure, not a wiring mistake.
			name: "a cap above NIST's limit is accepted",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(150)},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 150, p.FailureStreakLimit())
			},
		},
		{
			name: "a consumer cap just above a consumer threshold is accepted",
			opts: []lockout.Option{
				lockout.WithWaitThreshold(3),
				lockout.WithFailureStreakLimit(4),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 4, p.FailureStreakLimit())
			},
		},
		{
			// Spec: "Store without consecutive counts".
			name: "a cap with a store that keeps no streaks is refused",
			opts: []lockout.Option{
				lockout.WithAttemptStore(streaklessStore),
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
			},
			assert: refusedNaming("WithFailureStreakLimit needs"),
		},
		{
			// Spec: "Cap at the threshold": the first lock would already be a
			// hold.
			name:   "a cap at the threshold is refused",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(5)},
			assert: refusedNaming("WithFailureStreakLimit must be above"),
		},
		{
			name: "a cap below a consumer threshold is refused",
			opts: []lockout.Option{
				lockout.WithWaitThreshold(10),
				lockout.WithFailureStreakLimit(8),
			},
			assert: refusedNaming("WithFailureStreakLimit must be above"),
		},
		{
			name:   "a cap of zero is refused",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(0)},
			assert: refusedNaming("WithFailureStreakLimit must be positive"),
		},
		{
			name:   "a negative cap is refused",
			opts:   []lockout.Option{lockout.WithFailureStreakLimit(-1)},
			assert: refusedNaming("WithFailureStreakLimit must be positive"),
		},
		{
			// Spec: "Retention without a cap".
			name:   "a retention without a cap is refused",
			opts:   []lockout.Option{lockout.WithFailureStreakRetention(30 * 24 * time.Hour)},
			assert: refusedNaming("WithFailureStreakRetention"),
		},
		{
			name: "a retention of zero is refused",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(0),
			},
			assert: refusedNaming("WithFailureStreakRetention"),
		},
		{
			name: "a negative retention is refused",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(-time.Hour),
			},
			assert: refusedNaming("WithFailureStreakRetention"),
		},
		{
			// A count would expire while the window still counts its failures.
			name: "a retention shorter than the window is refused",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(time.Hour),
			},
			assert: refusedNaming("WithFailureStreakRetention"),
		},
		{
			name: "a retention equal to the window is accepted",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(24 * time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 24*time.Hour, p.FailureStreakRetention())
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
				assert.Equal(t, 5, p.WaitThreshold())
				assert.Equal(t, 24*time.Hour, p.FailureWindow())
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
			opts:   []lockout.Option{lockout.WithWindowFailureLimit(5)},
			assert: refused,
		},
		{
			name: "a ceiling below a consumer threshold is refused",
			opts: []lockout.Option{
				lockout.WithWaitThreshold(10),
				lockout.WithWindowFailureLimit(8),
			},
			assert: refused,
		},
		{
			name:   "a consumer threshold at the default ceiling is refused",
			opts:   []lockout.Option{lockout.WithWaitThreshold(100)},
			assert: refused,
		},
		{
			// NIST caps consecutive failures at 100; a higher ceiling is the
			// consumer's documented departure, not a wiring mistake.
			name: "a ceiling above one hundred is allowed",
			opts: []lockout.Option{lockout.WithWindowFailureLimit(150)},
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
				assert.Equal(t, 3, p.WaitThreshold())
				assert.Equal(t, 15*time.Minute, p.FailureWindow(), "FailureWindow did not report the sliding lock's window")
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
				assert.ErrorContains(t, err, "WithSliding")
				assert.NotContains(t, err.Error(), "WithFixedLockout")
			},
		},
		{
			name: "a sliding lock with a ceiling option is refused",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithWindowFailureLimit(50),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				refused(t, p, err)
				assert.Contains(t, err.Error(), "WithWindowFailureLimit")
				assert.NotContains(t, err.Error(), "WithWait", "the error named an option that was not combined")
				assert.NotContains(t, err.Error(), "WithWaitThreshold", "the error named an option that was not combined")
				assert.NotContains(t, err.Error(), "WithFailureWindow", "the error named an option that was not combined")
			},
		},
		{
			name: "a sliding lock with several conflicting options names each of them",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithWaitThreshold(3),
				lockout.WithWait(time.Second, time.Minute),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				refused(t, p, err)
				assert.Contains(t, err.Error(), "WithWaitThreshold")
				assert.Contains(t, err.Error(), "WithWait")
				assert.NotContains(t, err.Error(), "WithWindowFailureLimit")
			},
		},
		{
			// The order of the options must not matter: a threshold set
			// before the sliding lock would otherwise be silently overwritten.
			name: "a threshold option before a sliding lock is refused",
			opts: []lockout.Option{
				lockout.WithWaitThreshold(3),
				lockout.WithSliding(5, 15*time.Minute),
			},
			assert: refused,
		},
		{
			name: "a window option after a sliding lock is refused",
			opts: []lockout.Option{
				lockout.WithSliding(5, 15*time.Minute),
				lockout.WithFailureWindow(time.Hour),
			},
			assert: refused,
		},
		{
			name: "a consumer's own threshold and window are kept",
			opts: []lockout.Option{
				lockout.WithWaitThreshold(3),
				lockout.WithFailureWindow(time.Hour),
			},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 3, p.WaitThreshold())
				assert.Equal(t, time.Hour, p.FailureWindow())
			},
		},
		{
			name: "a consumer's own store is used instead of the in-memory one",
			opts: []lockout.Option{lockout.WithAttemptStore(must.Must(lockout.NewMemoryAttemptStore()))},
			assert: func(t *testing.T, p *lockout.Policy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
			},
		},
		{
			// A window of zero contains no failure at all, so lockout is
			// disabled while every call site still reads like a lockout.
			name:   "a zero window is refused rather than silently disabling lockout",
			opts:   []lockout.Option{lockout.WithFailureWindow(0)},
			assert: refused,
		},
		{
			name:   "a negative window is refused",
			opts:   []lockout.Option{lockout.WithFailureWindow(-time.Minute)},
			assert: refused,
		},
		{
			// Zero failures are at or above a threshold of zero, so every
			// account is locked, including one that has never failed.
			name:   "a zero threshold is refused rather than locking every account",
			opts:   []lockout.Option{lockout.WithWaitThreshold(0)},
			assert: refused,
		},
		{
			name:   "a negative threshold is refused",
			opts:   []lockout.Option{lockout.WithWaitThreshold(-1)},
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
				assert.Equal(t, 5, p.WaitThreshold())
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

// Standalone: it builds the policy with no options at all and reads its accessors before evaluating.
func TestAccountLockoutPolicyDefaults(t *testing.T) {
	t.Parallel()

	p, err := lockout.New()
	require.NoError(t, err)

	assert.Equal(t, 5, p.WaitThreshold(), "the default threshold is not five")
	assert.Equal(t, 24*time.Hour, p.FailureWindow(), "the default window is not twenty-four hours")
	assert.Equal(t, []policy.Phase{policy.PreAuthentication}, p.Phases(),
		"the lockout rule must apply whether or not the submitted secret is correct, which is the pre-authentication phase")
	assert.NotEmpty(t, p.Name())

	// No store was configured, so the default in-memory one is what these
	// failures land in and what the decision is made from.
	recordFailures(t, p, "ada", 5)
	d := p.Evaluate(t.Context(), lockoutInput("ada"))
	assert.Equal(t, policy.Deny, d.Outcome, "the default store did not count the failures recorded through it")
	assert.ErrorIs(t, d.Reason, lockout.ErrAccountLocked)
}

// TestLockoutError covers the error type as a consumer meets it, including one
// the consumer builds themselves.
func TestLockoutError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "a consumer-built refusal still matches the account-locked sentinel",
			err:  &lockout.Error{Wait: time.Minute},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, lockout.ErrAccountLocked)
				assert.Equal(t, lockout.ErrAccountLocked.Error(), err.Error(),
					"a refusal with no count must still read as the account-locked refusal")
			},
		},
		{
			name: "a wrapped refusal is still found with errors.As",
			err:  errors.Join(errors.New("authentication failed"), &lockout.Error{Wait: 2 * time.Minute}),
			assert: func(t *testing.T, err error) {
				var locked *lockout.Error
				require.ErrorAs(t, err, &locked)
				assert.Equal(t, 2*time.Minute, locked.Wait)
				assert.ErrorIs(t, err, lockout.ErrAccountLocked)
			},
		},
		{
			name: "it matches no other sentinel",
			err:  &lockout.Error{},
			assert: func(t *testing.T, err error) {
				assert.NotErrorIs(t, err, policy.ErrDenied)
				assert.NotErrorIs(t, err, policy.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.err)
		})
	}
}

// TestAccountLockoutPolicyLockoutError pins the refusal a Policy
// gives a locked identifier: it is the account-locked refusal, it states the
// wait it owes where one is owed, and its text is the library's own.
func TestAccountLockoutPolicyLockoutError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		record func(t *testing.T, store *lockout.MemoryAttemptStore)
		assert func(t *testing.T, d policy.Decision)
	}

	owing := func(wait time.Duration, text string) func(t *testing.T, d policy.Decision) {
		return func(t *testing.T, d policy.Decision) {
			t.Helper()

			require.Equal(t, policy.Deny, d.Outcome)
			require.ErrorIs(t, d.Reason, lockout.ErrAccountLocked,
				"the refusal no longer matches the account-locked sentinel")

			var locked *lockout.Error
			require.ErrorAs(t, d.Reason, &locked, "the refusal is not a *lockout.Error")
			assert.Equal(t, wait, locked.Wait)
			assert.Equal(t, text, d.Reason.Error())
			assert.NotErrorIs(t, d.Reason, policy.ErrDenied,
				"a lock was reported as a policy outage")
		}
	}

	cases := []testCase{
		{
			name:   "at the threshold the refusal carries the first wait",
			record: failuresEndingAt("ada", 5, 10*time.Second),
			assert: owing(30*time.Second,
				"lockout: account locked after repeated failures: 5 failures within 24h0m0s"),
		},
		{
			name:   "seven failures carry the doubled wait of 120 seconds",
			record: failuresEndingAt("ada", 7, 10*time.Second),
			assert: owing(120*time.Second,
				"lockout: account locked after repeated failures: 7 failures within 24h0m0s"),
		},
		{
			name:   "a huge exponent carries the longest wait",
			record: failuresEndingAt("ada", 70, time.Minute),
			assert: owing(time.Hour,
				"lockout: account locked after repeated failures: 70 failures within 24h0m0s"),
		},
		{
			// No wait lifts a lock at the ceiling, so none is stated.
			name:   "at the ceiling the refusal carries no wait",
			record: failuresEndingAt("ada", 100, 2*time.Hour),
			assert: owing(0,
				"lockout: account locked after repeated failures: 100 failures within 24h0m0s"),
		},
		{
			name:   "under a sliding lock the refusal carries no wait",
			opts:   []lockout.Option{lockout.WithSliding(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 10*time.Minute),
			assert: owing(0,
				"lockout: account locked after repeated failures: 5 failures within 15m0s"),
		},
		{
			name:   "a flat fifteen-minute wait is owed one second before it ends",
			opts:   []lockout.Option{lockout.WithWait(15*time.Minute, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 15*time.Minute-time.Second),
			assert: owing(15*time.Minute,
				"lockout: account locked after repeated failures: 5 failures within 24h0m0s"),
		},
		{
			name:   "a further failure owes the same flat wait, not a doubled one",
			opts:   []lockout.Option{lockout.WithWait(15*time.Minute, 15*time.Minute)},
			record: failuresEndingAt("ada", 6, 14*time.Minute),
			assert: owing(15*time.Minute,
				"lockout: account locked after repeated failures: 6 failures within 24h0m0s"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := must.Must(lockout.NewMemoryAttemptStore())
			tc.record(t, store)

			p := lockoutWith(t, append([]lockout.Option{lockout.WithAttemptStore(store)}, tc.opts...)...)
			tc.assert(t, p.Evaluate(t.Context(), lockoutInput("ada")))
		})
	}
}

func TestAccountLockoutPolicyEvaluates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		record func(t *testing.T, store *lockout.MemoryAttemptStore)
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
		assert.ErrorIs(t, d.Reason, lockout.ErrAccountLocked)
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
			opts:   []lockout.Option{lockout.WithWindowFailureLimit(20)},
			record: failuresEndingAt("ada", 20, 2*time.Hour),
			assert: denies,
		},
		{
			name:   "a consumer's own first wait is owed",
			opts:   []lockout.Option{lockout.WithWait(5*time.Minute, time.Hour)},
			record: failuresEndingAt("ada", 5, 4*time.Minute),
			assert: denies,
		},
		{
			name:   "a consumer's own longest wait caps the escalation",
			opts:   []lockout.Option{lockout.WithWait(30*time.Second, 2*time.Minute)},
			record: failuresEndingAt("ada", 10, 3*time.Minute),
			assert: allows,
		},
		{
			name: "a failure exactly at the window edge does not count",
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
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
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
				failuresEndingAt("ada", 4, 10*time.Second)(t, store)
				failuresAt(t, store, "ada", lockoutDefaultCutoff.Add(time.Nanosecond))
			},
			assert: denies,
		},
		{
			name: "failures older than the window have fallen out of it",
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
				for i := range 10 {
					failuresAt(t, store, "ada", lockoutNow.Add(-25*time.Hour-time.Duration(i)*time.Minute))
				}
			},
			assert: allows,
		},
		{
			name:   "a consumer threshold of three owes a wait at three failures",
			opts:   []lockout.Option{lockout.WithWaitThreshold(3)},
			record: failuresEndingAt("ada", 3, 10*time.Second),
			assert: denies,
		},
		{
			name: "a consumer window of one hour drops a failure the default would still count",
			opts: []lockout.Option{lockout.WithFailureWindow(time.Hour)},
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
				failuresEndingAt("ada", 4, 10*time.Second)(t, store)
				failuresAt(t, store, "ada", lockoutNow.Add(-2*time.Hour))
			},
			assert: allows,
		},
		{
			// A sliding lock owes no wait: it holds for as long as the window
			// counts the threshold, however old the newest failure.
			name:   "a sliding lock denies at its threshold however old the newest failure",
			opts:   []lockout.Option{lockout.WithSliding(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 10*time.Minute),
			assert: denies,
		},
		{
			name:   "a sliding lock lifts once the failures leave its window",
			opts:   []lockout.Option{lockout.WithSliding(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 16*time.Minute),
			assert: allows,
		},
		{
			// Failures spread across the window: only the oldest is outside it,
			// so four remain and the sliding lock has already lifted.
			name: "a sliding lock lifts as soon as its oldest failure leaves the window",
			opts: []lockout.Option{lockout.WithSliding(5, 15*time.Minute)},
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
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
			opts: []lockout.Option{lockout.WithSliding(5, 15*time.Minute)},
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
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
			opts:   []lockout.Option{lockout.WithSliding(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 4, 10*time.Second),
			assert: allows,
		},
		{
			// The escalating default's ceiling of 100 has no meaning under a
			// sliding lock, whose own threshold is the only count that locks.
			name:   "a sliding lock ignores the escalating ceiling",
			opts:   []lockout.Option{lockout.WithSliding(200, 24*time.Hour)},
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
				assert.ErrorIs(t, d.Reason, policy.ErrDenied)
			},
		},
		{
			// FailureCount counts strictly after its cutoff, so the lock is lifted
			// at the instant the fifteen minutes have passed.
			name:   "a flat fifteen-minute wait is served exactly at its end",
			opts:   []lockout.Option{lockout.WithWait(15*time.Minute, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 15*time.Minute),
			assert: allows,
		},
		{
			name:   "six failures under a flat wait are allowed once it ends",
			opts:   []lockout.Option{lockout.WithWait(15*time.Minute, 15*time.Minute)},
			record: failuresEndingAt("ada", 6, 15*time.Minute),
			assert: allows,
		},
		{
			// 24 failures a day is what the default waits let a patient guesser
			// make. Five days of it is 120 failures, but the ceiling counts only
			// the window, so it never refuses.
			name: "failures outside the window do not count toward the ceiling",
			record: func(t *testing.T, store *lockout.MemoryAttemptStore) {
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

			store := must.Must(lockout.NewMemoryAttemptStore())
			if tc.record != nil {
				tc.record(t, store)
			}

			p := lockoutWith(t, append([]lockout.Option{lockout.WithAttemptStore(store)}, tc.opts...)...)

			in := lockoutInput("ada")
			if tc.input != nil {
				in = tc.input()
			}

			tc.assert(t, p.Evaluate(t.Context(), in))
		})
	}
}

// Standalone: it drives a record, reset and record sequence through the policy rather than seeding a store.
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

// Standalone: each subtest sets its own mock expectation and calls a different policy method.
func TestAccountLockoutPolicyRecordsAndResetsThroughTheStore(t *testing.T) {
	t.Parallel()

	t.Run("a failure is recorded at the policy's own instant", func(t *testing.T) {
		t.Parallel()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)

		p := lockoutWith(t, lockout.WithAttemptStore(store))
		require.NoError(t, p.RecordFailure(t.Context(), "ada"))
	})

	t.Run("a store that cannot record says so", func(t *testing.T) {
		t.Parallel()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(errAttemptStoreDown)

		p := lockoutWith(t, lockout.WithAttemptStore(store))
		require.ErrorIs(t, p.RecordFailure(t.Context(), "ada"), errAttemptStoreDown,
			"a failure that was never recorded was reported as recorded, so the count never reaches the threshold")
	})

	t.Run("a store that cannot reset says so", func(t *testing.T) {
		t.Parallel()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

		p := lockoutWith(t, lockout.WithAttemptStore(store))
		require.ErrorIs(t, p.Reset(t.Context(), "ada"), errAttemptStoreDown)
	})
}

// Standalone: it evaluates through a policy.Engine in every phase, not through the policy directly.
func TestAccountLockoutPolicyRunsInPreAuthenticationOnly(t *testing.T) {
	t.Parallel()

	p := lockoutWith(t)
	recordFailures(t, p, "ada", 5)

	engine, err := policy.NewEngine(p)
	require.NoError(t, err)

	locked := engine.EvaluatePhase(t.Context(), policy.PreAuthentication, lockoutInput("ada"))
	require.Equal(t, policy.Deny, locked.Outcome)
	assert.ErrorIs(t, locked.Reason, lockout.ErrAccountLocked)

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

// storeDeniedText is the whole reason text of a refusal for a store that could
// not answer; the kind's text leads it.
var storeDeniedText = policy.ErrDenied.Error() +
	": the attempt store could not say how often this identifier has failed"

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
				assert.ErrorIs(t, d.Reason, policy.ErrDenied)
				assert.EqualError(t, d.Reason, storeDeniedText)
				assert.NotErrorIs(t, d.Reason, lockout.ErrAccountLocked,
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
				assert.ErrorIs(t, d.Reason, errAttemptStoreDown)
				assert.ErrorIs(t, d.Reason, policy.ErrDenied)
				assert.EqualError(t, d.Reason, storeDeniedText)
				assert.True(t, strings.HasPrefix(d.Reason.Error(), policy.ErrDenied.Error()+": "),
					"the reason does not lead with the denied sentinel's text: %q", d.Reason)
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
				assert.ErrorIs(t, d.Reason, policy.ErrDenied)
				assert.EqualError(t, d.Reason, storeDeniedText)
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
				assert.ErrorIs(t, d.Reason, lockout.ErrAccountLocked)
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
				assert.ErrorIs(t, d.Reason, policy.ErrDenied)
				assert.EqualError(t, d.Reason, storeDeniedText)
				assert.NotErrorIs(t, d.Reason, lockout.ErrAccountLocked,
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

			p := lockoutWith(t, lockout.WithAttemptStore(store))
			tc.assert(t, p.Evaluate(ctx, lockoutInput("ada")))
		})
	}
}

// reapableAttemptStore is a store that can also purge, assembled from the
// in-memory store and the generated reaper mock so a test can drive the sweep
// without giving up a real store to count in.
type reapableAttemptStore struct {
	*lockout.MemoryAttemptStore
	reaper *MockAttemptReaper
}

func newReapableAttemptStore(t *testing.T) *reapableAttemptStore {
	t.Helper()

	return &reapableAttemptStore{
		MemoryAttemptStore: must.Must(lockout.NewMemoryAttemptStore()),
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
		return 0, lockout.ErrRetainSinceRequired
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

// Standalone: its subtests each build a different store, and one calls the store's reaper directly.
func TestAccountLockoutPolicyPurgeExpired(t *testing.T) {
	t.Parallel()

	t.Run("the cutoff is the policy's own window and nothing else", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutDefaultCutoff).
			Return(3, nil)

		p := lockoutWith(t, lockout.WithAttemptStore(store))

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

		p := lockoutWith(t, lockout.WithAttemptStore(store), lockout.WithFailureWindow(time.Hour))

		_, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
	})

	t.Run("a sliding lock's own window is the cutoff", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutCutoff).
			Return(0, nil)

		p := lockoutWith(t, lockout.WithAttemptStore(store), lockout.WithSliding(5, 15*time.Minute))

		_, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
	})

	t.Run("a purge does not free a failure the window still counts", func(t *testing.T) {
		t.Parallel()

		// A sliding lock of one failure per 15 minutes: the failure locks for as
		// long as the window counts it, so a purge that took it would unlock.
		store := newSweepingAttemptStore()
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-5*time.Minute)))

		p := lockoutWith(t, lockout.WithAttemptStore(store), lockout.WithSliding(1, 15*time.Minute))

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

		p := lockoutWith(t, lockout.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, removed, "the sweep did not remove exactly the failure that had aged out")
		assert.Equal(t, 1, store.held("ada"), "the sweep took a failure the 24-hour window still counts")
	})

	t.Run("a consumer store that cannot purge reports unsupported rather than a silent zero", func(t *testing.T) {
		t.Parallel()

		// The mock expects no call: a store without AttemptReaper is never asked.
		p := lockoutWith(t, lockout.WithAttemptStore(NewMockAttemptStore(gomock.NewController(t))))

		removed, err := p.PurgeExpired(t.Context())
		require.ErrorIs(t, err, lockout.ErrReapUnsupported,
			"a store that cannot purge reported a successful sweep that never happened")
		assert.Zero(t, removed)
	})

	t.Run("a reaper that refuses the zero cutoff deletes nothing", func(t *testing.T) {
		t.Parallel()

		store := newSweepingAttemptStore()
		require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-time.Hour)))

		removed, err := store.DeleteAttemptsBefore(t.Context(), time.Time{})
		require.ErrorIs(t, err, lockout.ErrRetainSinceRequired)
		assert.Zero(t, removed)
		assert.Equal(t, 1, store.held("ada"), "a sweep with no cutoff deleted what it was asked to retain")
	})

	t.Run("a reaper that cannot answer is reported", func(t *testing.T) {
		t.Parallel()

		store := newReapableAttemptStore(t)
		store.reaper.EXPECT().
			DeleteAttemptsBefore(gomock.Any(), lockoutDefaultCutoff).
			Return(0, errAttemptStoreDown)

		p := lockoutWith(t, lockout.WithAttemptStore(store))

		removed, err := p.PurgeExpired(t.Context())
		require.ErrorIs(t, err, errAttemptStoreDown)
		assert.Zero(t, removed)
	})
}

// errLeakyStore is a store failure whose text quotes values the policy never
// saw: another column of the row and a user reference. Neither may reach a
// refusal's text or a record.
var errLeakyStore = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// leakedValues are the values errLeakyStore quotes.
var leakedValues = []string{"alice@example.com", "u-123"}

// TestLockoutReturnedErrors pins the diagnostic-redaction requirement for the
// account lockout policy's own store-facing methods (design decision 8):
// RecordFailure, Reset and PurgeExpired return the attempt store's failure
// behind fixed library text, with the store's own error still reachable by
// identity, and a bare AttemptReaper sentinel still comes back unchanged.
func TestLockoutReturnedErrors(t *testing.T) {
	t.Parallel()

	failingAttemptStore := func(t *testing.T) *MockAttemptStore {
		t.Helper()

		store := NewMockAttemptStore(gomock.NewController(t))
		store.EXPECT().RecordFailure(gomock.Any(), gomock.Any(), gomock.Any()).Return(errLeakyStore).AnyTimes()
		store.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(errLeakyStore).AnyTimes()

		return store
	}

	assertFixedText := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		for _, v := range leakedValues {
			assert.NotContains(t, err.Error(), v, "the returned error quoted the store's own text")
		}
		assert.ErrorIs(t, err, errLeakyStore, "the store's own error is no longer reachable")

		// A store failure must not read as any of the policy's own sentinels:
		// diag.Wrap's kinds are matched by every error it carries, so passing
		// a sentinel as a kind would make an unrelated outage look like that
		// specific refusal (design decision 8).
		assert.NotErrorIs(t, err, lockout.ErrRetainSinceRequired,
			"a store outage must not read as a retain-since cutoff being required")
		assert.NotErrorIs(t, err, lockout.ErrReapUnsupported,
			"a store outage must not read as the store lacking reap support")
		assert.NotErrorIs(t, err, policy.ErrDenied,
			"a store outage must not read as the policy's own denial reason")
	}

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "recording a failure the store cannot write",
			run: func(t *testing.T) error {
				t.Helper()

				p := lockoutWith(t, lockout.WithAttemptStore(failingAttemptStore(t)))

				return p.RecordFailure(t.Context(), "alice@example.com")
			},
			assert: assertFixedText,
		},
		{
			name: "clearing failures the store cannot reset",
			run: func(t *testing.T) error {
				t.Helper()

				p := lockoutWith(t, lockout.WithAttemptStore(failingAttemptStore(t)))

				return p.Reset(t.Context(), "alice@example.com")
			},
			assert: assertFixedText,
		},
		{
			name: "purging expired failures the store cannot sweep",
			run: func(t *testing.T) error {
				t.Helper()

				store := newReapableAttemptStore(t)
				store.reaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), gomock.Any()).Return(0, errLeakyStore)

				p := lockoutWith(t, lockout.WithAttemptStore(store))

				_, err := p.PurgeExpired(t.Context())

				return err
			},
			assert: assertFixedText,
		},
		{
			name: "purging passes a bare retain-since sentinel through unchanged",
			run: func(t *testing.T) error {
				t.Helper()

				store := newReapableAttemptStore(t)
				store.reaper.EXPECT().
					DeleteAttemptsBefore(gomock.Any(), gomock.Any()).
					Return(0, lockout.ErrRetainSinceRequired)

				p := lockoutWith(t, lockout.WithAttemptStore(store))

				_, err := p.PurgeExpired(t.Context())

				return err
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Same(t, lockout.ErrRetainSinceRequired, err,
					"a store's own bare sentinel must come back as itself, text included")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}

// errLogDown is the failure log's own outage, distinct from the streak's.
var errLogDown = errors.New("failure log down")

// TestLockoutCapView pins what the policy's view writes when a failure is
// recorded or cleared: without a cap the view never touches the streak, and
// with one the streak is advanced first, with the policy's cutoff and cap,
// and then the failure log.
func TestLockoutCapView(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		expect func(s *streakAttemptStore)
		act    func(t *testing.T, p *lockout.Policy) error
		assert func(t *testing.T, p *lockout.Policy, s *streakAttemptStore, err error)
	}

	recordAda := func(t *testing.T, p *lockout.Policy) error {
		t.Helper()

		return p.RecordFailure(t.Context(), "ada")
	}

	cases := []testCase{
		{
			name: "without a cap the view is the store and never touches the streak",
			expect: func(s *streakAttemptStore) {
				s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
			},
			act: recordAda,
			assert: func(t *testing.T, p *lockout.Policy, s *streakAttemptStore, err error) {
				require.NoError(t, err)
				assert.Same(t, s, p.Attempts(), "a policy without a cap or observer wrapped its store")
			},
		},
		{
			name: "with a cap the streak is written before the log",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(lockout.FailureStreak{Failures: 1, Newest: lockoutNow}, false, nil),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *lockout.Policy, _ *streakAttemptStore, err error) {
				require.NoError(t, err)
			},
		},
		{
			// A login endpoint records through the view at its own instant,
			// and the cutoff is taken from that instant, not the policy's
			// clock.
			name: "the view handed to an endpoint advances the streak with a consumer cap and retention",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(20),
				lockout.WithFailureStreakRetention(7 * 24 * time.Hour),
			},
			expect: func(s *streakAttemptStore) {
				at := lockoutNow.Add(-time.Hour)
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", at, at.Add(-7*24*time.Hour), 20).
						Return(lockout.FailureStreak{Failures: 1, Newest: at}, false, nil),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", at).Return(nil),
				)
			},
			act: func(t *testing.T, p *lockout.Policy) error {
				t.Helper()

				return p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow.Add(-time.Hour))
			},
			assert: func(t *testing.T, _ *lockout.Policy, _ *streakAttemptStore, err error) {
				require.NoError(t, err)
			},
		},
		{
			// The streak goes first because it cannot be rebuilt, but a failure
			// to write it does not skip the log: the log entry alone keeps the
			// windowed lock counting while the streak store is failing.
			name: "a failed streak write is returned and the log is still written",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(lockout.FailureStreak{}, false, errAttemptStoreDown),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *lockout.Policy, _ *streakAttemptStore, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.NotContains(t, err.Error(), errAttemptStoreDown.Error(),
					"the store's own text reached the caller")
			},
		},
		{
			name: "when both writes fail both errors are returned",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(lockout.FailureStreak{}, false, errAttemptStoreDown),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errLogDown),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *lockout.Policy, _ *streakAttemptStore, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				require.ErrorIs(t, err, errLogDown)
			},
		},
		{
			name: "a failed log write after the streak is returned",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			expect: func(s *streakAttemptStore) {
				gomock.InOrder(
					s.MockFailureStreakStore.EXPECT().
						AddStreakFailure(gomock.Any(), "ada", lockoutNow, lockoutNow.Add(-defaultCapRetention), 100).
						Return(lockout.FailureStreak{Failures: 1, Newest: lockoutNow}, false, nil),
					s.MockAttemptStore.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown),
				)
			},
			act: recordAda,
			assert: func(t *testing.T, _ *lockout.Policy, _ *streakAttemptStore, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
			},
		},
		{
			// With a cap and no observer there is nothing to report, so a
			// reset is the store's Reset, which clears the streak with the log.
			name: "with a cap and no observer a reset only clears through the store",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			expect: func(s *streakAttemptStore) {
				s.MockAttemptStore.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			},
			act: func(t *testing.T, p *lockout.Policy) error {
				t.Helper()

				return p.Reset(t.Context(), "ada")
			},
			assert: func(t *testing.T, _ *lockout.Policy, _ *streakAttemptStore, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newStreakAttemptStore(t)
			tc.expect(s)

			p, err := lockout.New(append([]lockout.Option{
				lockout.WithAttemptStore(s),
				lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, p, s, tc.act(t, p))
		})
	}
}

// TestLockoutCapEvaluate pins pre-authentication under a cap: a held
// identifier is refused first, however old its failures, and otherwise the
// windowed evaluation decides as it always has.
func TestLockoutCapEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []lockout.Option
		// store builds the attempt store; nil means a fresh in-memory one.
		store func(t *testing.T) policy.AttemptStore
		// seed records failures through the policy and moves the clock to
		// the instant pre-authentication runs at.
		seed   func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock)
		assert func(t *testing.T, p *lockout.Policy, d policy.Decision)
	}

	twentyADayForFiveDays := []int{20, 20, 20, 20, 20}

	cases := []testCase{
		{
			// Spec: "No cap by default".
			name: "no cap by default",
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", twentyADayForFiveDays...)
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a policy with no cap refused: %v", d.Reason)
			},
		},
		{
			// Spec: "Cap reached across days" and "Held refusal".
			name: "a cap of 100 reached across five days holds",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", twentyADayForFiveDays...)
				clk.Advance(3 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "Consumer cap".
			name: "a consumer cap of 20 reached over two days holds",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 10, 10)
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				deniedAsHeld(t, d, 20)
			},
		},
		{
			// A failure recorded through the view at a zero instant is recorded
			// at the policy's clock: at the zero instant the hold would be set
			// at time zero, which reads as no hold at all.
			name: "failures recorded at a zero instant through the view still hold",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			seed: func(t *testing.T, p *lockout.Policy, _ *clockwork.FakeClock) {
				t.Helper()

				for range 25 {
					require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", time.Time{}))
				}
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome, "a hold set at a zero instant was allowed")
				require.ErrorIs(t, d.Reason, lockout.ErrAccountHeld)
			},
		},
		{
			// Spec: "Below the cap".
			name: "ninety-nine failures under a cap of 100 are allowed",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 20, 20, 20, 20, 19)
				clk.Advance(2 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a count below the cap refused: %v", d.Reason)
			},
		},
		{
			// Spec: "Unknown identifiers are held alike". The policy cannot
			// tell them apart, and its refusal must not either.
			name: "an identifier with no account is held with the same refusal",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(20)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 10, 10)
				failDaily(t, p, clk, "nobody", 10, 10)
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, p *lockout.Policy, d policy.Decision) {
				deniedAsHeld(t, d, 20)

				other := p.Evaluate(t.Context(), lockoutInput("nobody"))
				deniedAsHeld(t, other, 20)
				assert.Equal(t, d.Reason.Error(), other.Reason.Error(),
					"the refusal tells a known identifier from an unknown one")
			},
		},
		{
			// Spec: "A windowed lock is not a hold".
			name: "a windowed lock under a cap is not a hold",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				for range 7 {
					clk.Advance(time.Second)
					require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
				}
				clk.Advance(10 * time.Second)
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome)
				require.ErrorIs(t, d.Reason, lockout.ErrAccountLocked)
				assert.NotErrorIs(t, d.Reason, lockout.ErrAccountHeld, "a windowed lock was reported as a hold")

				var locked *lockout.Error
				require.ErrorAs(t, d.Reason, &locked)
				assert.Equal(t, 120*time.Second, locked.Wait)
				assert.Equal(t, "lockout: account locked after repeated failures: 7 failures within 24h0m0s",
					d.Reason.Error())
			},
		},
		{
			// Spec: "Unreadable hold". The windowed count is never asked: a
			// policy that cannot tell whether an identifier is held does not
			// know enough to allow it.
			name: "a streak that cannot be read denies, wrapping the store's error",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			store: func(t *testing.T) policy.AttemptStore {
				t.Helper()

				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(lockout.FailureStreak{}, errAttemptStoreDown)

				return s
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				require.Equal(t, policy.Deny, d.Outcome, "an unreadable hold was allowed")
				require.ErrorIs(t, d.Reason, policy.ErrDenied)
				require.ErrorIs(t, d.Reason, errAttemptStoreDown)
				assert.NotErrorIs(t, d.Reason, lockout.ErrAccountLocked,
					"an outage was reported as a lock the policy does not know of")
				assert.NotContains(t, d.Reason.Error(), errAttemptStoreDown.Error(),
					"the store's own text reached the reason")
			},
		},
		{
			// Spec: "A hold outlives every window".
			name: "a hold set ninety days ago still holds",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 100)
				clk.Advance(90 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ *lockout.Policy, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "The correct password does not lift a hold".
			// Pre-authentication runs before the password is checked, so
			// whatever the login presents, the hold refuses it; and evaluating
			// writes nothing, so the identifier is still held afterwards. The
			// mock expects the two reads and nothing else.
			name: "pre-authentication refuses a held identifier and leaves it held",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			store: func(t *testing.T) policy.AttemptStore {
				t.Helper()

				heldAt := lockoutNow.Add(-time.Hour)
				s := newStreakAttemptStore(t)
				s.MockFailureStreakStore.EXPECT().
					FailureStreak(gomock.Any(), "ada", lockoutNow.Add(-defaultCapRetention)).
					Return(lockout.FailureStreak{Failures: 100, Newest: heldAt, HeldAt: heldAt}, nil).
					Times(2)

				return s
			},
			assert: func(t *testing.T, p *lockout.Policy, d policy.Decision) {
				deniedAsHeld(t, d, 100)
				deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("ada")), 100)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var store policy.AttemptStore = must.Must(lockout.NewMemoryAttemptStore())
			if tc.store != nil {
				store = tc.store(t)
			}
			clk := clockwork.NewFakeClockAt(lockoutNow)

			p, err := lockout.New(append([]lockout.Option{
				lockout.WithAttemptStore(store),
				lockout.WithClock(clk),
			}, tc.opts...)...)
			require.NoError(t, err)

			if tc.seed != nil {
				tc.seed(t, p, clk)
			}

			tc.assert(t, p, p.Evaluate(t.Context(), lockoutInput("ada")))
		})
	}
}

// TestLockoutCapRetention pins how long a consecutive count lives and what
// lifts a hold: a count below the cap restarts after the retention, a hold
// never expires, and the policy's Reset lifts it with the window.
func TestLockoutCapRetention(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []lockout.Option
		// seed records failures through the policy and moves the clock to
		// the instant pre-authentication runs at.
		seed   func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock)
		assert func(t *testing.T, store lockout.FailureStreakStore, now time.Time, d policy.Decision)
	}

	// streakOf reads ada's streak straight from the store, with the cutoff
	// the policy would use at now under retention.
	streakOf := func(
		t *testing.T, store lockout.FailureStreakStore, now time.Time, retention time.Duration,
	) lockout.FailureStreak {
		t.Helper()

		s, err := store.FailureStreak(t.Context(), "ada", now.Add(-retention))
		require.NoError(t, err)

		return s
	}

	cases := []testCase{
		{
			// Spec: "Inactive count restarts".
			name: "a count inactive for longer than the retention restarts",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 99)
				clk.Advance(31 * 24 * time.Hour)
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
			},
			assert: func(t *testing.T, store lockout.FailureStreakStore, now time.Time, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a restarted count refused: %v", d.Reason)

				s := streakOf(t, store, now, defaultCapRetention)
				assert.Equal(t, 1, s.Failures, "the inactive count did not restart")
				assert.False(t, s.Held())
			},
		},
		{
			// Spec: "Consumer retention".
			name: "a consumer retention of seven days restarts a count eight days old",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(7 * 24 * time.Hour),
			},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 99)
				clk.Advance(8 * 24 * time.Hour)
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
			},
			assert: func(t *testing.T, store lockout.FailureStreakStore, now time.Time, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a restarted count refused: %v", d.Reason)
				assert.Equal(t, 1, streakOf(t, store, now, 7*24*time.Hour).Failures,
					"the count did not restart after the consumer's retention")
			},
		},
		{
			// The retention is the consumer's, not the default: a count six
			// days old under seven days of retention still counts.
			name: "a consumer retention of seven days keeps a count six days old",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(7 * 24 * time.Hour),
			},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 99)
				clk.Advance(6 * 24 * time.Hour)
				require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", clk.Now()))
				clk.Advance(2 * time.Hour)
			},
			assert: func(t *testing.T, _ lockout.FailureStreakStore, _ time.Time, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "A hold does not expire".
			name: "a hold set thirty-one days ago still holds",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 100)
				clk.Advance(31 * 24 * time.Hour)
			},
			assert: func(t *testing.T, _ lockout.FailureStreakStore, _ time.Time, d policy.Decision) {
				deniedAsHeld(t, d, 100)
			},
		},
		{
			// Spec: "Reset unlocks". The hold, the count and the failures in
			// the window go together: with any of them left, ada would still
			// be refused, held or at the ceiling.
			name: "the policy's reset lifts a hold and clears the window",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			seed: func(t *testing.T, p *lockout.Policy, clk *clockwork.FakeClock) {
				t.Helper()

				failDaily(t, p, clk, "ada", 100)
				clk.Advance(time.Minute)
				deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("ada")), 100)

				require.NoError(t, p.Reset(t.Context(), "ada"))
			},
			assert: func(t *testing.T, store lockout.FailureStreakStore, now time.Time, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome, "a reset left ada refused: %v", d.Reason)
				assert.Zero(t, streakOf(t, store, now, defaultCapRetention), "a reset left a streak behind")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := must.Must(lockout.NewMemoryAttemptStore())
			clk := clockwork.NewFakeClockAt(lockoutNow)

			p, err := lockout.New(append([]lockout.Option{
				lockout.WithAttemptStore(store),
				lockout.WithClock(clk),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.seed(t, p, clk)

			tc.assert(t, store, clk.Now(), p.Evaluate(t.Context(), lockoutInput("ada")))
		})
	}
}

// streakReaperStore is an attempt store that keeps consecutive failures and
// can purge its log, as the durable stores can, built from the three
// generated mocks on one controller.
type streakReaperStore struct {
	*MockAttemptStore
	*MockFailureStreakStore
	*MockAttemptReaper
}

func newStreakReaperStore(t *testing.T) *streakReaperStore {
	t.Helper()

	ctrl := gomock.NewController(t)

	return &streakReaperStore{
		MockAttemptStore:       NewMockAttemptStore(ctrl),
		MockFailureStreakStore: NewMockFailureStreakStore(ctrl),
		MockAttemptReaper:      NewMockAttemptReaper(ctrl),
	}
}

var (
	_ lockout.FailureStreakStore = (*streakReaperStore)(nil)
	_ lockout.AttemptReaper      = (*streakReaperStore)(nil)
)

// TestLockoutCapPurge pins what a purge removes under a cap: the inactive
// streaks behind the policy's own retention, after the failures behind its
// window, and nothing of the streaks without a cap.
func TestLockoutCapPurge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		store  func(t *testing.T) policy.AttemptStore
		assert func(t *testing.T, removed int, err error)
	}

	windowCutoff := lockoutNow.Add(-24 * time.Hour)

	cases := []testCase{
		{
			name: "with a cap the inactive streaks behind the retention are purged too",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				gomock.InOrder(
					s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(3, nil),
					s.MockFailureStreakStore.EXPECT().
						DeleteStreaksBefore(gomock.Any(), lockoutNow.Add(-defaultCapRetention)).Return(2, nil),
				)

				return s
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 5, removed, "the total is not the failures and the streaks together")
			},
		},
		{
			name: "the streaks are purged behind the consumer's retention",
			opts: []lockout.Option{
				lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
				lockout.WithFailureStreakRetention(7 * 24 * time.Hour),
			},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(0, nil)
				s.MockFailureStreakStore.EXPECT().
					DeleteStreaksBefore(gomock.Any(), lockoutNow.Add(-7*24*time.Hour)).Return(4, nil)

				return s
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 4, removed)
			},
		},
		{
			// The mock expects no streak call: one would fail the case.
			name: "without a cap the streaks are never touched",
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(3, nil)

				return s
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
			},
		},
		{
			name: "a streak purge that failed is returned behind the library's text",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(3, nil)
				s.MockFailureStreakStore.EXPECT().
					DeleteStreaksBefore(gomock.Any(), gomock.Any()).Return(0, errAttemptStoreDown)

				return s
			},
			assert: func(t *testing.T, _ int, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.NotContains(t, err.Error(), errAttemptStoreDown.Error(),
					"the store's own text reached the caller")
			},
		},
		{
			name: "a failed attempt purge leaves the streaks alone",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			store: func(t *testing.T) policy.AttemptStore {
				s := newStreakReaperStore(t)
				s.MockAttemptReaper.EXPECT().DeleteAttemptsBefore(gomock.Any(), windowCutoff).Return(0, errAttemptStoreDown)

				return s
			},
			assert: func(t *testing.T, _ int, err error) {
				require.ErrorIs(t, err, errAttemptStoreDown)
			},
		},
		{
			// The in-memory store purges its log and its streaks: with
			// nothing recorded, the purge succeeds and removes nothing.
			name: "with a cap the in-memory store purges",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			store: func(*testing.T) policy.AttemptStore {
				return must.Must(lockout.NewMemoryAttemptStore())
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := lockout.New(append([]lockout.Option{
				lockout.WithAttemptStore(tc.store(t)),
				lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
			}, tc.opts...)...)
			require.NoError(t, err)

			removed, err := p.PurgeExpired(t.Context())
			tc.assert(t, removed, err)
		})
	}
}

// TestLockoutCapPurgeKeepsHolds is the spec scenario "Inactive counts are
// purged, holds are kept", run over real streaks rather than mocked ones, so
// it shows what goes and what stays rather than which cutoff is passed.
//
// Standalone: it purges real streaks in the in-memory store, where TestLockoutCapPurge mocks the store.
func TestLockoutCapPurgeKeepsHolds(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(lockoutNow)
	store := must.Must(lockout.NewMemoryAttemptStore())
	p, err := lockout.New(
		lockout.WithAttemptStore(store),
		lockout.WithClock(clk),
		lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit),
	)
	require.NoError(t, err)

	failDaily(t, p, clk, "ada", 10)
	failDaily(t, p, clk, "bob", 100)
	clk.Advance(31 * 24 * time.Hour)

	// Read with a cutoff old enough to see the inactive count, so its removal
	// is shown by the store and not by the read's own cutoff.
	longAgo := lockoutNow.Add(-time.Hour)
	before, err := store.FailureStreak(t.Context(), "ada", longAgo)
	require.NoError(t, err)
	require.Equal(t, 10, before.Failures, "the seed is not what the scenario needs")

	removed, err := p.PurgeExpired(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 111, removed, "the purge did not count the 110 aged-out failures and one inactive streak")

	after, err := store.FailureStreak(t.Context(), "ada", longAgo)
	require.NoError(t, err)
	assert.Zero(t, after, "the inactive count for ada was kept")

	deniedAsHeld(t, p.Evaluate(t.Context(), lockoutInput("bob")), 100)
}

func TestPolicy_RequiredAttemptView(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []lockout.Option
		assert func(t *testing.T, required bool)
	}

	tests := []testCase{
		{
			name: "with a cap the policy requires its view",
			opts: []lockout.Option{lockout.WithFailureStreakLimit(lockout.NISTFailureStreakLimit)},
			assert: func(t *testing.T, required bool) {
				assert.True(t, required)
			},
		},
		{
			name: "without a cap the policy does not require its view",
			assert: func(t *testing.T, required bool) {
				assert.False(t, required)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := lockout.New(tc.opts...)
			require.NoError(t, err)

			view, required := p.RequiredAttemptView()

			assert.Same(t, p.Attempts(), view, "the view is the one the policy hands out")
			tc.assert(t, required)
		})
	}
}

func TestLockoutExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) (expiry.Task, func(t *testing.T))
		assert func(t *testing.T, task expiry.Task, removed int, err error)
	}

	// sweeping builds a policy over a purge-capable store with the given
	// window, records failures at the offsets before lockoutNow, and returns
	// the policy, the store and a counter of what is still inside the window.
	sweeping := func(t *testing.T, window time.Duration, ago ...time.Duration) (*lockout.Policy, func(t *testing.T) int) {
		t.Helper()

		store := newSweepingAttemptStore()
		p, err := lockout.New(
			lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
			lockout.WithFailureWindow(window),
			lockout.WithAttemptStore(store),
		)
		require.NoError(t, err)

		for _, d := range ago {
			require.NoError(t, store.RecordFailure(t.Context(), "ada", lockoutNow.Add(-d)))
		}

		return p, func(*testing.T) int {
			store.mu.Lock()
			defer store.mu.Unlock()

			return len(store.failures["ada"])
		}
	}

	cases := []testCase{
		{
			name: "a 15m window removes only the failure past it",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, held := sweeping(t, 15*time.Minute, 5*time.Minute, 20*time.Minute)

				return lockout.ExpiryTask(p), func(t *testing.T) {
					assert.Equal(t, 1, held(t))
					n, err := p.PurgeExpired(t.Context())
					require.NoError(t, err)
					assert.Zero(t, n, "the failure inside the window is still counted")
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "a consumer's 1h window keeps a 30m-old failure",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, held := sweeping(t, time.Hour, 30*time.Minute)

				return lockout.ExpiryTask(p), func(t *testing.T) { assert.Equal(t, 1, held(t)) }
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
		{
			name: "a consumer store that cannot purge reports purge unsupported, never zero and nil",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, err := lockout.New(
					lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
					lockout.WithFailureWindow(15*time.Minute),
					lockout.WithAttemptStore(NewMockAttemptStore(gomock.NewController(t))),
				)
				require.NoError(t, err)

				return lockout.ExpiryTask(p), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, lockout.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
		{
			name: "the default in-memory store purges what left the window",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, err := lockout.New(
					lockout.WithClock(clockwork.NewFakeClockAt(lockoutNow)),
					lockout.WithFailureWindow(15*time.Minute),
				)
				require.NoError(t, err)
				for _, d := range []time.Duration{5 * time.Minute, 20 * time.Minute} {
					require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow.Add(-d)))
				}

				return lockout.ExpiryTask(p), func(t *testing.T) {
					count, err := p.Attempts().FailureCount(t.Context(), "ada", lockoutCutoff)
					require.NoError(t, err)
					assert.Equal(t, 1, count, "the purge took a failure the window still counts")
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "name is login-attempts and no interval is set",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, _ := sweeping(t, 15*time.Minute)

				return lockout.ExpiryTask(p), func(*testing.T) {}
			},
			assert: func(t *testing.T, task expiry.Task, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "login-attempts", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			task, after := tc.setup(t)
			require.NotNil(t, task.Run, "the task must carry a Run")

			removed, err := task.Run(t.Context())
			tc.assert(t, task, removed, err)
			after(t)
		})
	}
}
