package policy_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// TestAccountLockoutPolicyLockoutError pins the refusal an AccountLockoutPolicy
// gives a locked identifier: it is the account-locked refusal, it states the
// wait it owes where one is owed, and its text is the library's own.
func TestAccountLockoutPolicyLockoutError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		record func(t *testing.T, store *policy.MemoryAttemptStore)
		assert func(t *testing.T, d policy.Decision)
	}

	owing := func(wait time.Duration, text string) func(t *testing.T, d policy.Decision) {
		return func(t *testing.T, d policy.Decision) {
			t.Helper()

			require.Equal(t, policy.Deny, d.Outcome)
			require.ErrorIs(t, d.Reason, policy.ErrAccountLocked,
				"the refusal no longer matches the account-locked sentinel")

			var locked *policy.LockoutError
			require.ErrorAs(t, d.Reason, &locked, "the refusal is not a *LockoutError")
			assert.Equal(t, wait, locked.Wait)
			assert.Equal(t, text, d.Reason.Error())
			assert.NotErrorIs(t, d.Reason, policy.ErrPolicyDenied,
				"a lock was reported as a policy outage")
		}
	}

	cases := []testCase{
		{
			name:   "at the threshold the refusal carries the first wait",
			record: failuresEndingAt("ada", 5, 10*time.Second),
			assert: owing(30*time.Second,
				"policy: account locked after repeated failures: 5 failures within 24h0m0s"),
		},
		{
			name:   "seven failures carry the doubled wait of 120 seconds",
			record: failuresEndingAt("ada", 7, 10*time.Second),
			assert: owing(120*time.Second,
				"policy: account locked after repeated failures: 7 failures within 24h0m0s"),
		},
		{
			name:   "a huge exponent carries the longest wait",
			record: failuresEndingAt("ada", 70, time.Minute),
			assert: owing(time.Hour,
				"policy: account locked after repeated failures: 70 failures within 24h0m0s"),
		},
		{
			// No wait lifts a lock at the ceiling, so none is stated.
			name:   "at the ceiling the refusal carries no wait",
			record: failuresEndingAt("ada", 100, 2*time.Hour),
			assert: owing(0,
				"policy: account locked after repeated failures: 100 failures within 24h0m0s"),
		},
		{
			name:   "under a fixed lock the refusal carries no wait",
			opts:   []policy.LockoutOption{policy.WithFixedLockout(5, 15*time.Minute)},
			record: failuresEndingAt("ada", 5, 10*time.Minute),
			assert: owing(0,
				"policy: account locked after repeated failures: 5 failures within 15m0s"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := policy.NewMemoryAttemptStore()
			tc.record(t, store)

			p := lockoutWith(t, append([]policy.LockoutOption{policy.WithAttemptStore(store)}, tc.opts...)...)
			tc.assert(t, p.Evaluate(t.Context(), lockoutInput("ada")))
		})
	}
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
			err:  &policy.LockoutError{Wait: time.Minute},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, policy.ErrAccountLocked)
				assert.Equal(t, policy.ErrAccountLocked.Error(), err.Error(),
					"a refusal with no count must still read as the account-locked refusal")
			},
		},
		{
			name: "a wrapped refusal is still found with errors.As",
			err:  errors.Join(errors.New("authentication failed"), &policy.LockoutError{Wait: 2 * time.Minute}),
			assert: func(t *testing.T, err error) {
				var locked *policy.LockoutError
				require.ErrorAs(t, err, &locked)
				assert.Equal(t, 2*time.Minute, locked.Wait)
				assert.ErrorIs(t, err, policy.ErrAccountLocked)
			},
		},
		{
			name: "it matches no other sentinel",
			err:  &policy.LockoutError{},
			assert: func(t *testing.T, err error) {
				assert.NotErrorIs(t, err, policy.ErrPolicyDenied)
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
