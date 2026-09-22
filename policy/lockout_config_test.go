package policy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

func TestNewAccountLockoutPolicy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		assert func(t *testing.T, p *policy.AccountLockoutPolicy, err error)
	}

	var absentStore *policy.MemoryAttemptStore

	refused := func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
		t.Helper()

		require.ErrorIs(t, err, policy.ErrConfig)
		assert.Nil(t, p, "a refused configuration handed back a policy anyway")
	}

	cases := []testCase{
		{
			name: "no options construct the documented defaults",
			assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
				require.NoError(t, err)
				require.NotNil(t, p)
				assert.Equal(t, 5, p.Threshold())
				assert.Equal(t, 15*time.Minute, p.Window())
			},
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
