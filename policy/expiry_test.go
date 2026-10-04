package policy_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/policy"
)

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
	sweeping := func(t *testing.T, window time.Duration, ago ...time.Duration) (*policy.AccountLockoutPolicy, func(t *testing.T) int) {
		t.Helper()

		store := newSweepingAttemptStore()
		p, err := policy.NewAccountLockoutPolicy(
			policy.WithLockoutClock(clockwork.NewFakeClockAt(lockoutNow)),
			policy.WithLockoutWindow(window),
			policy.WithAttemptStore(store),
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

				return policy.LockoutExpiryTask(p), func(t *testing.T) {
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

				return policy.LockoutExpiryTask(p), func(t *testing.T) { assert.Equal(t, 1, held(t)) }
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
		{
			name: "the default in-memory store reports purge unsupported, never zero and nil",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, err := policy.NewAccountLockoutPolicy(
					policy.WithLockoutClock(clockwork.NewFakeClockAt(lockoutNow)),
					policy.WithLockoutWindow(15*time.Minute),
				)
				require.NoError(t, err)

				return policy.LockoutExpiryTask(p), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, policy.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
		{
			name: "name is login-attempts and no interval is set",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				p, _ := sweeping(t, 15*time.Minute)

				return policy.LockoutExpiryTask(p), func(*testing.T) {}
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
