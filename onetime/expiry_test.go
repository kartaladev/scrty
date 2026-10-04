package onetime_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
)

var expiryEpoch = time.Date(2026, time.March, 2, 9, 0, 0, 0, time.UTC)

// storeOnly hides everything but the Store contract, so a wrapped store has no
// Reaper.
type storeOnly struct{ onetime.Store }

// expiryManager builds a manager of purpose over store and clk, with the explicit
// lifetime (15m) and issuance window (1h) the cases reason about.
func expiryManager(t *testing.T, purpose string, store onetime.Store, clk clockwork.Clock) *onetime.Manager {
	t.Helper()

	m, err := onetime.NewManager(purpose,
		onetime.WithStore(store),
		onetime.WithClock(clk),
		onetime.WithTTL(15*time.Minute),
		onetime.WithIssuanceWindow(time.Hour),
	)
	require.NoError(t, err)

	return m
}

func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) (expiry.Task, func(t *testing.T))
		assert func(t *testing.T, task expiry.Task, removed int, err error)
	}

	cases := []testCase{
		{
			name: "an expired token inside the issuance window is kept and the count unchanged",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
				m := expiryManager(t, "email-change", store, clk)

				_, _, err := m.Issue(t.Context(), "carol")
				require.NoError(t, err)
				clk.Advance(30 * time.Minute) // past the 15m lifetime, inside the 1h window

				return onetime.ExpiryTask(m), func(t *testing.T) {
					n, err := m.IssuedCount(t.Context(), "carol")
					require.NoError(t, err)
					assert.Equal(t, 1, n, "a sweep must not free issuance quota")
					assert.Equal(t, 1, store.Len())
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
		{
			name: "an expired token past the issuance window is removed",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
				m := expiryManager(t, "email-change", store, clk)

				_, _, err := m.Issue(t.Context(), "carol")
				require.NoError(t, err)
				clk.Advance(2 * time.Hour)

				return onetime.ExpiryTask(m), func(t *testing.T) { assert.Zero(t, store.Len()) }
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "separate purposes stay separate",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
				mine := expiryManager(t, "email-change", store, clk)
				other := expiryManager(t, "magic-link", store, clk)

				for _, m := range []*onetime.Manager{mine, other} {
					_, _, err := m.Issue(t.Context(), "carol")
					require.NoError(t, err)
				}
				clk.Advance(2 * time.Hour)

				return onetime.ExpiryTask(mine), func(t *testing.T) {
					assert.Equal(t, 1, store.Len(), "the other purpose's record stays")
				}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "a store that cannot purge matches both sentinels",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := storeOnly{onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}

				return onetime.ExpiryTask(expiryManager(t, "email-change", store, clk)), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
		{
			name: "name carries the purpose and no interval is set",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				m := expiryManager(t, "email-change", onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)), clk)

				return onetime.ExpiryTask(m), func(*testing.T) {}
			},
			assert: func(t *testing.T, task expiry.Task, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "one-time-tokens:email-change", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "a chosen name replaces the default and the body is shared",
			setup: func(t *testing.T) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryEpoch)
				store := storeOnly{onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}

				return onetime.ExpiryTaskNamed("magiclink-tokens", expiryManager(t, "magic-link", store, clk)), func(*testing.T) {}
			},
			assert: func(t *testing.T, task expiry.Task, _ int, err error) {
				assert.Equal(t, "magiclink-tokens", task.Name)
				assert.Zero(t, task.Interval)
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
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
