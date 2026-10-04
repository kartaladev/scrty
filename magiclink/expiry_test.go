package magiclink_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/onetime"
)

// noPurgeStore hides the reaper of the memory store, so the store it wraps
// can insert and count but cannot purge.
type noPurgeStore struct {
	onetime.Store
}

func TestExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// store is the token store; nil means a purge-capable memory store.
		store func(clock *clockwork.FakeClock) onetime.Store
		// age is how long ago carol's one token was issued.
		age    time.Duration
		assert func(t *testing.T, task expiry.Task, tokens *onetime.Manager, removed int, err error)
	}

	cases := []testCase{
		{
			name: "a token expired but inside the issuance window is kept and still counted",
			age:  30 * time.Minute,
			assert: func(t *testing.T, _ expiry.Task, tokens *onetime.Manager, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)

				n, cerr := tokens.IssuedCount(t.Context(), "carol")
				require.NoError(t, cerr)
				assert.Equal(t, 1, n, "a sweep freed issuance quota")
			},
		},
		{
			name: "a token expired and past the issuance window is deleted",
			age:  2 * time.Hour,
			assert: func(t *testing.T, _ expiry.Task, _ *onetime.Manager, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "the task is named magiclink-tokens and sets no interval",
			age:  time.Minute,
			assert: func(t *testing.T, task expiry.Task, _ *onetime.Manager, _ int, err error) {
				require.NoError(t, err)
				assert.Equal(t, "magiclink-tokens", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "a store that cannot purge matches ErrPurgeUnsupported",
			store: func(clock *clockwork.FakeClock) onetime.Store {
				return noPurgeStore{Store: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clock))}
			},
			age: 2 * time.Hour,
			assert: func(t *testing.T, _ expiry.Task, _ *onetime.Manager, removed int, err error) {
				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
			var store onetime.Store = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
			if tc.store != nil {
				store = tc.store(clk)
			}

			tokens, err := onetime.NewManager("magic-link",
				onetime.WithStore(store), onetime.WithClock(clk),
				onetime.WithTTL(15*time.Minute), onetime.WithIssuanceWindow(time.Hour))
			require.NoError(t, err)

			_, _, err = tokens.Issue(t.Context(), "carol")
			require.NoError(t, err)
			clk.Advance(tc.age)

			m, err := magiclink.NewManager(tokens, stubLoader{}, &recordingSender{}, "https://app.example.com")
			require.NoError(t, err)

			task := magiclink.ExpiryTask(m)
			var removed int
			if task.Run != nil {
				removed, err = task.Run(t.Context())
			}
			tc.assert(t, task, tokens, removed, err)
		})
	}
}

func TestManager_PurgeExpired(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	tokens, err := onetime.NewManager("magic-link",
		onetime.WithStore(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))),
		onetime.WithClock(clk), onetime.WithTTL(15*time.Minute), onetime.WithIssuanceWindow(time.Hour))
	require.NoError(t, err)

	_, _, err = tokens.Issue(t.Context(), "carol")
	require.NoError(t, err)
	clk.Advance(2 * time.Hour)

	m, err := magiclink.NewManager(tokens, stubLoader{}, &recordingSender{}, "https://app.example.com")
	require.NoError(t, err)

	removed, err := m.PurgeExpired(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
}
