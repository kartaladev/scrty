package onetime_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/onetime"
)

func TestNewManager_DefaultStoreFollowsClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// offset places the manager's clock relative to the system clock.
		offset time.Duration
		// store is the explicit store option, nil for none.
		store func(clk clockwork.Clock) onetime.Option
		// window is the issuance window.
		window time.Duration
		// advance is how far the clock moves after issuing.
		advance time.Duration
		assert  func(t *testing.T, m *onetime.Manager, token string, purged int, err error)
	}

	cases := []testCase{
		{
			name:    "a clock ahead of the system clock purges what it expired",
			offset:  365 * 24 * time.Hour,
			window:  time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, _ *onetime.Manager, _ string, purged int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, purged)
			},
		},
		{
			name:    "a clock behind the system clock keeps a live token",
			offset:  -365 * 24 * time.Hour,
			window:  10 * time.Minute,
			advance: 12 * time.Minute,
			assert: func(t *testing.T, m *onetime.Manager, token string, purged int, err error) {
				require.NoError(t, err)
				assert.Zero(t, purged, "a token inside its lifetime must not be purged")
				_, checkErr := m.Check(t.Context(), token, "")
				assert.NoError(t, checkErr, "the token is still live")
			},
		},
		{
			name:   "an explicit store keeps its own clock",
			offset: 365 * 24 * time.Hour,
			store: func(clockwork.Clock) onetime.Option {
				return onetime.WithStore(onetime.NewMemoryStore())
			},
			window:  time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, _ *onetime.Manager, _ string, purged int, err error) {
				require.NoError(t, err)
				assert.Zero(t, purged, "the consumer's store judges expiry on its own clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fc := clockwork.NewFakeClockAt(time.Now().Add(tc.offset))
			opts := []onetime.Option{
				onetime.WithClock(fc),
				onetime.WithTTL(15 * time.Minute),
				onetime.WithIssuanceWindow(tc.window),
			}
			if tc.store != nil {
				opts = append(opts, tc.store(fc))
			}
			m, err := onetime.NewManager("email-change", opts...)
			require.NoError(t, err)

			ctx := t.Context()
			token, _, err := m.Issue(ctx, "carol")
			require.NoError(t, err)
			fc.Advance(tc.advance)

			purged, err := m.PurgeExpired(ctx)
			tc.assert(t, m, token, purged, err)
		})
	}
}
