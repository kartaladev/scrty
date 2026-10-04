package session_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

func TestNewManager_DefaultStoreFollowsClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// offset places the manager's clock relative to the system clock.
		offset time.Duration
		// store is the explicit store option, nil for none.
		store func() session.ManagerOption
		// plain wraps the clock so that it only tells the time.
		plain bool
		// advance is how far the clock moves after the first session.
		advance time.Duration
		assert  func(t *testing.T, m *session.Manager, live string, removed int, err error)
	}

	const idle, absolute = 30 * time.Minute, time.Hour

	cases := []testCase{
		{
			name:    "a clock ahead of the system clock sweeps what it expired",
			offset:  365 * 24 * time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, m *session.Manager, live string, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				_, loadErr := m.Load(t.Context(), live)
				assert.NoError(t, loadErr, "the live session stays")
			},
		},
		{
			name:    "a clock behind the system clock keeps a live session",
			offset:  -365 * 24 * time.Hour,
			advance: 2 * time.Hour,
			assert: func(t *testing.T, m *session.Manager, live string, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed, "only the session the clock expired goes")
				_, loadErr := m.Load(t.Context(), live)
				assert.NoError(t, loadErr, "the live session stays")
			},
		},
		{
			name:    "a clock that only tells the time is followed too",
			offset:  -365 * 24 * time.Hour,
			plain:   true,
			advance: 0,
			assert: func(t *testing.T, m *session.Manager, live string, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
				_, loadErr := m.Load(t.Context(), live)
				assert.NoError(t, loadErr, "the live session loads")
			},
		},
		{
			name:    "an explicit store keeps its own clock",
			offset:  365 * 24 * time.Hour,
			store:   func() session.ManagerOption { return session.WithStore(session.NewMemoryStore()) },
			advance: 2 * time.Hour,
			assert: func(t *testing.T, _ *session.Manager, _ string, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed, "the consumer's store judges expiry on the system clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fc := clockwork.NewFakeClockAt(time.Now().Add(tc.offset))
			var clk clock.Clock = fc
			if tc.plain {
				clk = fixedClock{at: fc.Now()}
			}
			opts := []session.ManagerOption{
				session.WithClock(clk),
				session.WithIdleTimeout(idle),
				session.WithAbsoluteTimeout(absolute),
			}
			if tc.store != nil {
				opts = append(opts, tc.store())
			}
			m := managerFor(t, opts...)

			ctx := t.Context()
			_, err := m.Create(ctx, testUser)
			require.NoError(t, err)
			fc.Advance(tc.advance)
			liveSession, err := m.Create(ctx, testUser)
			require.NoError(t, err)

			removed, err := m.DeleteExpired(ctx)
			tc.assert(t, m, liveSession.ID, removed, err)
		})
	}
}
