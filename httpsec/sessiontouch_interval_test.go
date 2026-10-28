package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// activityCountingStore counts the activity writes that reach the wrapped
// store.
type activityCountingStore struct {
	session.Store

	writes atomic.Int32
}

func (s *activityCountingStore) RecordActivity(
	ctx context.Context, sessionID string, lastAccessed, idleExpires, olderThan time.Time,
) error {
	s.writes.Add(1)

	return s.Store.RecordActivity(ctx, sessionID, lastAccessed, idleExpires, olderThan)
}

// TestSessionTouchHonoursTheManagersInterval pins that the chain's activity
// write-back goes through the manager's activity interval, so requests closer
// together than it persist activity once.
func TestSessionTouchHonoursTheManagersInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []session.Option
		assert func(t *testing.T, afterSecond, afterThird int32)
	}

	cases := []testCase{
		{
			name: "a one-minute interval persists two requests ten seconds apart once, and a third a minute later again",
			opts: []session.Option{session.WithTouchInterval(time.Minute)},
			assert: func(t *testing.T, afterSecond, afterThird int32) {
				assert.EqualValues(t, 1, afterSecond)
				assert.EqualValues(t, 2, afterThird)
			},
		},
		{
			name: "with no interval every request persists",
			assert: func(t *testing.T, afterSecond, afterThird int32) {
				assert.EqualValues(t, 2, afterSecond)
				assert.EqualValues(t, 3, afterThird)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
			store := &activityCountingStore{Store: session.NewMemoryStore(session.WithMemoryStoreClock(clk))}

			sessions, err := session.New(append([]session.Option{
				session.WithClock(clk), session.WithStore(store),
			}, tc.opts...)...)
			require.NoError(t, err)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
				Return(storedUser(), nil).AnyTimes()

			chain, err := httpsec.New(
				httpsec.WithClock(clk),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}))
			require.NoError(t, err)

			s, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			request := func() {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
				req.Header.Set("Authorization", "Bearer "+s.ID)

				out := serve(t, chain, req)
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)
			}

			// Just past the interval since the session's last recorded access,
			// so the first request's write is unambiguously due.
			clk.Advance(time.Minute + time.Second)
			request()
			clk.Advance(10 * time.Second)
			request()

			afterSecond := store.writes.Load()

			clk.Advance(50 * time.Second) // a minute after the first request
			request()

			tc.assert(t, afterSecond, store.writes.Load())
		})
	}
}
