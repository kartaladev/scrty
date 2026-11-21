package sweep_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/expiry/sweep"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// routeBuffer is a bytes.Buffer safe for concurrent writes.
type routeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *routeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *routeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func routeLogger(w *routeBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

const routeLockMessage = "sweep: distributed lock failed"

// TestLogRoute_Sweeper pins where a lock failure's record goes: the sweeper's
// own logger when given, else the logger of the chain the context handed to
// Start carries, else slog.Default() as it is when the record is written. It
// swaps the default logger, so it does not run in parallel.
func TestLogRoute_Sweeper(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	cases := []struct {
		name   string
		own    bool
		chain  bool
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, routeLockMessage)
				assert.Empty(t, def)
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, routeLockMessage)
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, _, def string) {
				assert.Contains(t, def, routeLockMessage)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var chain, own, def routeBuffer

			prev := slog.Default()
			slog.SetDefault(routeLogger(&def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			runner, err := expiry.NewRunner(
				[]expiry.Task{{Name: "sessions", Interval: time.Minute, Run: func(context.Context) (int, error) { return 0, nil }}},
				expiry.WithLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			locker := NewMockLocker(gomock.NewController(t))
			locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").Return(nil, errors.New("refused")).AnyTimes()

			fc := clockwork.NewFakeClock()
			opts := []sweep.Option{sweep.WithClock(fc), sweep.WithDistributedLocker(locker)}
			if tc.own {
				opts = append(opts, sweep.WithLogger(routeLogger(&own)))
			}

			s, err := sweep.New(runner, opts...)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}
			require.NoError(t, s.Start(ctx))

			wait, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, fc.BlockUntilContext(wait, 1))
			fc.Advance(time.Minute + time.Nanosecond)

			require.Eventually(t, func() bool {
				return chain.String()+own.String()+def.String() != ""
			}, 5*time.Second, 10*time.Millisecond)

			tc.assert(t, chain.String(), own.String(), def.String())
		})
	}
}
