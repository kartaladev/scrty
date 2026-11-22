package unavailable_test

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
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

// TestLogRoute_Unavailable pins where the fall-back transition record goes: the
// logger of the chain handling the request when the configuration names none,
// else the configuration's own logger, else slog.Default() as it is when the
// record is written. It swaps the default logger, so it does not run in
// parallel.
func TestLogRoute_Unavailable(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type result struct {
		chain, own, def string
		err             error
	}

	cases := []struct {
		name   string
		own    bool
		chain  bool
		assert func(t *testing.T, r result)
	}{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, r result) {
				require.NoError(t, r.err)
				assert.Contains(t, r.chain, msgFallBack)
				assert.Empty(t, r.def)
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, r result) {
				require.NoError(t, r.err)
				assert.Contains(t, r.own, msgFallBack)
				assert.Empty(t, r.chain)
				assert.Empty(t, r.def)
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, r result) {
				require.NoError(t, r.err)
				assert.Contains(t, r.def, msgFallBack)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var chain, own, def routeBuffer

			prev := slog.Default()
			slog.SetDefault(routeLogger(&def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			cfg := unavailable.DefaultConfig()
			cfg.Mode = ratelimit.UnavailableFallbackToLocal
			if tc.own {
				cfg.Logger = routeLogger(&own)
			}

			backend := NewMockLimiter(gomock.NewController(t))
			backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, errDown)

			l, err := unavailable.Wrap(backend, testNamespace, testLimit, testWindow, cfg)
			require.NoError(t, err)

			ctx := context.Background()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}
			_, _ = l.Exceeded(ctx, testKey)

			tc.assert(t, result{chain: chain.String(), own: own.String(), def: def.String()})
		})
	}
}

// TestLogRoute_Unavailable_NilLogger pins that a nil logger is a configuration
// error naming the logger.
func TestLogRoute_Unavailable_NilLogger(t *testing.T) {
	t.Parallel()

	cfg := unavailable.DefaultConfig()
	cfg.Logger = nil

	_, err := unavailable.Wrap(NewMockLimiter(gomock.NewController(t)), testNamespace, testLimit, testWindow, cfg)

	require.ErrorIs(t, err, ratelimit.ErrConfig)
	assert.Contains(t, err.Error(), "logger")
}
