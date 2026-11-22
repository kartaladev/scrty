package ratelimit_test

// TestLogRoute_SourceGuard and TestLogRoute_MemoryLimiter replace
// slog.Default() for their duration, so they do not run in parallel, and each
// restores the logger it found.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/ratelimit"
)

// lrBuf returns a logger writing to a buffer, and the buffer.
func lrBuf() (*bytes.Buffer, *slog.Logger) {
	buf := &bytes.Buffer{}

	return buf, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// lrRoute is one routing row: how the request's context is built, and what
// the three destinations hold afterwards.
type lrRoute[O any] struct {
	name   string
	ctx    func(t *testing.T, chain *slog.Logger) context.Context
	opts   func(own *slog.Logger) []O
	assert func(t *testing.T, chain, own, def string)
}

func lrRoutes[O any](record string, withOwn func(*slog.Logger) O) []lrRoute[O] {
	inChain := func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) }

	return []lrRoute[O]{
		{
			name: "no option, inside a configured chain",
			ctx:  inChain,
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, record)
				assert.Empty(t, def)
			},
		},
		{
			name: "own option wins",
			ctx:  inChain,
			opts: func(own *slog.Logger) []O { return []O{withOwn(own)} },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, record)
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			ctx:  func(t *testing.T, _ *slog.Logger) context.Context { return t.Context() },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, def, record)
				assert.Empty(t, chain)
				assert.Empty(t, own)
			},
		},
	}
}

func runLRRoutes[O any](t *testing.T, routes []lrRoute[O], act func(t *testing.T, ctx context.Context, opts []O)) {
	t.Helper()

	for _, tt := range routes {
		t.Run(tt.name, func(t *testing.T) {
			chainBuf, chain := lrBuf()
			ownBuf, own := lrBuf()
			defBuf, def := lrBuf()

			prev := slog.Default()
			slog.SetDefault(def)
			t.Cleanup(func() { slog.SetDefault(prev) })

			var opts []O
			if tt.opts != nil {
				opts = tt.opts(own)
			}

			act(t, tt.ctx(t, chain), opts)

			tt.assert(t, chainBuf.String(), ownBuf.String(), defBuf.String())
		})
	}
}

func TestLogRoute_SourceGuard(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	routes := lrRoutes("refusing an attempt from a source over its limit", ratelimit.WithSourceGuardLogger)

	runLRRoutes(t, routes, func(t *testing.T, ctx context.Context, opts []ratelimit.GuardOption) {
		t.Helper()

		l := NewMockLimiter(gomock.NewController(t))
		l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil)

		g, err := ratelimit.NewSourceGuard(testFlow, l, opts...)
		require.NoError(t, err)

		_, err = g.Check(ctx, testSource)
		require.ErrorIs(t, err, ratelimit.ErrThrottled)
	})

	t.Run("nil option", func(t *testing.T) {
		l := NewMockLimiter(gomock.NewController(t))

		_, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(nil))

		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.ErrorContains(t, err, "WithSourceGuardLogger")
	})
}

func TestLogRoute_MemoryLimiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	routes := lrRoutes("counts only this replica", ratelimit.WithMemoryLimiterLogger)

	runLRRoutes(t, routes, func(t *testing.T, ctx context.Context, opts []ratelimit.MemoryOption) {
		t.Helper()

		l, err := ratelimit.NewMemoryLimiter(testLimit, time.Minute, opts...)
		require.NoError(t, err)

		_, err = l.Exceeded(ctx, "key")
		require.NoError(t, err)
	})

	t.Run("nil option", func(t *testing.T) {
		_, err := ratelimit.NewMemoryLimiter(testLimit, time.Minute, ratelimit.WithMemoryLimiterLogger(nil))

		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.ErrorContains(t, err, "WithMemoryLimiterLogger")
	})
}
