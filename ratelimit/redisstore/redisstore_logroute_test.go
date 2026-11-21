package redisstore_test

// TestLogRoute_Limiter replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. The tests of this
// module run on a recording client, so none needs a container.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/ratelimit/redisstore"
)

func TestLogRoute_Limiter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	newBuf := func() (*bytes.Buffer, *slog.Logger) {
		buf := &bytes.Buffer{}

		return buf, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// verify makes the limiter log: the server will not tell its eviction
	// policy, which Verify warns about and passes.
	verify := func(t *testing.T, ctx context.Context, opts ...redisstore.Option) {
		t.Helper()

		client, rec := recordingClient(t, int64(1))
		rec.info = "# Server\r\nredis_version:8.0.0\r\n"
		rec.configErr = serverError("ERR unknown command 'CONFIG'")

		l, err := redisstore.NewLimiter(client, "api-key", 5, time.Minute, opts...)
		require.NoError(t, err)
		require.NoError(t, l.Verify(ctx))
	}

	const record = "maxmemory-policy could not be read"

	tests := []struct {
		name   string
		ctx    func(t *testing.T, chain *slog.Logger) context.Context
		opts   func(own *slog.Logger) []redisstore.Option
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name: "no option, inside a configured chain",
			ctx:  func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) },
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, record)
				assert.Empty(t, def)
			},
		},
		{
			name: "own option wins",
			ctx:  func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) },
			opts: func(own *slog.Logger) []redisstore.Option { return []redisstore.Option{redisstore.WithLogger(own)} },
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainBuf, chain := newBuf()
			ownBuf, own := newBuf()
			defBuf, def := newBuf()

			prev := slog.Default()
			slog.SetDefault(def)
			t.Cleanup(func() { slog.SetDefault(prev) })

			var opts []redisstore.Option
			if tt.opts != nil {
				opts = tt.opts(own)
			}

			verify(t, tt.ctx(t, chain), opts...)

			tt.assert(t, chainBuf.String(), ownBuf.String(), defBuf.String())
		})
	}

	t.Run("nil option", func(t *testing.T) {
		client, _ := recordingClient(t, int64(1))

		_, err := redisstore.NewLimiter(client, "api-key", 5, time.Minute, redisstore.WithLogger(nil))

		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.ErrorContains(t, err, "WithLogger")
	})
}
