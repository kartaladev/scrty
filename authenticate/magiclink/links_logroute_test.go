package magiclink_test

// TestLogRoute_Links replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

func TestLogRoute_Links(t *testing.T) {
	newBuf := func() (*bytes.Buffer, *slog.Logger) {
		buf := &bytes.Buffer{}

		return buf, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// request makes the manager log: the token store refuses the issuance.
	request := func(t *testing.T, ctx context.Context, opts ...magiclink.Option) {
		t.Helper()

		m, err := magiclink.New(tokensWithFailingStore(t), activeLoader(), &recordingSender{},
			"https://app.example.com", opts...)
		require.NoError(t, err)

		m.Request(ctx, "ada@example.com", "")
	}

	tests := []struct {
		name   string
		ctx    func(chain *slog.Logger) context.Context
		opts   func(own *slog.Logger) []magiclink.Option
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name: "no option, inside a configured chain",
			ctx:  func(chain *slog.Logger) context.Context { return ctxlog.With(context.Background(), chain) },
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, "magiclink:")
				assert.Empty(t, def)
			},
		},
		{
			name: "own option wins",
			ctx:  func(chain *slog.Logger) context.Context { return ctxlog.With(context.Background(), chain) },
			opts: func(own *slog.Logger) []magiclink.Option { return []magiclink.Option{magiclink.WithLogger(own)} },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, "magiclink:")
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			ctx:  func(*slog.Logger) context.Context { return context.Background() },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, def, "magiclink:")
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

			var opts []magiclink.Option
			if tt.opts != nil {
				opts = tt.opts(own)
			}

			request(t, tt.ctx(chain), opts...)

			tt.assert(t, chainBuf.String(), ownBuf.String(), defBuf.String())
		})
	}

	t.Run("nil option", func(t *testing.T) {
		_, err := newManager(t, "https://app.example.com", magiclink.WithLogger(nil))

		require.ErrorIs(t, err, magiclink.ErrConfig)
		assert.ErrorContains(t, err, "WithLogger")
	})
}
