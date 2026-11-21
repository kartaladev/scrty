package signingkey_test

// TestLogRoute_Keys replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/token/signingkey"
)

// lrCycle is an error whose chain contains itself, which the manager cannot
// walk and so writes one abort record about, at construction, on the
// caller's goroutine.
type lrCycle struct{}

func (*lrCycle) Error() string   { return "lr: cycle" }
func (c *lrCycle) Unwrap() error { return c }

func TestLogRoute_Keys(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	newBuf := func() (*bytes.Buffer, *slog.Logger) {
		buf := &bytes.Buffer{}

		return buf, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// construct makes the manager log: the store's listing fails with a chain
	// that cannot be walked.
	construct := func(t *testing.T, ctx context.Context, opts ...signingkey.Option) {
		t.Helper()

		store := NewMockKeyStore(gomock.NewController(t))
		store.EXPECT().LoadAll(gomock.Any()).Return(nil, &lrCycle{})

		_, err := signingkey.New(ctx, append([]signingkey.Option{signingkey.WithKeyStore(store)}, opts...)...)
		require.Error(t, err)
	}

	tests := []struct {
		name   string
		ctx    func(t *testing.T, chain *slog.Logger) context.Context
		opts   func(own *slog.Logger) []signingkey.Option
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name: "no option, inside a configured chain",
			ctx:  func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) },
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, porterr.MsgClassificationAborted)
				assert.Empty(t, def)
			},
		},
		{
			name: "own option wins",
			ctx:  func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) },
			opts: func(own *slog.Logger) []signingkey.Option { return []signingkey.Option{signingkey.WithLogger(own)} },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, porterr.MsgClassificationAborted)
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			ctx:  func(t *testing.T, _ *slog.Logger) context.Context { return t.Context() },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, def, porterr.MsgClassificationAborted)
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

			var opts []signingkey.Option
			if tt.opts != nil {
				opts = tt.opts(own)
			}

			construct(t, tt.ctx(t, chain), opts...)

			tt.assert(t, chainBuf.String(), ownBuf.String(), defBuf.String())
		})
	}

	t.Run("nil option", func(t *testing.T) {
		_, err := signingkey.New(t.Context(), signingkey.WithLogger(nil))

		require.ErrorIs(t, err, signingkey.ErrConfig)
		assert.ErrorContains(t, err, "WithLogger")
	})
}
