package onetime_test

// TestLogRoute_Tokens replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/token/onetime"
)

func TestLogRoute_Tokens(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	newBuf := func() (*bytes.Buffer, *slog.Logger) {
		buf := &bytes.Buffer{}

		return buf, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// request makes the manager log: the store refuses the read Check makes.
	request := func(t *testing.T, ctx context.Context, opts ...onetime.Option) {
		t.Helper()

		store := NewMockStore(gomock.NewController(t))
		store.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(nil, errRedactionFixture)

		all := append([]onetime.Option{
			onetime.WithStore(store),
			onetime.WithClock(clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))),
		}, opts...)

		m, err := onetime.New("magic-link", all...)
		require.NoError(t, err)

		_, err = m.Check(ctx, checkTokenID.String()+"."+checkSecret, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
	}

	tests := []struct {
		name   string
		ctx    func(t *testing.T, chain *slog.Logger) context.Context
		opts   func(own *slog.Logger) []onetime.Option
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name: "no option, inside a configured chain",
			ctx:  func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) },
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, "onetime:")
				assert.Empty(t, def)
			},
		},
		{
			name: "own option wins",
			ctx:  func(t *testing.T, chain *slog.Logger) context.Context { return ctxlog.With(t.Context(), chain) },
			opts: func(own *slog.Logger) []onetime.Option { return []onetime.Option{onetime.WithLogger(own)} },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, "onetime:")
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			ctx:  func(t *testing.T, _ *slog.Logger) context.Context { return t.Context() },
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, def, "onetime:")
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

			var opts []onetime.Option
			if tt.opts != nil {
				opts = tt.opts(own)
			}

			request(t, tt.ctx(t, chain), opts...)

			tt.assert(t, chainBuf.String(), ownBuf.String(), defBuf.String())
		})
	}

	t.Run("nil option", func(t *testing.T) {
		_, err := onetime.New("magic-link", onetime.WithLogger(nil))

		require.ErrorIs(t, err, onetime.ErrConfig)
		assert.ErrorContains(t, err, "WithLogger")
	})
}
