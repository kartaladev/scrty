package expiry_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
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

// TestLogRoute_Runner pins where a failed task's record goes: the runner's
// own logger when given, else the logger of the chain the context carries,
// else slog.Default() as it is when the record is written. It swaps the
// default logger, so it does not run in parallel.
func TestLogRoute_Runner(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const want = "expiry task failed"

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
				assert.Contains(t, chain, want)
				assert.Empty(t, def)
			},
		},
		{
			name:  "own option wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, want)
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, _, def string) {
				assert.Contains(t, def, want)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var chain, own, def routeBuffer

			prev := slog.Default()
			slog.SetDefault(routeLogger(&def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			var opts []expiry.Option
			if tc.own {
				opts = append(opts, expiry.WithLogger(routeLogger(&own)))
			}

			r, err := expiry.NewRunner([]expiry.Task{{
				Name: "sessions",
				Run:  func(context.Context) (int, error) { return 0, errors.New("store down") },
			}}, opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}
			_, _ = r.RunOnce(ctx)

			tc.assert(t, chain.String(), own.String(), def.String())
		})
	}
}

// TestLogRoute_Runner_NilLogger pins that a nil logger option fails
// construction, naming the option.
func TestLogRoute_Runner_NilLogger(t *testing.T) {
	t.Parallel()

	_, err := expiry.NewRunner([]expiry.Task{{
		Name: "sessions",
		Run:  func(context.Context) (int, error) { return 0, nil },
	}}, expiry.WithLogger(nil))

	require.ErrorIs(t, err, expiry.ErrInvalidOption)
	assert.Contains(t, err.Error(), "logger")
}
