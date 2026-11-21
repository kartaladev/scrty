package recovered_test

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/recovered"
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

// TestLogRoute_Recovered pins where the panic record goes: the given logger
// when there is one, else the logger of the chain the context carries, else
// slog.Default() as it is when the record is written. It swaps the default
// logger, so it does not run in parallel.
func TestLogRoute_Recovered(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	cases := []struct {
		name   string
		own    bool
		chain  bool
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name:  "nil logger, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, "consumer code panicked")
				assert.Empty(t, def)
			},
		},
		{
			name:  "own logger wins",
			own:   true,
			chain: true,
			assert: func(t *testing.T, chain, own, def string) {
				assert.Contains(t, own, "consumer code panicked")
				assert.Empty(t, chain)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, _, _, def string) {
				assert.Contains(t, def, "consumer code panicked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var chain, own, def routeBuffer

			prev := slog.Default()
			slog.SetDefault(routeLogger(&def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}

			var log *slog.Logger
			if tc.own {
				log = routeLogger(&own)
			}

			err := recovered.Call(ctx, log, "what", func() error { panic("boom") })
			require.ErrorIs(t, err, recovered.ErrPanicked)

			tc.assert(t, chain.String(), own.String(), def.String())
		})
	}
}
