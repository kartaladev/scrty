package depfault_test

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/pkg/id"
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

// TestLogRoute_Store pins where the abort record of a store error whose chain
// cannot be walked goes: the logger handed to Store when there is one, else
// the logger of the chain the context carries, else slog.Default() as it is
// when the record is written. It swaps the default logger, so it does not run
// in parallel.
func TestLogRoute_Store(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const want = "budget"

	cases := []struct {
		name   string
		own    bool
		chain  bool
		assert func(t *testing.T, chain, own, def string)
	}{
		{
			name:  "no logger, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, chain, _, def string) {
				assert.Contains(t, chain, want)
				assert.Empty(t, def)
			},
		},
		{
			name:  "own logger wins",
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

			var logger *slog.Logger
			if tc.own {
				logger = routeLogger(&own)
			}

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, routeLogger(&chain))
			}

			s := depfault.Store(failingStore{findErr: &cycleOne{}}, logger)
			_, _ = s.FindByID(ctx, id.Nil)

			tc.assert(t, chain.String(), own.String(), def.String())
		})
	}
}
