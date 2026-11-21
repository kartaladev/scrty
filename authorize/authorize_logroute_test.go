package authorize_test

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
)

// azBuffer is a bytes.Buffer safe for the bounded goroutine a flow runs on.
type azBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *azBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *azBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func azJSON(w *azBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestLogRoute_Authorize pins that the abort record of a consumer function's
// error whose chain cannot be walked reaches the logger of the chain handling
// the request, and none reaches the default; with no chain it is written to
// slog.Default() as it is when the record is written. The package holds no
// logger option of its own. It swaps the default logger, so it does not run
// in parallel.
func TestLogRoute_Authorize(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	flows := []struct {
		name string
		flow azFlow
	}{
		{"FirstOf authorizer", azFirstOf},
		{"role loader", azPrivilegeLoad},
		{"ownership identifier resolver", azOwnership(true)},
		{"ownership check", azOwnership(false)},
		{"AnyOf requirement", azAnyOf},
	}

	for _, fc := range flows {
		for _, chain := range []bool{true, false} {
			name := fc.name + ", no chain"
			if chain {
				name = fc.name + ", inside a configured chain"
			}

			t.Run(name, func(t *testing.T) {
				def, onChain := &azBuffer{}, &azBuffer{}

				previous := slog.Default()
				t.Cleanup(func() { slog.SetDefault(previous) })
				slog.SetDefault(azJSON(def))

				ctx := t.Context()
				if chain {
					ctx = ctxlog.With(ctx, azJSON(onChain))
				}

				azBounded(ctx, t, fc.flow, &azCycleOne{})

				if chain {
					assert.Contains(t, onChain.String(), porterr.MsgClassificationAborted, "the chain's logger takes the record")
					assert.Empty(t, def.String(), "the default logger must see nothing")

					return
				}

				assert.Contains(t, def.String(), porterr.MsgClassificationAborted, "the default as swapped at record time")
			})
		}
	}
}
