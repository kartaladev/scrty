package depfault_test

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/pkg/id"
)

// countingHandler counts the records it is handed and keeps each one's
// "reason" attribute.
type countingHandler struct {
	mu      sync.Mutex
	n       int
	reasons []string
}

func (*countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.n++

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "reason" {
			h.reasons = append(h.reasons, a.Value.String())
		}

		return true
	})

	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.n
}

// TestSilentAndStore_RecordOnAbort pins what reading a hostile chain writes:
// Silent writes no record of an aborted walk, since the classification of the
// same refusal reports it, and the Store decorator writes exactly one, on
// slog.Default(), with the abort's reason, because it hands the store's error
// to the sanitizer. A chain the sanitizer's walk completes (it never calls an
// Is that panics) writes none.
//
// It is not parallel: it swaps slog.Default(), which is process-wide.
//
//nolint:paralleltest // see above
func TestSilentAndStore_RecordOnAbort(t *testing.T) {
	type testCase struct {
		name        string
		err         func() error
		storeReason string // "" means the Store writes no record
	}

	// cycleMany is left out: it overflows the stack of an unbounded walk, which
	// the hostile-chain tests watch from a child process.
	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, storeReason: "budget"},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }, storeReason: "panic"},
		{name: "a link whose Is panics", err: func() error { return fmt.Errorf("x: %w", isPanics{}) }},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, storeReason: "budget"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := new(countingHandler)
			prev := slog.Default()
			slog.SetDefault(slog.New(h))
			t.Cleanup(func() { slog.SetDefault(prev) })

			err := tc.err()

			_ = within(t, func() bool { return depfault.Silent(t.Context(), err) })
			assert.Zero(t, h.count(), "Silent wrote a record of the abort")

			ctx, _ := depfault.Watching(t.Context())
			s := depfault.Store(failingStore{findErr: err}, nil)
			_ = within(t, func() error { _, got := s.FindByID(ctx, id.Nil); return got })

			if tc.storeReason == "" {
				assert.Zero(t, h.count(), "the Store wrote a record for a chain the walk completes")

				return
			}

			assert.Equal(t, 1, h.count(), "the Store did not write exactly one abort record")
			h.mu.Lock()
			defer h.mu.Unlock()
			assert.Equal(t, []string{tc.storeReason}, h.reasons)
		})
	}
}
