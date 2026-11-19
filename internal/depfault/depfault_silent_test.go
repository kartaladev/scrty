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

// countingHandler counts the records it is handed.
type countingHandler struct {
	mu sync.Mutex
	n  int
}

func (*countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.n++

	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.n
}

// TestSilentAndStore_WriteNoRecordOnAbort pins that reading a hostile chain is
// silent: Silent and the Store decorator's recording of a store failure write
// no record of the abort, since the classification of the same refusal reports
// it.
//
// It is not parallel: it swaps slog.Default(), which is process-wide.
//
//nolint:paralleltest // see above
func TestSilentAndStore_WriteNoRecordOnAbort(t *testing.T) {
	type testCase struct {
		name string
		err  func() error
	}

	// cycleMany is left out: it overflows the stack of an unbounded walk, which
	// the hostile-chain tests watch from a child process.
	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }},
		{name: "a link whose Is panics", err: func() error { return fmt.Errorf("x: %w", isPanics{}) }},
		{name: "a join that fans out", err: func() error { return fanOut(25) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := new(countingHandler)
			prev := slog.Default()
			slog.SetDefault(slog.New(h))
			t.Cleanup(func() { slog.SetDefault(prev) })

			err := tc.err()

			_ = within(t, func() bool { return depfault.Silent(t.Context(), err) })

			// The decorator's record helper runs on the store's answer.
			ctx, _ := depfault.Watching(t.Context())
			s := depfault.Store(failingStore{findErr: err})
			_ = within(t, func() error { _, got := s.FindByID(ctx, id.Nil); return got })

			assert.Zero(t, h.count(), "reading a hostile chain wrote a record")
		})
	}
}
