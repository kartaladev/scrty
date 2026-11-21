package diag_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/diag"
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

// TestFailureAndCauseOf_WriteNoRecordOnAbort pins that reading a hostile chain
// is silent: Failure and causeOf return, and write no record of the abort,
// since the record their caller writes is the one that tells the failure and
// the classification of the same error reports the abort.
//
// It is not parallel: it swaps slog.Default(), which is process-wide.
//
//nolint:paralleltest // see above
func TestFailureAndCauseOf_WriteNoRecordOnAbort(t *testing.T) {
	type testCase struct {
		name   string
		err    func() error
		assert func(t *testing.T, records int)
	}

	none := func(t *testing.T, records int) {
		t.Helper()
		assert.Zero(t, records, "reading a hostile chain wrote a record")
	}

	// cycleMany is left out: it overflows the stack of an unbounded walk, which
	// the hostile-chain tests watch from a child process.
	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, assert: none},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }, assert: none},
		{name: "a link whose Is panics", err: func() error { return fmt.Errorf("x: %w", isPanics{}) }, assert: none},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, assert: none},
		{name: "a fault whose cause cycles", err: func() error { return diag.Wrap(&cycleOne{}, "scrty: outer") }, assert: none},
		{name: "an Unwrap that answers a fresh fault around itself", err: func() error { return &selfFault{} }, assert: none},
		// These three get past the first walk and abort inside causeOf's descent.
		{name: "a wrapped Unwrap that answers a fresh fault around itself", err: func() error { return fmt.Errorf("x: %w", &selfFault{}) }, assert: none},
		{name: "a wrapped Unwrap that answers a fault on every other call", err: func() error { return fmt.Errorf("x: %w", &flipFault{}) }, assert: none},
		{name: "an As that panics inside a fault's cause", err: func() error { return diag.Wrap(fmt.Errorf("x: %w", asPanics{}), "scrty: outer") }, assert: none},
		{name: "a walkable error", err: func() error { return errors.New("plain") }, assert: none},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := new(countingHandler)
			prev := slog.Default()
			slog.SetDefault(slog.New(h))
			t.Cleanup(func() { slog.SetDefault(prev) })

			err := tc.err()
			_ = within(t, func() []slog.Attr { return diag.Failure("attempt-store", err) })
			_ = within(t, func() error { return diag.CauseOf(err) })

			tc.assert(t, h.count())
		})
	}
}
