package diag_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/diag"
)

// cycleOne contains itself through Unwrap() error.
type cycleOne struct{}

func (*cycleOne) Error() string   { return "cycle one" }
func (c *cycleOne) Unwrap() error { return c }

// cycleMany contains itself through Unwrap() []error. Stdlib errors.Is and
// errors.As recurse into it until the stack overflows, which kills the
// process, so its rows run in a child process.
type cycleMany struct{}

func (*cycleMany) Error() string     { return "cycle many" }
func (c *cycleMany) Unwrap() []error { return []error{c} }

// panicUnwrap is a link whose Unwrap panics.
type panicUnwrap struct{}

func (panicUnwrap) Error() string { return "panic unwrap" }
func (panicUnwrap) Unwrap() error { panic("test: the link's Unwrap panicked") }

// isPanics is a link whose own Is method panics.
type isPanics struct{}

func (isPanics) Error() string { return "is panics" }
func (isPanics) Is(error) bool { panic("test: the link's Is panicked") }

// asPanics is a link whose own As method panics.
type asPanics struct{}

func (asPanics) Error() string { return "as panics" }
func (asPanics) As(any) bool   { panic("test: the link's As panicked") }

// flipFault answers a fault around itself on every odd call of its Unwrap and
// nothing on every even one, so each single walk of it is short and finite,
// while looking for the innermost fault's cause again and again never ends.
type flipFault struct{ calls atomic.Int64 }

func (*flipFault) Error() string { return "flip fault" }

func (f *flipFault) Unwrap() error {
	if f.calls.Add(1)%2 == 1 {
		return diag.Wrap(f, "scrty: flip")
	}

	return nil
}

// selfFault answers a fresh fault around itself on every call of its Unwrap,
// so looking for the innermost fault's cause finds another one each time.
type selfFault struct{}

func (*selfFault) Error() string   { return "self fault" }
func (s *selfFault) Unwrap() error { return diag.Wrap(s, "scrty: self") }

// fanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func fanOut(depth int) error {
	err := errors.New("leaf")
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// hostileRowEnv names the row a child process runs. It is empty in the parent.
const hostileRowEnv = "SCRTY_DIAG_HOSTILE_ROW"

// hostileRanMarker prefixes the line a child prints on stdout, followed by the
// row's name, only after the row ran and passed. A child whose row name
// matches no case skips every row and exits 0, so only this line proves a row
// ran. Stdout reaches the parent's CombinedOutput without -v.
const hostileRanMarker = "SCRTY_DIAG_HOSTILE_RAN: "

// announceRan arranges for a child's row subtest to print the marker for row
// once it has finished, if it neither failed nor skipped. It does nothing in
// the parent, where only is empty. A cleanup runs after the subtest's own
// parallel work, so the row has really completed.
func announceRan(t *testing.T, only, row string) {
	t.Helper()

	if only == "" {
		return
	}

	t.Cleanup(func() {
		if !t.Failed() && !t.Skipped() {
			_, _ = os.Stdout.WriteString(hostileRanMarker + row + "\n")
		}
	})
}

// requireChildRan fails unless one whole line of the child's output is the
// marker for row: not a substring, so a suffix or a prefix does not count.
func requireChildRan(t *testing.T, out []byte, row string) {
	t.Helper()

	want := hostileRanMarker + row

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimRight(line, "\r") == want {
			return
		}
	}

	require.Fail(t, "the child never ran the row: its name matches no case",
		"row %q: no output line equals %q", row, want)
}

// childRow is the row this process runs as a child, or "" in the parent. A
// child lowers the stack limit, so an unbounded recursion overflows quickly.
func childRow() string {
	row := os.Getenv(hostileRowEnv)
	if row != "" {
		debug.SetMaxStack(64 << 20)
	}

	return row
}

// inChild re-runs the current top-level test in a child process, limited to
// row, and fails unless the child exits 0 within a minute. A stack overflow
// is fatal and cannot be recovered, so only a child can watch for one.
func inChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), hostileRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")
	require.NoError(t, err, "the child failed:\n%s", head(out))
	requireChildRan(t, out, row)
}

// head is the first lines of a child's output, where a fatal error or a failed
// assertion says why it failed.
func head(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	return strings.Join(lines[:min(len(lines), 8)], "\n")
}

// within runs call on its own goroutine and fails the test when it does not
// return within two seconds or lets a panic escape.
func within[T any](t *testing.T, call func() T) T {
	t.Helper()

	type result struct {
		got      T
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- result{panicked: true, value: recover()}
			}
		}()

		got := call()
		returned = true
		done <- result{got: got}
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a panic escaped: %v", r.value)

		return r.got
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the call did not return within 2s")

		var zero T

		return zero
	}
}

// TestFailure_HostileChains pins that Failure's look into an error is bounded
// and recovering: an error it cannot walk is recorded by reason and outermost
// type, without the cancelled attribute, since nothing in an unwalkable chain
// can show the caller hung up. It returns, and nothing panics.
func TestFailure_HostileChains(t *testing.T) {
	t.Parallel()

	only := childRow()

	type testCase struct {
		name       string
		err        func() error
		subprocess bool
		assert     func(t *testing.T, attrs []slog.Attr)
	}

	notCancelled := func(errorType string) func(t *testing.T, attrs []slog.Attr) {
		return func(t *testing.T, attrs []slog.Attr) {
			t.Helper()

			values := attrValues(t, attrs)
			assert.Len(t, values, 2)
			assert.Equal(t, "attempt-store", values["reason"].String())
			assert.Equal(t, errorType, values["error_type"].String())
			assert.NotContains(t, values, "cancelled")
		}
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, assert: notCancelled("*diag_test.cycleOne")},
		{name: "a cycle through Unwrap() []error", err: func() error { return &cycleMany{} }, subprocess: true, assert: notCancelled("*diag_test.cycleMany")},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }, assert: notCancelled("*fmt.wrapError")},
		{name: "a link whose Is panics", err: func() error { return fmt.Errorf("x: %w", isPanics{}) }, assert: notCancelled("*fmt.wrapError")},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, assert: notCancelled("*errors.joinError")},
		{
			name:   "a cancellation beside a cycle is not flagged, since the walk did not finish",
			err:    func() error { return errors.Join(context.Canceled, &cycleOne{}) },
			assert: notCancelled("*errors.joinError"),
		},
		{
			name: "a walkable wrapped cancellation inside a fault is flagged and typed by the cause, as before",
			err: func() error {
				return diag.Wrap(fmt.Errorf("store: %w", context.Canceled), "scrty: inner", errUnavailable)
			},
			assert: func(t *testing.T, attrs []slog.Attr) {
				values := attrValues(t, attrs)
				require.Contains(t, values, "cancelled")
				assert.True(t, values["cancelled"].Bool())
				assert.Equal(t, "*fmt.wrapError", values["error_type"].String())
			},
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.subprocess && only == "" {
				inChild(t, tc.name)

				return
			}

			announceRan(t, only, tc.name)
			t.Parallel()

			err := tc.err()
			tc.assert(t, within(t, func() []slog.Attr { return diag.Failure("attempt-store", err) }))
		})
	}
}

// TestCauseOf_HostileChains pins that looking for the innermost fault's cause
// is bounded and recovering: an error it cannot walk is its own answer, so a
// record names its outermost type. A walkable error is answered as before.
func TestCauseOf_HostileChains(t *testing.T) {
	t.Parallel()

	only := childRow()

	type testCase struct {
		name       string
		err        func() error
		subprocess bool
		assert     func(t *testing.T, err, got error)
	}

	unchanged := func(t *testing.T, err, got error) {
		t.Helper()
		assert.True(t, err == got, "got %T, want the error itself", got) //nolint:errorlint // identity
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, assert: unchanged},
		{name: "a cycle through Unwrap() []error", err: func() error { return &cycleMany{} }, subprocess: true, assert: unchanged},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }, assert: unchanged},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, assert: unchanged},
		{name: "a fault whose cause cycles", err: func() error { return diag.Wrap(&cycleOne{}, "scrty: outer") }, assert: unchanged},
		{name: "a fault whose cause's Unwrap panics", err: func() error { return diag.Wrap(panicUnwrap{}, "scrty: outer") }, assert: unchanged},
		{name: "an Unwrap that answers a fresh fault around itself", err: func() error { return &selfFault{} }, assert: unchanged},
		{name: "an Unwrap that answers a fault on every other call", err: func() error { return &flipFault{} }, assert: unchanged},
		{
			// The outer value differs from every cause the descent reaches, so a
			// partial cause returned at the cap cannot pass for err itself.
			name:   "a wrapped Unwrap that answers a fresh fault around itself is err itself, not the partial cause",
			err:    func() error { return fmt.Errorf("x: %w", &selfFault{}) },
			assert: unchanged,
		},
		{
			name:   "a wrapped Unwrap that answers a fault on every other call is err itself, not the partial cause",
			err:    func() error { return fmt.Errorf("x: %w", &flipFault{}) },
			assert: unchanged,
		},
		{
			name:   "an As that panics inside a fault's cause is err itself, not the partial cause",
			err:    func() error { return diag.Wrap(fmt.Errorf("x: %w", asPanics{}), "scrty: outer") },
			assert: unchanged,
		},
		{
			name: "a walkable fault around a fault is answered by the innermost cause, as before",
			err: func() error {
				return fmt.Errorf("x: %w", diag.Wrap(diag.Wrap(&storeError{detail: causeText}, "scrty: inner"), "scrty: outer"))
			},
			assert: func(t *testing.T, _, got error) {
				var cause *storeError
				require.ErrorAs(t, got, &cause)
				assert.True(t, got == error(cause), "got %T, want the innermost cause", got) //nolint:errorlint // identity
			},
		},
		{
			name:   "a fault built without a cause is its own answer, as before",
			err:    func() error { return &diag.Fault{} },
			assert: unchanged,
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.subprocess && only == "" {
				inChild(t, tc.name)

				return
			}

			announceRan(t, only, tc.name)
			t.Parallel()

			err := tc.err()
			tc.assert(t, err, within(t, func() error { return diag.CauseOf(err) }))
		})
	}
}
