package detach_test

// Every test here replaces slog.Default() for its duration, so none runs in
// parallel, and each restores the logger it found.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/porterr"
)

// hostileCauseRowEnv names the row a child process runs; empty in the parent.
const hostileCauseRowEnv = "SCRTY_DETACH_HOSTILE_CAUSE_ROW"

// hostileCauseRan is what a child prints once it has run its row, followed by
// the row's name. A child whose row matched nothing prints nothing, and its
// parent fails rather than passing on an empty run.
const hostileCauseRan = "detach-hostile-cause-row-ran:"

type cycleOne struct{}

func (*cycleOne) Error() string   { return "cycle one" }
func (c *cycleOne) Unwrap() error { return c }

type cycleMany struct{}

func (*cycleMany) Error() string     { return "cycle many" }
func (c *cycleMany) Unwrap() []error { return []error{c} }

type unwrapPanics struct{}

func (unwrapPanics) Error() string { return "unwrap panics" }
func (unwrapPanics) Unwrap() error { panic("the link's Unwrap panicked") }

type unwrapPanicsNil struct{}

func (unwrapPanicsNil) Error() string { return "unwrap panics nil" }
func (unwrapPanicsNil) Unwrap() error { panic(nil) } //nolint:govet // the row is panic(nil)

type isPanics struct{}

func (isPanics) Error() string { return "is panics" }
func (isPanics) Is(error) bool { panic("the link's Is panicked") }

type typedNil struct{}

func (*typedNil) Error() string { return "typed nil" }

// fanOut is a join nested depth deep, each level holding the one below twice.
func fanOut(depth int) error {
	err := errors.New("leaf")
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// recorder is a slog handler that keeps what it is given.
type recorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (*recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.recs = append(r.recs, rec)

	return nil
}
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

// aborts returns the reasons of the abort records seen.
func (r *recorder) aborts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var reasons []string

	for _, rec := range r.recs {
		if rec.Message != porterr.MsgClassificationAborted {
			continue
		}

		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == "reason" {
				reasons = append(reasons, a.Value.String())
			}

			return true
		})
	}

	return reasons
}

// swapDefault replaces slog.Default() and restores it on cleanup.
func swapDefault(t *testing.T) *recorder {
	t.Helper()

	rec := &recorder{}
	prev := slog.Default()

	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

// causeCtx is a context cancelled with cause.
func causeCtx(t *testing.T, cause error) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(cause)

	return ctx
}

// boundCause returns the cause a passed Bounded context ends with.
func boundCause(t *testing.T) error {
	t.Helper()

	ctx, cancel := detach.Bounded(t.Context(), time.Nanosecond)
	defer cancel()

	<-ctx.Done()

	return context.Cause(ctx)
}

// boundReachedWithin asks BoundReached on its own goroutine and fails when it
// does not return within two seconds or lets a panic escape. A stack overflow
// still kills the process, which only a child can watch for.
func boundReachedWithin(ctx context.Context, t *testing.T) bool {
	t.Helper()

	type result struct {
		got      bool
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

		got := detach.BoundReached(ctx)
		returned = true
		done <- result{got: got}
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a panic escaped BoundReached: %v", r.value)

		return r.got
	case <-time.After(2 * time.Second):
		t.Fatal("BoundReached did not return within 2s")

		return false
	}
}

// TestBoundReached_CauseIsConsumerInput pins that the cause a context was
// cancelled with, which any middleware may set, is read under the library's
// bounded, recovering walk. A cause that cannot be walked is not the library's
// bound, as a plain unrelated cause is not, and the abort is recorded once.
func TestBoundReached_CauseIsConsumerInput(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(hostileCauseRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		cause  func(t *testing.T) error
		child  bool
		want   bool
		reason string // the abort record's reason; empty means none
	}

	cases := []testCase{
		{name: "the library's bound", cause: boundCause, want: true},
		{name: "the library's bound, wrapped", cause: func(t *testing.T) error {
			return fmt.Errorf("middleware: %w", boundCause(t))
		}, want: true},
		{name: "a plain unrelated cause", cause: func(*testing.T) error { return errors.New("client gone") }},
		{name: "self-cycle through Unwrap() error", cause: func(*testing.T) error { return &cycleOne{} }, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", cause: func(*testing.T) error { return &cycleMany{} }, reason: "budget", child: true},
		{name: "join fanning out", cause: func(*testing.T) error { return fanOut(25) }, reason: "budget"},
		{name: "panicking Unwrap", cause: func(*testing.T) error { return unwrapPanics{} }, reason: "panic"},
		{name: "Unwrap panicking with nil", cause: func(*testing.T) error { return unwrapPanicsNil{} }, reason: "panic"},
		{name: "panicking Is", cause: func(*testing.T) error { return isPanics{} }, reason: "panic"},
		{name: "typed nil", cause: func(*testing.T) error { return (*typedNil)(nil) }},
	}

	for _, tc := range cases {
		if childRow != "" && childRow != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && childRow == "" {
				hostileCauseInChild(t, tc.name)

				return
			}

			rec := swapDefault(t)
			ctx := causeCtx(t, tc.cause(t))

			assert.Equal(t, tc.want, boundReachedWithin(ctx, t))

			if tc.reason == "" {
				assert.Empty(t, rec.aborts(), "a walk that completes writes no abort record")
			} else {
				assert.Equal(t, []string{tc.reason}, rec.aborts(), "one abort record")
			}

			if childRow != "" && !t.Failed() {
				_, _ = fmt.Fprintln(os.Stdout, hostileCauseRan+tc.name)
			}
		})
	}
}

// hostileCauseInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having run the
// row: a stack overflow is fatal and only a child can watch for one.
func hostileCauseInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), hostileCauseRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == hostileCauseRan+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", hostileCauseRan+row)
}
