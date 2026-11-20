package hangup_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/detach"
)

// hostileCauseRowEnv names the row a child process runs; empty in the parent.
const hostileCauseRowEnv = "SCRTY_HANGUP_HOSTILE_CAUSE_ROW"

// hostileCauseRan is what a child prints once it has run its row, followed by
// the row's name.
const hostileCauseRan = "hangup-hostile-cause-row-ran:"

type unwrapPanics struct{}

func (unwrapPanics) Error() string { return "unwrap panics" }
func (unwrapPanics) Unwrap() error { panic("the link's Unwrap panicked") }

type unwrapPanicsNil struct{}

func (unwrapPanicsNil) Error() string { return "unwrap panics nil" }
func (unwrapPanicsNil) Unwrap() error { panic(nil) } //nolint:govet // the row is panic(nil)

type typedNil struct{}

func (*typedNil) Error() string { return "typed nil" }

func fanOut(depth int) error {
	err := errors.New("leaf")
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// TestByCaller_HostileCause pins that the cause the request's context was
// cancelled with, which any middleware may set, never hangs or crashes the
// hang-up check: the check answers as for a plain cause, whatever the cause
// holds. The error handed in is the context's own error, so a hang-up is the
// answer for every cause but the library's own bound.
func TestByCaller_HostileCause(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(hostileCauseRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name  string
		cause func(t *testing.T) error
		child bool
		want  bool
	}

	bound := func(t *testing.T) error {
		t.Helper()

		ctx, cancel := detach.Bounded(t.Context(), time.Nanosecond)
		defer cancel()

		<-ctx.Done()

		return context.Cause(ctx)
	}

	cases := []testCase{
		{name: "the library's bound", cause: bound},
		{name: "a plain unrelated cause", cause: func(*testing.T) error { return errors.New("client gone") }, want: true},
		{name: "self-cycle through Unwrap() error", cause: func(*testing.T) error { return &cycleOne{} }, want: true},
		{name: "self-cycle through Unwrap() []error", cause: func(*testing.T) error { return &cycleMany{} }, want: true, child: true},
		{name: "join fanning out", cause: func(*testing.T) error { return fanOut(25) }, want: true},
		{name: "panicking Unwrap", cause: func(*testing.T) error { return unwrapPanics{} }, want: true},
		{name: "Unwrap panicking with nil", cause: func(*testing.T) error { return unwrapPanicsNil{} }, want: true},
		{name: "typed nil", cause: func(*testing.T) error { return (*typedNil)(nil) }, want: true},
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

			ctx, cancel := context.WithCancelCause(t.Context())
			cancel(tc.cause(t))

			got := byCallerWithin(ctx, t, ctx.Err())

			assert.Equal(t, tc.want, got.hungUp, "ByCallerWalk")
			assert.Equal(t, tc.want, got.byCaller, "ByCaller")
			assert.NoError(t, got.abort, "the error handed in walks clean")

			if childRow != "" && !t.Failed() {
				fmt.Fprintln(os.Stdout, hostileCauseRan+tc.name)
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
