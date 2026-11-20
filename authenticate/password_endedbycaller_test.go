package authenticate

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// endedByCallerRowEnv names the row a child process runs; empty in the parent.
const endedByCallerRowEnv = "SCRTY_AUTHENTICATE_ENDEDBYCALLER_ROW"

// endedByCallerRan is what a child prints once it has run its row, followed by
// the row's name; a parent fails on a child that printed none.
const endedByCallerRan = "authenticate-endedbycaller-row-ran:"

type causeCycleOne struct{}

func (*causeCycleOne) Error() string   { return "cycle one" }
func (c *causeCycleOne) Unwrap() error { return c }

type causeCycleMany struct{}

func (*causeCycleMany) Error() string     { return "cycle many" }
func (c *causeCycleMany) Unwrap() []error { return []error{c} }

type causeUnwrapPanics struct{}

func (causeUnwrapPanics) Error() string { return "unwrap panics" }
func (causeUnwrapPanics) Unwrap() error { panic("the link's Unwrap panicked") }

// TestEndedByCaller_CauseIsConsumerInput pins that the cause a caller's
// context was cancelled with is read under the bounded walk: one the walk
// gives up on is left out of the returned error, so a consumer's stdlib
// errors.Is on it cannot hang or die, while the sentinel and the context's own
// error still match and a walkable cause is still joined.
func TestEndedByCaller_CauseIsConsumerInput(t *testing.T) { //nolint:paralleltest // it replaces slog.Default() and re-runs itself in a child
	childRow := os.Getenv(endedByCallerRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	errCallerLeft := errors.New("middleware: the client left")
	unrelated := errors.New("an unrelated sentinel")

	type testCase struct {
		name   string
		cause  error
		child  bool
		assert func(t *testing.T, err error)
	}

	dropped := func(t *testing.T, err error) {
		t.Helper()

		assert.NotErrorIs(t, err, unrelated, "walking the returned error with errors.Is reached the hostile cause")
	}

	cases := []testCase{
		{name: "a walkable unrelated cause stays joined", cause: errCallerLeft, assert: func(t *testing.T, err error) {
			t.Helper()

			assert.ErrorIs(t, err, errCallerLeft)
		}},
		{name: "self-cycle through Unwrap() error", cause: &causeCycleOne{}, child: true, assert: dropped},
		{name: "self-cycle through Unwrap() []error", cause: &causeCycleMany{}, child: true, assert: dropped},
		{name: "panicking Unwrap", cause: causeUnwrapPanics{}, child: true, assert: dropped},
	}

	for _, tc := range cases {
		if childRow != "" && childRow != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && childRow == "" {
				endedByCallerInChild(t, tc.name)

				return
			}

			prev := slog.Default()
			slog.SetDefault(slog.New(slog.DiscardHandler))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx, cancel := context.WithCancelCause(t.Context())
			cancel(tc.cause)

			err := endedByCaller(ctx)

			done := make(chan struct{})

			go func() {
				defer close(done)

				assert.ErrorIs(t, err, ErrAuthenticationFailed)
				assert.ErrorIs(t, err, context.Canceled)
				tc.assert(t, err)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("walking the returned error did not finish within 2s")
			}

			if childRow != "" && !t.Failed() {
				fmt.Fprintln(os.Stdout, endedByCallerRan+tc.name)
			}
		})
	}
}

// endedByCallerInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having run the
// row: a stack overflow is fatal and only a child can watch for one.
func endedByCallerInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), endedByCallerRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == endedByCallerRan+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", endedByCallerRan+row)
}
