package depfault_test

import (
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

	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// cycleOne contains itself through Unwrap() error.
type cycleOne struct{}

func (*cycleOne) Error() string   { return "cycle one" }
func (c *cycleOne) Unwrap() error { return c }

// cycleMany contains itself through Unwrap() []error. Stdlib errors.Is
// recurses into it until the stack overflows, which kills the process, so its
// rows run in a child process.
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
const hostileRowEnv = "SCRTY_DEPFAULT_HOSTILE_ROW"

// hostileRanMarker prefixes the line a child prints on stdout, followed by the
// row's name, only after the row ran and passed. A child whose row name
// matches no case skips every row and exits 0, so only this line proves a row
// ran. Stdout reaches the parent's CombinedOutput without -v.
const hostileRanMarker = "SCRTY_DEPFAULT_HOSTILE_RAN: "

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

// TestSilent_HostileChains pins that Silent's look into an error is bounded
// and recovering: an error it cannot walk is not silent, so its refusal event
// is reported rather than dropped, on a live context and on an ended one.
func TestSilent_HostileChains(t *testing.T) {
	t.Parallel()

	only := childRow()

	type testCase struct {
		name       string
		ctx        func(ctx context.Context) context.Context
		err        func() error
		subprocess bool
		assert     func(t *testing.T, silent bool)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	notSilent := func(t *testing.T, silent bool) {
		t.Helper()
		assert.False(t, silent, "an error that could not be walked was kept from its event")
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, assert: notSilent},
		{name: "a cycle through Unwrap() []error", err: func() error { return &cycleMany{} }, subprocess: true, assert: notSilent},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }, assert: notSilent},
		{name: "a link whose Is panics", err: func() error { return fmt.Errorf("x: %w", isPanics{}) }, assert: notSilent},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, assert: notSilent},
		{name: "a cycle on an ended context", ctx: cancelled, err: func() error { return &cycleOne{} }, assert: notSilent},
		{
			name:   "a cancellation beside a cycle on an ended context",
			ctx:    cancelled,
			err:    func() error { return errors.Join(context.Canceled, &cycleOne{}) },
			assert: notSilent,
		},
		{
			name:   "a walkable dependency failure answered as a refusal is silent, as before",
			err:    func() error { return fmt.Errorf("x: %w", depfault.Refusal(errDown, errRefused)) },
			assert: func(t *testing.T, silent bool) { assert.True(t, silent) },
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

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			err := tc.err()
			tc.assert(t, within(t, func() bool { return depfault.Silent(ctx, err) }))
		})
	}
}

// TestStore_RecordsHostileChainsAsFailures pins that the decorator's look into
// a store's error is bounded and recovering: an error it cannot walk is not
// the store's "no such token" answer, so it is recorded as the failure it may
// be, and the call answers with the sanitizer's fault, the same value the
// Watch holds, never the store's own error.
func TestStore_RecordsHostileChainsAsFailures(t *testing.T) {
	t.Parallel()

	only := childRow()

	type watched struct {
		err     error
		failure error
	}

	type testCase struct {
		name       string
		err        func() error
		subprocess bool
		assert     func(t *testing.T, err error, got watched)
	}

	recorded := func(t *testing.T, storeErr error, got watched) {
		t.Helper()
		assert.True(t, got.err == got.failure, "the call and the Watch hold different errors") //nolint:errorlint // identity
		require.ErrorIs(t, got.err, porterr.ErrUnwalkable)
		assert.NotErrorIs(t, got.err, onetime.ErrTokenNotFound, "an unwalkable error was answered as no-such-token")
		assert.False(t, got.err == storeErr, "the call answered with the store's own error") //nolint:errorlint // identity
		assert.Error(t, got.failure, "the hostile chain was not recorded as a failure")
		assert.False(t, depfault.Silent(t.Context(), got.failure), "the unwalkable fault was recorded as a refusal")
	}

	// The sanitizer's walk calls Unwrap only, so an error whose Is panics
	// passes through unchanged: the call and the Watch hold the store's own.
	recordedAsOwn := func(t *testing.T, err error, got watched) {
		t.Helper()
		assert.True(t, err == got.err, "the call did not answer with the store's own error") //nolint:errorlint // identity
		assert.True(t, err == got.failure, "the failure recorded is not the store's error")  //nolint:errorlint // identity
	}

	cases := []testCase{
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, assert: recorded},
		{name: "a cycle through Unwrap() []error", err: func() error { return &cycleMany{} }, subprocess: true, assert: recorded},
		{name: "a link whose Unwrap panics", err: func() error { return fmt.Errorf("x: %w", panicUnwrap{}) }, assert: recorded},
		{name: "a link whose Is panics", err: func() error { return fmt.Errorf("x: %w", isPanics{}) }, assert: recordedAsOwn},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, assert: recorded},
		{
			name: "a walkable wrapped no-such-token answer is not a failure, as before",
			err:  func() error { return fmt.Errorf("x: %w", onetime.ErrTokenNotFound) },
			assert: func(t *testing.T, err error, got watched) {
				assert.True(t, err == got.err, "the call did not answer with the store's own error") //nolint:errorlint // identity
				assert.NoError(t, got.failure)
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
			ctx, w := depfault.Watching(t.Context())
			s := depfault.Store(failingStore{findErr: err}, nil)

			tc.assert(t, err, within(t, func() watched {
				_, got := s.FindByID(ctx, id.Nil)

				return watched{err: got, failure: w.Failure()}
			}))
		})
	}
}
