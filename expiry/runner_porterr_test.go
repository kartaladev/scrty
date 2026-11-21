package expiry_test

import (
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

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/porterr"
)

// runnerPortRowEnv names the row a child process runs. It is empty in the
// parent.
const runnerPortRowEnv = "SCRTY_EXPIRY_RUNNER_PORTERR_ROW"

// runnerPortRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const runnerPortRanMarker = "SCRTY_EXPIRY_RUNNER_PORTERR_RAN: "

// runnerPortSecret is text a hostile error carries that no record may quote.
const runnerPortSecret = "owner-store-secret-7f3a" //nolint:gosec // G101: a fixture, not a credential

// runnerPortBound bounds one RunOnce. An unbounded errors.Is over a cycle or
// a fan-out never returns within it.
const runnerPortBound = 10 * time.Second

// errRunnerPortPlain is the plain store failure every hostile row is compared
// with.
var errRunnerPortPlain = errors.New("owner store down: " + runnerPortSecret)

type runnerCycleOne struct{}

func (*runnerCycleOne) Error() string    { return "cycle one: " + runnerPortSecret }
func (c *runnerCycleOne) Unwrap() error  { return c }
func newRunnerCycleOne() *runnerCycleOne { return &runnerCycleOne{} }

type runnerCycleMany struct{}

func (*runnerCycleMany) Error() string     { return "cycle many: " + runnerPortSecret }
func (c *runnerCycleMany) Unwrap() []error { return []error{c} }

type runnerPanicUnwrap struct{}

func (runnerPanicUnwrap) Error() string { return "panic unwrap: " + runnerPortSecret }
func (runnerPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked: " + runnerPortSecret) }

type runnerPanicNilUnwrap struct{}

func (runnerPanicNilUnwrap) Error() string { return "panic nil unwrap: " + runnerPortSecret }
func (runnerPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// runnerTypedNil is returned as a nil *runnerTypedNil inside a non-nil error.
type runnerTypedNil struct{}

func (*runnerTypedNil) Error() string { return "typed nil" }

// runnerSelectiveIs is a consumer error whose Is method panics when asked
// about target, and only then. The sanitizer's walk calls Unwrap only, so it
// passes such an error through unchanged; every later read of it by the
// runner must go through the bounded, recovering walk.
type runnerSelectiveIs struct{ target error }

func (runnerSelectiveIs) Error() string { return "selective is: " + runnerPortSecret }

func (s runnerSelectiveIs) Is(target error) bool {
	if target == s.target {
		panic("test: consumer Is panicked: " + runnerPortSecret)
	}

	return false
}

// runnerSafeIs is errors.Is that reports false when an Is method panics, so
// the test's own class checks survive the rows whose error panics on purpose.
// It still hangs or overflows on what errors.Is hangs or overflows on.
func runnerSafeIs(err, target error) (matched bool) {
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()

	return errors.Is(err, target)
}

// runnerErrCtx is a caller's context that reports err from Err, as a
// consumer's own Context implementation may.
type runnerErrCtx struct {
	context.Context

	err error
}

func (c runnerErrCtx) Err() error { return c.err }

// runnerFanOut is errors.Join(n, n) nested depth times over leaf: no cycle,
// but 2^depth paths for an unbounded walk.
func runnerFanOut(leaf error, depth int) error {
	err := leaf
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// runnerRecorder is a slog.Handler that keeps every record it is handed.
type runnerRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*runnerRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *runnerRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())

	return nil
}

func (r *runnerRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *runnerRecorder) WithGroup(string) slog.Handler      { return r }

func (r *runnerRecorder) all() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]slog.Record(nil), r.records...)
}

func runnerAttrs(rec slog.Record) map[string]string {
	attrs := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})

	return attrs
}

// runnerOutcome is what one RunOnce over a failing task produced. Every field
// but the error's text and type is compared between a hostile row and the
// plain failure.
type runnerOutcome struct {
	// The failing task's result.
	removed int
	skipped bool
	// The classes its error matches.
	panicked, unsupported, cancelled, busy bool
	// The failure record the runner wrote for it.
	level   slog.Level
	msg     string
	reason  string
	logged  string // the record's removed attribute
	flagged bool   // the record carries cancelled
	// The healthy task after it still ran.
	nextRan     bool
	nextErr     bool
	observed    int  // results the observer received
	joinedFails bool // RunOnce's joined error matches the failing result's
}

// runnerMode is how one run is driven.
type runnerMode struct {
	// cancelDuringRun cancels the caller's context inside the failing task.
	cancelDuringRun bool
	// viaTask runs the two tasks with RunTask, one call each, in place of
	// one RunOnce.
	viaTask bool
	// ctxErr, when set, makes the caller's context report it from Err, so
	// both tasks are skipped with it and never run.
	ctxErr error
}

// runnerRun is one RunOnce (or two RunTask calls), bounded, of a failing task
// that removes 3 records and returns portErr, followed by a healthy task.
type runnerRun struct {
	outcome    runnerOutcome
	err        error // the failing task's Result.Err
	aborts     []slog.Record
	failRecord slog.Record
}

func runnerRunOnce(ctx context.Context, t *testing.T, portErr error, mode runnerMode) runnerRun {
	t.Helper()

	rec := &runnerRecorder{}
	nextRan := false

	var observed []expiry.Result

	tasks := []expiry.Task{
		{Name: "failing", Run: func(context.Context) (int, error) {
			return 3, portErr
		}},
		{Name: "next", Run: func(context.Context) (int, error) {
			nextRan = true
			return 1, nil
		}},
	}

	runCtx := ctx
	if mode.ctxErr != nil {
		runCtx = runnerErrCtx{Context: ctx, err: mode.ctxErr} //nolint:contextcheck // the case's ctx, wrapped to report an Err the case chooses
	}

	if mode.cancelDuringRun {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithCancel(ctx)
		defer cancel()
		// The failing task cancels the caller's context before it returns,
		// so the sanitizer is handed a context already done. The next task is
		// then skipped, as for any caller that cancels mid-run.
		tasks[0].Run = func(context.Context) (int, error) {
			cancel()
			return 3, portErr
		}
	}

	runner, err := expiry.NewRunner(tasks,
		expiry.WithLogger(slog.New(rec)),
		expiry.WithObserver(func(r expiry.Result) { observed = append(observed, r) }),
	)
	require.NoError(t, err)

	type done struct {
		rep    expiry.Report
		err    error
		panicV any
		ok     bool
	}

	ch := make(chan done, 1)

	go func() {
		var d done
		defer func() {
			if !d.ok {
				d.panicV = recover()
			}
			ch <- d
		}()

		if mode.viaTask {
			failing, failErr := runner.RunTask(runCtx, "failing")
			next, nextErr := runner.RunTask(runCtx, "next")
			d.rep = expiry.Report{Results: []expiry.Result{failing, next}}
			d.err = errors.Join(failErr, nextErr)
		} else {
			d.rep, d.err = runner.RunOnce(runCtx)
		}
		// The class checks a caller makes, inside the bound.
		_ = runnerSafeIs(d.err, expiry.ErrTaskPanicked)
		_ = runnerSafeIs(d.err, expiry.ErrPurgeUnsupported)
		_ = runnerSafeIs(d.err, context.Canceled)
		d.ok = true
	}()

	var d done
	select {
	case d = <-ch:
	case <-time.After(runnerPortBound):
		require.FailNow(t, "RunOnce did not return within the bound")
	}

	require.True(t, d.ok, "the run panicked: %v", d.panicV)
	require.Len(t, d.rep.Results, 2)

	failing := d.rep.Results[0]
	next := d.rep.Results[1]

	got := runnerRun{err: failing.Err}
	o := &got.outcome
	o.removed = failing.Removed
	o.skipped = failing.Skipped
	o.panicked = runnerSafeIs(failing.Err, expiry.ErrTaskPanicked)
	o.unsupported = runnerSafeIs(failing.Err, expiry.ErrPurgeUnsupported)
	o.cancelled = runnerSafeIs(failing.Err, context.Canceled)
	o.busy = runnerSafeIs(failing.Err, expiry.ErrTaskBusy)
	o.nextRan = nextRan
	o.nextErr = next.Err != nil
	o.observed = len(observed)
	o.joinedFails = failing.Err != nil && runnerSafeIs(d.err, failing.Err)

	for _, r := range rec.all() {
		attrs := runnerAttrs(r)

		switch {
		case r.Message == porterr.MsgClassificationAborted:
			got.aborts = append(got.aborts, r)
		case attrs["task"] == "failing":
			got.failRecord = r
			o.level = r.Level
			o.msg = r.Message
			o.reason = attrs["reason"]
			o.logged = attrs["removed"]
			_, o.flagged = attrs["cancelled"]
		}
	}

	return got
}

// runnerSwapDefault replaces slog.Default() with a recorder until the test
// ends.
func runnerSwapDefault(t *testing.T) *runnerRecorder {
	t.Helper()

	rec := &runnerRecorder{}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

// TestPortErrors_RunnerTask pins that a task's error, which comes from the
// consumer's Run or from the owner's store a built-in task wraps, is
// sanitized before the runner classifies it. A hostile error (a cycle, a
// fan-out, a panicking Unwrap) is reported exactly as a plain task failure:
// the same result, the same failure record with reason "purge", never
// "panic", "purge-unsupported" or "skipped", whatever sentinel it claims.
// The runner does not hang or panic, and the next task still runs. The
// sanitizer writes one abort record to the runner's logger and none to
// slog.Default().
//
// An error whose Is method panics only for one sentinel the runner reads
// passes the sanitizer unchanged. The runner reads it through the bounded
// walk, so it is still reported as a plain failure (or, as the caller's
// context error, a plain cancellation skip), via RunOnce and via RunTask, and
// that read writes the one abort record, reason "panic", per classification.
func TestPortErrors_RunnerTask(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(runnerPortRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		err    error
		child  bool
		mode   runnerMode
		assert func(t *testing.T, plain, got runnerRun)
	}

	sameAsPlain := func(t *testing.T, plain, got runnerRun) {
		t.Helper()

		assert.Equal(t, plain.outcome, got.outcome, "the outcome differs from a plain task failure")

		for k, v := range runnerAttrs(got.failRecord) {
			assert.NotContains(t, v, runnerPortSecret, "the failure record's %s quotes the error", k)
		}
	}

	asFailure := func(reason string) func(t *testing.T, plain, got runnerRun) {
		return func(t *testing.T, plain, got runnerRun) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.ErrorIs(t, got.err, porterr.ErrUnwalkable, "the result carries the sanitizer's fault")
			assert.NotContains(t, got.err.Error(), runnerPortSecret)

			require.Len(t, got.aborts, 1, "one abort record, on the runner's logger")
			assert.Equal(t, slog.LevelError, got.aborts[0].Level)
			assert.Equal(t, reason, runnerAttrs(got.aborts[0])["reason"])

			for k, v := range runnerAttrs(got.aborts[0]) {
				assert.NotContains(t, v, runnerPortSecret, "the abort record's %s quotes the error", k)
			}
		}
	}

	// selective is a row whose error passes the sanitizer unchanged and
	// panics in its Is method for one sentinel: aborts records, one per
	// classification that met it, each with reason "panic".
	selective := func(aborts int) func(t *testing.T, plain, got runnerRun) {
		return func(t *testing.T, plain, got runnerRun) {
			t.Helper()

			sameAsPlain(t, plain, got)

			_, isFault := got.err.(*porterr.Fault) //nolint:errorlint // the result's own value, unwrapped
			assert.False(t, isFault, "an error whose chain walks is passed on unchanged")

			require.Len(t, got.aborts, aborts, "one abort record per classification, on the runner's logger")

			for _, a := range got.aborts {
				assert.Equal(t, slog.LevelError, a.Level)
				assert.Equal(t, "panic", runnerAttrs(a)["reason"])

				for k, v := range runnerAttrs(a) {
					assert.NotContains(t, v, runnerPortSecret, "the abort record's %s quotes the error", k)
				}
			}
		}
	}

	walked := func(t *testing.T, plain, got runnerRun) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.NotErrorIs(t, got.err, porterr.ErrUnwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	cases := []testCase{
		{name: "a cycle", err: newRunnerCycleOne(), assert: asFailure("budget")},
		{
			name: "a cycle claiming ErrPurgeUnsupported", err: errors.Join(newRunnerCycleOne(), expiry.ErrPurgeUnsupported),
			assert: asFailure("budget"),
		},
		{
			name: "a cycle claiming ErrTaskPanicked", err: errors.Join(newRunnerCycleOne(), expiry.ErrTaskPanicked),
			assert: asFailure("budget"),
		},
		{
			name: "a cycle claiming context.Canceled", err: errors.Join(newRunnerCycleOne(), context.Canceled),
			assert: asFailure("budget"),
		},
		{
			name: "a fan-out claiming ErrPurgeUnsupported", err: runnerFanOut(expiry.ErrPurgeUnsupported, 40),
			assert: asFailure("budget"),
		},
		{
			name: "a fan-out claiming ErrTaskPanicked", err: runnerFanOut(fmt.Errorf("x: %w", expiry.ErrTaskPanicked), 40),
			assert: asFailure("budget"),
		},
		{name: "a panicking Unwrap", err: runnerPanicUnwrap{}, assert: asFailure("panic")},
		{name: "a panic(nil) Unwrap", err: runnerPanicNilUnwrap{}, assert: asFailure("panic")},
		{
			name: "a cycle handed over with the caller's context cancelled", err: newRunnerCycleOne(),
			mode: runnerMode{cancelDuringRun: true}, assert: asFailure("budget"),
		},
		{name: "a fan-out cycle (Unwrap() []error)", err: &runnerCycleMany{}, child: true, assert: asFailure("budget")},
		{
			name: "a fan-out cycle claiming ErrPurgeUnsupported", err: errors.Join(&runnerCycleMany{}, expiry.ErrPurgeUnsupported),
			child: true, assert: asFailure("budget"),
		},
		{name: "a typed-nil root walks to the end", err: (*runnerTypedNil)(nil), assert: walked},
		{name: "a plain failure, against itself", err: errRunnerPortPlain, assert: walked},
	}

	// A task's error whose Is panics only for one sentinel: each sentinel a
	// failed record's classification reads, via RunOnce and via RunTask. In a
	// child, since the panic, unfixed, can escape on a scheduler's goroutine.
	for _, via := range []struct {
		name    string
		viaTask bool
	}{{"via RunOnce", false}, {"via RunTask", true}} {
		for _, s := range []struct {
			name   string
			target error
		}{
			{"ErrTaskPanicked", expiry.ErrTaskPanicked},
			{"ErrPurgeUnsupported", expiry.ErrPurgeUnsupported},
			{"context.Canceled", context.Canceled},
			{"context.DeadlineExceeded", context.DeadlineExceeded},
		} {
			cases = append(cases, testCase{
				name: "a task error whose Is panics only for " + s.name + ", " + via.name,
				err:  runnerSelectiveIs{target: s.target}, child: true,
				mode: runnerMode{viaTask: via.viaTask}, assert: selective(1),
			})
		}

		// The caller's context reporting such an error from Err: both tasks
		// are skipped with it, and each skip's classification reads it.
		for _, s := range []struct {
			name   string
			target error
		}{
			{"ErrTaskBusy", expiry.ErrTaskBusy},
			{"context.Canceled", context.Canceled},
			{"context.DeadlineExceeded", context.DeadlineExceeded},
		} {
			err := runnerSelectiveIs{target: s.target}
			cases = append(cases, testCase{
				name: "a context error whose Is panics only for " + s.name + ", " + via.name,
				err:  err, child: true,
				mode: runnerMode{viaTask: via.viaTask, ctxErr: err}, assert: selective(2),
			})
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				runnerInChild(t, tc.name)

				return
			}

			defaults := runnerSwapDefault(t)

			plainMode := tc.mode
			if plainMode.ctxErr != nil {
				plainMode.ctxErr = errRunnerPortPlain
			}

			plain := runnerRunOnce(t.Context(), t, errRunnerPortPlain, plainMode)
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")

			if tc.mode.ctxErr != nil {
				require.Equal(t, "cancelled", plain.outcome.reason)
				require.Equal(t, "expiry task skipped", plain.outcome.msg)
				require.True(t, plain.outcome.skipped)
			} else {
				require.Equal(t, "purge", plain.outcome.reason)
				require.Equal(t, "expiry task failed", plain.outcome.msg)
			}

			got := runnerRunOnce(t.Context(), t, tc.err, tc.mode)
			tc.assert(t, plain, got)

			for _, r := range defaults.all() {
				assert.NotEqual(t, porterr.MsgClassificationAborted, r.Message, "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(runnerPortRanMarker + tc.name + "\n")
			}
		})
	}
}

// runnerInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func runnerInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), runnerPortRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := runnerPortRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
