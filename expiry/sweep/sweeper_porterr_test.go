package sweep_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/expiry/sweep"
	"github.com/kartaladev/scrty/internal/porterr"
)

// lockPortRowEnv names the row a child process runs. It is empty in the
// parent.
const lockPortRowEnv = "SCRTY_SWEEP_LOCK_PORTERR_ROW"

// lockPortRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const lockPortRanMarker = "SCRTY_SWEEP_LOCK_PORTERR_RAN: "

// lockPortSecret is text a hostile error carries that no record may quote.
const lockPortSecret = "lock-server-secret-91c2" //nolint:gosec // G101: a fixture, not a credential

// lockFailedMsg is the record the sweeper writes for a refused lock.
const lockFailedMsg = "sweep: distributed lock failed; run skipped"

// errLockPortPlain is the plain lock failure every hostile row is compared with.
var errLockPortPlain = errors.New("lock server refused: " + lockPortSecret)

type lockCycleOne struct{}

func (*lockCycleOne) Error() string   { return "cycle one: " + lockPortSecret }
func (c *lockCycleOne) Unwrap() error { return c }

type lockCycleMany struct{}

func (*lockCycleMany) Error() string     { return "cycle many: " + lockPortSecret }
func (c *lockCycleMany) Unwrap() []error { return []error{c} }

type lockPanicUnwrap struct{}

func (lockPanicUnwrap) Error() string { return "panic unwrap: " + lockPortSecret }
func (lockPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked: " + lockPortSecret) }

type lockPanicNilUnwrap struct{}

func (lockPanicNilUnwrap) Error() string { return "panic nil unwrap: " + lockPortSecret }
func (lockPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// lockTypedNil is returned as a nil *lockTypedNil inside a non-nil error.
type lockTypedNil struct{}

func (*lockTypedNil) Error() string { return "typed nil" }

// selectiveIs is a consumer error whose Is method panics when asked about
// target, and only then. The sanitizer's walk calls Unwrap only, so it passes
// such an error through unchanged; every later read of it by the library must
// go through the bounded, recovering walk.
type selectiveIs struct{ target error }

func (selectiveIs) Error() string { return "selective is: " + lockPortSecret }

func (s selectiveIs) Is(target error) bool {
	if target == s.target {
		panic("test: consumer Is panicked: " + lockPortSecret)
	}

	return false
}

// lockFanOut is errors.Join(n, n) nested depth times over leaf: no cycle, but
// 2^depth paths for an unbounded walk.
func lockFanOut(leaf error, depth int) error {
	err := leaf
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// lockRecords is a slog.Handler that keeps every record it is handed.
type lockRecords struct {
	mu      sync.Mutex
	records []slog.Record
	notify  chan struct{}
}

func (*lockRecords) Enabled(context.Context, slog.Level) bool { return true }

func (r *lockRecords) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	r.records = append(r.records, rec.Clone())
	r.mu.Unlock()

	select {
	case r.notify <- struct{}{}:
	default:
	}

	return nil
}

func (r *lockRecords) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *lockRecords) WithGroup(string) slog.Handler      { return r }

func (r *lockRecords) all() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]slog.Record(nil), r.records...)
}

// lockOutcome is what one run refused by a failing locker produced. Every
// field but the error's type is compared between a hostile row and the plain
// failure.
type lockOutcome struct {
	lockRecords int
	level       slog.Level
	task        string
	job         string
	reason      string
	cancelled   bool // the record carries cancelled
	runs        int32
	shutdownErr bool
}

type lockRun struct {
	outcome   lockOutcome
	errorType string
	aborts    []slog.Record
	attrs     map[string]string
}

// lockRunOnce starts a sweeper on a real clock whose one task runs at once,
// behind a locker that refuses with lockErr, waits, bounded, for the refusal's
// record, and shuts the sweeper down.
func lockRunOnce(ctx context.Context, t *testing.T, lockErr error) lockRun {
	t.Helper()

	var runs atomic.Int32

	runner, err := expiry.NewRunner([]expiry.Task{{
		Name: "sessions", Interval: time.Hour,
		Run: func(context.Context) (int, error) {
			runs.Add(1)
			return 0, nil
		},
	}}, expiry.WithLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	locker := NewMockLocker(gomock.NewController(t))
	locker.EXPECT().Lock(gomock.Any(), "sweep:sessions").Return(nil, lockErr).AnyTimes()

	rec := &lockRecords{notify: make(chan struct{}, 1)}

	s, err := sweep.New(runner,
		sweep.WithClock(clockwork.NewRealClock()),
		sweep.WithRunImmediately(),
		sweep.WithStopTimeout(time.Second),
		sweep.WithLogger(slog.New(rec)),
		sweep.WithDistributedLocker(locker),
	)
	require.NoError(t, err)

	require.NoError(t, s.Start(ctx))

	// Wait, bounded, for the refusal's record. A listener that hangs or dies
	// in an unbounded errors.Is never writes it.
	deadline := time.After(waitLimit)
	for found := false; !found; {
		for _, r := range rec.all() {
			if r.Message == lockFailedMsg {
				found = true
			}
		}

		if found {
			break
		}

		select {
		case <-rec.notify:
		case <-deadline:
			require.FailNow(t, "the lock failure was never recorded within the bound")
		}
	}

	// Give a wrong second record or a run the chance to show.
	time.Sleep(quiet)

	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), waitLimit)
	defer cancel()

	shutdownErr := s.Shutdown(stopCtx)

	got := lockRun{}
	got.outcome.runs = runs.Load()
	got.outcome.shutdownErr = shutdownErr != nil

	for _, r := range rec.all() {
		switch r.Message {
		case porterr.MsgClassificationAborted:
			got.aborts = append(got.aborts, r)
		case lockFailedMsg:
			got.outcome.lockRecords++
			got.outcome.level = r.Level
			got.attrs = recordAttrs(r)
			got.outcome.task = got.attrs["task"]
			got.outcome.job = got.attrs["job"]
			got.outcome.reason = got.attrs["reason"]
			_, got.outcome.cancelled = got.attrs["cancelled"]
			got.errorType = got.attrs["error_type"]
		}
	}

	return got
}

// TestPortErrors_DistributedLock pins that the consumer's gocron.Locker error
// is sanitized before the sweeper's lock-failure listener asks whether it was
// a cancellation. A hostile error (a cycle, a fan-out, a panicking Unwrap),
// whatever it claims, behaves as a plain lock failure: the run is skipped,
// one failure record with reason "lock" and no cancelled mark is written, and
// nothing hangs or panics. The sanitizer writes one abort record to the
// sweeper's logger and none to slog.Default().
func TestPortErrors_DistributedLock(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(lockPortRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name   string
		err    error
		child  bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, plain, got lockRun)
	}

	sameAsPlain := func(t *testing.T, plain, got lockRun) {
		t.Helper()

		assert.Equal(t, plain.outcome, got.outcome, "the outcome differs from a plain lock failure")

		for k, v := range got.attrs {
			assert.NotContains(t, v, lockPortSecret, "the failure record's %s quotes the error", k)
		}
	}

	asFailure := func(reason string) func(t *testing.T, plain, got lockRun) {
		return func(t *testing.T, plain, got lockRun) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.Equal(t, "*porterr.Fault", got.errorType, "the record names the sanitizer's fault")

			require.Len(t, got.aborts, 1, "one abort record, on the sweeper's logger")
			assert.Equal(t, slog.LevelError, got.aborts[0].Level)
			assert.Equal(t, reason, recordAttrs(got.aborts[0])["reason"])

			for k, v := range recordAttrs(got.aborts[0]) {
				assert.NotContains(t, v, lockPortSecret, "the abort record's %s quotes the error", k)
			}
		}
	}

	walked := func(t *testing.T, plain, got lockRun) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.NotEqual(t, "*porterr.Fault", got.errorType, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	// selective is a row whose error passes the sanitizer unchanged and
	// panics in its Is method for one sentinel the listener reads: one abort
	// record, reason "panic", from the listener's own read.
	selective := func(t *testing.T, plain, got lockRun) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.Equal(t, "sweep_test.selectiveIs", got.errorType, "an error whose chain walks is passed on unchanged")

		require.Len(t, got.aborts, 1, "one abort record, on the sweeper's logger")
		assert.Equal(t, slog.LevelError, got.aborts[0].Level)
		assert.Equal(t, "panic", recordAttrs(got.aborts[0])["reason"])

		for k, v := range recordAttrs(got.aborts[0]) {
			assert.NotContains(t, v, lockPortSecret, "the abort record's %s quotes the error", k)
		}
	}

	cases := []testCase{
		{name: "a cycle", err: &lockCycleOne{}, assert: asFailure("budget")},
		{
			name: "a cycle claiming context.Canceled", err: errors.Join(&lockCycleOne{}, context.Canceled),
			assert: asFailure("budget"),
		},
		{
			name: "a cycle claiming context.DeadlineExceeded", err: errors.Join(&lockCycleOne{}, context.DeadlineExceeded),
			assert: asFailure("budget"),
		},
		{
			name: "a fan-out claiming context.DeadlineExceeded", err: lockFanOut(context.DeadlineExceeded, 40),
			assert: asFailure("budget"),
		},
		{name: "a panicking Unwrap", err: lockPanicUnwrap{}, assert: asFailure("panic")},
		{name: "a panic(nil) Unwrap", err: lockPanicNilUnwrap{}, assert: asFailure("panic")},
		{
			name: "a cycle under a Start context already cancelled", err: &lockCycleOne{},
			ctx: cancelled, assert: asFailure("budget"),
		},
		{name: "a fan-out cycle (Unwrap() []error)", err: &lockCycleMany{}, child: true, assert: asFailure("budget")},
		{
			name: "a fan-out cycle claiming context.Canceled", err: errors.Join(&lockCycleMany{}, context.Canceled),
			child: true, assert: asFailure("budget"),
		},
		{name: "a typed-nil root walks to the end", err: (*lockTypedNil)(nil), assert: walked},
		{name: "a plain failure, against itself", err: errLockPortPlain, assert: walked},
		// In a child: unfixed, the panic escapes on gocron's goroutine and
		// kills the process.
		{
			name: "an Is that panics only for context.Canceled", err: selectiveIs{target: context.Canceled},
			child: true, assert: selective,
		},
		{
			name: "an Is that panics only for context.DeadlineExceeded", err: selectiveIs{target: context.DeadlineExceeded},
			child: true, assert: selective,
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, lockPortRowEnv, lockPortRanMarker, tc.name)

				return
			}

			defaults := &lockRecords{notify: make(chan struct{}, 1)}
			prev := slog.Default()
			slog.SetDefault(slog.New(defaults))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := lockRunOnce(ctx, t, errLockPortPlain)
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")
			require.Equal(t, 1, plain.outcome.lockRecords)
			require.Equal(t, "lock", plain.outcome.reason)
			require.False(t, plain.outcome.cancelled)
			require.Zero(t, plain.outcome.runs)

			got := lockRunOnce(ctx, t, tc.err)
			tc.assert(t, plain, got)

			for _, r := range defaults.all() {
				assert.NotEqual(t, porterr.MsgClassificationAborted, r.Message, "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(lockPortRanMarker + tc.name + "\n")
			}
		})
	}
}

// taskPortRowEnv names the row a child process of TestPortErrors_SweepTask
// runs. It is empty in the parent.
const taskPortRowEnv = "SCRTY_SWEEP_TASK_PORTERR_ROW"

// taskPortRanMarker prefixes the line a child of TestPortErrors_SweepTask
// prints, followed by the row's name, after the row ran and passed.
const taskPortRanMarker = "SCRTY_SWEEP_TASK_PORTERR_RAN: "

// taskOutcome is what one scheduled run of a failing task and a healthy one
// produced. Every field is compared between a hostile row and the plain
// failure.
type taskOutcome struct {
	level       slog.Level
	msg         string
	reason      string
	cancelled   bool // the failure record carries cancelled
	nextRan     bool
	shutdownErr bool
}

type taskRun struct {
	outcome taskOutcome
	aborts  []slog.Record
	attrs   map[string]string
}

// taskRunOnce starts a sweeper on a real clock over a task that returns
// taskErr and a healthy one, both run at once, waits, bounded, for the
// failure's record and the healthy task's, and shuts the sweeper down. The
// runner and the sweeper write to one recorder.
func taskRunOnce(ctx context.Context, t *testing.T, taskErr error) taskRun {
	t.Helper()

	var nextRuns atomic.Int32

	rec := &lockRecords{notify: make(chan struct{}, 1)}

	runner, err := expiry.NewRunner([]expiry.Task{
		{Name: "failing", Interval: time.Hour, Run: func(context.Context) (int, error) {
			return 3, taskErr
		}},
		{Name: "next", Interval: time.Hour, Run: func(context.Context) (int, error) {
			nextRuns.Add(1)
			return 1, nil
		}},
	}, expiry.WithLogger(slog.New(rec)))
	require.NoError(t, err)

	s, err := sweep.New(runner,
		sweep.WithClock(clockwork.NewRealClock()),
		sweep.WithRunImmediately(),
		sweep.WithStopTimeout(time.Second),
		sweep.WithLogger(slog.New(rec)),
	)
	require.NoError(t, err)

	require.NoError(t, s.Start(ctx))

	// Wait, bounded, for both tasks' records. A run that dies in an
	// unbounded errors.Is never writes the failure's.
	deadline := time.After(waitLimit)

	for {
		failed, finished := false, false

		for _, r := range rec.all() {
			task := recordAttrs(r)["task"]
			failed = failed || (task == "failing" && r.Message == "expiry task failed")
			finished = finished || (task == "next" && r.Message == "expiry task finished")
		}

		if failed && finished {
			break
		}

		select {
		case <-rec.notify:
		case <-deadline:
			require.FailNow(t, "the runs were never recorded within the bound")
		}
	}

	// Give a wrong second record the chance to show.
	time.Sleep(quiet)

	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), waitLimit)
	defer cancel()

	got := taskRun{}
	got.outcome.shutdownErr = s.Shutdown(stopCtx) != nil
	got.outcome.nextRan = nextRuns.Load() > 0

	for _, r := range rec.all() {
		attrs := recordAttrs(r)

		switch {
		case r.Message == porterr.MsgClassificationAborted:
			got.aborts = append(got.aborts, r)
		case attrs["task"] == "failing":
			got.attrs = attrs
			got.outcome.level = r.Level
			got.outcome.msg = r.Message
			got.outcome.reason = attrs["reason"]
			_, got.outcome.cancelled = attrs["cancelled"]
		}
	}

	return got
}

// TestPortErrors_SweepTask pins that a task's error whose Is method panics
// only for one sentinel the runner's report reads, which the sanitizer passes
// unchanged, does not crash the process when the sweeper runs the task on
// gocron's goroutine. It is recorded as a plain failure, reason "purge" and no
// cancelled mark, the other task still runs, and the runner's read writes one
// abort record, reason "panic", to the runner's logger and none to
// slog.Default().
func TestPortErrors_SweepTask(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(taskPortRowEnv)

	type testCase struct {
		name   string
		err    error
		child  bool
		assert func(t *testing.T, plain, got taskRun)
	}

	sameAsPlain := func(t *testing.T, plain, got taskRun) {
		t.Helper()

		assert.Equal(t, plain.outcome, got.outcome, "the outcome differs from a plain task failure")

		for k, v := range got.attrs {
			assert.NotContains(t, v, lockPortSecret, "the failure record's %s quotes the error", k)
		}
	}

	selective := func(t *testing.T, plain, got taskRun) {
		t.Helper()

		sameAsPlain(t, plain, got)

		require.Len(t, got.aborts, 1, "one abort record, on the runner's logger")
		assert.Equal(t, slog.LevelError, got.aborts[0].Level)
		assert.Equal(t, "panic", recordAttrs(got.aborts[0])["reason"])

		for k, v := range recordAttrs(got.aborts[0]) {
			assert.NotContains(t, v, lockPortSecret, "the abort record's %s quotes the error", k)
		}
	}

	walked := func(t *testing.T, plain, got taskRun) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	// The selective rows run in a child: unfixed, the panic escapes on
	// gocron's goroutine and kills the process.
	cases := []testCase{
		{name: "a plain failure, against itself", err: errLockPortPlain, assert: walked},
		{
			name: "an Is that panics only for ErrTaskPanicked", err: selectiveIs{target: expiry.ErrTaskPanicked},
			child: true, assert: selective,
		},
		{
			name: "an Is that panics only for ErrPurgeUnsupported", err: selectiveIs{target: expiry.ErrPurgeUnsupported},
			child: true, assert: selective,
		},
		{
			name: "an Is that panics only for context.Canceled", err: selectiveIs{target: context.Canceled},
			child: true, assert: selective,
		},
		{
			name: "an Is that panics only for context.DeadlineExceeded", err: selectiveIs{target: context.DeadlineExceeded},
			child: true, assert: selective,
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, taskPortRowEnv, taskPortRanMarker, tc.name)

				return
			}

			defaults := &lockRecords{notify: make(chan struct{}, 1)}
			prev := slog.Default()
			slog.SetDefault(slog.New(defaults))
			t.Cleanup(func() { slog.SetDefault(prev) })

			plain := taskRunOnce(t.Context(), t, errLockPortPlain)
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")
			require.Equal(t, "purge", plain.outcome.reason)
			require.Equal(t, "expiry task failed", plain.outcome.msg)
			require.False(t, plain.outcome.cancelled)
			require.True(t, plain.outcome.nextRan)

			got := taskRunOnce(t.Context(), t, tc.err)
			tc.assert(t, plain, got)

			for _, r := range defaults.all() {
				assert.NotEqual(t, porterr.MsgClassificationAborted, r.Message, "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(taskPortRanMarker + tc.name + "\n")
			}
		})
	}
}

// portErrInChild re-runs the current top-level test in a child process limited
// to row, named through env, and fails unless it exits 0 within a minute and
// prints marker followed by row: a stack overflow, or a panic on gocron's
// goroutine, is fatal and only a child can watch for one.
func portErrInChild(t *testing.T, env, marker, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), env+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := marker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
