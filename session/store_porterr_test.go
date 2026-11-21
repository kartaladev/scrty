package session_test

import (
	"context"
	"errors"
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
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/session"
)

// expiryTaskRowEnv names the row a child process runs. It is empty in the
// parent.
const expiryTaskRowEnv = "SCRTY_SESSION_EXPIRYTASK_PORTERR_ROW"

// expiryTaskRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const expiryTaskRanMarker = "SCRTY_SESSION_EXPIRYTASK_PORTERR_RAN: "

// expiryTaskBound bounds one RunOnce. An unbounded errors.Is over a cycle or a
// fan-out never returns within it.
const expiryTaskBound = 10 * time.Second

var errExpiryTaskPlain = errors.New("session store down")

type expiryTaskCycleOne struct{}

func (*expiryTaskCycleOne) Error() string   { return "cycle one" }
func (c *expiryTaskCycleOne) Unwrap() error { return c }

type expiryTaskCycleMany struct{}

func (*expiryTaskCycleMany) Error() string     { return "cycle many" }
func (c *expiryTaskCycleMany) Unwrap() []error { return []error{c} }

type expiryTaskPanicUnwrap struct{}

func (expiryTaskPanicUnwrap) Error() string { return "panic unwrap" }
func (expiryTaskPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked") }

type expiryTaskPanicNilUnwrap struct{}

func (expiryTaskPanicNilUnwrap) Error() string { return "panic nil unwrap" }
func (expiryTaskPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type expiryTaskTypedNil struct{}

func (*expiryTaskTypedNil) Error() string { return "typed nil" }

// expiryTaskSelectiveIs panics in its Is method for target, and only then.
type expiryTaskSelectiveIs struct{ target error }

func (expiryTaskSelectiveIs) Error() string { return "selective is" }

func (s expiryTaskSelectiveIs) Is(target error) bool {
	if target == s.target {
		panic("test: Is panicked")
	}

	return false
}

func expiryTaskFanOut(leaf error, depth int) error {
	err := leaf
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// expiryTaskSafeIs is errors.Is that reports false when an Is method panics.
func expiryTaskSafeIs(err, target error) (matched bool) {
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()

	return errors.Is(err, target)
}

type expiryTaskRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*expiryTaskRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *expiryTaskRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())

	return nil
}

func (r *expiryTaskRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *expiryTaskRecorder) WithGroup(string) slog.Handler      { return r }

func (r *expiryTaskRecorder) all() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]slog.Record(nil), r.records...)
}

func expiryTaskAttrs(rec slog.Record) map[string]string {
	attrs := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})

	return attrs
}

// expiryTaskOutcome is what one RunOnce over the sessions task produced. A
// hostile row is compared with the plain failure on every field.
type expiryTaskOutcome struct {
	removed   int
	skipped   bool
	cancelled bool
	level     slog.Level
	msg       string
	reason    string
	nextRan   bool
	nextSkip  bool
}

type expiryTaskRun struct {
	outcome expiryTaskOutcome
	err     error
	aborts  []slog.Record
}

// expiryTaskRunOnce runs session.ExpiryTask over a store whose DeleteExpired
// removes 3 sessions and returns storeErr, through an expiry.Runner, followed
// by a healthy task. cancelInStore cancels the caller's context inside
// DeleteExpired before it returns.
func expiryTaskRunOnce(t *testing.T, storeErr error, cancelInStore bool) expiryTaskRun {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	store := NewMockStore(gomock.NewController(t))
	store.EXPECT().DeleteExpired(gomock.Any()).DoAndReturn(func(context.Context) (int, error) {
		if cancelInStore {
			cancel()
		}

		return 3, storeErr
	}).AnyTimes()

	nextRan := false
	rec := &expiryTaskRecorder{}

	runner, err := expiry.NewRunner([]expiry.Task{
		session.ExpiryTask(store),
		{Name: "next", Run: func(context.Context) (int, error) {
			nextRan = true
			return 1, nil
		}},
	}, expiry.WithLogger(slog.New(rec)))
	require.NoError(t, err)

	type done struct {
		rep    expiry.Report
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

		d.rep, _ = runner.RunOnce(ctx)
		d.ok = true
	}()

	var d done
	select {
	case d = <-ch:
	case <-time.After(expiryTaskBound):
		require.FailNow(t, "RunOnce did not return within the bound")
	}

	require.True(t, d.ok, "the run panicked: %v", d.panicV)
	require.Len(t, d.rep.Results, 2)

	res := d.rep.Results[0]
	got := expiryTaskRun{err: res.Err}
	o := &got.outcome
	o.removed = res.Removed
	o.skipped = res.Skipped
	o.cancelled = expiryTaskSafeIs(res.Err, context.Canceled)
	o.nextRan = nextRan
	o.nextSkip = d.rep.Results[1].Skipped

	for _, r := range rec.all() {
		switch attrs := expiryTaskAttrs(r); {
		case r.Message == porterr.MsgClassificationAborted:
			got.aborts = append(got.aborts, r)
		case attrs["task"] == "sessions":
			o.level, o.msg, o.reason = r.Level, r.Message, attrs["reason"]
		}
	}

	return got
}

// TestPortErrors_ExpiryTask pins that the session store's DeleteExpired error,
// which session.ExpiryTask hands to the expiry runner as the task's error,
// never hangs or crashes the runner, and is answered as a plain task failure.
// ExpiryTask itself reads no error: the runner sanitizes the task's error
// right after Run and classifies it through the bounded walk, so a hostile
// store error (a cycle, a fan-out, a panicking Unwrap) is reported once and
// the next task still runs. An error whose Is method panics for one sentinel
// the runner reads passes the sanitizer and is read through the bounded walk.
func TestPortErrors_ExpiryTask(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(expiryTaskRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name          string
		err           error
		child         bool
		cancelInStore bool
		assert        func(t *testing.T, plain, got expiryTaskRun)
	}

	asFailure := func(reason string) func(t *testing.T, plain, got expiryTaskRun) {
		return func(t *testing.T, plain, got expiryTaskRun) {
			t.Helper()

			assert.Equal(t, plain.outcome, got.outcome, "the outcome differs from a plain task failure")
			assert.ErrorIs(t, got.err, porterr.ErrUnwalkable, "the result carries the sanitizer's fault")
			require.Len(t, got.aborts, 1, "one abort record, on the runner's logger")
			assert.Equal(t, slog.LevelError, got.aborts[0].Level)
			assert.Equal(t, reason, expiryTaskAttrs(got.aborts[0])["reason"])
		}
	}

	selective := func(t *testing.T, plain, got expiryTaskRun) {
		t.Helper()

		assert.Equal(t, plain.outcome, got.outcome, "the outcome differs from a plain task failure")
		require.Len(t, got.aborts, 1, "one abort record, on the runner's logger")
		assert.Equal(t, "panic", expiryTaskAttrs(got.aborts[0])["reason"])
	}

	walked := func(t *testing.T, plain, got expiryTaskRun) {
		t.Helper()

		assert.Equal(t, plain.outcome, got.outcome, "the outcome differs from a plain task failure")
		assert.NotErrorIs(t, got.err, porterr.ErrUnwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	cases := []testCase{
		{name: "cycleOne", err: &expiryTaskCycleOne{}, assert: asFailure("budget")},
		{name: "fan-out", err: expiryTaskFanOut(session.ErrNotFound, 40), assert: asFailure("budget")},
		{name: "panicUnwrap", err: expiryTaskPanicUnwrap{}, assert: asFailure("panic")},
		{name: "panic(nil) Unwrap", err: expiryTaskPanicNilUnwrap{}, assert: asFailure("panic")},
		{
			name: "cycleOne with the caller's context cancelled", err: &expiryTaskCycleOne{},
			cancelInStore: true, assert: asFailure("budget"),
		},
		{name: "cycleMany in a child process", err: &expiryTaskCycleMany{}, child: true, assert: asFailure("budget")},
		{name: "typed-nil root walks to the end", err: (*expiryTaskTypedNil)(nil), assert: walked},
		{
			name: "Is panics only for ErrPurgeUnsupported", err: expiryTaskSelectiveIs{target: expiry.ErrPurgeUnsupported},
			child: true, assert: selective,
		},
		{
			name: "Is panics only for context.Canceled", err: expiryTaskSelectiveIs{target: context.Canceled},
			child: true, assert: selective,
		},
		{name: "plain failure, against itself", err: errExpiryTaskPlain, assert: walked},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				expiryTaskInChild(t, tc.name)

				return
			}

			defaults := &expiryTaskRecorder{}
			prev := slog.Default()
			slog.SetDefault(slog.New(defaults))
			t.Cleanup(func() { slog.SetDefault(prev) })

			plain := expiryTaskRunOnce(t, errExpiryTaskPlain, tc.cancelInStore)
			require.Empty(t, plain.aborts, "a plain failure writes no abort record")
			require.Equal(t, "expiry task failed", plain.outcome.msg)
			require.Equal(t, "purge", plain.outcome.reason)
			require.Equal(t, 3, plain.outcome.removed)

			got := expiryTaskRunOnce(t, tc.err, tc.cancelInStore)
			tc.assert(t, plain, got)

			for _, r := range defaults.all() {
				assert.NotEqual(t, porterr.MsgClassificationAborted, r.Message, "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(expiryTaskRanMarker + tc.name + "\n")
			}
		})
	}
}

// expiryTaskInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints a
// line equal to the marker that shows it ran the row.
func expiryTaskInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), expiryTaskRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := expiryTaskRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
