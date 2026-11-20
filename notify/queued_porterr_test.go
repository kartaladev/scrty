package notify_test

// TestQueuedSender_PortErrors is one matrix of rows sharing one invariant set
// (the worker survives, the delivery-failed record is the plain outage's, one
// abort record or none, nothing quoted), so it keeps one shared assertion
// block rather than an assert closure per row. It replaces slog.Default() for
// its duration, so it does not run in parallel, and restores what it found.

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/notify"
)

// queuedPortErrRowEnv names the row a child process of
// TestQueuedSender_PortErrors runs. It is empty in the parent.
const queuedPortErrRowEnv = "SCRTY_NOTIFY_QUEUED_PORTERR_ROW"

// queuedPortErrRan is what a child prints, on a line of its own followed by the
// row's name, once it has run its row to the end and every check passed.
const queuedPortErrRan = "notify-queued-porterr-row-ran:"

// queuedSecret is the text every hostile error and panic value carries. A
// record that quotes it has leaked the consumer's error.
const queuedSecret = "queued-hostile-secret-text"

const queuedDeliveryFailed = "notify: delivery failed"

type queuedCycleOne struct{}

func (*queuedCycleOne) Error() string   { return queuedSecret }
func (c *queuedCycleOne) Unwrap() error { return c }

type queuedCycleMany struct{}

func (*queuedCycleMany) Error() string     { return queuedSecret }
func (c *queuedCycleMany) Unwrap() []error { return []error{c} }

type queuedUnwrapPanics struct{}

func (queuedUnwrapPanics) Error() string { return queuedSecret }
func (queuedUnwrapPanics) Unwrap() error { panic(queuedSecret) }

type queuedUnwrapPanicsNil struct{}

func (queuedUnwrapPanicsNil) Error() string { return queuedSecret }
func (queuedUnwrapPanicsNil) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type queuedIsPanics struct{}

func (queuedIsPanics) Error() string { return queuedSecret }
func (queuedIsPanics) Is(error) bool { panic(queuedSecret) }

type queuedTypedNil struct{}

func (*queuedTypedNil) Error() string { return queuedSecret }

// queuedFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func queuedFanOut(depth int) error {
	err := errors.New(queuedSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// queuedRecord is one record a logger received, with its attributes flattened
// to text.
type queuedRecord struct {
	msg   string
	level slog.Level
	attrs map[string]string
}

func (r queuedRecord) text() string {
	var b strings.Builder

	b.WriteString(r.msg)

	for k, v := range r.attrs {
		b.WriteString(" " + k + "=" + v)
	}

	return b.String()
}

// queuedLogs captures every record it is handed.
type queuedLogs struct {
	mu      sync.Mutex
	records []queuedRecord
}

func (*queuedLogs) Enabled(context.Context, slog.Level) bool { return true }

func (h *queuedLogs) Handle(_ context.Context, r slog.Record) error {
	rec := queuedRecord{msg: r.Message, level: r.Level, attrs: map[string]string{}}

	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()

		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, rec)

	return nil
}

func (h *queuedLogs) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *queuedLogs) WithGroup(string) slog.Handler      { return h }

func (h *queuedLogs) all() []queuedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]queuedRecord(nil), h.records...)
}

func (h *queuedLogs) named(msg string) []queuedRecord {
	var out []queuedRecord

	for _, r := range h.all() {
		if r.msg == msg {
			out = append(out, r)
		}
	}

	return out
}

// queuedPortOutcome is what one run of a failing inner sender produced.
type queuedPortOutcome struct {
	logs     *queuedLogs
	defaults *queuedLogs

	// nextDelivered is whether the message queued after the failing one reached
	// the inner sender, on the only worker, within the bound.
	nextDelivered bool

	// shutdownErr is what Shutdown returned, bounded.
	shutdownErr error
}

// queuedPortRun queues one message to a sender whose inner Send fails with
// portErr, then a second that succeeds, on a pool of one worker so the second
// reaches the inner sender only if the worker survived the first. When
// expired is set the inner sender returns portErr only after its delivery's
// context has ended, so the failure is read under an expired context.
func queuedPortRun(t *testing.T, portErr error, expired bool) queuedPortOutcome {
	t.Helper()

	out := queuedPortOutcome{logs: &queuedLogs{}, defaults: &queuedLogs{}}

	prev := slog.Default()
	slog.SetDefault(slog.New(out.defaults))
	t.Cleanup(func() { slog.SetDefault(prev) })

	var calls atomic.Int64

	next := make(chan struct{})

	inner := senderFunc(func(ctx context.Context, _ notify.Message) error {
		if calls.Add(1) == 1 {
			if expired {
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Second):
				}
			}

			return portErr
		}

		close(next)

		return nil
	})

	opts := []notify.QueuedOption{notify.WithQueueWorkers(1), notify.WithQueueLogger(slog.New(out.logs))}
	if expired {
		opts = append(opts, notify.WithQueueSendTimeout(20*time.Millisecond))
	}

	s, err := notify.NewQueuedSender(inner, opts...)
	require.NoError(t, err)

	require.NoError(t, s.Send(t.Context(), testMessage()))
	require.NoError(t, s.Send(t.Context(), testMessage()))

	select {
	case <-next:
		out.nextDelivered = true
	case <-time.After(10 * time.Second):
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
	defer cancel()

	out.shutdownErr = s.Shutdown(ctx)

	return out
}

// queuedPortErrInChild re-runs the test binary on the one row and requires the
// child to exit 0 within a minute and to print the marker line of that row.
// The child skips every row whose name does not match, so a row name that
// matches nothing prints no marker and fails here.
func queuedPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), queuedPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	ran := false

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if sc.Text() == queuedPortErrRan+row {
			ran = true
		}
	}

	require.NoError(t, sc.Err())
	assert.True(t, ran, "the child printed no line %q: it did not run its row", queuedPortErrRan+row)
}

// TestQueuedSender_PortErrors pins that a hostile error from the wrapped
// sender, which the queue's worker reads on a goroutine the library owns, is
// answered as a plain outage is: the worker neither hangs nor panics, the
// delivery-failed record is written as for a plain outage, the abort of the
// error's walk is reported once to the sender's logger and never to
// slog.Default(), no record quotes the error, and the same worker delivers the
// next message. An error whose Is panics, or a typed-nil one, walks to the end
// and writes no abort record.
func TestQueuedSender_PortErrors(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(queuedPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainErr := errors.New("smtp: connection refused")

	type testCase struct {
		name string
		err  error

		// reason is the abort record's reason, and "" when the walk completes.
		reason string

		// child runs the row in a child process: an unbounded read of it
		// overflows the stack fatally.
		child bool
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: &queuedCycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &queuedCycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: queuedUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: queuedUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: queuedFanOut(25), reason: "budget"},
		// Walked to the end: nothing for the walk to abort on.
		{name: "Is panicking", err: queuedIsPanics{}},
		{name: "typed-nil root", err: (*queuedTypedNil)(nil)},
	}

	contexts := []struct {
		name    string
		expired bool
	}{
		{name: "live"},
		{name: "expired"},
	}

	for _, c := range contexts {
		for _, tc := range cases {
			row := c.name + "/" + tc.name
			if childRow != "" && childRow != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if tc.child && childRow == "" {
					queuedPortErrInChild(t, row)

					return
				}

				plain := queuedPortRun(t, plainErr, c.expired)
				require.True(t, plain.nextDelivered, "the plain outage does not stop the worker")
				require.NoError(t, plain.shutdownErr)
				require.Len(t, plain.logs.named(queuedDeliveryFailed), 1)
				require.Empty(t, plain.logs.named(porterr.MsgClassificationAborted), "a plain outage writes no abort record")

				got := queuedPortRun(t, tc.err, c.expired)

				assert.True(t, got.nextDelivered, "the worker did not deliver the next message")
				assert.NoError(t, got.shutdownErr, "the drain did not finish")

				failed := got.logs.named(queuedDeliveryFailed)
				require.Len(t, failed, 1, "one delivery-failed record, as for a plain outage")
				assert.Equal(t, slog.LevelError, failed[0].level)
				assert.Equal(t, plain.logs.named(queuedDeliveryFailed)[0].attrs["reason"], failed[0].attrs["reason"])

				aborts := got.logs.named(porterr.MsgClassificationAborted)
				if tc.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the sender's logger")
					assert.Equal(t, slog.LevelError, aborts[0].level)
					assert.Equal(t, tc.reason, aborts[0].attrs["reason"])
				}

				assert.Empty(t, got.defaults.named(porterr.MsgClassificationAborted), "none on slog.Default()")

				for _, r := range got.logs.all() {
					assert.NotContains(t, r.text(), queuedSecret, "a record quotes the consumer's error")
				}

				if childRow != "" && !t.Failed() {
					fmt.Fprintln(os.Stdout, queuedPortErrRan+row)
				}
			})
		}
	}
}
