package notify_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/notify"
)

// queuedPanickingLogRowEnv names the row a child process of
// TestQueuedSender_SurvivesPanickingLogHandler runs. It is empty in the parent.
const queuedPanickingLogRowEnv = "SCRTY_NOTIFY_QUEUED_PANICKINGLOG_ROW"

// queuedPanickingLogRan is printed by a child, followed by the row's name, once
// the row ran to the end and every check passed.
const queuedPanickingLogRan = "notify-queued-panickinglog-row-ran:"

// panickingHandler notes every record it is handed, then panics, as a consumer
// handler that is down does on every write.
type panickingHandler struct {
	mu   sync.Mutex
	seen []string
}

func (*panickingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *panickingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.seen = append(h.seen, r.Message)
	h.mu.Unlock()

	panic("handler down")
}

func (h *panickingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *panickingHandler) WithGroup(string) slog.Handler      { return h }

func (h *panickingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]string(nil), h.seen...)
}

// TestQueuedSender_SurvivesPanickingLogHandler pins that a consumer slog.Handler
// that panics on every record costs the worker only the record: the process
// lives, the same worker delivers the next message, and a recovered panic of the
// inner sender is not mistaken for a goroutine that ended. The handler is
// reached as the sender's own logger and, separately, as the chain's logger on
// the queuing context. Each row runs in a child process, because the failure
// under test kills the process.
func TestQueuedSender_SurvivesPanickingLogHandler(t *testing.T) { //nolint:paralleltest // children re-run the binary
	row := os.Getenv(queuedPanickingLogRowEnv)

	cases := []struct {
		name  string
		chain bool
		inner func() error
	}{
		{name: "own logger, inner fails", inner: func() error { return errors.New("smtp: down") }},
		{name: "own logger, inner panics", inner: func() error { panic("inner down") }},
		{name: "chain logger, inner fails", chain: true, inner: func() error { return errors.New("smtp: down") }},
		{name: "chain logger, inner panics", chain: true, inner: func() error { panic("inner down") }},
		{name: "own logger, inner error unwalkable", inner: unwalkableError},
		{name: "chain logger, inner error unwalkable", chain: true, inner: unwalkableError},
	}

	for _, tc := range cases {
		if row != "" && row != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if row == "" {
				queuedPanickingLogInChild(t, tc.name)

				return
			}

			h := &panickingHandler{}
			next := make(chan struct{})

			var once sync.Once

			first := make(chan struct{}, 1)
			first <- struct{}{}

			inner := senderFunc(func(context.Context, notify.Message) error {
				select {
				case <-first:
					return tc.inner()
				default:
					once.Do(func() { close(next) })

					return nil
				}
			})

			opts := []notify.QueuedOption{notify.WithQueueWorkers(1)}
			ctx := t.Context()

			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(h))
			} else {
				opts = append(opts, notify.WithQueueLogger(slog.New(h)))
			}

			s, err := notify.NewQueuedSender(inner, opts...)
			require.NoError(t, err)

			require.NoError(t, s.Send(ctx, testMessage()))
			require.NoError(t, s.Send(ctx, testMessage()))

			select {
			case <-next:
			case <-time.After(10 * time.Second):
				t.Fatal("the worker did not deliver the next message")
			}

			sctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 10*time.Second)
			defer cancel()

			require.NoError(t, s.Shutdown(sctx))

			for _, m := range h.messages() {
				assert.NotContains(t, m, "ended its goroutine", "a handler panic is not a goexit")

				if strings.Contains(tc.name, "unwalkable") {
					assert.NotContains(t, m, "sender panicked", "the abort record's handler panic is not the sender's")
				}
			}

			println(queuedPanickingLogRan + tc.name) //nolint:forbidigo // the marker the parent reads
		})
	}
}

// cyclicError is an error whose Unwrap chain never ends.
type cyclicError struct{}

func (e *cyclicError) Error() string { return "cyclic" }
func (e *cyclicError) Unwrap() error { return e }

func unwalkableError() error { return &cyclicError{} }

func queuedPanickingLogInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), queuedPanickingLogRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	assert.Contains(t, string(out), queuedPanickingLogRan+row, "the child did not run its row")
}
