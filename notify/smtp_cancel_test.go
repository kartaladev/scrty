package notify_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/notify"
)

// levelRecorder is a slog handler that keeps the level and message of every
// record it is given, so a case can ask what the sender logged and how loudly.
type levelRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*levelRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, r.Clone())

	return nil
}

func (h *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *levelRecorder) WithGroup(string) slog.Handler { return h }

// levels returns the level of every record whose message is msg.
func (h *levelRecorder) levels(msg string) []slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []slog.Level

	for _, r := range h.records {
		if r.Message == msg {
			out = append(out, r.Level)
		}
	}

	return out
}

func (h *levelRecorder) anyAt(level slog.Level) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, r := range h.records {
		if r.Level == level {
			return true
		}
	}

	return false
}

const sendFailedMsg = "notify: smtp send failed"

func TestSMTPSender_CallerEndedSendReportsContextError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []notify.SMTPOption
		// ctx modifies the caller's context; nil leaves it live.
		ctx    func(t *testing.T, ctx context.Context) context.Context
		assert func(t *testing.T, err error, logged *levelRecorder)
	}

	// isTimeout is today's outcome of a send that ran past a deadline: the
	// connection's own timeout, reachable through the returned error.
	isTimeout := func(t *testing.T, err error) {
		t.Helper()

		var netErr net.Error

		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout(), "the network error must stay in the chain as a timeout")
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	}

	cases := []testCase{
		{
			name: "the caller cancels while the server has not greeted",
			opts: []notify.SMTPOption{notify.WithSMTPTimeout(30 * time.Second)},
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				t.Helper()

				ctx, cancel := context.WithCancel(ctx)
				timer := time.AfterFunc(100*time.Millisecond, cancel)
				t.Cleanup(func() { timer.Stop(); cancel() })

				return ctx
			},
			assert: func(t *testing.T, err error, logged *levelRecorder) {
				require.ErrorIs(t, err, context.Canceled,
					"a send the caller cancelled must match context.Canceled; got %T", err)
				assert.NotErrorIs(t, err, context.DeadlineExceeded)
				assert.False(t, logged.anyAt(slog.LevelError), "a caller's hang-up is not an error-level failure")
				assert.Equal(t, []slog.Level{slog.LevelDebug}, logged.levels(sendFailedMsg),
					"a caller's hang-up is still recorded, at debug level")
			},
		},
		{
			name: "the caller's deadline passes before the sender's own",
			opts: []notify.SMTPOption{notify.WithSMTPTimeout(30 * time.Second)},
			ctx: func(t *testing.T, ctx context.Context) context.Context {
				t.Helper()

				ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
				t.Cleanup(cancel)

				return ctx
			},
			assert: func(t *testing.T, err error, logged *levelRecorder) {
				require.ErrorIs(t, err, context.DeadlineExceeded,
					"a send that ran past the caller's deadline must match context.DeadlineExceeded; got %T", err)
				assert.NotErrorIs(t, err, context.Canceled)
				isTimeout(t, err)
				assert.False(t, logged.anyAt(slog.LevelError), "a caller's hang-up is not an error-level failure")
				assert.Equal(t, []slog.Level{slog.LevelDebug}, logged.levels(sendFailedMsg),
					"a caller's hang-up is still recorded, at debug level")
			},
		},
		{
			name: "the sender's own deadline passes while the caller is live",
			opts: []notify.SMTPOption{notify.WithSMTPTimeout(200 * time.Millisecond)},
			assert: func(t *testing.T, err error, logged *levelRecorder) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, context.Canceled, "the caller did not cancel")
				assert.NotErrorIs(t, err, context.DeadlineExceeded, "the caller's deadline did not pass")
				isTimeout(t, err)
				assert.Equal(t, []slog.Level{slog.LevelError}, logged.levels(sendFailedMsg),
					"the sender's own timeout is a failed send")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logged := &levelRecorder{}

			srv := startScriptedServer(t, scriptSilentGreeting())
			s := newTestSMTPSender(t, srv,
				append([]notify.SMTPOption{notify.WithSMTPLogger(slog.New(logged))}, tc.opts...)...)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t, ctx)
			}

			done := make(chan error, 1)
			go func() { done <- s.Send(ctx, testMessage()) }()

			select {
			case err := <-done:
				tc.assert(t, err, logged)
			case <-time.After(10 * time.Second):
				t.Fatal("the send must end well inside the 30s bound once its deadline or the caller ends it")
			}
		})
	}
}
