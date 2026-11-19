package policy_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

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

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/policy"
)

// counterErrCycleOne is an error whose Unwrap returns itself.
type counterErrCycleOne struct{}

func (*counterErrCycleOne) Error() string   { return "counter: hostile text" }
func (c *counterErrCycleOne) Unwrap() error { return c }

// counterErrCycleMany is an error whose Unwrap() []error contains itself.
type counterErrCycleMany struct{}

func (*counterErrCycleMany) Error() string     { return "counter: hostile text" }
func (c *counterErrCycleMany) Unwrap() []error { return []error{c} }

// counterErrUnwrapPanics is an error whose Unwrap panics.
type counterErrUnwrapPanics struct{}

func (counterErrUnwrapPanics) Error() string { return "counter: hostile text" }
func (counterErrUnwrapPanics) Unwrap() error { panic("counter: the link's Unwrap panicked") }

// recordSink collects the records written to a logger.
type recordSink struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (*recordSink) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordSink) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r.Clone())

	return nil
}

func (h *recordSink) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordSink) WithGroup(string) slog.Handler      { return h }

func (h *recordSink) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.recs...)
}

const counterRowEnv = "SCRTY_POLICY_PORTERR_ROW"

// evaluateWithin runs Evaluate with a counter that fails with err, on its own
// goroutine, and fails the test when it hangs or panics.
func evaluateWithin(t *testing.T, err error) policy.Decision {
	t.Helper()

	type result struct {
		d        policy.Decision
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			if v := recover(); v != nil {
				r.panicked, r.value = true, v
			}

			done <- r
		}()

		counter := NewMockSessionCounter(gomock.NewController(t))
		counter.EXPECT().CountActiveByUser(gomock.Any(), concurrentUser).AnyTimes().Return(0, err)

		p, perr := policy.NewConcurrentSessions(counter, 3)
		if perr != nil {
			panic(perr)
		}

		r.d = p.Evaluate(t.Context(), &policy.Input{User: concurrentUser})
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile counter error escaped as a panic: %v", r.value)

		return r.d
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile counter error hung Evaluate")

		return policy.Decision{}
	}
}

// TestConcurrentSessions_PortErrors pins that a hostile error from the
// counter is denied exactly as a plain outage of it is, and reported once.
func TestConcurrentSessions_PortErrors(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(counterRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	sink := &recordSink{}
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })

	plain := evaluateWithin(t, errors.New("the session store is unreachable"))
	require.Equal(t, policy.Deny, plain.Outcome)
	require.ErrorIs(t, plain.Reason, policy.ErrTooManySessions)
	require.Empty(t, sink.records(), "a plain outage writes no record")

	type testCase struct {
		name   string
		err    error
		reason string
		child  bool
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: &counterErrCycleOne{}, reason: "budget"},
		{name: "panicking Unwrap", err: counterErrUnwrapPanics{}, reason: "panic"},
		{name: "self-cycle through Unwrap() []error", err: &counterErrCycleMany{}, reason: "budget", child: true},
	}

	for _, tc := range cases {
		if childRow != "" && !tc.child {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && childRow == "" {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()

				//nolint:gosec // G204: re-runs this test binary with this test's own name
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConcurrentSessions_PortErrors$", "-test.count=1")
				cmd.Env = append(os.Environ(), counterRowEnv+"=1")

				out, err := cmd.CombinedOutput()
				require.NoError(t, ctx.Err(), "the child did not finish within a minute")

				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

				return
			}

			before := len(sink.records())
			d := evaluateWithin(t, tc.err)

			assert.Equal(t, plain.Outcome, d.Outcome, "the hostile error is denied as a plain outage is")
			require.Error(t, d.Reason)
			assert.Equal(t, plain.Reason.Error(), d.Reason.Error(), "behind the same fixed text")
			assert.ErrorIs(t, d.Reason, policy.ErrTooManySessions)
			assert.ErrorIs(t, d.Reason, porterr.ErrUnwalkable, "and the cause is the library's fault, not the consumer's error")

			recs := sink.records()[before:]
			require.Len(t, recs, 1, "one abort record")
			assert.Equal(t, slog.LevelError, recs[0].Level)
			assert.Equal(t, porterr.MsgClassificationAborted, recs[0].Message)

			var reason string

			recs[0].Attrs(func(a slog.Attr) bool {
				if a.Key == "reason" {
					reason = a.Value.String()
				}

				assert.NotContains(t, a.Value.String(), "hostile text")

				return true
			})
			assert.Equal(t, tc.reason, reason)
		})
	}
}
