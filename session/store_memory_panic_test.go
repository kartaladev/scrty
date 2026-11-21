package session_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

const (
	housekeepingRowEnv    = "SCRTY_SESSION_HOUSEKEEPING_ROW"
	housekeepingMarker    = "housekeeping survived"
	housekeepingSecretVal = "sekret-clock-value" //nolint:gosec // G101: a fixture, not a credential
)

// scriptedClock is a clock.Timed whose first After and first Now call run the
// scripted behaviour; every later call is well-behaved on the system clock.
type scriptedClock struct {
	after func() <-chan time.Time
	now   func() time.Time

	afterCalls atomic.Int32
	nowCalls   atomic.Int32
}

var _ clock.Timed = (*scriptedClock)(nil)

func (c *scriptedClock) Now() time.Time {
	if c.nowCalls.Add(1) == 1 && c.now != nil {
		return c.now()
	}

	return time.Now()
}

func (c *scriptedClock) After(d time.Duration) <-chan time.Time {
	if c.afterCalls.Add(1) == 1 && c.after != nil {
		return c.after()
	}

	return time.After(d)
}

// recordingHandler keeps every record it handles.
type recordingHandler struct {
	mu      sync.Mutex
	records []string
	errors  int
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)

		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, b.String())
	if r.Level >= slog.LevelError {
		h.errors++
	}

	return nil
}

type housekeepingRow struct {
	clock       func() *scriptedClock
	wantRecords int
	// panicHandler installs a default slog handler whose Handle panics, so no
	// record is kept and wantRecords is not checked.
	panicHandler bool
}

// panickingHandler is a consumer slog handler whose Handle panics.
type panickingHandler struct{}

func (panickingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (h panickingHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h panickingHandler) WithGroup(string) slog.Handler           { return h }
func (panickingHandler) Handle(context.Context, slog.Record) error { panic("handler boom") }

func housekeepingRows() map[string]housekeepingRow {
	return map[string]housekeepingRow{
		"after-panics-with-value": {func() *scriptedClock {
			return &scriptedClock{after: func() <-chan time.Time { panic(housekeepingSecretVal) }}
		}, 1, false},
		"after-panics-nil": {func() *scriptedClock {
			return &scriptedClock{after: func() <-chan time.Time { panic(nil) }}
		}, 1, false},
		"after-runtime-error": {func() *scriptedClock {
			return &scriptedClock{after: func() <-chan time.Time {
				var m map[string]int
				m[housekeepingSecretVal] = 1 //nolint:staticcheck // SA5000: the panic is the point: a runtime error from the consumer clock

				return nil
			}}
		}, 1, false},
		"after-returns-nil-channel": {func() *scriptedClock {
			return &scriptedClock{after: func() <-chan time.Time { return nil }}
		}, 1, false},
		"after-returns-nil-channel-handler-panics": {func() *scriptedClock {
			return &scriptedClock{after: func() <-chan time.Time { return nil }}
		}, 0, true},
		"now-panics-with-value": {func() *scriptedClock {
			return &scriptedClock{now: func() time.Time { panic(housekeepingSecretVal) }}
		}, 1, false},
		"now-panics-nil": {func() *scriptedClock {
			return &scriptedClock{now: func() time.Time { panic(nil) }}
		}, 1, false},
		"no-panic": {func() *scriptedClock { return &scriptedClock{} }, 0, false},
	}
}

// TestHousekeepingChild is the body the parent re-executes. It does nothing
// unless the parent names a row in the environment, and prints the marker only
// when housekeeping got past the consumer clock's failure, swept, and exited.
func TestHousekeepingChild(t *testing.T) {
	name := os.Getenv(housekeepingRowEnv)
	if name == "" {
		t.Skip("runs only as a child of TestHousekeepingSurvivesConsumerClockFailure")
	}
	row, ok := housekeepingRows()[name]
	require.True(t, ok, "unknown row %q", name)

	ignore := goleak.IgnoreCurrent()
	rec := &recordingHandler{}
	if row.panicHandler {
		slog.SetDefault(slog.New(panickingHandler{}))
	} else {
		slog.SetDefault(slog.New(rec))
	}

	store, err := session.NewMemoryStore(
		session.WithMemoryStoreClock(row.clock()),
		session.WithMemoryStoreHousekeepingInterval(5*time.Millisecond),
	)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, store.Create(t.Context(), &session.Session{
		ID:                "expired",
		FamilyID:          storedFamily,
		FamilyCreatedAt:   createdAt,
		UserID:            testUser,
		CreatedAt:         now,
		IdleExpiresAt:     now.Add(-time.Second),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, store.Start(t.Context()))

	require.Eventually(t, func() bool { return store.Len() == 0 },
		5*time.Second, time.Millisecond, "housekeeping never swept after the clock failed")
	require.NoError(t, store.Shutdown(t.Context()), "the loop did not end at Shutdown")
	goleak.VerifyNone(t, ignore)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !row.panicHandler {
		assert.Equal(t, row.wantRecords, rec.errors, "records: %v", rec.records)
	}
	for _, r := range rec.records {
		assert.NotContains(t, r, housekeepingSecretVal, "the panic value leaked into a record")
	}
	if t.Failed() {
		return
	}

	fmt.Println(housekeepingMarker)
}

// TestHousekeepingSurvivesConsumerClockFailure proves a panic or a nil channel
// from the consumer's clock neither crashes the process nor stops the loop:
// the failed cycle is skipped, one record is written, and the next cycle
// sweeps. Each row runs in a child process, because the failure it guards
// against ends the whole process.
func TestHousekeepingSurvivesConsumerClockFailure(t *testing.T) {
	for name := range housekeepingRows() {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHousekeepingChild$", "-test.count=1") //nolint:gosec // G204: this test binary re-executed with fixed arguments
			cmd.Env = append(os.Environ(), housekeepingRowEnv+"="+name)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out

			err := cmd.Run()
			require.NoError(t, err, "child failed:\n%s", out.String())

			found := false
			for _, line := range strings.Split(out.String(), "\n") {
				if line == housekeepingMarker {
					found = true
				}
			}
			assert.True(t, found, "child did not reach the marker:\n%s", out.String())
		})
	}
}
