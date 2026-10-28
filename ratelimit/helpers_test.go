package ratelimit_test

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

func newExpiryLimiter(t *testing.T) (*ratelimit.MemoryLimiter, *clockwork.FakeClock) {
	t.Helper()

	clk := clockwork.NewFakeClock()
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	return l, clk
}

func recordFor(t *testing.T, l *ratelimit.MemoryLimiter, keys ...string) {
	t.Helper()

	for _, key := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), key))
	}
}

const (
	testLimit  = 3
	testWindow = time.Minute
)

// epoch is the instant every clock-driven case starts from, so the times a
// failing case prints are readable rather than whatever the machine's clock says.
var epoch = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now, and
// never advances on its own, unlike clockwork's fakes.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// logRecorder collects what a component wrote, so a test can count records
// rather than trust that logging happened at all.
type logRecorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newLogRecorder() (*logRecorder, *slog.Logger) {
	rec := &logRecorder{}
	return rec, slog.New(slog.NewJSONHandler(rec, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (r *logRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.buf.Write(p)
}

func (r *logRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.buf.String()
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(new(bytes.Buffer), nil))
}

// memoryLimiter returns the default limiter, kept quiet.
func memoryLimiter(t *testing.T) *ratelimit.MemoryLimiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	return l
}
