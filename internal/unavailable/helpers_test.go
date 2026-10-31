package unavailable_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

const (
	testNamespace = "mfa-verify"
	testLimit     = 3
	testWindow    = time.Minute
	testKey       = "k"
	otherKey      = "other"

	defaultTimeout  = 250 * time.Millisecond
	defaultInterval = time.Second
)

// epoch is where every fake clock starts, so the times a failing case prints
// are readable.
var epoch = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// errDown stands for any backend failure: a refused connection, a timeout, an
// exhausted pool.
var errDown = errors.New("dial tcp 10.0.0.1:6379: connection refused")

// harness is one wrapped limiter over a mock backend, with the fake clock its
// breaker and hold set read, and the records it logged. backend scripts the
// backend's checks, records, charges and refunds.
type harness struct {
	backend *MockLimiter
	clock   *clockwork.FakeClock
	logs    *recorder
	limiter ratelimit.Limiter
}

func newHarness(t *testing.T, mode ratelimit.UnavailableMode) *harness {
	t.Helper()

	return newHarnessWith(t, mode, nil)
}

// newHarnessWith is newHarness with edit applied to the configuration last, so
// a case can override a default the harness would otherwise set.
func newHarnessWith(t *testing.T, mode ratelimit.UnavailableMode, edit func(cfg *unavailable.Config)) *harness {
	t.Helper()

	backend := NewMockLimiter(gomock.NewController(t))
	h := &harness{
		backend: backend,
		clock:   clockwork.NewFakeClockAt(epoch),
		logs:    &recorder{},
	}

	cfg := unavailable.DefaultConfig()
	cfg.Mode = mode
	cfg.Clock = h.clock
	cfg.Logger = slog.New(h.logs)
	if edit != nil {
		edit(&cfg)
	}

	l, err := unavailable.Wrap(backend, testNamespace, testLimit, testWindow, cfg)
	require.NoError(t, err)
	h.limiter = l

	return h
}

// down makes every backend call fail, as many times as it is called.
func (h *harness) down() {
	h.backend.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errDown).AnyTimes()
	h.backend.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errDown).AnyTimes()
}

// openBreaker fails one check, which opens the breaker.
func (h *harness) openBreaker(t *testing.T) {
	t.Helper()

	h.backend.EXPECT().Exceeded(gomock.Any(), otherKey).Return(true, errDown)
	_, _ = h.limiter.Exceeded(t.Context(), otherKey)
}

// record is one log record, flattened.
type record struct {
	level   slog.Level
	message string
	attrs   map[string]slog.Value
}

// recorder is a slog.Handler that keeps every record it is given.
type recorder struct {
	mu      sync.Mutex
	records []record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	attrs := map[string]slog.Value{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value
		return true
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record{level: rec.Level, message: rec.Message, attrs: attrs})

	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *recorder) WithGroup(string) slog.Handler { return r }

// all returns a copy of what has been recorded so far.
func (r *recorder) all() []record {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.records)
}

// at returns the records written at level.
func (r *recorder) at(level slog.Level) []record {
	var out []record
	for _, rec := range r.all() {
		if rec.level == level {
			out = append(out, rec)
		}
	}

	return out
}

const (
	msgFallBack  = "ratelimit: backend unavailable, counting locally"
	msgAllow     = "ratelimit: backend unavailable, allowing every attempt"
	msgRecovered = "ratelimit: backend available again"
	msgAllowSupp = "ratelimit: backend unavailable records suppressed"
)

// assertRecords asserts that exactly n records were written at level, each
// with message and naming the namespace.
func assertRecords(t *testing.T, h *harness, level slog.Level, message string, n int) []record {
	t.Helper()

	recs := h.logs.at(level)
	require.Len(t, recs, n, "%s records: %+v", level, h.logs.all())
	for _, rec := range recs {
		assert.Equal(t, message, rec.message)
		assert.Equal(t, testNamespace, rec.attrs["namespace"].String())
	}

	return recs
}

// writesFailReadsSucceed is a backend out of memory under noeviction: every
// record fails and every check answers "not exceeded".
func (h *harness) writesFailReadsSucceed() {
	h.backend.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errDown).AnyTimes()
	h.backend.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
}

// recordN records n failures for key and returns what each record returned.
func (h *harness) recordN(t *testing.T, key string, n int) []error {
	t.Helper()

	errs := make([]error, n)
	for i := range n {
		errs[i] = h.limiter.RecordFailure(t.Context(), key)
	}

	return errs
}

// refusedUnavailable asserts a fail-closed answer that names the outage.
func refusedUnavailable(t *testing.T, exceeded bool, err error) {
	t.Helper()

	require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
	assert.True(t, exceeded)
}
