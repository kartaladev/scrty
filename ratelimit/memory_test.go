package ratelimit_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

const (
	testLimit  = 3
	testWindow = time.Minute
)

// epoch is the instant every clock-driven case starts from, so the times a
// failing case prints are readable rather than whatever the machine's clock says.
var epoch = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

// TestLimitsCountFailuresNotRequests pins the difference between a rate limiter
// and a request limiter: only a recorded failure spends the allowance, so a
// source making ordinary traffic can ask forever without throttling itself.
func TestLimitsCountFailuresNotRequests(t *testing.T) {
	t.Parallel()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow)
	require.NoError(t, err)

	for range 100 {
		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		require.False(t, exceeded, "checking tripped the limit without a single failure")
	}

	for range testLimit - 1 {
		require.NoError(t, l.RecordFailure(t.Context(), "k"))
	}
	exceeded, err := l.Exceeded(t.Context(), "k")
	require.NoError(t, err)
	assert.False(t, exceeded, "a key one failure short of the limit was reported as exceeded")

	require.NoError(t, l.RecordFailure(t.Context(), "k"))
	exceeded, err = l.Exceeded(t.Context(), "k")
	require.NoError(t, err)
	assert.True(t, exceeded, "the limit's failure did not trip the limit")
}

// TestTheWindowSlides pins the boundary itself. "A one-minute window" means the
// same thing at every call site only if the rule is exact, so the edge and the
// instant either side of it are all named cases.
func TestTheWindowSlides(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		limit  int
		at     []time.Duration // failure times, relative to the instant of the check
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, exceeded bool, err error)
	}

	counts := func(t *testing.T, exceeded bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, exceeded, "a failure inside the window was not counted")
	}
	doesNotCount := func(t *testing.T, exceeded bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, exceeded, "a failure outside the window was still counted")
	}

	cases := []testCase{
		{
			name:   "a failure inside the window counts",
			limit:  1,
			at:     []time.Duration{-30 * time.Second},
			assert: counts,
		},
		{
			name:   "a failure exactly at the window edge does not count",
			limit:  1,
			at:     []time.Duration{-testWindow},
			assert: doesNotCount,
		},
		{
			name:   "a failure one instant inside the edge counts",
			limit:  1,
			at:     []time.Duration{-testWindow + time.Nanosecond},
			assert: counts,
		},
		{
			name:   "a failure older than the window does not count",
			limit:  1,
			at:     []time.Duration{-2 * testWindow},
			assert: doesNotCount,
		},
		{
			name:   "failures either side of a fixed boundary count together",
			limit:  2,
			at:     []time.Duration{-30 * time.Second, -10 * time.Second},
			assert: counts,
		},
		{
			name:  "a check whose context has ended is an error, not an answer",
			limit: 1,
			at:    []time.Duration{-30 * time.Second},
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				return cancelled
			},
			assert: func(t *testing.T, exceeded bool, err error) {
				require.ErrorIs(t, err, context.Canceled,
					"a check that could not be made reported an answer anyway")
				assert.True(t, exceeded,
					"the bool a careless caller reads lifted the limit while the check was failing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clock := newFakeClock(epoch)
			l, err := ratelimit.NewMemoryLimiter(tc.limit, testWindow,
				ratelimit.WithMemoryLimiterClock(clock),
				ratelimit.WithMemoryLimiterLogger(discardLogger()))
			require.NoError(t, err)

			for _, offset := range tc.at {
				clock.Set(epoch.Add(offset))
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
			}
			clock.Set(epoch)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			exceeded, err := l.Exceeded(ctx, "k")
			tc.assert(t, exceeded, err)
		})
	}
}

// TestNewMemoryLimiterRefusesALimiterThatCannotWork pins that a limit which can
// never trip, and one which always trips, are wiring mistakes caught at
// construction rather than surprises discovered under attack.
func TestNewMemoryLimiterRefusesALimiterThatCannotWork(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, l *ratelimit.MemoryLimiter, err error)
	}

	refused := func(t *testing.T, l *ratelimit.MemoryLimiter, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.Nil(t, l, "a refused configuration still handed back a limiter")
	}

	cases := []testCase{
		{name: "a limit of zero throttles everyone", limit: 0, window: testWindow, assert: refused},
		{name: "a negative limit throttles everyone", limit: -1, window: testWindow, assert: refused},
		{name: "a window of zero counts nothing", limit: testLimit, window: 0, assert: refused},
		{name: "a negative window counts nothing", limit: testLimit, window: -time.Second, assert: refused},
		{
			name:   "the smallest limiter that can work is accepted",
			limit:  1,
			window: time.Nanosecond,
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, err error) {
				require.NoError(t, err)
				assert.NotNil(t, l)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := ratelimit.NewMemoryLimiter(tc.limit, tc.window,
				ratelimit.WithMemoryLimiterLogger(discardLogger()))
			tc.assert(t, l, err)
		})
	}
}

// TestTheLimiterBoundsItsMemoryWithoutDisarmingLimits pins both halves of the
// trade-off at once: an attacker must not be able to grow the limiter without
// bound, and the limiter must not buy that bound by forgetting failures the
// window still counts.
func TestTheLimiterBoundsItsMemoryWithoutDisarmingLimits(t *testing.T) {
	t.Parallel()

	newLimiter := func(t *testing.T, clock *fakeClock) *ratelimit.MemoryLimiter {
		t.Helper()
		l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
			ratelimit.WithMemoryLimiterClock(clock),
			ratelimit.WithMemoryLimiterLogger(discardLogger()))
		require.NoError(t, err)
		return l
	}

	t.Run("at most limit stamps are kept per key", func(t *testing.T) {
		t.Parallel()

		clock := newFakeClock(epoch)
		l := newLimiter(t, clock)

		for range 1000 {
			require.NoError(t, l.RecordFailure(t.Context(), "k"))
		}
		assert.LessOrEqual(t, l.StampsFor("k"), testLimit, "the limiter grew without bound")

		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "trimming stamps let the key back under its limit")
	})

	t.Run("pruning never drops a key whose newest stamp is still inside the window", func(t *testing.T) {
		t.Parallel()

		clock := newFakeClock(epoch)
		l, err := ratelimit.NewMemoryLimiter(1, testWindow,
			ratelimit.WithMemoryLimiterClock(clock),
			ratelimit.WithMemoryLimiterLogger(discardLogger()))
		require.NoError(t, err)

		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		clock.Advance(testWindow / 2)
		l.Prune()

		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "pruning freed a key the window still counts")
	})

	t.Run("a key keeps counting while its newest stamp is live and its oldest has expired", func(t *testing.T) {
		t.Parallel()

		clock := newFakeClock(epoch)
		l, err := ratelimit.NewMemoryLimiter(1, testWindow,
			ratelimit.WithMemoryLimiterClock(clock),
			ratelimit.WithMemoryLimiterLogger(discardLogger()))
		require.NoError(t, err)

		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		clock.Advance(50 * time.Second)
		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		clock.Advance(20 * time.Second) // 12:01:10: the first stamp has expired, the second has not
		l.Prune()

		assert.Equal(t, 1, l.StampsFor("k"), "the key was dropped although it still counts one failure")
		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "the live failure stopped counting")
	})

	t.Run("expired keys are dropped inline, without a background goroutine", func(t *testing.T) {
		t.Parallel()

		clock := newFakeClock(epoch)
		l := newLimiter(t, clock)

		const keys = 10_000
		for i := range keys {
			require.NoError(t, l.RecordFailure(t.Context(), fmt.Sprintf("k%d", i)))
		}
		clock.Advance(testWindow + time.Second)

		_, err := l.Exceeded(t.Context(), "unrelated")
		require.NoError(t, err)

		for i := range keys {
			require.Zero(t, l.StampsFor(fmt.Sprintf("k%d", i)),
				"an expired key was still held after a check swept the limiter")
		}
	})

	t.Run("pruning runs at most once per window", func(t *testing.T) {
		t.Parallel()

		clock := newFakeClock(epoch)
		l := newLimiter(t, clock)

		clock.Advance(30 * time.Second)
		require.NoError(t, l.RecordFailure(t.Context(), "k")) // expires at epoch+90s

		clock.Advance(30 * time.Second) // epoch+60s: a sweep runs and keeps the live key
		_, err := l.Exceeded(t.Context(), "unrelated")
		require.NoError(t, err)
		require.Equal(t, 1, l.StampsFor("k"), "a sweep dropped a key that was still inside its window")

		clock.Advance(31 * time.Second) // epoch+91s: the key has expired, but the window is not up
		for range 100 {
			_, err := l.Exceeded(t.Context(), "unrelated")
			require.NoError(t, err)
			require.NoError(t, l.RecordFailure(t.Context(), "unrelated"))
		}
		assert.Equal(t, 1, l.StampsFor("k"),
			"the limiter swept again inside the same window, so traffic paces the sweep instead of the window")

		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.False(t, exceeded, "an unswept expired stamp was counted, so memory drove the limit")

		clock.Advance(29 * time.Second) // epoch+120s: one window since the last sweep
		_, err = l.Exceeded(t.Context(), "unrelated")
		require.NoError(t, err)
		assert.Zero(t, l.StampsFor("k"), "the next window's sweep did not run")
	})
}

// TestThePerReplicaWarningIsWrittenOnce pins that the default limiter states its
// own limit at runtime exactly once. Saying it on every call would bury it in the
// noise it warns about, and saying it never would leave an operator believing a
// limit of 3 holds across a fleet where it is really 3 per replica.
func TestThePerReplicaWarningIsWrittenOnce(t *testing.T) {
	t.Parallel()

	recorder, logger := newLogRecorder()
	clock := newFakeClock(epoch)
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clock),
		ratelimit.WithMemoryLimiterLogger(logger))
	require.NoError(t, err)

	for range 50 {
		_, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
	}
	for range 50 {
		require.NoError(t, l.RecordFailure(t.Context(), "k"))
	}

	assert.Equal(t, 1, strings.Count(recorder.String(), "counts only this replica"),
		"the per-replica warning repeated on every call")
}

// fakeClock is the time source the clock-driven cases advance by hand, so a
// window's boundary is tested at the nanosecond rather than approached by
// sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func (c *fakeClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = now
}

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
