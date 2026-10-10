package ratelimit_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
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

// fixedClock is a consumer's own read-only clock: the "Read-only source for a
// read-only component" scenario (time-source spec). It carries only Now, and
// never advances on its own, unlike clockwork's fakes.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

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

			clock := clockwork.NewFakeClockAt(epoch)
			l, err := ratelimit.NewMemoryLimiter(tc.limit, testWindow,
				ratelimit.WithMemoryLimiterClock(clock),
				ratelimit.WithMemoryLimiterLogger(discardLogger()))
			require.NoError(t, err)

			for _, offset := range tc.at {
				clock.Advance(epoch.Add(offset).Sub(clock.Now()))
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
			}
			clock.Advance(epoch.Sub(clock.Now()))

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
		opts   []ratelimit.MemoryOption
		assert func(t *testing.T, l *ratelimit.MemoryLimiter, err error)
	}

	refused := func(t *testing.T, l *ratelimit.MemoryLimiter, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.Nil(t, l, "a refused configuration still handed back a limiter")
	}

	// *clockwork.FakeClock implements Now through a pointer receiver, so a nil
	// one passed to WithMemoryLimiterClock is an interface holding a nil
	// pointer: `== nil` misses it, and only the reflect-based check the
	// constructor now uses catches it before the first sweep reads from a nil
	// receiver.
	var nilClock *clockwork.FakeClock

	cases := []testCase{
		{name: "a limit of zero throttles everyone", limit: 0, window: testWindow, assert: refused},
		{name: "a negative limit throttles everyone", limit: -1, window: testWindow, assert: refused},
		{name: "a window of zero counts nothing", limit: testLimit, window: 0, assert: refused},
		{name: "a negative window counts nothing", limit: testLimit, window: -time.Second, assert: refused},
		{
			name:   "a typed nil clock is refused the same as an absent one",
			limit:  testLimit,
			window: testWindow,
			opts:   []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterClock(nilClock)},
			assert: refused,
		},
		{
			name:   "a maximum of zero keys holds no source at all",
			limit:  testLimit,
			window: testWindow,
			opts:   []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterMaxKeys(0)},
			assert: refused,
		},
		{
			name:   "a negative maximum of keys holds no source at all",
			limit:  testLimit,
			window: testWindow,
			opts:   []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterMaxKeys(-1)},
			assert: refused,
		},
		{
			name:   "the smallest limiter that can work is accepted",
			limit:  1,
			window: time.Nanosecond,
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, err error) {
				require.NoError(t, err)
				assert.NotNil(t, l)
			},
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and the limiter
			// reads its window from the consumer's clock: since fixedClock
			// never advances, a failure it stamps stays inside even a
			// nanosecond window for as long as real wall-clock time keeps
			// moving, which is only possible if the limiter asks the clock
			// rather than the wall clock for "now".
			name:   "a consumer's own read-only clock is accepted and used as the time source",
			limit:  1,
			window: time.Millisecond,
			opts:   []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterClock(fixedClock{at: epoch})},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, l)

				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				time.Sleep(50 * time.Millisecond) // real time passes; the frozen clock does not

				exceeded, exceededErr := l.Exceeded(t.Context(), "k")
				require.NoError(t, exceededErr)
				assert.True(t, exceeded,
					"a clock that never advances must keep the window from ever elapsing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]ratelimit.MemoryOption{ratelimit.WithMemoryLimiterLogger(discardLogger())}, tc.opts...)
			l, err := ratelimit.NewMemoryLimiter(tc.limit, tc.window, opts...)
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

	newLimiter := func(t *testing.T, clock *clockwork.FakeClock) *ratelimit.MemoryLimiter {
		t.Helper()
		l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
			ratelimit.WithMemoryLimiterClock(clock),
			ratelimit.WithMemoryLimiterLogger(discardLogger()))
		require.NoError(t, err)
		return l
	}

	t.Run("at most limit stamps are kept per key", func(t *testing.T) {
		t.Parallel()

		clock := clockwork.NewFakeClockAt(epoch)
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

		clock := clockwork.NewFakeClockAt(epoch)
		l, err := ratelimit.NewMemoryLimiter(1, testWindow,
			ratelimit.WithMemoryLimiterClock(clock),
			ratelimit.WithMemoryLimiterLogger(discardLogger()))
		require.NoError(t, err)

		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		clock.Advance(testWindow / 2)
		_, _ = l.Prune(t.Context())

		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "pruning freed a key the window still counts")
	})

	t.Run("a key keeps counting while its newest stamp is live and its oldest has expired", func(t *testing.T) {
		t.Parallel()

		clock := clockwork.NewFakeClockAt(epoch)
		l, err := ratelimit.NewMemoryLimiter(1, testWindow,
			ratelimit.WithMemoryLimiterClock(clock),
			ratelimit.WithMemoryLimiterLogger(discardLogger()))
		require.NoError(t, err)

		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		clock.Advance(50 * time.Second)
		require.NoError(t, l.RecordFailure(t.Context(), "k"))
		clock.Advance(20 * time.Second) // 12:01:10: the first stamp has expired, the second has not
		_, _ = l.Prune(t.Context())

		assert.Equal(t, 1, l.StampsFor("k"), "the key was dropped although it still counts one failure")
		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "the live failure stopped counting")
	})

	t.Run("expired keys are dropped inline, without a background goroutine", func(t *testing.T) {
		t.Parallel()

		clock := clockwork.NewFakeClockAt(epoch)
		l := newLimiter(t, clock)

		const keys = 10_000
		for i := range keys {
			require.NoError(t, l.RecordFailure(t.Context(), fmt.Sprintf("k%d", i)))
		}
		clock.Advance(testWindow + time.Second)

		// A check sweeps only its own key's shard, so every key is checked: that
		// reaches every shard, as traffic does.
		for i := range keys {
			_, err := l.Exceeded(t.Context(), fmt.Sprintf("k%d", i))
			require.NoError(t, err)
		}

		for i := range keys {
			require.Zero(t, l.StampsFor(fmt.Sprintf("k%d", i)),
				"an expired key was still held after checks swept the limiter")
		}
	})

	t.Run("pruning runs at most once per window", func(t *testing.T) {
		t.Parallel()

		clock := clockwork.NewFakeClockAt(epoch)
		l := newLimiter(t, clock)

		// Sweeps are per shard, and one unrelated key shares k's shard only one time
		// in sixty-four, so the traffic is spread over enough keys that one of them
		// all but certainly does (the chance none does is about 1.5e-7).
		unrelated := make([]string, 1000)
		for i := range unrelated {
			unrelated[i] = fmt.Sprintf("u%d", i)
		}
		checkAll := func() {
			for _, u := range unrelated {
				_, err := l.Exceeded(t.Context(), u)
				require.NoError(t, err)
			}
		}

		clock.Advance(30 * time.Second)
		require.NoError(t, l.RecordFailure(t.Context(), "k")) // expires at epoch+90s

		clock.Advance(30 * time.Second) // epoch+60s: a sweep runs and keeps the live key
		checkAll()
		require.Equal(t, 1, l.StampsFor("k"), "a sweep dropped a key that was still inside its window")

		clock.Advance(31 * time.Second) // epoch+91s: the key has expired, but the window is not up
		checkAll()
		for _, u := range unrelated {
			require.NoError(t, l.RecordFailure(t.Context(), u))
		}
		assert.Equal(t, 1, l.StampsFor("k"),
			"the limiter swept again inside the same window, so traffic paces the sweep instead of the window")

		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.False(t, exceeded, "an unswept expired stamp was counted, so memory drove the limit")

		clock.Advance(29 * time.Second) // epoch+120s: one window since the last sweep
		checkAll()
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
	clock := clockwork.NewFakeClockAt(epoch)
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

// settableClock is a clock a test can set to any instant, backwards included,
// which clockwork's fake clock cannot do.
type settableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *settableClock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = at
}

// TestMemoryLimiter_SweepResumesAfterClockSteppedBack pins that a clock stepped
// backwards after a sweep does not stop the inline sweep until the clock catches
// up: keys recorded after the step must still be swept once they expire.
func TestMemoryLimiter_SweepResumesAfterClockSteppedBack(t *testing.T) {
	t.Parallel()

	clk := &settableClock{now: epoch}
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow, ratelimit.WithMemoryLimiterClock(clk))
	require.NoError(t, err)

	_, _ = l.Prune(t.Context())
	clk.Set(epoch.Add(-time.Hour))

	keys := slash64Keys(1000)
	for _, k := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}

	clk.Set(epoch.Add(-time.Hour + 2*time.Minute))
	for _, k := range keys {
		_, err := l.Exceeded(t.Context(), k)
		require.NoError(t, err)
	}

	for _, k := range keys {
		require.Zero(t, l.StampsFor(k), "key %s was still held after its window passed", k)
	}
}

// TestMemoryLimiter_ReturnsMemoryAfterFlood pins that a flood's memory is given
// back once its keys have expired and been swept, rather than held by the map's
// buckets for the life of the process.
func TestMemoryLimiter_ReturnsMemoryAfterFlood(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates 1M keys")
	}

	clk := clockwork.NewFakeClockAt(epoch)
	keys := slash64Keys(1_000_000)
	base := heapAlloc()
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(discardLogger()),
		ratelimit.WithMemoryLimiterMaxKeys(math.MaxInt)) // a flood past the default cap
	require.NoError(t, err)
	for _, k := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}
	// Signed, so a heap that reads below base cannot wrap around to a huge value.
	peak := int64(heapAlloc()) - int64(base) //nolint:gosec // G115: heap sizes are far below MaxInt64

	clk.Advance(2*testWindow + time.Second)
	for _, k := range keys {
		_, _ = l.Exceeded(t.Context(), k)
	}
	after := int64(heapAlloc()) - int64(base) //nolint:gosec // G115: heap sizes are far below MaxInt64
	runtime.KeepAlive(l)
	runtime.KeepAlive(keys)

	assert.Less(t, after, peak/10, "peak=%d after=%d", peak, after)
}

// TestMemoryLimiter_CompactionKeepsLiveKeys pins that replacing a shard's map
// after a sweep carries every surviving key across with its stamps, so giving
// memory back never forgets a failure the window still counts.
func TestMemoryLimiter_CompactionKeepsLiveKeys(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(epoch)
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	keys := slash64Keys(200_000) // about 3,000 per shard, above the 1,024 mark
	for _, k := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}
	clk.Advance(50 * time.Second)
	live := keys[:1000] // a few per shard: well under a quarter of each
	for _, k := range live {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}
	clk.Advance(20 * time.Second) // the first stamps have expired; the live keys' second stamps have not
	_, _ = l.Prune(t.Context())

	for _, k := range live {
		assert.Equal(t, 2, l.StampsFor(k), "key %s lost stamps when its shard was compacted", k)
		exceeded, err := l.Exceeded(t.Context(), k)
		require.NoError(t, err)
		assert.False(t, exceeded, "key %s", k)
	}
	assert.Zero(t, l.StampsFor(keys[len(keys)-1]), "an expired key survived the prune")
}

// TestMemoryLimiter_ConcurrentSweepsKeepLiveKeys pins that inline sweeps,
// explicit prunes and the compactions they trigger, running in every shard at
// once, never lose a failure the window still counts while new failures for the
// same keys are being recorded.
func TestMemoryLimiter_ConcurrentSweepsKeepLiveKeys(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(epoch)
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(discardLogger()))
	require.NoError(t, err)

	keys := slash64Keys(100_000) // about 1,500 per shard, above the 1,024 mark
	for _, k := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}
	clk.Advance(50 * time.Second)
	live := keys[:2000] // about 30 per shard: every shard compacts and carries them
	for _, k := range live {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}
	clk.Advance(20 * time.Second) // the first stamps have expired; the live keys' second stamps have not

	const workers = 8
	var (
		wg   sync.WaitGroup
		lost atomic.Int64
	)
	for w := range workers {
		wg.Add(2)
		go func() { // records a third failure for each live key and looks for all of them
			defer wg.Done()
			for i := w; i < len(live); i += workers {
				_ = l.RecordFailure(t.Context(), live[i])
				if l.StampsFor(live[i]) < 2 {
					lost.Add(1)
				}
			}
		}()
		go func() { // drives sweeps in every shard, inline and explicit
			defer wg.Done()
			for i := len(live) + w; i < len(keys); i += workers {
				_, _ = l.Exceeded(t.Context(), keys[i])
				if i%10_000 < workers {
					_, _ = l.Prune(t.Context())
				}
			}
		}()
	}
	wg.Wait()
	_, _ = l.Prune(t.Context())

	assert.Zero(t, lost.Load(), "a failure the window still counts vanished while shards were swept")
	for _, k := range live {
		assert.Equal(t, testLimit, l.StampsFor(k), "key %s", k)
	}
	assert.Zero(t, l.StampsFor(keys[len(keys)-1]), "an expired key survived")
}
