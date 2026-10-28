// The memory limiter cases are separate TestXxx functions where their setup
// differs in kind — a fake, settable or stalling clock, racing goroutines, or a
// heap measurement — and tables wherever the rows share one call shape.
package ratelimit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
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

// TestMemoryLimiter_Prune pins the count Prune returns and that it removes only
// keys the window no longer counts.
func TestMemoryLimiter_Prune(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock)
		assert func(t *testing.T, l *ratelimit.MemoryLimiter, removed int)
	}

	cases := []testCase{
		{
			name: "quiet limiter with three expired keys removes three",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "a", "b", "c")
				clk.Advance(testWindow + time.Second)
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, removed int) {
				assert.Equal(t, 3, removed)
				for _, key := range []string{"a", "b", "c"} {
					assert.Zero(t, l.StampsFor(key))
				}
			},
		},
		{
			name: "key with a stamp inside the window survives with its count",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "old", "live")
				clk.Advance(testWindow / 2)
				recordFor(t, l, "live")
				clk.Advance(testWindow/2 + time.Second) // old expired, live's newest stamp has not
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, removed int) {
				assert.Equal(t, 1, removed)
				assert.Equal(t, 2, l.StampsFor("live"))
				exceeded, err := l.Exceeded(t.Context(), "live")
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Zero(t, l.StampsFor("old"))
			},
		},
		{
			name: "nothing expired removes nothing",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				recordFor(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, removed int) {
				assert.Zero(t, removed)
				assert.Equal(t, 1, l.StampsFor("a"))
				assert.Equal(t, 1, l.StampsFor("b"))
			},
		},
		{
			name: "a second prune removes nothing",
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				recordFor(t, l, "a", "b")
				clk.Advance(testWindow + time.Second)
				n, err := l.Prune(t.Context())
				require.NoError(t, err)
				require.Equal(t, 2, n)
			},
			assert: func(t *testing.T, _ *ratelimit.MemoryLimiter, removed int) {
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, clk := newExpiryLimiter(t)
			tc.setup(t, l, clk)
			removed, err := l.Prune(t.Context())
			require.NoError(t, err)
			tc.assert(t, l, removed)
		})
	}
}

func TestMemoryLimiterFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []ratelimit.MemoryOption // nil builds the factory with a discarding logger
		limit  int
		window time.Duration
		assert func(t *testing.T, f ratelimit.LimiterFactory, l ratelimit.Limiter, err error)
	}

	cases := []testCase{
		{
			name: "builds a working limiter", limit: 2, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "each call has its own buckets", limit: 1, window: time.Minute,
			assert: func(t *testing.T, f ratelimit.LimiterFactory, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				other, err := f.NewLimiter("ns", 1, time.Minute)
				require.NoError(t, err)
				exceeded, err := other.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "zero limit refused", limit: 0, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "negative limit refused", limit: -1, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "zero window refused", limit: 1, window: 0,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "negative window refused", limit: 1, window: -time.Second,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			// The factory's options apply to every limiter it builds.
			name:  "a nil logger option is refused when a limiter is built",
			opts:  []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterLogger(nil)},
			limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name:  "valid options build",
			opts:  []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler))},
			limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			if opts == nil {
				opts = []ratelimit.MemoryOption{ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler))}
			}
			f := ratelimit.MemoryLimiterFactory(opts...)
			l, err := f.NewLimiter("ns", tc.limit, tc.window)
			tc.assert(t, f, l, err)
		})
	}
}

// TestMemoryLimiter_Policy pins the "In-memory limiter" scenario: the limiter
// reports, through the optional contract, the limit and window it was built
// with.
func TestMemoryLimiter_Policy(t *testing.T) {
	t.Parallel()

	l, err := ratelimit.NewMemoryLimiter(20, time.Minute)
	require.NoError(t, err)

	var r ratelimit.PolicyReporter = l
	limit, window := r.Policy()

	assert.Equal(t, 20, limit)
	assert.Equal(t, time.Minute, window)
}

// TestTheLimiterIsSafeUnderConcurrentUse drives every operation at once over
// overlapping keys. A limiter is asked from whatever goroutine is serving a
// request, so a race here is not a theoretical one: it is the ordinary way it is
// called.
func TestTheLimiterIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	t.Run("concurrent failures for one key stay bounded", func(t *testing.T) {
		t.Parallel()

		l := memoryLimiter(t)

		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()

				_ = l.RecordFailure(t.Context(), "k")
			}()
		}
		wg.Wait()

		assert.LessOrEqual(t, l.StampsFor("k"), testLimit, "the limiter grew without bound")

		exceeded, err := l.Exceeded(t.Context(), "k")
		require.NoError(t, err)
		assert.True(t, exceeded, "100 concurrent failures left the key under its limit")
	})

	t.Run("checking, recording and pruning overlapping keys race with nothing", func(t *testing.T) {
		t.Parallel()

		l := memoryLimiter(t)

		const workers = 64
		var wg sync.WaitGroup
		for worker := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()

				key := fmt.Sprintf("k%d", worker%4) // overlapping, so the workers contend
				for range 50 {
					if _, err := l.Exceeded(t.Context(), key); err != nil {
						return
					}
					_ = l.RecordFailure(t.Context(), key)
					l.StampsFor(key)
					_, _ = l.Prune(t.Context())
				}
			}()
		}
		wg.Wait()

		for key := range 4 {
			assert.LessOrEqual(t, l.StampsFor(fmt.Sprintf("k%d", key)), testLimit)
		}
	})
}

// TestMemoryLimiter_DefaultMaxKeys pins the default cap, which is a
// compatibility decision rather than a tuning detail.
func TestMemoryLimiter_DefaultMaxKeys(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 250_000, ratelimit.DefaultMemoryLimiterMaxKeys)
}

// TestMemoryLimiter_MaxKeysHoldsOnlyThatMany pins the "Consumer cap" scenario:
// a limiter capped at three keys holds the first three sources it records and
// not the fourth.
func TestMemoryLimiter_MaxKeysHoldsOnlyThatMany(t *testing.T) {
	t.Parallel()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterLogger(discardLogger()),
		ratelimit.WithMemoryLimiterMaxKeys(3))
	require.NoError(t, err)

	for _, key := range []string{"a", "b", "c", "d"} {
		_ = l.RecordFailure(t.Context(), key)
	}

	for _, key := range []string{"a", "b", "c"} {
		assert.Equal(t, 1, l.StampsFor(key), "held key %q lost its stamp", key)
	}
	assert.Zero(t, l.StampsFor("d"), "a fourth key was held past a cap of three")
}

// TestMemoryLimiter_Full pins what a limiter holding its maximum number of keys
// does: it refuses keys it does not hold, keeps counting the ones it does,
// evicts nothing, and frees a place for every key a sweep or Prune removes —
// exactly once, so that after any amount of churn it again admits exactly its
// maximum.
func TestMemoryLimiter_Full(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		limit int
		// maxKeys is passed with WithMemoryLimiterMaxKeys; zero passes no
		// option, so the default applies.
		maxKeys int
		// setup brings the limiter to the state the case starts from.
		setup  func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock)
		assert func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock)
	}

	record := func(t *testing.T, l *ratelimit.MemoryLimiter, keys ...string) {
		t.Helper()
		for _, key := range keys {
			require.NoError(t, l.RecordFailure(t.Context(), key), "recording %q", key)
		}
	}
	numbered := func(prefix string, n int) []string {
		keys := make([]string, n)
		for i := range keys {
			keys[i] = fmt.Sprintf("%s-%d", prefix, i)
		}
		return keys
	}
	// refillsExactly asserts that the limiter admits exactly n new keys and
	// refuses the one after them, which is what a count that has not drifted
	// in either direction allows.
	refillsExactly := func(t *testing.T, l *ratelimit.MemoryLimiter, n int) {
		t.Helper()
		record(t, l, numbered("refill", n)...)
		err := l.RecordFailure(t.Context(), "refill-one-too-many")
		require.ErrorIs(t, err, ratelimit.ErrLimiterFull,
			"the limiter admitted more than its maximum after a refill, so its count drifted low")
	}

	cases := []testCase{
		{
			// No cap option: the default maximum applies.
			name:    "new source at the default cap",
			limit:   testLimit,
			maxKeys: 0,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				for _, key := range numbered("held", ratelimit.DefaultMemoryLimiterMaxKeys) {
					if err := l.RecordFailure(t.Context(), key); err != nil {
						require.NoError(t, err, "recording %q", key)
					}
				}
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				exceeded, err := l.Exceeded(t.Context(), "one-too-many")
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.True(t, exceeded)
				require.ErrorIs(t, l.RecordFailure(t.Context(), "one-too-many"), ratelimit.ErrLimiterFull)
				assert.Zero(t, l.StampsFor("one-too-many"))
			},
		},
		{
			name:    "new source at the cap",
			limit:   testLimit,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				record(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				exceeded, err := l.Exceeded(t.Context(), "c")
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.True(t, exceeded, "a full limiter must report an unheld key as exceeded")
			},
		},
		{
			// An ended context is the caller's error, and says nothing about
			// whether the limiter had room.
			name:    "new source at the cap, context already ended",
			limit:   testLimit,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				record(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				exceeded, err := l.Exceeded(ctx, "c")
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, ratelimit.ErrLimiterFull,
					"an ended context was reported as a full limiter")
				assert.True(t, exceeded)
			},
		},
		{
			name:    "record for new source at the cap",
			limit:   testLimit,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				record(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				err := l.RecordFailure(t.Context(), "c")
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				assert.Zero(t, l.StampsFor("c"), "a refused record still stored a stamp")
			},
		},
		{
			name:    "held source at the cap",
			limit:   3,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				record(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				record(t, l, "a", "a")
				exceeded, err := l.Exceeded(t.Context(), "a")
				require.NoError(t, err, "a held key was refused as if it were new")
				assert.True(t, exceeded, "a held key stopped being counted at the cap")
			},
		},
		{
			name:    "room after pruning",
			limit:   testLimit,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				record(t, l, "a", "b") // at 12:00:00
				clk.Advance(2 * time.Minute)
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				_, _ = l.Prune(t.Context()) // at 12:02:00
				clk.Advance(30 * time.Second)
				require.NoError(t, l.RecordFailure(t.Context(), "c")) // at 12:02:30
				assert.Equal(t, 1, l.StampsFor("c"), "c was not held after expired keys were pruned")
				assert.Zero(t, l.StampsFor("a"))
				assert.Zero(t, l.StampsFor("b"))
			},
		},
		{
			// Each shard sweeps itself, so an expired key frees its place once
			// its own shard is next touched: here, by checking it.
			name:    "room after inline sweeps",
			limit:   testLimit,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				record(t, l, "a", "b") // at 12:00:00
				clk.Advance(2*time.Minute + 30*time.Second)
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				for _, key := range []string{"a", "b"} {
					exceeded, err := l.Exceeded(t.Context(), key)
					require.NoError(t, err)
					require.False(t, exceeded)
				}
				require.NoError(t, l.RecordFailure(t.Context(), "c"))
				assert.Equal(t, 1, l.StampsFor("c"), "c was not held after expired keys were swept")
				assert.Zero(t, l.StampsFor("a"))
				assert.Zero(t, l.StampsFor("b"))
			},
		},
		{
			name:    "live keys never evicted",
			limit:   testLimit,
			maxKeys: 2,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				record(t, l, "a", "b")
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				for _, key := range numbered("other", 1000) {
					_, err := l.Exceeded(t.Context(), key)
					require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
					require.ErrorIs(t, l.RecordFailure(t.Context(), key), ratelimit.ErrLimiterFull)
				}
				assert.Equal(t, 1, l.StampsFor("a"), "a live key was evicted to make room")
				assert.Equal(t, 1, l.StampsFor("b"), "a live key was evicted to make room")
			},
		},
		{
			name:    "refill after full prune",
			limit:   testLimit,
			maxKeys: 100,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				record(t, l, numbered("first", 100)...)
				require.ErrorIs(t, l.RecordFailure(t.Context(), "first-one-too-many"), ratelimit.ErrLimiterFull)
				clk.Advance(2*testWindow + time.Second)
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				_, _ = l.Prune(t.Context())
				_, _ = l.Prune(t.Context()) // a second prune finds nothing, and must give back nothing
				refillsExactly(t, l, 100)
			},
		},
		{
			// The same refill, with the expired keys removed by each shard's own
			// inline sweep rather than by Prune. Checking every first key
			// touches every shard that holds one.
			name:    "refill after inline sweeps",
			limit:   testLimit,
			maxKeys: 100,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				record(t, l, numbered("first", 100)...)
				require.ErrorIs(t, l.RecordFailure(t.Context(), "first-one-too-many"), ratelimit.ErrLimiterFull)
				clk.Advance(2*testWindow + time.Second)
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				for _, key := range numbered("first", 100) {
					exceeded, err := l.Exceeded(t.Context(), key)
					require.NoError(t, err)
					require.False(t, exceeded)
				}
				_, _ = l.Prune(t.Context()) // everything is already swept, so this must give back nothing
				refillsExactly(t, l, 100)
			},
		},
		{
			// Enough keys that shards pass the compaction mark, with survivors
			// few enough that the sweep replaces their maps. Compaction moves
			// keys without removing any, so the count must not change.
			name:    "refill after a sweep that compacts",
			limit:   testLimit,
			maxKeys: 70_000,
			setup: func(t *testing.T, l *ratelimit.MemoryLimiter, clk *clockwork.FakeClock) {
				record(t, l, numbered("old", 69_000)...)
				clk.Advance(testWindow / 2)
				record(t, l, numbered("live", 1_000)...)
				require.ErrorIs(t, l.RecordFailure(t.Context(), "one-too-many"), ratelimit.ErrLimiterFull)
				clk.Advance(testWindow/2 + time.Second) // the old keys have expired, the live ones not
			},
			assert: func(t *testing.T, l *ratelimit.MemoryLimiter, _ *clockwork.FakeClock) {
				_, _ = l.Prune(t.Context())
				for _, key := range numbered("live", 1_000) {
					require.Equal(t, 1, l.StampsFor(key), "a live key was lost to compaction")
				}
				refillsExactly(t, l, 69_000)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(epoch)
			opts := []ratelimit.MemoryOption{
				ratelimit.WithMemoryLimiterClock(clk),
				ratelimit.WithMemoryLimiterLogger(discardLogger()),
			}
			if tc.maxKeys > 0 {
				opts = append(opts, ratelimit.WithMemoryLimiterMaxKeys(tc.maxKeys))
			}
			l, err := ratelimit.NewMemoryLimiter(tc.limit, testWindow, opts...)
			require.NoError(t, err)

			tc.setup(t, l, clk)
			tc.assert(t, l, clk)
		})
	}
}

// TestMemoryLimiter_CapHoldsUnderConcurrency pins that the cap is exact when new
// keys race for the last places from different shards, which no shard's own
// lock can serialise.
func TestMemoryLimiter_CapHoldsUnderConcurrency(t *testing.T) {
	t.Parallel()

	const (
		workers   = 64
		perWorker = 50
		maxKeys   = 100
	)

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterLogger(discardLogger()),
		ratelimit.WithMemoryLimiterMaxKeys(maxKeys))
	require.NoError(t, err)

	key := func(w, i int) string { return fmt.Sprintf("w%d-k%d", w, i) }

	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			<-start
			for i := range perWorker {
				err := l.RecordFailure(t.Context(), key(w, i))
				if err != nil {
					assert.ErrorIs(t, err, ratelimit.ErrLimiterFull)
				}
			}
		})
	}
	close(start)
	wg.Wait()

	held := 0
	for w := range workers {
		for i := range perWorker {
			if l.StampsFor(key(w, i)) > 0 {
				held++
			}
		}
	}
	assert.Equal(t, maxKeys, held, "the limiter must hold exactly its maximum once more keys than that have raced for it")
}

// TestMemoryLimiter_FullWarning pins the "Flood at the cap" scenario: a full
// limiter says so once when it first refuses a source, and at most once a
// window after that, however many sources it refuses and however many shards
// refuse them at once.
func TestMemoryLimiter_FullWarning(t *testing.T) {
	t.Parallel()

	const maxKeys = 10

	recorder, logger := newLogRecorder()
	clk := clockwork.NewFakeClockAt(epoch)
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(logger),
		ratelimit.WithMemoryLimiterMaxKeys(maxKeys))
	require.NoError(t, err)

	held := make([]string, maxKeys)
	for i := range held {
		held[i] = fmt.Sprintf("held-%d", i)
		require.NoError(t, l.RecordFailure(t.Context(), held[i]))
	}
	require.Empty(t, fullWarnings(t, recorder.String()), "a limiter that refused nothing warned that it was full")

	// 500 new sources within one minute: 250 at once from many goroutines, so
	// shards race to write the warning, and 250 more half a window later.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := range 50 {
		wg.Go(func() {
			<-start
			for i := range 5 {
				_, err := l.Exceeded(t.Context(), fmt.Sprintf("flood-%d-%d", g, i))
				assert.ErrorIs(t, err, ratelimit.ErrLimiterFull)
			}
		})
	}
	close(start)
	wg.Wait()

	clk.Advance(testWindow / 2)
	for _, key := range held {
		require.NoError(t, l.RecordFailure(t.Context(), key)) // keep the limiter full past the next window
	}
	for i := range 250 {
		_, err := l.Exceeded(t.Context(), fmt.Sprintf("late-flood-%d", i))
		require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
	}

	warnings := fullWarnings(t, recorder.String())
	require.Len(t, warnings, 1, "a full limiter must warn once per window, not once per refusal")
	assert.Contains(t, warnings[0]["msg"], "refused")
	assert.EqualValues(t, maxKeys, warnings[0]["max_keys"])
	assert.EqualValues(t, testWindow, warnings[0]["window"])

	clk.Advance(testWindow / 2) // one window after the first warning
	err = l.RecordFailure(t.Context(), "after-a-window")
	require.ErrorIs(t, err, ratelimit.ErrLimiterFull)

	assert.Len(t, fullWarnings(t, recorder.String()), 2,
		"a limiter still full a window later must warn again")
}

// fullWarnings returns the full-limiter records in a JSON log, each decoded.
func fullWarnings(t *testing.T, log string) []map[string]any {
	t.Helper()

	var found []map[string]any
	for line := range strings.Lines(log) {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if msg, _ := record["msg"].(string); strings.Contains(msg, "maximum number of keys") {
			found = append(found, record)
		}
	}

	return found
}

// TestMemoryLimiter_FullWarningFollowsTheClock pins when a full limiter's
// warning is written again: once a window has passed since the last one, or
// when the clock has stepped back by a window or more, which would otherwise
// silence the warning until the clock caught up. A reading earlier than the
// last by less than a window is not a step back worth a record: it is as likely
// a call that read the clock just before another one did.
func TestMemoryLimiter_FullWarningFollowsTheClock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// refusals are the clock readings, relative to epoch, at which the
		// full limiter refuses one new key each.
		refusals []time.Duration
		assert   func(t *testing.T, warnings []map[string]any)
	}

	cases := []testCase{
		{
			name:     "forward within a window",
			refusals: []time.Duration{0, 30 * time.Second, testWindow - time.Nanosecond},
			assert: func(t *testing.T, warnings []map[string]any) {
				assert.Len(t, warnings, 1)
			},
		},
		{
			name:     "forward by a window",
			refusals: []time.Duration{0, testWindow},
			assert: func(t *testing.T, warnings []map[string]any) {
				assert.Len(t, warnings, 2)
			},
		},
		{
			name:     "back by less than a window",
			refusals: []time.Duration{0, -30 * time.Second, -testWindow + time.Nanosecond},
			assert: func(t *testing.T, warnings []map[string]any) {
				assert.Len(t, warnings, 1, "a reading slightly behind the last re-armed the warning")
			},
		},
		{
			name:     "back by more than a window",
			refusals: []time.Duration{0, -testWindow - time.Second},
			assert: func(t *testing.T, warnings []map[string]any) {
				assert.Len(t, warnings, 2, "a clock stepped back by more than a window silenced the warning")
			},
		},
		{
			name:     "back by more than a window, then on from there",
			refusals: []time.Duration{0, -2 * testWindow, -2*testWindow + 30*time.Second, -testWindow},
			assert: func(t *testing.T, warnings []map[string]any) {
				assert.Len(t, warnings, 3, "after a step back the warning must be paced from the new reading")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorder, logger := newLogRecorder()
			clk := &settableClock{now: epoch}
			l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
				ratelimit.WithMemoryLimiterClock(clk),
				ratelimit.WithMemoryLimiterLogger(logger),
				ratelimit.WithMemoryLimiterMaxKeys(1))
			require.NoError(t, err)

			for i, offset := range tc.refusals {
				clk.Set(epoch.Add(offset))
				require.NoError(t, l.RecordFailure(t.Context(), "held")) // keeps the limiter full
				_, err := l.Exceeded(t.Context(), fmt.Sprintf("new-%d", i))
				require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
			}

			tc.assert(t, fullWarnings(t, recorder.String()))
		})
	}
}

// stallClock moves forward one second per reading and, when armed, holds the
// caller of its next reading until resumed: a goroutine preempted between
// reading the clock and using what it read.
type stallClock struct {
	mu      sync.Mutex
	now     time.Time
	armed   bool
	stalled chan struct{}
	resume  chan struct{}
}

func (c *stallClock) Now() time.Time {
	c.mu.Lock()
	at := c.now
	c.now = c.now.Add(time.Second)
	stall := c.armed
	c.armed = false
	c.mu.Unlock()

	if stall {
		close(c.stalled)
		<-c.resume
	}

	return at
}

// TestMemoryLimiter_FullWarningIgnoresStaleReading pins that a refusal whose
// clock reading is older than the last warning's — because its caller read the
// clock and was then held up while another refused and warned — does not write
// a second warning in the same window. It stands alone because its setup is a
// stalled goroutine rather than a sequence of readings.
func TestMemoryLimiter_FullWarningIgnoresStaleReading(t *testing.T) {
	t.Parallel()

	recorder, logger := newLogRecorder()
	clk := &stallClock{now: epoch, stalled: make(chan struct{}), resume: make(chan struct{})}
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterLogger(logger),
		ratelimit.WithMemoryLimiterMaxKeys(1))
	require.NoError(t, err)
	require.NoError(t, l.RecordFailure(t.Context(), "held"))

	clk.mu.Lock()
	clk.armed = true
	clk.mu.Unlock()

	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := l.Exceeded(t.Context(), "new-1") // reads the clock, then stalls
		assert.ErrorIs(t, err, ratelimit.ErrLimiterFull)
	})
	<-clk.stalled
	_, err = l.Exceeded(t.Context(), "new-2") // reads one second later, refuses and warns
	require.ErrorIs(t, err, ratelimit.ErrLimiterFull)
	close(clk.resume)
	wg.Wait()

	assert.Len(t, fullWarnings(t, recorder.String()), 1,
		"two refusals a second apart on a forward-only clock wrote two warnings")
}

// TestMemoryLimiter_FullWarningOnceUnderRace pins that refusals racing from
// many shards at the same instant write one warning between them. One race is
// rarely close enough to show a second writer, so it is run many times, each on
// a fresh limiter whose first refusals all start together.
func TestMemoryLimiter_FullWarningOnceUnderRace(t *testing.T) {
	t.Parallel()

	const (
		rounds  = 200
		racers  = 16
		maxKeys = 1
	)

	for round := range rounds {
		recorder, logger := newLogRecorder()
		l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
			ratelimit.WithMemoryLimiterClock(clockwork.NewFakeClockAt(epoch)),
			ratelimit.WithMemoryLimiterLogger(logger),
			ratelimit.WithMemoryLimiterMaxKeys(maxKeys))
		require.NoError(t, err)
		require.NoError(t, l.RecordFailure(t.Context(), "held"))

		start := make(chan struct{})
		var wg sync.WaitGroup
		for r := range racers {
			wg.Go(func() {
				<-start
				_, err := l.Exceeded(t.Context(), fmt.Sprintf("racer-%d", r))
				assert.ErrorIs(t, err, ratelimit.ErrLimiterFull)
			})
		}
		close(start)
		wg.Wait()

		require.Len(t, fullWarnings(t, recorder.String()), 1,
			"round %d: refusals racing at one instant wrote more than one warning", round)
	}
}

const (
	measuredKeys = 1_000_000
	hotKeys      = 4096
	readers      = 8
)

// slash64Keys returns n distinct /64 keys in the shape SourceGuard composes.
func slash64Keys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("api-key:2001:db8:%x:%x::/64", i>>16, i&0xffff)
	}

	return keys
}

// heapAlloc returns the live heap after two collections, so garbage still
// waiting to be collected is not counted as held.
func heapAlloc() uint64 {
	runtime.GC()
	runtime.GC()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return m.HeapAlloc
}

// newMeasuredLimiter returns a limiter at the test limit and window, driven by
// clk. It is uncapped, because the measurements hold more keys than the default
// cap admits.
func newMeasuredLimiter(t testing.TB, clk *clockwork.FakeClock) *ratelimit.MemoryLimiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
		ratelimit.WithMemoryLimiterClock(clk),
		ratelimit.WithMemoryLimiterMaxKeys(math.MaxInt))
	require.NoError(t, err)

	return l
}

// measureEnv is the environment variable that runs the measurement tests.
//
// They are opt-in rather than part of every run: they allocate a million keys
// and time wall-clock latency, which on a loaded machine or a shared CI runner
// measures the scheduler rather than the limiter. They are run on demand, on a
// quiet machine, and their figures are recorded in the change's design.
const measureEnv = "SCRTY_MEASURE"

// skipUnlessMeasuring skips a measurement test unless measureEnv is set.
func skipUnlessMeasuring(t *testing.T) {
	t.Helper()

	if testing.Short() || os.Getenv(measureEnv) == "" {
		t.Skipf("measurement: set %s=1 to run it", measureEnv)
	}
}

// fill records one failure for every key, on a clone so the limiter owns its
// key memory rather than sharing the slice's.
func fill(t testing.TB, l *ratelimit.MemoryLimiter, keys []string) {
	t.Helper()

	for _, k := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), strings.Clone(k)))
	}
}

// TestMemoryLimiterMeasure_Heap logs what the limiter holds for n failing keys.
func TestMemoryLimiterMeasure_Heap(t *testing.T) {
	skipUnlessMeasuring(t)

	for _, n := range []int{100_000, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			keys := slash64Keys(n)
			clk := clockwork.NewFakeClockAt(epoch)

			before := heapAlloc()
			l := newMeasuredLimiter(t, clk)
			fill(t, l, keys)
			after := heapAlloc()

			t.Logf("keys=%d heap=%.1fMiB perKey=%.1fB", n,
				float64(after-before)/(1<<20), float64(after-before)/float64(n))
			runtime.KeepAlive(l)
			runtime.KeepAlive(keys)
		})
	}
}

// Trial and reference counts for TestMemoryLimiterMeasure_SweepStall.
const (
	stallTrials     = 5
	referenceRuns   = 3
	stallPercentile = 99
)

// stallTrial is what one run of the sweep-stall measurement saw.
type stallTrial struct {
	mainCall  time.Duration // the call that advanced past the window and swept
	readerMax time.Duration // the slowest call any reader made
	readerP99 time.Duration // the readers' 99th percentile, to a power of two
	calls     int
	worst     time.Duration
}

// readerStats is one reader's account of its calls, kept without allocating so
// that recording a call cannot start a collection inside the timed window.
type readerStats struct {
	max     time.Duration
	calls   int
	buckets [64]int // calls by bit length of their nanoseconds
}

func (r *readerStats) record(d time.Duration) {
	r.max = max(r.max, d)
	r.calls++
	r.buckets[bits.Len64(uint64(max(d, 0)))]++
}

// percentile returns the upper bound of the bucket holding the p-th percentile
// of the merged calls.
func percentile(all []readerStats, p int) time.Duration {
	var merged [64]int
	total := 0
	for i := range all {
		total += all[i].calls
		for b, n := range all[i].buckets {
			merged[b] += n
		}
	}

	rank, seen := total*p/100, 0
	for b, n := range merged {
		seen += n
		if seen > rank {
			return time.Duration(uint64(1)<<b - 1)
		}
	}

	return 0
}

// TestMemoryLimiterMeasure_SweepStall measures how long checks wait while the
// inline sweep removes a million expired keys, and holds the worst of them to
// one-thirtieth of sweeping every key under one lock on the same machine.
//
// The readers draw from hotKeys keys, which land in every shard, so every
// shard's sweep runs while they are being timed; each trial confirms that by
// finding no expired key left afterwards. The worst call is taken over every
// call, the readers' included, because with shards a reader's own shard sweep
// can be the slowest.
//
// Preemption and collections only ever add time to a call, so one trial can be
// slower than the code is but none can be faster. The test therefore runs
// stallTrials trials and judges the one with the lowest worst call, against the
// median of referenceRuns single-lock scans, and logs every trial.
func TestMemoryLimiterMeasure_SweepStall(t *testing.T) {
	skipUnlessMeasuring(t)

	refs := make([]time.Duration, referenceRuns)
	for i := range refs {
		refs[i] = singleLockReference(t)
	}
	slices.Sort(refs)
	reference := refs[len(refs)/2]

	var best stallTrial
	for i := range stallTrials {
		trial := runStallTrial(t)
		t.Logf("trial=%d keys=%d mainCall=%s readerMax=%s readerP99<=%s readerCalls=%d worst=%s reference=%s ratio=%.1f",
			i, measuredKeys, trial.mainCall, trial.readerMax, trial.readerP99, trial.calls, trial.worst,
			reference, float64(reference)/float64(trial.worst))
		if i == 0 || trial.worst < best.worst {
			best = trial
		}
	}
	t.Logf("chosen: worst=%s reference=%s (runs %v) ratio=%.1f",
		best.worst, reference, refs, float64(reference)/float64(best.worst))

	if raceEnabled {
		t.Log("the race detector distorts latency, so the stall ratio is not asserted")

		return
	}
	assert.LessOrEqual(t, best.worst*30, reference, "worst=%s reference=%s", best.worst, reference)
}

// runStallTrial fills a fresh limiter, lets the readers time checks against it,
// expires every key with one call, and reports what the calls saw.
func runStallTrial(t *testing.T) stallTrial {
	t.Helper()

	keys := slash64Keys(measuredKeys)
	clk := clockwork.NewFakeClockAt(epoch)
	l := newMeasuredLimiter(t, clk)
	fill(t, l, keys)

	var (
		stop  atomic.Bool
		wg    sync.WaitGroup
		stats = make([]readerStats, readers)
	)
	for r := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var local readerStats
			rng := rand.New(rand.NewPCG(uint64(r), 0)) //nolint:gosec // G404: picks benchmark keys, not secrets
			for !stop.Load() {
				k := keys[rng.IntN(hotKeys)]
				start := time.Now()
				_, _ = l.Exceeded(t.Context(), k)
				local.record(time.Since(start))
			}
			stats[r] = local
		}()
	}

	time.Sleep(50 * time.Millisecond)
	// Collect before the clock moves, so the sweep is not measured against
	// garbage the fill left behind.
	runtime.GC()
	clk.Advance(testWindow + time.Second)

	start := time.Now()
	_, err := l.Exceeded(t.Context(), keys[hotKeys])
	trigger := time.Since(start)
	require.NoError(t, err)

	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	trial := stallTrial{mainCall: trigger, readerP99: percentile(stats, stallPercentile)}
	for i := range stats {
		trial.readerMax = max(trial.readerMax, stats[i].max)
		trial.calls += stats[i].calls
	}
	trial.worst = max(trial.mainCall, trial.readerMax)

	held := 0
	for _, k := range keys[hotKeys+1:] {
		held += l.StampsFor(k)
	}
	require.Zero(t, held, "some shards were not swept while the calls were timed")
	runtime.KeepAlive(l)

	return trial
}

// TestMemoryLimiterMeasure_SingleLockReference logs one full scan, deleting
// every entry, of a plain map behind one mutex: the cost the sweep is judged by.
func TestMemoryLimiterMeasure_SingleLockReference(t *testing.T) {
	skipUnlessMeasuring(t)

	t.Logf("keys=%d reference=%s", measuredKeys, singleLockReference(t))
}

// singleLockReference times one full scan of measuredKeys expired entries in a
// plain map behind one mutex, deleting each: what the sweep cost before it was
// sharded, measured on this machine.
func singleLockReference(t *testing.T) time.Duration {
	t.Helper()

	var mu sync.Mutex
	held := make(map[string][]time.Time, measuredKeys)
	for _, k := range slash64Keys(measuredKeys) {
		held[strings.Clone(k)] = []time.Time{epoch}
	}

	cutoff := epoch.Add(testWindow)

	start := time.Now()
	mu.Lock()
	for k, stamps := range held {
		if stamps[len(stamps)-1].Before(cutoff) {
			delete(held, k)
		}
	}
	mu.Unlock()
	reference := time.Since(start)

	require.Empty(t, held)

	return reference
}

// TestMemoryLimiterMeasure_HeapAfterSweep logs the heap a limiter keeps once
// every key it held has been swept.
func TestMemoryLimiterMeasure_HeapAfterSweep(t *testing.T) {
	skipUnlessMeasuring(t)

	keys := slash64Keys(measuredKeys)
	clk := clockwork.NewFakeClockAt(epoch)

	before := heapAlloc()
	l := newMeasuredLimiter(t, clk)
	fill(t, l, keys)
	full := heapAlloc()

	clk.Advance(testWindow + time.Second)
	_, _ = l.Prune(t.Context())
	swept := heapAlloc()

	t.Logf("keys=%d full=%.1fMiB afterSweep=%.1fMiB", measuredKeys,
		float64(full-before)/(1<<20), float64(swept-before)/(1<<20))
	runtime.KeepAlive(l)
	runtime.KeepAlive(keys)
}

// BenchmarkMemoryLimiter_Mixed measures throughput with 90% checks and 10%
// recorded failures over 100,000 held keys.
func BenchmarkMemoryLimiter_Mixed(b *testing.B) {
	const n = 100_000

	keys := slash64Keys(n)
	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow)
	require.NoError(b, err)
	fill(b, l, keys)

	var seed atomic.Uint64

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		rng := rand.New(rand.NewPCG(seed.Add(1), 0)) //nolint:gosec // G404: picks benchmark keys, not secrets
		for pb.Next() {
			k := keys[rng.IntN(n)]
			if rng.IntN(10) == 0 {
				_ = l.RecordFailure(b.Context(), k)
			} else {
				_, _ = l.Exceeded(b.Context(), k)
			}
		}
	})
}
