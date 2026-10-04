package ratelimit_test

import (
	"fmt"
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

// newMeasuredLimiter returns a limiter at the test limit and window, driven by clk.
func newMeasuredLimiter(t testing.TB, clk *clockwork.FakeClock) *ratelimit.MemoryLimiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(testLimit, testWindow, ratelimit.WithMemoryLimiterClock(clk))
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
			rng := rand.New(rand.NewPCG(uint64(r), 0))
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
	l.Prune()
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
		rng := rand.New(rand.NewPCG(seed.Add(1), 0))
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
