package ratelimit_test

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
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
	if testing.Short() {
		t.Skip("measurement")
	}

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

// TestMemoryLimiterMeasure_SweepStall logs how long checks wait while the
// inline sweep removes a million expired keys.
func TestMemoryLimiterMeasure_SweepStall(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}

	keys := slash64Keys(measuredKeys)
	clk := clockwork.NewFakeClockAt(epoch)
	l := newMeasuredLimiter(t, clk)
	fill(t, l, keys)

	var (
		stop    atomic.Bool
		wg      sync.WaitGroup
		samples = make([][]time.Duration, readers)
	)
	for r := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			rng := rand.New(rand.NewPCG(uint64(r), 0))
			for !stop.Load() {
				k := keys[rng.IntN(hotKeys)]
				start := time.Now()
				_, _ = l.Exceeded(t.Context(), k)
				samples[r] = append(samples[r], time.Since(start))
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	clk.Advance(testWindow + time.Second)

	start := time.Now()
	_, err := l.Exceeded(t.Context(), keys[hotKeys])
	trigger := time.Since(start)
	require.NoError(t, err)

	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	var all []time.Duration
	for _, s := range samples {
		all = append(all, s...)
	}
	slices.Sort(all)

	t.Logf("keys=%d mainCall=%s readerMax=%s readerP99=%s readerCalls=%d",
		measuredKeys, trigger, all[len(all)-1], all[len(all)*99/100], len(all))
}

// TestMemoryLimiterMeasure_SingleLockReference logs one full scan, deleting
// every entry, of a plain map behind one mutex: the cost the sweep is judged by.
func TestMemoryLimiterMeasure_SingleLockReference(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}

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
	t.Logf("keys=%d reference=%s", measuredKeys, reference)
}

// TestMemoryLimiterMeasure_HeapAfterSweep logs the heap a limiter keeps once
// every key it held has been swept.
func TestMemoryLimiterMeasure_HeapAfterSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}

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
