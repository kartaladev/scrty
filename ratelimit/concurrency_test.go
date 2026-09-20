package ratelimit_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
					l.Prune()
				}
			}()
		}
		wg.Wait()

		for key := range 4 {
			assert.LessOrEqual(t, l.StampsFor(fmt.Sprintf("k%d", key)), testLimit)
		}
	})
}

// TestCheckThenRecordOvershootsByAtMostTheConcurrency pins the bound the guard's
// godoc states, rather than an exact count. Checking and recording are separate
// calls, so a burst can have every attempt read the count before any of them has
// recorded; what must hold is that the overshoot is bounded by the burst itself
// and the limit still stops sustained guessing.
func TestCheckThenRecordOvershootsByAtMostTheConcurrency(t *testing.T) {
	t.Parallel()

	const (
		concurrency      = 8
		attemptsPerBurst = 25
	)

	g := guardOver(t, memoryLimiter(t))

	var passed atomic.Int64
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()

			<-start
			for range attemptsPerBurst {
				src, err := g.Check(t.Context(), testSource)
				if err != nil {
					continue
				}
				passed.Add(1)
				g.RecordFailure(t.Context(), src)
			}
		}()
	}
	close(start)
	wg.Wait()

	admitted := int(passed.Load())
	assert.LessOrEqual(t, admitted, testLimit+concurrency,
		"a concurrent burst overshot the limit by more than its own concurrency")
	assert.GreaterOrEqual(t, admitted, testLimit,
		"the limit's own allowance was never available")
	assert.Less(t, admitted, concurrency*attemptsPerBurst,
		"the guard admitted every attempt, so nothing was limited at all")
}
