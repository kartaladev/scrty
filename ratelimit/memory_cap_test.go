package ratelimit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

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
