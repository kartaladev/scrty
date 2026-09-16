package logsample_test

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/pkg/logsample"
)

var base = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type event struct {
	key string
	at  time.Duration
}

type result struct {
	write      bool
	suppressed int
}

func run(s *logsample.Sampler, events []event) []result {
	out := make([]result, 0, len(events))
	for _, e := range events {
		w, n := s.Allow(e.key, base.Add(e.at))
		out = append(out, result{write: w, suppressed: n})
	}
	return out
}

func TestSampler_Allow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		events []event
		assert func(t *testing.T, got []result)
	}

	cases := []testCase{
		{
			name:   "repeated events for one key",
			events: []event{{"a", 0}, {"a", time.Second}, {"a", 2 * time.Second}, {"a", 3 * time.Second}, {"a", 4 * time.Second}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, []result{{true, 0}, {false, 0}, {false, 0}, {false, 0}, {false, 0}}, got)
			},
		},
		{
			name:   "independent keys",
			events: []event{{"a", 0}, {"b", time.Second}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, []result{{true, 0}, {true, 0}}, got)
			},
		},
		{
			name: "count carried into the next window",
			events: []event{
				{"a", 0}, {"a", 10 * time.Second}, {"a", 20 * time.Second}, {"a", 30 * time.Second}, {"a", 40 * time.Second},
				{"a", 70 * time.Second},
			},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, result{true, 4}, got[5])
			},
		},
		{
			name:   "nothing suppressed",
			events: []event{{"a", 0}, {"a", 70 * time.Second}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, []result{{true, 0}, {true, 0}}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, run(logsample.New(time.Minute), tc.events))
		})
	}
}

func TestSampler_DisabledAndBackwardsClock(t *testing.T) {
	t.Parallel()

	fiveOfA := []event{{"a", 0}, {"a", time.Second}, {"a", 2 * time.Second}, {"a", 3 * time.Second}, {"a", 4 * time.Second}}
	allWritten := func(t *testing.T, got []result) {
		for n, r := range got {
			assert.Equal(t, result{true, 0}, r, "event %d", n)
		}
	}

	type testCase struct {
		name    string
		sampler *logsample.Sampler
		events  []event
		assert  func(t *testing.T, got []result)
	}

	cases := []testCase{
		{name: "zero window", sampler: logsample.New(0), events: fiveOfA, assert: allWritten},
		{name: "negative window", sampler: logsample.New(-time.Second), events: fiveOfA, assert: allWritten},
		{name: "nil sampler", sampler: nil, events: fiveOfA, assert: allWritten},
		{
			name:    "backwards clock cannot extend suppression",
			sampler: logsample.New(time.Minute),
			events:  []event{{"a", 30 * time.Second}, {"a", 0}, {"a", time.Minute}},
			assert: func(t *testing.T, got []result) {
				assert.Equal(t, result{false, 0}, got[1], "second event suppressed")
				assert.True(t, got[2].write, "third event written")
				assert.Equal(t, 1, got[2].suppressed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, run(tc.sampler, tc.events))
		})
	}
}

type recorder struct {
	mu    sync.Mutex
	got   map[string]int
	calls int
}

func (r *recorder) report(key string, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.got == nil {
		r.got = map[string]int{}
	}
	r.got[key] += suppressed
	r.calls++
}

func TestSampler_ReporterOnRotation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		events []event
		assert func(t *testing.T, got []result, rec *recorder)
	}

	cases := []testCase{
		{
			name: "key goes quiet",
			events: []event{
				{"a", 0}, {"a", 10 * time.Second}, {"a", 20 * time.Second}, {"a", 30 * time.Second},
				{"b", 150 * time.Second},
				{"a", 160 * time.Second},
			},
			assert: func(t *testing.T, got []result, rec *recorder) {
				assert.Equal(t, map[string]int{"a": 3}, rec.got)
				assert.Equal(t, result{true, 0}, got[5], "a later event for a reported key carries 0")
			},
		},
		{
			name: "long silence drops both windows",
			events: []event{
				{"a", 0}, {"a", 10 * time.Second},
				{"b", 70 * time.Second}, {"b", 80 * time.Second},
				{"c", 210 * time.Second},
			},
			assert: func(t *testing.T, _ []result, rec *recorder) {
				assert.Equal(t, map[string]int{"a": 1, "b": 1}, rec.got)
				assert.Equal(t, 2, rec.calls, "each key reported once")
			},
		},
		{
			name:   "keys with nothing suppressed are not reported",
			events: []event{{"a", 0}, {"b", 150 * time.Second}},
			assert: func(t *testing.T, _ []result, rec *recorder) {
				assert.Zero(t, rec.calls)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recorder{}
			s := logsample.New(time.Minute, logsample.WithReporter(rec.report))
			got := run(s, tc.events)
			tc.assert(t, got, rec)
		})
	}
}

func TestSampler_FlushAndLowerBound(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		reporter bool
		drive    func(s *logsample.Sampler) []result
		assert   func(t *testing.T, got []result, rec *recorder)
	}

	cases := []testCase{
		{
			name:     "flush at shutdown reports pending counts and forgets keys",
			reporter: true,
			drive: func(s *logsample.Sampler) []result {
				got := run(s, []event{{"a", 0}, {"a", 10 * time.Second}, {"a", 20 * time.Second}})
				s.Flush()
				return append(got, run(s, []event{{"a", 30 * time.Second}})...)
			},
			assert: func(t *testing.T, got []result, rec *recorder) {
				assert.Equal(t, map[string]int{"a": 2}, rec.got)
				assert.Equal(t, result{true, 0}, got[3])
			},
		},
		{
			name: "flush without a reporter forgets keys",
			drive: func(s *logsample.Sampler) []result {
				run(s, []event{{"a", 0}, {"a", time.Second}})
				s.Flush()
				return run(s, []event{{"a", 2 * time.Second}})
			},
			assert: func(t *testing.T, got []result, _ *recorder) {
				assert.Equal(t, []result{{true, 0}}, got)
			},
		},
		{
			name: "without a reporter an aged-out count is discarded",
			drive: func(s *logsample.Sampler) []result {
				return run(s, []event{{"a", 0}, {"a", time.Second}, {"a", 2 * time.Second}, {"a", 3 * time.Second}, {"a", 180 * time.Second}})
			},
			assert: func(t *testing.T, got []result, _ *recorder) {
				assert.Equal(t, result{true, 0}, got[4])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recorder{}
			var opts []logsample.Option
			if tc.reporter {
				opts = append(opts, logsample.WithReporter(rec.report))
			}
			s := logsample.New(time.Minute, opts...)
			got := tc.drive(s)
			tc.assert(t, got, rec)
		})
	}
}

// The reporter calls back into the Sampler, so this test has a different setup
// from the tables above: it needs a self-referencing sampler and a deadlock guard.
func TestSampler_ReentrantReporterDoesNotDeadlock(t *testing.T) {
	t.Parallel()

	var s *logsample.Sampler
	s = logsample.New(time.Minute, logsample.WithReporter(func(string, int) {
		s.Allow("summary", base.Add(151*time.Second))
	}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		run(s, []event{{"a", 0}, {"a", 10 * time.Second}, {"b", 150 * time.Second}})
		s.Flush()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reporter calling Allow deadlocked")
	}
}

func TestSampler_TotalsBalance(t *testing.T) {
	t.Parallel()

	type counts struct {
		suppressedEvents atomic.Int64 // events Allow marked as suppressed
		writtenCounts    atomic.Int64 // suppressed counts returned on written events
	}

	record := func(c *counts, write bool, n int) {
		if write {
			c.writtenCounts.Add(int64(n))
			return
		}
		c.suppressedEvents.Add(1)
	}

	type testCase struct {
		name   string
		drive  func(s *logsample.Sampler, c *counts)
		assert func(t *testing.T, suppressed, written, reported int64)
	}

	balanced := func(t *testing.T, suppressed, written, reported int64) {
		assert.Positive(t, suppressed)
		assert.Equal(t, suppressed, written+reported)
	}

	cases := []testCase{
		{
			name: "sequential random sequence",
			drive: func(s *logsample.Sampler, c *counts) {
				rng := rand.New(rand.NewPCG(42, 99))
				at := base
				for range 200_000 {
					at = at.Add(time.Duration(rng.IntN(20_000)) * time.Millisecond)
					switch rng.IntN(1000) {
					case 0:
						at = at.Add(3 * time.Minute)
					case 1:
						at = at.Add(-30 * time.Second)
					}
					w, n := s.Allow(fmt.Sprintf("k%d", rng.IntN(50)), at)
					record(c, w, n)
				}
			},
			assert: balanced,
		},
		{
			name: "64 concurrent goroutines",
			drive: func(s *logsample.Sampler, c *counts) {
				var clock atomic.Int64
				clock.Store(base.UnixNano())
				var wg sync.WaitGroup
				for worker := range 64 {
					wg.Go(func() {
						rng := rand.New(rand.NewPCG(uint64(worker), 7))
						for range 5_000 {
							at := time.Unix(0, clock.Add(int64(rng.IntN(50))*int64(time.Millisecond)))
							w, n := s.Allow(fmt.Sprintf("k%d", rng.IntN(20)), at)
							record(c, w, n)
						}
					})
				}
				wg.Wait()
			},
			assert: balanced,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var reported atomic.Int64
			s := logsample.New(time.Minute, logsample.WithReporter(func(_ string, n int) { reported.Add(int64(n)) }))
			var c counts
			tc.drive(s, &c)
			s.Flush()
			tc.assert(t, c.suppressedEvents.Load(), c.writtenCounts.Load(), reported.Load())
		})
	}
}
