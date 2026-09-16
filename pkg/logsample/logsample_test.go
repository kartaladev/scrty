package logsample_test

import (
	"sync"
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
