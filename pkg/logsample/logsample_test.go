package logsample_test

import (
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
