package logsample

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSampler_Bounds sprays a million distinct keys into one window and then
// reads the sampler's state, which must stay bounded whatever the key space.
func TestSampler_Bounds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		after  func(s *Sampler, base time.Time) // nil sends nothing more
		assert func(t *testing.T, s *Sampler)
	}

	cases := []testCase{
		{
			// The window must not grow past the cap.
			name: "keys per window are capped",
			assert: func(t *testing.T, s *Sampler) {
				// The cap's keys plus the one overflow key.
				assert.LessOrEqual(t, len(s.current), DefaultMaxKeys+1)
			},
		},
		{
			name: "memory stays bounded",
			after: func(s *Sampler, base time.Time) {
				s.Allow("late", base.Add(3*time.Minute))
			},
			assert: func(t *testing.T, s *Sampler) {
				assert.LessOrEqual(t, len(s.current)+len(s.previous), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
			s := New(time.Minute)
			for n := range 1_000_000 {
				s.Allow("k"+strconv.Itoa(n), base)
			}
			if tc.after != nil {
				tc.after(s, base)
			}

			s.mu.Lock()
			defer s.mu.Unlock()
			tc.assert(t, s)
		})
	}
}

// TestSampler_OverflowIsCountedExactly checks that events for keys past the cap
// are sampled together, and that every one is accounted for.
func TestSampler_OverflowIsCountedExactly(t *testing.T) {
	t.Parallel()

	const (
		capKeys = 10
		keys    = 100
	)
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		opts   func(report func(string, int)) []Option
		assert func(t *testing.T, writes, suppressed int, reports map[string]int)
	}{
		{
			name: "keys past the cap share one sample",
			opts: func(report func(string, int)) []Option {
				return []Option{WithMaxKeys(capKeys), WithReporter(report)}
			},
			assert: func(t *testing.T, writes, suppressed int, reports map[string]int) {
				// capKeys written for themselves, one for the whole overflow.
				assert.Equal(t, capKeys+1, writes)
				assert.Equal(t, keys-capKeys-1, reports[OverflowKey]+suppressed)
				assert.Equal(t, keys-capKeys-1, reports[OverflowKey])
			},
		},
		{
			name: "the default cap leaves these keys alone",
			opts: func(report func(string, int)) []Option {
				return []Option{WithReporter(report)}
			},
			assert: func(t *testing.T, writes, _ int, reports map[string]int) {
				assert.Equal(t, keys, writes)
				assert.Empty(t, reports)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reports := map[string]int{}
			s := New(time.Minute, tt.opts(func(k string, n int) { reports[k] += n })...)

			var writes, suppressed int
			for n := range keys {
				w, c := s.Allow("k"+strconv.Itoa(n), start)
				if w {
					writes++
					suppressed += c
				}
			}
			s.Flush()

			require.NotNil(t, reports)
			tt.assert(t, writes, suppressed, reports)
		})
	}
}
