package logsample

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSampler_KeysPerWindowAreCapped sprays a million distinct keys into one
// window: the window must not grow past the cap, whatever the key space.
func TestSampler_KeysPerWindowAreCapped(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s := New(time.Minute)
	for n := range 1_000_000 {
		s.Allow("k"+strconv.Itoa(n), start)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The cap's keys plus the one overflow key.
	assert.LessOrEqual(t, len(s.current), DefaultMaxKeys+1)
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
