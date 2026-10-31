package logsample

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
