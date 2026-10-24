package httpsec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSweepClock pins when a method's sweep of its expired challenges is due:
// the first ever, then once a window, and again after the clock steps
// backwards, so a clock set back does not stop the sweeps for as long as it
// was set back by.
func TestSweepClock(t *testing.T) {
	t.Parallel()

	const window = time.Hour

	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	type testCase struct {
		name string
		// at are the times claims are made at, in order.
		at     []time.Time
		assert func(t *testing.T, due []bool)
	}

	cases := []testCase{
		{
			name: "the first claim is due",
			at:   []time.Time{t0},
			assert: func(t *testing.T, due []bool) {
				assert.Equal(t, []bool{true}, due)
			},
		},
		{
			name: "a claim within the window is not due",
			at:   []time.Time{t0, t0.Add(window - time.Second)},
			assert: func(t *testing.T, due []bool) {
				assert.Equal(t, []bool{true, false}, due)
			},
		},
		{
			name: "a claim a window later is due",
			at:   []time.Time{t0, t0.Add(window)},
			assert: func(t *testing.T, due []bool) {
				assert.Equal(t, []bool{true, true}, due)
			},
		},
		{
			// After the clock steps back an hour, a claim is due at the step
			// and again a window past it, rather than held back until the
			// clock catches up with the claim made before the step.
			name: "claims after the clock steps backwards",
			at:   []time.Time{t0, t0.Add(-time.Hour), t0.Add(-time.Hour + window + time.Second)},
			assert: func(t *testing.T, due []bool) {
				assert.Equal(t, []bool{true, true, true}, due)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var c sweepClock

			due := make([]bool, 0, len(tc.at))
			for _, at := range tc.at {
				_, ok := c.claim(at, window)
				due = append(due, ok)
			}

			tc.assert(t, due)
		})
	}
}
