package unavailable_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestUnavailable_RefuseHoldIsBoundedUnderKeySpray covers the refuse hold's key
// cap: a spray of distinct, long keys cannot grow it past the cap, and a key it
// cannot hold is still answered as exceeded for the window.
func TestUnavailable_RefuseHoldIsBoundedUnderKeySpray(t *testing.T) {
	t.Parallel()

	const (
		capKeys = 50
		spray   = 500
	)

	tests := []struct {
		name    string
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness)
	}{
		{
			name: "the hold never holds more than its cap",
			arrange: func(t *testing.T, h *harness) {
				for i := range spray {
					h.recordN(t, strings.Repeat("k", 2048)+strconv.Itoa(i), 1)
				}
			},
			assert: func(t *testing.T, h *harness) {
				assert.LessOrEqual(t, unavailable.HeldLen(h.limiter), capKeys)
			},
		},
		{
			name: "a key the full hold cannot take is refused for the window",
			arrange: func(t *testing.T, h *harness) {
				for i := range spray {
					h.recordN(t, "key-"+strconv.Itoa(i), 1)
				}
				h.clock.Advance(testWindow - time.Nanosecond)
			},
			assert: func(t *testing.T, h *harness) {
				exceeded, err := h.limiter.Exceeded(t.Context(), "never-failed")
				refusedUnavailable(t, exceeded, err)
			},
		},
		{
			name: "the refusal ends with the window",
			arrange: func(t *testing.T, h *harness) {
				for i := range spray {
					h.recordN(t, "key-"+strconv.Itoa(i), 1)
				}
				h.clock.Advance(testWindow)
			},
			assert: func(t *testing.T, h *harness) {
				exceeded, err := h.limiter.Exceeded(t.Context(), "never-failed")
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "a key long enough to be digested is held and refused",
			arrange: func(t *testing.T, h *harness) {
				h.recordN(t, strings.Repeat("a", 4096), 1)

				// A successful probe closes the breaker, so only the hold refuses.
				h.clock.Advance(defaultInterval)
				_, err := h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, h *harness) {
				exceeded, err := h.limiter.Exceeded(t.Context(), strings.Repeat("a", 4096))
				refusedUnavailable(t, exceeded, err)
				exceeded, err = h.limiter.Exceeded(t.Context(), strings.Repeat("a", 4095)+"b")
				require.NoError(t, err)
				assert.False(t, exceeded, "a different long key was refused as the held one")
				assert.LessOrEqual(t, unavailable.HeldKeyBytes(h.limiter), 80, "a long key was held whole")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableRefuse)
			unavailable.SetHoldCap(h.limiter, capKeys)
			h.writesFailReadsSucceed()
			tt.arrange(t, h)
			tt.assert(t, h)
		})
	}
}

// TestHold_ClockStepsBackwards covers the sweep when the clock steps back. A
// clock stepped back must not leave the sweep waiting for the clock to catch up
// (the sweep's re-arming), and a hold seen to have ended, but not yet swept, is
// released by the next sweep after the step, not held again for as long as the
// step was long (the scenario as written).
func TestHold_ClockStepsBackwards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		assert func(t *testing.T, h *harness)
	}{
		{
			name: "sweeps after clock steps backwards",
			assert: func(t *testing.T, h *harness) {
				h.recordN(t, testKey, 1)
				h.clock.Advance(-time.Hour)
				h.recordN(t, otherKey, 1)

				h.clock.Advance(testWindow)
				// Any lookup runs the sweep; its answer is not what is under test.
				_, _ = h.limiter.Exceeded(t.Context(), "probe")

				// testKey's hold, taken before the step, still runs on the earlier clock's
				// time and is kept; otherKey's, taken after it, has ended and must be swept.
				assert.Equal(t, 1, unavailable.HeldLen(h.limiter), "ended holds were not swept after the clock stepped back")
			},
		},
		{
			name: "releases ended holds when clock steps backwards",
			assert: func(t *testing.T, h *harness) {
				h.clock.Advance(testWindow * 9 / 10)
				h.recordN(t, testKey, 1)
				h.clock.Advance(testWindow * 2 / 10)
				// Runs the sweep that is due, so the next one is a window away.
				_, _ = h.limiter.Exceeded(t.Context(), "probe")
				h.clock.Advance(testWindow * 85 / 100)
				// testKey's hold has ended and no sweep is due, so it is seen but not swept.
				held, _ := h.limiter.Exceeded(t.Context(), testKey)
				require.False(t, held, "the hold had not ended")
				require.Equal(t, 1, unavailable.HeldLen(h.limiter))

				h.clock.Advance(-time.Hour)
				h.clock.Advance(testWindow)

				held, _ = h.limiter.Exceeded(t.Context(), testKey)
				assert.False(t, held, "an ended hold answered exceeded again after the clock stepped back")
				assert.Equal(t, 0, unavailable.HeldLen(h.limiter), "ended holds were not released after the clock stepped back")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableRefuse)
			h.writesFailReadsSucceed()
			tt.assert(t, h)
		})
	}
}

// TestHold_SweepsEndedHoldsBeforeDeclaringItselfFull covers the full check: holds
// that have ended but are not yet swept must not count towards the cap, so the
// refusal of every key does not start while fewer than the cap are live.
func TestHold_SweepsEndedHoldsBeforeDeclaringItselfFull(t *testing.T) {
	t.Parallel()

	const capKeys = 5

	tests := []struct {
		name    string
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness)
	}{
		{
			name: "ended holds waiting for the sweep make room",
			arrange: func(t *testing.T, h *harness) {
				h.clock.Advance(testWindow / 2)
				for i := range capKeys - 1 {
					h.recordN(t, "old-"+strconv.Itoa(i), 1)
				}
				// Runs the sweep that is due, so the next is a window away.
				h.clock.Advance(testWindow / 2)
				_, _ = h.limiter.Exceeded(t.Context(), "probe")
				// The old holds have ended; no sweep is due.
				h.clock.Advance(testWindow * 6 / 10)
				for i := range capKeys {
					h.recordN(t, "new-"+strconv.Itoa(i), 1)
				}
			},
			assert: func(t *testing.T, h *harness) {
				// A successful probe closes the breaker, so only the hold can refuse.
				h.clock.Advance(defaultInterval)
				_, err := h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)

				exceeded, err := h.limiter.Exceeded(t.Context(), "never-failed")
				require.NoError(t, err)
				assert.False(t, exceeded, "every key was refused with fewer than the cap of holds live")
				assert.Equal(t, capKeys, unavailable.HeldLen(h.limiter))
			},
		},
		{
			name: "a hold set of live holds is still full",
			arrange: func(t *testing.T, h *harness) {
				for i := range capKeys + 1 {
					h.recordN(t, "live-"+strconv.Itoa(i), 1)
				}
			},
			assert: func(t *testing.T, h *harness) {
				exceeded, err := h.limiter.Exceeded(t.Context(), "never-failed")
				refusedUnavailable(t, exceeded, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, ratelimit.UnavailableRefuse)
			unavailable.SetHoldCap(h.limiter, capKeys)
			h.writesFailReadsSucceed()
			tt.arrange(t, h)
			tt.assert(t, h)
		})
	}
}
