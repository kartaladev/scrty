package ratelimittest

import (
	"testing"
	"time"
)

// runShared runs the cross-instance scenarios. They hold for a limiter whose
// state lives outside the instance, so they are skipped when the harness has
// no second instance to offer.
func runShared(t *testing.T, h Harness) {
	t.Helper()

	type testCase struct {
		name string
		run  func(t *testing.T, h Harness)
	}

	cases := []testCase{
		{
			name: "two replicas, one limit",
			run: func(t *testing.T, h Harness) {
				first := h.New(t, "replicas", 3, time.Minute)
				second := h.SecondInstance(t, "replicas", 3, time.Minute)
				record(t, first, "k", 2)
				record(t, second, "k", 1)
				requireExceeded(t, first, "k", true)
				requireExceeded(t, second, "k", true)
			},
		},
		{
			// A replica with a shorter window must not shorten the life of
			// failures another replica is counting over a longer one.
			name: "shorter-window instance does not disarm a longer one",
			run: func(t *testing.T, h Harness) {
				long := h.New(t, "windows", 2, 15*time.Minute)
				short := h.SecondInstance(t, "windows", 2, time.Minute)
				record(t, long, "k", 1)
				h.Advance(30 * time.Second)
				record(t, short, "k", 1)
				h.Advance(10 * time.Minute)
				requireExceeded(t, long, "k", true)

				// The short instance recording again, after its own window
				// has passed since the first record, must not trim what the
				// long one still counts: limit 3, one failure from each
				// instance at 0 and +30s, a third at +90s, checked at +10m.
				long = h.New(t, "windows-later", 3, 15*time.Minute)
				short = h.SecondInstance(t, "windows-later", 3, time.Minute)
				record(t, long, "k", 1)
				h.Advance(30 * time.Second)
				record(t, short, "k", 1)
				h.Advance(time.Minute)
				record(t, short, "k", 1)
				h.Advance(9 * time.Minute)
				requireExceeded(t, long, "k", true)
			},
		},
		{
			name: "separate namespaces",
			run: func(t *testing.T, h Harness) {
				apiKey := h.New(t, "api-key", 1, time.Minute)
				magicLink := h.New(t, "magic-link-redeem", 1, time.Minute)
				record(t, apiKey, "k", 1)
				requireExceeded(t, apiKey, "k", true)
				requireExceeded(t, magicLink, "k", false)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip each case, not the caller: a skip on the caller's t would
			// mark the whole single-instance run as skipped.
			if h.SecondInstance == nil {
				t.Skip("the harness offers no second instance, so the cross-instance scenarios do not run")
			}
			tc.run(t, h)
		})
	}
}
