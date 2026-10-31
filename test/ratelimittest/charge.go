package ratelimittest

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// chargeCases are the scenarios of ratelimit.Charger: a charge decides and
// records in one step, and a refund removes the one failure its charge
// recorded. They observe the key through the limiter's Exceeded, so they need
// nothing from a harness beyond what the other cases use.
func chargeCases() []testCase {
	return []testCase{
		{
			// Every caller is held at one barrier and released together, so
			// a charge that checks and records in two steps lets more than
			// the limit through. The refund at the end shows the key held
			// exactly the limit: at the limit before it, below it after.
			name: "concurrent charges stop at the limit", limit: 5, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {

				const callers = 64
				type outcome struct {
					receipt  ratelimit.Receipt
					exceeded bool
					err      error
				}
				outcomes := make([]outcome, callers)
				start := make(chan struct{})
				var ready, done sync.WaitGroup
				for i := range callers {
					ready.Add(1)
					done.Go(func() {
						ready.Done()
						<-start
						r, exceeded, err := l.Charge(t.Context(), "k")
						outcomes[i] = outcome{receipt: r, exceeded: exceeded, err: err}
					})
				}
				ready.Wait()
				close(start)
				done.Wait()

				accepted := 0
				var receipt ratelimit.Receipt
				for _, o := range outcomes {
					require.NoError(t, o.err)
					if !o.exceeded {
						accepted++
						receipt = o.receipt
					}
				}
				require.Equal(t, 5, accepted,
					"charges reported below the limit of 5, out of %d concurrent callers", callers)
				requireExceeded(t, l, "k", true)
				require.NoError(t, l.Refund(t.Context(), receipt))
				requireExceeded(t, l, "k", false)
			},
		},
		{
			name: "refund returns the allowance", limit: 5, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				charge(t, l, "k", 4)
				fifth := requireCharge(t, l, "k", false)
				requireExceeded(t, l, "k", true)

				require.NoError(t, l.Refund(t.Context(), fifth))
				requireExceeded(t, l, "k", false)
				requireCharge(t, l, "k", false)
				requireExceeded(t, l, "k", true)
			},
		},
		{
			// The clock does not move, so both charges carry the same stamp.
			// A refund that removes every failure equal to its stamp gives
			// back two allowances for one receipt.
			name: "refund removes only its own failure", limit: 5, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				first := requireCharge(t, l, "k", false)
				second := requireCharge(t, l, "k", false)
				require.True(t, first.Stamp().Equal(second.Stamp()),
					"the clock did not move, yet the receipts carry different stamps: %s and %s",
					first.Stamp(), second.Stamp())

				require.NoError(t, l.Refund(t.Context(), first))
				charge(t, l, "k", 4) // one failure is left, so four more reach the limit
				requireCharge(t, l, "k", true)
			},
		},
		{
			// The first failure has left the window, and a limiter that
			// keeps only the newest stamps may already have dropped it.
			// Refunding it must not take one of the two failures the window
			// still counts in its place.
			name: "refund after the window removes nothing", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				stale := requireCharge(t, l, "k", false)
				h.Advance(time.Minute)
				charge(t, l, "k", 2)
				requireExceeded(t, l, "k", true)

				require.NoError(t, l.Refund(t.Context(), stale))
				requireExceeded(t, l, "k", true)
			},
		},
		{
			// A refund must take the failure its receipt names, not the
			// newest one. A is refunded while B is still counted, and A
			// would have left the window by +61s anyway while B has not, so
			// a limiter that removed B instead holds one failure fewer than
			// it should: the charge at +61s then leaves the key below the
			// limit, not at it.
			name: "refund removes its own failure, not a newer one", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				a := requireCharge(t, l, "k", false)
				h.Advance(30 * time.Second)
				requireCharge(t, l, "k", false)

				require.NoError(t, l.Refund(t.Context(), a))
				h.Advance(31 * time.Second)
				requireCharge(t, l, "k", false)
				requireExceeded(t, l, "k", true)
			},
		},
		{
			// A refused charge that recorded its attempt would keep a key
			// held for as long as it kept being refused. Here the two
			// failures expire at +60s, so both charges then succeed only if
			// the refusal at +30s left nothing behind.
			name: "a refused charge records nothing", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				charge(t, l, "k", 2)
				h.Advance(30 * time.Second)
				requireCharge(t, l, "k", true)
				h.Advance(30 * time.Second)
				charge(t, l, "k", 2)
			},
		},
		{
			name: "ended context: Charge refuses with an error", limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				_, exceeded, err := l.Charge(endedContext(t), "k")
				require.Error(t, err)
				assert.True(t, exceeded, "a charge that could not be decided reported the key below its limit")
				requireExceeded(t, l, "k", false)
			},
		},
	}
}

// charge charges key n times, and fails the test unless every charge reports
// the key below its limit.
func charge(t *testing.T, l ratelimit.Limiter, key string, n int) {
	t.Helper()

	for i := range n {
		_, exceeded, err := l.Charge(t.Context(), key)
		require.NoError(t, err)
		require.False(t, exceeded, "charge %d of %d for %q was refused", i+1, n, key)
	}
}

// requireCharge charges key once, asserts the answer without an error, and
// returns the receipt.
func requireCharge(t *testing.T, l ratelimit.Limiter, key string, wantExceeded bool) ratelimit.Receipt {
	t.Helper()

	r, exceeded, err := l.Charge(t.Context(), key)
	require.NoError(t, err)
	require.Equal(t, wantExceeded, exceeded, "Charge(%q) exceeded", key)

	return r
}
