package ratelimittest_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/ratelimittest"
)

// brokenVar names the environment variable that selects the one broken
// variant the child test runs, so each verdict is attributable to that variant.
const brokenVar = "RATELIMITTEST_BROKEN"

func stampVariant(flaw, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: flaw,
		Run: func(t *testing.T) {
			t.Run("double", func(t *testing.T) {
				ratelimittest.Run(t, singleHarness(func(limit int, window time.Duration, clk clockwork.Clock) ratelimit.Limiter {
					return newStampLimiter(flaw, limit, window, clk)
				}))
			})
		},
		FailsCase: failsCase,
	}
}

func sharedVariant(flaw, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: flaw,
		Run: func(t *testing.T) {
			t.Run("double", func(t *testing.T) { ratelimittest.Run(t, newSharedHarness(flaw)) })
		},
		FailsCase: failsCase,
	}
}

// brokenVariants are the defects the suite must catch, each at the case that
// guards it. A defect the backend cannot host (a Redis expiry that only ever
// grows, say) belongs to that backend's own run, not here.
func brokenVariants() []storefix.BrokenVariant {
	variants := []storefix.BrokenVariant{
		stampVariant(flawAlwaysExceeded, "no failures is not exceeded"),
		stampVariant(flawExceedsEarly, "limit minus one is not exceeded"),
		stampVariant(flawExceedsLate, "limit is exceeded"),
		stampVariant(flawKeyBlind, "other keys do not count"),
		stampVariant(flawExpiresEarly, "one microsecond inside the window counts"),
		stampVariant(flawInclusiveExpiry, "exactly one window old does not count"),
		stampVariant(flawTTLReset, "exactly one window old does not count"),
		{
			Name: "fixed-window",
			Run: func(t *testing.T) {
				t.Run("double", func(t *testing.T) {
					ratelimittest.Run(t, singleHarness(func(limit int, window time.Duration, clk clockwork.Clock) ratelimit.Limiter {
						return &fixedWindowLimiter{limit: limit, window: window, clk: clk, counts: map[string]int{}}
					}))
				})
			},
			FailsCase: "failures straddling a boundary count together",
		},
		stampVariant(flawPruneByOldest, "excess failures keep the newest stamps"),
		stampVariant(flawKeepOldest, "excess failures keep the newest stamps"),
		stampVariant(flawFailOpen, "ended context: Exceeded returns true and an error"),
		stampVariant(flawRecordHonoursCtx, "ended context: RecordFailure still records"),
		sharedVariant(flawPerInstanceState, "two replicas, one limit"),
		sharedVariant(flawShrinkingExpiry, "shorter-window instance does not disarm a longer one"),
		sharedVariant(flawTrimByRecorder, "shorter-window instance does not disarm a longer one"),
		sharedVariant(flawNamespaceBlind, "separate namespaces"),
	}

	// A data race is visible only to a binary built with -race.
	if raceEnabled {
		variants = append(variants, storefix.BrokenVariant{
			Name: "unsynchronised",
			Run: func(t *testing.T) {
				t.Run("double", func(t *testing.T) {
					ratelimittest.Run(t, singleHarness(func(limit int, _ time.Duration, _ clockwork.Clock) ratelimit.Limiter {
						return &unsynchronisedLimiter{limit: limit}
					}))
				})
			},
			FailsCase: "concurrent use ends exceeded without a race",
			FailsWith: "DATA RACE",
		})
	}

	return variants
}

// TestRateLimitConformance_Broken runs the broken variant named by the
// environment, and is the child half of TestRateLimitSuiteCatchesBrokenLimiters.
// Without a variant named it skips.
func TestRateLimitConformance_Broken(t *testing.T) {
	storefix.RunBrokenChild(t, brokenVar, "TestRateLimitSuiteCatchesBrokenLimiters", brokenVariants())
}

// TestRateLimitSuiteCatchesBrokenLimiters checks that the suite fails against
// each broken variant, at the case guarding its defect. Each variant runs in
// its own process, because a failing suite reports through its own *testing.T
// and would fail this test with it.
func TestRateLimitSuiteCatchesBrokenLimiters(t *testing.T) {
	t.Parallel()

	storefix.CatchBrokenVariants(t, brokenVar, "TestRateLimitConformance_Broken", "double", brokenVariants())
}
