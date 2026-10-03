package ratelimittest_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/test/ratelimittest"
)

// TestRateLimitConformance_Memory holds the in-memory limiter to the suite,
// which encodes the behaviour every shared limiter must match.
func TestRateLimitConformance_Memory(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClock()
	ratelimittest.Run(t, ratelimittest.Harness{
		New: func(t *testing.T, _ string, limit int, window time.Duration) ratelimit.Limiter {
			l, err := ratelimit.NewMemoryLimiter(limit, window,
				ratelimit.WithMemoryLimiterClock(clk),
				ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)

			return l
		},
		Advance: clk.Advance,
	})
}

// TestRateLimitConformance_SharedDouble runs the whole suite, cross-instance
// scenarios included, against a correct shared double, so that the shared
// scenarios are known to pass for a sound implementation before they are used
// to judge the broken ones.
func TestRateLimitConformance_SharedDouble(t *testing.T) {
	t.Parallel()

	ratelimittest.Run(t, newSharedHarness(""))
}
