package ctxlog

import (
	"log/slog"
	"testing"
)

// SwapFallback replaces, for t, the handler a routing logger writes to when
// slog.Default() is itself a routing logger.
func SwapFallback(t *testing.T, h slog.Handler) {
	t.Helper()

	prev := fallback
	fallback = h

	t.Cleanup(func() { fallback = prev })
}
