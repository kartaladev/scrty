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

// NewSummariesWithMax returns a Summaries whose generations hold at most max
// keys each, so a test can reach the bound without DefaultSummaryKeys notes.
func NewSummariesWithMax(maxKeys int) *Summaries { return &Summaries{max: maxKeys} }

// Len reports how many keys s remembers a destination for.
func (s *Summaries) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.cur) + len(s.prev)
}
