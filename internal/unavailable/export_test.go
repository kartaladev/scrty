package unavailable

import "github.com/kartaladev/scrty/ratelimit"

// HeldLen reports how many keys l is holding as refused after a failed record,
// expired ones not yet swept included. It is for the pruning test only.
func HeldLen(l ratelimit.Limiter) int {
	return l.(*limiter).hold.len()
}

// ReplaceLocal puts local in place of l's fall-back count, so a test can fill
// one with a small cap rather than with the default's 250,000 keys.
func ReplaceLocal(l ratelimit.Limiter, local *ratelimit.MemoryLimiter) {
	l.(*limiter).local = local
}
