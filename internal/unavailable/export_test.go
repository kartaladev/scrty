package unavailable

import "github.com/kartaladev/scrty/ratelimit"

// HeldLen reports how many keys l is holding as refused after a failed record,
// expired ones not yet swept included. It is for the pruning test only.
func HeldLen(l ratelimit.Limiter) int {
	return l.(*limiter).hold.len()
}
