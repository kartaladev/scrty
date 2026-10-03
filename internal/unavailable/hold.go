package unavailable

import (
	"sync"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
)

// hold is the set of keys refuse mode answers as exceeded because a failure for
// them could not be recorded.
//
// It is what keeps a store that rejects writes but still answers reads from
// lifting a limit: without it, a source whose failures are never written reads
// as "not exceeded" for as long as the writes keep failing. Each key is held
// for one window from its last unrecorded failure, the longest that failure
// could have counted had it been written.
//
// Its memory is bounded the way the in-memory limiter's is: a key is dropped
// once its window has passed, by a sweep run from inside its own calls at most
// once per window, so its size follows the keys failing now rather than every
// key that ever failed, and an attacker sending more requests cannot make the
// sweep run more often.
type hold struct {
	clock  clock.Clock
	window time.Duration

	mu sync.Mutex
	// until maps a key to the instant its hold ends.
	until   map[string]time.Time
	sweptAt time.Time
}

func newHold(clk clock.Clock, window time.Duration) *hold {
	return &hold{
		clock:   clk,
		window:  window,
		until:   map[string]time.Time{},
		sweptAt: clk.Now(),
	}
}

// add holds key for one window from now. A hold already running longer is
// kept, so a clock stepped backwards cannot shorten one.
func (h *hold) add(key string) {
	now := h.clock.Now()
	end := now.Add(h.window)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.sweepLocked(now)

	if current, ok := h.until[key]; !ok || end.After(current) {
		h.until[key] = end
	}
}

// held reports whether key is held now. A hold ends exactly one window after
// the failure, matching the in-memory limiter, for which a stamp exactly one
// window old no longer counts.
func (h *hold) held(key string) bool {
	now := h.clock.Now()

	h.mu.Lock()
	defer h.mu.Unlock()

	h.sweepLocked(now)

	end, ok := h.until[key]

	return ok && now.Before(end)
}

// len reports how many keys are held, ended holds not yet swept included.
func (h *hold) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.until)
}

// sweepLocked drops ended holds, at most once per window.
func (h *hold) sweepLocked(now time.Time) {
	if now.Sub(h.sweptAt) < h.window {
		return
	}

	for key, end := range h.until {
		if !now.Before(end) {
			delete(h.until, key)
		}
	}
	h.sweptAt = now
}
