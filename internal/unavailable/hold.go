package unavailable

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
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
	// maxKeys is the most keys held at once.
	maxKeys int

	mu sync.Mutex
	// until maps a key to the instant its hold ends.
	until   map[string]time.Time
	sweptAt time.Time
	// fullSweptAt is when a full set last swept to make room, zero before the
	// first. It paces that sweep apart from sweptAt's.
	fullSweptAt time.Time
	// seenAt is the time of the latest call, so a step backwards is told from the
	// clock merely running behind a sweep.
	seenAt time.Time
	// fullUntil is when the refusal of every key ends, set when a key could not
	// be held because the set was full. Zero when no key was turned away.
	fullUntil time.Time
}

// maxKeyBytes is the longest key held as it is. A longer one is held as its
// digest, so the memory the hold uses is bounded in bytes as well as in keys.
const maxKeyBytes = 64

// holdKey is the form in which key is held: itself, or for a long one a digest
// of it that is longer than maxKeyBytes, so it cannot equal a short key.
func holdKey(key string) string {
	if len(key) <= maxKeyBytes {
		return key
	}
	sum := sha256.Sum256([]byte(key))

	return "sha256:" + hex.EncodeToString(sum[:])
}

func newHold(clk clock.Clock, window time.Duration) *hold {
	return &hold{
		clock:   clk,
		window:  window,
		maxKeys: ratelimit.DefaultMemoryLimiterMaxKeys,
		until:   map[string]time.Time{},
		sweptAt: clk.Now(),
		seenAt:  clk.Now(),
	}
}

// add holds key for one window from now. A hold already running longer is
// kept, so a clock stepped backwards cannot shorten one.
//
// A key the set has no room for is not held, and every key is answered as held
// until one window from now instead: refuse mode fails closed, so a spray of
// distinct keys can neither grow the set nor slip past it. The cap is the
// in-memory limiter's default, ratelimit.DefaultMemoryLimiterMaxKeys. It has no
// option: the hold is internal, and only bounds what a backend outage can make it
// remember.
func (h *hold) add(key string) {
	key = holdKey(key)
	now := h.clock.Now()
	end := now.Add(h.window)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.sweepLocked(now)

	current, ok := h.until[key]
	switch {
	case ok && !end.After(current):
	case !ok && !h.roomLocked(now):
		if end.After(h.fullUntil) {
			h.fullUntil = end
		}
	default:
		h.until[key] = end
	}
}

// fullSweepInterval is the most often a full set sweeps again to make room, so
// a spray of distinct keys cannot make every add a scan of the whole set.
const fullSweepInterval = time.Minute

// roomLocked reports whether the set can take one more key. A full set first
// drops its ended holds, which the once-per-window sweep may not have reached,
// and is full only if it is still at the cap. That sweep runs at most once per
// fullSweepInterval, or per window when that is shorter, so the cost of a spray
// stays one scan per interval; between scans a genuinely full set fails closed.
func (h *hold) roomLocked(now time.Time) bool {
	if len(h.until) < h.maxKeys {
		return true
	}

	// A clock stepped back re-arms the pacing from now rather than waiting for
	// the clock to catch up.
	if now.Before(h.fullSweptAt) {
		h.fullSweptAt = now
	}
	if h.fullSweptAt.IsZero() || now.Sub(h.fullSweptAt) >= min(fullSweepInterval, h.window) {
		h.pruneLocked(now)
		h.fullSweptAt = now
	}

	return len(h.until) < h.maxKeys
}

// pruneLocked drops the holds that have ended by now.
func (h *hold) pruneLocked(now time.Time) {
	for key, end := range h.until {
		if !now.Before(end) {
			delete(h.until, key)
		}
	}
}

// held reports whether key is held now. A hold ends exactly one window after
// the failure, matching the in-memory limiter, for which a stamp exactly one
// window old no longer counts.
func (h *hold) held(key string) bool {
	key = holdKey(key)
	now := h.clock.Now()

	h.mu.Lock()
	defer h.mu.Unlock()

	h.sweepLocked(now)

	end, ok := h.until[key]

	return (ok && now.Before(end)) || now.Before(h.fullUntil)
}

// len reports how many keys are held, ended holds not yet swept included.
func (h *hold) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.until)
}

// sweepLocked drops ended holds, at most once per window.
//
// A clock stepped back re-arms it from the earlier time, as the passkey login
// purge does; waiting for the clock to catch up would leave ended holds in place
// for as long as the step was long. The full-set refusal is capped to one window
// from the new time for the same reason. A hold already seen to have ended is
// released at the step: by the new clock it would otherwise be running again for
// as long as the step was long. One still running at the step is kept, as add
// promises.
func (h *hold) sweepLocked(now time.Time) {
	if now.Before(h.seenAt) {
		for key, end := range h.until {
			if !end.After(h.seenAt) {
				delete(h.until, key)
			}
		}
		if !h.fullUntil.After(h.seenAt) {
			h.fullUntil = time.Time{}
		}
	}
	h.seenAt = now
	if now.Before(h.sweptAt) {
		h.sweptAt = now
		if limit := now.Add(h.window); h.fullUntil.After(limit) {
			h.fullUntil = limit
		}
	}
	if now.Sub(h.sweptAt) < h.window {
		return
	}

	h.pruneLocked(now)
	h.sweptAt = now
}
