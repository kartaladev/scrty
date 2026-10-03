package unavailable

import (
	"sync"
	"time"

	"github.com/kartaladev/scrty/pkg/clock"
)

// breaker stops calls to a backend that has just failed.
//
// Closed, every call passes. An unavailable error opens it; open, no call
// passes until the probe interval has elapsed since it opened, and then exactly
// one call passes as the probe. The probe's success closes the breaker and its
// failure reopens it for another interval. While a probe is in flight every
// other call is answered without the backend, so a crowd arriving at the end
// of an outage sends the backend one request, not the crowd.
//
// Each close starts a new generation, and every call is admitted with the
// generation it passed in. Only calls of the current generation change the
// state: a call admitted before the breaker opened cannot close it, and one
// admitted before it last closed cannot reopen it, since either says something
// about the backend at a time that has passed.
//
// It runs nothing on its own: time is read from the clock when a call asks.
type breaker struct {
	clock    clock.Clock
	interval time.Duration

	mu       sync.Mutex
	open     bool
	probing  bool
	openedAt time.Time
	// gen counts closes. A call admitted under an older value began before
	// the breaker last closed.
	gen uint64
}

// admission is what a call that may reach the backend carries back to the
// breaker with its outcome.
type admission struct {
	// probe is set on the one call allowed through an open breaker.
	probe bool
	// gen is the breaker's generation when the call was admitted.
	gen uint64
}

// allow reports whether a call may reach the backend now and, when it may, its
// admission. Every call that passes must report its outcome with exactly one
// of success, failure or abandon, passing the admission back; a call that ends
// any other way, a panic included, reports abandon.
func (b *breaker) allow() (admission, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.open {
		return admission{gen: b.gen}, true
	}
	if b.probing || b.clock.Now().Sub(b.openedAt) < b.interval {
		return admission{}, false
	}
	b.probing = true

	return admission{probe: true, gen: b.gen}, true
}

// success records a call the backend answered. Only the probe's answer closes
// the breaker: a call that passed while it was still closed and returns after it
// opened says nothing about the backend now. Closing starts a new generation.
// It reports whether the breaker closed.
func (b *breaker) success(a admission) (closed bool) {
	if !a.probe {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.open, b.probing = false, false
	b.gen++

	return true
}

// failure records an unavailable error. It opens a closed breaker, and a failed
// probe restarts the interval. A call that passed while the breaker was closed
// and fails after another call opened it changes nothing, so it cannot clear a
// probe in flight; nor does one admitted before the breaker last closed, so a
// call left over from the outage cannot reopen it.
//
// It reports whether the breaker went from closed to open, and whether the
// call was current: the probe, or a call admitted in the breaker's current
// generation. A failure that is not current is stale: it describes an outage
// that has since ended, so the caller must not report it as one.
func (b *breaker) failure(a admission) (opened, current bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	current = a.probe || a.gen == b.gen

	switch {
	case a.probe:
		b.probing, b.openedAt = false, b.clock.Now()
		return false, current
	case b.open, a.gen != b.gen:
		return false, current
	default:
		b.open, b.openedAt = true, b.clock.Now()
		return true, current
	}
}

// abandon records a call that ended without an answer: its caller's context
// ended, or the backend call panicked. That says nothing about the backend, so
// the state is unchanged, except that an abandoned probe frees the next call to
// probe: otherwise the breaker would wait for a probe that is never coming back.
func (b *breaker) abandon(a admission) {
	if !a.probe {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.probing = false
}
