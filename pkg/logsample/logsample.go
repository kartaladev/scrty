// Package logsample bounds repeated log records, such as refusals driven by an
// attacker or an outage, to one record per key per window.
//
// A Sampler keeps counts only for keys seen in the current window and the one
// before it, so memory stays bounded whatever the key space. The first event for a
// key in a window is written and carries how many events for that key were
// suppressed since its previous written record.
//
// By default there is no reporter, and a key that does not recur before its counts
// age out has them discarded: suppressed counts are then a lower bound. With
// WithReporter, every suppressed event is counted exactly once, either on a later
// written record or in a report. Flush reports everything pending, for example at
// shutdown.
//
// The reporter runs synchronously on the goroutine whose Allow or Flush call
// triggered it, after the Sampler's lock is released, so it may call back into the
// Sampler. It must be fast and must not panic.
package logsample

import (
	"slices"
	"strings"
	"sync"
	"time"
)

// Sampler writes at most one record per key per fixed window, anchored to the first
// event it sees. A nil *Sampler, or one with a window of zero or less, writes every
// event. It is safe for concurrent use.
type Sampler struct {
	mu          sync.Mutex
	window      time.Duration
	report      func(key string, suppressed int)
	windowStart time.Time
	current     map[string]int
	previous    map[string]int
}

// Option configures a Sampler.
type Option func(*Sampler)

// WithReporter receives every suppressed count that would otherwise be discarded.
// Default: no reporter, so counts of keys that do not recur are dropped.
func WithReporter(fn func(key string, suppressed int)) Option {
	return func(s *Sampler) { s.report = fn }
}

// New returns a Sampler with fixed windows of the given length.
func New(window time.Duration, opts ...Option) *Sampler {
	s := &Sampler{
		window:   window,
		current:  map[string]int{},
		previous: map[string]int{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Allow reports whether the event for key at now should be written, and how many
// events for key were suppressed since its previous written record.
//
// A nil Sampler, or one with a window of zero or less, writes every event with a
// count of 0. A now earlier than the current window's start moves the start back to
// now without starting a new window, so a backwards clock cannot extend suppression.
func (s *Sampler) Allow(key string, now time.Time) (write bool, suppressed int) {
	if s == nil || s.window <= 0 {
		return true, 0
	}

	var evicted []pending
	s.mu.Lock()

	// A backwards clock moves the window start back without rotating, so it can
	// never extend suppression.
	if now.Before(s.windowStart) {
		s.windowStart = now
	}
	// Rotating twice empties both windows, which is also the cold start, so the
	// whole rule is this one step applied at most twice. The step count is clamped
	// as a Duration before it becomes an int, so a tiny window cannot overflow it.
	for range int(min(now.Sub(s.windowStart)/s.window, 2)) {
		evicted = s.rotate(evicted)
		s.windowStart = now
	}

	if _, seen := s.current[key]; !seen {
		suppressed = s.previous[key]
		delete(s.previous, key)
		s.current[key] = 0
		write = true
	} else {
		s.current[key]++
	}
	s.mu.Unlock()

	s.deliver(evicted)
	return write, suppressed
}

// Flush reports every pending suppressed count, then forgets all keys, so the next
// event for any key is written with a count of 0. It is safe on a nil Sampler.
func (s *Sampler) Flush() {
	if s == nil || s.window <= 0 {
		return
	}
	s.mu.Lock()
	evicted := s.rotate(s.rotate(nil))
	s.windowStart = time.Time{}
	s.mu.Unlock()

	s.deliver(evicted)
}

// rotate performs one window rotation: it collects what previous is about to lose,
// shifts current into previous, and leaves current empty. Collecting before
// discarding is part of this single step, so no caller can drop a count by
// forgetting it. Rotating twice empties both windows.
//
// The drained map is recycled, so a Sampler keeps the bucket capacity of its
// busiest window rather than shrinking after a burst.
func (s *Sampler) rotate(dst []pending) []pending {
	if s.report != nil {
		dst = collect(dst, s.previous)
	}
	drained := s.previous
	clear(drained)
	s.previous, s.current = s.current, drained
	return dst
}

// pending is one key's suppressed count, waiting to be reported.
type pending struct {
	key        string
	suppressed int
}

// collect appends every non-zero count in m, in key order. Only the entries it
// appends are sorted, not the whole key space, which matters when one burst leaves
// many single-event keys behind.
func collect(dst []pending, m map[string]int) []pending {
	start := len(dst)
	for k, n := range m {
		if n > 0 {
			dst = append(dst, pending{key: k, suppressed: n})
		}
	}
	slices.SortFunc(dst[start:], func(a, b pending) int { return strings.Compare(a.key, b.key) })
	return dst
}

// deliver calls the reporter on the calling goroutine. It must run without the lock
// held, so a reporter may itself call Allow or Flush.
func (s *Sampler) deliver(ps []pending) {
	if s.report == nil {
		return
	}
	for _, p := range ps {
		s.report(p.key, p.suppressed)
	}
}
