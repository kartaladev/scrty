package logsample

import (
	"maps"
	"slices"
	"sync"
	"time"
)

// Sampler writes at most one record per key per window.
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
	s := &Sampler{window: window}
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

	s.mu.Lock()
	defer s.mu.Unlock()

	switch elapsed := now.Sub(s.windowStart); {
	case s.windowStart.IsZero():
		s.reset(now)
	case now.Before(s.windowStart):
		s.windowStart = now
	case elapsed >= 2*s.window:
		s.evict(s.previous)
		s.evict(s.current)
		s.reset(now)
	case elapsed >= s.window:
		s.evict(s.previous)
		s.windowStart = now
		s.previous = s.current
		s.current = map[string]int{}
	}

	if _, seen := s.current[key]; !seen {
		suppressed = s.previous[key]
		delete(s.previous, key)
		s.current[key] = 0
		return true, suppressed
	}
	s.current[key]++
	return false, 0
}

// evict reports every non-zero count in m, in key order.
func (s *Sampler) evict(m map[string]int) {
	if s.report == nil {
		return
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if n := m[k]; n > 0 {
			s.report(k, n)
		}
	}
}

func (s *Sampler) reset(now time.Time) {
	s.windowStart = now
	s.current = map[string]int{}
	s.previous = map[string]int{}
}
