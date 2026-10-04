package ratelimit

import (
	"maps"
	"sync"
	"time"
)

// shardCount is how many independently locked parts a MemoryLimiter divides its
// keys into.
//
// A sweep holds one shard's lock, so a check waits for at most a sixty-fourth of
// the sweep work, and checks of keys in other shards do not wait at all. It is a
// constant rather than an option because it changes latency and nothing else:
// which keys are held, what they count and when they are swept are the same at
// any shard count, so an option would be a tuning knob with no policy behind it.
const shardCount = 64

// compactMinKeys is the high-water mark below which a shard's map is never
// replaced. Under it, the buckets a sweep leaves behind are too few to be worth
// the copy.
const compactMinKeys = 1024

// memoryShard is one independently locked part of a MemoryLimiter's keys.
//
// Every field is guarded by mu. A shard paces its own sweep, so a check or record
// that finds its shard due sweeps that shard alone, and the work is spread over
// the calls that land in each shard rather than paid in full by one of them.
type memoryShard struct {
	mu   sync.Mutex
	keys map[string][]time.Time
	// sweptAt is when this shard was last swept. Pacing the sweep by the window
	// rather than by traffic keeps its cost proportional to time rather than to
	// the request rate an attacker chooses.
	sweptAt time.Time
	// highWater is the most keys this shard has held since its map was last
	// replaced. It is what tells a shard emptied by a sweep from one that was
	// always small.
	highWater int

	// The padding keeps one shard's fields off the cache line of its
	// neighbour's, so a lock taken on one shard does not slow the next. It is a
	// full 128 bytes because some arm64 parts use 128-byte lines; with it, no
	// line of either size can hold the fields of two shards.
	_ [128]byte
}

// countLocked returns how many of key's stamps are later than cutoff.
//
// The comparison is strictly after the cutoff, which is what makes "a one-minute
// window" mean the same thing at every call site: a stamp exactly one window old
// has expired, and one a nanosecond younger has not. Every stamp is examined
// rather than the slice being searched, because nothing here guarantees the
// stamps are ordered — a clock stepped backwards by an NTP correction is enough
// to break that — and there are at most limit of them.
func (s *memoryShard) countLocked(key string, cutoff time.Time) int {
	count := 0
	for _, stamp := range s.keys[key] {
		if stamp.After(cutoff) {
			count++
		}
	}

	return count
}

// recordLocked appends one stamp at now to key, keeping at most limit of them.
func (s *memoryShard) recordLocked(key string, now time.Time, limit int) {
	stamps := append(s.keys[key], now)
	if len(stamps) > limit {
		stamps = dropOldest(stamps)
	}
	s.keys[key] = stamps

	if n := len(s.keys); n > s.highWater {
		s.highWater = n
	}
}

// sweepLocked sweeps the shard at most once per window, and reports how many
// keys it removed.
//
// The sweep is what keeps the limiter's memory proportional to the sources
// currently failing rather than to every source that has ever failed, and it
// runs from the calls themselves so that there is no goroutine to start, stop or
// leak. Pacing it by the window rather than by call count means an attacker
// cannot make it run on every request by sending more of them.
func (s *memoryShard) sweepLocked(now time.Time, window time.Duration) int {
	// A clock stepped backwards leaves sweptAt in the future, and pacing on a
	// negative interval would stop sweeping until the clock caught up again.
	// Re-arming from now resumes it one window later; sweeping sooner never
	// removes a live key, because keys are judged by their newest stamp. Each
	// shard re-arms itself the first time it is touched after the step.
	if now.Before(s.sweptAt) {
		s.sweptAt = now

		return 0
	}
	if now.Sub(s.sweptAt) < window {
		return 0
	}

	return s.pruneLocked(now, now.Add(-window))
}

// pruneLocked removes the keys whose newest stamp is not later than cutoff,
// marks the shard swept at now, and reports how many keys it removed.
//
// A key is judged by its newest stamp alone. Dropping a key with one expired and
// one live stamp would forget a failure the window still counts, which is how a
// memory bound turns into a lifted limit; keeping it costs at most limit stamps
// until its newest stamp expires too.
func (s *memoryShard) pruneLocked(now, cutoff time.Time) int {
	removed := 0
	for key, stamps := range s.keys {
		if newest(stamps).After(cutoff) {
			continue
		}
		delete(s.keys, key)
		removed++
	}

	s.sweptAt = now
	s.compactLocked()

	return removed
}

// compactLocked replaces the shard's map once a sweep has left it under a
// quarter of its high-water mark, and resets the mark to the keys that remain.
//
// Go maps keep their buckets after their entries are deleted, so without this a
// flood's memory would stay held long after its keys had gone. The copy costs
// time in proportion to the survivors, which are under a quarter of the most
// keys the shard has held and never more than the sweep just scanned, so a
// compacting call costs at most about twice one shard's sweep.
func (s *memoryShard) compactLocked() {
	n := len(s.keys)
	if s.highWater < compactMinKeys || 4*n >= s.highWater {
		return
	}

	fresh := make(map[string][]time.Time, n)
	maps.Copy(fresh, s.keys)
	s.keys, s.highWater = fresh, n
}

// prune locks the shard for the length of one pruneLocked, and no longer, and
// passes how many keys it removed to release before unlocking. Releasing under
// the lock, as the inline sweep does, means the limiter's count of held keys
// never stays above the keys it holds once the shard is free again.
func (s *memoryShard) prune(now, cutoff time.Time, release func(removed int)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	release(s.pruneLocked(now, cutoff))
}
