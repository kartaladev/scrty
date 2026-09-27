package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
)

// perReplicaWarning is written once per limiter, on first use.
//
// It names the multiplication rather than merely saying "in memory", because
// the mistake it prevents is an operator reading a limit of 5 as the number of
// guesses an attacker gets and deploying six replicas behind a load balancer
// that spreads them.
const perReplicaWarning = "ratelimit: the in-memory limiter counts only this replica, " +
	"so behind N replicas every per-source limit is effectively N times higher"

// MemoryLimiter counts failures in this process, in a sliding window.
//
// It is the default limiter and needs no configuration beyond a limit and a
// window: a consumer that wires nothing else gets a working limit. It holds at
// most the limit's number of failure stamps per key and sweeps keys whose newest
// stamp has left the window from inside its own calls, so it needs no background
// goroutine and nothing to stop.
//
// # Limits, stated
//
// The counts are this replica's own. Behind N replicas each per-source limit is
// effectively N times higher, because a source spreading its attempts across the
// fleet is counted separately by each process. The limiter writes one warning
// saying so on first use. A consumer that needs one limit across a fleet
// supplies its own Limiter — backed by shared storage — to NewSourceGuard, and
// then no MemoryLimiter is constructed and no warning is written.
//
// Checking and recording are separate steps, so a burst of concurrent attempts
// from one source can exceed the limit by up to the burst's concurrency: every
// attempt in the burst may read the count before any of them has recorded. The
// limit holds against sustained pressure, which is what it is for; it is not a
// semaphore. See SourceGuard for the same bound stated where the two steps are
// called.
//
// A MemoryLimiter is safe for concurrent use.
type MemoryLimiter struct {
	limit  int
	window time.Duration
	clock  Clock
	logger *slog.Logger

	// warnOnce keeps the per-replica warning to one record. Repeating it on
	// every call would bury it in the traffic it is warning about.
	warnOnce sync.Once

	mu   sync.Mutex
	keys map[string][]time.Time
	// sweptAt is when the inline sweep last ran. Pacing the sweep by the window
	// rather than by traffic keeps its cost proportional to time rather than to
	// the request rate an attacker chooses.
	sweptAt time.Time
}

// NewMemoryLimiter returns a limiter that reports a key as exceeded once it has
// accumulated limit failures within window.
//
// A limit or window of zero or less is a configuration error wrapping ErrConfig:
// a limit of zero throttles every source from its first attempt, and a window of
// zero counts nothing, so neither could be what a caller meant. Catching both
// here is the difference between a wiring mistake found at startup and one found
// when a limit turns out to be either absent or total.
//
// Defaults: the system clock, replaceable with WithMemoryLimiterClock, and
// slog.Default, replaceable with WithMemoryLimiterLogger.
func NewMemoryLimiter(limit int, window time.Duration, opts ...MemoryOption) (*MemoryLimiter, error) {
	l := &MemoryLimiter{
		limit:  limit,
		window: window,
		clock:  systemClock{},
		logger: slog.Default(),
		keys:   map[string][]time.Time{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}

	if l.limit <= 0 {
		return nil, fmt.Errorf("%w: a limit of %d throttles every source from its first attempt",
			ErrConfig, l.limit)
	}
	if l.window <= 0 {
		return nil, fmt.Errorf("%w: a window of %s counts no failure at all", ErrConfig, l.window)
	}
	if nilcheck.IsNil(l.clock) {
		return nil, fmt.Errorf("%w: the clock is nil, so no failure could be stamped", ErrConfig)
	}
	if l.logger == nil {
		return nil, fmt.Errorf("%w: the logger is nil, so the per-replica warning would be lost", ErrConfig)
	}

	l.sweptAt = l.clock.Now()

	return l, nil
}

// Exceeded reports whether key has accumulated the limit's number of failures
// inside the window. It records nothing, so a caller may ask as often as it
// likes without spending the source's allowance.
//
// A context that has already ended is an error rather than an answer, and the
// bool returned with it is true. The error is what callers act on — SourceGuard
// refuses on it — but a caller that reads only the bool then still fails closed,
// where a false would have lifted the limit at the moment the check stopped
// working.
func (l *MemoryLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	l.warnOnce.Do(l.warnPerReplica)

	if err := ctx.Err(); err != nil {
		return true, fmt.Errorf("ratelimit: check %q: %w", key, err)
	}

	now := l.clock.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	return l.countLocked(key, now) >= l.limit, nil
}

// RecordFailure counts one failure for key at the current time.
//
// It ignores a cancelled context deliberately. Recording is an append to a map
// this process already holds, so there is no work to abandon, and refusing to
// count a failure because the attempt's caller has gone away would hand an
// attacker a free guess for every connection it drops after sending one.
func (l *MemoryLimiter) RecordFailure(_ context.Context, key string) error {
	l.warnOnce.Do(l.warnPerReplica)

	now := l.clock.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	stamps := append(l.keys[key], now)
	if len(stamps) > l.limit {
		stamps = dropOldest(stamps)
	}
	l.keys[key] = stamps

	return nil
}

// Prune drops every key whose newest failure has left the window, for a consumer
// that would rather sweep on its own schedule than wait for the inline sweep.
//
// It takes no window and no cutoff, so no caller can shorten a limit by pruning:
// the only keys it can remove are those the window no longer counts. It is
// therefore always safe to call, and calling it often costs time rather than
// allowances.
func (l *MemoryLimiter) Prune() {
	now := l.clock.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)
}

// StampsFor reports how many failure stamps the limiter currently holds for key,
// including any that have left the window but have not yet been swept. It
// measures what the limiter is keeping, not what it is counting; Exceeded
// answers the latter.
func (l *MemoryLimiter) StampsFor(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.keys[key])
}

// countLocked returns how many of key's stamps the window still counts.
//
// The comparison is strictly after now-window, which is what makes "a one-minute
// window" mean the same thing at every call site: a stamp exactly one window old
// has expired, and one a nanosecond younger has not. Every stamp is examined
// rather than the slice being searched, because nothing here guarantees the
// stamps are ordered — a clock stepped backwards by an NTP correction is enough
// to break that — and there are at most limit of them.
func (l *MemoryLimiter) countLocked(key string, now time.Time) int {
	cutoff := now.Add(-l.window)

	count := 0
	for _, stamp := range l.keys[key] {
		if stamp.After(cutoff) {
			count++
		}
	}

	return count
}

// sweepLocked runs the inline sweep at most once per window.
//
// The sweep is what keeps the limiter's memory proportional to the sources
// currently failing rather than to every source that has ever failed, and it
// runs from the calls themselves so that there is no goroutine to start, stop or
// leak. Pacing it by the window rather than by call count means an attacker
// cannot make it run on every request by sending more of them.
func (l *MemoryLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.sweptAt) < l.window {
		return
	}

	l.pruneLocked(now)
}

// pruneLocked removes keys whose newest stamp has left the window.
//
// A key is judged by its newest stamp alone. Dropping a key with one expired and
// one live stamp would forget a failure the window still counts, which is how a
// memory bound turns into a lifted limit; keeping it costs at most limit stamps
// until its newest stamp expires too.
func (l *MemoryLimiter) pruneLocked(now time.Time) {
	cutoff := now.Add(-l.window)

	for key, stamps := range l.keys {
		if newest(stamps).After(cutoff) {
			continue
		}
		delete(l.keys, key)
	}

	l.sweptAt = now
}

// warnPerReplica states the default limiter's one limit where an operator will
// meet it: in the logs of the process that is applying it.
func (l *MemoryLimiter) warnPerReplica() {
	l.logger.Warn(perReplicaWarning, slog.Int("limit", l.limit), slog.Duration("window", l.window))
}

// dropOldest removes the oldest stamp, which bounds a key at limit stamps.
//
// The stamp removed is found by value rather than taken from the front of the
// slice. Append order is time order only while the clock moves forwards, and a
// clock stepped backwards would otherwise drop the newest stamp instead — handing
// back an allowance precisely when the limiter's own view of time is unreliable.
func dropOldest(stamps []time.Time) []time.Time {
	oldest := 0
	for i, stamp := range stamps {
		if stamp.Before(stamps[oldest]) {
			oldest = i
		}
	}

	return slices.Delete(stamps, oldest, oldest+1)
}

// newest returns the latest stamp, or the zero time when there are none. The
// zero time is older than any cutoff a real clock produces, so a key left empty
// is swept rather than kept forever.
func newest(stamps []time.Time) time.Time {
	var latest time.Time
	for _, stamp := range stamps {
		if stamp.After(latest) {
			latest = stamp
		}
	}

	return latest
}

var _ Limiter = (*MemoryLimiter)(nil)
