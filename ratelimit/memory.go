package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// perReplicaWarning is written once per limiter, on first use.
//
// It names the multiplication rather than merely saying "in memory", because
// the mistake it prevents is an operator reading a limit of 5 as the number of
// guesses an attacker gets and deploying six replicas behind a load balancer
// that spreads them.
const perReplicaWarning = "ratelimit: the in-memory limiter counts only this replica, " +
	"so behind N replicas every per-source limit is effectively N times higher"

// ErrLimiterFull is wrapped by the error a MemoryLimiter returns for a key it
// does not hold while it is holding its maximum number of keys
// (WithMemoryLimiterMaxKeys). Exceeded returns it together with true, so a
// caller that reads only the bool still refuses; RecordFailure returns it
// having stored nothing. Keys the limiter already holds are unaffected.
//
// A guard can tell it apart from a limiter that has stopped working with
// errors.Is: the limiter is doing its job, and a flood of new sources is what
// filled it.
var ErrLimiterFull = errors.New("ratelimit: the limiter is holding its maximum number of keys")

// fullWarning is written when the limiter refuses a key because it is holding
// its maximum number of keys, and at most once a window while it stays full.
//
// It says what is being refused, not just that a bound was reached, because
// the limiters with no guard in front of them — the per-user ones — have no
// other record of a flood that has filled them.
const fullWarning = "ratelimit: the in-memory limiter is holding its maximum number of keys, " +
	"so attempts from sources it does not already hold are refused"

// MemoryLimiter counts failures in this process, in a sliding window.
//
// It is the default limiter and needs no configuration beyond a limit and a
// window: a consumer that wires nothing else gets a working limit. It holds at
// most the limit's number of failure stamps per key and sweeps keys whose newest
// stamp has left the window from inside its own calls, so it needs no background
// goroutine and nothing to stop.
//
// # Key cap
//
// It holds at most DefaultMemoryLimiterMaxKeys keys, 250,000, about 37 MiB;
// WithMemoryLimiterMaxKeys sets another maximum. While it holds that many, a key
// it does not already hold is refused: Exceeded reports it as exceeded with an
// error wrapping ErrLimiterFull, and RecordFailure stores nothing and returns
// that error. Keys it already holds are checked and recorded as below the
// maximum, and none is evicted to make room, since evicting a key would reset a
// count the window still holds. A key gives its place back when a sweep or
// Prune removes it, so an expired key can keep its place until its shard is
// next swept, at most one window after it expired. The cap is exact under
// concurrent use. The limiter writes a warning through its logger when it first
// refuses a key for want of room, and at most once a window while it stays
// full.
//
// # Sweeping
//
// The keys are divided into 64 shards, each with its own lock. A key's shard is
// chosen by a hash seeded afresh for every limiter, so an attacker cannot aim a
// flood at one shard. Each shard sweeps itself at most once per window, from the
// first check or record that lands in it once the window is up, and a check or
// record waits only for its own shard's sweep: never for another shard's, and
// never for the limiter as a whole. The longest a call can wait is therefore one
// shard's sweep, about a sixty-fourth of the keys held. The limiter's benchmark
// holds that worst call, with a million expired keys, to at most one-thirtieth
// of sweeping every key under a single lock.
//
// A Go map keeps its memory after its keys are deleted, so a shard whose sweep
// leaves it holding fewer than a quarter of the most keys it has held, where
// that most was at least 1,024, copies its survivors into a fresh map and lets
// the old one go. The memory a flood took is returned once its keys have been
// swept, rather than held for the life of the process.
//
// The shard count has no option. It changes how long a call can wait and
// nothing else — which keys are held, what they count and when they are swept
// are the same at any count — so an option for it would be a tuning knob with
// no policy behind it.
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
	limit   int
	window  time.Duration
	maxKeys int
	clock   clock.Clock
	logger  *slog.Logger

	// warnOnce keeps the per-replica warning to one record. Repeating it on
	// every call would bury it in the traffic it is warning about.
	warnOnce sync.Once

	// seed is drawn per limiter, so which shard a key lands in cannot be worked
	// out in advance and an attacker cannot aim a flood at one shard.
	seed   maphash.Seed
	shards [shardCount]memoryShard

	// held counts the keys across every shard, against maxKeys. A new key
	// reserves its place with a compare-and-swap that never takes the count
	// past the maximum, so two shards racing for the last place cannot both
	// take it, and a key refused for want of room never holds a place, even
	// for a moment, that another key could have had. Every key a sweep or
	// Prune removes gives its place back once, under the lock of the shard it
	// was removed from. No lock spans shards, so the count is what makes the
	// cap exact.
	held atomic.Int64
	// warnedFullAt is when the full-limiter warning was last written, in Unix
	// nanoseconds, or zero before the first. One record a window is enough to
	// say the limiter is full; one per refusal would let a flood choose how
	// much the operator's logging costs.
	warnedFullAt atomic.Int64
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
// Defaults:
//   - at most DefaultMemoryLimiterMaxKeys keys, replaceable with
//     WithMemoryLimiterMaxKeys; a maximum of zero or less is a configuration
//     error wrapping ErrConfig;
//   - clock.System(), replaceable with WithMemoryLimiterClock;
//   - slog.Default, replaceable with WithMemoryLimiterLogger.
func NewMemoryLimiter(limit int, window time.Duration, opts ...MemoryOption) (*MemoryLimiter, error) {
	l := &MemoryLimiter{
		limit:   limit,
		window:  window,
		maxKeys: DefaultMemoryLimiterMaxKeys,
		clock:   clock.System(),
		logger:  slog.Default(),
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
	if l.maxKeys <= 0 {
		return nil, fmt.Errorf("%w: a maximum of %d keys holds no source at all", ErrConfig, l.maxKeys)
	}
	if nilcheck.IsNil(l.clock) {
		return nil, fmt.Errorf("%w: the clock is nil, so no failure could be stamped", ErrConfig)
	}
	if l.logger == nil {
		return nil, fmt.Errorf("%w: the logger is nil, so the per-replica warning would be lost", ErrConfig)
	}

	l.seed = maphash.MakeSeed()
	now := l.clock.Now()
	for i := range l.shards {
		l.shards[i].keys = map[string][]time.Time{}
		l.shards[i].sweptAt = now
	}

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
//
// A key the limiter does not hold, asked about while it holds its maximum
// number of keys, is reported as exceeded with an error wrapping
// ErrLimiterFull, for the same reason.
func (l *MemoryLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	l.warnOnce.Do(l.warnPerReplica)

	if err := ctx.Err(); err != nil {
		return true, fmt.Errorf("ratelimit: check %q: %w", key, err)
	}

	now := l.clock.Now()
	s := l.shardFor(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	l.release(s.sweepLocked(now, l.window))

	if _, ok := s.keys[key]; !ok && l.held.Load() >= int64(l.maxKeys) {
		l.warnFull(now)

		return true, fmt.Errorf("ratelimit: check %q: %w", key, ErrLimiterFull)
	}

	return s.countLocked(key, now.Add(-l.window)) >= l.limit, nil
}

// RecordFailure counts one failure for key at the current time.
//
// It ignores a cancelled context deliberately. Recording is an append to a map
// this process already holds, so there is no work to abandon, and refusing to
// count a failure because the attempt's caller has gone away would hand an
// attacker a free guess for every connection it drops after sending one.
//
// A failure for a key the limiter does not hold, while it holds its maximum
// number of keys, is not stored, and the error returned wraps ErrLimiterFull.
func (l *MemoryLimiter) RecordFailure(_ context.Context, key string) error {
	l.warnOnce.Do(l.warnPerReplica)

	now := l.clock.Now()
	s := l.shardFor(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	l.release(s.sweepLocked(now, l.window))

	// The shard lock keeps key's presence fixed until the stamp is stored, so
	// a new key reserves its place exactly once.
	if _, ok := s.keys[key]; !ok && !l.reserve() {
		l.warnFull(now)

		return fmt.Errorf("ratelimit: record %q: %w", key, ErrLimiterFull)
	}
	s.recordLocked(key, now, l.limit)

	return nil
}

// Prune drops every key whose newest failure has left the window, for a consumer
// that would rather sweep on its own schedule than wait for the inline sweep.
//
// It takes no window and no cutoff, so no caller can shorten a limit by pruning:
// the only keys it can remove are those the window no longer counts. It is
// therefore always safe to call, and calling it often costs time rather than
// allowances. Every key it removes gives back its place under the key cap.
//
// The shards are swept one after another, each locked only while it is swept,
// so a Prune never holds more than one shard and a check waits at most for its
// own shard's part of it.
func (l *MemoryLimiter) Prune() {
	now := l.clock.Now()
	cutoff := now.Add(-l.window)

	for i := range l.shards {
		l.shards[i].prune(now, cutoff, l.release)
	}
}

// StampsFor reports how many failure stamps the limiter currently holds for key,
// including any that have left the window but have not yet been swept. It
// measures what the limiter is keeping, not what it is counting; Exceeded
// answers the latter.
func (l *MemoryLimiter) StampsFor(key string) int {
	s := l.shardFor(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.keys[key])
}

// reserve takes a place for a new key, and reports false, taking nothing, when
// the limiter already holds its maximum.
//
// The count is read and raised in one compare-and-swap, retried when another
// shard changed it in between, so it never goes past the maximum: a reservation
// that added first and gave back on overshooting would, for that moment, count
// a place nobody holds, and a key racing it for a place just freed could be
// refused while there was room.
func (l *MemoryLimiter) reserve() bool {
	maxKeys := int64(l.maxKeys)
	for {
		cur := l.held.Load()
		if cur >= maxKeys {
			return false
		}
		if l.held.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// release gives back the places of removed keys, which a sweep or Prune has
// just deleted. It is called under the lock of the shard they were removed
// from.
func (l *MemoryLimiter) release(removed int) {
	if removed > 0 {
		l.held.Add(-int64(removed))
	}
}

// warnFull writes fullWarning when the limiter first refuses a key for want of
// room, and at most once a window after that.
//
// The last write is claimed with a compare-and-swap rather than under a lock,
// because the shards that refuse keys at the same moment hold different locks:
// whichever swaps first writes the record, and the rest see it written.
//
// A reading earlier than the last write is a step back only when it is a window
// or more earlier. Each caller reads the clock before it takes its shard's lock,
// so a caller held up after reading can arrive with a time a little older than
// a record another caller has just written; treating that as a step back would
// write the warning twice in one window. A clock stepped back by a window or
// more re-arms the warning rather than silencing it until the clock catches up.
func (l *MemoryLimiter) warnFull(now time.Time) {
	at := now.UnixNano()
	last := l.warnedFullAt.Load()
	window := int64(l.window)
	if last != 0 && at-last < window && last-at < window {
		return
	}
	if !l.warnedFullAt.CompareAndSwap(last, at) {
		return
	}

	l.logger.Warn(fullWarning, slog.Int("max_keys", l.maxKeys), slog.Duration("window", l.window))
}

// shardFor returns the shard that holds key.
func (l *MemoryLimiter) shardFor(key string) *memoryShard {
	return &l.shards[maphash.String(l.seed, key)%shardCount]
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
