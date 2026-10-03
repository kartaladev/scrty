package ratelimittest_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/test/ratelimittest"
)

// Single-instance flaws. Each names the one defect a stampLimiter carries.
const (
	flawAlwaysExceeded  = "always-exceeded"
	flawExceedsEarly    = "exceeds-one-early"
	flawExceedsLate     = "exceeds-one-late"
	flawKeyBlind        = "key-blind"
	flawExpiresEarly    = "expires-one-microsecond-early"
	flawInclusiveExpiry = "inclusive-expiry"
	flawTTLReset        = "ttl-reset-on-check"
	// flawPruneByOldest never caps a key's stamps on record, and on a check
	// discards the whole key once its oldest stamp has aged out, even when
	// newer stamps are still inside the window. It models expiry driven by
	// the oldest stamp, not a cap that keeps the wrong end.
	flawPruneByOldest = "prune-by-oldest"
	// flawKeepOldest caps a key's stamps by dropping the newest, as a
	// ZREMRANGEBYRANK with the wrong range would, so the survivors age out
	// sooner than they should.
	flawKeepOldest       = "keep-oldest"
	flawFailOpen         = "fail-open"
	flawRecordHonoursCtx = "record-honours-context"
)

// stampLimiter is a sliding-window limiter that is correct unless flaw names
// a defect. It is the shape of the in-memory limiter, kept small enough to
// carry one deliberate mistake at a time.
type stampLimiter struct {
	flaw   string
	limit  int
	window time.Duration
	clk    clockwork.Clock

	mu   sync.Mutex
	keys map[string][]time.Time
}

func newStampLimiter(flaw string, limit int, window time.Duration, clk clockwork.Clock) *stampLimiter {
	return &stampLimiter{flaw: flaw, limit: limit, window: window, clk: clk, keys: map[string][]time.Time{}}
}

func (l *stampLimiter) keyOf(key string) string {
	if l.flaw == flawKeyBlind {
		return ""
	}

	return key
}

func (l *stampLimiter) counts(stamp, now time.Time) bool {
	switch l.flaw {
	case flawInclusiveExpiry:
		return !stamp.Before(now.Add(-l.window))
	case flawExpiresEarly:
		return now.Sub(stamp) < l.window-time.Microsecond
	default:
		return stamp.After(now.Add(-l.window))
	}
}

func (l *stampLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return l.flaw != flawFailOpen, err
	}
	if l.flaw == flawAlwaysExceeded {
		return true, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clk.Now()
	key = l.keyOf(key)
	stamps := l.keys[key]

	if l.flaw == flawPruneByOldest && len(stamps) > 0 && !l.counts(slices.MinFunc(stamps, time.Time.Compare), now) {
		delete(l.keys, key)
		stamps = nil
	}

	count := 0
	for _, s := range stamps {
		if l.counts(s, now) {
			count++
		}
	}

	threshold := l.limit
	switch l.flaw {
	case flawExceedsEarly:
		threshold--
	case flawExceedsLate:
		threshold++
	}
	exceeded := count >= threshold

	if l.flaw == flawTTLReset && exceeded {
		for i := range stamps {
			stamps[i] = now
		}
	}

	return exceeded, nil
}

func (l *stampLimiter) RecordFailure(ctx context.Context, key string) error {
	if l.flaw == flawRecordHonoursCtx {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	key = l.keyOf(key)
	stamps := append(l.keys[key], l.clk.Now())
	if len(stamps) > l.limit && l.flaw != flawPruneByOldest {
		if l.flaw == flawKeepOldest {
			stamps = stamps[:len(stamps)-1] // drops the newest stamp: the cap's range is wrong
		} else {
			stamps = stamps[1:] // stamps are appended in time order here
		}
	}
	l.keys[key] = stamps

	return nil
}

// fixedWindowLimiter counts failures in buckets of the window's length, so two
// failures a second apart are counted together only when no boundary falls
// between them.
type fixedWindowLimiter struct {
	limit  int
	window time.Duration
	clk    clockwork.Clock

	mu     sync.Mutex
	counts map[string]int
}

func (l *fixedWindowLimiter) bucket(key string) string {
	return fmt.Sprintf("%s|%d", key, l.clk.Now().UnixNano()/int64(l.window))
}

func (l *fixedWindowLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.counts[l.bucket(key)] >= l.limit, nil
}

func (l *fixedWindowLimiter) RecordFailure(_ context.Context, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.counts[l.bucket(key)]++

	return nil
}

// unsynchronisedLimiter counts without a lock, which only the race detector
// can see.
type unsynchronisedLimiter struct {
	limit int
	n     int
}

func (l *unsynchronisedLimiter) Exceeded(ctx context.Context, _ string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, err
	}

	return l.n >= l.limit, nil
}

func (l *unsynchronisedLimiter) RecordFailure(_ context.Context, _ string) error {
	l.n++

	return nil
}

// singleHarness builds a harness over limiters from build, all reading one
// fake clock, with no second instance.
func singleHarness(build func(limit int, window time.Duration, clk clockwork.Clock) ratelimit.Limiter) ratelimittest.Harness {
	clk := clockwork.NewFakeClock()

	return ratelimittest.Harness{
		New: func(_ *testing.T, _ string, limit int, window time.Duration) ratelimit.Limiter {
			return build(limit, window, clk)
		},
		Advance: clk.Advance,
	}
}

// Shared-double flaws.
const (
	flawPerInstanceState = "per-instance-state"
	flawShrinkingExpiry  = "shorter-window-shrinks-expiry"
	flawNamespaceBlind   = "namespace-blind"
	flawTrimByRecorder   = "trim-by-recording-window"
)

// sharedScope is the state a shared backend keeps for one namespace.
type sharedScope struct {
	mu      sync.Mutex
	stamps  map[string][]time.Time
	expires map[string]time.Time
}

func newSharedScope() *sharedScope {
	return &sharedScope{stamps: map[string][]time.Time{}, expires: map[string]time.Time{}}
}

// sharedBackend stands in for a store several replicas share. Its scopes are
// keyed by namespace, and a key's lifetime is the longest any replica asked
// for, unless flaw says otherwise.
type sharedBackend struct {
	flaw string
	clk  *clockwork.FakeClock

	mu     sync.Mutex
	scopes map[string]*sharedScope
}

func newSharedHarness(flaw string) ratelimittest.Harness {
	b := &sharedBackend{flaw: flaw, clk: clockwork.NewFakeClock(), scopes: map[string]*sharedScope{}}

	return ratelimittest.Harness{
		New: func(_ *testing.T, ns string, limit int, window time.Duration) ratelimit.Limiter {
			b.mu.Lock()
			defer b.mu.Unlock()

			if b.flaw == flawNamespaceBlind {
				ns = ""
			}
			if scope, ok := b.scopes[ns]; ok && b.flaw == flawNamespaceBlind {
				// Every namespace is the one scope, and starting one afresh
				// empties it for all of them.
				scope.mu.Lock()
				clear(scope.stamps)
				clear(scope.expires)
				scope.mu.Unlock()
			} else {
				b.scopes[ns] = newSharedScope()
			}

			return &sharedLimiter{b: b, scope: b.scopes[ns], limit: limit, window: window}
		},
		SecondInstance: func(_ *testing.T, ns string, limit int, window time.Duration) ratelimit.Limiter {
			b.mu.Lock()
			defer b.mu.Unlock()

			if b.flaw == flawNamespaceBlind {
				ns = ""
			}
			scope := b.scopes[ns]
			if b.flaw == flawPerInstanceState {
				scope = newSharedScope()
			}

			return &sharedLimiter{b: b, scope: scope, limit: limit, window: window}
		},
		Advance: b.clk.Advance,
	}
}

type sharedLimiter struct {
	b      *sharedBackend
	scope  *sharedScope
	limit  int
	window time.Duration
}

func (l *sharedLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, err
	}

	l.scope.mu.Lock()
	defer l.scope.mu.Unlock()

	now := l.b.clk.Now()
	if exp, ok := l.scope.expires[key]; ok && !exp.After(now) {
		delete(l.scope.stamps, key)
		delete(l.scope.expires, key)
	}

	count := 0
	for _, s := range l.scope.stamps[key] {
		if s.After(now.Add(-l.window)) {
			count++
		}
	}

	return count >= l.limit, nil
}

func (l *sharedLimiter) RecordFailure(_ context.Context, key string) error {
	l.scope.mu.Lock()
	defer l.scope.mu.Unlock()

	now := l.b.clk.Now()
	stamps := l.scope.stamps[key]
	if l.b.flaw == flawTrimByRecorder {
		// Trims by the recording instance's window, so a shorter window
		// discards stamps a longer one is still counting.
		stamps = slices.DeleteFunc(slices.Clone(stamps), func(s time.Time) bool { return !s.After(now.Add(-l.window)) })
	}
	stamps = append(stamps, now)
	if len(stamps) > l.limit {
		stamps = stamps[len(stamps)-l.limit:]
	}
	l.scope.stamps[key] = stamps

	expiry := now.Add(l.window)
	if prev, ok := l.scope.expires[key]; ok && prev.After(expiry) && l.b.flaw != flawShrinkingExpiry {
		expiry = prev
	}
	l.scope.expires[key] = expiry

	return nil
}
