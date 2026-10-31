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

	// flawCheckThenRecord charges by calling Exceeded, then RecordFailure, so
	// a charge is two steps where it must be one. Between the two, a caller
	// waits for a second caller to pass its check (see chargeInTwoSteps), so
	// concurrent charges overlap there on every run, not when the scheduler
	// happens to interleave them.
	flawCheckThenRecord = "check-then-record"
	// flawRefusedChargeRecords records the attempt of a charge it refuses.
	flawRefusedChargeRecords = "refused-charge-records"
	// flawChargeFailOpen reports a charge it could not decide as below the
	// limit.
	flawChargeFailOpen = "charge-fail-open"
	// flawRefundNothing accepts a refund and removes nothing.
	flawRefundNothing = "refund-removes-nothing"
	// flawRefundEveryEqual removes every stamp equal to the receipt's, so one
	// receipt refunds every charge made at the same instant.
	flawRefundEveryEqual = "refund-removes-every-equal-stamp"
	// flawRefundAnyFailure removes some other counted failure when the
	// receipt's own is no longer there to remove.
	flawRefundAnyFailure = "refund-removes-another-failure"
	// flawRefundNewest checks that the receipt's failure is still counted,
	// then removes the key's newest counted failure instead of that one.
	flawRefundNewest = "refund-removes-newest-instead"
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

	// pairing guards the rendezvous of chargeInTwoSteps. inFlight counts
	// the charges inside it, overlapped records that two were ever inside it
	// at once, and waiting is the channel of the caller waiting for a
	// partner, or nil.
	pairing    sync.Mutex
	inFlight   int
	overlapped bool
	waiting    chan struct{}
}

// A charge with flawCheckThenRecord waits between its check and its record for
// a second charge to pass its own check. Until two charges have overlapped on
// the limiter it waits soloBound, so each sequential charge pays about a
// millisecond; once they have, it waits up to pairBound, so a slow host still
// pairs the charge that reaches the limit with the one behind it.
const (
	soloBound = time.Millisecond
	pairBound = 50 * time.Millisecond
)

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

	return l.exceededLocked(l.keyOf(key), l.clk.Now()), nil
}

func (l *stampLimiter) exceededLocked(key string, now time.Time) bool {
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

	return exceeded
}

func (l *stampLimiter) RecordFailure(ctx context.Context, key string) error {
	if l.flaw == flawRecordHonoursCtx {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.recordLocked(l.keyOf(key), l.clk.Now())

	return nil
}

func (l *stampLimiter) recordLocked(key string, now time.Time) {
	stamps := append(l.keys[key], now)
	if len(stamps) > l.limit && l.flaw != flawPruneByOldest {
		if l.flaw == flawKeepOldest {
			stamps = stamps[:len(stamps)-1] // drops the newest stamp: the cap's range is wrong
		} else {
			stamps = stamps[1:] // stamps are appended in time order here
		}
	}
	l.keys[key] = stamps
}

// Charge decides and records under one hold of the lock, unless flaw names a
// defect of charging.
func (l *stampLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return ratelimit.Receipt{}, l.flaw != flawChargeFailOpen, err
	}
	if l.flaw == flawCheckThenRecord {
		return l.chargeInTwoSteps(ctx, key)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clk.Now()
	if l.exceededLocked(l.keyOf(key), now) {
		if l.flaw == flawRefusedChargeRecords {
			l.recordLocked(l.keyOf(key), now)
		}

		return ratelimit.Receipt{}, true, nil
	}
	l.recordLocked(l.keyOf(key), now)

	return ratelimit.NewReceipt(key, now), false, nil
}

// chargeInTwoSteps checks with Exceeded, then records with RecordFailure:
// each step holds the lock, but nothing holds it across both. Between the two,
// a caller whose check passed waits to pair with the next caller whose check
// passes, and only then do both record. So whenever charges run concurrently,
// the one whose check sees the key one below the limit is joined by a second
// that sees the same count, and both are accepted. A caller nobody pairs with
// records alone, as a sequential charge does, after soloBound or pairBound.
func (l *stampLimiter) chargeInTwoSteps(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	l.pairing.Lock()
	l.inFlight++
	if l.inFlight > 1 {
		l.overlapped = true
	}
	l.pairing.Unlock()
	defer func() {
		l.pairing.Lock()
		l.inFlight--
		l.pairing.Unlock()
	}()

	exceeded, err := l.Exceeded(ctx, key)
	if err != nil || exceeded {
		return ratelimit.Receipt{}, true, err
	}
	l.awaitPartner()
	now := l.clk.Now()
	if err := l.RecordFailure(ctx, key); err != nil {
		return ratelimit.Receipt{}, true, err
	}

	return ratelimit.NewReceipt(key, now), false, nil
}

// awaitPartner releases the caller already waiting, if there is one, and
// returns at once. Otherwise it waits to be released by the next caller. It
// gives up after soloBound while no two charges have overlapped, and after
// pairBound once they have; blocking, not yielding, is what lets a scheduler
// with one thread run the next caller meanwhile.
func (l *stampLimiter) awaitPartner() {
	l.pairing.Lock()
	if partner := l.waiting; partner != nil {
		l.waiting = nil
		l.pairing.Unlock()
		close(partner)

		return
	}
	released := make(chan struct{})
	l.waiting = released
	l.pairing.Unlock()

	// The wait runs on the wall clock, not on clk: a fake clock never advances
	// on its own, so a solo caller timed by it would wait for ever.
	start := time.Now()
	tick := time.NewTicker(soloBound)
	defer tick.Stop()
	for {
		select {
		case <-released:
			return
		case <-tick.C:
		}

		l.pairing.Lock()
		if l.waiting != released {
			l.pairing.Unlock() // a partner took it as it timed out

			return
		}
		if !l.overlapped || time.Since(start) >= pairBound {
			l.waiting = nil // nobody came: record alone
			l.pairing.Unlock()

			return
		}
		l.pairing.Unlock()
	}
}

// Refund removes one stamp equal to the receipt's, while it is in the window,
// unless flaw names a defect of refunding.
func (l *stampLimiter) Refund(_ context.Context, r ratelimit.Receipt) error {
	if l.flaw == flawRefundNothing || r.Stamp().IsZero() {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clk.Now()
	key := l.keyOf(r.Key())
	stamps := l.keys[key]
	own := func(s time.Time) bool { return s.Equal(r.Stamp()) }

	if l.flaw == flawRefundEveryEqual {
		l.keys[key] = slices.DeleteFunc(stamps, own)

		return nil
	}

	i := -1
	if l.counts(r.Stamp(), now) {
		i = slices.IndexFunc(stamps, own)
	}
	if i >= 0 && l.flaw == flawRefundNewest {
		i = len(stamps) - 1 // stamps are appended in time order
	}
	if i < 0 && l.flaw == flawRefundAnyFailure {
		i = slices.IndexFunc(stamps, func(s time.Time) bool { return l.counts(s, now) })
	}
	if i >= 0 {
		l.keys[key] = slices.Delete(stamps, i, i+1)
	}

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
	return l.bucketAt(key, l.clk.Now())
}

func (l *fixedWindowLimiter) bucketAt(key string, at time.Time) string {
	return fmt.Sprintf("%s|%d", key, at.UnixNano()/int64(l.window))
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

// Charge decides and records under one hold of the lock, in the current
// bucket.
func (l *fixedWindowLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return ratelimit.Receipt{}, true, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clk.Now()
	b := l.bucketAt(key, now)
	if l.counts[b] >= l.limit {
		return ratelimit.Receipt{}, true, nil
	}
	l.counts[b]++

	return ratelimit.NewReceipt(key, now), false, nil
}

// Refund removes one failure from the bucket the receipt was charged in.
func (l *fixedWindowLimiter) Refund(_ context.Context, r ratelimit.Receipt) error {
	if r.Stamp().IsZero() {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if b := l.bucketAt(r.Key(), r.Stamp()); l.counts[b] > 0 {
		l.counts[b]--
	}

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

// Charge decides and records without a lock, as the rest of this double does.
func (l *unsynchronisedLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return ratelimit.Receipt{}, true, err
	}
	if l.n >= l.limit {
		return ratelimit.Receipt{}, true, nil
	}
	l.n++

	return ratelimit.NewReceipt(key, time.Now()), false, nil
}

// Refund removes one failure, without a lock.
func (l *unsynchronisedLimiter) Refund(_ context.Context, r ratelimit.Receipt) error {
	if !r.Stamp().IsZero() && l.n > 0 {
		l.n--
	}

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

	return l.exceededLocked(key, l.b.clk.Now()), nil
}

func (l *sharedLimiter) exceededLocked(key string, now time.Time) bool {
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

	return count >= l.limit
}

func (l *sharedLimiter) RecordFailure(_ context.Context, key string) error {
	l.scope.mu.Lock()
	defer l.scope.mu.Unlock()

	l.recordLocked(key, l.b.clk.Now())

	return nil
}

// Charge decides and records under one hold of the scope's lock.
func (l *sharedLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return ratelimit.Receipt{}, true, err
	}

	l.scope.mu.Lock()
	defer l.scope.mu.Unlock()

	now := l.b.clk.Now()
	if l.exceededLocked(key, now) {
		return ratelimit.Receipt{}, true, nil
	}
	l.recordLocked(key, now)

	return ratelimit.NewReceipt(key, now), false, nil
}

// Refund removes one stamp equal to the receipt's, while it is in the window.
func (l *sharedLimiter) Refund(_ context.Context, r ratelimit.Receipt) error {
	if r.Stamp().IsZero() {
		return nil
	}

	l.scope.mu.Lock()
	defer l.scope.mu.Unlock()

	if !r.Stamp().After(l.b.clk.Now().Add(-l.window)) {
		return nil
	}
	stamps := l.scope.stamps[r.Key()]
	if i := slices.IndexFunc(stamps, func(s time.Time) bool { return s.Equal(r.Stamp()) }); i >= 0 {
		l.scope.stamps[r.Key()] = slices.Delete(slices.Clone(stamps), i, i+1)
	}

	return nil
}

func (l *sharedLimiter) recordLocked(key string, now time.Time) {
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
}
