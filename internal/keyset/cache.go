package keyset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/kartaladev/scrty/internal/recovered"
	"github.com/kartaladev/scrty/pkg/clock"
)

// errCooledDown is what a refetch for an unknown key id returns, marked not
// attempted, when the subject's cooldown has not ended: no request is sent,
// and the caller is answered from the current value.
var errCooledDown = errors.New("keyset: refetch cooling down")

// errNotAttempted marks a refusal that never reached the network: a backoff
// refusal, or a failure of a nested resource inside a fetch. It neither opens
// nor widens a backoff window, since the remote was not asked.
var errNotAttempted = errors.New("keyset: fetch not attempted")

// notAttemptedError marks err with errNotAttempted and keeps its message.
type notAttemptedError struct{ err error }

func (e notAttemptedError) Error() string   { return e.err.Error() } //nolint:forbidigo // an Error() method delegating to its cause
func (e notAttemptedError) Unwrap() []error { return []error{e.err, errNotAttempted} }

// NotAttempted marks err as a failure that never reached the network, so it
// opens no backoff window. A fetch returns it for a failure of a nested
// resource, whose own entry keeps its own window.
func NotAttempted(err error) error { return notAttemptedError{err: err} }

// Key names one cached resource: a Resource kind ("key set", "discovery
// document") of one Subject (a provider, a source). Both appear in logs.
type Key struct {
	Resource string
	Subject  string
}

func (k Key) flight() string { return k.Resource + "\x00" + k.Subject }

// entry is one cached resource.
type entry[V any] struct {
	val     V
	fetched time.Time // when val was fetched; zero until the first success

	err    error     // the last failure that reached the network
	until  time.Time // end of the backoff window that failure opened
	misses int       // consecutive failures that reached the network

	cooled time.Time // end of the unknown-key-id refetch cooldown
}

// Cache holds remote resources (discovery documents, key sets) of type V, in
// one map keyed by Key. It runs nothing in the background: every fetch is made
// on behalf of a caller.
//
// Within the TTL a value is served with no request. A failed fetch that
// reached the network opens a backoff window, starting at BackoffBase and
// doubling per consecutive failure up to BackoffMax, during which the failure
// is answered with no request. Concurrent fetches of one resource are
// coalesced. A refetch for a value lacking what the caller needs (Lookup) is
// sent at most once per Cooldown. With Stale above zero, an expired value
// whose refetch fails is served for that long past the TTL, with a warning.
//
// Set every field before the first call; the zero values of TTL,
// BackoffBase, BackoffMax, Cooldown, Clock and Log are not usable.
type Cache[V any] struct {
	TTL                     time.Duration
	BackoffBase, BackoffMax time.Duration
	Cooldown                time.Duration
	Stale                   time.Duration // zero: an expired entry is never served

	Clock clock.Clock
	Log   *slog.Logger

	// SubjectAttr is the log attribute naming a Key's Subject.
	SubjectAttr string
	// StaleMessage and BackoffMessage are the messages of the warnings for a
	// stale value served and a failure backed off.
	StaleMessage, BackoffMessage string
	// PanicError builds the failure answered when a flight panics; err wraps
	// recovered.ErrPanicked.
	PanicError func(k Key, err error) error

	// flight coalesces concurrent fetches of one resource into one request.
	flight singleflight.Group

	mu      sync.Mutex
	entries map[Key]*entry[V]
}

// locked runs f with mu held, and releases mu however f ends, a panic
// included. f reads and writes entries only: the clock is read before, and no
// consumer code runs inside, so a slow or panicking consumer never holds mu.
func (c *Cache[V]) locked(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
}

// entry returns the entry for key, creating an empty one. Call it with mu
// held.
func (c *Cache[V]) entry(key Key) *entry[V] {
	if c.entries == nil {
		c.entries = make(map[Key]*entry[V])
	}
	e, ok := c.entries[key]
	if !ok {
		e = &entry[V]{}
		c.entries[key] = e
	}
	return e
}

// backoff returns the window that follows the given number of consecutive
// failures: the base, doubled per failure after the first, capped at the max.
func (c *Cache[V]) backoff(misses int) time.Duration {
	w := c.BackoffBase
	for i := 1; i < misses && w < c.BackoffMax; i++ {
		if w > c.BackoffMax/2 {
			return c.BackoffMax
		}
		w *= 2
	}
	return min(w, c.BackoffMax)
}

// fresh reports whether e holds a value younger than the TTL at now. Call it
// with mu held.
func (c *Cache[V]) fresh(e *entry[V], now time.Time) bool {
	return !e.fetched.IsZero() && now.Sub(e.fetched) < c.TTL
}

// Lookup returns the value at key, which has reports whether it holds what
// the caller needs.
//
// A fresh value that has accepts is returned with no request. A fresh value
// that lacks it is refetched once, and further misses for the key are answered
// from the cache until the cooldown ends. An expired value is refetched as Get
// does, with usable set to has. The caller checks has on the result: a value
// that still lacks it is returned with no error.
func (c *Cache[V]) Lookup(ctx context.Context, key Key, fetch func(context.Context) (V, error), has func(V) bool) (V, error) {
	now := c.Clock.Now()
	var (
		e     *entry[V]
		fresh bool
		v     V
	)
	c.locked(func() {
		e = c.entry(key)
		fresh, v = c.fresh(e, now), e.val
	})

	if fresh {
		if has(v) {
			return v, nil
		}
		v, err := c.shared(ctx, key, e, now, fetch, true)
		if errors.Is(err, errCooledDown) {
			err = nil // no refetch was sent; v is the current value
		}
		if err != nil {
			var zero V
			return zero, err
		}
		return v, nil
	}

	return c.Get(ctx, key, fetch, has)
}

// Get returns the value at key when it is fresh, the recorded failure
// inside a backoff window, and otherwise the result of a shared fetch.
//
// When that fails and a stale window is configured, an expired value no older
// than the TTL plus the window is served instead, provided usable (nil means
// always) accepts it, with a warning for every such use.
func (c *Cache[V]) Get(ctx context.Context, key Key, fetch func(context.Context) (V, error), usable func(V) bool) (V, error) {
	now := c.Clock.Now()
	var (
		e    *entry[V]
		v    V
		done bool
		err  error
	)
	c.locked(func() {
		e = c.entry(key)
		v, done, err = c.settled(e, now)
	})

	if !done {
		v, err = c.shared(ctx, key, e, now, fetch, false)
	}
	if err == nil || ctx.Err() != nil || c.Stale == 0 {
		return v, err
	}
	return c.staleOr(ctx, key, e, usable, err)
}

// staleOr serves e in place of a failed refetch when it has expired no more
// than the stale window ago and usable accepts it, and returns err otherwise.
// It is reached only from an expired entry's refetch, never from a refetch
// for an unknown key id, so a fresh entry is never served in place of one.
func (c *Cache[V]) staleOr(ctx context.Context, key Key, e *entry[V], usable func(V) bool, err error) (V, error) {
	now := c.Clock.Now()
	var (
		v       V
		fetched time.Time
	)
	c.locked(func() { v, fetched = e.val, e.fetched })
	age := now.Sub(fetched)

	if fetched.IsZero() || age < c.TTL || age > c.TTL+c.Stale || (usable != nil && !usable(v)) {
		var zero V
		return zero, err
	}

	c.Log.LogAttrs(ctx, slog.LevelWarn, c.StaleMessage,
		slog.String(c.SubjectAttr, key.Subject),
		slog.String("resource", key.Resource),
		slog.Duration("age", age))
	return v, nil
}

// shared fetches the resource at key once for every concurrent caller, and
// stores the result in e.
//
// The fetch runs on the first caller's context with its cancellation removed,
// so a caller who gives up does not fail the others; the outbound client's
// timeout still bounds it. Each caller stops waiting when its own context
// ends. The fetch's goroutine ends with the fetch, so nothing outlives the
// request that started it by more than the outbound bound.
//
// forKid asks for a refetch of a fresh value that lacks what the caller needs.
// Its cooldown is checked and claimed inside the flight, so the goroutine that
// claims the window is the one that fetches, and callers arriving meanwhile
// share its result instead of being refused. Inside the cooldown it returns
// the current value with errCooledDown, marked not attempted.
//
// A failed fetch that reached the network opens a backoff window. So does a
// panic anywhere in the flight (see refresh).
//
// now is the caller's latest read of the clock, which refresh falls back on
// when the clock panics before a failure can be timed.
func (c *Cache[V]) shared(ctx context.Context, key Key, e *entry[V], now time.Time, fetch func(context.Context) (V, error), forKid bool) (V, error) {
	var zero V
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	ch := c.flight.DoChan(key.flight(), func() (any, error) {
		return c.refresh(context.WithoutCancel(ctx), key, e, now, fetch, forKid)
	})

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case r := <-ch:
		v, _ := r.Val.(V)
		if !forKid && errors.Is(r.Err, errCooledDown) {
			// This caller joined another's unknown-kid refetch, which the
			// cooldown refused; the value it returned is fresh.
			return v, nil
		}
		return v, r.Err
	}
}

// refresh is the body of shared's flight. It runs on a goroutine singleflight
// starts, with no request recovery above it, and singleflight re-raises a
// flight's panic where nothing can recover it. The flight calls consumer code
// (the clock, the outbound client's Transport) and parses the remote's answer,
// so its whole work runs under recovered.Call, named after the resource. A
// panic is reported once, at Error, to the cache's logger without the panic
// value's text, and answered as a fetch failure built by PanicError, which
// every waiter on the flight receives and which opens a backoff window.
//
// mu is only ever held through locked, so a panic leaves it released, and the
// entry is written whole or not at all: a value and its fetch time together,
// or a failure and its window together.
func (c *Cache[V]) refresh(ctx context.Context, key Key, e *entry[V], seen time.Time, fetch func(context.Context) (V, error), forKid bool) (V, error) {
	what := key.Resource + " refresh"

	var v V
	returned := false
	err := recovered.Call(ctx, c.Log, what, func() error {
		var err error
		v, err = c.refreshEntry(ctx, e, &seen, fetch, forKid)
		returned = true
		return err
	})
	if !returned {
		err = c.PanicError(key, err)
	}
	if err == nil || errors.Is(err, errNotAttempted) {
		return v, err
	}

	// The failure is timed by a fresh read. A clock that panics here too is
	// reported like the first panic, and the failure is timed by the latest
	// read that returned instead, so the window still opens.
	now := seen
	_ = recovered.Call(ctx, c.Log, what, func() error { //nolint:errcheck // a panic is reported by Call; seen stands in
		now = c.Clock.Now()
		return nil
	})

	var (
		attrs []slog.Attr
		log   bool
	)
	c.locked(func() { attrs, log = c.recordFailure(key, e, err, now) })
	if log {
		// The logger is the consumer's handler, and this runs on the
		// flight's goroutine, where a panic would be re-raised by
		// singleflight beyond recovery. The failure is already recorded, so
		// a handler that panics loses only this record.
		_ = recovered.Call(ctx, c.Log, what, func() error { //nolint:errcheck // a panic is reported by Call; the answer is err
			c.Log.LogAttrs(ctx, slog.LevelWarn, c.BackoffMessage, attrs...)
			return nil
		})
	}
	var zero V
	return zero, err
}

// refreshEntry re-checks e, fetches when it still needs a fetch, and stores a
// success in e. It returns a fetch failure unrecorded, for refresh to record.
// Every clock read is stored in seen as it returns.
//
// forKid asks for a refetch of a fresh value that lacks what the caller
// needs; see shared.
func (c *Cache[V]) refreshEntry(ctx context.Context, e *entry[V], seen *time.Time, fetch func(context.Context) (V, error), forKid bool) (V, error) {
	now := c.Clock.Now()
	*seen = now
	var (
		v    V
		done bool
		err  error
	)
	c.locked(func() {
		if forKid && c.fresh(e, now) {
			switch {
			case now.Before(e.cooled):
				v, done, err = e.val, true, NotAttempted(errCooledDown)
			case now.Before(e.until):
				done, err = true, NotAttempted(e.err)
			default:
				e.cooled = now.Add(c.Cooldown)
			}
			return
		}
		// A flight that finished since the caller looked may have filled the
		// entry or opened a window: honour it, so one window never sends two
		// requests.
		v, done, err = c.settled(e, now)
	})
	if done {
		return v, err
	}

	got, err := fetch(ctx)
	if err != nil {
		var zero V
		return zero, err
	}

	now = c.Clock.Now()
	*seen = now
	c.locked(func() {
		e.val, e.fetched = got, now
		e.err, e.until, e.misses = nil, time.Time{}, 0
		v = e.val
	})
	return v, nil
}

// settled answers from e without a fetch when it can: its value while fresh,
// or its recorded failure, marked not attempted, inside a backoff window.
// Call it with mu held.
func (c *Cache[V]) settled(e *entry[V], now time.Time) (V, bool, error) {
	var zero V
	switch {
	case c.fresh(e, now):
		return e.val, true, nil
	case now.Before(e.until):
		return zero, true, NotAttempted(e.err)
	}
	return zero, false, nil
}

// recordFailure opens the next backoff window for a failure that reached the
// network, at now. A not-attempted failure changes nothing. Call it with mu
// held.
//
// It returns the attributes for the "backing off" log record the transition
// warrants, and whether one is warranted at all, instead of writing the log
// itself: the caller logs after releasing mu, so a slow slog handler stalls
// no other subject's lookups.
func (c *Cache[V]) recordFailure(key Key, e *entry[V], err error, now time.Time) ([]slog.Attr, bool) {
	if errors.Is(err, errNotAttempted) {
		return nil, false
	}
	e.misses++
	window := c.backoff(e.misses)
	e.err, e.until = err, now.Add(window)

	return []slog.Attr{
		slog.String(c.SubjectAttr, key.Subject),
		slog.String("resource", key.Resource),
		slog.Int("failures", e.misses),
		slog.Duration("window", window),
		slog.String("error", err.Error()), //nolint:forbidigo // key-set retrieval failure, fixed text with no remote content
	}, true
}

// checkTimings validates the cache's durations, naming the source.
func checkTimings(ttl, base, maxWindow, cooldown time.Duration) error {
	switch {
	case ttl <= 0:
		return fmt.Errorf("%w: the TTL must be positive, got %s", ErrConfig, ttl)
	case base <= 0 || maxWindow < base:
		return fmt.Errorf("%w: the backoff needs 0 < base <= max, got %s and %s", ErrConfig, base, maxWindow)
	case cooldown <= 0:
		return fmt.Errorf("%w: the refetch cooldown must be positive, got %s", ErrConfig, cooldown)
	}
	return nil
}
