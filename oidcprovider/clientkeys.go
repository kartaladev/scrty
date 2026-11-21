package oidcprovider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/sync/singleflight"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/recovered"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
)

// fetchFailureText is what a failed key-set fetch says, whatever the cause was.
const fetchFailureText = "oidcprovider: fetch client key set"

// clientKeySets caches the key sets clients publish at their jwks_uri. It runs nothing
// in the background: every fetch is made on behalf of a caller, and is the one
// network effect a stranger's request can have here, so each client's is bounded:
//
//   - concurrent callers share one fetch;
//   - a kid the set does not hold refetches at most once per cooldown;
//   - a failed fetch is not retried until the cooldown has passed, and is reported
//     to everyone asking meanwhile.
//
// A set is used for its lifetime and then fetched again. An expired set is never served
// in place of a failed fetch, because that would keep a withdrawn key working.
type clientKeySets struct {
	out      *outbound.Client
	logger   *slog.Logger // the provider's; takes the outbound client's abort record
	clock    clock.Clock
	ttl      time.Duration
	cooldown time.Duration

	flight singleflight.Group

	mu      sync.Mutex
	entries map[string]*clientKeySet
}

// clientKeySet is what is known of one client's published set.
type clientKeySet struct {
	set     jwk.Set
	fetched time.Time // when set was fetched; zero until the first success

	cooled time.Time // no refetch for an unknown kid before this
	failed error     // the last failed fetch's failure, answered until until
	until  time.Time // no fetch at all before this
}

// get returns the client's set, holding kid when it can. A set lacking kid is returned
// as it is, and the caller's signature check refuses the assertion. An empty kid asks
// for no particular key. An error is an outage and no verdict on the client.
func (c *clientKeySets) get(ctx context.Context, clientID, uri, kid string) (jwk.Set, error) {
	// A client identifier is printable ASCII, so this cannot run two clients together.
	// The URI is in the key so that a client moved elsewhere starts afresh. A deleted
	// client's entry stays, and only registered clients ever get one.
	key := clientID + "\x00" + uri

	// The clock is the consumer's, so it is read before mu is taken: a panic in it
	// then cannot leave mu held.
	now := c.clock.Now()
	var (
		e    *clientKeySet
		set  jwk.Set
		held bool
	)
	c.locked(func() {
		e = c.entry(key)
		if held = c.holds(e, kid, now); held {
			set = e.set
		}
	})
	if held {
		return set, nil
	}

	// The fetch keeps the first caller's values and not its cancellation, so one caller
	// leaving does not fail those sharing it. The outbound client's timeout bounds it,
	// and each caller stops waiting when its own context ends.
	ch := c.flight.DoChan(key, func() (any, error) {
		return c.settle(context.WithoutCancel(ctx), e, uri, kid, now)
	})

	select {
	case <-ctx.Done():
		return nil, dependencyFailure(ctx, ctx.Err(), fetchFailureText)
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		set, _ := r.Val.(jwk.Set)

		return set, nil
	}
}

// clientKeysFlight names the flight in the record of a panic recovered on it.
const clientKeysFlight = "client key set fetch"

// errFlightPanicked is what every caller sharing a flight is answered when consumer
// code panicked on it. It is fixed text: the panic value, which can quote a secret,
// is never part of it.
var errFlightPanicked = fmt.Errorf("%w: a client key set fetch panicked: %w", ErrDependency, recovered.ErrPanicked)

// settle is the body of the flight. It runs on a goroutine singleflight starts, with
// no request recovery above it, and singleflight re-raises a panic there where nothing
// can recover it and the process ends. The flight calls consumer code (the clock, the
// outbound client's transport, the logger the outbound client writes to) and parses a
// document any registered client publishes, so its whole work runs under
// recovered.Call. A panic is recorded once on the provider's logger, without the panic
// value, and answered as a failed fetch: every caller sharing the flight gets
// errFlightPanicked, a dependency failure, and the failure window opens.
//
// seen is the caller's latest clock read. It times the window when the clock itself
// keeps panicking.
//
// mu is only ever held through locked, and never around consumer code, so a panic
// cannot leave it held.
func (c *clientKeySets) settle(ctx context.Context, e *clientKeySet, uri, kid string, seen time.Time) (jwk.Set, error) {
	var set jwk.Set
	returned := false
	err := recovered.Call(ctx, c.logger, clientKeysFlight, func() error {
		var err error
		set, err = c.settleEntry(ctx, e, uri, kid, &seen)
		returned = true

		return err
	})
	if returned {
		return set, err
	}

	// The failure is timed by a fresh read. A clock that panics here too is recorded
	// like the first panic, and the latest read that returned stands in, so the window
	// still opens.
	now := seen
	_ = recovered.Call(ctx, c.logger, clientKeysFlight, func() error { //nolint:errcheck // a panic is recorded by Call; seen stands in
		now = c.clock.Now()

		return nil
	})
	c.locked(func() { e.failed, e.until = errFlightPanicked, now.Add(c.cooldown) })

	return nil, errFlightPanicked
}

// settleEntry decides again what get decided outside the flight: a flight that
// finished after the caller looked may have filled the entry, opened a failure window
// or claimed the cooldown. It is what lets the cooldown hold however callers
// interleave. Each clock read that returns is stored in seen.
func (c *clientKeySets) settleEntry(ctx context.Context, e *clientKeySet, uri, kid string, seen *time.Time) (jwk.Set, error) {
	now := c.clock.Now()
	*seen = now

	var (
		set  jwk.Set
		err  error
		done bool
	)
	c.locked(func() {
		switch {
		case c.holds(e, kid, now):
			set, done = e.set, true
		case now.Before(e.until):
			err, done = e.failed, true
		case c.fresh(e, now):
			if now.Before(e.cooled) {
				set, done = e.set, true

				return
			}
			e.cooled = now.Add(c.cooldown)
		}
	})
	if done {
		return set, err
	}

	set, err = c.fetch(ctx, uri)

	now = c.clock.Now()
	*seen = now
	c.locked(func() {
		if err != nil {
			e.failed, e.until = err, now.Add(c.cooldown)

			return
		}
		e.set, e.fetched = set, now
		if !holdsKeyID(set, kid) {
			// The newest document has just been read, so asking again at once would
			// add nothing.
			e.cooled = now.Add(c.cooldown)
		}
	})
	if err != nil {
		return nil, err
	}

	return set, nil
}

// fetch reads and filters the document. A panic in it (a consumer's transport, the
// parse) is recovered by settle, around the whole flight.
func (c *clientKeySets) fetch(ctx context.Context, uri string) (jwk.Set, error) {
	res, err := c.out.Get(ctxlog.With(ctx, c.logger), uri, nil)
	if err != nil {
		return nil, dependencyFailure(ctx, err, fetchFailureText)
	}
	if res.Status != http.StatusOK {
		return nil, fmt.Errorf("%w: client key set: status %d", ErrDependency, res.Status)
	}
	parsed, err := jwk.Parse(res.Body)
	if err != nil {
		return nil, errKeySetUnreadable
	}
	usable := verificationKeys(parsed)
	if usable.Len() == 0 {
		return nil, errKeySetEmpty
	}

	return usable, nil
}

// The failures that say nothing of the document they came from.
var (
	errKeySetUnreadable = fmt.Errorf("%w: a client key set is not a JSON Web Key set", ErrDependency)
	errKeySetEmpty      = fmt.Errorf("%w: a client key set holds no key that can verify an assertion", ErrDependency)
)

// locked runs f holding mu, and releases it however f ends.
func (c *clientKeySets) locked(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
}

// entry returns the entry for key, creating an empty one. The caller holds mu.
func (c *clientKeySets) entry(key string) *clientKeySet {
	if c.entries == nil {
		c.entries = make(map[string]*clientKeySet)
	}
	e, ok := c.entries[key]
	if !ok {
		e = &clientKeySet{}
		c.entries[key] = e
	}

	return e
}

// fresh says the entry's set is within its lifetime. The caller holds mu.
func (c *clientKeySets) fresh(e *clientKeySet, now time.Time) bool {
	return !e.fetched.IsZero() && now.Sub(e.fetched) < c.ttl
}

// holds says the entry can answer kid with no fetch. The caller holds mu.
func (c *clientKeySets) holds(e *clientKeySet, kid string, now time.Time) bool {
	return c.fresh(e, now) && holdsKeyID(e.set, kid)
}

// holdsKeyID says set holds kid. An empty kid asks for no particular key.
func holdsKeyID(set jwk.Set, kid string) bool {
	if kid == "" {
		return true
	}
	_, ok := set.LookupKeyID(kid)

	return ok
}
