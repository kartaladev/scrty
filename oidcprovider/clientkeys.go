package oidcprovider

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/sync/singleflight"

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

	c.mu.Lock()
	e := c.entry(key)
	if c.holds(e, kid, c.clock.Now()) {
		set := e.set
		c.mu.Unlock()

		return set, nil
	}
	c.mu.Unlock()

	// The fetch keeps the first caller's values and not its cancellation, so one caller
	// leaving does not fail those sharing it. The outbound client's timeout bounds it,
	// and each caller stops waiting when its own context ends.
	ch := c.flight.DoChan(key, func() (any, error) {
		return c.settle(context.WithoutCancel(ctx), e, uri, kid)
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

// settle runs inside the flight, and decides again what get decided outside it: a
// flight that finished after the caller looked may have filled the entry, opened a
// failure window or claimed the cooldown. It is what lets the cooldown hold however
// callers interleave.
func (c *clientKeySets) settle(ctx context.Context, e *clientKeySet, uri, kid string) (jwk.Set, error) {
	c.mu.Lock()
	now := c.clock.Now()
	switch {
	case c.holds(e, kid, now):
		set := e.set
		c.mu.Unlock()

		return set, nil
	case now.Before(e.until):
		err := e.failed
		c.mu.Unlock()

		return nil, err
	case c.fresh(e, now):
		if now.Before(e.cooled) {
			set := e.set
			c.mu.Unlock()

			return set, nil
		}
		e.cooled = now.Add(c.cooldown)
	}
	c.mu.Unlock()

	set, err := c.fetch(ctx, uri)

	c.mu.Lock()
	defer c.mu.Unlock()

	now = c.clock.Now()
	if err != nil {
		e.failed, e.until = err, now.Add(c.cooldown)

		return nil, err
	}
	e.set, e.fetched = set, now
	if !holdsKeyID(set, kid) {
		// The newest document has just been read, so asking again at once would add
		// nothing.
		e.cooled = now.Add(c.cooldown)
	}

	return set, nil
}

// fetch reads and filters the document. A panic in a consumer's transport is answered
// as a failed fetch: this runs on the flight's goroutine, where it could otherwise only
// end the process, and any stranger's request can start it.
func (c *clientKeySets) fetch(ctx context.Context, uri string) (set jwk.Set, err error) {
	defer func() {
		if recover() != nil {
			set, err = nil, fmt.Errorf("%w: a client key set fetch panicked", ErrDependency)
		}
	}()

	res, err := c.out.Get(ctx, uri, nil)
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
