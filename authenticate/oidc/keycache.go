package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/sync/singleflight"
)

// DefaultDiscoveryTTL is how long a provider's discovery document and key
// set are served from the cache before they are refetched (WithDiscoveryTTL).
const DefaultDiscoveryTTL = 15 * time.Minute

// DefaultDiscoveryBackoffBase and DefaultDiscoveryBackoffMax bound the window
// after a failed fetch during which no refetch is sent
// (WithDiscoveryFailureBackoff).
const (
	DefaultDiscoveryBackoffBase = time.Second
	DefaultDiscoveryBackoffMax  = 30 * time.Second
)

// DefaultJWKSRefetchCooldown is how long after a refetch for an unknown key id
// the next one for the same provider waits (WithJWKSRefetchCooldown).
const DefaultJWKSRefetchCooldown = 30 * time.Second

// errUnknownSigningKey is returned by keysFor when the provider's key set
// holds no key with the token's key id, after a refetch or inside the
// refetch cooldown. Verification reports it as an invalid token, not as a
// provider failure.
var errUnknownSigningKey = errors.New("oidc: unknown signing key")

// errCooledDown is what a refetch for an unknown key id returns, marked not
// attempted, when the provider's cooldown has not ended: no request is sent,
// and the caller is answered from the current set.
var errCooledDown = errors.New("oidc: key-set refetch cooling down")

// Cache key prefixes: one resource of each kind per provider.
const (
	metaResource = "meta:"
	keysResource = "keys:"
)

// cacheEntry is one cached resource: a provider's metadata or its key set.
type cacheEntry struct {
	md      metadata  // for meta:<provider>
	keys    jwk.Set   // for keys:<provider>
	fetched time.Time // when the value was fetched; zero until the first success

	err    error     // the last failure that reached the network
	until  time.Time // end of the backoff window that failure opened
	misses int       // consecutive failures that reached the network

	cooled time.Time // end of the unknown-key-id refetch cooldown (key sets only)
}

// errNotAttempted marks a refusal that never reached the network: a backoff
// refusal, or a metadata failure inside a key-set fetch. It neither opens nor
// widens a backoff window, since the provider was not asked.
var errNotAttempted = errors.New("oidc: fetch not attempted")

// notAttemptedError marks err with errNotAttempted and keeps its message.
type notAttemptedError struct{ err error }

func (e notAttemptedError) Error() string   { return e.err.Error() } //nolint:forbidigo // stated exception (design decision 6): an Error() method delegating to its cause
func (e notAttemptedError) Unwrap() []error { return []error{e.err, errNotAttempted} }

func notAttempted(err error) error { return notAttemptedError{err: err} }

// keyCache holds every provider's discovery document and key set, in one map
// keyed by resource. It runs nothing in the background: every fetch is made on
// behalf of a caller.
type keyCache struct {
	ttl                     time.Duration
	backoffBase, backoffMax time.Duration
	cooldown                time.Duration
	stale                   time.Duration // zero: an expired entry is never served

	// flight coalesces concurrent fetches of one resource into one request.
	flight singleflight.Group

	mu      sync.Mutex
	entries map[string]*cacheEntry
}

// entry returns the entry for key, creating an empty one. Call it with mu
// held.
func (c *keyCache) entry(key string) *cacheEntry {
	if c.entries == nil {
		c.entries = make(map[string]*cacheEntry)
	}
	e, ok := c.entries[key]
	if !ok {
		e = &cacheEntry{}
		c.entries[key] = e
	}
	return e
}

// backoff returns the window that follows the given number of consecutive
// failures: the base, doubled per failure after the first, capped at the max.
func (c *keyCache) backoff(misses int) time.Duration {
	w := c.backoffBase
	for i := 1; i < misses && w < c.backoffMax; i++ {
		if w > c.backoffMax/2 {
			return c.backoffMax
		}
		w *= 2
	}
	return min(w, c.backoffMax)
}

// fresh reports whether e holds a value younger than the TTL at now. Call it
// with mu held.
func (c *keyCache) fresh(e *cacheEntry, now time.Time) bool {
	return !e.fetched.IsZero() && now.Sub(e.fetched) < c.ttl
}

// metadataFor returns the named provider's metadata: the pinned endpoints when
// all three are pinned, with no request, and otherwise the cached discovery
// document, refetched when it is older than the TTL.
func (m *Manager) metadataFor(ctx context.Context, provider string) (metadata, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return metadata{}, fmt.Errorf("%w: %q", ErrUnknownProvider, provider)
	}
	if md, ok := pinnedMetadata(p); ok {
		return md, nil
	}

	e, err := m.cached(ctx, metaResource+p.Name, func(ctx context.Context) (cacheEntry, error) {
		md, err := m.fetchMetadata(ctx, p)
		return cacheEntry{md: md}, err
	}, nil)
	if err != nil {
		return metadata{}, err
	}
	return e.md, nil
}

// keysFor returns the named provider's key set, restricted to keys usable
// with the provider's signing algorithms. It is served from the cache while
// younger than the TTL and refetched otherwise.
//
// The kid is the key id the caller's token names; an empty kid means no
// particular key is needed. A fresh set that lacks the kid is refetched once,
// and further unknown key ids for the provider are refused from the cache
// until the refetch cooldown ends. A set that still lacks the kid is refused
// with errUnknownSigningKey, which is a refusal of the token, not a provider
// failure.
func (m *Manager) keysFor(ctx context.Context, provider, kid string) (jwk.Set, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, provider)
	}
	if symmetricOnly(p.SigningAlgs) {
		return nil, fmt.Errorf("%w: provider %q: key set: the provider's signing algorithms are symmetric only; there is no key set to fetch",
			ErrDiscoveryFailed, p.Name)
	}
	key := keysResource + p.Name
	fetch := func(ctx context.Context) (cacheEntry, error) {
		md, err := m.metadataFor(ctx, p.Name)
		if err != nil {
			return cacheEntry{}, notAttempted(err) // the metadata entry keeps its own window
		}
		set, err := m.fetchKeys(ctx, p, md)
		return cacheEntry{keys: set}, err
	}
	unknown := func() (jwk.Set, error) {
		return nil, fmt.Errorf("%w: provider %q: no key with the token's key id", errUnknownSigningKey, p.Name)
	}

	c := &m.cache
	c.mu.Lock()
	e := c.entry(key)
	fresh, v := c.fresh(e, m.clock.Now()), *e
	c.mu.Unlock()

	if fresh {
		if hasKeyID(v.keys, kid) {
			return v.keys, nil
		}
		v, err := m.shared(ctx, key, e, fetch, true)
		if errors.Is(err, errCooledDown) {
			err = nil // no refetch was sent; v is the current set
		}
		if err != nil {
			return nil, err
		}
		if !hasKeyID(v.keys, kid) {
			return unknown()
		}
		return v.keys, nil
	}

	v, err := m.cached(ctx, key, fetch, func(v cacheEntry) bool { return hasKeyID(v.keys, kid) })
	if err != nil {
		return nil, err
	}
	if !hasKeyID(v.keys, kid) {
		return unknown()
	}
	return v.keys, nil
}

// hasKeyID reports whether set holds a key with the given id; an empty id
// asks for no particular key.
func hasKeyID(set jwk.Set, kid string) bool {
	if kid == "" {
		return true
	}
	_, ok := set.LookupKeyID(kid)
	return ok
}

// cached returns the entry for key when it is fresh, the recorded failure
// inside a backoff window, and otherwise the result of a shared fetch.
//
// When that fails and a stale window is configured, an expired entry no older
// than the TTL plus the window is served instead, provided usable (nil means
// always) accepts it, with a warning for every such use.
func (m *Manager) cached(ctx context.Context, key string, fetch func(context.Context) (cacheEntry, error), usable func(cacheEntry) bool) (cacheEntry, error) {
	c := &m.cache

	c.mu.Lock()
	e := c.entry(key)
	v, done, err := c.settled(e, m.clock.Now())
	c.mu.Unlock()

	if !done {
		v, err = m.shared(ctx, key, e, fetch, false)
	}
	if err == nil || ctx.Err() != nil || c.stale == 0 {
		return v, err
	}
	return m.staleOr(ctx, key, e, usable, err)
}

// staleOr serves e in place of a failed refetch when it has expired no more
// than the stale window ago and usable accepts it, and returns err otherwise.
// It is reached only from an expired entry's refetch, never from a refetch
// for an unknown key id, so a fresh entry is never served in place of one.
func (m *Manager) staleOr(ctx context.Context, key string, e *cacheEntry, usable func(cacheEntry) bool, err error) (cacheEntry, error) {
	c := &m.cache

	c.mu.Lock()
	v := *e
	age := m.clock.Now().Sub(v.fetched)
	c.mu.Unlock()

	if v.fetched.IsZero() || age < c.ttl || age > c.ttl+c.stale || (usable != nil && !usable(v)) {
		return cacheEntry{}, err
	}

	kind, provider, _ := strings.Cut(key, ":")
	m.log.LogAttrs(ctx, slog.LevelWarn, "oidc provider metadata served stale after a failed refetch",
		slog.String("provider", provider),
		slog.String("resource", resourceName(kind)),
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
// forKid asks for a refetch of a fresh key set that lacks a key id. Its
// cooldown is checked and claimed inside the flight, so the goroutine that
// claims the window is the one that fetches, and callers arriving meanwhile
// share its result instead of being refused. Inside the cooldown it returns
// the current entry with errCooledDown, marked not attempted.
//
// A failed fetch that reached the network opens a backoff window.
func (m *Manager) shared(ctx context.Context, key string, e *cacheEntry, fetch func(context.Context) (cacheEntry, error), forKid bool) (cacheEntry, error) {
	if err := ctx.Err(); err != nil {
		return cacheEntry{}, err
	}
	c := &m.cache

	ch := c.flight.DoChan(key, func() (any, error) {
		c.mu.Lock()
		now := m.clock.Now()
		if forKid && c.fresh(e, now) {
			switch {
			case now.Before(e.cooled):
				v := *e
				c.mu.Unlock()
				return v, notAttempted(errCooledDown)
			case now.Before(e.until):
				c.mu.Unlock()
				return cacheEntry{}, notAttempted(e.err)
			}
			e.cooled = now.Add(c.cooldown)
		} else if v, done, err := c.settled(e, now); done {
			// A flight that finished since the caller looked may have filled
			// the entry or opened a window: honour it, so one window never
			// sends two requests.
			c.mu.Unlock()
			return v, err
		}
		c.mu.Unlock()

		v, err := fetch(context.WithoutCancel(ctx))

		c.mu.Lock()
		if err != nil {
			attrs, log := m.recordFailure(key, e, err)
			c.mu.Unlock()
			if log {
				m.log.LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn, "oidc provider fetch failed; backing off", attrs...)
			}
			return cacheEntry{}, err
		}
		e.md, e.keys, e.fetched = v.md, v.keys, m.clock.Now()
		e.err, e.until, e.misses = nil, time.Time{}, 0
		result := *e
		c.mu.Unlock()
		return result, nil
	})

	select {
	case <-ctx.Done():
		return cacheEntry{}, ctx.Err()
	case r := <-ch:
		v, _ := r.Val.(cacheEntry)
		if !forKid && errors.Is(r.Err, errCooledDown) {
			// This caller joined another's unknown-kid refetch, which the
			// cooldown refused; the entry it returned is fresh.
			return v, nil
		}
		return v, r.Err
	}
}

// settled answers from e without a fetch when it can: its value while fresh,
// or its recorded failure, marked not attempted, inside a backoff window.
// Call it with mu held.
func (c *keyCache) settled(e *cacheEntry, now time.Time) (cacheEntry, bool, error) {
	switch {
	case c.fresh(e, now):
		return *e, true, nil
	case now.Before(e.until):
		return cacheEntry{}, true, notAttempted(e.err)
	}
	return cacheEntry{}, false, nil
}

// recordFailure opens the next backoff window for a failure that reached the
// network. A not-attempted failure changes nothing. Call it with mu held.
//
// It returns the attributes for the "backing off" log record the transition
// warrants, and whether one is warranted at all, instead of writing the log
// itself: the caller logs after releasing mu, so a slow slog handler stalls
// no other provider's lookups.
func (m *Manager) recordFailure(key string, e *cacheEntry, err error) ([]slog.Attr, bool) {
	if errors.Is(err, errNotAttempted) {
		return nil, false
	}
	e.misses++
	window := m.cache.backoff(e.misses)
	e.err, e.until = err, m.clock.Now().Add(window)

	kind, provider, _ := strings.Cut(key, ":")
	return []slog.Attr{
		slog.String("provider", provider),
		slog.String("resource", resourceName(kind)),
		slog.Int("failures", e.misses),
		slog.Duration("window", window),
		slog.String("error", err.Error()), //nolint:forbidigo // stated exception (design decision 6): key-set retrieval failure
	}, true
}

// resourceName names a cache key's kind in logs.
func resourceName(kind string) string {
	if kind+":" == keysResource {
		return "key set"
	}
	return "discovery document"
}

// fetchKeys fetches and parses the provider's key set through the outbound
// client, keeping only the keys its signing algorithms can use. Every failure
// wraps ErrDiscoveryFailed and carries no part of the provider's answer.
func (m *Manager) fetchKeys(ctx context.Context, p Provider, md metadata) (jwk.Set, error) {
	fail := func(format string, args ...any) (jwk.Set, error) {
		return nil, fmt.Errorf("%w: provider %q: key set: %s", ErrDiscoveryFailed, p.Name, fmt.Sprintf(format, args...))
	}

	res, err := m.out.Get(ctx, md.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: provider %q: key set: %w", ErrDiscoveryFailed, p.Name, err)
	}
	if res.Status != http.StatusOK {
		return fail("status %d", res.Status)
	}
	set, err := jwk.Parse(res.Body)
	if err != nil {
		return fail("the document is not a JSON Web Key set")
	}

	usable := jwk.NewSet()
	for _, k := range set.All() {
		if signsWith(k, p.SigningAlgs) {
			if err := usable.AddKey(k); err != nil {
				return fail("the set holds a duplicate key")
			}
		}
	}
	if usable.Len() == 0 {
		return fail("no key is usable with the provider's signing algorithms")
	}
	return usable, nil
}

// symmetricOnly reports whether every one of algs is a symmetric algorithm,
// so the provider has no key set to fetch: an HS* signature is verified with
// the client secret, never with a key from the provider's key set. algs is
// never empty here: keysFor and Prefetch always look it up through
// Registry.Lookup, which resolves a nil list to RS256.
func symmetricOnly(algs []string) bool {
	return len(algs) > 0 && !slices.ContainsFunc(algs, func(alg string) bool {
		return slices.Contains(asymmetricAlgs, alg)
	})
}

// signsWith reports whether k can verify a signature under one of algs: it is
// a signing key (or does not say), and its alg is listed, or, when it names
// none, its key type fits a listed asymmetric algorithm. A symmetric key is
// never taken from a key set: a symmetric algorithm uses the client secret.
func signsWith(k jwk.Key, algs []string) bool {
	if use, ok := k.KeyUsage(); ok && use != string(jwk.ForSignature) {
		return false
	}
	if alg, ok := k.Algorithm(); ok {
		return slices.Contains(asymmetricAlgs, alg.String()) && slices.Contains(algs, alg.String())
	}

	kty := k.KeyType().String()
	return slices.ContainsFunc(algs, func(alg string) bool {
		switch {
		case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
			return kty == "RSA"
		case strings.HasPrefix(alg, "ES"):
			return kty == "EC"
		case alg == "EdDSA":
			return kty == "OKP"
		}
		return false
	})
}

// Prefetch fetches every provider's discovery document (unless all three
// endpoints are pinned) and key set now, in registration order, and fills the
// cache with them. A provider whose signing algorithms are all symmetric has
// no key set to fetch, so only its discovery document is prefetched. It
// returns at the first failure, with an error naming that provider and
// wrapping ErrDiscoveryFailed, or the context's error.
//
// Calling it is optional. By default nothing is fetched until the first login
// needs it, because NewManager takes no context and so makes no request; a
// consumer who would rather find an unreachable provider at start-up calls
// Prefetch then. It starts no background work: entries still expire after the
// TTL and are refetched on demand.
func (m *Manager) Prefetch(ctx context.Context) error {
	for _, name := range m.registry.Names() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := m.metadataFor(ctx, name); err != nil {
			return fmt.Errorf("oidc: prefetch of provider %q: %w", name, err)
		}
		p, _ := m.registry.Lookup(name)
		if symmetricOnly(p.SigningAlgs) {
			continue
		}
		if _, err := m.keysFor(ctx, name, ""); err != nil {
			return fmt.Errorf("oidc: prefetch of provider %q: %w", name, err)
		}
	}
	return nil
}
