package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"golang.org/x/sync/singleflight"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/internal/recovered"
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

// locked runs f with mu held, and releases mu however f ends, a panic
// included. f reads and writes entries only: the clock is read before, and no
// consumer code runs inside, so a slow or panicking consumer never holds mu.
func (c *keyCache) locked(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
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
func (m *RelyingParty) metadataFor(ctx context.Context, provider string) (metadata, error) {
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
func (m *RelyingParty) keysFor(ctx context.Context, provider, kid string) (jwk.Set, error) {
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
	now := m.clock.Now()
	var (
		e     *cacheEntry
		fresh bool
		v     cacheEntry
	)
	c.locked(func() {
		e = c.entry(key)
		fresh, v = c.fresh(e, now), *e
	})

	if fresh {
		if hasKeyID(v.keys, kid) {
			return v.keys, nil
		}
		v, err := m.shared(ctx, key, e, now, fetch, true)
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
func (m *RelyingParty) cached(ctx context.Context, key string, fetch func(context.Context) (cacheEntry, error), usable func(cacheEntry) bool) (cacheEntry, error) {
	c := &m.cache

	now := m.clock.Now()
	var (
		e    *cacheEntry
		v    cacheEntry
		done bool
		err  error
	)
	c.locked(func() {
		e = c.entry(key)
		v, done, err = c.settled(e, now)
	})

	if !done {
		v, err = m.shared(ctx, key, e, now, fetch, false)
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
func (m *RelyingParty) staleOr(ctx context.Context, key string, e *cacheEntry, usable func(cacheEntry) bool, err error) (cacheEntry, error) {
	c := &m.cache

	now := m.clock.Now()
	var v cacheEntry
	c.locked(func() { v = *e })
	age := now.Sub(v.fetched)

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
// A failed fetch that reached the network opens a backoff window. So does a
// panic anywhere in the flight (see refresh).
//
// now is the caller's latest read of the clock, which refresh falls back on
// when the clock panics before a failure can be timed.
func (m *RelyingParty) shared(ctx context.Context, key string, e *cacheEntry, now time.Time, fetch func(context.Context) (cacheEntry, error), forKid bool) (cacheEntry, error) {
	if err := ctx.Err(); err != nil {
		return cacheEntry{}, err
	}
	c := &m.cache

	ch := c.flight.DoChan(key, func() (any, error) {
		return m.refresh(context.WithoutCancel(ctx), key, e, now, fetch, forKid)
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

// refresh is the body of shared's flight. It runs on a goroutine singleflight
// starts, with no request recovery above it, and singleflight re-raises a
// flight's panic where nothing can recover it. The flight calls consumer code
// (the clock, the outbound client's Transport) and parses the provider's
// answer, so its whole work runs under recovered.Call, named after the
// resource. A panic is reported once, at Error, to the relying party's logger
// without the panic value's text, and answered as a fetch failure:
// ErrDiscoveryFailed wrapping recovered.ErrPanicked, which every waiter on the
// flight receives and which opens a backoff window.
//
// mu is only ever held through keyCache.locked, so a panic leaves it released,
// and the entry is written whole or not at all: a value and its fetch time
// together, or a failure and its window together.
func (m *RelyingParty) refresh(ctx context.Context, key string, e *cacheEntry, seen time.Time, fetch func(context.Context) (cacheEntry, error), forKid bool) (cacheEntry, error) {
	kind, provider, _ := strings.Cut(key, ":")
	what := resourceName(kind) + " refresh"

	var v cacheEntry
	returned := false
	err := recovered.Call(ctx, m.log, what, func() error {
		var err error
		v, err = m.refreshEntry(ctx, e, &seen, fetch, forKid)
		returned = true
		return err
	})
	if !returned {
		err = fmt.Errorf("%w: provider %q: %s: %w", ErrDiscoveryFailed, provider, resourceName(kind), err)
	}
	if err == nil || errors.Is(err, errNotAttempted) {
		return v, err
	}

	// The failure is timed by a fresh read. A clock that panics here too is
	// reported like the first panic, and the failure is timed by the latest
	// read that returned instead, so the window still opens.
	now := seen
	_ = recovered.Call(ctx, m.log, what, func() error { //nolint:errcheck // a panic is reported by Call; seen stands in
		now = m.clock.Now()
		return nil
	})

	var (
		attrs []slog.Attr
		log   bool
	)
	m.cache.locked(func() { attrs, log = m.recordFailure(key, e, err, now) })
	if log {
		// The relying party's logger is the consumer's handler, and this runs
		// on the flight's goroutine, where a panic would be re-raised by
		// singleflight beyond recovery. The failure is already recorded, so
		// a handler that panics loses only this record.
		_ = recovered.Call(ctx, m.log, what, func() error { //nolint:errcheck // a panic is reported by Call; the answer is err
			m.log.LogAttrs(ctx, slog.LevelWarn, "oidc provider fetch failed; backing off", attrs...)
			return nil
		})
	}
	return cacheEntry{}, err
}

// refreshEntry re-checks e, fetches when it still needs a fetch, and stores a
// success in e. It returns a fetch failure unrecorded, for refresh to record.
// Every clock read is stored in seen as it returns.
//
// forKid asks for a refetch of a fresh key set that lacks a key id; see
// shared.
func (m *RelyingParty) refreshEntry(ctx context.Context, e *cacheEntry, seen *time.Time, fetch func(context.Context) (cacheEntry, error), forKid bool) (cacheEntry, error) {
	c := &m.cache

	now := m.clock.Now()
	*seen = now
	var (
		v    cacheEntry
		done bool
		err  error
	)
	c.locked(func() {
		if forKid && c.fresh(e, now) {
			switch {
			case now.Before(e.cooled):
				v, done, err = *e, true, notAttempted(errCooledDown)
			case now.Before(e.until):
				done, err = true, notAttempted(e.err)
			default:
				e.cooled = now.Add(c.cooldown)
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
		return cacheEntry{}, err
	}

	now = m.clock.Now()
	*seen = now
	c.locked(func() {
		e.md, e.keys, e.fetched = got.md, got.keys, now
		e.err, e.until, e.misses = nil, time.Time{}, 0
		v = *e
	})
	return v, nil
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
// network, at now. A not-attempted failure changes nothing. Call it with mu
// held.
//
// It returns the attributes for the "backing off" log record the transition
// warrants, and whether one is warranted at all, instead of writing the log
// itself: the caller logs after releasing mu, so a slow slog handler stalls
// no other provider's lookups.
func (m *RelyingParty) recordFailure(key string, e *cacheEntry, err error, now time.Time) ([]slog.Attr, bool) {
	if errors.Is(err, errNotAttempted) {
		return nil, false
	}
	e.misses++
	window := m.cache.backoff(e.misses)
	e.err, e.until = err, now.Add(window)

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
func (m *RelyingParty) fetchKeys(ctx context.Context, p Provider, md metadata) (jwk.Set, error) {
	fail := func(format string, args ...any) (jwk.Set, error) {
		return nil, fmt.Errorf("%w: provider %q: key set: %s", ErrDiscoveryFailed, p.Name, fmt.Sprintf(format, args...))
	}

	res, err := m.out.Get(ctxlog.With(ctx, m.log), md.JWKSURI, nil)
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
// needs it, because NewRelyingParty takes no context and so makes no request; a
// consumer who would rather find an unreachable provider at start-up calls
// Prefetch then. It starts no background work: entries still expire after the
// TTL and are refetched on demand.
func (m *RelyingParty) Prefetch(ctx context.Context) error {
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

// confined reports whether a discovered endpoint is on the provider issuer's
// origin, with a scheme the outbound client allows.
func (m *RelyingParty) confined(p Provider, raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && m.out.AllowsScheme(u.Scheme) && origin.Same(p.Issuer, raw)
}

// wellKnownPath is where an issuer publishes its discovery document.
const wellKnownPath = "/.well-known/openid-configuration"

// metadata is what the manager needs from a provider, discovered or pinned.
type metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// pinnedMetadata returns the provider's pinned endpoints, and true when all
// three are pinned, so discovery is never needed.
func pinnedMetadata(p Provider) (metadata, bool) {
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return metadata{}, false
	}
	return metadata{
		Issuer:                p.Issuer,
		AuthorizationEndpoint: p.AuthorizationEndpoint,
		TokenEndpoint:         p.TokenEndpoint,
		JWKSURI:               p.JWKSURI,
		EndSessionEndpoint:    p.EndSessionEndpoint,
		UserInfoEndpoint:      p.UserInfoEndpoint,
	}, true
}

// fetchMetadata returns the provider's metadata: its pinned endpoints when all
// three are pinned, with no request, and otherwise the issuer's discovery
// document, fetched through the outbound client and confined to the issuer.
//
// The document must name the configured issuer exactly, the authorization,
// token and key-set endpoints, and put every endpoint it names on the issuer's
// origin with a scheme the outbound client allows. A pinned end-session or
// UserInfo endpoint wins over a discovered one. A discovered UserInfo endpoint
// off the issuer's origin, or with a refused scheme, is dropped with a WARN
// record rather than failing discovery, since only UserInfo needs it. Every failure wraps ErrDiscoveryFailed
// and carries no part of the provider's answer.
func (m *RelyingParty) fetchMetadata(ctx context.Context, p Provider) (metadata, error) {
	if md, ok := pinnedMetadata(p); ok {
		return md, nil
	}

	fail := func(format string, args ...any) (metadata, error) {
		return metadata{}, fmt.Errorf("%w: provider %q: discovery: %s", ErrDiscoveryFailed, p.Name, fmt.Sprintf(format, args...))
	}

	res, err := m.out.Get(ctxlog.With(ctx, m.log), strings.TrimSuffix(p.Issuer, "/")+wellKnownPath, nil)
	if err != nil {
		return metadata{}, fmt.Errorf("%w: provider %q: discovery: %w", ErrDiscoveryFailed, p.Name, err)
	}
	if res.Status != http.StatusOK {
		return fail("status %d", res.Status)
	}

	var md metadata
	if err := json.Unmarshal(res.Body, &md); err != nil {
		return fail("the document is not a JSON object")
	}
	if md.Issuer != p.Issuer {
		return fail("the document names another issuer")
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.JWKSURI == "" {
		return fail("a required endpoint is missing")
	}
	for _, raw := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.JWKSURI, md.EndSessionEndpoint} {
		if raw == "" {
			continue // only the end-session endpoint may be absent, checked above
		}
		if !m.confined(p, raw) {
			return fail("an endpoint is not on the issuer's origin")
		}
	}
	if p.EndSessionEndpoint != "" {
		md.EndSessionEndpoint = p.EndSessionEndpoint // a pin wins over discovery
	}
	switch {
	case p.UserInfoEndpoint != "":
		md.UserInfoEndpoint = p.UserInfoEndpoint // a pin wins over discovery
	case md.UserInfoEndpoint != "" && !m.confined(p, md.UserInfoEndpoint):
		// Only UserInfo needs it, so it is dropped rather than failing every
		// login: UserInfo then fails with no endpoint known, and is never
		// sent where the issuer's origin does not reach.
		md.UserInfoEndpoint = ""
		m.log.LogAttrs(ctx, slog.LevelWarn, "oidc discovered userinfo endpoint ignored",
			slog.String("provider", p.Name),
			slog.String("reason", "not on the issuer's origin, or a scheme the outbound client refuses"))
	}

	return md, nil
}
