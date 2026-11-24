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
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/keyset"
	"github.com/kartaladev/scrty/internal/origin"
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

// Cache resource kinds: one resource of each kind per provider, named as
// logs name them.
const (
	metaResource = "discovery document"
	keysResource = "key set"
)

// cached is one cached resource: a provider's metadata or its key set.
type cached struct {
	md   metadata // for the discovery document
	keys jwk.Set  // for the key set
}

// keyCache holds every provider's discovery document and key set.
type keyCache = keyset.Cache[cached]

// wireCache gives the cache the relying party's clock and logger and the
// wording of its records and failures. NewRelyingParty calls it once every
// option has been applied.
func (m *RelyingParty) wireCache() {
	m.cache.Clock, m.cache.Log = m.clock, m.log
	m.cache.SubjectAttr = "provider"
	m.cache.StaleMessage = "oidc provider metadata served stale after a failed refetch"
	m.cache.BackoffMessage = "oidc provider fetch failed; backing off"
	m.cache.PanicError = func(k keyset.Key, err error) error {
		return fmt.Errorf("%w: provider %q: %s: %w", ErrDiscoveryFailed, k.Subject, k.Resource, err)
	}
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

	e, err := m.cache.Get(ctx, keyset.Key{Resource: metaResource, Subject: p.Name}, func(ctx context.Context) (cached, error) {
		md, err := m.fetchMetadata(ctx, p)
		return cached{md: md}, err
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
	key := keyset.Key{Resource: keysResource, Subject: p.Name}
	fetch := func(ctx context.Context) (cached, error) {
		md, err := m.metadataFor(ctx, p.Name)
		if err != nil {
			return cached{}, keyset.NotAttempted(err) // the metadata entry keeps its own window
		}
		set, err := m.fetchKeys(ctx, p, md)
		return cached{keys: set}, err
	}

	v, err := m.cache.Lookup(ctx, key, fetch, func(v cached) bool { return hasKeyID(v.keys, kid) })
	if err != nil {
		return nil, err
	}
	if !hasKeyID(v.keys, kid) {
		return nil, fmt.Errorf("%w: provider %q: no key with the token's key id", errUnknownSigningKey, p.Name)
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
