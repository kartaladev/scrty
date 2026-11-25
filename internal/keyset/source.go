package keyset

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
	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/clock"
)

// Defaults New applies, each replaceable by the option named beside it.
const (
	DefaultTTL             = 15 * time.Minute // WithTTL
	DefaultBackoffBase     = time.Second      // WithBackoff
	DefaultBackoffMax      = 30 * time.Second // WithBackoff
	DefaultRefetchCooldown = 30 * time.Second // WithRefetchCooldown
)

var (
	// ErrUnknownKey is returned by Key when the key set holds no signing key
	// for the token: no key with its key id after a refetch (or inside the
	// refetch cooldown), or, for a token with no key id, not exactly one
	// signing key. It is a refusal of the token, not a dependency failure.
	ErrUnknownKey = errors.New("keyset: no key for the token")

	// ErrUnavailable wraps every failure to obtain the key set: the issuer's
	// metadata or key set could not be fetched, was malformed, named another
	// issuer, or put the key set on another origin. It carries no part of the
	// remote's answer.
	ErrUnavailable = errors.New("keyset: key set unavailable")

	// ErrConfig wraps every error New returns for a wiring mistake.
	ErrConfig = errors.New("keyset: invalid configuration")
)

// Well-known metadata locations: OpenID Connect Discovery 1.0 §4 appends its
// segment to the issuer; RFC 8414 §3 inserts its segment before the issuer's
// path.
const (
	openIDConfiguration = "/.well-known/openid-configuration"
	oauthServerMetadata = "/.well-known/oauth-authorization-server"
)

const (
	metaResource = "authorization server metadata"
	keysResource = "key set"
)

// value is one cached resource of a Source: its metadata's key-set URL, or
// its key set.
type value struct {
	jwksURI string
	keys    jwk.Set
}

// Source serves the signing keys of one remote issuer, fetched through a
// confined outbound client and cached. Build one with New; it is safe for
// concurrent use and starts no goroutine of its own.
//
// The key set's URL is found from the issuer's metadata: OpenID Connect
// Discovery first, then RFC 8414 when, and only when, that answers 404. The
// metadata must name the configured issuer, and the key-set URL it gives must
// be on the issuer's origin. WithJWKSURL pins the URL instead, and no metadata
// is read.
type Source struct {
	name    string
	out     *outbound.Client
	issuer  string
	jwksURL string
	log     *slog.Logger

	cache Cache[value]
}

// Option configures a Source.
type Option func(*Source) error

// WithIssuer sets the issuer whose metadata locates the key set. It must be an
// absolute https URL with no userinfo, query or fragment (RFC 8414 §2). There is no
// default: New needs WithIssuer, WithJWKSURL or both.
func WithIssuer(iss string) Option {
	return func(s *Source) error {
		u, err := url.Parse(iss)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(iss, "#") {
			return fmt.Errorf("%w: WithIssuer needs an absolute https URL with no userinfo, query or fragment", ErrConfig)
		}
		s.issuer = iss
		return nil
	}
}

// WithJWKSURL pins the key set's URL, so no metadata is read. It must be an
// absolute https URL, and may be on another origin than the issuer. The
// default is to discover it from the issuer's metadata.
func WithJWKSURL(u string) Option {
	return func(s *Source) error {
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "https" || p.Host == "" {
			return fmt.Errorf("%w: WithJWKSURL needs an absolute https URL", ErrConfig)
		}
		s.jwksURL = u
		return nil
	}
}

// WithTTL sets how long metadata and the key set are served with no request.
// The default is DefaultTTL. Zero or less is refused.
func WithTTL(ttl time.Duration) Option {
	return func(s *Source) error {
		s.cache.TTL = ttl
		return nil
	}
}

// WithRefetchCooldown sets how long after a refetch for an unknown key id the
// next one waits; unknown key ids meanwhile are refused from the cache. The
// default is DefaultRefetchCooldown. Zero or less is refused.
func WithRefetchCooldown(cooldown time.Duration) Option {
	return func(s *Source) error {
		s.cache.Cooldown = cooldown
		return nil
	}
}

// WithBackoff sets the window after a failed fetch during which no refetch is
// sent: base, doubled per consecutive failure up to maxWindow. The defaults
// are DefaultBackoffBase and DefaultBackoffMax. It needs 0 < base <= maxWindow.
func WithBackoff(base, maxWindow time.Duration) Option {
	return func(s *Source) error {
		s.cache.BackoffBase, s.cache.BackoffMax = base, maxWindow
		return nil
	}
}

// WithClock replaces the time source, clock.System() by default. A nil clock
// is refused.
func WithClock(c clock.Clock) Option {
	return func(s *Source) error {
		if c == nil {
			return fmt.Errorf("%w: WithClock needs a clock", ErrConfig)
		}
		s.cache.Clock = c
		return nil
	}
}

// WithLogger replaces the logger of fetch failures and recovered panics,
// ctxlog.Routing() by default. A nil logger is refused.
func WithLogger(l *slog.Logger) Option {
	return func(s *Source) error {
		if l == nil {
			return fmt.Errorf("%w: WithLogger needs a logger", ErrConfig)
		}
		s.log = l
		return nil
	}
}

// New returns a Source named name, which appears in logs and errors and keys
// nothing outside this Source: two Sources never share an entry. fetcher sends
// every request; nil means outbound.New() with its defaults (https only, same
// origin redirects, bounded time and size).
func New(name string, fetcher *outbound.Client, opts ...Option) (*Source, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: a source needs a name", ErrConfig)
	}
	s := &Source{name: name, out: fetcher}
	s.cache.TTL = DefaultTTL
	s.cache.BackoffBase, s.cache.BackoffMax = DefaultBackoffBase, DefaultBackoffMax
	s.cache.Cooldown = DefaultRefetchCooldown
	s.cache.Clock = clock.System()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if s.issuer == "" && s.jwksURL == "" {
		return nil, fmt.Errorf("%w: source %q needs WithIssuer or WithJWKSURL", ErrConfig, name)
	}
	if err := checkTimings(s.cache.TTL, s.cache.BackoffBase, s.cache.BackoffMax, s.cache.Cooldown); err != nil {
		return nil, fmt.Errorf("source %q: %w", name, err)
	}
	if s.out == nil {
		out, err := outbound.New()
		if err != nil {
			return nil, fmt.Errorf("%w: source %q: default outbound client: %w", ErrConfig, name, err)
		}
		s.out = out
	}
	if s.log == nil {
		s.log = ctxlog.Routing()
	}
	s.cache.Log = s.log
	s.cache.SubjectAttr = "source"
	s.cache.StaleMessage = "remote key set served stale after a failed refetch"
	s.cache.BackoffMessage = "remote key set fetch failed; backing off"
	s.cache.PanicError = func(k Key, err error) error {
		return fmt.Errorf("%w: source %q: %s: %w", ErrUnavailable, k.Subject, k.Resource, err)
	}
	return s, nil
}

// Key returns the signing key with the given key id. An empty kid is answered
// with the set's only signing key, and refused when the set holds more than
// one. A key id the cached set lacks triggers at most one refetch per
// cooldown. It returns ErrUnknownKey for a key it cannot find, ErrUnavailable
// for a dependency failure, or the context's error.
func (s *Source) Key(ctx context.Context, kid string) (jwk.Key, error) {
	has := func(v value) bool { return pick(v.keys, kid) != nil }
	v, err := s.cache.Lookup(ctx, Key{Resource: keysResource, Subject: s.name}, s.fetchSet, has)
	if err != nil {
		return nil, err
	}
	k := pick(v.keys, kid)
	if k == nil {
		return nil, fmt.Errorf("%w: source %q", ErrUnknownKey, s.name)
	}
	return k, nil
}

// pick returns the key named kid, or for an empty kid the only key, or nil.
func pick(set jwk.Set, kid string) jwk.Key {
	if set == nil {
		return nil
	}
	if kid == "" {
		if set.Len() != 1 {
			return nil
		}
		k, _ := set.Key(0)
		return k
	}
	k, ok := set.LookupKeyID(kid)
	if !ok {
		return nil
	}
	return k
}

// fetchSet locates and fetches the key set.
func (s *Source) fetchSet(ctx context.Context) (value, error) {
	u := s.jwksURL
	if u == "" {
		md, err := s.cache.Get(ctx, Key{Resource: metaResource, Subject: s.name}, s.fetchMetadata, nil)
		if err != nil {
			return value{}, NotAttempted(err) // the metadata entry keeps its own window
		}
		u = md.jwksURI
	}
	set, err := s.fetchKeys(ctx, u)
	return value{keys: set}, err
}

func (s *Source) fail(resource, format string, args ...any) error {
	return fmt.Errorf("%w: source %q: %s: %s", ErrUnavailable, s.name, resource, fmt.Sprintf(format, args...))
}

// fetchMetadata reads the issuer's metadata: OpenID Discovery, then RFC 8414
// on a 404 only. The metadata must name the configured issuer, and a key-set
// URL on the issuer's origin with a scheme the outbound client allows.
func (s *Source) fetchMetadata(ctx context.Context) (value, error) {
	ctx = ctxlog.With(ctx, s.log)
	res, err := s.out.Get(ctx, strings.TrimSuffix(s.issuer, "/")+openIDConfiguration, nil)
	if err != nil {
		return value{}, fmt.Errorf("%w: source %q: %s: %w", ErrUnavailable, s.name, metaResource, err)
	}
	if res.Status == http.StatusNotFound {
		res, err = s.out.Get(ctx, oauthMetadataURL(s.issuer), nil)
		if err != nil {
			return value{}, fmt.Errorf("%w: source %q: %s: %w", ErrUnavailable, s.name, metaResource, err)
		}
	}
	if res.Status != http.StatusOK {
		return value{}, s.fail(metaResource, "status %d", res.Status)
	}

	var md struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(res.Body, &md); err != nil {
		return value{}, s.fail(metaResource, "the document is not a JSON object")
	}
	if md.Issuer != s.issuer {
		return value{}, s.fail(metaResource, "the document names another issuer")
	}
	if md.JWKSURI == "" {
		return value{}, s.fail(metaResource, "the document names no key set")
	}
	u, err := url.Parse(md.JWKSURI)
	if err != nil || !s.out.AllowsScheme(u.Scheme) || !origin.Same(s.issuer, md.JWKSURI) {
		return value{}, s.fail(metaResource, "the key set is not on the issuer's origin")
	}
	return value{jwksURI: md.JWKSURI}, nil
}

// oauthMetadataURL inserts RFC 8414's well-known segment between the issuer's
// host and its path.
func oauthMetadataURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return "" // unreachable: WithIssuer validated it; Get refuses an empty URL
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	return u.Scheme + "://" + u.Host + oauthServerMetadata + path
}

// fetchKeys fetches and parses the key set, keeping only asymmetric signing
// keys: one marked for encryption, one whose key_ops lack verify, or a
// symmetric key, is never used to verify a signature.
func (s *Source) fetchKeys(ctx context.Context, u string) (jwk.Set, error) {
	res, err := s.out.Get(ctxlog.With(ctx, s.log), u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: source %q: %s: %w", ErrUnavailable, s.name, keysResource, err)
	}
	if res.Status != http.StatusOK {
		return nil, s.fail(keysResource, "status %d", res.Status)
	}
	set, err := jwk.Parse(res.Body)
	if err != nil {
		return nil, s.fail(keysResource, "the document is not a JSON Web Key set")
	}
	usable := jwk.NewSet()
	for _, k := range set.All() {
		if use, ok := k.KeyUsage(); ok && use != string(jwk.ForSignature) {
			continue
		}
		if ops, ok := k.KeyOps(); ok && !slices.Contains(ops, jwk.KeyOpVerify) {
			continue
		}
		if k.KeyType().String() == "oct" {
			continue
		}
		if err := usable.AddKey(k); err != nil {
			return nil, s.fail(keysResource, "the set holds a duplicate key")
		}
	}
	if usable.Len() == 0 {
		return nil, s.fail(keysResource, "no signing key")
	}
	return usable, nil
}
