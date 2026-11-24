// Package introspect asks an OAuth 2.0 authorization server whether an opaque
// access token is active (RFC 7662), and decides from its answer whether a
// resource may accept the token.
//
// The client posts the token with token_type_hint=access_token through an
// outbound.Client, authenticating as client_secret_basic (Config.Secret) or
// private_key_jwt (Config.Key, RFC 7523). It reaches https endpoints only,
// trusts exactly one issuer, and never writes a token, a secret, a key or an
// answer's body into a log record or an error.
//
// An endpoint that cannot answer — a transport failure, a status other than
// 200, a body that is not a well-formed introspection answer — is ErrUnavailable,
// never an inactive token, so a caller can answer an outage as a dependency
// failure rather than a refused credential.
//
// Concurrent introspections of one token share one call. An optional cache
// (Config.Cache, off by default) keeps an active answer for at most its bound
// and never past the token's expiry; it is keyed by the SHA-256 of the token,
// so the token itself is never held.
package introspect

import (
	"container/list"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"golang.org/x/sync/singleflight"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/outbound"
)

var (
	// ErrConfig is wrapped by every error New returns for a wiring mistake.
	ErrConfig = errors.New("introspect: invalid configuration")

	// ErrUnavailable is wrapped by every error Introspect returns when the
	// endpoint could not give a usable answer. It never means the token is
	// inactive.
	ErrUnavailable = errors.New("introspect: the introspection endpoint could not answer")
)

// assertionLifetime is how long a private_key_jwt client assertion is valid.
const assertionLifetime = time.Minute

// assertionTypeJWT is the client_assertion_type of RFC 7523 §2.2.
const assertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// signingAlgs are the asymmetric algorithms a Key may sign with.
var signingAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// Key is the private key of private_key_jwt client authentication.
type Key struct {
	// Signer signs the client assertion. Required.
	Signer crypto.Signer
	// Algorithm is the JWS algorithm, one of the asymmetric algorithms
	// (RS*, PS*, ES*, EdDSA). Required.
	Algorithm string
	// The assertion's aud is the configured Config.Issuer (RFC 7523 §3).
	// KeyID is put in the assertion's kid header when not empty.
	KeyID string
}

// Cache bounds the cache of active answers. The zero value disables it.
// Both fields are set together or neither is.
type Cache struct {
	// MaxAge is how long an answer may be reused, further bounded by the
	// token's exp.
	MaxAge time.Duration
	// MaxEntries is how many answers are held; the oldest is evicted first.
	MaxEntries int
}

// Config configures a Client.
type Config struct {
	// Issuer is the authorization server the answers must come from. Required.
	// An answer naming another iss is treated as inactive; one naming none is
	// taken as this issuer's.
	Issuer string
	// Endpoint is the introspection endpoint, an https URL. Required.
	Endpoint string
	// ClientID is the resource server's client identifier. Required.
	ClientID string
	// Secret selects client_secret_basic. Exactly one of Secret and Key is set.
	Secret string
	// Key selects private_key_jwt. Exactly one of Secret and Key is set.
	Key *Key
	// Cache enables the answer cache. Default: off.
	Cache Cache
	// Clock is the time source. Default: the real clock.
	Clock clockwork.Clock
	// Logger receives failure records. Default: the logger the request
	// context carries, else slog.Default().
	Logger *slog.Logger
}

// Result is an introspection answer, read as RFC 7662 §2.2 describes it.
// Claims holds every member of the answer, unchanged.
type Result struct {
	Active    bool
	TokenType string
	Issuer    string
	Subject   string
	ClientID  string
	ACR       string
	Audience  []string
	Scopes    []string
	AMR       []string
	ExpiresAt time.Time
	AuthTime  time.Time
	// Confirmation holds the string members of the cnf claim (jkt, x5t#S256).
	// Members of other types, such as jwk, are not kept here and remain only
	// in Claims.
	Confirmation map[string]string
	Claims       map[string]any
}

// Accepts reports whether a resource identified by resource may accept the
// token at now: it is active, its token_type is absent or names an access
// token (access_token, Bearer, DPoP), its audience names resource, its subject
// is not empty, and it carries an exp later than now. A refresh token an
// authorization server reports active is refused here.
func (r *Result) Accepts(resource string, now time.Time) bool {
	if r == nil || !r.Active || resource == "" || r.Subject == "" || r.ExpiresAt.IsZero() || !now.Before(r.ExpiresAt) {
		return false
	}
	switch strings.ToLower(r.TokenType) {
	case "", "access_token", "bearer", "dpop":
	default:
		return false
	}
	return slices.Contains(r.Audience, resource)
}

func (r *Result) clone() *Result {
	c := *r
	c.Audience = slices.Clone(r.Audience)
	c.Scopes = slices.Clone(r.Scopes)
	c.AMR = slices.Clone(r.AMR)
	c.Confirmation = maps.Clone(r.Confirmation)
	c.Claims = cloneAny(r.Claims)
	return &c
}

func cloneAny[T any](v T) T {
	switch x := any(v).(type) {
	case map[string]any:
		if x == nil {
			return v
		}
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = cloneAny(e)
		}
		return any(m).(T)
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = cloneAny(e)
		}
		return any(s).(T)
	default:
		return v
	}
}

// Client introspects tokens at one endpoint for one issuer. It is safe for
// concurrent use.
type Client struct {
	cfg     Config
	alg     jwa.SignatureAlgorithm
	fetcher *outbound.Client
	clock   clockwork.Clock
	logger  *slog.Logger
	group   singleflight.Group
	cache   *cache
	// joined, when set by a test, runs once a caller has joined the shared call.
	joined func()
}

// New builds a Client, or returns an error wrapping ErrConfig naming what
// cannot work. An http endpoint is refused whatever the fetcher allows.
func New(cfg Config, fetcher *outbound.Client) (*Client, error) {
	refuse := func(format string, args ...any) (*Client, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrConfig}, args...)...)
	}
	if fetcher == nil {
		return refuse("no outbound client")
	}
	if cfg.Issuer == "" {
		return refuse("no issuer")
	}
	if cfg.ClientID == "" {
		return refuse("no client id")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return refuse("the endpoint is not a URL")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Fragment != "" || u.User != nil {
		return refuse("the endpoint must be an https URL with a host, no userinfo and no fragment")
	}
	c := &Client{cfg: cfg, fetcher: fetcher, clock: cfg.Clock, logger: cfg.Logger}
	switch {
	case cfg.Secret != "" && cfg.Key != nil:
		return refuse("both a secret and a key are set")
	case cfg.Secret == "" && cfg.Key == nil:
		return refuse("neither a secret nor a key is set")
	case cfg.Key != nil:
		if cfg.Key.Signer == nil {
			return refuse("the key has no signer")
		}
		alg, ok := jwa.LookupSignatureAlgorithm(cfg.Key.Algorithm)
		if !ok || !slices.Contains(signingAlgs, cfg.Key.Algorithm) {
			return refuse("the key algorithm %q is not an asymmetric signature algorithm", cfg.Key.Algorithm)
		}
		c.alg = alg
	}
	switch {
	case cfg.Cache.MaxAge < 0 || cfg.Cache.MaxEntries < 0:
		return refuse("a cache bound is negative")
	case (cfg.Cache.MaxAge == 0) != (cfg.Cache.MaxEntries == 0):
		return refuse("the cache needs both a maximum age and a maximum entry count")
	case cfg.Cache.MaxAge > 0:
		c.cache = &cache{maxAge: cfg.Cache.MaxAge, maxEntries: cfg.Cache.MaxEntries,
			byKey: map[[sha256.Size]byte]*list.Element{}, order: list.New()}
	}
	if c.clock == nil {
		c.clock = clockwork.NewRealClock()
	}
	if c.logger == nil {
		c.logger = ctxlog.Routing()
	}
	return c, nil
}

// Introspect asks the endpoint about token. An inactive, foreign-issuer or
// unknown token is a Result with Active false and no error; a failure to get a
// usable answer is an error wrapping ErrUnavailable. Each Result is the
// caller's own copy.
func (c *Client) Introspect(ctx context.Context, token string) (*Result, error) {
	key := sha256.Sum256([]byte(token))
	if res, ok := c.cache.get(key, c.clock.Now()); ok {
		return res, nil
	}
	// A caller already gone must not start a call nobody will read.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	// The shared call runs detached from any one caller's cancellation, so a
	// caller that leaves does not fail the others; outbound's timeout bounds it.
	ch := c.group.DoChan(string(key[:]), func() (any, error) {
		res, err := c.call(context.WithoutCancel(ctx), token)
		if err == nil {
			c.cache.put(key, res, c.clock.Now())
		}
		return res, err
	})
	if c.joined != nil {
		c.joined()
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("introspect: %w", ctx.Err())
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(*Result).clone(), nil
	}
}

func (c *Client) call(ctx context.Context, token string) (*Result, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	var header http.Header
	if c.cfg.Key != nil {
		assertion, err := c.assertion()
		if err != nil {
			c.warn(ctx, "the client assertion could not be signed")
			return nil, fmt.Errorf("%w: the client assertion could not be signed", ErrUnavailable)
		}
		form.Set("client_id", c.cfg.ClientID)
		form.Set("client_assertion_type", assertionTypeJWT)
		form.Set("client_assertion", assertion)
	} else {
		// RFC 6749 §2.3.1: both halves are form-encoded before they are joined.
		creds := url.QueryEscape(c.cfg.ClientID) + ":" + url.QueryEscape(c.cfg.Secret)
		header = http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(creds))}}
	}

	res, err := c.fetcher.PostForm(ctxlog.With(ctx, c.cfg.Logger), c.cfg.Endpoint, form, header)
	if err != nil {
		// outbound's errors name the URL and the failure, never the form or
		// header, so the cause is kept for errors.Is.
		c.warn(ctx, "the introspection request failed", slog.String("error", err.Error()))
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if res.Status != http.StatusOK {
		c.warn(ctx, "the introspection endpoint answered an error status", slog.Int("status", res.Status))
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, res.Status)
	}
	out, reason := parse(res.Body)
	if reason != "" {
		c.warn(ctx, "the introspection answer is malformed", slog.String("reason", reason))
		return nil, fmt.Errorf("%w: malformed answer: %s", ErrUnavailable, reason)
	}
	switch {
	case !out.Active:
		return &Result{Claims: out.Claims}, nil
	case out.Issuer == "":
		out.Issuer = c.cfg.Issuer
	case out.Issuer != c.cfg.Issuer:
		c.warn(ctx, "the introspection answer names another issuer")
		return &Result{Claims: out.Claims}, nil
	}
	return out, nil
}

func (c *Client) warn(ctx context.Context, msg string, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("issuer", c.cfg.Issuer))
	c.logger.LogAttrs(ctx, slog.LevelWarn, "introspect: "+msg, attrs...)
}

func (c *Client) assertion() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := c.clock.Now()
	claims, err := jwt.NewBuilder().Issuer(c.cfg.ClientID).Subject(c.cfg.ClientID).
		Audience([]string{c.cfg.Issuer}).JwtID(base64.RawURLEncoding.EncodeToString(jti)).
		IssuedAt(now).Expiration(now.Add(assertionLifetime)).Build()
	if err != nil {
		return "", err
	}
	headers := jws.NewHeaders()
	if c.cfg.Key.KeyID != "" {
		if err := headers.Set(jws.KeyIDKey, c.cfg.Key.KeyID); err != nil {
			return "", err
		}
	}
	signed, err := jwt.Sign(claims, jwt.WithKey(c.alg, c.cfg.Key.Signer, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// parse reads an introspection answer. A non-empty reason names, in fixed
// words, why the body is not one; it never quotes the body.
func parse(body []byte) (*Result, string) {
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil || claims == nil {
		return nil, "not a JSON object"
	}
	active, ok := claims["active"].(bool)
	if !ok {
		return nil, "active is missing or not a boolean"
	}
	r := &Result{Active: active, Claims: claims}
	if !active {
		return r, ""
	}
	var reason string
	str := func(name string) string {
		v, present := claims[name]
		if !present {
			return ""
		}
		s, ok := v.(string)
		if !ok && reason == "" {
			reason = name + " is not a string"
		}
		return s
	}
	strs := func(name string, single bool) []string {
		v, present := claims[name]
		if !present {
			return nil
		}
		if s, ok := v.(string); ok && single {
			return []string{s}
		}
		arr, ok := v.([]any)
		if !ok {
			if reason == "" {
				reason = name + " is not a string array"
			}
			return nil
		}
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				if reason == "" {
					reason = name + " is not a string array"
				}
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	numericDate := func(name string) time.Time {
		v, present := claims[name]
		if !present {
			return time.Time{}
		}
		f, ok := v.(float64)
		if !ok || f <= 0 || f > math.MaxInt32*4 || math.IsNaN(f) {
			if reason == "" {
				reason = name + " is not a valid NumericDate"
			}
			return time.Time{}
		}
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(frac*1e9)).UTC()
	}

	r.TokenType = str("token_type")
	r.Issuer = str("iss")
	r.Subject = str("sub")
	r.ClientID = str("client_id")
	r.ACR = str("acr")
	if scope := str("scope"); scope != "" {
		r.Scopes = strings.Fields(scope)
	}
	r.Audience = strs("aud", true)
	r.AMR = strs("amr", false)
	r.ExpiresAt = numericDate("exp")
	r.AuthTime = numericDate("auth_time")
	if v, present := claims["cnf"]; present {
		obj, ok := v.(map[string]any)
		if !ok && reason == "" {
			reason = "cnf is not an object"
		}
		r.Confirmation = make(map[string]string, len(obj))
		for k, e := range obj {
			if s, ok := e.(string); ok {
				r.Confirmation[k] = s
			}
		}
	}
	if reason != "" {
		return nil, reason
	}
	return r, ""
}

// cache holds active answers keyed by token digest, in insertion order so the
// oldest is evicted first. A nil cache holds nothing.
type cache struct {
	mu         sync.Mutex
	maxAge     time.Duration
	maxEntries int
	byKey      map[[sha256.Size]byte]*list.Element
	order      *list.List
}

type entry struct {
	key   [sha256.Size]byte
	res   *Result
	until time.Time
}

func (c *cache) get(key [sha256.Size]byte, now time.Time) (*Result, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if !now.Before(e.until) {
		c.order.Remove(el)
		delete(c.byKey, key)
		return nil, false
	}
	return e.res.clone(), true
}

// put keeps an active answer that carries an exp, until the earlier of now
// plus the age bound and the exp. Any other answer is not kept.
func (c *cache) put(key [sha256.Size]byte, res *Result, now time.Time) {
	if c == nil || !res.Active || res.ExpiresAt.IsZero() {
		return
	}
	until := now.Add(c.maxAge)
	if res.ExpiresAt.Before(until) {
		until = res.ExpiresAt
	}
	if !now.Before(until) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[key]; ok {
		c.order.Remove(el)
		delete(c.byKey, key)
	}
	for c.order.Len() >= c.maxEntries {
		oldest := c.order.Front()
		c.order.Remove(oldest)
		delete(c.byKey, oldest.Value.(*entry).key)
	}
	c.byKey[key] = c.order.PushBack(&entry{key: key, res: res.clone(), until: until})
}
