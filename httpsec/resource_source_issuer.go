package httpsec

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/introspect"
	"github.com/kartaladev/scrty/internal/keyset"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/token"
)

// optionFromIssuer names FromIssuer in configuration errors and as a source.
const optionFromIssuer = "FromIssuer"

// The names of the source options, as configuration errors name them.
const (
	optionSourceAudience   = "WithSourceAudience"
	optionJWKSURL          = "WithJWKSURL"
	optionOutboundClient   = "WithOutboundClient"
	optionAlgorithms       = "WithAlgorithms"
	optionClockSkew        = "WithClockSkew"
	optionUnboundTokens    = "WithUnboundTokens"
	optionUntypedTokens    = "WithUntypedTokens"
	optionJWTIntrospection = "WithJWTIntrospection"
)

// Bounds and defaults of a remote issuer's verification.
const (
	// maxClockSkew is the most WithClockSkew allows.
	maxClockSkew = 5 * time.Minute

	// issuedAtLeeway is how far ahead of now a token's iat and nbf may be, whatever the source's
	// skew, so a token used the moment it is issued survives an issuer clock slightly ahead.
	issuedAtLeeway = 60 * time.Second
)

// defaultIssuerAlgorithms are the algorithms a remote issuer's tokens may be signed with when the
// source is given no WithAlgorithms.
var defaultIssuerAlgorithms = []string{"RS256", "ES256"}

// The fixed texts a remote-issuer source answers a failure that is not a refusal with. A hang-up has
// texts of its own, so an error handler that logs by text does not report a client that left as an
// outage.
const (
	textIssuerKeysUnavailable  = "httpsec: the access token issuer's keys could not be fetched"           //nolint:gosec // G101: error text, not a credential
	textIssuerKeysEnded        = "httpsec: the request ended while the access token issuer's keys loaded" //nolint:gosec // G101: error text, not a credential
	textIntrospectionUnusable  = "httpsec: the access token could not be introspected"                    //nolint:gosec // G101: error text, not a credential
	textIntrospectionCallEnded = "httpsec: the request ended while the access token was introspected"     //nolint:gosec // G101: error text, not a credential
)

// sourceConfig is what a source's options set. Every field's zero value is the source's default.
type sourceConfig struct {
	// given names each option given, in order, so a source refuses one it does not take.
	given []string

	audience      string
	audienceGiven bool

	jwksURL string

	fetcher *outbound.Client

	algorithms      []string
	algorithmsGiven bool

	skew time.Duration

	unbound bool

	untypedClaim, untypedValue string
	untypedGiven               bool

	introspection *IntrospectionConfig

	// strategy is the caller strategy (resource_strategy.go).
	strategy strategyConfig

	// The introspection source's own settings (resource_source_introspect.go).
	introspectSecret  string
	introspectKey     *IntrospectionKey
	cacheMaxAge       time.Duration
	cacheMaxEntries   int
	cacheGiven        bool
	opaquePrefix      string
	opaquePrefixGiven bool
}

// newSourceConfig applies opts, skipping nil ones.
func newSourceConfig(opts []SourceOption) (*sourceConfig, error) {
	cfg := &sourceConfig{}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// refuseOptions is a configuration error naming the first option given to the source called name
// that is not among taken, and nil when every one is.
func (cfg *sourceConfig) refuseOptions(rsID, name string, taken ...string) error {
	for _, given := range cfg.given {
		if !slices.Contains(taken, given) {
			return newConfigError("%s (%s): %s does not take %s", optionResourceServer, rsID, name, given)
		}
	}

	return nil
}

// note records that option was given.
func (cfg *sourceConfig) note(option string) { cfg.given = append(cfg.given, option) }

// WithSourceAudience accepts this source's tokens whose audience names audience, beside the
// resource server's identifier and aliases. It applies to this source alone, may be any non-empty
// text other than the source's issuer, and is how an issuer that names the API in its own spelling
// is trusted.
//
// Default: a token's audience must name the resource server's identifier or one of its aliases.
func WithSourceAudience(audience string) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionSourceAudience)
		cfg.audience, cfg.audienceGiven = audience, true

		return nil
	}
}

// WithJWKSURL pins the URL of the issuer's key set, an https URL that may be on another origin than
// the issuer, so that no metadata is read.
//
// Default: the key set is found from the issuer's metadata (OpenID Connect Discovery, then RFC 8414
// on a 404 only), which must name the issuer, and must put the key set on the issuer's own origin.
func WithJWKSURL(rawURL string) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionJWKSURL)
		cfg.jwksURL = rawURL

		return nil
	}
}

// WithOutboundClient sends every metadata, key-set and introspection request of the source through
// client, for a proxy or a custom certificate authority.
//
// Default: outbound.New() with its defaults: https only, redirects kept on the origin, bounded time
// and size. A nil client keeps the default.
func WithOutboundClient(client *outbound.Client) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionOutboundClient)
		cfg.fetcher = client

		return nil
	}
}

// WithAlgorithms replaces the algorithms the source's tokens may be signed with. Each is an
// asymmetric JWS algorithm (RS*, PS*, ES*, EdDSA); none, the HS* family and an empty list are
// configuration errors from New.
//
// Default: RS256 and ES256.
func WithAlgorithms(algorithms ...string) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionAlgorithms)
		cfg.algorithms, cfg.algorithmsGiven = slices.Clone(algorithms), true

		return nil
	}
}

// WithClockSkew allows the issuer's clock and the chain's to disagree by up to skew when a token's
// expiry, issue time and not-before time are judged. It is at most five minutes; a negative or
// larger skew is a configuration error from New. A token's iat and nbf may in any case be up to 60
// seconds ahead.
//
// Default: 0, as an access token is judged on every request.
func WithClockSkew(skew time.Duration) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionClockSkew)
		cfg.skew = skew

		return nil
	}
}

// WithUnboundTokens accepts this source's tokens that are bound to no key or certificate. A token
// that is bound is still held to its binding, and one whose confirmation names only a method the
// chain cannot check is still refused. It is a configuration error from New on a chain whose DPoP is
// required.
//
// Default: a token bound to no key or certificate is refused.
func WithUnboundTokens() SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionUnboundTokens)
		cfg.unbound = true

		return nil
	}
}

// WithUntypedTokens accepts this source's tokens typed JWT, or not typed at all, when their claim
// named claim holds the string value, so that the issuer's ID tokens, which do not, stay refused.
// Such a token may name its client in azp when it has no client_id. A blank claim or value is a
// configuration error from New, as is a chain session generator declaring the type JWT.
//
// Default: only tokens typed at+jwt (RFC 9068) are accepted.
func WithUntypedTokens(claim, value string) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionUntypedTokens)
		cfg.untypedClaim, cfg.untypedValue, cfg.untypedGiven = claim, value, true

		return nil
	}
}

// IntrospectionConfig is how a source reaches its issuer's introspection endpoint (RFC 7662).
type IntrospectionConfig struct {
	// Endpoint is the introspection endpoint, an https URL. Required.
	Endpoint string

	// ClientID is the resource server's client identifier at the issuer. Required.
	ClientID string

	// Secret authenticates the client as client_secret_basic. Exactly one of Secret and Key is set.
	Secret string

	// Key authenticates the client as private_key_jwt. Exactly one of Secret and Key is set.
	Key *IntrospectionKey
}

// IntrospectionKey is the private key of private_key_jwt client authentication (RFC 7523).
type IntrospectionKey struct {
	// Signer signs the client assertion. Required.
	Signer crypto.Signer

	// Algorithm is the assertion's JWS algorithm, an asymmetric one. Required.
	Algorithm string

	// KeyID is put in the assertion's kid header when not empty.
	KeyID string
}

// WithJWTIntrospection has the source introspect every JWT it verifies at cfg's endpoint, and refuse
// one the endpoint reports inactive, so a token the issuer revokes is refused before it expires. An
// endpoint that cannot answer is a dependency failure, never a refusal. The answer must come from the
// source's issuer. A configuration the introspection client refuses is a configuration error from
// New.
//
// Default: a verified JWT is accepted until it expires (RFC 9068), whatever happens at its issuer
// meanwhile.
func WithJWTIntrospection(cfg IntrospectionConfig) SourceOption {
	return func(c *sourceConfig) error {
		c.note(optionJWTIntrospection)
		c.introspection = &cfg

		return nil
	}
}

// FromIssuer trusts the JWT access tokens a remote issuer signs, verified against the key set it
// publishes. issuer is an absolute https URL with no userinfo, query or fragment, and is neither the
// resource server's identifier nor an alias.
//
// A token is accepted only when it is a compact JWS signed with one of the source's algorithms by a
// key of the issuer's set (a token with no kid only when the set holds exactly one signing key);
// header jku, jwk and x5u are ignored. It must be typed at+jwt, carry the issuer as iss, an audience
// naming the resource server, an alias or the source's audience, a non-empty sub, client_id, iat and
// exp, and, typed at+jwt, a jti. The key set is cached, and an unknown key id refetches it at most
// once per cooldown.
//
// Default: the caller is a claims-only caller, the user kind, whose identifier is the issuer and the
// subject joined by "#" (never a local user's identifier), carrying the token's scopes and no role.
//
// Default: the token must be bound to a DPoP key or a certificate, as every source's must
// (WithUnboundTokens). A token is valid until it expires (WithJWTIntrospection). The key set is
// found from the issuer's metadata (WithJWKSURL), through outbound.New() (WithOutboundClient).
//
// A key set or introspection endpoint that cannot be reached is a dependency failure, answered 500,
// never a refusal. Every mistake in the issuer or the options is a configuration error from New.
func FromIssuer(issuer string, opts ...SourceOption) ResourceServerOption {
	return func(rs *resourceServer) error {
		cfg, err := newSourceConfig(opts)
		if err != nil {
			return err
		}

		rs.sources = append(rs.sources, &issuerSource{iss: issuer, rs: rs, cfg: cfg})

		return nil
	}
}

// issuerSource is FromIssuer: a remote issuer of JWT access tokens.
type issuerSource struct {
	iss string
	rs  *resourceServer
	cfg *sourceConfig

	// algorithms are the source's, settled at New.
	algorithms []string

	// keys serves the issuer's key set; introspector is nil without WithJWTIntrospection; now is the
	// chain's clock. All three are built at New.
	keys         *keyset.Source
	introspector *introspect.Client
	now          func() time.Time
}

func (s *issuerSource) name() string        { return optionFromIssuer + "(" + s.iss + ")" }
func (s *issuerSource) issuer() string      { return s.iss }
func (s *issuerSource) allowsUnbound() bool { return s.cfg.unbound }

// resolvesLocalUsers says the source's caller strategy can name a local user.
func (s *issuerSource) resolvesLocalUsers() bool { return s.cfg.strategy.resolvesLocal() }

// recognises claims a JWT naming the source's issuer.
func (s *issuerSource) recognises(t peeked) recognition {
	if t.format == formatJWT && t.iss == s.iss {
		return recMarked
	}

	return recNone
}

// acceptsUntyped says the source opted in to tokens typed JWT.
func (s *issuerSource) acceptsUntyped() bool { return s.cfg.untypedGiven }

// checkWiring refuses an issuer or an option that is a mistake, and builds the key set and the
// introspection client.
func (s *issuerSource) checkWiring(c *config) error {
	if err := s.checkOptions(); err != nil {
		return err
	}

	if err := checkNotOwnIssuer(c, s.rs.id, optionFromIssuer, s.iss); err != nil {
		return err
	}

	s.now = c.clock.Now

	keyOpts := []keyset.Option{keyset.WithIssuer(s.iss), keyset.WithClock(c.clock)}
	if s.cfg.jwksURL != "" {
		keyOpts = append(keyOpts, keyset.WithJWKSURL(s.cfg.jwksURL))
	}

	keys, err := keyset.New(s.name(), s.cfg.fetcher, keyOpts...)
	if err != nil {
		return fmt.Errorf("%w: %s (%s): %s could not configure its key set: %w", ErrConfig,
			optionResourceServer, s.rs.id, s.name(), err)
	}

	s.keys = keys

	if ic := s.cfg.introspection; ic != nil {
		cfg := introspect.Config{Issuer: s.iss, Endpoint: ic.Endpoint, ClientID: ic.ClientID, Secret: ic.Secret}
		if ic.Key != nil {
			cfg.Key = &introspect.Key{Signer: ic.Key.Signer, Algorithm: ic.Key.Algorithm, KeyID: ic.Key.KeyID}
		}

		fetcher, err := s.cfg.outboundClient()
		if err != nil {
			return err
		}

		client, err := introspect.New(cfg, fetcher)
		if err != nil {
			return fmt.Errorf("%w: %s (%s): %s was given %s it cannot use: %w", ErrConfig,
				optionResourceServer, s.rs.id, s.name(), optionJWTIntrospection, err)
		}

		s.introspector = client
	}

	return nil
}

// checkOptions refuses the source's issuer and options when they are a mistake, and settles its
// algorithms.
func (s *issuerSource) checkOptions() error {
	if err := s.cfg.refuseOptions(s.rs.id, s.name(), optionSourceAudience, optionJWKSURL, optionOutboundClient,
		optionAlgorithms, optionClockSkew, optionUnboundTokens, optionUntypedTokens, optionJWTIntrospection,
		optionClaimsOnly, optionClaimsMapper, optionLocalUsers, optionLinkedUsers); err != nil {
		return err
	}

	if err := s.cfg.strategy.checkStrategy(s.rs.id, s.name(), true); err != nil {
		return err
	}

	if err := checkSourceIssuer(s.iss); err != nil {
		return newConfigError("%s (%s) was given the issuer %q to %s, which %s", optionResourceServer, s.rs.id,
			s.iss, optionFromIssuer, err)
	}

	if s.iss == s.rs.id || slices.Contains(s.rs.aliases, s.iss) {
		return newConfigError("%s (%s): %s names the resource server's identifier or an alias as its issuer",
			optionResourceServer, s.rs.id, s.name())
	}

	cfg := s.cfg

	if cfg.audienceGiven && (strings.TrimSpace(cfg.audience) == "" || cfg.audience == s.iss) {
		return newConfigError("%s (%s): %s was given %s with an empty audience or its own issuer; a token "+
			"whose audience is only its issuer is not meant for an API", optionResourceServer, s.rs.id, s.name(),
			optionSourceAudience)
	}

	if cfg.skew < 0 || cfg.skew > maxClockSkew {
		return newConfigError("%s (%s): %s was given %s of %s, outside 0 to %s", optionResourceServer, s.rs.id,
			s.name(), optionClockSkew, cfg.skew, maxClockSkew)
	}

	s.algorithms = defaultIssuerAlgorithms

	if cfg.algorithmsGiven {
		if len(cfg.algorithms) == 0 {
			return newConfigError("%s (%s): %s was given %s with no algorithm", optionResourceServer, s.rs.id,
				s.name(), optionAlgorithms)
		}

		for _, alg := range cfg.algorithms {
			if !asymmetricAlgorithms[alg] {
				return newConfigError("%s (%s): %s was given %s with %q, which is not an asymmetric signature "+
					"algorithm; none and the HS* family are never accepted", optionResourceServer, s.rs.id,
					s.name(), optionAlgorithms, alg)
			}
		}

		s.algorithms = cfg.algorithms
	}

	if cfg.untypedGiven && (strings.TrimSpace(cfg.untypedClaim) == "" || cfg.untypedValue == "") {
		return newConfigError("%s (%s): %s was given %s without a claim and the value it must hold, which "+
			"would accept the issuer's ID tokens", optionResourceServer, s.rs.id, s.name(), optionUntypedTokens)
	}

	return nil
}

// checkSourceIssuer says why iss is not a source's issuer, and nil when it is: an absolute https URL
// with a host and no userinfo, query or fragment (RFC 8414 section 2), so that "<issuer>#<sub>" names
// one caller.
func checkSourceIssuer(iss string) error {
	u, err := url.Parse(iss)

	switch {
	case err != nil || !u.IsAbs() || u.Host == "":
		return errors.New("is not an absolute URL")
	case u.Scheme != "https":
		return errors.New("is not an https URL")
	case u.User != nil:
		return errors.New("carries userinfo")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(iss, "#"):
		return errors.New("carries a query or a fragment")
	default:
		return nil
	}
}

// verify verifies raw against the issuer's key set and the profile's claims. A refusal is
// ErrInvalidToken; a key set or introspection endpoint that failed, or the request's own end, is
// returned as the failure it is.
func (s *issuerSource) verify(ctx context.Context, raw string) (*verifiedToken, error) {
	alg, kid, typ, ok := s.readHeader(raw)
	if !ok {
		return nil, ErrInvalidToken
	}

	key, err := s.keys.Key(ctx, kid)

	switch {
	case errors.Is(err, keyset.ErrUnknownKey):
		return nil, ErrInvalidToken
	case err != nil && hangup.ByCaller(ctx, err):
		return nil, dependencyOf(err, textIssuerKeysEnded, ctx.Err())
	case err != nil:
		return nil, dependencyOf(err, textIssuerKeysUnavailable)
	}

	// A key that names its own algorithm is used with that algorithm alone (RFC 8725 section 3.1).
	if named, found := key.Algorithm(); found && named.String() != alg.String() {
		return nil, ErrInvalidToken
	}

	payload, err := jws.Verify([]byte(raw), jws.WithKey(alg, key))
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := decodeClaims(payload)
	if !ok {
		return nil, ErrInvalidToken
	}

	tok, ok := s.readClaims(claims, typ)
	if !ok {
		return nil, ErrInvalidToken
	}

	if err := s.introspect(ctx, raw); err != nil {
		return nil, err
	}

	vt := &verifiedToken{
		confirmation: tok.Confirmation,
		kind:         factor.ExternalAccessToken,
		token:        tok,
	}

	if err := s.cfg.strategy.resolveExternal(ctx, s.iss, tok, s.now(), vt); err != nil {
		return nil, err
	}

	return vt, nil
}

// readHeader reads raw's protected header: an algorithm among the source's, the key id (empty when
// absent) and the type, lower-cased without "application/". ok is false for a token that is not one
// compact JWS with one signature, or whose algorithm the source does not take. jku, jwk and x5u are
// never read.
func (s *issuerSource) readHeader(raw string) (alg jwa.SignatureAlgorithm, kid, typ string, ok bool) {
	if strings.Count(raw, ".") != 2 {
		return alg, "", "", false
	}

	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) != 1 {
		return alg, "", "", false
	}

	hdr := msg.Signatures()[0].ProtectedHeaders()

	named, found := hdr.Algorithm()
	if !found || !slices.Contains(s.algorithms, named.String()) {
		return alg, "", "", false
	}

	alg, found = jwa.LookupSignatureAlgorithm(named.String())
	if !found {
		return alg, "", "", false
	}

	kid, _ = hdr.KeyID()

	if t, found := hdr.Type(); found {
		typ = strings.TrimPrefix(asciiLower(t), "application/")
	}

	return alg, kid, typ, true
}

// decodeClaims decodes a verified payload as a JSON object, keeping numbers exact.
func decodeClaims(payload []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()

	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil || dec.More() {
		return nil, false
	}

	return claims, true
}

// readClaims holds claims, of a token declaring typ, to the profile, and returns what the token
// states. ok is false for a token the source refuses.
func (s *issuerSource) readClaims(claims map[string]any, typ string) (*AccessToken, bool) {
	typed := typ == token.TypeAccessToken

	switch {
	case typed:
	case s.acceptsUntyped() && (typ == "" || typ == "jwt"):
		if v, ok := claims[s.cfg.untypedClaim].(string); !ok || v != s.cfg.untypedValue {
			return nil, false
		}
	default:
		return nil, false
	}

	tok := &AccessToken{Claims: claims}

	var ok bool

	if tok.Issuer, ok = claims["iss"].(string); !ok || tok.Issuer != s.iss {
		return nil, false
	}

	if tok.Subject, ok = claims["sub"].(string); !ok || tok.Subject == "" {
		return nil, false
	}

	if tok.ClientID, ok = s.client(claims, typed); !ok {
		return nil, false
	}

	if typed {
		if jti, isString := claims["jti"].(string); !isString || jti == "" {
			return nil, false
		}
	}

	if tok.Audience, ok = stringsClaim(claims["aud"], false); !ok || !s.audienceNamed(tok.Audience) {
		return nil, false
	}

	if tok.Scopes, ok = scopesOf(claims); !ok {
		return nil, false
	}

	if !s.timesHold(claims, tok) {
		return nil, false
	}

	if tok.Confirmation, ok = confirmationOf(claims); !ok {
		return nil, false
	}

	tok.ACR, _ = claims["acr"].(string)

	if amr, present := claims["amr"]; present {
		if tok.AMR, ok = stringsClaim(amr, false); !ok {
			return nil, false
		}
	}

	return tok, true
}

// client is the token's client: client_id, or, for a source that accepts untyped tokens and a token
// that is not typed at+jwt (RFC 9068 requires client_id), azp when client_id is absent.
func (s *issuerSource) client(claims map[string]any, typed bool) (string, bool) {
	if v, present := claims["client_id"]; present {
		id, ok := v.(string)

		return id, ok && id != ""
	}

	if typed || !s.acceptsUntyped() {
		return "", false
	}

	id, ok := claims["azp"].(string)

	return id, ok && id != ""
}

// audienceNamed says audience names the resource server, an alias, or the source's own audience.
func (s *issuerSource) audienceNamed(audience []string) bool {
	return s.rs.audienceNamed(audience) || s.cfg.audienceGiven && slices.Contains(audience, s.cfg.audience)
}

// timesHold reads exp, iat and nbf into tok and says they hold at now: exp later than now less the
// skew; iat and nbf no later than now plus the larger of the skew and issuedAtLeeway.
func (s *issuerSource) timesHold(claims map[string]any, tok *AccessToken) bool {
	now := s.now()
	ahead := now.Add(max(s.cfg.skew, issuedAtLeeway))

	exp, ok := numericDate(claims["exp"])
	if !ok || !now.Before(exp.Add(s.cfg.skew)) {
		return false
	}

	iat, ok := numericDate(claims["iat"])
	if !ok || iat.After(ahead) {
		return false
	}

	if v, present := claims["nbf"]; present {
		nbf, ok := numericDate(v)
		if !ok || nbf.After(ahead) {
			return false
		}
	}

	if v, present := claims["auth_time"]; present {
		authTime, ok := numericDate(v)
		if !ok {
			return false
		}

		tok.AuthTime = authTime
	}

	tok.IssuedAt, tok.ExpiresAt = iat, exp

	return true
}

// introspect asks the issuer's introspection endpoint about raw when the source introspects. An
// inactive answer is ErrInvalidToken; an endpoint that cannot answer is a dependency failure.
func (s *issuerSource) introspect(ctx context.Context, raw string) error {
	if s.introspector == nil {
		return nil
	}

	res, err := s.introspector.Introspect(ctx, raw)

	switch {
	case err != nil && hangup.ByCaller(ctx, err):
		return dependencyOf(err, textIntrospectionCallEnded, ctx.Err())
	case err != nil:
		return dependencyOf(err, textIntrospectionUnusable)
	case res == nil || !res.Active:
		return ErrInvalidToken
	default:
		return nil
	}
}

// numericDate reads a JSON NumericDate, whole or fractional seconds. A negative one is refused.
func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}

	if i, err := n.Int64(); err == nil {
		if i < 0 {
			return time.Time{}, false
		}

		return time.Unix(i, 0), true
	}

	f, err := n.Float64()
	if err != nil || f < 0 || f > 1<<40 {
		return time.Time{}, false
	}

	return time.Unix(0, int64(f*float64(time.Second))), true
}

// stringsClaim reads a claim that is a string or an array of strings; split splits a string on
// spaces. An empty result, or any other shape, is not ok.
func stringsClaim(v any, split bool) ([]string, bool) {
	switch x := v.(type) {
	case string:
		if split {
			out := strings.Fields(x)

			return out, len(out) > 0
		}

		return []string{x}, x != ""
	case []any:
		out := make([]string, 0, len(x))

		for _, e := range x {
			str, ok := e.(string)
			if !ok {
				return nil, false
			}

			out = append(out, str)
		}

		return out, len(out) > 0
	default:
		return nil, false
	}
}

// scopesOf reads the token's scopes from scope, a space-separated string, or, when scope is absent,
// from scp, a string or an array of strings. A token stating neither has no scope; one stating
// either in another shape is not ok.
func scopesOf(claims map[string]any) ([]string, bool) {
	if v, present := claims["scope"]; present {
		str, ok := v.(string)
		if !ok {
			return nil, false
		}

		return strings.Fields(str), true
	}

	if v, present := claims["scp"]; present {
		return stringsClaim(v, true)
	}

	return nil, true
}

// confirmationOf reads the token's cnf: its jkt and x5t#S256 members. A token with no cnf is
// unbound. A cnf that is not an object, or names neither method the chain checks, is not ok: it is
// never taken for an unbound token.
func confirmationOf(claims map[string]any) (map[string]string, bool) {
	v, present := claims["cnf"]
	if !present {
		return nil, true
	}

	cnf, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}

	out := map[string]string{}

	for _, member := range []string{oidcConfirmationJKT, oidcConfirmationX5T} {
		if m, present := cnf[member]; present {
			str, ok := m.(string)
			if !ok || str == "" {
				return nil, false
			}

			out[member] = str
		}
	}

	return out, len(out) > 0
}

// outboundClient is the source's outbound client: WithOutboundClient's, or else outbound.New() with
// its defaults.
func (cfg *sourceConfig) outboundClient() (*outbound.Client, error) {
	if cfg.fetcher != nil {
		return cfg.fetcher, nil
	}

	client, err := outbound.New()
	if err != nil {
		return nil, fmt.Errorf("%w: the default outbound client could not be built: %w", ErrConfig, err)
	}

	return client, nil
}
