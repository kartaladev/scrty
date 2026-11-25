package httpsec

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/introspect"
)

// optionFromIntrospection names FromIntrospection in configuration errors and as a source.
const optionFromIntrospection = "FromIntrospection"

// The names of the introspection source's own options, as configuration errors name them.
const (
	optionIntrospectionSecret = "WithIntrospectionSecret"
	optionIntrospectionKey    = "WithIntrospectionKey"
	optionIntrospectionCache  = "WithIntrospectionCache"
	optionOpaquePrefix        = "WithOpaquePrefix"
)

// WithIntrospectionSecret authenticates a FromIntrospection source to its endpoint as
// client_secret_basic with secret. Exactly one of it and WithIntrospectionKey is given; neither, or
// both, is a configuration error from New. The secret is never logged or put in an error.
func WithIntrospectionSecret(secret string) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionIntrospectionSecret)
		cfg.introspectSecret = secret

		return nil
	}
}

// WithIntrospectionKey authenticates a FromIntrospection source to its endpoint as private_key_jwt
// (RFC 7523) with key. Exactly one of it and WithIntrospectionSecret is given.
func WithIntrospectionKey(key IntrospectionKey) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionIntrospectionKey)
		cfg.introspectKey = &key

		return nil
	}
}

// WithIntrospectionCache keeps a FromIntrospection source's active answers for at most maxAge, and at
// most maxEntries of them, keyed by the SHA-256 of the token (never the token itself). An answer is
// never kept past its token's exp, and one with no exp is not kept. Concurrent requests carrying one
// token share one call whether or not the cache is on. A non-positive bound is a configuration error
// from New.
//
// Default: no cache: the endpoint is asked on every request, so a token revoked at the issuer is
// refused on the next one. With it, a revoked token may be accepted until its answer ages out.
func WithIntrospectionCache(maxAge time.Duration, maxEntries int) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionIntrospectionCache)
		cfg.cacheMaxAge, cfg.cacheMaxEntries, cfg.cacheGiven = maxAge, maxEntries, true

		return nil
	}
}

// WithOpaquePrefix has a FromIntrospection source claim only the opaque tokens that begin with
// prefix; the whole token, prefix included, is what is sent to the endpoint. A token with the prefix
// is then unmistakably this source's: off every covered path it is refused rather than handed on. An
// empty prefix is a configuration error from New, and so is, on a chain where another mode reads
// the Bearer scheme, a prefix made only of the characters session references use (A-Z, a-z, 0-9,
// "-" and "_"): a session reference or an API key could begin with it. "op." and "intro:" are
// accepted.
//
// Default: the source claims every opaque token no other source claims, and only while no other
// mode on the chain reads the Bearer scheme. On a chain with session-reference bearers
// (EnableSessionBearer), signed bearer tokens (EnableBearerToken), or API keys under the Bearer
// scheme, a source without a prefix is a configuration error from New naming both, so neither a
// session reference nor an API key is ever sent to a third party.
func WithOpaquePrefix(prefix string) SourceOption {
	return func(cfg *sourceConfig) error {
		cfg.note(optionOpaquePrefix)
		cfg.opaquePrefix, cfg.opaquePrefixGiven = prefix, true

		return nil
	}
}

// FromIntrospection trusts the opaque access tokens issuer issues, verified on every request at its
// introspection endpoint (RFC 7662), an https URL, as the client clientID. issuer is an absolute https
// URL with no userinfo, query or fragment, and is neither the resource server's identifier nor an
// alias; it keys identity links and assurance evidence, and an answer naming another issuer is
// refused.
//
// The token is posted with token_type_hint=access_token. It is accepted only when the endpoint
// reports it active, with a token_type that is absent or names an access token (a refresh token
// reported active is refused), an audience naming the resource server, an alias or the source's
// audience (WithSourceAudience), a non-empty sub and an exp in the future. The chain provider's own
// opaque tokens are never sent here, nor is a JWT or a token typed as the chain's session tokens.
//
// Default: the caller is a claims-only caller (WithClaimsOnly; WithClaimsMapper and WithLinkedUsers
// replace it). The token must be bound, by the cnf the endpoint reports, to the DPoP key or the
// certificate the request proves (WithUnboundTokens); a cnf naming no method the chain checks is
// refused. No answer is cached (WithIntrospectionCache). Every opaque token no other source claims
// is claimed (WithOpaquePrefix). Requests go through outbound.New() (WithOutboundClient).
//
// An endpoint that cannot answer is a dependency failure, answered 500, never a refusal. A refused
// token is counted against the client address's refusal budget (WithRefusalLimiter). Every mistake
// in the arguments or the options, a plain-http endpoint included, is a configuration error from New.
func FromIntrospection(issuer, endpoint, clientID string, opts ...SourceOption) ResourceServerOption {
	return func(rs *resourceServer) error {
		cfg, err := newSourceConfig(opts)
		if err != nil {
			return err
		}

		rs.sources = append(rs.sources, &introspectionSource{
			iss: issuer, endpoint: endpoint, clientID: clientID, rs: rs, cfg: cfg,
		})

		return nil
	}
}

// introspectionSource is FromIntrospection: an issuer's introspection endpoint.
type introspectionSource struct {
	iss, endpoint, clientID string

	rs  *resourceServer
	cfg *sourceConfig

	// client and now are built at New.
	client *introspect.Client
	now    func() time.Time
}

func (s *introspectionSource) name() string        { return optionFromIntrospection + "(" + s.iss + ")" }
func (s *introspectionSource) issuer() string      { return s.iss }
func (s *introspectionSource) allowsUnbound() bool { return s.cfg.unbound }

// resolvesLocalUsers says the source's caller strategy can name a local user.
func (s *introspectionSource) resolvesLocalUsers() bool { return s.cfg.strategy.resolvesLocal() }

// recognises claims an opaque token carrying the source's prefix, or, with no prefix, any opaque
// token as a fallback. The provider's own formats and JWTs are never claimed.
func (s *introspectionSource) recognises(t peeked) recognition {
	switch {
	case t.format != formatOpaque:
		return recNone
	case s.cfg.opaquePrefixGiven:
		if s.cfg.opaquePrefix != "" && strings.HasPrefix(t.raw, s.cfg.opaquePrefix) {
			return recMarked
		}

		return recNone
	default:
		return recFallback
	}
}

// checkWiring refuses an argument or an option that is a mistake, and builds the introspection
// client.
func (s *introspectionSource) checkWiring(c *config) error {
	if err := s.checkOptions(c); err != nil {
		return err
	}

	if err := checkNotOwnIssuer(c, s.rs.id, optionFromIntrospection, s.iss); err != nil {
		return err
	}

	s.now = c.clock.Now

	cfg := introspect.Config{Issuer: s.iss, Endpoint: s.endpoint, ClientID: s.clientID, Secret: s.cfg.introspectSecret}
	if k := s.cfg.introspectKey; k != nil {
		cfg.Key = &introspect.Key{Signer: k.Signer, Algorithm: k.Algorithm, KeyID: k.KeyID}
	}

	if s.cfg.cacheGiven {
		cfg.Cache = introspect.Cache{MaxAge: s.cfg.cacheMaxAge, MaxEntries: s.cfg.cacheMaxEntries}
	}

	if cw, ok := c.clock.(clockwork.Clock); ok {
		cfg.Clock = cw
	}

	fetcher, err := s.cfg.outboundClient()
	if err != nil {
		return err
	}

	client, err := introspect.New(cfg, fetcher)
	if err != nil {
		return fmt.Errorf("%w: %s (%s): %s cannot reach its endpoint as configured: %w", ErrConfig,
			optionResourceServer, s.rs.id, s.name(), err)
	}

	s.client = client

	return nil
}

// checkOptions refuses the source's arguments and options when they are a mistake.
func (s *introspectionSource) checkOptions(c *config) error {
	cfg := s.cfg

	if err := cfg.refuseOptions(s.rs.id, s.name(), optionSourceAudience, optionOutboundClient, optionUnboundTokens,
		optionIntrospectionSecret, optionIntrospectionKey, optionIntrospectionCache, optionOpaquePrefix,
		optionClaimsOnly, optionClaimsMapper, optionLocalUsers, optionLinkedUsers); err != nil {
		return err
	}

	if err := cfg.strategy.checkStrategy(s.rs.id, s.name(), true); err != nil {
		return err
	}

	if err := checkSourceIssuer(s.iss); err != nil {
		return newConfigError("%s (%s) was given the issuer %q to %s, which %s", optionResourceServer, s.rs.id,
			s.iss, optionFromIntrospection, err)
	}

	if s.iss == s.rs.id || slices.Contains(s.rs.aliases, s.iss) {
		return newConfigError("%s (%s): %s names the resource server's identifier or an alias as its issuer",
			optionResourceServer, s.rs.id, s.name())
	}

	if cfg.audienceGiven && (strings.TrimSpace(cfg.audience) == "" || cfg.audience == s.iss) {
		return newConfigError("%s (%s): %s was given %s with an empty audience or its own issuer",
			optionResourceServer, s.rs.id, s.name(), optionSourceAudience)
	}

	if (cfg.introspectSecret == "") == (cfg.introspectKey == nil) {
		return newConfigError("%s (%s): %s needs exactly one of %s and %s", optionResourceServer, s.rs.id,
			s.name(), optionIntrospectionSecret, optionIntrospectionKey)
	}

	if cfg.cacheGiven && (cfg.cacheMaxAge <= 0 || cfg.cacheMaxEntries <= 0) {
		return newConfigError("%s (%s): %s was given %s with a bound that is not positive", optionResourceServer,
			s.rs.id, s.name(), optionIntrospectionCache)
	}

	if cfg.opaquePrefixGiven && cfg.opaquePrefix == "" {
		return newConfigError("%s (%s): %s was given %s with an empty prefix", optionResourceServer, s.rs.id,
			s.name(), optionOpaquePrefix)
	}

	if cfg.opaquePrefixGiven {
		if other := bearerSchemeReader(c); other != "" && inSessionAlphabet(cfg.opaquePrefix) {
			return newConfigError("%s (%s): %s was given %s %q made only of the characters session references "+
				"use (A-Z, a-z, 0-9, \"-\", \"_\"), and %s also reads the Bearer scheme, so a session reference "+
				"or an API key could begin with it and be sent to the introspection endpoint; give a prefix with "+
				"a character outside that alphabet, such as \".\" or \":\"", optionResourceServer, s.rs.id,
				s.name(), optionOpaquePrefix, cfg.opaquePrefix, other)
		}
	}

	if !cfg.opaquePrefixGiven {
		if other := bearerSchemeReader(c); other != "" {
			return newConfigError("%s (%s): %s has no %s, and %s also reads the Bearer scheme, so its "+
				"credentials would be sent to the introspection endpoint; give the source a prefix",
				optionResourceServer, s.rs.id, s.name(), optionOpaquePrefix, other)
		}

		for _, o := range s.rs.sources {
			if o, ok := o.(*introspectionSource); ok && o != s && !o.cfg.opaquePrefixGiven {
				return newConfigError("%s (%s): %s and %s both claim every opaque token; give each a %s",
					optionResourceServer, s.rs.id, s.name(), o.name(), optionOpaquePrefix)
			}
		}
	}

	return nil
}

// sessionAlphabet is the alphabet session references are written in: URL-safe base64 without
// padding.
const sessionAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// inSessionAlphabet reports whether every character of prefix belongs to sessionAlphabet, so that a
// session reference could begin with it.
func inSessionAlphabet(prefix string) bool {
	for _, r := range prefix {
		if !strings.ContainsRune(sessionAlphabet, r) {
			return false
		}
	}

	return true
}

// isBearerScheme reports whether scheme is the Bearer scheme, compared trimmed and without regard
// to case, the same way for every mode that reads it.
func isBearerScheme(scheme string) bool {
	return strings.EqualFold(strings.TrimSpace(scheme), strings.TrimSpace(DefaultBearerScheme))
}

// bearerSchemeReader names a credential mode on the chain, other than a resource server, that reads
// the Bearer scheme, and "" when there is none.
func bearerSchemeReader(c *config) string {
	var found string

	_ = eachInterceptor(c, func(b *sessionBearer) error {
		if found == "" && isBearerScheme(b.scheme) {
			found = "EnableSessionBearer"
		}

		return nil
	})
	_ = eachInterceptor(c, func(b *bearerToken) error {
		if found == "" && isBearerScheme(b.scheme) {
			found = "EnableBearerToken"
		}

		return nil
	})
	_ = eachInterceptor(c, func(i *apiKeyInterceptor) error {
		if found == "" && isBearerScheme(i.scheme) {
			found = "EnableAPIKey (WithAPIKeyScheme)"
		}

		return nil
	})

	return found
}

// verify asks the endpoint about raw and holds the answer to the resource. A refusal is
// ErrInvalidToken; an endpoint that cannot answer, a caller strategy's port that failed, or the
// request's own end, is returned as the failure it is. The binding the answer reports is returned as
// the token's confirmation, which the resource server holds the request's proof to before accepting
// (introspect.Result.Accepts does not).
func (s *introspectionSource) verify(ctx context.Context, raw string) (*verifiedToken, error) {
	res, err := s.client.Introspect(ctx, raw)

	switch {
	case err != nil && hangup.ByCaller(ctx, err):
		return nil, dependencyOf(err, textIntrospectionCallEnded, ctx.Err())
	case err != nil:
		return nil, dependencyOf(err, textIntrospectionUnusable)
	case res == nil || !s.accepts(res):
		return nil, ErrInvalidToken
	}

	// The binding is read from the whole cnf: one naming only a method the chain cannot check (a
	// jwk, say) is refused, never taken for an unbound token.
	confirmation, ok := confirmationOf(res.Claims)
	if !ok {
		return nil, ErrInvalidToken
	}

	tok := &AccessToken{
		Issuer:       s.iss,
		Subject:      res.Subject,
		ClientID:     res.ClientID,
		Audience:     slices.Clone(res.Audience),
		Scopes:       slices.Clone(res.Scopes),
		ExpiresAt:    res.ExpiresAt,
		AuthTime:     res.AuthTime,
		ACR:          res.ACR,
		AMR:          slices.Clone(res.AMR),
		Confirmation: confirmation,
		Claims:       maps.Clone(res.Claims),
	}

	vt := &verifiedToken{confirmation: confirmation, kind: factor.ExternalAccessToken, token: tok}

	if err := s.cfg.strategy.resolveExternal(ctx, s.iss, tok, s.now(), vt); err != nil {
		return nil, err
	}

	return vt, nil
}

// accepts says the answer accepts the token for the resource server's identifier, an alias, or the
// source's audience.
func (s *introspectionSource) accepts(res *introspect.Result) bool {
	now := s.now()

	candidates := append([]string{s.rs.id}, s.rs.aliases...)
	if s.cfg.audienceGiven {
		candidates = append(candidates, s.cfg.audience)
	}

	for _, resource := range candidates {
		if res.Accepts(resource, now) {
			return true
		}
	}

	return false
}
