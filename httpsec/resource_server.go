package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/token"
)

// optionResourceServer names EnableResourceServer in configuration errors.
const optionResourceServer = "EnableResourceServer"

// source is one issuer of access tokens a resource server trusts: the chain's own provider, a
// remote issuer, or an introspection endpoint. The set is closed: no consumer implements it.
type source interface {
	// name names the source in configuration errors and logs; it is never a secret.
	name() string

	// issuer is the issuer the source answers for, and "" for a source that names none. Two sources
	// of one resource server may not answer for one issuer.
	issuer() string

	// allowsUnbound says the source accepts a token bound to no key or certificate.
	allowsUnbound() bool

	// recognises says how strongly the source claims a token from its unverified read.
	recognises(t peeked) recognition

	// verify verifies raw and returns what it states. A refusal wraps ErrInvalidToken; any
	// other error is a dependency failure or the request's own context ending.
	verify(ctx context.Context, raw string) (*verifiedToken, error)
}

// recognition is how strongly a source claims a token.
type recognition int

const (
	// recNone is a token the source does not claim.
	recNone recognition = iota

	// recFallback is a token the source would take for want of any mark: an opaque token an
	// introspection source with no prefix accepts. It never refuses a token off every prefix.
	recFallback

	// recMarked is a token carrying a mark naming the source: the provider's own format, an issuer
	// the source answers for, or an introspection prefix.
	recMarked
)

// verifiedToken is what a source verified of an access token.
type verifiedToken struct {
	// principal is the caller the token names.
	principal *identity.Principal

	// confirmation is the token's cnf: the key or certificate it is bound to, and empty for an
	// unbound token.
	confirmation map[string]string

	// kind is the first-factor kind the caller is published with: factor.AccessToken for the chain
	// provider's own tokens, factor.ExternalAccessToken for every other source's.
	kind factor.Kind

	// external says the principal is not a local user. Its zero value means a local user, so a
	// source that records nothing is judged by the MFA requirement (it fails closed). secondFactor
	// is the provider grant's library-recorded marker; evidence is the federated evidence the
	// caller is judged by, from the grant or from the external token. All three feed
	// policy.Input's assurance.
	external     bool
	secondFactor bool
	evidence     assurance.Federated

	// token is what the token states, published for the request's handlers. Its scopes are the
	// caller's, whatever the principal carries.
	token *AccessToken
}

// ResourceServerOption configures a resource server, or adds a token source to it.
type ResourceServerOption func(*resourceServer) error

// resourceServer is one resource server: an identifier, the paths it covers and the sources it
// trusts.
type resourceServer struct {
	id       string
	aliases  []string
	prefixes []string
	sources  []source

	// prefixGiven records that WithPathPrefix was given, so one given no prefix is refused rather
	// than read as covering every path.
	prefixGiven bool

	// limiter counts the resource server's verification refusals (WithRefusalLimiter), and is nil
	// for the chain factory's; limiterGiven records that the option was given.
	limiter      ratelimit.Limiter
	limiterGiven bool
}

// EnableResourceServer accepts OAuth access tokens for the API identified by resourceID, at
// OrderResourceServer.
//
// resourceID, and each alias WithResourceAliases adds, is an absolute URI with no fragment, and is
// not the chain provider's issuer: a token whose audience is only the issuer is meant for UserInfo.
// Every source the options add verifies the tokens it recognises, and a token is accepted only
// when one does.
//
// Default: the resource server covers every path, and is then allowed only as the chain's one
// resource server. WithPathPrefix confines it to the paths under its prefixes, so that several
// resource servers, each trusting its own sources, can serve one chain; their prefixes may not
// overlap. A token is judged by the resource server covering the request's path first, then by the
// source it belongs to there.
//
// Default: every source requires a token bound to a key or a certificate, so the chain must enable
// DPoP or certificate binding; the resource server counts as a feature that verifies bound
// credentials for both.
//
// A token the resource server recognises and refuses is never handed to a later credential mode.
// A token it does not recognise passes on, so the chain's session tokens, session references and
// API keys reach their own modes. A session token typed as the chain's signed bearer declares is
// never offered to a source.
//
// Every mistake above, and a resource server with no source or a nil one, is a configuration
// error from New.
func EnableResourceServer(resourceID string, opts ...ResourceServerOption) Option {
	return func(c *config) error {
		rs := &resourceServer{id: resourceID}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(rs); err != nil {
				return err
			}
		}

		set := resourceServersOf(c)
		set.modes = append(set.modes, rs)

		c.enable(optionResourceServer, func() error {
			if err := rs.check(c); err != nil {
				return err
			}

			// Checked once per chain, by the first resource server: every one is added by then.
			if set.modes[0] != rs {
				return nil
			}

			return set.check()
		})

		return nil
	}
}

// check refuses a resource server whose own settings are a mistake.
func (rs *resourceServer) check(c *config) error {
	if !validResourceIdentifier(rs.id) {
		return newConfigError("%s was given the identifier %q, which is not an absolute URI with no fragment",
			optionResourceServer, rs.id)
	}

	seen := map[string]bool{rs.id: true}

	for _, alias := range rs.aliases {
		if !validResourceIdentifier(alias) {
			return newConfigError("%s (%s) was given the alias %q, which is not an absolute URI with no fragment",
				optionResourceServer, rs.id, alias)
		}

		if seen[alias] {
			return newConfigError("%s (%s) was given %q twice, as its identifier or an alias",
				optionResourceServer, rs.id, alias)
		}

		seen[alias] = true
	}

	if c.oidcProvider != nil && c.oidcProvider.provider != nil {
		if iss := c.oidcProvider.provider.Issuer(); seen[iss] {
			return newConfigError("%s names the provider's issuer %q as its identifier or an alias; a token "+
				"whose audience is the issuer is meant for UserInfo, so give the API an identifier of its own",
				optionResourceServer, iss)
		}
	}

	if rs.prefixGiven && len(rs.prefixes) == 0 {
		return newConfigError("%s (%s) was given WithPathPrefix with no prefix; leave the option out to "+
			"cover every path", optionResourceServer, rs.id)
	}

	for _, prefix := range rs.prefixes {
		if err := checkPathPrefix(prefix); err != nil {
			return newConfigError("%s (%s) was given the prefix %q, which %s", optionResourceServer, rs.id, prefix, err)
		}
	}

	rs.prefixes = distinctPrefixes(rs.prefixes)

	if err := rs.checkLimiter(); err != nil {
		return err
	}

	return rs.checkSources(c)
}

// checkSources refuses a resource server with no source, a nil one, two answering for one issuer,
// or a binding nothing on the chain can check.
func (rs *resourceServer) checkSources(c *config) error {
	if len(rs.sources) == 0 {
		return newConfigError("%s (%s) was given no token source; add FromProvider, FromIssuer or "+
			"FromIntrospection", optionResourceServer, rs.id)
	}

	issuers := make(map[string]string, len(rs.sources))

	for _, src := range rs.sources {
		if nilcheck.IsNil(src) {
			return newConfigError("%s (%s) was given a nil token source", optionResourceServer, rs.id)
		}

		if w, ok := src.(sourceWiring); ok {
			if err := w.checkWiring(c); err != nil {
				return err
			}
		}

		iss := src.issuer()
		if iss == "" {
			continue
		}

		if other, ok := issuers[iss]; ok {
			return newConfigError("%s (%s) was given two sources, %s and %s, for the issuer %q; a token "+
				"from it could not be routed to one", optionResourceServer, rs.id, other, src.name(), iss)
		}

		issuers[iss] = src.name()
	}

	for _, src := range rs.sources {
		if src.allowsUnbound() {
			if c.dpop != nil && c.dpop.cfg.Require {
				return newConfigError("%s (%s): the source %s accepts unbound tokens, and the chain's DPoP is "+
					"required (DPoP.Require), which refuses every unbound token; keep the source's default "+
					"binding, or leave DPoP optional", optionResourceServer, rs.id, src.name())
			}

			continue
		}

		if !c.dpopEnabled && c.certBinding == nil {
			return newConfigError("%s (%s): the source %s requires bound tokens by default, and the chain "+
				"checks no binding; enable EnableDPoP or EnableCertificateBinding, or let the source accept "+
				"unbound tokens", optionResourceServer, rs.id, src.name())
		}
	}

	return nil
}

// check refuses resource servers that cannot share a chain: one covering every path beside
// another, and prefixes of different resource servers that overlap, a prefix of another included.
// Prefixes nested inside one resource server are accepted: it is the one judge of them all.
func (s *resourceServers) check() error {
	if len(s.modes) < 2 {
		return nil
	}

	var owners []struct{ prefix, id string }

	for _, rs := range s.modes {
		if len(rs.prefixes) == 0 {
			return newConfigError("%s (%s) has no path prefix, and covers every path, so it can only be the "+
				"chain's one resource server; give each a WithPathPrefix", optionResourceServer, rs.id)
		}

		for _, prefix := range rs.prefixes {
			owners = append(owners, struct{ prefix, id string }{prefix, rs.id})
		}
	}

	for i, a := range owners {
		for _, b := range owners[i+1:] {
			if a.id == b.id {
				continue // nested prefixes of one resource server are one judge, not two
			}

			if hasPrefixFold(a.prefix, b.prefix) || hasPrefixFold(b.prefix, a.prefix) {
				return newConfigError("%s: the prefixes %q (%s) and %q (%s) overlap, so a path could be "+
					"judged by either; give them prefixes that share no path", optionResourceServer,
					a.prefix, a.id, b.prefix, b.id)
			}
		}
	}

	return nil
}

// validResourceIdentifier says whether value could be a resource identifier (RFC 8707 section 2):
// valid UTF-8, an absolute URI with no fragment, and no space around it. It is the provider's rule,
// so an identifier the provider accepts for a client is one a resource server accepts too.
func validResourceIdentifier(value string) bool {
	if value == "" || !utf8.ValidString(value) || value != strings.TrimSpace(value) || strings.Contains(value, "#") {
		return false
	}

	u, err := url.Parse(value)

	return err == nil && u.IsAbs()
}

// checkPathPrefix says why prefix is not a path prefix, and nil when it is: it begins and ends
// with "/", is valid UTF-8, and holds no empty, "." or ".." segment, no query and no fragment, so
// it matches whole segments of a canonical path.
func checkPathPrefix(prefix string) error {
	switch {
	case !strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/"):
		return errors.New("must begin and end with \"/\"")
	case !utf8.ValidString(prefix) || strings.ContainsAny(prefix, "?#%\\ \t\r\n"):
		return errors.New("must be a plain path, with no query, fragment, escape or space")
	case prefix != "/" && (strings.Contains(prefix, "//") || hasDotSegment(strings.Trim(prefix, "/"))):
		return errors.New("must hold no empty, \".\" or \"..\" segment")
	default:
		return nil
	}
}

// distinctPrefixes is prefixes with each repeat dropped, a repeat that differs only in ASCII case
// included, since a prefix matches without regard to it: the same prefix given twice is one prefix,
// not an overlap. The first spelling is kept.
func distinctPrefixes(prefixes []string) []string {
	seen := make(map[string]bool, len(prefixes))
	out := prefixes[:0:0]

	for _, prefix := range prefixes {
		key := asciiLower(prefix)
		if seen[key] {
			continue
		}

		seen[key] = true
		out = append(out, prefix)
	}

	return out
}

// WithPathPrefix confines the resource server to the paths under prefixes.
//
// A prefix matches a path without regard to ASCII case, as several routers match routes by
// default: a path a router serves under the prefix is never left uncovered for its case. Covering a
// path that differs only in case is the safe side: it is judged, never left to a later mode.
func WithPathPrefix(prefixes ...string) ResourceServerOption {
	return func(rs *resourceServer) error {
		rs.prefixGiven = true
		rs.prefixes = append(rs.prefixes, prefixes...)

		return nil
	}
}

// WithResourceAliases accepts tokens whose audience names one of aliases as well as the identifier.
func WithResourceAliases(aliases ...string) ResourceServerOption {
	return func(rs *resourceServer) error {
		rs.aliases = append(rs.aliases, aliases...)

		return nil
	}
}

// withSource adds s to the resource server. Every public source constructor goes through it.
func withSource(s source) ResourceServerOption {
	return func(rs *resourceServer) error {
		rs.sources = append(rs.sources, s)

		return nil
	}
}

// resourceServers is the one interceptor every resource server of a chain shares, so that a token
// is routed by path across all of them.
type resourceServers struct {
	modes []*resourceServer

	// bound is the largest token read, settled at assembly: the larger of minTokenBound and the
	// chain provider's own.
	bound int

	// dpop is the chain's DPoP verifier, handed over at assembly, and nil while DPoP is off.
	dpop *dpopVerifier

	// certBinding says the chain checks certificate bindings, handed over at assembly. A source
	// requiring a binding then may be answered with a certificate, so its challenge is Bearer's.
	certBinding bool

	// engine runs the per-request policy phase for an accepted caller, and now dates the
	// authentication: both handed over at assembly.
	engine *policy.Engine
	now    func() time.Time

	// guards count each source's verification refusals per client address, built once the chain
	// exists (resource_throttle.go); log is the chain's logger.
	guards map[source]sourceGuard
	log    *slog.Logger
}

// resourceServersOf returns the chain's resource-server interceptor, registering it at
// OrderResourceServer the first time.
func resourceServersOf(c *config) *resourceServers {
	var found *resourceServers

	_ = eachInterceptor(c, func(s *resourceServers) error {
		found = s

		return nil
	})

	if found != nil {
		return found
	}

	s := &resourceServers{bound: minTokenBound}
	c.register(s, OrderResourceServer)
	c.bindingVerifiers = append(c.bindingVerifiers, optionResourceServer)

	// The refusal guards need the chain's keyer, which exists only once the chain is built.
	c.checkAfterWiring(func() error { return s.buildGuards(c) })
	c.checkAfterWiring(func() error { return s.checkAssuranceSource(c) })

	// EnableDPoP and EnableOIDCProvider may come after this option.
	c.wire(func(*Chain) {
		s.dpop = c.dpop
		s.certBinding = c.certBinding != nil
		s.engine = c.engine
		s.now = c.clock.Now

		if c.oidcProvider != nil && c.oidcProvider.provider != nil {
			s.bound = max(s.bound, c.oidcProvider.provider.MaxAccessTokenSize())
		}
	})

	return s
}

// Intercept judges an access token on the request. In order:
//
//  1. a request with no token under the Bearer scheme, or the DPoP scheme while DPoP is on, passes
//     on; one with more than one Authorization header is refused with invalid_request on a covered
//     path, as which header a mode reads would be a guess, and passes on off every covered path;
//  2. on a path a resource server covers, a token over the bound is refused before any of it is
//     decoded;
//  3. the token is read for routing only; a session token is never offered to a source;
//  4. off every covered path, only a token that is unmistakably an access token is refused: the
//     provider's own formats, an at+jwt, and a token a source's mark names; any other passes on;
//  5. on a covered path, the token goes to the one source it belongs to, and is refused, never
//     handed on, when it is an access token no source can take;
//  6. the source verifies it, and its binding is held to the request; the proof is recorded last.
//
// Every refusal is ErrInvalidToken, or the sender-constrained refusal its binding calls for, and
// carries the one challenge bearerChallenge answers it with. A source's dependency failure is
// returned as it is, and is not a refusal.
func (s *resourceServers) Intercept(ex *Exchange, next Next) error {
	path := canonicalPath(ex.Request.Path())
	rs := s.covering(path)

	raw, underDPoP, claimed, err := readAuthorization(ex.Request, s.dpop)
	switch {
	case err != nil && rs != nil:
		return &accessTokenRefusal{err: err, dpop: s.dpopRequired(), code: codeInvalidRequest}
	case err != nil || !claimed || raw == "":
		return next(ex)
	}

	if len(raw) > s.bound {
		if rs == nil {
			return next(ex)
		}

		return s.refused(ex, rs, nil, ErrInvalidToken, underDPoP)
	}

	t := peek(raw)
	if t.sessionTyped() {
		return next(ex)
	}

	if rs == nil {
		if s.offPrefixRefused(t) {
			return s.refused(ex, nil, nil, ErrInvalidToken, underDPoP)
		}

		return next(ex)
	}

	src, refuse := rs.route(t)

	switch {
	case src != nil:
	case refuse:
		return s.refused(ex, rs, nil, ErrInvalidToken, underDPoP)
	default:
		return next(ex)
	}

	if err := s.admit(ex, rs, src, raw, underDPoP); err != nil {
		return err
	}

	return next(ex)
}

// refuse is err, a refusal of a token presented under DPoP when underDPoP, carrying its
// challenge: DPoP's when the token came under DPoP, when the chain requires DPoP, or when src
// requires a binding only DPoP can prove; Bearer's otherwise, a certificate-bound source's
// included (RFC 8705 uses Bearer). src is nil when no source took the token.
func (s *resourceServers) refuse(err error, underDPoP bool, src source) error {
	dpop := s.dpop != nil &&
		(underDPoP || s.dpopRequired() || src != nil && !src.allowsUnbound() && !s.certBinding)
	if errors.Is(err, ErrCertificateBinding) {
		dpop = false // RFC 8705 answers a certificate-binding refusal under Bearer alone
	}

	return &accessTokenRefusal{err: err, dpop: dpop, code: codeInvalidToken}
}

// refused is refuse, reporting the refusal as event.AccessTokenRefused: naming rs's identifier
// (empty off every covered path) and src as configured (empty when no source took the token), never
// the token. Only an invalid-token refusal is reported here; a binding refusal reports its own event
// through the chain's refusal reporting.
func (s *resourceServers) refused(ex *Exchange, rs *resourceServer, src source, err error, underDPoP bool) error {
	e := event.Event{Name: event.AccessTokenRefused, Outcome: event.OutcomeFailure}
	if rs != nil {
		e.Target = rs.id
	}

	if src != nil {
		e.Cause = src.name()
	}

	emitEvent(ex.Context(), e)

	return s.refuse(err, underDPoP, src)
}

// dpopRequired says the chain's DPoP is on and required, so every token is presented under DPoP.
func (s *resourceServers) dpopRequired() bool { return s.dpop != nil && s.dpop.cfg.Require }

// admit verifies raw at src, holds it to its binding, runs the per-request policy phase for its
// caller, and publishes the caller and the token on ex.
func (s *resourceServers) admit(ex *Exchange, rs *resourceServer, src source, raw string, underDPoP bool) error {
	ctx := ex.Context()

	// A throttled address is refused before anything is fetched or called for its token.
	rsrc, throttled, err := s.admitSource(ctx, src, ex.Request.ClientIP())
	switch {
	case throttled:
		emitEvent(ctx, event.Event{Name: event.ExcessRateLimitExceeded, Outcome: event.OutcomeFailure})

		return s.refuse(err, underDPoP, src)
	case errors.Is(err, ErrInvalidToken):
		return s.refused(ex, rs, src, err, underDPoP)
	case err != nil:
		return err
	}

	// Only a verification refusal is counted: binding, nonce and assurance answers below, and
	// dependency failures, are not.
	vt, err := src.verify(ctx, raw)
	switch {
	case isDependencyFailure(err):
		// Whatever the dependency's error wraps, it is never a refusal and never counted.
		return err
	case errors.Is(err, ErrInvalidToken):
		s.countRefusal(ctx, src, rsrc)

		return s.refused(ex, rs, src, err, underDPoP)
	case err != nil:
		return err
	case vt == nil || vt.principal == nil:
		s.countRefusal(ctx, src, rsrc)

		return s.refused(ex, rs, src, ErrInvalidToken, underDPoP)
	}

	check, err := checkBinding(ex, s.dpop, underDPoP, raw, vt.confirmation)
	if err != nil {
		return err
	}

	if err := bindingRefusal(check.verdict, src); err != nil {
		return s.refuse(err, underDPoP, src)
	}

	verdict, err := check.record(ctx, s.dpop)
	if err != nil {
		return err
	}

	if err := bindingRefusal(verdict, src); err != nil {
		return s.refuse(err, underDPoP, src)
	}

	return s.publish(ex, rs, vt, underDPoP, src)
}

// publish runs the per-request policy phase for vt's caller and, when it allows, publishes the
// caller and the token on ex. The caller's scopes are the token's, whatever the source's principal
// carried, so no caller strategy can widen them.
func (s *resourceServers) publish(ex *Exchange, rs *resourceServer, vt *verifiedToken, underDPoP bool, src source) error {
	ctx := ex.Context()
	now := s.now()

	tok := vt.token
	if tok == nil {
		tok = &AccessToken{}
	}

	tok = tok.clone()
	tok.Resource = rs.id

	kind := vt.kind
	if kind == "" {
		kind = factor.ExternalAccessToken // fail closed: never taken for the provider's own token
	}

	p := *vt.principal
	p.Scopes = slices.Clone(tok.Scopes)

	in := accessTokenInput(&p, kind, vt, now)

	d := evaluatePhase(ctx, s.engine, policy.PerRequest, in)

	switch d.Outcome {
	case policy.Deny:
		return s.policyRefusal(d, underDPoP, src)
	case policy.Challenge:
		// No session can hold the challenge, so the caller is sent for a stronger sign-in instead,
		// and nothing is marked anywhere.
		return s.refuseInsufficient(underDPoP, src)
	case policy.Allow:
	}

	auth := &authenticate.Authentication{
		Principal:   &p,
		Credentials: accessTokenCredentials{kind: kind, external: vt.external},
		Time:        now,
	}

	ex.Authentication = auth
	ex.SetContext(withAccessToken(WithCaller(ctx, auth), tok))
	ex.accessTokenClaimed = true

	return nil
}

// bindingRefusal answers a binding verdict as the sender-constrained-token rules do, and nil for a
// binding that holds, or an unbound token from a source that accepts one.
func bindingRefusal(verdict bindingVerdict, src source) error {
	switch verdict {
	case bindingHeld:
		return nil
	case bindingUnbound:
		if src.allowsUnbound() {
			return nil
		}

		return ErrInvalidToken
	case bindingKeyMismatch, bindingProofInvalid:
		return ErrInvalidDPoPProof
	case bindingNonceRequired:
		return ErrDPoPNonceRequired
	case bindingCertificateMismatch:
		return ErrCertificateBinding
	default:
		return ErrInvalidToken
	}
}

// covering returns the resource server covering path, and nil when none does. Prefixes do not
// overlap, so at most one does.
func (s *resourceServers) covering(path string) *resourceServer {
	for _, rs := range s.modes {
		if rs.covers(path) {
			return rs
		}
	}

	return nil
}

// offPrefixRefused says a token on a path no resource server covers is unmistakably an access token,
// and so refused rather than handed to a later mode: the provider's own formats, an at+jwt, and a
// token any source's mark names. A source's fallback claim refuses nothing.
func (s *resourceServers) offPrefixRefused(t peeked) bool {
	if t.format == formatProvider || t.accessTyped() {
		return true
	}

	for _, rs := range s.modes {
		if rs.marked(t) != nil {
			return true
		}
	}

	return false
}

// tokenTyped is a generator that reports the type it declares, as token.JWTGenerator does.
type tokenTyped interface {
	TokenType() string
}

// checkSessionTokenType refuses a session token generator whose declared type a resource server on
// the chain would take for an access token's: at+jwt in any case or spelling, and JWT while a source
// accepts untyped tokens. A generator that does not report its type cannot be seen.
func checkSessionTokenType(c *config, option, field string, g token.Generator) error {
	typed, ok := g.(tokenTyped)
	if nilcheck.IsNil(g) || !ok {
		return nil
	}

	declared := typed.TokenType()
	typ := strings.TrimPrefix(asciiLower(declared), "application/")

	return eachInterceptor(c, func(s *resourceServers) error {
		if typ == token.TypeAccessToken {
			return newConfigError("%s was given a token generator (%s) declaring the type %q, which a resource "+
				"server takes for an access token; give session tokens a type of their own", option, field, declared)
		}

		if typ != "jwt" {
			return nil
		}

		for _, rs := range s.modes {
			for _, src := range rs.sources {
				if u, ok := src.(interface{ acceptsUntyped() bool }); ok && u.acceptsUntyped() {
					return newConfigError("%s was given a token generator (%s) declaring the type %q, and %s (%s) "+
						"accepts tokens typed JWT (%s) through %s; give session tokens a type of their own",
						option, field, declared, optionResourceServer, rs.id, optionUntypedTokens, src.name())
				}
			}
		}

		return nil
	})
}

// checkNotOwnIssuer refuses a remote source (option names it) whose issuer is the chain's own
// provider's: only FromProvider may trust the provider's tokens, as it reads the grant they name.
func checkNotOwnIssuer(c *config, rsID, option, iss string) error {
	if c.oidcProvider == nil || c.oidcProvider.provider == nil || c.oidcProvider.provider.Issuer() != iss {
		return nil
	}

	return newConfigError("%s (%s): %s names the chain provider's own issuer %q; only FromProvider may trust "+
		"the provider's own tokens", optionResourceServer, rsID, option, iss)
}
