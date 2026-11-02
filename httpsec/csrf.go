package httpsec

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/session"
)

// ErrCrossSiteRequest is the refusal of a state-changing request CSRF
// protection judged to come from another site, or to lack its sign-in's token.
// Its text names no origin and no token.
var ErrCrossSiteRequest = errors.New("httpsec: cross-site request refused")

// Fetch Metadata and Origin header names and values.
const (
	headerSecFetchSite = "Sec-Fetch-Site"
	fetchSameOrigin    = "same-origin"
	fetchNone          = "none"
)

// CSRFOption adjusts CSRF protection. Each names, in its own documentation, the
// default it replaces.
type CSRFOption func(*csrfLayer) error

// csrfLayer is the layer EnableCSRFProtection registers. It is built once and
// read-only while serving.
type csrfLayer struct {
	// added are the normalised origins WithCSRFTrustedOrigins trusts.
	added []string

	// noCORS is set by WithoutCORSOriginsTrustedForCSRF.
	noCORS bool

	// trusted holds every normalised trusted origin, and patterns the CORS
	// patterns trusted with them, both settled when the chain is built.
	trusted  []string
	patterns []originPattern

	// header and field name where a request carries its token.
	header string
	field  string

	// tokens is the token source.
	tokens CSRFTokens

	// issue is whether sign-ins are created with a stored token: an
	// interceptor on the chain authenticates by a cookie, and the default
	// token source, which reads it, is in use. It is settled when the chain is
	// built.
	issue bool

	// exemptions are the routes WithCSRFExemption names, and noBackchannel is
	// set by WithoutBackchannelLogoutExemption. exempt is every exempt route,
	// the back-channel logout endpoint included, settled when the chain is
	// built.
	exemptions    []csrfExemption
	noBackchannel bool
	exempt        []csrfExemption
}

// EnableCSRFProtection refuses state-changing requests another site makes the
// user's browser send.
//
// Default: off. Once enabled, a request whose method is not exactly GET, HEAD
// or OPTIONS (compared case-sensitively, so "get" and PROPFIND are judged) is
// judged in OrderCSRF, before any authentication interceptor, by the browser's
// own signals:
//
//   - Sec-Fetch-Site of same-origin or none passes.
//   - Any other Sec-Fetch-Site value is refused unless the request's Origin is
//     a trusted origin.
//   - With no Sec-Fetch-Site, an Origin that differs in scheme, host or port
//     from the request's own is refused unless it is trusted. The request's
//     own scheme and host are those the chain resolved (Request.Secure and
//     Request.Host, through EnableTrustedProxies or WithHTTPSDeployment), and
//     both sides are normalised as CORS normalises origins: lower case, and no
//     default port. Origin: null never matches and is never trusted.
//   - A request with neither header passes: it is not a browser's.
//
// The refusal is ErrCrossSiteRequest, answered 403. The check reads no session
// and no body.
//
// A request a CookieAuthenticator authenticates must also carry its sign-in's
// token (CheckCSRFToken), which a page reads with CSRFToken. A request
// authenticated only by an Authorization header needs none. A
// CookieAuthenticator must be registered after OrderCSRF; one at or before it
// fails construction with ErrConfig. Giving this option
// is required once a CookieAuthenticator is registered, unless
// WithoutCSRFProtection is given instead; giving it twice is a configuration
// error.
//
// The defaults each option replaces:
//
//   - Trusted origins: every origin EnableCORS lists or matches by a pattern,
//     never a CORS "*" (WithCSRFTrustedOrigins adds more;
//     WithoutCORSOriginsTrustedForCSRF drops the CORS ones).
//   - Token names: header X-CSRF-Token and form field csrf_token
//     (WithCSRFTokenNames).
//   - Token source: 32 random bytes stored on the sign-in when it is created,
//     carried by its renewals, compared in constant time (WithCSRFTokens).
//     Sign-ins store a token only while this source is in use.
//   - Exempt routes: none but the OIDC back-channel logout endpoint, by POST
//     (WithCSRFExemption adds one; WithoutBackchannelLogoutExemption removes
//     the back-channel one).
func EnableCSRFProtection(opts ...CSRFOption) Option {
	const option = "EnableCSRFProtection"

	return func(c *config) error {
		dup := eachInterceptor(c, func(*csrfLayer) error {
			return newConfigError("%s was given twice; one chain has one CSRF layer", option)
		})
		if dup != nil {
			return dup
		}

		l := &csrfLayer{
			header: DefaultCSRFTokenHeader,
			field:  DefaultCSRFTokenField,
			tokens: sessionCSRFTokens{compare: subtle.ConstantTimeCompare},
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}

			if err := opt(l); err != nil {
				return err
			}
		}

		c.register(l, OrderCSRF)
		c.csrfTokenHeader = l.header

		// CORS, OIDC login and the cookie authenticators may be enabled by an
		// option given after this one, so what the layer reads from them is
		// settled once every option has been applied (wireCSRF).
		return nil
	}
}

// wireCSRF settles the CSRF layer once every option has been applied, and
// hands each first factor that ends its login through completeLogin whether
// the sign-ins it makes carry a token. Deciding that here, when the chain is
// built, rather than from the request, means a redeemer that runs its checks
// on a context of its own still issues the token. A chain with no CSRF layer
// hands every first factor false.
func (c *config) wireCSRF() error {
	issue := false

	err := eachInterceptor(c, func(l *csrfLayer) error {
		if err := l.settle(c); err != nil {
			return err
		}

		issue = l.issue

		return nil
	})
	if err != nil {
		return err
	}

	c.csrfTokensAtLogin(issue)

	return nil
}

// csrfTokensAtLogin hands issue to every first factor that ends its login
// through completeLogin: form login, magic link, OIDC and passwordless passkey
// login; and to account recovery, whose sign-in the recovery core creates, at
// its completion or its finish.
func (c *config) csrfTokensAtLogin(issue bool) {
	_ = eachInterceptor(c, func(l *formLogin) error {
		l.csrfToken = issue

		return nil
	})

	_ = eachInterceptor(c, func(i *magicLinkInterceptor) error {
		i.csrfToken = issue

		return nil
	})

	_ = eachInterceptor(c, func(i *oidcInterceptor) error {
		i.csrfToken = issue

		return nil
	})

	_ = eachInterceptor(c, func(i *passwordlessInterceptor) error {
		i.csrfToken = issue

		return nil
	})

	_ = eachInterceptor(c, func(i *recoveryInterceptor) error {
		i.csrfToken = issue

		return nil
	})
}

// settle settles what the layer reads from the rest of the chain: whether
// sign-ins carry a token (a cookie authenticator is registered and the default
// token source is in use), the exempt routes (settleExemptions), and the
// trusted origins: those WithCSRFTrustedOrigins added, and,
// unless WithoutCORSOriginsTrustedForCSRF was given, every origin the CORS
// layer lists exactly or matches by a pattern. A CORS "*" trusts nothing.
func (l *csrfLayer) settle(c *config) error {
	// A consumer's own source keeps no sealed value it never reads.
	_, stored := l.tokens.(sessionCSRFTokens)
	l.issue = stored && hasCookieAuthenticator(c)

	if err := l.settleExemptions(c); err != nil {
		return err
	}

	l.trusted = slices.Clone(l.added)

	if l.noCORS {
		return nil
	}

	exact, patterns := c.corsOrigins()
	for _, o := range exact {
		if o != corsAnyOrigin && !slices.Contains(l.trusted, o) {
			l.trusted = append(l.trusted, o)
		}
	}

	l.patterns = patterns

	return nil
}

// trustedOrigin reports whether raw is a trusted origin. One that does not
// parse, "null" among them, never is.
func (l *csrfLayer) trustedOrigin(raw string) bool {
	scheme, host, port, err := parseOrigin(raw)
	if err != nil {
		return false
	}

	if slices.Contains(l.trusted, joinOrigin(scheme, host, port)) {
		return true
	}

	return slices.ContainsFunc(l.patterns, func(p originPattern) bool { return p.matches(scheme, host, port) })
}

// isSafeMethod reports whether method is exactly GET, HEAD or OPTIONS.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// Intercept judges an unsafe request by Fetch Metadata and Origin, and calls
// next when it passes.
func (l *csrfLayer) Intercept(ex *Exchange, next Next) error {
	// An exempt route is judged by neither the Fetch Metadata check nor the
	// token check.
	unsafe := !isSafeMethod(ex.Request.Method()) && !l.exempts(ex.Request)

	if unsafe {
		if err := l.judge(ex.Request); err != nil {
			return err
		}
	}

	// Published on every request, safe ones too, so a page served on a GET
	// reads its token (CSRFToken), and a cookie authenticator behind this slot
	// checks it (CheckCSRFToken).
	ex.SetContext(context.WithValue(ex.Context(), csrfKey{}, &csrfRequest{layer: l, unsafe: unsafe}))

	return next(ex)
}

// judge is the Fetch Metadata and Origin check of one unsafe request.
func (l *csrfLayer) judge(req Request) error {
	switch req.Header(headerSecFetchSite) {
	case "":
		// No Fetch Metadata: an older browser, or no browser at all. The
		// Origin decides.
	case fetchSameOrigin, fetchNone:
		return nil
	default:
		if l.trustedOrigin(req.Header(headerOrigin)) {
			return nil
		}

		return ErrCrossSiteRequest
	}

	origin := req.Header(headerOrigin)
	if origin == "" {
		return nil
	}

	if sameOriginAsRequest(origin, req) || l.trustedOrigin(origin) {
		return nil
	}

	return ErrCrossSiteRequest
}

// sameOriginAsRequest reports whether origin, normalised, is the request's own
// origin: the scheme and host the chain resolved, normalised the same way. An
// origin that does not parse, "null" among them, is never the request's.
func sameOriginAsRequest(origin string, req Request) bool {
	theirs, err := normaliseOrigin(origin)
	if err != nil {
		return false
	}

	scheme := "http"
	if req.Secure() {
		scheme = "https"
	}

	ours, err := normaliseOrigin(scheme + "://" + req.Host())
	if err != nil {
		return false
	}

	return theirs == ours
}

// WithCSRFTrustedOrigins trusts origins, in addition to the CORS layer's, so
// an unsafe request from a page on one of them passes the Fetch Metadata and
// Origin check. Each is an exact scheme://host[:port] with an http or https
// scheme, validated and normalised as EnableCORS validates its origins.
//
// Default: no origin beyond the CORS layer's. Construction fails with ErrConfig
// when no origin is given, or one is "null", "*", a pattern, or not a
// well-formed origin: "null" is shared by sandboxed documents and local files,
// and trusting every origin is turning the protection off, which
// WithoutCSRFProtection says plainly.
func WithCSRFTrustedOrigins(origins ...string) CSRFOption {
	const option = "WithCSRFTrustedOrigins"

	return func(l *csrfLayer) error {
		if len(origins) == 0 {
			return newConfigError("%s was given no origin", option)
		}

		for _, raw := range origins {
			if strings.Contains(raw, "*") {
				return newConfigError("%s was given %q; a trusted origin is exact, never \"*\" or a pattern", option, raw)
			}

			origin, err := normaliseOrigin(raw)
			if err != nil {
				return newConfigError("%s was given %q: %s", option, raw, err)
			}

			if !slices.Contains(l.added, origin) {
				l.added = append(l.added, origin)
			}
		}

		return nil
	}
}

// WithoutCORSOriginsTrustedForCSRF stops the CORS layer's origins from being
// trusted by CSRF protection, so only the request's own origin and those
// WithCSRFTrustedOrigins names pass.
//
// Default: every origin EnableCORS lists exactly, or matches by
// WithOriginPattern, is trusted, so a frontend on a sibling subdomain can call
// the API; a CORS "*" trusts none.
func WithoutCORSOriginsTrustedForCSRF() CSRFOption {
	return func(l *csrfLayer) error {
		l.noCORS = true

		return nil
	}
}

// Default names of the CSRF token's header and form field.
const (
	DefaultCSRFTokenHeader = "X-CSRF-Token" //nolint:gosec // G101: the name of a request header, not a credential
	DefaultCSRFTokenField  = "csrf_token"
)

// csrfFormBodyLimit is how many request body bytes are read looking for the
// token's form field.
const csrfFormBodyLimit int64 = 1 << 20

// WithCSRFTokenNames replaces the request header and the form field a
// cookie-authenticated unsafe request carries its CSRF token in. The header is
// read first; the field is read only from a body declared
// "application/x-www-form-urlencoded", of at most 1 MiB, and never from the
// URL query, where a token would reach access logs and the Referer. An empty
// field reads the header alone.
//
// Default: header X-CSRF-Token (DefaultCSRFTokenHeader) and field csrf_token
// (DefaultCSRFTokenField). Construction fails with ErrConfig when header is
// not a single header name.
func WithCSRFTokenNames(header, field string) CSRFOption {
	return func(l *csrfLayer) error {
		if !isCORSToken(header) {
			return newConfigError("WithCSRFTokenNames was given the header %q, which is not a single header name", header)
		}

		l.header, l.field = header, field

		return nil
	}
}

// CSRFTokens is the source of a sign-in's CSRF token: what CSRFToken answers
// a page, and what a cookie-authenticated unsafe request's token is checked
// against.
//
// Default: the token stored on the sign-in (session.Session.CSRFToken), made
// when the sign-in is created and carried by every renewal, compared in
// constant time; a sign-in holding no token is refused.
type CSRFTokens interface {
	// Token returns s's token, for the page to send back. An error or an empty
	// token means s has none.
	Token(ctx context.Context, s *session.Session) (string, error)

	// Verify checks that presented is s's token, comparing in constant time.
	// It returns ErrCrossSiteRequest, or an error wrapping it, for a token
	// that is missing, malformed or not s's. Any other error is a failure of
	// the source, answered as such rather than as a refusal.
	Verify(ctx context.Context, s *session.Session, presented string) error
}

// WithCSRFTokens replaces the token source, for example with an HMAC over the
// sign-in's family under the consumer's own key. CSRFToken and the check both
// read through it.
//
// Default: the token stored on the sign-in (see CSRFTokens). Construction
// fails with ErrConfig when t is nil or a typed nil.
func WithCSRFTokens(t CSRFTokens) CSRFOption {
	return func(l *csrfLayer) error {
		if err := requireDep("WithCSRFTokens", "token source", t); err != nil {
			return err
		}

		l.tokens = t

		return nil
	}
}

// csrfKey is the context key the layer publishes its request state under.
type csrfKey struct{}

// csrfRequest is what the layer publishes for one request.
type csrfRequest struct {
	layer *csrfLayer

	// unsafe is whether the request's method is one the token is required on.
	unsafe bool

	// signIn is the sign-in a cookie authenticator's CheckCSRFToken passed,
	// and nil until one has.
	signIn *session.Session
}

// csrfRequestFrom returns the state the layer published on ctx, and nil when
// no CSRF layer ran.
func csrfRequestFrom(ctx context.Context) *csrfRequest {
	r, _ := ctx.Value(csrfKey{}).(*csrfRequest)

	return r
}

// CSRFToken returns the CSRF token of the request's sign-in, for the page to
// send back on its state-changing requests, in the header or field
// WithCSRFTokenNames names. It reads through the configured CSRFTokens source.
//
// The sign-in is the session the chain published on ctx (SessionFromContext),
// or else the one a cookie authenticator's CheckCSRFToken passed, so a
// consumer's authenticator need publish nothing more for a page to read it.
//
// It reports false when CSRF protection is not enabled, the request carries no
// sign-in, or the sign-in holds no token. A sign-in made before CSRF
// protection was enabled holds none, and is refused on unsafe
// cookie-authenticated requests until the user signs in again.
func CSRFToken(ctx context.Context) (string, bool) {
	r := csrfRequestFrom(ctx)
	if r == nil {
		return "", false
	}

	s, ok := SessionFromContext(ctx)
	if !ok {
		s = r.signIn
	}

	if s == nil {
		return "", false
	}

	tok, err := r.layer.tokens.Token(ctx, s)
	if err != nil || tok == "" {
		return "", false
	}

	return tok, true
}

// WithoutCSRFProtection builds a chain that authenticates by a cookie with no
// CSRF protection. It is the explicit opt-out the construction check asks for,
// for a deployment whose cookies cannot be sent cross-site by other means it
// is answerable for; every cross-site page can otherwise make the user's
// browser send a state-changing request with the user's cookie.
//
// Default: a chain registering a CookieAuthenticator fails construction with
// ErrConfig unless EnableCSRFProtection is given. A
// chain authenticating by no cookie needs neither. Giving this together with
// EnableCSRFProtection is a configuration error.
func WithoutCSRFProtection() Option {
	return func(c *config) error {
		c.csrfOptOut = true

		return nil
	}
}

// CookieAuthenticator is implemented by an interceptor that authenticates a
// request by a cookie, a consumer's own included. Declaring it binds the chain
// to CSRF protection: New fails with ErrConfig unless EnableCSRFProtection or
// WithoutCSRFProtection is given, and with EnableCSRFProtection sign-ins are
// created holding a token (see CSRFTokens).
//
// Such an interceptor calls CheckCSRFToken with the session the cookie
// resolved, and refuses the request with its error, before handing the session
// on. It must run after the CSRF layer: New fails with ErrConfig when one is
// registered at or before OrderCSRF while EnableCSRFProtection is given. There
// is no override, because an authenticator running ahead of the check would
// make the token optional. An interceptor that does not authenticate by a cookie, a bearer token's
// for example, does not implement it.
type CookieAuthenticator interface {
	// AuthenticatesByCookie marks the interceptor. It is never called.
	AuthenticatesByCookie()
}

// hasCookieAuthenticator reports whether an interceptor registered on c
// authenticates by a cookie.
func hasCookieAuthenticator(c *config) bool {
	found := errors.New("found")

	return eachInterceptor(c, func(CookieAuthenticator) error { return found }) != nil
}

// refuseCookiesWithoutCSRF refuses a chain that authenticates by a cookie with
// neither CSRF protection nor the explicit opt-out, one given both, and one
// whose cookie authenticator runs at or before the CSRF layer's slot, where
// no token would have been checked for it.
func (c *config) refuseCookiesWithoutCSRF() error {
	protected := eachInterceptor(c, func(*csrfLayer) error { return errors.New("found") }) != nil

	switch {
	case protected && c.csrfOptOut:
		return newConfigError("EnableCSRFProtection and WithoutCSRFProtection were both given; give one or the other")
	case !protected && !c.csrfOptOut && hasCookieAuthenticator(c):
		return newConfigError("an interceptor authenticates requests by a cookie, and CSRF protection is not enabled: " +
			"any site could make the user's browser send a state-changing request with that cookie; " +
			"enable it with EnableCSRFProtection, or opt out explicitly with WithoutCSRFProtection")
	case protected:
		for _, r := range c.registrations {
			if _, ok := r.interceptor.(CookieAuthenticator); ok && r.order <= OrderCSRF {
				return newConfigError("an interceptor authenticating requests by a cookie is registered at slot %d, "+
					"at or before OrderCSRF (%d), so it would run before CSRF protection judged the request "+
					"and its token would go unchecked; register it after OrderCSRF", r.order, OrderCSRF)
			}
		}
	}

	return nil
}

// errCSRFNotJudged is CheckCSRFToken's answer on an exchange the CSRF layer
// never judged, on a chain that did not opt out: a wiring fault, not a
// refusal of the request.
var errCSRFNotJudged = newConfigError("CheckCSRFToken was called on a request CSRF protection never judged: " +
	"the cookie authenticator runs outside the chain or ahead of the CSRF layer; register it after " +
	"OrderCSRF on a chain built with EnableCSRFProtection, or opt out with WithoutCSRFProtection")

// CheckCSRFToken checks the CSRF token of a request a cookie authenticated
// with the sign-in s. Every CookieAuthenticator calls it before handing s on,
// and refuses the request with its error.
//
// It is nil for a GET, HEAD or OPTIONS, and for a route WithCSRFExemption
// exempts, which carries every other protection but this check. Otherwise the
// token is read from the header first, then from the form field of a
// URL-encoded body of at most 1 MiB, never from the query (see
// WithCSRFTokenNames), and checked through the configured CSRFTokens source.
// A token that is absent or empty is refused without asking the source. A
// refusal is ErrCrossSiteRequest; any other failure of the source is returned
// as it is. No error names the token. When it passes, s is the sign-in
// CSRFToken reads the token of.
//
// It fails closed, with an error wrapping ErrConfig (answered 500), when the
// CSRF layer has not judged the request: the authenticator runs outside the
// chain, or ahead of the layer. The one exception is a chain built with
// WithoutCSRFProtection, where it is nil.
func CheckCSRFToken(ex *Exchange, s *session.Session) error {
	r := csrfRequestFrom(ex.Context())
	if r == nil {
		if ex.csrfOptOut {
			return nil
		}

		return errCSRFNotJudged
	}

	if r.unsafe {
		presented := r.layer.presentedToken(ex.Request)
		if presented == "" {
			return ErrCrossSiteRequest
		}

		if err := r.layer.tokens.Verify(ex.Context(), s, presented); err != nil {
			return err
		}
	}

	checked := *r
	checked.signIn = s
	ex.SetContext(context.WithValue(ex.Context(), csrfKey{}, &checked))

	return nil
}

// presentedToken reads the token the request carries, "" for none.
func (l *csrfLayer) presentedToken(req Request) string {
	if tok := req.Header(l.header); tok != "" {
		return tok
	}

	if l.field == "" {
		return ""
	}

	tok, err := postedFieldLimited(req, l.field, csrfFormBodyLimit)
	if err != nil {
		return ""
	}

	return tok
}

// sessionCSRFTokens is the default token source: the token stored on the
// sign-in (session.WithCSRFToken).
type sessionCSRFTokens struct {
	// compare is subtle.ConstantTimeCompare; tests replace it to see it used.
	compare func(x, y []byte) int
}

// Token returns the sign-in's stored token, and ErrCrossSiteRequest when it
// holds none.
func (sessionCSRFTokens) Token(_ context.Context, s *session.Session) (string, error) {
	if s == nil || s.CSRFToken == "" {
		return "", ErrCrossSiteRequest
	}

	return s.CSRFToken, nil
}

// Verify compares presented with the sign-in's stored token in constant time.
// A sign-in holding no token refuses every token.
func (t sessionCSRFTokens) Verify(_ context.Context, s *session.Session, presented string) error {
	if s == nil || s.CSRFToken == "" || presented == "" {
		return ErrCrossSiteRequest
	}

	if t.compare([]byte(presented), []byte(s.CSRFToken)) != 1 {
		return ErrCrossSiteRequest
	}

	return nil
}
