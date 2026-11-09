package httpsec

import (
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Defaults of the CORS layer.
const (
	// defaultCORSMaxAge is how long a browser may cache an allowed preflight.
	defaultCORSMaxAge = 10 * time.Minute

	// corsAnyOrigin is the origin that stands for every origin.
	corsAnyOrigin = "*"
)

// defaultCORSMethods are the methods allowed when the policy names none.
var defaultCORSMethods = []string{"GET", "HEAD", "POST"}

// CORSPolicy is what EnableCORS allows. Each field names its default.
type CORSPolicy struct {
	// AllowedOrigins are the origins allowed to call the chain, each an exact
	// scheme://host[:port] with an http or https scheme, or "*" alone for every
	// origin. There is no default: at least one origin, here or through
	// WithOriginPattern, is required.
	AllowedOrigins []string

	// AllowedMethods are the methods a preflight may ask for, compared
	// case-sensitively. Default: GET, HEAD and POST.
	AllowedMethods []string

	// AllowedHeaders are the request headers a preflight may ask for, compared
	// case-insensitively. Default: none.
	AllowedHeaders []string

	// ExposedHeaders are the response headers an allowed origin's script may
	// read on an actual response. Default: none.
	ExposedHeaders []string

	// AllowCredentials lets an allowed origin send cookies and read the
	// response to a credentialed request. Default: false.
	AllowCredentials bool

	// MaxAge is how long a browser may cache an allowed preflight. Default:
	// zero, which means 10 minutes. It is sent in whole seconds, so a positive
	// value below one second, which would round to no caching at all, is a
	// configuration error; WithoutPreflightCaching turns caching off.
	MaxAge time.Duration
}

// CORSOption adjusts the CORS layer. Each names, in its own documentation, the
// default it replaces.
type CORSOption func(*corsLayer) error

// originPattern is an allowed origin whose leftmost host label is a wildcard
// matching exactly one non-empty label.
type originPattern struct {
	scheme string

	// suffix is the host after the wildcard label, with its leading dot.
	suffix string

	// port is "" for the scheme's default port.
	port string
}

// corsLayer is the layer EnableCORS registers. It is built once and read-only
// while serving.
type corsLayer struct {
	// exact holds the normalised allowed origins, or corsAnyOrigin alone.
	exact    []string
	patterns []originPattern

	credentials bool

	// exposedNames are the exposed response headers, and exposed the
	// Access-Control-Expose-Headers value naming them, "" for none.
	exposedNames []string
	exposed      string

	// methods are the allowed methods, and methodsValue the
	// Access-Control-Allow-Methods value naming them.
	methods      []string
	methodsValue string

	// headers maps each allowed request header, lower-cased, to the spelling
	// the policy gave it.
	headers map[string]string

	// maxAge is the Access-Control-Max-Age value.
	maxAge string

	// noPreflightCache is set by WithoutPreflightCaching.
	noPreflightCache bool

	// manual is set by WithoutAutomaticCORSHeaders: the chain's own features
	// add nothing to the policy.
	manual bool

	// provider is the OpenID Provider on the chain, nil when there is none. It
	// is set once the chain is wired and read-only afterwards; its paths are
	// read on each request.
	provider *oidcEndpoints

	// clientHeaders and clientExposed are headers and exposed what the
	// provider's client-facing endpoints follow: the policy's lists, with
	// Authorization and DPoP allowed and DPoP-Nonce and WWW-Authenticate
	// exposed. They are set by follow.
	clientHeaders map[string]string
	clientExposed string
}

// EnableCORS lets browser pages on the origins policy names call the chain's
// endpoints and the consumer's routes behind it.
//
// Default: off; the chain sends no CORS header. Once enabled:
//
//   - A request's Origin is allowed only when it equals one of
//     policy.AllowedOrigins exactly, after both are normalised to a lower-case
//     scheme and host with no default port, or matches a WithOriginPattern
//     pattern. "*" alone allows every origin, without credentials: any
//     request carrying an Origin, including "null" and one that is not a
//     well-formed origin, gets "*", and no origin is ever reflected.
//   - Every response the layer or an interceptor behind it answers carries
//     Vary: Origin, whether or not the request carried an Origin and whether
//     or not it was allowed. Origin is added to the Vary values already set,
//     by middleware outside the chain or an earlier interceptor, never in
//     place of them. The limit: a consumer interceptor registered ahead of
//     OrderCORS, such as at Before(OrderCORS), runs outside the layer, and a
//     response it writes carries no Vary: Origin unless it adds one itself.
//     Register a consumer interceptor at or after the layer's slot to have
//     its responses marked.
//   - An allowed actual request gets Access-Control-Allow-Origin with its
//     origin ("*" for "*"), Access-Control-Allow-Credentials: true when
//     policy.AllowCredentials is set (default false), and
//     Access-Control-Expose-Headers naming policy.ExposedHeaders (default none).
//     These are set before the next interceptor runs, so a refusal from a
//     later one, such as a bearer token's 401, is readable by the page.
//   - A preflight, an OPTIONS request carrying Origin and
//     Access-Control-Request-Method, is answered with 204 in OrderCORS, and
//     reaches no authentication interceptor, authorizer or handler. It is
//     allowed when its origin is, its method is one of policy.AllowedMethods
//     (default GET, HEAD and POST, compared case-sensitively) and every header
//     it asks for is one of policy.AllowedHeaders (default none, compared
//     case-insensitively, every Access-Control-Request-Headers line read as
//     one list). An allowed preflight carries the allowed origin, the allowed
//     methods, the requested headers and Access-Control-Max-Age, policy.MaxAge in
//     whole seconds (default 600; 0 with WithoutPreflightCaching). Any other
//     preflight gets 204 with no CORS header. Every preflight answer adds
//     Origin, Access-Control-Request-Method, Access-Control-Request-Headers to
//     Vary.
//   - An OPTIONS request without Access-Control-Request-Method is not a
//     preflight and continues through the chain.
//   - A request from an origin not allowed gets no CORS header but Vary, and
//     is otherwise handled as if CORS were off.
//   - With DPoP enabled, DPoP is allowed and DPoP-Nonce and WWW-Authenticate
//     are exposed; with CSRF protection reading a token header, that header is
//     allowed. WithoutAutomaticCORSHeaders turns these additions off.
//   - With an OpenID Provider on the chain (EnableOIDCProvider), its endpoints
//     are treated as the protocol requires, at the paths the provider settled:
//     the token, UserInfo, revocation and introspection endpoints, and the
//     metadata documents, follow the allowlist as any route does, with
//     Authorization and DPoP allowed as request headers whether or not DPoP is
//     enabled, DPoP-Nonce and WWW-Authenticate exposed, and credentials never
//     allowed, whatever policy.AllowCredentials says; the authorization, resume,
//     end-session and logout confirmation endpoints carry no Access-Control
//     header at all, whatever the allowlist says, and a preflight to them is
//     not answered by the layer. WithoutAutomaticCORSHeaders also turns off the
//     provider's header additions; it cannot allow credentials on the
//     provider's endpoints or lift the exclusion, which guard the protocol
//     (RFC 9700 section 2.6). Every response still varies by Origin.
//
// Construction fails with ErrConfig, naming the setting or the origin, when no
// origin is given; an origin is "null", has a scheme other than http or https,
// a path (even "/"), a query, a fragment, userinfo or no host; "*" is given
// with AllowCredentials or beside other origins; an origin holds a wildcard
// without WithOriginPattern; policy.MaxAge is negative, positive but below one
// second, or set together with WithoutPreflightCaching; a method or header
// name is not a single token, or is "*"; or CORS is enabled twice.
//
// The layer is scrty's own rather than a framework's middleware, so it behaves
// the same on every adapter, and a preflight is answered before the chain's
// fail-closed authorizer could refuse it.
func EnableCORS(policy CORSPolicy, opts ...CORSOption) Option {
	const option = "EnableCORS"

	return func(c *config) error {
		dup := eachInterceptor(c, func(*corsLayer) error {
			return newConfigError("%s was given twice; one chain has one CORS layer", option)
		})
		if dup != nil {
			return dup
		}

		l, err := newCORSLayer(policy, opts)
		if err != nil {
			return err
		}

		c.register(l, OrderCORS)

		// A refusal written before the layer's slot, a host that is not
		// allowed or a security-headers nonce that could not be generated,
		// runs no CORS interceptor, so it is marked here as the layer marks
		// every other response.
		c.wire(func(ch *Chain) {
			ch.refusalSteps = append(ch.refusalSteps, func(ex *Exchange) {
				ex.Writer.AddHeader(headerVary, headerOrigin)
			})
		})

		// The features the layer follows may be enabled by options given after
		// this one, so it reads them once every option has been applied.
		c.wire(func(*Chain) {
			l.follow(c.dpopEnabled, c.csrfTokenHeader)
			l.provider = c.oidcProvider
		})

		return nil
	}
}

// newCORSLayer validates p and opts and builds the layer.
func newCORSLayer(p CORSPolicy, opts []CORSOption) (*corsLayer, error) {
	l := &corsLayer{}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt(l); err != nil {
			return nil, err
		}
	}

	for _, raw := range p.AllowedOrigins {
		if raw == corsAnyOrigin {
			if len(p.AllowedOrigins) > 1 || len(l.patterns) > 0 {
				return nil, newConfigError(`EnableCORS: AllowedOrigins lists "*" beside other origins; "*" stands for every origin and must be given alone`)
			}

			if p.AllowCredentials {
				return nil, newConfigError(`EnableCORS: AllowCredentials cannot be set with the origin "*": ` +
					`it would let every site read credentialed responses; name the origins instead`)
			}

			l.exact = append(l.exact, corsAnyOrigin)

			continue
		}

		if strings.Contains(raw, "*") {
			return nil, newConfigError("EnableCORS: AllowedOrigins lists %q, a pattern; give a pattern with WithOriginPattern", raw)
		}

		origin, err := normaliseOrigin(raw)
		if err != nil {
			return nil, newConfigError("EnableCORS: AllowedOrigins lists %q: %s", raw, err)
		}

		l.exact = append(l.exact, origin)
	}

	if len(l.exact) == 0 && len(l.patterns) == 0 {
		return nil, newConfigError("EnableCORS: AllowedOrigins is empty; name at least one origin")
	}

	switch {
	case p.MaxAge < 0:
		return nil, newConfigError("EnableCORS: MaxAge is negative")
	case p.MaxAge > 0 && p.MaxAge < time.Second:
		return nil, newConfigError("EnableCORS: MaxAge %s is below one second and would be sent as 0; "+
			"turn preflight caching off with WithoutPreflightCaching instead", p.MaxAge)
	case p.MaxAge > 0 && l.noPreflightCache:
		return nil, newConfigError("EnableCORS: MaxAge is set together with WithoutPreflightCaching; give one or the other")
	}

	for _, list := range []struct {
		field string
		names []string
	}{
		{"AllowedMethods", p.AllowedMethods},
		{"AllowedHeaders", p.AllowedHeaders},
		{"ExposedHeaders", p.ExposedHeaders},
	} {
		for _, n := range list.names {
			if !isCORSToken(n) {
				return nil, newConfigError("EnableCORS: %s lists %q, which is not a single header name or method", list.field, n)
			}
		}
	}

	l.credentials = p.AllowCredentials
	for _, h := range p.ExposedHeaders {
		l.expose(h)
	}

	l.methods = slices.Clone(p.AllowedMethods)
	if len(l.methods) == 0 {
		l.methods = slices.Clone(defaultCORSMethods)
	}

	l.methodsValue = strings.Join(l.methods, ", ")

	l.headers = make(map[string]string, len(p.AllowedHeaders))
	for _, h := range p.AllowedHeaders {
		l.allowHeader(h)
	}

	maxAge := p.MaxAge
	if maxAge == 0 && !l.noPreflightCache {
		maxAge = defaultCORSMaxAge
	}

	l.maxAge = strconv.FormatInt(int64(maxAge/time.Second), 10)

	return l, nil
}

// isCORSToken reports whether s is an RFC 9110 token other than "*", which
// browsers read as a wildcard in some of these lists and literally in others.
func isCORSToken(s string) bool {
	if s == "" || s == corsAnyOrigin {
		return false
	}

	for i := range len(s) {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			continue
		}

		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}

	return true
}

// errOrigin is why an origin is not a serialised http or https origin.
type errOrigin string

func (e errOrigin) Error() string { return string(e) }

// parseOrigin splits raw into a lower-case scheme and host and a port, "" for
// the scheme's default, refusing anything but scheme://host[:port].
func parseOrigin(raw string) (scheme, host, port string, err error) {
	if raw == "null" {
		return "", "", "", errOrigin(`the "null" origin is shared by sandboxed documents and local files, so it identifies no site`)
	}

	if strings.ContainsAny(raw, "#") {
		return "", "", "", errOrigin("an origin has no fragment")
	}

	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", "", errOrigin("it is not a URL")
	}

	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", "", "", errOrigin("an origin's scheme is http or https")
	case u.Opaque != "" || u.User != nil:
		return "", "", "", errOrigin("an origin has no userinfo")
	case u.Path != "" || u.RawPath != "":
		return "", "", "", errOrigin("an origin has no path")
	case u.RawQuery != "" || u.ForceQuery:
		return "", "", "", errOrigin("an origin has no query")
	case u.Hostname() == "" || strings.Contains(u.Hostname(), "%"):
		return "", "", "", errOrigin("an origin has a host")
	}

	port = u.Port()
	if port != "" {
		n, aerr := strconv.Atoi(port)
		if aerr != nil || n < 1 || n > 65535 {
			return "", "", "", errOrigin("an origin's port is a number from 1 to 65535")
		}

		port = strconv.Itoa(n)
	}

	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}

	return u.Scheme, strings.ToLower(u.Hostname()), port, nil
}

// normaliseOrigin returns raw as browsers serialise an origin: lower-case
// scheme and host, and no default port.
func normaliseOrigin(raw string) (string, error) {
	scheme, host, port, err := parseOrigin(raw)
	if err != nil {
		return "", err
	}

	return joinOrigin(scheme, host, port), nil
}

// joinOrigin serialises an origin's parts.
func joinOrigin(scheme, host, port string) string {
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}

	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}

	return scheme + "://" + host
}

// WithOriginPattern allows every origin that matches pattern, an origin whose
// leftmost host label is "*", such as https://*.example.com. The wildcard
// matches exactly one non-empty label: https://a.example.com, but neither
// https://a.b.example.com nor https://example.com. Scheme and port must match
// exactly.
//
// Default: no pattern; AllowedOrigins are matched exactly. A pattern is never
// accepted in AllowedOrigins, so a wildcard is always a deliberate choice. A
// wildcard anywhere but a whole leftmost label fails construction, and so does
// a pattern with fewer than two labels after its wildcard, such as
// https://*.com, which would allow every site under a top-level domain.
//
// The library holds no public-suffix list, so that is the only breadth check:
// https://*.co.uk is accepted exactly as https://*.example.com is, although it
// allows every site registered under co.uk. Naming a pattern under a public
// suffix is the consumer's responsibility.
func WithOriginPattern(pattern string) CORSOption {
	return func(l *corsLayer) error {
		p, err := parseOriginPattern(pattern)
		if err != nil {
			return newConfigError("WithOriginPattern was given %q: %s", pattern, err)
		}

		l.patterns = append(l.patterns, p)

		return nil
	}
}

// parseOriginPattern validates and normalises one pattern.
func parseOriginPattern(raw string) (originPattern, error) {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || !strings.HasPrefix(rest, "*.") {
		return originPattern{}, errOrigin(`a pattern's leftmost host label is "*", as in https://*.example.com`)
	}

	// The wildcard is replaced by a plain label so the rest is checked as an
	// ordinary origin; any other "*" is then refused.
	const label = "wildcard"

	s, host, port, err := parseOrigin(scheme + "://" + label + rest[1:])
	if err != nil {
		return originPattern{}, err
	}

	suffix := strings.TrimPrefix(host, label)
	if strings.Contains(suffix, "*") {
		return originPattern{}, errOrigin(`a pattern's only wildcard is its whole leftmost host label`)
	}

	labels := strings.Split(strings.TrimPrefix(suffix, "."), ".")
	if len(labels) < 2 || slices.Contains(labels, "") {
		return originPattern{}, errOrigin(`a pattern needs at least two labels after its wildcard, as in https://*.example.com`)
	}

	return originPattern{scheme: s, suffix: suffix, port: port}, nil
}

// matches reports whether the parsed origin matches p.
func (p originPattern) matches(scheme, host, port string) bool {
	if scheme != p.scheme || port != p.port {
		return false
	}

	label, ok := strings.CutSuffix(host, p.suffix)

	return ok && label != "" && !strings.Contains(label, ".")
}

// WithoutAutomaticCORSHeaders stops the CORS layer adding the headers the
// chain's own features need to the policy, leaving exactly the consumer's
// lists.
//
// Default: with DPoP enabled, DPoP is an allowed request header and
// DPoP-Nonce and WWW-Authenticate are exposed response headers; with CSRF
// protection reading a token header, that header is allowed. Without these, a
// browser page on another origin cannot send a DPoP proof or a CSRF token, nor
// read a DPoP nonce, unless the consumer lists them.
func WithoutAutomaticCORSHeaders() CORSOption {
	return func(l *corsLayer) error {
		l.manual = true

		return nil
	}
}

// WithoutPreflightCaching sends Access-Control-Max-Age: 0 on an allowed
// preflight, so a browser sends a preflight before every request that needs
// one.
//
// Default: an allowed preflight may be cached for CORSPolicy.MaxAge, 10
// minutes when MaxAge is zero. Setting MaxAge as well fails construction.
func WithoutPreflightCaching() CORSOption {
	return func(l *corsLayer) error {
		l.noPreflightCache = true

		return nil
	}
}

// Header names the CORS layer adds for the chain's own features.
const (
	headerDPoP            = "DPoP"
	headerDPoPNonce       = "DPoP-Nonce"
	headerWWWAuthenticate = "WWW-Authenticate"
)

// follow adds the headers the chain's enabled features need, unless the
// consumer turned the additions off. It runs once, when the chain is built.
func (l *corsLayer) follow(dpop bool, csrfTokenHeader string) {
	if !l.manual {
		if dpop {
			l.allowHeader(headerDPoP)
			l.expose(headerDPoPNonce)
			l.expose(headerWWWAuthenticate)
		}

		if csrfTokenHeader != "" {
			l.allowHeader(csrfTokenHeader)
		}
	}

	l.deriveClientLists()
}

// expose adds name to the exposed response headers, unless a spelling of it is
// already there.
func (l *corsLayer) expose(name string) {
	if slices.ContainsFunc(l.exposedNames, func(e string) bool { return strings.EqualFold(e, name) }) {
		return
	}

	l.exposedNames = append(l.exposedNames, name)
	l.exposed = strings.Join(l.exposedNames, ", ")
}

// allowedOrigin returns the Access-Control-Allow-Origin value for the
// request's origin, and false when the origin is not allowed.
func (l *corsLayer) allowedOrigin(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}

	// "*" answers every origin with "*" before the origin is parsed, so "null"
	// and a malformed origin are allowed too, and nothing is reflected.
	if slices.Equal(l.exact, []string{corsAnyOrigin}) {
		return corsAnyOrigin, true
	}

	scheme, host, port, err := parseOrigin(raw)
	if err != nil {
		return "", false
	}

	origin := joinOrigin(scheme, host, port)

	if slices.Contains(l.exact, origin) {
		return origin, true
	}

	if slices.ContainsFunc(l.patterns, func(p originPattern) bool { return p.matches(scheme, host, port) }) {
		return origin, true
	}

	return "", false
}

// allowHeader adds name to the allowed request headers, unless a spelling of
// it is already there.
func (l *corsLayer) allowHeader(name string) {
	key := strings.ToLower(name)
	if _, ok := l.headers[key]; !ok {
		l.headers[key] = name
	}
}

// Header names of the CORS protocol.
const (
	headerOrigin           = "Origin"
	headerVary             = "Vary"
	headerRequestMethod    = "Access-Control-Request-Method"
	headerRequestHeaders   = "Access-Control-Request-Headers"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerExposeHeaders    = "Access-Control-Expose-Headers"
	headerMaxAge           = "Access-Control-Max-Age"
	preflightVary          = headerOrigin + ", " + headerRequestMethod + ", " + headerRequestHeaders
)

// isPreflight reports whether req is a CORS preflight: an OPTIONS request
// carrying Origin and Access-Control-Request-Method.
func isPreflight(req Request) bool {
	return req.Method() == http.MethodOptions &&
		req.HeaderValues(headerOrigin) != nil &&
		req.HeaderValues(headerRequestMethod) != nil
}

// preflight answers req with 204, and the allow headers when its origin, its
// method and every header it asks for are allowed.
func (l *corsLayer) preflight(ex *Exchange, scope corsScope) error {
	w := ex.Writer
	w.AddHeader(headerVary, preflightVary)

	if origin, ok := l.allowedOrigin(ex.Request.Header(headerOrigin)); ok {
		if allowed, ok := l.preflightHeaders(ex.Request, scope); ok {
			l.allow(w, origin, scope)
			w.SetHeader(headerAllowMethods, l.methodsValue)

			if allowed != "" {
				w.SetHeader(headerAllowHeaders, allowed)
			}

			w.SetHeader(headerMaxAge, l.maxAge)
		}
	}

	w.WriteHeader(http.StatusNoContent)

	return nil
}

// preflightHeaders checks the requested method and headers, and returns the
// Access-Control-Allow-Headers value naming the requested ones, in the
// policy's spelling.
func (l *corsLayer) preflightHeaders(req Request, scope corsScope) (string, bool) {
	allowedHeaders := l.headers
	if scope == corsScopeClient {
		allowedHeaders = l.clientHeaders
	}

	if !slices.Contains(l.methods, req.Header(headerRequestMethod)) {
		return "", false
	}

	var names []string

	for _, line := range req.HeaderValues(headerRequestHeaders) {
		for item := range strings.SplitSeq(line, ",") {
			item = strings.ToLower(strings.Trim(item, " \t"))
			if item == "" {
				continue
			}

			name, ok := allowedHeaders[item]
			if !ok {
				return "", false
			}

			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}

	return strings.Join(names, ", "), true
}

// Intercept sets the CORS headers of an actual request and calls next.
//
// The headers are set before next, so a refusal from a later interceptor is
// readable by an allowed origin's script, and Origin is added to Vary on every
// response, so no cache serves one origin's answer to another.
func (l *corsLayer) Intercept(ex *Exchange, next Next) error {
	scope := l.provider.corsScope(ex.Request.Path())

	if scope == corsScopeBrowser {
		// The provider's pages and redirects are for the user's own browser. They
		// answer no cross-origin script, so no CORS header is set and a preflight
		// is not answered; the request is handled as if CORS were off.
		ex.Writer.AddHeader(headerVary, headerOrigin)

		return next(ex)
	}

	if isPreflight(ex.Request) {
		return l.preflight(ex, scope)
	}

	w := ex.Writer
	w.AddHeader(headerVary, headerOrigin)

	if origin, ok := l.allowedOrigin(ex.Request.Header(headerOrigin)); ok {
		l.allow(w, origin, scope)

		exposed := l.exposed
		if scope == corsScopeClient {
			exposed = l.clientExposed
		}

		if exposed != "" {
			w.SetHeader(headerExposeHeaders, exposed)
		}
	}

	return next(ex)
}

// allow sets the headers every allowed response carries. The provider's
// client endpoints never allow credentials.
func (l *corsLayer) allow(w ResponseWriter, origin string, scope corsScope) {
	w.SetHeader(headerAllowOrigin, origin)

	if l.credentials && scope != corsScopeClient {
		w.SetHeader(headerAllowCredentials, "true")
	}
}

// corsOrigins returns the CORS layer's normalised exact origins and its
// patterns, both nil when CORS is not enabled. The exact list is corsAnyOrigin
// alone when every origin is allowed. It is what CSRF protection reads to
// trust the same origins.
func (c *config) corsOrigins() (exact []string, patterns []originPattern) {
	_ = eachInterceptor(c, func(l *corsLayer) error {
		exact, patterns = slices.Clone(l.exact), slices.Clone(l.patterns)

		return nil
	})

	return exact, patterns
}
