package httpsec

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// The cookies the provider sets. Their names are fixed: the __Host- prefix is what stops
// another host of the domain planting a value in them, so there is no option to replace
// it. A page that resumes through the Go API (oidcprovider.Provider.Resume) reads them by
// these names. Under an issuer built with oidcprovider.WithLoopbackHTTPIssuer each loses
// the prefix and Secure, because a browser refuses the prefix over plain http.
const (
	// OIDCFlowCookie binds a pending request to the browser that started it.
	OIDCFlowCookie = "__Host-scrty-op-flow"

	// OIDCBrowserSessionCookie holds the provider's browser session.
	OIDCBrowserSessionCookie = "__Host-scrty-op-session"
)

// oidcHostPrefix is what the loopback issuer's cookie names leave out.
const oidcHostPrefix = "__Host-"

// oidcAuthorizeFlow names the authorization endpoint's rate-limit buckets and sampler keys.
const oidcAuthorizeFlow = "oidc-authorize"

// How many requests one source may park or fail on at the authorization endpoint before
// it is refused unread. They are proposed values: everyone behind one address signing in
// at once must fit, while anyone may otherwise fill the pending-request store.
const (
	defaultOIDCAuthorizeLimit  = 300
	defaultOIDCAuthorizeWindow = time.Minute
)

// oidcAuthorizeGroup serves the authorization endpoint.
type oidcAuthorizeGroup struct {
	oidcGroupBase

	throttle  oidcClientThrottle
	bodyLimit int64
}

// bind takes the provider's state, and the default the options replace.
func (g *oidcAuthorizeGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcAuthorizeGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCAuthorize], handle: g.serve},
	}
}

func (g *oidcAuthorizeGroup) settle(c *config) error {
	return g.throttle.settleAt(c, oidcAuthorizeFlow, defaultOIDCAuthorizeLimit, defaultOIDCAuthorizeWindow)
}

func (g *oidcAuthorizeGroup) wire(ch *Chain) {
	g.throttle.wire(ch)
}

func (g *oidcAuthorizeGroup) flushRefusalLogs() error {
	g.throttle.flush()

	return nil
}

// WithOIDCAuthorizeLimiter counts, per source, the requests the authorization endpoint
// parks and those naming an invalid client or redirect URI. A source past its limit is
// refused with ErrOIDCThrottled, which wraps ratelimit.ErrThrottled and answers 429, before
// the request is read. A limiter that cannot answer, and a source that cannot be
// attributed, are refused the same way: the limit fails closed.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-authorize", or else an in-memory limiter of 300 per source a minute. A deployment
// of more than one replica supplies a factory or a limiter its replicas share, or the
// limit is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read
// as no limit while the consumer believed they had replaced one.
func WithOIDCAuthorizeLimiter(limiter ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCAuthorizeLimiter", "limiter", limiter); err != nil {
			return err
		}

		op.authorize.throttle.limiter = limiter

		return nil
	}
}

// WithOIDCAuthorizeBodyLimit reads at most limit bytes of a form POST to the authorization
// endpoint.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of
// zero or less is refused, because it would refuse every form POST.
func WithOIDCAuthorizeBodyLimit(limit int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("WithOIDCAuthorizeBodyLimit takes a positive bound, and %d would refuse "+
				"every form POST", limit)
		}

		op.authorize.bodyLimit = limit

		return nil
	}
}

// serve answers a request to the authorization endpoint. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. a method it does not serve, and a request not made over TLS, are refused with
//     nothing read from them;
//  3. the source is asked before anything else is read, so a throttled source costs no
//     parsing, no client lookup and no store write. A source over the limit, a limiter
//     that cannot answer and a source that cannot be attributed are all refused with
//     ErrOIDCThrottled, which answers 429: this endpoint is visited by a browser, and a
//     401 there reads as "sign the user in";
//  4. a form POST with no flow cookie is bounced to a GET, by bounceOIDCPost, with nothing
//     set, parked or charged;
//  5. the provider judges the request. What it cannot answer by redirect goes to the
//     chain's error handling, with no Location, and anything else is a 303.
//
// A request that parks is charged to its source, as is one naming an invalid client or
// redirect URI. An error redirected to a registered client's redirect URI is not, and
// neither is a failure, which is no verdict on the source.
//
// A code answered from a valid browser session is not charged either, though it writes
// one: it parks nothing, and such a code needs a live browser session, so a source can
// mint no more of them than the sessions it holds. That is accepted.
func (g *oidcAuthorizeGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	method := ex.Request.Method()
	if method != http.MethodGet && method != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodGet+", "+http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return ErrOIDCInvalidAuthorization
	}

	src, ok := g.throttle.admit(ex, g.op)
	if !ok {
		return ErrOIDCThrottled
	}

	params, err := readOIDCAuthorizeParams(ex.Request, g.bodyLimit)
	if err != nil {
		return err
	}

	presented, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))
	if method == http.MethodPost && presented == "" {
		return bounceOIDCPost(ex, g.op.publicURL(g.op.paths[OIDCAuthorize]), params)
	}

	ctx := ex.Context()

	browser, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCBrowserSessionCookie))

	res, err := g.op.provider.Authorize(ctx, oidcprovider.AuthorizeInput{
		Params:               params,
		FlowSecret:           presented,
		BrowserSessionSecret: browser,
		IdleTimeout:          g.op.sessions.IdleTimeout(),
	})
	if err != nil {
		if !errors.Is(err, oidcprovider.ErrInvalidAuthorization) {
			return err
		}

		g.throttle.charge(ctx, src)

		return ErrOIDCInvalidAuthorization
	}

	if res.FlowSecret != "" {
		g.throttle.charge(ctx, src)

		if res.FlowSecret != presented {
			setOIDCCookie(ex.Writer, g.op.provider, OIDCFlowCookie, res.FlowSecret)
		}
	}

	ex.Writer.SetHeader("Location", res.Location)
	ex.Writer.WriteHeader(http.StatusSeeOther)

	return nil
}

// bounceOIDCPost answers a form POST that came with no flow cookie by sending the browser back
// to endpoint, the address the provider publishes, by GET with params in the query. A browser
// sends no SameSite=Lax cookie on a cross-site POST, so such a POST cannot tell a browser that
// holds a flow cookie from one that does not, and setting one would replace the cookie its other
// tabs' parked requests are bound to. The GET a 303 turns it into is a top-level navigation, which
// carries the cookies, the browser session's included. So nothing is set, parked or charged here.
//
// The address is the published one and not the request's path, because a router stripping the
// issuer's path leaves a path the browser cannot reach the chain at.
//
// There is no option to answer such a POST directly, because that would only bring back a way
// for any page to break another tab's request. The cost is that a value sent by POST reaches the
// URL, as a GET's does, where it can be logged, and Referrer-Policy keeps it out of what the next
// page is told. A POST holding the cookie avoids both.
func bounceOIDCPost(ex *Exchange, endpoint string, params url.Values) error {
	location := endpoint
	if query := params.Encode(); query != "" {
		location += "?" + query
	}

	ex.Writer.SetHeader("Referrer-Policy", "no-referrer")
	ex.Writer.SetHeader("Location", location)
	ex.Writer.WriteHeader(http.StatusSeeOther)

	return nil
}

// readOIDCAuthorizeParams reads a request's parameters: a POST's from its form body and
// never its query, and a GET's from its raw query. Both are parsed strictly, with
// url.ParseQuery, on every adapter, because a framework's own query reading drops a pair
// that does not parse, and a pair dropped can hide a repeated redirect_uri, a request_uri
// or a prompt=none. A query or body that does not parse has named no client that could
// be redirected to.
//
// Every parameter is handed to the provider, which reads the ones it knows and ignores
// the rest, so there is no list here to fall out of step with it.
func readOIDCAuthorizeParams(r Request, limit int64) (url.Values, error) {
	if r.Method() != http.MethodPost {
		params, err := url.ParseQuery(r.RawQuery())
		if err != nil {
			return nil, ErrOIDCInvalidAuthorization
		}

		return params, nil
	}

	body, err := r.Body(limit)
	if err != nil {
		return nil, err
	}

	if !declaresForm(r.Header("Content-Type")) {
		return nil, ErrOIDCInvalidAuthorization
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, ErrOIDCInvalidAuthorization
	}

	return params, nil
}

// settleAt builds t's guard under flow with limit and window as its defaults, from a
// group's settle, for an endpoint whose numbers are not a client authentication's.
func (t *oidcClientThrottle) settleAt(c *config, flow string, limit int, window time.Duration) error {
	guard, err := c.resolveSourceGuard(optionOIDCProvider, flow, t.limiter, limit, window, c.refusalInterval)
	if err != nil {
		return err
	}

	t.flow = flow
	t.guard = guard

	return nil
}

// oidcCookieName is the name p's cookie goes by: name, unless p has the loopback issuer.
// The issuer's scheme is compared as parsed, so that "HTTP://127.0.0.1:8080", which is the
// same issuer, loses the prefix too, as plainHTTPAllowed judges it.
func oidcCookieName(p *oidcprovider.Provider, name string) string {
	if issuerIsPlainHTTP(p) {
		return strings.TrimPrefix(name, oidcHostPrefix)
	}

	return name
}

// setOIDCCookie sets one of p's cookies, with the attributes they share. It lasts as long
// as the browser does, because the record its secret names has the deadline that matters.
func setOIDCCookie(w ResponseWriter, p *oidcprovider.Provider, name, value string) {
	named := oidcCookieName(p, name)

	w.SetCookie(&Cookie{
		Name:     named,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   named == name,
		SameSite: http.SameSiteLaxMode,
	})
}
