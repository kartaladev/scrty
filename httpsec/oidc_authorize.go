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

// oidcAuthorizeParams names what the authorization endpoint reads from a GET's query.
// A Request reads its query by name, and an unknown parameter is ignored in any case, so
// a parameter left out of this list is one the provider does not act on.
var oidcAuthorizeParams = []string{
	"client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "resource", "request", "request_uri", "prompt",
	"max_age", "display", "id_token_hint", "dpop_jkt", "login_hint", "ui_locales",
	"claims_locales", "acr_values",
}

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
// refused with ratelimit.ErrThrottled before the request is read.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-authorize", or else an in-memory limiter of 300 per source a minute. A deployment
// of more than one replica supplies a factory or a limiter its replicas share, or the
// limit is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read
// as no limit while the consumer believed they had replaced one.
func WithOIDCAuthorizeLimiter(l ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCAuthorizeLimiter", "limiter", l); err != nil {
			return err
		}

		op.authorize.throttle.limiter = l

		return nil
	}
}

// WithOIDCAuthorizeBodyLimit reads at most n bytes of a form POST to the authorization
// endpoint.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of
// zero or less is refused, because it would refuse every form POST.
func WithOIDCAuthorizeBodyLimit(n int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if n <= 0 {
			return newConfigError("WithOIDCAuthorizeBodyLimit takes a positive bound, and %d would refuse "+
				"every form POST", n)
		}

		op.authorize.bodyLimit = n

		return nil
	}
}

// serve answers a request to the authorization endpoint. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. a method it does not serve, and a request not made over TLS, are refused with
//     nothing read from them;
//  3. the source is asked before anything else is read, so a throttled source costs no
//     parsing, no client lookup and no store write;
//  4. the provider judges the request. What it cannot answer by redirect goes to the
//     chain's error handling, with no Location, and anything else is a 303.
//
// A request that parks is charged to its source, as is one naming an invalid client or
// redirect URI. An answer that writes nothing and names a registered client is not, and
// neither is a failure, which is no verdict on the source.
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
		return ratelimit.ErrThrottled
	}

	params, err := readOIDCAuthorizeParams(ex.Request, g.bodyLimit)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	presented, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))
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

// readOIDCAuthorizeParams reads a request's parameters: a POST's from its form body and
// never its query, and a GET's from its query. A body that is not a form, or does not
// parse, has named no client that could be redirected to.
func readOIDCAuthorizeParams(r Request, limit int64) (url.Values, error) {
	if r.Method() != http.MethodPost {
		params := url.Values{}

		for _, name := range oidcAuthorizeParams {
			if values := r.QueryValues(name); len(values) > 0 {
				params[name] = values
			}
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
func oidcCookieName(p *oidcprovider.Provider, name string) string {
	if strings.HasPrefix(p.Issuer(), "http://") {
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
