package httpsec

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/kartaladev/scrty/internal/origin"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// oidcDeviceAuthorizationFlow names the device authorization endpoint's rate-limit
// buckets and sampler keys.
const oidcDeviceAuthorizationFlow = "oidc-device-authorization"

// oidcDeviceEntryFlow is the namespace the chain's rate-limiter factory is asked for the
// provider's user-code entry limiter under.
const oidcDeviceEntryFlow = "oidc-device-entry"

// oidcUserCodeParam is the parameter the code-entry endpoint reads the user code from.
const oidcUserCodeParam = "user_code"

// The code-entry endpoint's refusals. Each wraps the provider's own sentinel, so a
// consumer's error handler matching either reaches it, and StatusForError answers it
// through the provider's sentinel's row: 400 for an invalid code, 429 for a throttled one.
var (
	errOIDCInvalidUserCode   = fmt.Errorf("httpsec: invalid user code: %w", oidcprovider.ErrInvalidUserCode)
	errOIDCUserCodeThrottled = fmt.Errorf("%w: %w", ErrOIDCThrottled, oidcprovider.ErrUserCodeThrottled)

	// errOIDCUserCodePlainHTTP is a code entry refused for arriving without TLS. It is
	// answered as an invalid code, so a page learns nothing it would not from a wrong
	// one, but its own text lets a log tell a misrouted deployment from a mistyped code.
	errOIDCUserCodePlainHTTP = fmt.Errorf("httpsec: code entry refused over plain HTTP: %w", errOIDCInvalidUserCode)
)

// oidcUserCodeMaxLen bounds the bytes of a user code the code-entry endpoint reads, and
// so what it ever echoes into a Location. The longest code any format may have
// (oidcprovider.WithUserCodeFormat) is 32 characters, shown with at most 7 dashes, 39 bytes;
// 64 leaves room for a separator a person types after nearly every character. A longer
// value cannot be a code, and is refused as an invalid one before anything is redirected,
// claimed or charged.
const oidcUserCodeMaxLen = 64

// The Sec-Fetch-Site value a navigation within one site carries. same-origin and none are
// csrf.go's.
const fetchSameSite = "same-site"

// deviceGrantOption records that setting, an option that only means something for a
// provider with the device grant, was given, so check can refuse it on one without.
func (op *oidcEndpoints) deviceGrantOption(setting string) {
	op.deviceSettings = append(op.deviceSettings, setting)
}

// deviceServed reports whether the provider serves the device endpoints, which it does
// only when it enabled the device grant.
func (op *oidcEndpoints) deviceServed() bool {
	return op.provider.DeviceEnabled()
}

// served reports whether the chain answers endpoint e.
func (op *oidcEndpoints) served(e OIDCEndpoint) bool {
	switch e {
	case OIDCDeviceAuthorization, OIDCDeviceEntry:
		return op.deviceServed()
	default:
		return true
	}
}

// checkDeviceSettings refuses an option for the device endpoints on a provider that
// does not serve them: the consumer configured something that would never run, which
// is a wiring mistake, not a default to fall back to.
func (op *oidcEndpoints) checkDeviceSettings(*config) error {
	if op.deviceServed() || len(op.deviceSettings) == 0 {
		return nil
	}

	return newConfigError("%s was given %s, but the provider has not enabled the device grant, so the "+
		"device endpoints are not served: enable it with oidcprovider.WithDeviceAuthorization, or remove "+
		"the option", optionOIDCProvider, op.deviceSettings[0])
}

// oidcDeviceAuthorizationGroup serves the device authorization endpoint (RFC 8628
// section 3.1).
type oidcDeviceAuthorizationGroup struct {
	oidcGroupBase

	throttle  oidcClientThrottle
	bodyLimit int64
}

// bind takes the provider's state, and the defaults the options replace.
func (g *oidcDeviceAuthorizationGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcDeviceAuthorizationGroup) routes() []oidcRoute {
	if !g.op.deviceServed() {
		return nil
	}

	return []oidcRoute{
		{path: g.op.paths[OIDCDeviceAuthorization], handle: g.serve},
	}
}

// settle builds the throttle only for a provider that serves the endpoint, so a chain
// without the grant asks its factory for nothing in the namespace.
func (g *oidcDeviceAuthorizationGroup) settle(c *config) error {
	if !g.op.deviceServed() {
		return nil
	}

	return g.throttle.settle(c, oidcDeviceAuthorizationFlow)
}

func (g *oidcDeviceAuthorizationGroup) wire(ch *Chain) {
	g.throttle.wire(ch)
}

func (g *oidcDeviceAuthorizationGroup) flushRefusalLogs() error {
	g.throttle.flush()

	return nil
}

// WithOIDCDeviceAuthorizationLimiter counts the device authorization endpoint's failed
// client authentications through limiter.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-device-authorization", or else an in-memory limiter of 10 failures per source in
// 15 minutes. It is the token endpoint's rule with a budget of its own, so failures at
// one endpoint never spend the other's. A deployment of more than one replica supplies a
// factory or a limiter its replicas share, or the limit is per process.
//
// A source past its limit, a limiter that cannot answer and a source that cannot be
// attributed are all refused as invalid_client, as at the token endpoint: the limit fails
// closed, and a client cannot tell it from a wrong credential.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read
// as no limit while the consumer believed they had replaced one. So is the option on a
// provider without the device grant, which serves no such endpoint.
func WithOIDCDeviceAuthorizationLimiter(limiter ratelimit.Limiter) OIDCProviderOption {
	const option = "WithOIDCDeviceAuthorizationLimiter"

	return func(op *oidcEndpoints) error {
		if err := requireDep(option, "limiter", limiter); err != nil {
			return err
		}

		op.deviceAuthorization.throttle.limiter = limiter
		op.deviceGrantOption(option)

		return nil
	}
}

// WithOIDCDeviceAuthorizationBodyLimit reads at most limit bytes of a device
// authorization request's body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed or any
// client is known, and a body over it answers ErrRequestTooLarge. A limit of zero or less
// is refused, because it would refuse every request, and so is the option on a provider
// without the device grant.
func WithOIDCDeviceAuthorizationBodyLimit(limit int64) OIDCProviderOption {
	const option = "WithOIDCDeviceAuthorizationBodyLimit"

	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("%s takes a positive bound, and %d would refuse every device "+
				"authorization request", option, limit)
		}

		op.deviceAuthorization.bodyLimit = limit
		op.deviceGrantOption(option)

		return nil
	}
}

// oidcDeviceAuthorizationDocument is a successful device authorization response (RFC
// 8628 section 3.2).
type oidcDeviceAuthorizationDocument struct {
	DeviceCode              string `json:"device_code"` //nolint:gosec // G117: the code is the document's purpose
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// serve answers a request to the device authorization endpoint. The order is the token
// endpoint's, and so is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but POST is refused, and so is a request not made over TLS, as the chain
//     reports the connection, unless the provider was built with the loopback issuer,
//     each with nothing read from it;
//  3. the source is asked before anything else is read, so a throttled source costs no
//     parsing and no secret comparison, and is refused as invalid_client;
//  4. the body is read, bounded, and the query only for credentials to refuse it for,
//     exactly as the token endpoint reads them;
//  5. the provider authenticates the client and issues, once.
//
// A protocol refusal is answered in the token endpoint's form, and invalid_client is
// charged to the source. A failure goes to the chain's error handling.
func (g *oidcDeviceAuthorizationGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return writeOIDCRefusal(ex, oidcprovider.CodeInvalidRequest)
	}

	src, ok := g.throttle.admit(ex, g.op)
	if !ok {
		return writeOIDCRefusal(ex, oidcprovider.CodeInvalidClient)
	}

	creds, err := readOIDCClientRequest(ex.Context(), ex.Request, g.bodyLimit)
	if err != nil {
		return g.throttle.answer(ex, src, err)
	}

	res, err := g.op.provider.AuthorizeDevice(ex.Context(), oidcprovider.DeviceAuthorizationRequest{
		Credentials: creds,
		Form:        creds.Form,
		Query:       creds.Query,
	})
	if err != nil {
		return g.throttle.answer(ex, src, err)
	}

	return writeSuccessDocument(ex, oidcDeviceAuthorizationDocument{
		DeviceCode:              res.DeviceCode,
		UserCode:                res.UserCode,
		VerificationURI:         res.VerificationURI,
		VerificationURIComplete: res.VerificationURIComplete,
		ExpiresIn:               res.ExpiresIn,
		Interval:                res.Interval,
	})
}

// oidcDeviceEntryGroup serves the code-entry endpoint, where a browser enters the user
// code a device shows (RFC 8628 section 3.3). The provider throttles the entries itself
// (oidcprovider.Provider.EnterUserCode), so the group holds no throttle of its own; it
// hands the provider the chain's rate-limiter factory instead.
type oidcDeviceEntryGroup struct {
	oidcGroupBase

	bodyLimit int64

	// page is the consumer's code-entry page, read by settle, which the gate sends a GET it
	// will not claim from to.
	page *url.URL

	// chain is the chain the group is wired into, which the gate's refusal record is
	// written through (its logger, sampler and clock).
	chain *Chain
}

// wire keeps the chain, whose logger, sampler and clock are read when a record is written.
func (g *oidcDeviceEntryGroup) wire(ch *Chain) { g.chain = ch }

// bind takes the provider's state, and the default the options replace.
func (g *oidcDeviceEntryGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcDeviceEntryGroup) routes() []oidcRoute {
	if !g.op.deviceServed() {
		return nil
	}

	return []oidcRoute{
		{path: g.op.paths[OIDCDeviceEntry], handle: g.serve},
	}
}

// settle checks that the gate's redirect cannot loop, keeps the consumer's code-entry page
// for it, and arranges to hand the provider's user-code entry throttle the chain's
// rate-limiter factory (nil when the consumer configured none), the namespace
// "oidc-device-entry" and the chain's source keyer, so the throttle counts where the chain's
// other throttles count and keys sources as they do (WithIPv6SourcePrefix).
//
// The hand-over is the last step that may refuse New (handOverLast), so a chain that fails
// for any other reason leaves the provider as it found it. The provider keeps a limiter or a
// keyer its consumer gave it (oidcprovider.WithUserCodeEntryLimiter, WithUserCodeEntryKeyer),
// and refuses a second, different hand-over: a second chain over the same provider with
// another factory or prefix fails New rather than splitting the counts.
func (g *oidcDeviceEntryGroup) settle(c *config) error {
	if !g.op.deviceServed() {
		return nil
	}

	page, err := g.checkEntryPage()
	if err != nil {
		return err
	}

	g.page = page

	c.handOverLast(func() error {
		if err := g.op.provider.UseUserCodeEntryLimiter(c.limiterFactory, oidcDeviceEntryFlow, c.keyer); err != nil {
			return newConfigError("%s could not hand the provider its rate-limiter factory for namespace %q "+
				"and its source keying: %v", optionOIDCProvider, oidcDeviceEntryFlow, err)
		}

		return nil
	})

	return nil
}

// checkEntryPage reads the consumer's code-entry page, which the gate redirects a GET it
// will not claim from to, and refuses one on which that redirect could loop.
//
// The redirect is a 303 the browser follows from a navigation that was not the user's own,
// so the GET it makes carries Sec-Fetch-Site of cross-site again: the Fetch standard judges
// a redirected request against the origin that started it, across every URL of the chain.
// Were the page the code-entry endpoint itself, the endpoint would redirect it there again,
// until the browser gave up. So the page is refused when its path, decoded, cleaned of
// empty and trailing segments and compared without regard to letter case, is the
// endpoint's public path (the issuer's path and the served path) or its served path alone,
// which the chain answers at whatever the issuer's path is: every spelling a router might
// serve as the endpoint is covered, and a page that merely resembles it is refused too,
// which costs nothing.
//
// A page on another site would loop too, once the user submitted the form there: the
// cookieless POST is bounced to a GET whose chain begins on that site. The provider refuses
// any page off the issuer's origin (oidcprovider.WithDeviceAuthorization), and the
// endpoint's public URL is on the issuer's origin, so that loop cannot be built; the origin
// is compared again here, as a backstop.
func (g *oidcDeviceEntryGroup) checkEntryPage() (*url.URL, error) {
	raw := g.op.provider.DeviceEntryURL()

	page, err := url.Parse(raw)
	if err != nil || !origin.Same(raw, g.op.provider.Issuer()) {
		return nil, newConfigError("%s has a code-entry page (oidcprovider.WithDeviceAuthorization) that is no "+
			"URL on the issuer's origin", optionOIDCProvider)
	}

	served := g.op.paths[OIDCDeviceEntry]
	pagePath := normaliseLoopPath(page.Path)

	for _, endpoint := range []string{g.op.publicPath(served), served} {
		if pagePath != normaliseLoopPath(endpoint) {
			continue
		}

		return nil, newConfigError("%s serves the code-entry endpoint (OIDCDeviceEntry) at %q, and the "+
			"code-entry page given to oidcprovider.WithDeviceAuthorization is that path, so a link the "+
			"endpoint will not claim from would be redirected to itself without end: give the page a "+
			"path of its own, or move the endpoint with WithOIDCProviderPath", optionOIDCProvider, endpoint)
	}

	return page, nil
}

// normaliseLoopPath is p decoded, cleaned of empty and trailing segments and lower-cased,
// the form in which two paths a router might serve as one are equal.
func normaliseLoopPath(p string) string {
	if decoded, err := url.PathUnescape(p); err == nil {
		p = decoded
	}

	return strings.ToLower(path.Clean("/" + p))
}

// WithOIDCDeviceEntryBodyLimit reads at most limit bytes of a form POST to the
// code-entry endpoint.
//
// Default: DefaultLoginBodyLimit. A body over it answers ErrRequestTooLarge. A limit of
// zero or less is refused, because it would refuse every form POST, and so is the option
// on a provider without the device grant.
//
// The entry throttle is the provider's: oidcprovider.WithUserCodeEntryLimiter replaces
// it, and the chain's WithRateLimiterFactory supplies it under namespace
// "oidc-device-entry" when the consumer gave the provider none.
func WithOIDCDeviceEntryBodyLimit(limit int64) OIDCProviderOption {
	const option = "WithOIDCDeviceEntryBodyLimit"

	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("%s takes a positive bound, and %d would refuse every form POST",
				option, limit)
		}

		op.deviceEntry.bodyLimit = limit
		op.deviceGrantOption(option)

		return nil
	}
}

// serve answers a request to the code-entry endpoint. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. a method it does not serve, and a request not made over TLS, are refused with
//     nothing read from them, the latter as an invalid user code (400);
//  3. the code is read, from a GET's query or a form POST's body and never both, and a
//     missing, empty, repeated or overlong (oidcUserCodeMaxLen) user_code, or parameters
//     that do not parse, are refused as an invalid user code before the provider is asked
//     and before anything echoes it;
//  4. a GET the browser does not report as its own navigation (ownNavigation) is sent
//     with 303 to the consumer's code-entry page with the code prefilled, with nothing
//     set, claimed or charged, so the user confirms the code there and submits it, under
//     the chain's CSRF check: a link from anywhere cannot claim a code. This holds whether
//     or not EnableCSRFProtection is given, and has no option;
//  5. a form POST with no flow cookie is bounced to a GET carrying the code, by
//     bounceOIDCPost, with nothing set, claimed or charged, as at the authorization
//     endpoint;
//  6. the provider throttles, claims and parks, from the source the chain resolved
//     (trusted proxies included). Its flow secret is set as the cookie whenever it
//     answers one the browser does not hold, on a failure too: a claim it may have
//     written is bound to that secret, and only the browser holding it can recover the
//     claim.
//
// A throttled entry answers 429 and an invalid code 400, both with no body, through the
// chain's error handling, which a consumer's handler may render. Neither says which
// check failed. A failure goes there too.
func (g *oidcDeviceEntryGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	method := ex.Request.Method()
	if method != http.MethodGet && method != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodGet+", "+http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return errOIDCUserCodePlainHTTP
	}

	code, err := readOIDCUserCode(ex.Context(), ex.Request, g.bodyLimit)
	if err != nil {
		return err
	}

	if method == http.MethodGet && !ownNavigation(ex.Request) {
		return g.toEntryPage(ex, code)
	}

	presented, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCFlowCookie))
	if method == http.MethodPost && presented == "" {
		return bounceOIDCPost(ex, g.op.publicURL(g.op.paths[OIDCDeviceEntry]), url.Values{oidcUserCodeParam: {code}})
	}

	browser, _ := ex.Request.Cookie(oidcCookieName(g.op.provider, OIDCBrowserSessionCookie))

	res, err := g.op.provider.EnterUserCode(ex.Context(), oidcprovider.DeviceEntryInput{
		UserCode:             code,
		FlowSecret:           presented,
		BrowserSessionSecret: browser,
		Source:               ex.Request.ClientIP(),
		IdleTimeout:          g.op.sessions.IdleTimeout(),
	})

	if res.FlowSecret != "" && res.FlowSecret != presented {
		setOIDCCookie(ex.Writer, g.op.provider, OIDCFlowCookie, res.FlowSecret)
	}

	if err != nil {
		return oidcUserCodeRefusal(err)
	}

	ex.Writer.SetHeader("Location", res.Location)
	ex.Writer.WriteHeader(http.StatusSeeOther)

	return nil
}

// ownNavigation reports whether the browser reports a request as its own navigation:
// exactly one Sec-Fetch-Site line, of same-origin, same-site or none, or none at all (a
// client that is no browser, or a browser too old to send it). The value is compared
// exactly, as the Fetch standard writes it: another case, an empty value, a list or a
// second line is no browser's, and is not trusted.
func ownNavigation(r Request) bool {
	values := r.HeaderValues(headerSecFetchSite)

	switch len(values) {
	case 0:
		return true
	case 1:
		switch values[0] {
		case fetchSameOrigin, fetchSameSite, fetchNone:
			return true
		}
	}

	return false
}

// msgDeviceEntryGated is the record of a GET carrying a code that the gate sent to the
// entry page instead of claiming from.
const msgDeviceEntryGated = "httpsec: a code-entry link from another site was sent to the entry page"

// gatedSourceMaxLen bounds the Sec-Fetch-Site text a gated record carries, which the
// requester wrote.
const gatedSourceMaxLen = 64

// toEntryPage sends the browser to the consumer's code-entry page with code prefilled as
// user_code, keeping the page's own query. Nothing is set, claimed or charged. It leaves
// Referrer-Policy to the chain's headers: the code is in the Location either way, and a
// policy of no-referrer would hide from the entry page which site sent the user.
//
// The redirect is recorded, one record per source per refusal-log window
// (WithRefusalLogInterval) through the chain's logger, naming the source and the
// Sec-Fetch-Site the request carried, so a phishing campaign is visible; the user code is
// never in it, nor in the sampler's key.
func (g *oidcDeviceEntryGroup) toEntryPage(ex *Exchange, code string) error {
	g.logGated(ex)

	page := *g.page
	query := page.Query()
	query.Set(oidcUserCodeParam, code)
	page.RawQuery = query.Encode()

	ex.Writer.SetHeader("Location", page.String())
	ex.Writer.WriteHeader(http.StatusSeeOther)

	return nil
}

// logGated writes the gated redirect's sampled record, and nothing when the group has no
// chain to write through.
func (g *oidcDeviceEntryGroup) logGated(ex *Exchange) {
	c := g.chain
	if c == nil || c.logger == nil || c.perRequest == nil {
		return
	}

	source := ex.Request.ClientIP()

	site := strings.Join(ex.Request.HeaderValues(headerSecFetchSite), ", ")
	if len(site) > gatedSourceMaxLen {
		site = site[:gatedSourceMaxLen]
	}

	logSampled(ex.Context(), c.sampler, c.logger, slog.LevelWarn, c.perRequest.now(),
		oidcDeviceEntryFlow+sampleKeySeparator+"gated"+sampleKeySeparator+source, msgDeviceEntryGated,
		slog.String("source", source), slog.String("sec_fetch_site", site))
}

// oidcUserCodeRefusal is the chain's refusal a provider's entry error stands for, or the
// error itself when it is a failure.
func oidcUserCodeRefusal(err error) error {
	switch {
	case errors.Is(err, oidcprovider.ErrUserCodeThrottled):
		return errOIDCUserCodeThrottled
	case errors.Is(err, oidcprovider.ErrInvalidUserCode):
		return errOIDCInvalidUserCode
	default:
		return err
	}
}

// readOIDCUserCode reads the one user code a request carries: a POST's from its form body
// and never its query, and a GET's from its raw query. Both are parsed strictly, with
// url.ParseQuery, so a pair a framework would drop cannot hide a second code. Anything but
// exactly one non-empty user_code of at most oidcUserCodeMaxLen bytes is an invalid user
// code, and a body over limit is ErrRequestTooLarge.
func readOIDCUserCode(ctx context.Context, r Request, limit int64) (string, error) {
	raw := r.RawQuery()

	if r.Method() == http.MethodPost {
		body, err := readBody(ctx, r, limit)

		switch {
		case errors.Is(err, ErrRequestTooLarge):
			return "", ErrRequestTooLarge
		case err != nil:
			return "", err
		case !declaresForm(r.Header("Content-Type")):
			return "", errOIDCInvalidUserCode
		}

		raw = string(body)
	}

	params, err := url.ParseQuery(raw)
	if err != nil {
		return "", errOIDCInvalidUserCode
	}

	codes := params[oidcUserCodeParam]
	if len(codes) != 1 || codes[0] == "" || len(codes[0]) > oidcUserCodeMaxLen {
		return "", errOIDCInvalidUserCode
	}

	return codes[0], nil
}
