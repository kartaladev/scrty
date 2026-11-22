package httpsec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

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
// consumer's error handler matching either reaches it, and a sentinel StatusForError
// already maps, so the default answer is the right status with no body.
//
// TODO(C2): when the error-propagation helper gains its own rows for
// oidcprovider.ErrInvalidUserCode (400) and oidcprovider.ErrUserCodeThrottled (429),
// errOIDCInvalidUserCode no longer needs to borrow ErrMalformedRequest's row.
var (
	errOIDCInvalidUserCode = fmt.Errorf("httpsec: invalid user code: %w: %w",
		ErrMalformedRequest, oidcprovider.ErrInvalidUserCode)
	errOIDCUserCodeThrottled = fmt.Errorf("%w: %w", ErrOIDCThrottled, oidcprovider.ErrUserCodeThrottled)
)

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
}

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

// settle shares the chain's rate-limiter factory with the provider's user-code entry
// throttle, when the consumer configured one and the provider has the grant. The
// factory is asked here, so its error fails New before anything else is built from it.
// The limiter is handed over in the last check New runs, so a chain that fails for any
// other reason leaves the provider as it found it.
//
// The provider keeps a limiter its consumer gave it (oidcprovider.WithUserCodeEntryLimiter)
// and refuses a second, different one, which is what a second chain over the same
// provider with another factory hands it: that fails New rather than splitting the
// counts between the two.
func (g *oidcDeviceEntryGroup) settle(c *config) error {
	if !g.op.deviceServed() || c.limiterFactory == nil {
		return nil
	}

	limiter, err := c.limiterFactory.NewLimiter(oidcDeviceEntryFlow,
		oidcprovider.DefaultUserCodeEntryLimit, oidcprovider.DefaultUserCodeEntryWindow)
	if err != nil {
		return newConfigError("%s could not build its limiter for namespace %q: %s",
			optionOIDCProvider, oidcDeviceEntryFlow, err)
	}

	c.checkAfterWiring(func() error {
		if err := g.op.provider.UseUserCodeEntryLimiter(limiter); err != nil {
			return newConfigError("%s could not hand the provider the limiter for namespace %q from "+
				"WithRateLimiterFactory: %v", optionOIDCProvider, oidcDeviceEntryFlow, err)
		}

		return nil
	})

	return nil
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
//     missing, empty or repeated user_code, or parameters that do not parse, are refused
//     as an invalid user code before the provider is asked;
//  4. a form POST with no flow cookie is bounced to a GET carrying the code, by
//     bounceOIDCPost, with nothing set, claimed or charged, as at the authorization
//     endpoint;
//  5. the provider throttles, claims and parks, from the source the chain resolved
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
		return errOIDCInvalidUserCode
	}

	code, err := readOIDCUserCode(ex.Context(), ex.Request, g.bodyLimit)
	if err != nil {
		return err
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
// exactly one non-empty user_code is an invalid user code, and a body over limit is
// ErrRequestTooLarge.
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
	if len(codes) != 1 || codes[0] == "" {
		return "", errOIDCInvalidUserCode
	}

	return codes[0], nil
}
