package httpsec

import "context"

// Client is what the chain resolved about who sent a request and how it
// arrived: the address the request is attributed to, whether it reached the
// deployment over TLS, the host the client asked for, and whether a trusted
// proxy supplied any of them.
//
// Without EnableTrustedProxies it holds the transport's own values: the peer,
// the connection's TLS state (or true under WithHTTPSDeployment) and the Host
// header, with ViaProxy false.
type Client struct {
	// IP is the client's address, or "" when the request cannot be attributed
	// to one: a trusted proxy named no address, an obfuscated one, or one that
	// does not parse.
	IP string

	// Secure reports whether the client's request reached the deployment over
	// TLS.
	Secure bool

	// Host is the host the client asked for, port included when one was sent.
	// A host a trusted proxy forwarded is lower-cased, and is always one of
	// ForwardedHost's allowed hosts.
	Host string

	// ViaProxy reports whether a trusted proxy's forwarded headers supplied
	// any of the values above.
	ViaProxy bool
}

// clientContextKey is the context key the resolved Client is stored under.
type clientContextKey struct{}

// ClientFromContext returns the Client the chain resolved for the request ctx
// belongs to: the address, transport security and host every interceptor and
// the handler read, and whether a trusted proxy supplied them.
//
// The chain resolves every request, with or without EnableTrustedProxies, so
// behind the chain it is always there; without trusted proxies it holds the
// transport peer, the connection's TLS state and the Host header, with
// ViaProxy false. It reports false for a context the chain did not run.
func ClientFromContext(ctx context.Context) (Client, bool) {
	c, ok := ctx.Value(clientContextKey{}).(Client)

	return c, ok
}

// clientResolver resolves the Client of each request the chain runs. It is
// built once, at construction.
type clientResolver struct {
	// proxies is the trusted-proxy configuration, and nil without one.
	proxies *trustedProxies

	// httpsDeployment is WithHTTPSDeployment's declaration that every request
	// reached the deployment over TLS.
	httpsDeployment bool
}

// newClientResolver returns the resolver c's options call for.
func newClientResolver(c *config) *clientResolver {
	return &clientResolver{proxies: c.proxies, httpsDeployment: c.httpsDeployment}
}

// rewrites reports whether the resolved values can differ from the adapter's
// own, which is when the adapter's request must be wrapped. Without trusted
// proxies or the HTTPS declaration the request is left exactly as it was.
func (cr *clientResolver) rewrites() bool {
	return cr.proxies != nil || cr.httpsDeployment
}

// resolve answers the Client of r, and ErrHostNotAllowed for a forwarded host
// on none of the allowed hosts.
func (cr *clientResolver) resolve(r Request) (Client, error) {
	if cr.proxies != nil {
		res, err := cr.proxies.resolve(r)

		return res.client, err
	}

	return Client{IP: r.ClientIP(), Secure: cr.httpsDeployment || r.Secure(), Host: r.Host()}, nil
}

// begin resolves ex's request before the first interceptor runs: it removes
// the consumed forwarded headers, publishes the Client on the exchange's
// context and, where the answer can differ from the adapter's, wraps the
// request so every interceptor reads the one resolved answer. A refusal leaves
// the exchange's request and context as they were.
func (cr *clientResolver) begin(ex *Exchange) error {
	client, err := cr.resolve(ex.Request)

	cr.removeForwarded(ex.Request)

	if err != nil {
		return err
	}

	ex.SetContext(context.WithValue(ex.Context(), clientContextKey{}, client))

	if cr.rewrites() {
		ex.Request = &resolvedRequest{Request: ex.Request, client: client, hide: cr.hidden()}
	}

	return nil
}

// hidden is the predicate naming the headers removed after resolution, and nil
// when none are.
func (cr *clientResolver) hidden() func(name string) bool {
	if cr.proxies == nil || cr.proxies.settings.keepHeaders {
		return nil
	}

	return cr.proxies.forwardedHeader
}

// removeForwarded removes the consumed forwarded headers from the request the
// adapter's framework hands on, when the adapter's request can remove headers
// (headerRemover). Every adapter the library provides can.
func (cr *clientResolver) removeForwarded(r Request) {
	hide := cr.hidden()
	if hide == nil {
		return
	}

	if hr, ok := r.(headerRemover); ok {
		hr.DelHeaders(hide)
	}
}

// headerRemover is implemented by an integration's request that can remove
// headers from the request its framework hands to the handlers after the
// chain. DelHeaders removes every header whose name match reports true.
//
// The chain needs it to remove the forwarded headers it consumed
// (EnableTrustedProxies), so code behind the chain cannot read them again with
// looser rules. A request that does not implement it still has them hidden
// from every interceptor, but not from the framework's handlers.
type headerRemover interface {
	DelHeaders(match func(name string) bool)
}

// resolvedRequest is the adapter's request with the resolved client values.
// Everything else is read from the adapter's request unchanged, except the
// removed forwarded headers, which it never returns.
type resolvedRequest struct {
	Request

	client Client

	// hide names the removed forwarded headers, and is nil when none are.
	hide func(name string) bool
}

// ClientIP is the resolved client address.
func (r *resolvedRequest) ClientIP() string { return r.client.IP }

// Host is the resolved host.
func (r *resolvedRequest) Host() string { return r.client.Host }

// Secure is the resolved transport security.
func (r *resolvedRequest) Secure() bool { return r.client.Secure }

// Header is the adapter's header, or "" for a removed forwarded header.
func (r *resolvedRequest) Header(name string) string {
	if r.hide != nil && r.hide(name) {
		return ""
	}

	return r.Request.Header(name)
}

// HeaderValues is the adapter's header lines, or nil for a removed forwarded
// header.
func (r *resolvedRequest) HeaderValues(name string) []string {
	if r.hide != nil && r.hide(name) {
		return nil
	}

	return r.Request.HeaderValues(name)
}
