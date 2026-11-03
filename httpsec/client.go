package httpsec

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/session"
)

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

// resolve answers the resolution of r, its Client above all, and
// ErrHostNotAllowed for a forwarded host on none of the allowed hosts.
func (cr *clientResolver) resolve(r Request) (resolution, error) {
	if cr.proxies != nil {
		return cr.proxies.resolve(r)
	}

	return resolution{client: Client{IP: r.ClientIP(), Secure: cr.httpsDeployment || r.Secure(), Host: r.Host()}}, nil
}

// begin resolves ex's request before the first interceptor runs: it removes
// the consumed forwarded headers, publishes the Client and the request's user
// agent on the exchange's context, the sign-in metadata every first factor
// records (signInMetadata), and, where the answer can differ from the adapter's, wraps the
// request so every interceptor reads the one resolved answer. A refusal leaves
// the exchange's request and context as they were.
//
// The raw forwarded client certificate a trusted proxy sent is kept by the
// resolution before the header is removed, and the wrapped request decodes it
// the first time its certificate is asked for.
func (cr *clientResolver) begin(ex *Exchange) error {
	res, err := cr.resolve(ex.Request)

	cr.removeForwarded(ex.Request)

	if err != nil {
		if errors.Is(err, ErrHostNotAllowed) {
			// The client the trusted proxies named: the host is refused, not
			// the client address.
			emitEvent(ex.Context(), event.Event{
				Name: event.HostRefused, Outcome: event.OutcomeFailure, ClientIP: res.client.IP,
			})
		}

		return err
	}

	ctx := context.WithValue(ex.Context(), clientContextKey{}, res.client)
	ex.SetContext(withSignInUserAgent(ctx, ex.Request.Header("User-Agent")))

	if cr.rewrites() {
		rr := &resolvedRequest{Request: ex.Request, client: res.client, hide: cr.hidden()}
		if res.trustedPeer {
			rr.cert = &forwardedCert{raw: res.forwardedCert, decode: cr.proxies.settings.certDecode}
		}

		ex.Request = rr
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

	// cert is the client certificate a trusted proxy forwarded, and nil when
	// the peer is not a trusted proxy, whose request answers its own
	// connection's certificate.
	cert *forwardedCert
}

// forwardedCert is the client certificate header value a trusted proxy sent,
// decoded once, the first time it is asked for.
type forwardedCert struct {
	raw    string
	decode func(string) (*x509.Certificate, error)

	once sync.Once
	cert *x509.Certificate
}

// certificate is the decoded certificate, and nil when the value is empty,
// does not decode, or decodes to none.
func (f *forwardedCert) certificate() *x509.Certificate {
	f.once.Do(func() {
		if f.raw == "" {
			return
		}

		decode := f.decode
		if decode == nil {
			decode = decodeEscapedPEM
		}

		if cert, err := decode(f.raw); err == nil && cert != nil {
			f.cert = cert
		}
	})

	return f.cert
}

// ClientCertificate is the resolved client certificate, answered to every
// interceptor and judged by certificate binding when it is enabled: a trusted
// proxy's forwarded certificate, or none, from a trusted proxy, and the
// connection's own from any other peer.
func (r *resolvedRequest) ClientCertificate() *x509.Certificate {
	if r.cert != nil {
		return r.cert.certificate()
	}

	return r.Request.ClientCertificate()
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

// signInUserAgentKey is the context key the request's user agent is carried
// under, from where the chain resolves the client to where a login builds its
// session.
type signInUserAgentKey struct{}

// withSignInUserAgent returns ctx carrying ua as the user agent of a sign-in
// made on it. The chain sets it once per request, when it resolves the client
// (clientResolver.begin), so no flow reads the header itself.
func withSignInUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, signInUserAgentKey{}, ua)
}

// signInMetadata is the client address and user agent a sign-in made on ctx
// records (session.WithClientMetadata): the address the chain resolved
// (ClientFromContext) and the user agent withSignInUserAgent carried, each
// empty when absent.
func signInMetadata(ctx context.Context) session.CreateOption {
	client, _ := ClientFromContext(ctx)
	ua, _ := ctx.Value(signInUserAgentKey{}).(string)

	return session.WithClientMetadata(client.IP, ua)
}
