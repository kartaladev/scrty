package httpsec

import (
	"net/http"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

//go:generate mockgen -destination=clientregistry_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidcprovider ClientRegistry

// The rate-limit buckets and sampler keys of the revocation and introspection endpoints. Each
// counts on its own, so failures at one do not throttle the other.
const (
	oidcRevokeFlow     = "oidc-revoke"
	oidcIntrospectFlow = "oidc-introspect"
)

// oidcClientEndpoint is what an endpoint a client authenticates at keeps of its own.
type oidcClientEndpoint struct {
	throttle  oidcClientThrottle
	bodyLimit int64
}

// oidcRevokeGroup serves the revocation and introspection endpoints.
type oidcRevokeGroup struct {
	oidcGroupBase

	revocation    oidcClientEndpoint
	introspection oidcClientEndpoint
}

// bind takes the provider's state, and the defaults the options replace.
func (g *oidcRevokeGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.revocation.bodyLimit = DefaultLoginBodyLimit
	g.introspection.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcRevokeGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCRevoke], handle: g.serveRevoke},
		{path: g.op.paths[OIDCIntrospect], handle: g.serveIntrospect},
	}
}

func (g *oidcRevokeGroup) settle(c *config) error {
	if err := g.revocation.throttle.settle(c, oidcRevokeFlow); err != nil {
		return err
	}

	return g.introspection.throttle.settle(c, oidcIntrospectFlow)
}

func (g *oidcRevokeGroup) wire(ch *Chain) {
	g.revocation.throttle.wire(ch)
	g.introspection.throttle.wire(ch)
}

func (g *oidcRevokeGroup) flushRefusalLogs() error {
	g.revocation.throttle.flush()
	g.introspection.throttle.flush()

	return nil
}

// WithOIDCRevokeLimiter counts the revocation endpoint's failed client authentications through limiter.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace "oidc-revoke",
// or else an in-memory limiter of 10 failures per source in 15 minutes. A deployment of more than one
// replica supplies a factory or a limiter its replicas share, or the limit is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read as no limit
// while the consumer believed they had replaced one.
func WithOIDCRevokeLimiter(limiter ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCRevokeLimiter", "limiter", limiter); err != nil {
			return err
		}

		op.revoke.revocation.throttle.limiter = limiter

		return nil
	}
}

// WithOIDCIntrospectLimiter counts the introspection endpoint's failed client authentications
// through limiter.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-introspect", or else an in-memory limiter of 10 failures per source in 15 minutes. A
// deployment of more than one replica supplies a factory or a limiter its replicas share, or the
// limit is per process.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read as no limit
// while the consumer believed they had replaced one.
func WithOIDCIntrospectLimiter(limiter ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCIntrospectLimiter", "limiter", limiter); err != nil {
			return err
		}

		op.revoke.introspection.throttle.limiter = limiter

		return nil
	}
}

// WithOIDCRevokeBodyLimit reads at most limit bytes of a revocation request's body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed or any client is known,
// and a body over it answers ErrRequestTooLarge. A limit of zero or less is refused, because it would
// refuse every request.
func WithOIDCRevokeBodyLimit(limit int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("WithOIDCRevokeBodyLimit takes a positive bound, and %d would refuse every "+
				"revocation request", limit)
		}

		op.revoke.revocation.bodyLimit = limit

		return nil
	}
}

// WithOIDCIntrospectBodyLimit reads at most limit bytes of an introspection request's body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed or any client is known,
// and a body over it answers ErrRequestTooLarge. A limit of zero or less is refused, because it would
// refuse every request.
func WithOIDCIntrospectBodyLimit(limit int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("WithOIDCIntrospectBodyLimit takes a positive bound, and %d would refuse "+
				"every introspection request", limit)
		}

		op.revoke.introspection.bodyLimit = limit

		return nil
	}
}

// serveRevoke answers a request to the revocation endpoint (RFC 7009). What it cannot revoke is a
// success, which the provider decides: an empty 200 says the token is no longer of use, and says
// nothing of whether it ever was.
func (g *oidcRevokeGroup) serveRevoke(ex *Exchange, _ Next) error {
	creds, src, ok, err := g.read(ex, &g.revocation)
	if !ok {
		return err
	}

	if err := g.op.provider.Revoke(ex.Context(), creds, creds.Form); err != nil {
		return g.revocation.throttle.answer(ex, src, err)
	}

	ex.Writer.WriteHeader(http.StatusOK)

	return nil
}

// serveIntrospect answers a request to the introspection endpoint (RFC 7662). The provider says
// what the answer holds, and it is sent as it came.
func (g *oidcRevokeGroup) serveIntrospect(ex *Exchange, _ Next) error {
	creds, src, ok, err := g.read(ex, &g.introspection)
	if !ok {
		return err
	}

	answer, err := g.op.provider.Introspect(ex.Context(), creds, creds.Form)
	if err != nil {
		return g.introspection.throttle.answer(ex, src, err)
	}

	return writeSuccessDocument(ex, answer)
}

// read does what both endpoints do before the provider is asked, in an order that is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but POST is refused, and so is a request not made over TLS, as the chain reports the
//     connection, unless the provider was built for a loopback issuer, each with nothing read;
//  3. the source is asked before anything else is read, so a throttled source costs no parsing and
//     no secret comparison;
//  4. the body is read, bounded.
//
// It authenticates no one. The provider does, once, in the call that also judges the token, because
// a client's assertion is single-use. False means the request has been answered, with err to return.
func (g *oidcRevokeGroup) read(ex *Exchange, e *oidcClientEndpoint) (oidcprovider.ClientCredentials, ratelimit.Source, bool, error) {
	var (
		creds oidcprovider.ClientCredentials
		src   ratelimit.Source
	)

	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return creds, src, false, nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return creds, src, false, writeOIDCRefusal(ex, oidcprovider.CodeInvalidRequest)
	}

	src, ok := e.throttle.admit(ex, g.op)
	if !ok {
		return creds, src, false, writeOIDCRefusal(ex, oidcprovider.CodeInvalidClient)
	}

	creds, err := readOIDCClientRequest(ex.Request, e.bodyLimit)
	if err != nil {
		return creds, src, false, e.throttle.answer(ex, src, err)
	}

	return creds, src, true, nil
}
