package httpsec

import (
	"context"
	"net/http"

	"github.com/kartaladev/scrty/internal/diag"
)

//go:generate mockgen -destination=keysetprovider_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec KeySetProvider

// DefaultJWKSPath is the path the key set is served on when the consumer names
// none. It is the conventional discovery location, so a client configured with
// nothing but the issuer finds the keys where every other deployment puts
// them.
const DefaultJWKSPath = "/.well-known/jwks.json"

// KeySetProvider produces the public verification keys, already encoded as a
// JSON Web Key Set.
//
// There is no default: a library that invented a key set would serve keys
// nothing signs with. The signing-key manager this library ships satisfies it,
// and so does a consumer's own source of published keys.
//
// What it returns is served unchanged, so an implementation returns the public
// half and nothing else: the bytes handed back are the bytes every client on
// the internet reads.
type KeySetProvider interface {
	// JWKS returns the key set document. ctx is the request's own context,
	// with no deadline of the library's added: an implementation over a
	// remote key service should honour it. The endpoint is public and asked on
	// every fetch, so such an implementation is expected to cache.
	//
	// An error is a dependency failure, never a refusal: the endpoint serves
	// nothing in its place, and the error reaches the consumer's error handler
	// behind fixed library text, answered 500 by the default status mapping,
	// with the provider's own error reachable through errors.Is and errors.As.
	JWKS(ctx context.Context) ([]byte, error)
}

// jwksEndpoint serves the public key set.
type jwksEndpoint struct {
	pathDeclarations

	keys KeySetProvider

	// declaredPath is where the options placed the endpoint, without the base
	// path; path is where it answers, settled by resolvePaths.
	declaredPath string
	path         string
}

// Intercept serves the key set on its own path, and passes everything else
// through untouched.
//
// Only GET: the key set is something to read, and answering a write on it
// would claim a path the consumer may have routed for something else. The
// response is served before any authentication interceptor has run, because a
// client verifying a token has no token to present yet.
func (j *jwksEndpoint) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodGet || ex.Request.Path() != j.path {
		return next(ex)
	}

	set, err := j.keys.JWKS(ex.Context())
	if err != nil {
		// Propagated, not swallowed. An empty set served with a 200 would tell
		// every client that every signature is invalid, and they would cache
		// that answer; an error says the deployment has a problem. The text is
		// fixed rather than the provider's own, which a consumer's key source
		// may word with whatever it holds; its error stays reachable.
		return diag.Wrap(err, "httpsec: the public key set could not be read")
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(set)

	return err
}

// JWKSOption configures the key set endpoint. Each replaces one of the
// defaults named on EnableJWKSEndpoint.
type JWKSOption func(*jwksEndpoint) error

// EnableJWKSEndpoint serves the public key set at the key set slot.
//
// Default: GET on DefaultJWKSPath, answered 200 with a JSON content type and
// whatever the provider returned, unchanged. The downstream handler is never
// called, and every other request — including a POST on that path — passes
// through untouched.
//
// The slot is the outermost of the built-ins, because a client fetching the
// keys to verify a token with has no token to be authenticated by.
func EnableJWKSEndpoint(keys KeySetProvider, opts ...JWKSOption) Option {
	const option = "EnableJWKSEndpoint"

	return func(c *config) error {
		j := &jwksEndpoint{keys: keys, declaredPath: DefaultJWKSPath}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(j); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "key set provider", keys)
		})

		c.register(j, OrderJWKS)

		return nil
	}
}

// WithJWKSEndpointPath serves the key set on path instead.
//
// Default: DefaultJWKSPath, "/.well-known/jwks.json", which keeps passing
// through once the consumer moves the endpoint — a deployment that serves the
// conventional location through its own route is free to. The path is within
// the base path (WithBasePath): with a base path of "/auth", the default answers
// "/auth/.well-known/jwks.json", which is no longer a well-known URI (RFC 8615
// roots those at the top of the path), so clients find the key set through the
// provider's published jwks_uri. An empty path is refused: it would match
// nothing, so the endpoint the consumer asked for would silently not exist.
func WithJWKSEndpointPath(path string) JWKSOption {
	return func(j *jwksEndpoint) error {
		if err := checkEndpointPath("WithJWKSEndpointPath", path); err != nil {
			return err
		}

		j.declaredPath = path
		j.declare("WithJWKSEndpointPath", path)

		return nil
	}
}

// endpoints declares the key set.
func (j *jwksEndpoint) endpoints() []Endpoint {
	return []Endpoint{
		declare("EnableJWKSEndpoint", "WithJWKSEndpointPath", OperationKeySet, j.path,
			MatchExact, PassThrough, RequiresNothing, http.MethodGet),
	}
}
