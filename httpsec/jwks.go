package httpsec

import (
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
// the internet reads. An error it returns reaches the consumer's error handler
// behind fixed text, matching by identity through errors.Is and errors.As.
type KeySetProvider interface {
	JWKS() ([]byte, error)
}

// jwksEndpoint serves the public key set.
type jwksEndpoint struct {
	keys KeySetProvider

	path string
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

	set, err := j.keys.JWKS()
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
		j := &jwksEndpoint{keys: keys, path: DefaultJWKSPath}

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
// Default: DefaultJWKSPath, which keeps passing through once the consumer
// moves the endpoint — a deployment that serves the conventional location
// through its own route is free to. An empty path is refused: it would match
// nothing, so the endpoint the consumer asked for would silently not exist.
func WithJWKSEndpointPath(path string) JWKSOption {
	return func(j *jwksEndpoint) error {
		if path == "" {
			return newConfigError("WithJWKSEndpointPath was given no path, so the key set " +
				"would be served nowhere")
		}

		j.path = path

		return nil
	}
}
