package httpsec

import (
	"fmt"
	"net/http"
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
		// that answer; an error says the deployment has a problem.
		return fmt.Errorf("httpsec: the public key set could not be read: %w", err)
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.WriteHeader(http.StatusOK)
	_, err = ex.Writer.Write(set)

	return err
}
