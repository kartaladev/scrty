// Package token issues and verifies signed JSON Web Tokens for an
// authenticated principal.
//
// # What no configuration can invert
//
// The signing algorithm is pinned by the key: verification selects the key by
// the token's kid from the key source's current set and checks the signature
// with the algorithm recorded on that key, never with the one the token's own
// header claims. A token whose header names a different algorithm, or none,
// therefore never verifies, and no option enables unsigned tokens. Expiry is
// always required. The issuer and the audience are enforced exactly when the
// consumer configured one.
//
// # The subject
//
// The subject of an issued token is the principal's username. Renaming a user
// therefore invalidates their live tokens, which is the documented cost of
// carrying a name a consumer's own systems can read rather than an opaque
// identifier.
//
// # No jwx in the public surface
//
// No exported signature in this package carries a type from the underlying
// JOSE library: tokens travel as strings, keys arrive through
// signingkey.KeySource, and verified claims are read through Claims. The JOSE
// stack can therefore be replaced without breaking a consumer.
//
// Verification has nothing to refetch: the keys come from an in-process key
// source, so there is no JWKS endpoint to poll and no network call on the
// verification path.
package token

import (
	"errors"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ErrTokenInvalid identifies every rejection of a token. The specific cause is
// wrapped, so errors.Is(err, ErrTokenInvalid) answers "was this token
// refused?" while the wrapped error says why.
//
// A failure to obtain the key set, and a context cancelled before the check
// finished, are not rejections: each is returned as itself and deliberately
// does not match ErrTokenInvalid, so an outage is never reported as a failed
// authentication.
//
// Nothing on the issue path matches it either. ErrTokenInvalid is the verdict
// on a token a caller presented, and issuing has no such token: a consumer who
// maps it to "credential refused" must never see it from Generate.
var ErrTokenInvalid = errors.New("token: invalid")

// Claims are the claims of a token that has been verified. There is no way to
// obtain one from a token that was not verified.
type Claims struct {
	tok jwt.Token
}

// Subject reports the principal's username, as carried in sub. It is empty
// when the token carries no subject.
func (c *Claims) Subject() string {
	sub, _ := c.tok.Subject()

	return sub
}

// ID reports the token identifier the caller supplied at issue, as carried in
// jti. On the session path this is the session identifier. It is empty when the
// token carries no identifier.
func (c *Claims) ID() string {
	id, err := jwt.Get[string](c.tok, jwt.JwtIDKey)
	if err != nil {
		return ""
	}

	return id
}
