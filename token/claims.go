// Package token issues and verifies signed JSON Web Tokens for an
// authenticated principal.
//
// # What no configuration can invert
//
// The signing algorithm is pinned by the key: verification selects the key by
// the token's kid from the key source's current set and checks the signature
// with the algorithm recorded on that key, never with the one the token's own
// header claims. A token whose header names a different algorithm, or none,
// therefore never verifies. No option enables unsigned tokens: the algorithm a
// generator signs with is checked at construction against the algorithms this
// library's key sources can actually produce, so "none" and the symmetric
// family are configuration errors rather than failures at the first token.
//
// Expiry is always required, and every time comparison is made at the
// resolution the configured clock reports: no skew is tolerated, and no
// process-global setting in the underlying JOSE library can widen that. The
// issuer and the audience are enforced exactly when the consumer configured
// one.
//
// A token must be presented exactly as it was issued — one compact JWS, three
// unpadded base64url segments, nothing around it — so one issued token has one
// string that verifies and a consumer may safely key a revocation list, a
// replay cache or a rate-limit bucket on it. Verify also refuses a string
// longer than a configurable maximum before decoding anything, so the work an
// unauthenticated request can buy is bounded.
//
// These rules are pinned by a test that reads this package's own source and
// fails on any use of the JOSE library outside a reviewed allow-list, because
// a single option could otherwise undo them where no behavioural test would
// notice.
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

// ErrNoSubject reports that Generate was handed a principal with no username,
// so there is no subject to name. identity.Principal is a plain struct, so a
// store row with a blank username arrives as a principal that names nobody,
// and a token with sub: "" would be indistinguishable from one carrying no
// subject at all.
//
// Like every failure on the issue path it deliberately does not match
// ErrTokenInvalid: there is no presented token to pass a verdict on.
var ErrNoSubject = errors.New("token: principal has no username to name as subject")

// ErrNoTokenID reports that Generate was handed an empty token identifier.
// The identifier becomes jti, which is the session identifier on the session
// path, and Claims.ID cannot tell a token carrying "" from one carrying no
// identifier at all.
//
// Like every failure on the issue path it deliberately does not match
// ErrTokenInvalid.
var ErrNoTokenID = errors.New("token: no token identifier to carry as jti")

// ErrNoVerificationKeys reports that the key source supplied nothing to verify
// against: no key set at all, or a set holding no keys. The verifier has then
// reached no verdict on the token, so this deliberately does not match
// ErrTokenInvalid — a consumer who maps every refusal to "credential refused"
// must not show a key-service outage as a failed login.
var ErrNoVerificationKeys = errors.New("token: key source supplied no verification keys")

// Claims are the claims of a token that has been verified.
//
// This package produces one only from a completed verification. NewClaims is
// the single other source, and exists because Verifier is an exported port: it
// carries what a consumer's own Verifier verified by its own means. So
// possession of a Claims means some Verifier vouched for the token, not
// necessarily this one.
//
// The zero value is usable and reports every claim as empty.
type Claims struct {
	// tok holds the verified token this package's own verification produced.
	// It is nil for claims a consumer's Verifier reported through NewClaims,
	// which carries them in the two fields below instead.
	tok     jwt.Token
	subject string
	id      string
}

// NewClaims returns the Claims a consumer's own Verifier reports for a token
// it has verified by its own means.
//
// It exists because Verifier is an exported port. A consumer substituting
// their own — a fake in their tests, a shim over a different JOSE library, or
// a wrapper around a remote introspection endpoint — has to be able to produce
// the value their own code then reads, and every field of Claims is
// unexported.
//
// The caller vouches for the verification; this package cannot check it. That
// is the stated limit on the guarantee Claims carries: call this only from a
// Verifier implementation, and only after that implementation has accepted the
// token. Never call it to describe a token that was not checked, and never on
// a path where the resulting Claims could be mistaken for the verdict of a
// verification that did not happen.
func NewClaims(subject, id string) *Claims {
	return &Claims{subject: subject, id: id}
}

// Subject reports the principal's username, as carried in sub. It is empty
// when the token carries no subject, and on the zero value.
func (c *Claims) Subject() string {
	if c == nil {
		return ""
	}
	if c.tok == nil {
		return c.subject
	}

	sub, _ := c.tok.Subject()

	return sub
}

// ID reports the token identifier the caller supplied at issue, as carried in
// jti. On the session path this is the session identifier. It is empty when the
// token carries no identifier, and on the zero value.
func (c *Claims) ID() string {
	if c == nil {
		return ""
	}
	if c.tok == nil {
		return c.id
	}

	id, err := jwt.Get[string](c.tok, jwt.JwtIDKey)
	if err != nil {
		return ""
	}

	return id
}
