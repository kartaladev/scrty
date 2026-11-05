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
// process-global setting in the underlying JOSE library can widen that.
//
// A verifier checks the issuer and the audience of every token. NewVerifier
// refuses to construct one that is given neither an issuer nor an explicit
// waiver of the issuer check, and likewise for the audience, so two services
// sharing a key source do not accept each other's tokens because one of them
// left a claim unconfigured. A consumer that does not want a check waives it by
// name, with WithoutVerifyIssuer or WithoutVerifyAudience, and accepts in
// writing what that gives up. A generator verifies the tokens it issues, so
// NewGenerator applies the same rule through WithIssuer or WithoutIssuer, and
// WithAudience or WithoutAudience; a waived claim is then neither issued nor
// checked.
//
// A token must be presented exactly as it was issued — one compact JWS, three
// unpadded base64url segments, nothing around it — so one issued token has one
// string that verifies and a consumer may safely key a revocation list, a
// replay cache or a rate-limit bucket on it. Verify also refuses a string
// longer than a configurable maximum before decoding anything, so the work an
// unauthenticated request can buy is bounded.
//
// A verifier accepts only the one token type it is for, read from the typ header
// after the signature has been checked, and no option makes it accept any type.
// See "Token types".
//
// These rules are pinned by a test that reads this package's own source and
// fails on any use of the JOSE library outside a reviewed allow-list, because
// a single option could otherwise undo them where no behavioural test would
// notice.
//
// # The subject
//
// The subject of an issued token is, by default, the principal's user
// identifier. A rename does not change it and it is never reassigned to another
// user, so it stays a safe thing for every verifier to key on.
//
// WithUsernameSubject makes it the principal's username instead, for a consumer
// whose own systems read the name. Renaming a user then invalidates their live
// tokens, and a username later given to someone else names that someone else,
// which is the documented cost of that choice.
//
// A subject means only what its reader takes it to mean, so the option on the
// generator must agree with the ones on its readers:
// authenticate.WithJWTUsernameSubject and httpsec.WithBearerUsernameSubject.
// Issuing for a principal with no value for the chosen subject fails with
// ErrNoSubject.
//
// # Token types
//
// Every token declares its kind in its typ header, and a verifier refuses every
// kind but its own as an invalid token, so tokens signed by the same keys, with
// the same issuer and audience, do not stand in for one another (RFC 8725 section
// 3.12). A token with no typ is refused too.
//
// A generator declares TypeFirstParty, "scrty+jwt", and a verifier accepts it, by
// default. WithTokenType replaces the first, and refuses the type of another kind
// of token; WithVerifyTokenType replaces the second, and takes any one type, such
// as TypeAccessToken for a resource server. Types are compared without regard to
// case and with an "application/" prefix ignored.
//
// A Generator's first-party tokens carry its subject mode. Every other kind comes
// from an Issuer, built by NewIssuer over a key source, an algorithm and an issuer
// identifier. It issues a token of the type declared by each Issue, for the
// subject and audience named there, with further claims, which cannot replace the
// token's own. On a verified token, Claims.Audience and Claims.Claim read them
// back.
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
	"slices"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// ErrInvalid identifies every rejection of a token. The specific cause is
// wrapped, so errors.Is(err, ErrInvalid) answers "was this token
// refused?" while the wrapped error says why.
//
// A failure to obtain the key set, and a context cancelled before the check
// finished, are not rejections: each is returned as itself and deliberately
// does not match ErrInvalid, so an outage is never reported as a failed
// authentication.
//
// Nothing on the issue path matches it either. ErrInvalid is the verdict
// on a token a caller presented, and issuing has no such token: a consumer who
// maps it to "credential refused" must never see it from Generate.
var ErrInvalid = errors.New("token: invalid")

// ErrNoSubject reports a principal with no value for the chosen subject: no user
// identifier by default, no username under WithUsernameSubject. Generate returns
// it. httpsec also uses it as the cause when a login's principal has no user
// identifier. Basic uses it only when a provider names no principal at all, not
// for a principal with no user identifier, which Basic allows. Both hold in
// every subject mode, including chains that issue no token, so a consumer
// matches one error whichever way their chain reads a credential. The
// value the other mode would carry does not stand in for it.
// identity.Principal is a plain struct, so a store row with a blank value arrives
// as a principal that names nobody, and a token with sub: "" would be
// indistinguishable from one carrying no subject at all.
//
// Like every failure on the issue path it deliberately does not match
// ErrInvalid: there is no presented token to pass a verdict on.
var ErrNoSubject = errors.New("token: principal has no value for the chosen subject")

// ErrNoTokenID reports that Generate was handed an empty token identifier.
// The identifier becomes jti, which is the session identifier on the session
// path, and Claims.ID cannot tell a token carrying "" from one carrying no
// identifier at all.
//
// Like every failure on the issue path it deliberately does not match
// ErrInvalid.
var ErrNoTokenID = errors.New("token: no token identifier to carry as jti")

// ErrNoVerificationKeys reports that the key source supplied nothing to verify
// against: no keys at all, or an empty list of them. The verifier has then
// reached no verdict on the token, so this deliberately does not match
// ErrInvalid — a consumer who maps every refusal to "credential refused"
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

	// cnf is the confirmation claim, read once at verification, or reported
	// by a consumer's Verifier through NewClaimsWithConfirmation.
	cnf Confirmation
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

// Subject reports the subject the token carries in sub: the principal's user
// identifier by default, or its username when the issuer used
// WithUsernameSubject. The token does not say which, so the reader must be
// configured to match. It is empty when the token carries no subject, and on
// the zero value.
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

// Audience reports the values the token carries in aud. The slice is the caller's
// own. It is empty when the token carries none, on the zero value, and for claims
// a consumer's Verifier reported through NewClaims, which carries none.
func (c *Claims) Audience() []string {
	if c == nil || c.tok == nil {
		return nil
	}

	audience, _ := c.tok.Audience()

	return slices.Clone(audience)
}

// Claim reports the value of the named claim, as the verified token carries it,
// and whether it carries one. Further claims read back as JSON decodes them: a
// list as []any, an object as map[string]any.
//
// The value belongs to these Claims, so a caller must not change one it gets
// back. Reports false on the zero value, and for claims a consumer's Verifier
// reported through NewClaims, which carries none.
func (c *Claims) Claim(name string) (any, bool) {
	if c == nil || c.tok == nil {
		return nil, false
	}

	return c.tok.Field(name)
}
