package authenticate

import "github.com/kartaladev/scrty/identity"

//go:generate mockgen -source=bearer.go -package=authenticate_test -destination=bearercredentials_mock_test.go -typed

// BearerCredentials is the shape the bearer-token provider reads a token from.
//
// It is an interface rather than a concrete type so a consumer whose transport
// already has its own credential type — one that carries a scheme, a source
// header or a tenant alongside the token — can present that type directly
// instead of copying the token into one of this library's.
type BearerCredentials interface {
	identity.Credentials

	// Token reports the token exactly as it was presented, with no scheme,
	// whitespace or quoting around it. A verifier accepts only the string that
	// was issued, so anything this returns but the token itself is rejected.
	Token() string
}

// BearerToken is a token presented as a bearer credential.
type BearerToken struct {
	token string
}

// NewBearerToken returns credentials carrying token.
//
// The caller strips the transport's framing — the "Bearer " prefix of an
// Authorization header, say — before calling this. Doing it here would mean
// guessing at a framing this package cannot see, and a token that survived the
// wrong guess would be one the verifier refuses for reasons that point at the
// issuer.
func NewBearerToken(token string) *BearerToken {
	return &BearerToken{token: token}
}

// Token reports the presented token.
func (c *BearerToken) Token() string {
	if c == nil {
		return ""
	}

	return c.token
}

// Type reports identity.CredentialsJWT.
func (c *BearerToken) Type() identity.CredentialsType { return identity.CredentialsJWT }

// Cleanup drops the token and reports no error.
//
// It cannot wipe it. A Go string is immutable, so unlike the byte slice behind
// a password there is nothing to overwrite in place: the bytes stay resident
// until the garbage collector reclaims them, and a token that was also read
// from a request header is resident there too. That is the stated limit of this
// cleanup. A bearer token is short-lived and the issuer can revoke it, which is
// what the design relies on instead.
//
// Cleaning up an absent credential does nothing and reports no error, so a
// provider's deferred cleanup is safe whether or not it produced a credential.
func (c *BearerToken) Cleanup() error {
	if c == nil {
		return nil
	}

	c.token = ""

	return nil
}

var _ BearerCredentials = (*BearerToken)(nil)
