package authenticate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -source=jwt.go -package=authenticate_test -destination=jwt_mock_test.go -typed
//go:generate mockgen -destination=verifier_mock_test.go -package=authenticate_test -typed github.com/kartaladev/scrty/token Verifier

// JWTOption configures the bearer-token provider.
//
// A nil option is skipped, so a consumer who builds the slice conditionally
// need not filter it first.
type JWTOption func(*JWTAuthenticator)

// WithJWTVerifier supplies the verifier every presented token is checked by.
//
// It is required and has no default. A verifier decides which issuers, which
// signing keys, which audience and which clock skew are acceptable, and there
// is no answer to that a library could invent: one invented here would either
// accept tokens the deployment never meant to trust, or reject every token it
// issues.
//
// A nil verifier, including a non-nil interface holding a nil pointer, is the
// same as supplying none.
func WithJWTVerifier(v token.Verifier) JWTOption {
	return func(a *JWTAuthenticator) { a.verifier = v }
}

// WithJWTIDGenerator replaces the generator that names an authentication whose
// token carries no identifier this library can use.
//
// The default is id.NewV7Generator. It is consulted only as a fallback: a token
// whose jti is a canonical identifier names the authentication itself, so the
// event and the token it came from carry the same name.
//
// A nil generator is a configuration error rather than a silent return to the
// default, because a consumer supplying one means their records are keyed by
// its identifiers.
func WithJWTIDGenerator(g id.Generator) JWTOption {
	return func(a *JWTAuthenticator) { a.ids = g; a.idsSet = true }
}

// JWTAuthenticator resolves a bearer token through a token verifier. It is an
// Authenticator.
//
// Build it with NewJWTAuthenticator; the zero value is not usable, because it
// has no verifier. Every field is fixed at construction, so it is safe for
// concurrent use.
type JWTAuthenticator struct {
	verifier token.Verifier

	ids    id.Generator
	idsSet bool
}

// NewJWTAuthenticator returns a provider that resolves BearerCredentials
// through a token verifier.
//
// WithJWTVerifier is required. Defaults: id.NewV7Generator, for the identifier
// an authentication takes when its token carries none this library can use.
//
// Nothing here parses or trusts a token itself. The verifier is the only thing
// that reads one, and this provider builds a principal only from what the
// verifier reported — never from an unverified segment of the presented string.
func NewJWTAuthenticator(opts ...JWTOption) (*JWTAuthenticator, error) {
	a := &JWTAuthenticator{}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}

	if nilcheck.IsNil(a.verifier) {
		return nil, fmt.Errorf("%w: a token verifier is required; supply WithJWTVerifier", ErrConfig)
	}
	if a.idsSet && nilcheck.IsNil(a.ids) {
		return nil, fmt.Errorf("%w: the authentication identifier generator is nil", ErrConfig)
	}
	if a.ids == nil {
		a.ids = id.NewV7Generator()
	}

	return a, nil
}

// Authenticate verifies the presented token and resolves the caller from its
// claims.
//
// A verification failure is returned as errors.Join(ErrAuthenticationFailed,
// err), so a caller matches the uniform failure while an operator's log still
// records which check the token failed. Joining rather than wrapping keeps both
// matchable without deciding which of the two is the "real" error.
//
// A verified token with no subject is refused. A principal with no username
// satisfies every check that asks only whether someone is authenticated, while
// naming nobody the consumer's store could recognise, so it must not exist.
func (a *JWTAuthenticator) Authenticate(ctx context.Context, c identity.Credentials) (*Authentication, error) {
	creds, ok := c.(BearerCredentials)
	if !ok {
		return nil, ErrUnsupportedCredentials
	}

	claims, err := a.verifier.Verify(ctx, creds.Token())
	if err != nil {
		return nil, errors.Join(ErrAuthenticationFailed, err)
	}
	if claims == nil || claims.Subject() == "" {
		return nil, ErrAuthenticationFailed
	}

	eventID, err := a.eventID(claims)
	if err != nil {
		return nil, err
	}

	// Dropped now that the token has been accepted, for the same reason a
	// password is wiped: nothing downstream needs the credential, and a result
	// that carried it would spread it into every log and trace that records
	// what authenticated the request.
	if err := creds.Cleanup(); err != nil {
		return nil, diag.Wrap(err, "authenticate: clearing the presented token")
	}

	return &Authentication{
		ID:          eventID,
		Credentials: creds,
		Principal:   &identity.Principal{Username: claims.Subject()},
		Time:        time.Now(),
	}, nil
}

// eventID names the authentication after the token that caused it.
//
// A jti in this library's canonical layout is used as it stands, so the
// authentication and the token share one name and a consumer can join their
// records on it. An issuer is free to mint jti values in any format it likes,
// though, and refusing a token the verifier accepted because its identifier is
// not a UUID would refuse a perfectly valid credential over a detail this
// library does not own. Such a token is named by the generator instead: the
// event is still named, and only the correspondence with the token is lost.
func (a *JWTAuthenticator) eventID(claims *token.Claims) (id.ID, error) {
	if fromToken, err := id.Parse(claims.ID()); err == nil {
		return fromToken, nil
	}

	generated, err := a.ids.NewID()
	if err != nil {
		return id.Nil, fmt.Errorf("authenticate: naming the authentication: %w", err)
	}

	return generated, nil
}

var _ Authenticator = (*JWTAuthenticator)(nil)

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
