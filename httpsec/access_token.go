package httpsec

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
)

// AccessToken is the access token a resource server accepted for the request, as its source verified
// it. Read it with AccessTokenFromContext; each read is the caller's own copy.
type AccessToken struct {
	// Resource is the identifier of the resource server that accepted the token.
	Resource string

	// Issuer, Subject and ClientID are the token's iss, sub and client: client_id, or azp for a
	// source that accepts untyped tokens and found only that.
	Issuer, Subject, ClientID string

	// Audience and Scopes are the token's aud and its granted scopes, read from scope or scp.
	Audience, Scopes []string

	// IssuedAt and ExpiresAt bound the token's life; AuthTime is when its user signed in, and the
	// zero time when the token does not say.
	IssuedAt, ExpiresAt, AuthTime time.Time

	// ACR and AMR are the authentication context the sign-in reached and the methods it used, as
	// the token states them. They are statements, not proof of a second factor.
	ACR string
	AMR []string

	// Confirmation is the token's cnf: jkt or x5t#S256, and empty for an unbound token.
	Confirmation map[string]string

	// Claims are the token's claims, unchanged, for a remote issuer's or an introspection source's
	// token; empty for the chain provider's own, whose facts are the fields above.
	Claims map[string]any
}

// accessTokenKey is the context key the accepted access token is published under.
type accessTokenKey struct{}

// withAccessToken publishes t on a context derived from ctx.
func withAccessToken(ctx context.Context, t *AccessToken) context.Context {
	return context.WithValue(ctx, accessTokenKey{}, t)
}

// AccessTokenFromContext returns the access token the resource server accepted for the request, and
// false when the request was not authenticated by one. The token is a deep copy: a handler that
// changes it changes nothing another reader sees.
func AccessTokenFromContext(ctx context.Context) (*AccessToken, bool) {
	if ctx == nil {
		return nil, false
	}

	t, ok := ctx.Value(accessTokenKey{}).(*AccessToken)
	if !ok || t == nil {
		return nil, false
	}

	return t.clone(), true
}

// clone is a deep copy of t.
func (t *AccessToken) clone() *AccessToken {
	c := *t
	c.Audience = slices.Clone(t.Audience)
	c.Scopes = slices.Clone(t.Scopes)
	c.AMR = slices.Clone(t.AMR)
	c.Confirmation = maps.Clone(t.Confirmation)

	if t.Claims != nil {
		c.Claims, _ = cloneClaim(t.Claims).(map[string]any)
	}

	return &c
}

// cloneClaim is a deep copy of a decoded JSON value: objects and arrays are copied, every other
// value is immutable.
func cloneClaim(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = cloneClaim(e)
		}

		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = cloneClaim(e)
		}

		return s
	default:
		return v
	}
}

// accessTokenCredentials is the credential an accepted access token is published as: it names the
// first-factor kind, factor.AccessToken for the chain provider's own tokens and
// factor.ExternalAccessToken for every other source's, and holds no secret. external says the
// caller names no local user (claims only, or a mapper's caller declared external), so no event
// takes its principal's identifier for a user reference.
type accessTokenCredentials struct {
	kind     factor.Kind
	external bool
}

// Type is the factor kind, as a credentials type: "access-token" or "external-access-token".
func (c accessTokenCredentials) Type() identity.CredentialsType {
	return identity.CredentialsType(c.kind)
}

// Cleanup has nothing to wipe: the token itself is never kept.
func (c accessTokenCredentials) Cleanup() error { return nil }

// Kind is the first-factor kind the token stands for.
func (c accessTokenCredentials) Kind() factor.Kind { return c.kind }
