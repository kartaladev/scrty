package oidcprovider

import (
	"context"
	"reflect"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

//go:generate mockgen -destination=claimsource_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider ClaimSource

// The scope the default claim source releases anything for, and the claims it releases.
const (
	scopeProfile = "profile"

	claimName              = "name"
	claimPreferredUsername = "preferred_username"
)

// ClaimSource says what UserInfo answers about a user, beyond sub. WithClaimSource supplies one.
// With none, the provider reads the user it has just loaded from Deps.Users: for the scope profile,
// their display name as name and their username as preferred_username, and for no other scope
// anything, as an identity.Details holds no email or verified state to release for the scope email.
//
// A source decides which scopes release which claims, a standard claim or one of its own, and is
// given the token's scopes to do so. What it returns is answered unchanged, except that a claim whose
// value is null or empty is left out, and sub is always the token's own.
//
// An error is a dependency failure and no verdict on the token, and it is not repeated to anyone. A
// source is asked only about a user who exists and is active. It is called on the request's context,
// and returning that context's error is how a source says the caller left.
type ClaimSource interface {
	// Claims returns user's claims for scopes. The map stays the source's: the provider copies from
	// it and never changes it.
	Claims(ctx context.Context, user identity.UserID, scopes []string) (map[string]any, error)
}

// identityClaims is the default claim source, over a user already loaded.
func identityClaims(details *identity.Details, scopes []string) map[string]any {
	if !slices.Contains(scopes, scopeProfile) {
		return nil
	}

	return map[string]any{claimName: details.Name, claimPreferredUsername: details.Username}
}

// absentClaim says a claim's value is one the user does not have: null, or empty, as OIDC Core §5.3.2
// asks of a claim not returned. false and zero are values.
func absentClaim(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String, reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Pointer:
		return v.IsNil()
	default:
		return false
	}
}
