package oidcprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/mail"
	"reflect"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

//go:generate mockgen -destination=claimsource_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider ClaimSource

// The scope the default claim source releases anything for, and the claims it releases.
const (
	scopeProfile = "profile"
	scopeEmail   = "email"

	claimName              = "name"
	claimPreferredUsername = "preferred_username"
	claimEmail             = "email"
	claimEmailVerified     = "email_verified"
)

// ClaimSource says what UserInfo answers about a user, beyond sub. WithClaimSource supplies one.
// With none, the provider reads the user it has just loaded from Deps.Users: for the scope profile,
// their display name as name and their username as preferred_username, and for the scope email, their
// username as email with email_verified false, when the username is exactly an email address. That is
// when mail.ParseAddress accepts it and returns that same address, so "Ada <ada@example.com>" and
// "ada" release neither claim. email_verified is always false from the default source, because a
// username proves nothing about who controls that address, and a true would be a statement it cannot
// stand behind. The address is only released, never used to look up a user. No other scope releases
// anything. A source of the consumer's own replaces all of this, and its email_verified, true
// included, is answered unchanged.
//
// A source decides which scopes release which claims, a standard claim or one of its own, and is
// given the token's scopes to do so. What it returns is answered unchanged, except that a claim whose
// value is null or the empty string is left out, whatever form it takes: a nil, a nil slice or map, a
// nil pointer or one to such a value, a raw JSON null or "". An empty list or object that is not nil
// is kept, and sub is always the token's own.
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
	claims := map[string]any{}
	if slices.Contains(scopes, scopeProfile) {
		claims[claimName], claims[claimPreferredUsername] = details.Name, details.Username
	}
	if slices.Contains(scopes, scopeEmail) && isEmailAddress(details.Username) {
		// Never true: a username proves nothing about who controls the address.
		claims[claimEmail], claims[claimEmailVerified] = details.Username, false
	}

	return claims
}

// isEmailAddress says s is exactly one bare email address, and not a display form such as
// "Ada <ada@example.com>" that mail.ParseAddress also accepts.
func isEmailAddress(s string) bool {
	parsed, err := mail.ParseAddress(s)

	return err == nil && parsed.Address == s
}

// absentClaim says a claim's value is one the user does not have, as OIDC Core §5.3.2 asks of a
// claim not returned: JSON null or the empty string, in any form it can take. That is a nil, a nil
// slice or map, a nil pointer, a pointer to what is itself absent, and a raw JSON null or "". Nothing
// else is: an empty but non-nil list or object is a value the source means, as are false and zero.
func absentClaim(value any) bool {
	if value == nil {
		return true
	}
	if raw, ok := value.(json.RawMessage); ok {
		trimmed := string(bytes.TrimSpace(raw))

		return trimmed == "" || trimmed == "null" || trimmed == `""`
	}

	v := reflect.ValueOf(value)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return true
		}

		v = v.Elem()
		if raw, ok := v.Interface().(json.RawMessage); ok {
			return absentClaim(raw)
		}
	}

	switch v.Kind() {
	case reflect.String:
		return v.Len() == 0
	case reflect.Slice, reflect.Map, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}
