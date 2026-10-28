package session

import "encoding/base64"

// identifierEncoding is how a session identifier's random bytes are written:
// URL-safe base64 without padding, decoded strictly, so a value whose final
// character carries set spare bits is not a second spelling of one
// identifier.
var identifierEncoding = base64.RawURLEncoding.Strict()

// ValidIdentifier reports whether v has the exact shape of an identifier the
// Sessions issues: identifierBytes of entropy, encoded URL-safe without
// padding, which is 43 characters of the alphabet A–Z, a–z, 0–9, "-" and "_".
//
// It says nothing about whether such a session exists. It is for a caller that
// receives a presented identifier from outside, such as an HTTP bearer, and
// wants to refuse a value that cannot be one before it costs a store lookup.
// An identifier minted by a consumer's own store is not one the Sessions
// issues, and is reported invalid.
func ValidIdentifier(v string) bool {
	if len(v) != identifierEncoding.EncodedLen(identifierBytes) {
		return false
	}

	// The decoder skips carriage returns and line feeds, so the decoded length
	// is checked as well as the encoded one.
	raw, err := identifierEncoding.DecodeString(v)

	return err == nil && len(raw) == identifierBytes
}
