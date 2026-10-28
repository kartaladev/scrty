package oidc

import "strings"

// linkKey is the identity of a link: provider, issuer and subject together.
// A struct key needs no separator, so no value of one part can be mistaken for
// a boundary between two.
type linkKey struct{ provider, issuer, subject string }

// linkKeyOf returns the key l is stored under.
func linkKeyOf(l Link) linkKey { return linkKey{l.Provider, l.Issuer, l.Subject} }

// emailDomain returns the part of email after its last "@", which is all of
// an email a log record may carry, or "" when there is none.
func emailDomain(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	return email[at+1:]
}
