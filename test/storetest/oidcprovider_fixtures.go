package storetest

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
)

// The provider suites' fixtures. Every instant is dated from suiteStart, so a store
// judging anything by the wall clock, which is years before it, is caught. The cases
// that must also catch the opposite date their records long before the wall clock
// (longAgo).
const (
	opClient      = "billing-web"
	opOtherClient = "billing-ios"
	opIssuer      = "https://idp.example.com"
	opOtherIssuer = "https://other-idp.example.com"
	opUpstream    = "x-9"
	opOtherStream = "x-10"
)

// longAgo is a date the wall clock has long passed.
var longAgo = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

// opSignIn returns a local sign-in of user in family n, with every field set.
func opSignIn(user string, n int) oidcprovider.SignIn {
	return oidcprovider.SignIn{
		User:              identity.UserID(user),
		Family:            suiteID(n),
		AuthenticatedAt:   suiteStart.Add(-time.Hour),
		AMR:               []string{"pwd", "otp"},
		ACR:               "urn:example:loa:2",
		AbsoluteExpiresAt: suiteStart.Add(12 * time.Hour),
	}
}

// userID returns user as a user reference.
func userID(user string) identity.UserID { return identity.UserID(user) }

// opDigest returns the n-th digest a suite uses.
func opDigest(n byte) []byte {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = n
	}

	return digest
}

// assertNoDigest requires err's text to carry digest in none of the forms it could be
// rendered in.
func assertNoDigest(t *testing.T, err error, digest []byte) {
	t.Helper()

	text := err.Error()
	assert.NotContains(t, text, string(digest), "an error must not carry a digest")
	assert.NotContains(t, text, hex.EncodeToString(digest), "an error must not carry a digest, in hex")
	assert.NotContains(t, text, base64.RawURLEncoding.EncodeToString(digest), "an error must not carry a digest, in base64")
	assert.NotContains(t, text, base64.StdEncoding.EncodeToString(digest), "an error must not carry a digest, in base64")
}

// utc returns tm normalised, so a store that returns another location conforms.
func utc(tm time.Time) time.Time { return tm.UTC() }

// selectorShape is one valid shape of a SignInSelector, with a sign-in it selects and
// a sign-in it must not.
type selectorShape struct {
	name string
	sel  oidcprovider.SignInSelector
	// in is selected. out shares every fact of in but the one the shape turns on.
	in, out oidcprovider.SignIn
}

// selectorShapes returns the five valid shapes.
func selectorShapes() []selectorShape {
	federated := func(user string, n int, issuer, session string) oidcprovider.SignIn {
		s := opSignIn(user, n)
		s.ExternalIssuer, s.ExternalSessionID = issuer, session

		return s
	}

	return []selectorShape{
		{
			name: "family",
			sel:  oidcprovider.SignInSelector{Family: suiteID(1)},
			in:   opSignIn("u-1", 1),
			out:  opSignIn("u-1", 2),
		},
		{
			name: "user",
			sel:  oidcprovider.SignInSelector{User: "u-1"},
			in:   opSignIn("u-1", 1),
			out:  opSignIn("u-2", 1),
		},
		{
			name: "user except a family",
			sel:  oidcprovider.SignInSelector{User: "u-1", ExceptFamily: suiteID(2)},
			in:   opSignIn("u-1", 1),
			out:  opSignIn("u-1", 2),
		},
		{
			name: "upstream issuer and session",
			sel:  oidcprovider.SignInSelector{ExternalIssuer: opIssuer, ExternalSessionID: opUpstream},
			in:   federated("u-1", 1, opIssuer, opUpstream),
			out:  federated("u-1", 1, opIssuer, opOtherStream),
		},
		{
			name: "user and upstream issuer",
			sel:  oidcprovider.SignInSelector{User: "u-1", ExternalIssuer: opIssuer},
			in:   federated("u-1", 1, opIssuer, opUpstream),
			out:  federated("u-1", 1, opOtherIssuer, opUpstream),
		},
	}
}

// selectorsWithinUser returns the shapes naming a user and something more, each of which
// stays within that user. selectorShapes cannot show it, as its out differs from its in
// by the one fact a shape turns on, and here the user is not that fact.
func selectorsWithinUser() map[string]oidcprovider.SignInSelector {
	return map[string]oidcprovider.SignInSelector{
		"user except a family":     {User: "u-1", ExceptFamily: suiteID(9)},
		"user and upstream issuer": {User: "u-1", ExternalIssuer: opIssuer},
	}
}

// invalidSelectors returns selectors of no valid shape, the empty one first.
func invalidSelectors() map[string]oidcprovider.SignInSelector {
	return map[string]oidcprovider.SignInSelector{
		"empty":                  {},
		"family and user":        {Family: suiteID(1), User: "u-1"},
		"family and except":      {Family: suiteID(1), ExceptFamily: suiteID(2)},
		"family and issuer":      {Family: suiteID(1), ExternalIssuer: opIssuer},
		"except alone":           {ExceptFamily: suiteID(2)},
		"issuer alone":           {ExternalIssuer: opIssuer},
		"session alone":          {ExternalSessionID: opUpstream},
		"user and session":       {User: "u-1", ExternalSessionID: opUpstream},
		"user, issuer, session":  {User: "u-1", ExternalIssuer: opIssuer, ExternalSessionID: opUpstream},
		"user, except, issuer":   {User: "u-1", ExceptFamily: suiteID(2), ExternalIssuer: opIssuer},
		"except, issuer, stream": {ExceptFamily: suiteID(2), ExternalIssuer: opIssuer, ExternalSessionID: opUpstream},
	}
}
