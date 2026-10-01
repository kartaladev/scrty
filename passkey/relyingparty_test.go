package passkey_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey"
)

func TestRelyingParty_Validate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		rp     passkey.RelyingParty
		assert func(t *testing.T, err error)
	}

	refused := func(field string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, passkey.ErrConfig)
			assert.Contains(t, err.Error(), field)
		}
	}
	accepted := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	rp := func(id string, origins ...string) passkey.RelyingParty {
		return passkey.RelyingParty{ID: id, Name: "Example", Origins: origins}
	}

	cases := []testCase{
		{name: "same host origin", rp: rp("example.com", "https://example.com"), assert: accepted},
		{name: "subdomain origin", rp: rp("example.com", "https://login.example.com"), assert: accepted},
		{name: "origin with port", rp: rp("example.com", "https://example.com:8443"), assert: accepted},
		{name: "host compared case-insensitively", rp: rp("Example.com", "https://LOGIN.example.COM"), assert: accepted},
		{name: "loopback development origin", rp: rp("localhost", "http://localhost:8080"), assert: accepted},
		{name: "loopback subdomain origin", rp: rp("app.localhost", "http://app.localhost:3000"), assert: accepted},
		{name: "missing ID", rp: rp("", "https://example.com"), assert: refused("relying-party ID")},
		{name: "ID with scheme", rp: rp("https://example.com", "https://example.com"), assert: refused("relying-party ID")},
		{name: "ID with port", rp: rp("example.com:443", "https://example.com"), assert: refused("relying-party ID")},
		{name: "ID with path", rp: rp("example.com/login", "https://example.com"), assert: refused("relying-party ID")},
		{name: "ID with trailing dot", rp: rp("example.com.", "https://example.com"), assert: refused("relying-party ID")},
		{name: "ID with empty label", rp: rp("example..com", "https://example.com"), assert: refused("relying-party ID")},
		{
			// WebAuthn scopes credentials to a domain, so an IP address is
			// no relying-party ID, loopback or not.
			name:   "IP address ID",
			rp:     rp("127.0.0.1", "http://127.0.0.1:3000"),
			assert: refused("relying-party ID"),
		},
		{
			name:   "empty name",
			rp:     passkey.RelyingParty{ID: "example.com", Name: " ", Origins: []string{"https://example.com"}},
			assert: refused("relying-party name"),
		},
		{name: "no origins", rp: rp("example.com"), assert: refused("origins")},
		{name: "origin outside the relying party", rp: rp("example.com", "https://example.org"), assert: refused("origin")},
		{name: "origin merely ending with the ID", rp: rp("example.com", "https://badexample.com"), assert: refused("origin")},
		{name: "plain http outside loopback", rp: rp("example.com", "http://example.com"), assert: refused("origin")},
		{name: "loopback IP origin for localhost", rp: rp("localhost", "http://127.0.0.1:3000"), assert: refused("origin")},
		{name: "origin with path", rp: rp("example.com", "https://example.com/app"), assert: refused("origin")},
		{name: "origin with trailing slash", rp: rp("example.com", "https://example.com/"), assert: refused("origin")},
		{name: "origin with query", rp: rp("example.com", "https://example.com?x=1"), assert: refused("origin")},
		{name: "origin with user info", rp: rp("example.com", "https://u@example.com"), assert: refused("origin")},
		{name: "relative origin", rp: rp("example.com", "example.com"), assert: refused("origin")},
		{name: "other scheme", rp: rp("example.com", "ftp://example.com"), assert: refused("origin")},
		{
			name:   "one bad origin among good ones",
			rp:     rp("example.com", "https://example.com", "https://example.net"),
			assert: refused("origin"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.rp.Validate())
		})
	}
}
