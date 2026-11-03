package oidcprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/oidcprovider"
)

func TestClient_MatchRedirectURI(t *testing.T) {
	t.Parallel()

	web := func(uris ...string) oidcprovider.Client {
		return oidcprovider.Client{ApplicationType: oidcprovider.Web, RedirectURIs: uris}
	}
	native := func(uris ...string) oidcprovider.Client {
		return oidcprovider.Client{ApplicationType: oidcprovider.Native, RedirectURIs: uris}
	}

	type testCase struct {
		name   string
		client oidcprovider.Client
		uri    string
		assert func(t *testing.T, matched bool)
	}

	matches := func(t *testing.T, matched bool) { t.Helper(); assert.True(t, matched) }
	differs := func(t *testing.T, matched bool) { t.Helper(); assert.False(t, matched) }

	const webCB = "https://rp.example.com/cb"
	const nativeCB = "http://127.0.0.1/cb"

	cases := []testCase{
		// The four scenarios of oidc-provider-clients.
		{name: "exact match required", client: web(webCB), uri: webCB + "/", assert: differs},
		{name: "native loopback port varies", client: native(nativeCB), uri: "http://127.0.0.1:51004/cb", assert: matches},
		{name: "loopback path still exact", client: native(nativeCB), uri: "http://127.0.0.1:51004/other", assert: differs},
		{name: "port not relaxed for a web client", client: web(webCB), uri: "https://rp.example.com:8443/cb", assert: differs},

		{name: "the registered URI itself", client: web(webCB), uri: webCB, assert: matches},
		{name: "any registered URI", client: web("https://rp.example.com/a", webCB), uri: webCB, assert: matches},
		{name: "empty", client: web(webCB), uri: "", assert: differs},
		{name: "a query that differs", client: web(webCB + "?a=1"), uri: webCB + "?a=2", assert: differs},
		{name: "case is significant", client: web(webCB), uri: "https://RP.example.com/cb", assert: differs},

		{name: "native IPv6 port varies", client: native("http://[::1]/cb"), uri: "http://[::1]:5000/cb", assert: matches},
		{name: "native registered port varies", client: native("http://127.0.0.1:8080/cb"), uri: "http://127.0.0.1:9090/cb", assert: matches},
		{name: "native registered port dropped", client: native("http://127.0.0.1:8080/cb"), uri: nativeCB, assert: matches},
		{name: "native same query", client: native(nativeCB + "?a=1"), uri: "http://127.0.0.1:5/cb?a=1", assert: matches},
		{name: "native query that differs", client: native(nativeCB + "?a=1"), uri: "http://127.0.0.1:5/cb?a=2", assert: differs},
		{name: "native query added", client: native(nativeCB), uri: "http://127.0.0.1:5/cb?a=1", assert: differs},
		{name: "native fragment added", client: native(nativeCB), uri: "http://127.0.0.1:5/cb#x", assert: differs},
		{name: "native another loopback family", client: native(nativeCB), uri: "http://[::1]:5/cb", assert: differs},
		{name: "native another loopback address", client: native(nativeCB), uri: "http://127.0.0.2:5/cb", assert: differs},
		{name: "native a name is not an IP literal", client: native("http://localhost/cb"), uri: "http://localhost:5000/cb", assert: differs},
		{name: "native user information", client: native(nativeCB), uri: "http://x@127.0.0.1:5/cb", assert: differs},
		{name: "native a host hidden behind user information", client: native(nativeCB), uri: "http://127.0.0.1:5@rp.example.com/cb", assert: differs}, //nolint:gosec // an attack shape under test, not a credential
		{name: "native scheme in capitals", client: native(nativeCB), uri: "HTTP://127.0.0.1:5/cb", assert: differs},
		{name: "native https is not relaxed", client: native("https://127.0.0.1/cb"), uri: "https://127.0.0.1:5/cb", assert: differs},
		{name: "native a port that is not a number", client: native(nativeCB), uri: "http://127.0.0.1:abc/cb", assert: differs},
		{name: "native an empty port", client: native(nativeCB), uri: "http://127.0.0.1:/cb", assert: differs},
		{name: "native a port of zero", client: native(nativeCB), uri: "http://127.0.0.1:0/cb", assert: differs},
		{name: "native a port out of range", client: native(nativeCB), uri: "http://127.0.0.1:65536/cb", assert: differs},
		{name: "native non-loopback IP literal", client: native("http://192.0.2.1/cb"), uri: "http://192.0.2.1:5/cb", assert: differs},
		{name: "native non-loopback host", client: native("http://rp.example.com/cb"), uri: "http://rp.example.com:5/cb", assert: differs},
		{name: "a web client's loopback URI is not relaxed", client: web(nativeCB), uri: "http://127.0.0.1:5/cb", assert: differs},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.client.MatchRedirectURI(tc.uri))
		})
	}
}
