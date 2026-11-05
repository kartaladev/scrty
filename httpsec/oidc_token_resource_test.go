package httpsec_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/oidcprovider"
)

// A client sends a resource it is not allowed at the token endpoint: 400 invalid_target, over HTTP.
func TestOIDCToken_ResourceNotAllowedIsInvalidTarget(t *testing.T) {
	t.Parallel()

	const allowedResource = "https://api.example.com"

	e := newTokenEndpoint(t, tokenSetup{
		clients: []oidcprovider.Client{{
			ID: "resource-app", Type: oidcprovider.Confidential, Secret: []byte(tokenSecret),
			RedirectURIs: []string{rpCallback}, Scopes: []string{"openid"},
			Resources: []string{allowedResource},
		}},
	})

	code := e.issue(t, "resource-app", func(v url.Values) { v.Set("scope", "openid") })
	refused := e.send(t, exchangeOf(code, "resource", "https://nowhere.example.com"), asClient("resource-app"))
	assertTokenRefused(t, refused, oidcprovider.CodeInvalidTarget)
	assert.JSONEq(t, `{"error":"invalid_target"}`, refused.body)

	// The refusal spent nothing: the same code, asking for an allowed resource, is exchanged.
	assertTokenIssued(t, e.send(t, exchangeOf(code, "resource", allowedResource), asClient("resource-app")), "Bearer")
}
