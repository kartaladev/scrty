package httpsec_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// A default public web client's offline grant ends with its sign-in, end to end through the chain's logout.
func TestOIDCProvider_PublicWebClientOfflineGrantEndsAtLogout(t *testing.T) {
	t.Parallel()

	f := newSignInEnds(t, endsSetup{logoutFirst: true})
	require.NoError(t, f.registry.Put(t.Context(), oidcprovider.Client{
		ID: "spa", Name: "SPA", Type: oidcprovider.Public, RedirectURIs: []string{rpCallback},
		Scopes:     strings.Fields(endsOffline),
		GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
	}))
	s := f.signIn(t)
	require.NoError(t, f.consents.Give(t.Context(), s.UserID, "spa", strings.Fields(endsOffline), true, f.clk.Now()))
	handle, flow := f.park(t, "spa", func(v url.Values) { v.Set("scope", endsOffline) })
	resumed := f.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	require.Equal(t, http.StatusOK, resumed.status, resumed.body)
	code := resumed.redirectTo(t).Query().Get("code")
	require.NotEmpty(t, code)

	send := func(form url.Values) flowAnswer {
		form.Set("client_id", "spa")
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+"/oauth2/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return f.serve(t, r, nil)
	}
	got := send(exchangeOf(code))
	require.Equal(t, http.StatusOK, got.status, got.body)
	var doc struct {
		Refresh string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(got.body), &doc))
	require.NotEmpty(t, doc.Refresh)

	require.Equal(t, http.StatusOK, f.logoutAs(t, s).status)
	refused := send(refreshOf(doc.Refresh))
	assert.Equal(t, http.StatusBadRequest, refused.status, refused.body)
	assert.Contains(t, refused.body, "invalid_grant")
}

// A client with no refresh grant is told of a logout, end to end through the chain.
func TestOIDCProvider_ClientWithoutRefreshGrantGetsLogoutToken(t *testing.T) {
	t.Parallel()

	f := newSignInEnds(t, endsSetup{logoutFirst: true})
	require.NoError(t, f.registry.Put(t.Context(), oidcprovider.Client{
		ID: "code-only", Name: "Code only", Type: oidcprovider.Confidential, Secret: []byte(tokenSecret),
		RedirectURIs: []string{rpCallback}, Scopes: []string{"openid", "profile"},
		BackChannelLogoutURI: endsLogoutURI,
	}))
	s := f.signIn(t)
	require.NoError(t, f.consents.Give(t.Context(), s.UserID, "code-only", []string{"openid", "profile"}, false, f.clk.Now()))
	handle, flow := f.park(t, "code-only", func(v url.Values) { v.Set("scope", "openid profile") })
	resumed := f.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	require.Equal(t, http.StatusOK, resumed.status, resumed.body)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+"/oauth2/token",
		strings.NewReader(exchangeOf(resumed.redirectTo(t).Query().Get("code")).Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("code-only", tokenSecret)
	got := f.serve(t, r, nil)
	require.Equal(t, http.StatusOK, got.status, got.body)
	assert.NotContains(t, got.body, "refresh_token")

	require.Equal(t, http.StatusOK, f.logoutAs(t, s).status)
	assert.Equal(t, []string{s.FamilyID.String()}, sidsOf(f.toldOf(t)))
}
