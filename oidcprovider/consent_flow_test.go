package oidcprovider_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// resumeWithoutConsent parks a request for clientID with no consent given, resumes it with no
// answer, and returns what the resume sent the browser to.
func resumeWithoutConsent(t *testing.T, x *exchangeFixture, clientID, redirect, scope string) url.Values {
	t.Helper()

	r := park(t, x.parkFixture, func(v url.Values) {
		asClient(v, clientID, redirect)
		v.Set("scope", scope)
	})
	signIn := testSignIn(x.parkFixture, "u-1")
	res, err := x.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)

	return queryOf(t, res.RedirectTo)
}

func TestProvider_Resume_ConsentIsSkippedWhereTheClientIsTrusted(t *testing.T) {
	t.Parallel()

	both := []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}

	t.Run("a first-party client asking openid profile gets its code with no consent stage", func(t *testing.T) {
		t.Parallel()

		x := newExchangeFixture(t)
		require.NoError(t, x.registry.Put(t.Context(), oidcprovider.Client{
			ID: "first-party-web", Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret), FirstParty: true,
			RedirectURIs: []string{tiedRedirect}, Scopes: []string{"openid", "profile"},
		}))

		answer := resumeWithoutConsent(t, x, "first-party-web", tiedRedirect, "openid profile")
		require.NotEmpty(t, answer.Get("code"), "no consent stage: %v", answer)

		record := recordOf(t, x.parkFixture, answer.Get("code"))
		assert.Equal(t, []string{"openid", "profile"}, record.Scopes)
	})

	t.Run("a pre-authorized first-party native client asking offline_access gets a grant holding it", func(t *testing.T) {
		t.Parallel()

		x := newExchangeFixture(t)
		require.NoError(t, x.registry.Put(t.Context(), oidcprovider.Client{
			ID: "preauth-native", Type: oidcprovider.Public, ApplicationType: oidcprovider.Native, FirstParty: true,
			OfflineAccess: oidcprovider.OfflinePreAuthorized,
			RedirectURIs:  []string{nativeRedirect}, Scopes: []string{"openid", "offline_access"}, GrantTypes: both,
		}))

		answer := resumeWithoutConsent(t, x, "preauth-native", nativeRedirect, "openid offline_access")
		code := answer.Get("code")
		require.NotEmpty(t, code, "no consent stage: %v", answer)

		res, err := x.p.Token(t.Context(), oidcprovider.TokenRequest{
			Form: exchangeForm(issuedCode{code: code}, nativeRedirect, func(v url.Values) { v.Set("client_id", "preauth-native") }),
		})
		require.NoError(t, err)
		assert.Equal(t, "openid offline_access", res.Scope)
		assert.NotEmpty(t, res.RefreshToken, "the grant includes offline access")
	})

	t.Run("a first-party client asking offline_access is still shown the consent stage", func(t *testing.T) {
		t.Parallel()

		x := newExchangeFixture(t)
		require.NoError(t, x.registry.Put(t.Context(), oidcprovider.Client{
			ID: "first-party-offline", Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret), FirstParty: true,
			RedirectURIs: []string{tiedRedirect}, Scopes: []string{"openid", "offline_access"}, GrantTypes: both,
		}))

		answer := resumeWithoutConsent(t, x, "first-party-offline", tiedRedirect, "openid offline_access")
		assert.Empty(t, answer.Get("code"))
	})
}

func TestProvider_Token_PartialConsentCarriesNoUngrantedScope(t *testing.T) {
	t.Parallel()

	x := newExchangeFixture(t)
	signIn := testSignIn(x.parkFixture, "u-1")
	r, _ := atConsent(t, x.parkFixture, func(v url.Values) { v.Set("scope", "openid profile email") }, signIn)
	in := r.input(&signIn)
	answerWith(&in, "openid", "profile")
	res, err := x.p.Resume(t.Context(), in)
	require.NoError(t, err)
	c := issuedCode{code: queryOf(t, res.RedirectTo).Get("code"), signIn: signIn}
	require.NotEmpty(t, c.code)

	tokens, err := x.p.Token(t.Context(), byOwner(c))
	require.NoError(t, err)
	assert.Equal(t, "openid profile", tokens.Scope)

	_, claims := decodeJWT(t, tokens.AccessToken)
	assert.Equal(t, "openid profile", claims["scope"], "the access token carries no email scope")
}
