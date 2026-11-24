package oidcprovider_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// provedSignIn is a sign-in of u-1 whose amr claims mfa, changed by change.
func provedSignIn(x *exchangeFixture, change func(*oidcprovider.SignIn)) oidcprovider.SignIn {
	s := testSignIn(x.parkFixture, "u-1")
	s.AMR = []string{"mfa"}
	change(&s)

	return s
}

// issueProved is an offline code for the opaque client, which may refresh, from signIn.
func issueProved(t *testing.T, x *exchangeFixture, signIn oidcprovider.SignIn) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, opaqueClient, func(v url.Values) {
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid offline_access")
	}, signIn, "openid", "offline_access")
}

// TestGrant_KeepsHowItsSignInWasProved pins that a code's exchange copies the sign-in's
// second-factor marker and federated evidence into the grant, that a refresh keeps them, and
// that the access tokens of both read them from the grant.
func TestGrant_KeepsHowItsSignInWasProved(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		signIn func(*oidcprovider.SignIn)
		assert func(t *testing.T, g *oidcprovider.Grant)
	}

	cases := []testCase{
		{
			name:   "a consumer mapping's mfa with no verified second factor records none",
			signIn: func(*oidcprovider.SignIn) {},
			assert: func(t *testing.T, g *oidcprovider.Grant) {
				assert.Equal(t, []string{"mfa"}, g.AMR, "amr is the sign-in's, as stated")
				assert.False(t, g.SecondFactorVerified)
			},
		},
		{
			name:   "a verified second factor is recorded",
			signIn: func(s *oidcprovider.SignIn) { s.SecondFactorVerified = true },
			assert: func(t *testing.T, g *oidcprovider.Grant) {
				assert.True(t, g.SecondFactorVerified)
			},
		},
		{
			name: "a federated sign-in's evidence is recorded",
			signIn: func(s *oidcprovider.SignIn) {
				s.ExternalProvider, s.ExternalIssuer, s.ExternalSessionID = "corp", "https://corp.example", "up-1"
				s.ExternalAMR, s.ExternalACR = []string{"mfa"}, "urn:corp:silver"
			},
			assert: func(t *testing.T, g *oidcprovider.Grant) {
				assert.False(t, g.SecondFactorVerified)
				assert.Equal(t, "corp", g.ExternalProvider)
				assert.Equal(t, "https://corp.example", g.ExternalIssuer)
				assert.Equal(t, []string{"mfa"}, g.ExternalAMR)
				assert.Equal(t, "urn:corp:silver", g.ExternalACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			x := newExchangeFixture(t)
			c := issueProved(t, x, provedSignIn(x, tc.signIn))
			res, err := x.p.Token(t.Context(), confidentialExchange(opaqueClient, opaqueRedirect, c, nil))
			require.NoError(t, err)

			grant := grantOf(t, x, c)
			tc.assert(t, grant)
			at, err := x.p.VerifyAccessToken(t.Context(), res.AccessToken)
			require.NoError(t, err)
			tc.assert(t, grantFactsOf(at))

			refreshed, err := x.p.Token(t.Context(), refreshRequest(opaqueClient, res.RefreshToken, nil))
			require.NoError(t, err)
			after, err := x.p.GrantsForTest().Load(t.Context(), grant.Family)
			require.NoError(t, err)
			tc.assert(t, after)
			at, err = x.p.VerifyAccessToken(t.Context(), refreshed.AccessToken)
			require.NoError(t, err)
			tc.assert(t, grantFactsOf(at))
		})
	}
}

// grantFactsOf is what an access token read from its grant, as a grant, for the same assertions.
func grantFactsOf(at *oidcprovider.AccessToken) *oidcprovider.Grant {
	return &oidcprovider.Grant{
		AMR:                  at.AMR,
		SecondFactorVerified: at.SecondFactorVerified,
		ExternalProvider:     at.ExternalProvider,
		ExternalIssuer:       at.ExternalIssuer,
		ExternalAMR:          at.ExternalAMR,
		ExternalACR:          at.ExternalACR,
	}
}

// TestGrant_DeviceKeepsAVerifiedSecondFactor pins that a device's exchange copies the approving
// sign-in's marker and evidence into its grant, and that a refresh keeps them.
func TestGrant_DeviceKeepsAVerifiedSecondFactor(t *testing.T) {
	t.Parallel()

	f := newDeviceTokenFixture(t)
	code, record := f.seed(t, tvRefresh, then(approved("openid", "offline_access"), func(r *oidcprovider.DeviceAuthorization) {
		r.Approval.SignIn.SecondFactorVerified = true
		r.Approval.SignIn.ExternalProvider = "corp"
		r.Approval.SignIn.ExternalIssuer = "https://corp.example"
		r.Approval.SignIn.ExternalAMR = []string{"mfa"}
		r.Approval.SignIn.ExternalACR = "urn:corp:silver"
	}))
	res, err := f.p.Token(t.Context(), deviceRequest(tvRefresh, code))
	require.NoError(t, err)

	check := func(t *testing.T, g *oidcprovider.Grant) {
		t.Helper()
		require.NotNil(t, g)
		assert.True(t, g.SecondFactorVerified)
		assert.Equal(t, "corp", g.ExternalProvider)
		assert.Equal(t, "https://corp.example", g.ExternalIssuer)
		assert.Equal(t, []string{"mfa"}, g.ExternalAMR)
		assert.Equal(t, "urn:corp:silver", g.ExternalACR)
	}
	check(t, f.grantRow(t, record.Approval.GrantFamily))

	refreshed, err := f.p.Token(t.Context(), publicRefresh(tvRefresh, res.RefreshToken, ""))
	require.NoError(t, err)
	check(t, f.grantRow(t, record.Approval.GrantFamily))
	at, err := f.p.VerifyAccessToken(t.Context(), refreshed.AccessToken)
	require.NoError(t, err)
	check(t, grantFactsOf(at))
}

// TestVerifyAccessToken_SignInFacts pins that a JWT and an opaque token alike state the sign-in's
// time, context and methods.
func TestVerifyAccessToken_SignInFacts(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name               string
		client, redirectTo string
	}

	cases := []testCase{
		{name: "a JWT reads them from its claims", client: "billing-web", redirectTo: authzRedirect},
		{name: "an opaque token reads them from its grant", client: opaqueClient, redirectTo: opaqueRedirect},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			x := newExchangeFixture(t)
			signIn := testSignIn(x.parkFixture, "u-1")
			signIn.AuthenticatedAt = x.clk.Now().Add(-3 * time.Minute)
			c := issueCodeFor(t, x.parkFixture, tc.client, func(v url.Values) {
				asClient(v, tc.client, tc.redirectTo)
				v.Set("scope", "openid")
			}, signIn, "openid")
			res, err := x.p.Token(t.Context(), confidentialExchange(tc.client, tc.redirectTo, c, nil))
			require.NoError(t, err)

			at, err := x.p.VerifyAccessToken(t.Context(), res.AccessToken)
			require.NoError(t, err)
			assert.True(t, signIn.AuthenticatedAt.Truncate(time.Second).Equal(at.AuthTime), "auth_time %v", at.AuthTime)
			assert.Equal(t, signIn.ACR, at.ACR)
			assert.Equal(t, signIn.AMR, at.AMR)
		})
	}
}

// TestIntrospect_SignInMembers pins that an active access token's answer holds the sign-in's
// auth_time, acr and amr, as its grant records them.
func TestIntrospect_SignInMembers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name               string
		client, redirectTo string
	}

	cases := []testCase{
		{name: "a JWT", client: "billing-web", redirectTo: authzRedirect},
		{name: "an opaque token", client: opaqueClient, redirectTo: opaqueRedirect},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			x := newExchangeFixture(t)
			signIn := testSignIn(x.parkFixture, "u-1")
			signIn.AMR = []string{"pwd", "mfa"}
			c := issueCodeFor(t, x.parkFixture, tc.client, func(v url.Values) {
				asClient(v, tc.client, tc.redirectTo)
				v.Set("scope", "openid")
			}, signIn, "openid")
			res, err := x.p.Token(t.Context(), confidentialExchange(tc.client, tc.redirectTo, c, nil))
			require.NoError(t, err)

			answer, err := x.p.Introspect(t.Context(),
				oidcprovider.ClientCredentials{Authorization: basic(tc.client, exchangeSecret)},
				url.Values{"token": {res.AccessToken}})
			require.NoError(t, err)
			assert.Equal(t, true, answer["active"])
			assert.Equal(t, signIn.AuthenticatedAt.Unix(), answer["auth_time"])
			assert.Equal(t, signIn.ACR, answer["acr"])
			assert.Equal(t, []string{"pwd", "mfa"}, answer["amr"])
			assert.NotContains(t, answer, "second_factor_verified", "the library marker is not published")
		})
	}
}

// TestIntrospect_InactiveHoldsNoSignInMembers pins that an inactive answer says nothing more.
func TestIntrospect_InactiveHoldsNoSignInMembers(t *testing.T) {
	t.Parallel()

	x := newExchangeFixture(t)
	answer, err := x.p.Introspect(t.Context(),
		oidcprovider.ClientCredentials{Authorization: basic("billing-web", exchangeSecret)},
		url.Values{"token": {"at.not-a-token"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"active": false}, answer)
}

// TestProvider_UserLoader pins that the provider hands out the loader it was given.
func TestProvider_UserLoader(t *testing.T) {
	t.Parallel()

	x := newExchangeFixture(t)
	loader := x.p.UserLoader()
	require.NotNil(t, loader)
	_, ok := loader.(*MockUserLoader)
	assert.True(t, ok, "the loader is Deps.Users itself, %T", loader)
}
