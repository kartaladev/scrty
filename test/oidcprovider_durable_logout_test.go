package test_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// Logout's parking and confirmation, and the session-answered flow, over each durable adapter.
func TestOIDCProvider_DurableLogoutAndSSO(t *testing.T) {
	t.Parallel()
	for _, a := range opAdapters {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			e := newDurEnv(t, a.name, a.open)
			ctx := t.Context()
			p := e.build(t, nil)

			// A login leaves a browser session.
			require.NoError(t, e.consents.Give(ctx, durUser, durWeb.id, []string{"openid", "email"}, false, e.clk.Now()))
			params := url.Values{
				"client_id": {durWeb.id}, "redirect_uri": {opRedirect}, "response_type": {"code"},
				"scope": {durScope}, "state": {"s"}, "code_challenge": {opChallenge}, "code_challenge_method": {"S256"},
			}
			auth, err := p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: params})
			require.NoError(t, err)
			loc, _ := url.Parse(auth.Location)
			signIn := oidcprovider.SignIn{User: durUser, Family: newID(), AuthenticatedAt: e.clk.Now(), AMR: []string{"pwd"}, AbsoluteExpiresAt: e.clk.Now().Add(8 * time.Hour)}
			res, err := p.Resume(ctx, oidcprovider.ResumeInput{Handle: loc.Query().Get("req"), FlowSecret: auth.FlowSecret, SignIn: &signIn, IdleTimeout: 15 * time.Minute})
			require.NoError(t, err)
			require.NotEmpty(t, res.BrowserSessionSecret)
			back, _ := url.Parse(res.RedirectTo)
			tokens, err := p.Token(ctx, oidcprovider.TokenRequest{Credentials: durWeb.creds(), Form: url.Values{
				"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "redirect_uri": {opRedirect}, "code_verifier": {opVerifier},
			}})
			require.NoError(t, err)

			// After a restart the browser session answers a silent request.
			second := e.build(t, nil)
			silent := url.Values{}
			for k, v := range params {
				silent[k] = v
			}
			silent.Set("prompt", "none")
			sso, err := second.Authorize(ctx, oidcprovider.AuthorizeInput{Params: silent, BrowserSessionSecret: res.BrowserSessionSecret, IdleTimeout: 15 * time.Minute})
			require.NoError(t, err)
			assert.Contains(t, sso.Location, "code=", sso.Location)

			// No hint parks a logout, with no client, scopes or sign-in.
			parked, err := second.EndSession(ctx, oidcprovider.EndSessionInput{Params: url.Values{}, FlowSecret: auth.FlowSecret})
			require.NoError(t, err)
			require.Nil(t, parked.Ended)
			ploc, _ := url.Parse(parked.Location)
			handle := ploc.Query().Get("req")
			require.NotEmpty(t, handle)

			third := e.build(t, nil)
			confirmed, err := third.ConfirmLogout(ctx, handle, auth.FlowSecret, res.BrowserSessionSecret, true)
			require.NoError(t, err)
			require.NotNil(t, confirmed.Ended)
			_, err = third.EndSignIn(ctx, *confirmed.Ended)
			require.NoError(t, err)
			third.SpendLogout(ctx, handle, auth.FlowSecret)

			e.requireRefreshRefused(t, third, durWeb, tokens.RefreshToken)
			after, err := third.Authorize(ctx, oidcprovider.AuthorizeInput{Params: silent, BrowserSessionSecret: res.BrowserSessionSecret, IdleTimeout: 15 * time.Minute})
			require.NoError(t, err)
			assert.Contains(t, after.Location, "error=login_required")
		})
	}
}

// A hint held by a provider with browser sessions off parks a sign-in holding only user and family.
func TestOIDCProvider_DurableHintParkWithoutBrowserSessions(t *testing.T) {
	t.Parallel()
	for _, a := range opAdapters {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			e := newDurEnv(t, a.name, a.open)
			ctx := t.Context()
			st := e.open(t, e.conn, e.cipher, e.clk)
			consents, clients := e.admin(t, e.conn)
			p, err := oidcprovider.New(oidcprovider.Deps{
				Issuer: opIssuer, Registry: clients, Keys: e.keys, Users: durUsers{},
				LoginURL: opIssuer + "/login", ConsentURL: opIssuer + "/consent", LogoutURL: opIssuer + "/logout", LoggedOutURL: opIssuer + "/bye",
			}, oidcprovider.WithClock(e.clk), oidcprovider.WithoutBrowserSessions(),
				oidcprovider.WithPendingRequestStore(st.pending), oidcprovider.WithCodeStore(st.codes), oidcprovider.WithGrantStore(st.grants),
				oidcprovider.WithCodeTokenStore(st.tokens), oidcprovider.WithAccessTokenStore(st.access), oidcprovider.WithAssertionIDStore(st.assertions),
				oidcprovider.WithRefreshTokenStore(st.lineage), oidcprovider.WithRefreshSuccessorKey(durSuccessorKey),
				oidcprovider.WithConsentStore(consents))
			require.NoError(t, err)
			issued := e.issue(t, p, durWeb)

			parked, err := p.EndSession(ctx, oidcprovider.EndSessionInput{Params: url.Values{"id_token_hint": {issued.tokens.IDToken}}, FlowSecret: issued.flow})
			require.NoError(t, err, "parks")
			ploc, _ := url.Parse(parked.Location)
			handle := ploc.Query().Get("req")
			require.NotEmpty(t, handle, parked.Location)

			confirmed, err := p.ConfirmLogout(ctx, handle, issued.flow, "", true)
			require.NoError(t, err, "a sign-in parked with no times reads back")
			require.NotNil(t, confirmed.Ended, "the hint's sign-in ends")
			e.requireRefreshRefused(t, p, durWeb, issued.tokens.RefreshToken)
		})
	}
}
