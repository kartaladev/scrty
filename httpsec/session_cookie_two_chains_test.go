package httpsec_test

import (
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
)

// twoChainClient is a first-party client of the provider that asks for the API as the resource of
// its tokens.
const twoChainClient = "two-chain-web"

// twoChainCall is one call of the API through the mux, and what the handler behind the token chain
// saw of it.
type twoChainCall struct {
	status int
	header http.Header
	body   string

	ran     bool
	caller  *identity.Principal
	cookies []*http.Cookie
}

// twoChainWorld is one http.ServeMux serving a provider on a cookie chain and an API under
// "/api" on a token chain that trusts that provider.
type twoChainWorld struct {
	// flow is the provider on the cookie chain.
	flow *opFlow

	// api is the token chain, mux the one multiplexer serving both chains.
	api *httpsec.Chain
	mux *http.ServeMux

	// seen is what the API's handler saw of the call in flight.
	seen twoChainCall
}

// newTwoChainProvider is a provider on a cookie chain whose first-party client asks for the API
// and whose tokens may be bound to a key.
func newTwoChainProvider(t *testing.T) *opFlow {
	t.Helper()

	w, _, err := newCookieOP(t, func(s *flowSetup) {
		s.clients = []oidcprovider.Client{{
			ID: twoChainClient, Type: oidcprovider.Confidential, Secret: []byte(tokenSecret), FirstParty: true,
			RedirectURIs: []string{rpCallback}, Scopes: []string{"openid", "profile"},
			GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode},
			Resources:  []string{psAPI},
		}}
		s.provider = append(s.provider, oidcprovider.WithDPoP())
		s.chain = func(*testing.T, *opFlow) []httpsec.Option {
			return []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer})}
		}
	})
	require.NoError(t, err)

	return w
}

// newTwoChainWorld is the cookie chain of the provider flow, and a token chain under "/api" whose
// resource server trusts trusted, on one mux.
func newTwoChainWorld(t *testing.T, flow *opFlow, trusted *oidcprovider.Provider) *twoChainWorld {
	t.Helper()

	api, err := httpsec.New(httpsec.WithClock(flow.clk),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer}),
		httpsec.EnableResourceServer(psAPI, httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(trusted)))
	require.NoError(t, err)

	w := &twoChainWorld{flow: flow, api: api, mux: http.NewServeMux()}

	w.mux.Handle("/api/", api.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		w.seen.ran = true
		w.seen.caller, _ = identity.PrincipalFromContext(r.Context())
		w.seen.cookies = r.Cookies()
	})))
	w.mux.Handle("/", flow.chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

	return w
}

// token is a DPoP-bound access token of u-1 for the API, obtained through a cookie sign-in, a
// first-party authorization, the resume that completes it and the code exchange.
func (w *twoChainWorld) token(t *testing.T, k dpopKey) string {
	t.Helper()

	s := w.flow.session(t)
	handle, flowSecret := w.flow.park(t, twoChainClient, func(params url.Values) { params.Set("resource", psAPI) })

	res, err := w.flow.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle:     handle,
		FlowSecret: flowSecret,
		SignIn: &oidcprovider.SignIn{
			User: s.UserID, Family: s.FamilyID,
			AuthenticatedAt: s.AuthenticatedAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		},
		IdleTimeout: w.flow.sessions.IdleTimeout(),
	})
	require.NoError(t, err)

	redirect, err := url.Parse(res.RedirectTo)
	require.NoError(t, err)

	code := redirect.Query().Get("code")
	require.NotEmpty(t, code, "the first-party authorization answers with a code")

	proof := k.validProof("issuing").with(map[string]any{
		"htm": http.MethodPost, "htu": tokenURL, "iat": w.flow.clk.Now().Unix(),
	}).sign(t)

	a := w.flow.postForm(t, "/oauth2/token", exchangeOf(code),
		deviceBasic(twoChainClient, tokenSecret),
		func(r *http.Request) { r.Header.Add("DPoP", proof) })
	require.Equal(t, http.StatusOK, a.status, a.body)

	var doc struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}

	require.NoError(t, json.Unmarshal([]byte(a.body), &doc))
	require.NotEmpty(t, doc.AccessToken)
	require.Equal(t, "DPoP", doc.TokenType, "the token is bound to the key")

	return doc.AccessToken
}

// call is GET /api/orders through the mux with tok and a fresh proof of k, carrying no cookie.
func (w *twoChainWorld) call(t *testing.T, tok string, k dpopKey, jti string) twoChainCall {
	t.Helper()

	w.seen = twoChainCall{}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, psAPIURL, nil)
	r.RemoteAddr = tokenAddr
	r.Header.Set("Authorization", "DPoP "+tok)
	r.Header.Set("DPoP", k.validProof(jti).with(map[string]any{
		"htu": psAPIURL, "iat": w.flow.clk.Now().Unix(), "ath": tokenHash(tok),
	}).sign(t))

	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, r)

	out := w.seen
	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()

	return out
}

// TestSessionCookie_TwoChainsWithProvider pins that an API on a token chain trusts the provider
// that a cookie chain serves, on one mux: a bound token the provider issued after a cookie
// sign-in is accepted as the signed-in user, with no session cookie on the request, and a token
// whose grant the provider revoked is refused as an invalid token.
func TestSessionCookie_TwoChainsWithProvider(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		act    func(t *testing.T, w *twoChainWorld, k dpopKey) twoChainCall
		assert func(t *testing.T, out twoChainCall)
	}

	cases := []testCase{
		{
			name: "a bound token the cookie chain's provider issued is accepted on the token chain",
			act: func(t *testing.T, w *twoChainWorld, k dpopKey) twoChainCall {
				return w.call(t, w.token(t, k), k, "j-1")
			},
			assert: func(t *testing.T, out twoChainCall) {
				t.Helper()

				require.Equal(t, http.StatusOK, out.status, out.body)
				require.True(t, out.ran, "the handler ran")
				require.NotNil(t, out.caller)
				assert.Equal(t, identity.UserID("u-1"), out.caller.ID)
				assert.Empty(t, out.cookies, "the request carried no session cookie")
			},
		},
		{
			name: "a token whose grant is revoked is refused on the token chain",
			act: func(t *testing.T, w *twoChainWorld, k dpopKey) twoChainCall {
				tok := w.token(t, k)

				first := w.call(t, tok, k, "j-1")
				require.Equal(t, http.StatusOK, first.status, first.body)
				require.True(t, first.ran)

				require.NoError(t, w.flow.p.RevokeUserGrants(t.Context(), "u-1", "test"))

				return w.call(t, tok, k, "j-2")
			},
			assert: func(t *testing.T, out twoChainCall) {
				t.Helper()

				assert.Equal(t, http.StatusUnauthorized, out.status)
				assert.False(t, out.ran, "the handler did not run")
				assert.Equal(t, []string{`DPoP error="invalid_token", algs="ES256"`}, out.header.Values("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			flow := newTwoChainProvider(t)
			w := newTwoChainWorld(t, flow, flow.p)
			k := newDPoPKey(t, elliptic.P256())

			tc.assert(t, tc.act(t, w, k))
		})
	}
}
