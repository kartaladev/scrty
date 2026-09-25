package oidctest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/signingkey"
	identitytest "github.com/kartaladev/scrty/test/identity"
	oidctest "github.com/kartaladev/scrty/test/oidc"
	"github.com/kartaladev/scrty/token"
)

// testProviderName is the provider name every case in this file registers
// the fixture under.
const testProviderName = "corp"

// testSubject and testUsername are the external identity a login harness
// links to a provisioned user, so a genuine callback resolves to somebody.
const (
	testSubject  = "sub-1"
	testUsername = "ada@example.com"
)

// loginHarness is a full federated-login chain over one IdentityProvider: a
// real oidc.Manager, broker, handoff manager and session manager, wired
// through httpsec.EnableOIDCLogin and served over net/http.
type loginHarness struct {
	provider *oidctest.IdentityProvider
	sessions *session.Manager
	tokens   token.Generator
	srv      *httptest.Server
}

// newLoginHarness builds the harness for one test: a provider registered as
// testProviderName, a user provisioned and linked to its subject, and a
// chain served over an httptest.Server.
func newLoginHarness(t *testing.T, auth oidc.ClientAuthMethod) *loginHarness {
	t.Helper()

	p := oidctest.NewIdentityProvider(t)

	users := identitytest.NewInMemoryStore()
	provisioned, err := users.Provision(t.Context(), testUsername)
	require.NoError(t, err)

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider:  testProviderName,
		Issuer:    p.Issuer(),
		Subject:   testSubject,
		UserID:    provisioned.ID,
		CreatedAt: time.Now(),
	}))

	broker, err := oidc.NewBroker(links, users)
	require.NoError(t, err)

	registry, err := oidc.NewRegistry(p.Provider(testProviderName, auth))
	require.NoError(t, err)

	manager, err := oidc.NewManager(registry, broker, oidc.WithOutboundClient(p.Outbound(t)))
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), users)
	require.NoError(t, err)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	keys, err := signingkey.NewKeyManager(t.Context())
	require.NoError(t, err)

	tokens, err := token.NewGenerator(keys)
	require.NoError(t, err)

	chain, err := httpsec.New(httpsec.EnableOIDCLogin(manager, handoffs,
		httpsec.WithOIDCTokens(tokens), httpsec.WithOIDCSessions(sessions)))
	require.NoError(t, err)

	srv := httptest.NewServer(chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	t.Cleanup(srv.Close)

	return &loginHarness{provider: p, sessions: sessions, tokens: tokens, srv: srv}
}

// httpClient is a client that never follows a redirect on its own, so a test
// can read a 302's Location and cookies for itself, and that keeps cookies
// across requests the way a browser would.
func httpClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// readBody reads and returns resp's body, for a failure message: assertions
// below read it only when the expected status did not come back.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(b)
}

// startAuthorize starts a login with provider and returns the authorization
// redirect it was sent to.
func startAuthorize(t *testing.T, client *http.Client, h *loginHarness, provider string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.srv.URL+httpsec.DefaultOIDCAuthorizePath+provider, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode, "authorize did not redirect: %s", readBody(t, resp))

	target := resp.Header.Get("Location")
	require.NotEmpty(t, target, "authorize set no Location")

	return target
}

// TestTestIdentityProvider drives one full login end to end, for both client
// authentication methods and across a key rotation: starting the login, the
// provider's callback, and redeeming the handoff code the callback conveys
// the login with. It pins that a session exists afterwards, recording the
// provider's own issuer, that the client authenticated on the channel it was
// configured for and no other, and, for the rotated-key case, that the
// provider's key set publishes every key it has ever signed with and none of
// their private components.
func TestTestIdentityProvider(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		auth oidc.ClientAuthMethod

		// rotate, when set, rotates the provider to a second signing key
		// before Login, so the login is completed with the new key and the
		// key set must publish both.
		rotate bool

		assertAuth func(t *testing.T, auth oidctest.TokenAuthObservation)
	}

	cases := []testCase{
		{
			name: "client_secret_post",
			auth: oidc.ClientSecretPost,
			assertAuth: func(t *testing.T, auth oidctest.TokenAuthObservation) {
				assert.Equal(t, oidc.ClientSecretPost, auth.Method)
				assert.False(t, auth.AuthorizationHeader,
					"client_secret_post sent an Authorization header; the client secret is form-only")
			},
		},
		{
			name: "client_secret_basic",
			auth: oidc.ClientSecretBasic,
			assertAuth: func(t *testing.T, auth oidctest.TokenAuthObservation) {
				assert.Equal(t, oidc.ClientSecretBasic, auth.Method)
				assert.False(t, auth.FormClientSecret,
					"client_secret_basic sent client_secret in the form; the secret is header-only")
			},
		},
		{
			name:   "client_secret_post after key rotation",
			auth:   oidc.ClientSecretPost,
			rotate: true,
			assertAuth: func(t *testing.T, auth oidctest.TokenAuthObservation) {
				assert.Equal(t, oidc.ClientSecretPost, auth.Method)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginHarness(t, tc.auth)
			if tc.rotate {
				h.provider.Rotate(t, "k2")
			}
			client := httpClient(t)

			authorizeURL := startAuthorize(t, client, h, testProviderName)

			callbackPath := h.provider.Login(t, authorizeURL, map[string]any{
				"sub":   testSubject,
				"email": testUsername,
			})

			cbReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.srv.URL+callbackPath, nil)
			require.NoError(t, err)
			cbResp, err := client.Do(cbReq)
			require.NoError(t, err)
			defer func() { _ = cbResp.Body.Close() }()
			require.Equal(t, http.StatusFound, cbResp.StatusCode,
				"the callback did not redirect: %s", readBody(t, cbResp))

			loc, err := url.Parse(cbResp.Header.Get("Location"))
			require.NoError(t, err)
			code := loc.Query().Get(httpsec.DefaultOIDCHandoffParam)
			require.NotEmpty(t, code, "the callback's redirect carried no handoff code")

			redeemForm := url.Values{httpsec.DefaultOIDCHandoffParam: {code}}
			redeemReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				h.srv.URL+httpsec.DefaultOIDCHandoffPath, strings.NewReader(redeemForm.Encode()))
			require.NoError(t, err)
			redeemReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			redeemResp, err := client.Do(redeemReq)
			require.NoError(t, err)
			defer func() { _ = redeemResp.Body.Close() }()

			// Read once: the message argument below would otherwise drain
			// the body before the JSON decode that follows ever saw it.
			redeemBody := readBody(t, redeemResp)
			require.Equal(t, http.StatusOK, redeemResp.StatusCode, "redemption failed: %s", redeemBody)

			var body struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal([]byte(redeemBody), &body))
			require.NotEmpty(t, body.AccessToken, "redemption answered no access token")

			claims, err := h.tokens.Verify(t.Context(), body.AccessToken)
			require.NoError(t, err, "the issued access token does not verify")

			s, err := h.sessions.Load(t.Context(), claims.ID())
			require.NoError(t, err, "no session was created for the issued token")
			assert.Equal(t, h.provider.Issuer(), s.ExternalIssuer)
			assert.Equal(t, testProviderName, s.ExternalProvider)

			discovery, jwks, _ := h.provider.Calls()
			assert.Positive(t, discovery, "the manager never fetched discovery")
			assert.Positive(t, jwks, "the manager never fetched the key set")

			tc.assertAuth(t, h.provider.LastTokenAuth())

			if tc.rotate {
				assertPublicJWKS(t, h.provider, 2)
			}
		})
	}
}

// assertPublicJWKS fetches provider's published key set and asserts it
// carries exactly wantKeys entries, none of them holding a private RSA
// component: rotation must publish every key it has ever signed with, and
// only the public half of each.
func assertPublicJWKS(t *testing.T, provider *oidctest.IdentityProvider, wantKeys int) {
	t.Helper()

	res, err := provider.Outbound(t).Get(t.Context(), provider.Issuer()+"/jwks", nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.Status, "fetching the key set failed: %s", string(res.Body))

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(res.Body, &set))
	require.Len(t, set.Keys, wantKeys, "the key set does not publish every rotated key")

	for _, k := range set.Keys {
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			_, present := k[private]
			assert.False(t, present, "published key %v carries private component %q", k["kid"], private)
		}
	}
}

// TestTestIdentityProviderMalformedTokens drives every malformed-token
// option of design decision 15 through the same login flow: each must fail
// the callback as an authentication failure, 401, and never as a server
// failure, 500 — including UnknownKid, which triggers an extra key-set
// fetch on the way to being refused, and must not be mistaken for the
// provider being unreachable.
func TestTestIdentityProviderMalformedTokens(t *testing.T) {
	t.Parallel()

	// assertRefusedAsUnauthorized is every case's assertion: a malformed
	// token must fail the callback as an authentication failure, never as a
	// server failure. It is shared, not per-case, because every option in
	// this table is refused the same way; a case that needed a different
	// outcome would give assert its own closure instead.
	assertRefusedAsUnauthorized := func(t *testing.T, name string, cbResp *http.Response) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, cbResp.StatusCode, "%s: %s", name, readBody(t, cbResp))
	}

	type testCase struct {
		name   string
		opt    oidctest.TokenOption
		assert func(t *testing.T, name string, cbResp *http.Response)
	}

	cases := []testCase{
		{name: "wrong issuer", opt: oidctest.WrongIssuer(), assert: assertRefusedAsUnauthorized},
		{name: "wrong audience", opt: oidctest.WrongAudience(), assert: assertRefusedAsUnauthorized},
		{name: "expired", opt: oidctest.Expired(), assert: assertRefusedAsUnauthorized},
		{name: "future issued-at", opt: oidctest.FutureIssuedAt(), assert: assertRefusedAsUnauthorized},
		{name: "bad signature", opt: oidctest.BadSignature(), assert: assertRefusedAsUnauthorized},
		{name: "unknown kid", opt: oidctest.UnknownKid(), assert: assertRefusedAsUnauthorized},
		{name: "alg none", opt: oidctest.AlgNone(), assert: assertRefusedAsUnauthorized},
		{
			name:   "HS256 signed with the client secret",
			opt:    oidctest.HS256WithClientSecret(),
			assert: assertRefusedAsUnauthorized,
		},
		{name: "wrong nonce", opt: oidctest.WrongNonce(), assert: assertRefusedAsUnauthorized},
		{name: "no subject", opt: oidctest.NoSubject(), assert: assertRefusedAsUnauthorized},
		{
			name:   "multiple audiences without azp",
			opt:    oidctest.MultipleAudiencesWithoutAZP(),
			assert: assertRefusedAsUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginHarness(t, oidc.ClientSecretPost)
			client := httpClient(t)

			authorizeURL := startAuthorize(t, client, h, testProviderName)

			callbackPath := h.provider.Login(t, authorizeURL, map[string]any{
				"sub":   testSubject,
				"email": testUsername,
			}, tc.opt)

			cbReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.srv.URL+callbackPath, nil)
			require.NoError(t, err)
			cbResp, err := client.Do(cbReq)
			require.NoError(t, err)
			defer func() { _ = cbResp.Body.Close() }()

			tc.assert(t, tc.name, cbResp)
		})
	}
}

// TestTestIdentityProviderLogoutToken pins LogoutToken against the same
// manager a login harness wires: a default token verifies, and a malformed
// one is refused as an invalid logout token, never as an outage.
func TestTestIdentityProviderLogoutToken(t *testing.T) {
	t.Parallel()

	h := newLoginHarness(t, oidc.ClientSecretPost)
	clientID := "client-" + testProviderName

	registry, err := oidc.NewRegistry(h.provider.Provider(testProviderName, oidc.ClientSecretPost))
	require.NoError(t, err)

	users := identitytest.NewInMemoryStore()
	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), users)
	require.NoError(t, err)

	manager, err := oidc.NewManager(registry, broker, oidc.WithOutboundClient(h.provider.Outbound(t)))
	require.NoError(t, err)

	type testCase struct {
		name   string
		opts   []oidctest.TokenOption
		assert func(t *testing.T, claims oidc.LogoutClaims, err error)
	}

	cases := []testCase{
		{
			name: "a well-formed token verifies",
			assert: func(t *testing.T, claims oidc.LogoutClaims, err error) {
				require.NoError(t, err)
				assert.Equal(t, testSubject, claims.Subject)
			},
		},
		{
			name: "a wrong issuer is refused",
			opts: []oidctest.TokenOption{oidctest.WrongIssuer()},
			assert: func(t *testing.T, _ oidc.LogoutClaims, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidLogoutToken)
			},
		},
		{
			name: "a bad signature is refused",
			opts: []oidctest.TokenOption{oidctest.BadSignature()},
			assert: func(t *testing.T, _ oidc.LogoutClaims, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidLogoutToken)
			},
		},
		{
			name: "alg none is refused",
			opts: []oidctest.TokenOption{oidctest.AlgNone()},
			assert: func(t *testing.T, _ oidc.LogoutClaims, err error) {
				require.ErrorIs(t, err, oidc.ErrInvalidLogoutToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := h.provider.LogoutToken(t, map[string]any{"aud": clientID, "sub": testSubject}, tc.opts...)
			claims, err := manager.VerifyLogoutToken(t.Context(), testProviderName, raw)
			tc.assert(t, claims, err)
		})
	}
}
