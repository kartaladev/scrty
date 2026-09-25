package test

import (
	"encoding/json"
	"net"
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
	"github.com/kartaladev/scrty/token"
)

// keycloakBackchannelPrefix is the path prefix the realm's back-channel logout
// URLs are registered under; each client's URL ends in its own id, which is
// also the name its provider is registered under here.
const keycloakBackchannelPrefix = httpsec.DefaultOIDCBackchannelPath

// TestKeycloak drives a federated login against a real Keycloak, once per
// client authentication method, through a net/http chain with
// httpsec.EnableOIDCLogin: discovery with no pinned endpoint, the authorize
// redirect, the code exchange, ID token verification, handoff redemption into
// a session, and a back-channel logout Keycloak sends when an administrator
// ends the user's Keycloak session.
//
// One Keycloak and one chain serve every row. The chain's listener exists
// before the container starts, because Keycloak is told at import where to
// deliver back-channel logout tokens, and it runs inside the container, where
// the host is reachable only through testcontainers' host port access.
func TestKeycloak(t *testing.T) {
	t.Parallel()

	srv := httptest.NewUnstartedServer(nil)
	t.Cleanup(srv.Close)
	chainPort := srv.Listener.Addr().(*net.TCPAddr).Port

	kc := RunTestKeycloak(t, WithTestKeycloakBackchannelLogout(chainPort, keycloakBackchannelPrefix))
	require.Len(t, kc.Users, len(kc.Clients), "the realm needs one user per client, so rows never share a session")

	users := identitytest.NewInMemoryStore()
	links := oidc.NewMemoryLinkStore()

	providers := make([]oidc.Provider, 0, len(kc.Clients))
	for i, c := range kc.Clients {
		// No endpoint is pinned: every one comes from Keycloak's discovery.
		providers = append(providers, oidc.Provider{
			Name:         c.ID,
			Issuer:       kc.Issuer,
			ClientID:     c.ID,
			ClientSecret: c.Secret,
			RedirectURL:  c.RedirectURL,
			ClientAuth:   c.Auth,
		})

		provisioned, err := users.Provision(t.Context(), kc.Users[i].Email)
		require.NoError(t, err)
		require.NoError(t, links.Insert(t.Context(), oidc.Link{
			Provider:  c.ID,
			Issuer:    kc.Issuer,
			Subject:   kc.Users[i].Subject,
			UserID:    provisioned.ID,
			CreatedAt: time.Now(),
		}))
	}

	registry, err := oidc.NewRegistry(providers...)
	require.NoError(t, err)

	broker, err := oidc.NewBroker(links, users)
	require.NoError(t, err)

	manager, err := oidc.NewManager(registry, broker, oidc.WithOutboundClient(kc.Outbound))
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

	srv.Config.Handler = chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Start()

	type loginResult struct {
		authorizeURL string
		session      *session.Session
		user         KeycloakUser
	}

	type testCase struct {
		name   string
		auth   oidc.ClientAuthMethod
		assert func(t *testing.T, res loginResult)
	}

	// Both rows assert the same outcome; what varies is the client, and so
	// how it authenticates at Keycloak's token endpoint.
	assertFederatedLogin := func(t *testing.T, res loginResult) {
		t.Helper()

		assert.True(t, strings.HasPrefix(res.authorizeURL, kc.Issuer+"/"),
			"the authorize redirect %q does not target Keycloak's realm %q", res.authorizeURL, kc.Issuer)

		assert.Equal(t, kc.Issuer, res.session.ExternalIssuer)
		assert.NotEmpty(t, res.session.ExternalSessionID, "Keycloak's sid was not recorded on the session")

		kc.LogoutUser(t, res.user.Subject)

		require.Eventually(t, func() bool {
			_, err := sessions.Load(t.Context(), res.session.ID)
			return err != nil
		}, 10*time.Second, 100*time.Millisecond,
			"the session outlived Keycloak's back-channel logout")

		_, err := sessions.Load(t.Context(), res.session.ID)
		require.ErrorIs(t, err, session.ErrSessionNotFound)
	}

	cases := []testCase{
		{name: "client_secret_post", auth: oidc.ClientSecretPost, assert: assertFederatedLogin},
		{name: "client_secret_basic", auth: oidc.ClientSecretBasic, assert: assertFederatedLogin},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			i := keycloakClientIndex(t, kc, tc.auth)
			client, user := kc.Clients[i], kc.Users[i]

			browser := keycloakBrowser(t)

			// Start the login: the chain discovers Keycloak's endpoints and
			// redirects to its authorization endpoint.
			authorizeReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				srv.URL+httpsec.DefaultOIDCAuthorizePath+client.ID, nil)
			require.NoError(t, err)
			resp, err := browser.Do(authorizeReq) //nolint:bodyclose // closed by readAll once the caller is done with it
			require.NoError(t, err)
			body := readAll(t, resp)
			require.Equal(t, http.StatusFound, resp.StatusCode, "authorize did not redirect: %s", body)
			authorizeURL := resp.Header.Get("Location")

			// The user logs in at Keycloak, which redirects to the registered
			// callback URL; the chain is reached on the same path and query.
			callback, err := url.Parse(kc.Login(t, authorizeURL, user.Username, user.Password))
			require.NoError(t, err)
			require.Equal(t, httpsec.DefaultOIDCCallbackPath+client.ID, callback.Path)

			// The callback exchanges the code and verifies the ID token.
			callbackReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+callback.RequestURI(), nil)
			require.NoError(t, err)
			resp, err = browser.Do(callbackReq) //nolint:bodyclose // closed by readAll once the caller is done with it
			require.NoError(t, err)
			body = readAll(t, resp)
			require.Equal(t, http.StatusFound, resp.StatusCode, "the callback did not redirect: %s", body)

			loc, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			code := loc.Query().Get(httpsec.DefaultOIDCHandoffParam)
			require.NotEmpty(t, code, "the callback's redirect carried no handoff code")

			handoffForm := url.Values{httpsec.DefaultOIDCHandoffParam: {code}}
			handoffReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				srv.URL+httpsec.DefaultOIDCHandoffPath, strings.NewReader(handoffForm.Encode()))
			require.NoError(t, err)
			handoffReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err = browser.Do(handoffReq) //nolint:bodyclose // closed by readAll once the caller is done with it
			require.NoError(t, err)
			body = readAll(t, resp)
			require.Equal(t, http.StatusOK, resp.StatusCode, "redemption failed: %s", body)

			var issued struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal(body, &issued))

			claims, err := tokens.Verify(t.Context(), issued.AccessToken)
			require.NoError(t, err, "the issued access token does not verify")

			s, err := sessions.Load(t.Context(), claims.ID())
			require.NoError(t, err, "no session was created for the issued token")
			require.Equal(t, client.ID, s.ExternalProvider)

			tc.assert(t, loginResult{authorizeURL: authorizeURL, session: s, user: user})
		})
	}
}

// keycloakClientIndex finds the realm client standing for auth.
func keycloakClientIndex(t *testing.T, kc KeycloakConn, auth oidc.ClientAuthMethod) int {
	t.Helper()

	for i, c := range kc.Clients {
		if c.Auth == auth {
			return i
		}
	}

	require.FailNow(t, "the realm has no client for the method", "%v", auth)

	return -1
}

// keycloakBrowser is the client that plays the browser against the chain: it
// keeps cookies, so the flow cookie reaches the callback, and never follows a
// redirect on its own, so each step's Location can be read.
func keycloakBrowser(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &http.Client{
		Jar:           jar,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
