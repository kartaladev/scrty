package test_test

import (
	"context"
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
	"golang.org/x/oauth2"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/migrate"
	"github.com/kartaladev/scrty/store/seal"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	devE2EClient    = "device-e2e-cli"
	devE2EEntryPath = "/enter-code"
	devE2EScope     = "openid offline_access"
)

// devE2E is a provider on an httpsec chain behind a TLS server, with the device grant on and
// one public native client registered for it, as a consumer deploys them. A browser is the
// consumer's own sign-in and consent handler, scripted by the test.
type devE2E struct {
	srv      *httptest.Server
	issuer   string
	conf     *oauth2.Config
	sessions *session.Sessions
	// oauthCtx makes the oauth2 client trust the server's certificate.
	oauthCtx context.Context
}

// newDevE2E builds the deployment over in-memory stores, or over sqlstore on a migrated
// PostgreSQL database when durable.
func newDevE2E(t *testing.T, durable bool) *devE2E {
	t.Helper()

	e := &devE2E{}
	// The handler is set once the issuer, which is the server's own address, is known.
	var handler http.Handler
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	e.srv.EnableHTTP2 = false
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	e.issuer = e.srv.URL

	keys, err := signingkey.New(t.Context(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore()), signingkey.WithAlgs(signingkey.ES256))
	require.NoError(t, err)

	client := oidcprovider.Client{
		ID: devE2EClient, Name: "Device E2E CLI", Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
		Scopes:     []string{"openid", "offline_access"},
		GrantTypes: []oidcprovider.GrantType{oidcprovider.GrantDeviceCode, oidcprovider.GrantRefreshToken},
		IDTokenAlg: signingkey.ES256,
	}
	deps := oidcprovider.Deps{
		Issuer: e.issuer, Keys: keys, Users: durUsers{},
		LoginURL: e.issuer + "/login", ConsentURL: e.issuer + "/consent",
		LogoutURL: e.issuer + "/logout-page", LoggedOutURL: e.issuer + "/bye",
	}
	// A short interval keeps the polling quick; the entry page is on the issuer's origin.
	device := []oidcprovider.DeviceOption{oidcprovider.WithDevicePollInterval(time.Second)}
	var opts []oidcprovider.Option

	if durable {
		set := migrate.SecurityState()
		conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
		var cipher seal.Cipher = storefix.TestCipher(t)
		st := opAdapters[0].open(t, conn, cipher, clock.System())
		consents, clients := durAdmins["sqlstore"](t, conn)
		require.NoError(t, clients.Put(t.Context(), client))
		devices := deviceStores["sqlstore"](t, conn)

		deps.Registry = clients
		device = append(device, oidcprovider.WithUserCodeKey(deviceUserCodeKey),
			oidcprovider.WithDeviceAuthorizationStore(devices))
		opts = append(opts,
			oidcprovider.WithPendingRequestStore(st.pending), oidcprovider.WithCodeStore(st.codes),
			oidcprovider.WithGrantStore(st.grants), oidcprovider.WithCodeTokenStore(st.tokens),
			oidcprovider.WithAccessTokenStore(st.access), oidcprovider.WithAssertionIDStore(st.assertions),
			oidcprovider.WithBrowserSessionStore(st.browser), oidcprovider.WithRefreshTokenStore(st.lineage),
			oidcprovider.WithRefreshSuccessorKey(durSuccessorKey), oidcprovider.WithConsentStore(consents))
	} else {
		deps.Clients = []oidcprovider.Client{client}
	}
	opts = append(opts, oidcprovider.WithDeviceAuthorization(e.issuer+devE2EEntryPath, device...))

	p, err := oidcprovider.New(deps, opts...)
	require.NoError(t, err)

	e.sessions, err = session.New(session.WithEndObserver(p))
	require.NoError(t, err)

	chain, err := httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: e.sessions, Users: durUsers{}}),
		httpsec.EnableJWKSEndpoint(keys),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(p),
	)
	require.NoError(t, err)
	handler = chain.Middleware()(http.NotFoundHandler())

	e.conf = &oauth2.Config{
		ClientID: devE2EClient,
		Scopes:   strings.Fields(devE2EScope),
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: e.issuer + "/oauth2/device-authorization",
			TokenURL:      e.issuer + "/oauth2/token",
			AuthStyle:     oauth2.AuthStyleInParams,
		},
	}
	e.oauthCtx = context.WithValue(t.Context(), oauth2.HTTPClient, e.srv.Client())

	return e
}

// devBrowser is a browser: one cookie jar, no automatic redirects, and the Sec-Fetch-Site
// header a navigation of the given kind carries.
type devBrowser struct {
	t      *testing.T
	client *http.Client
}

func (e *devE2E) newBrowser(t *testing.T) *devBrowser {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &devBrowser{t: t, client: &http.Client{
		Transport:     &http.Transport{TLSClientConfig: e.srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()},
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}}
}

// devPage is a response a browser saw, its body read.
type devPage struct {
	status   int
	location *url.URL
	body     string
}

func (b *devBrowser) do(req *http.Request) devPage {
	b.t.Helper()

	res, err := b.client.Do(req)
	require.NoError(b.t, err)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	require.NoError(b.t, err)

	page := devPage{status: res.StatusCode, body: string(body)}
	if loc := res.Header.Get("Location"); loc != "" {
		page.location, err = req.URL.Parse(loc)
		require.NoError(b.t, err)
	}

	return page
}

// enter is the browser's navigation to the code-entry endpoint with code, as a link or the
// entry page's redirect would make it.
func (b *devBrowser) enter(ctx context.Context, issuer, code, fetchSite string) devPage {
	b.t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		issuer+"/oauth2/device?"+url.Values{"user_code": {code}}.Encode(), nil)
	require.NoError(b.t, err)
	req.Header.Set("Sec-Fetch-Site", fetchSite)

	return b.do(req)
}

// resume is the consumer's login or consent page posting to the provider's resume endpoint,
// signed in as credential, a session secret.
func (b *devBrowser) resume(ctx context.Context, issuer, credential string, body map[string]any) devPage {
	b.t.Helper()

	doc, err := json.Marshal(body)
	require.NoError(b.t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oauth2/authorize/resume",
		strings.NewReader(string(doc)))
	require.NoError(b.t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)

	return b.do(req)
}

// redirectTo is the URL in a resume's document.
func (p devPage) redirectTo(t *testing.T) *url.URL {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(p.body), &doc), p.body)
	raw, ok := doc["redirect_to"].(string)
	require.True(t, ok, p.body)
	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

// approve runs a browser from the code-entry endpoint, with the user signed in, to an
// approval of scopes.
func (e *devE2E) approve(t *testing.T, code string) {
	t.Helper()

	ctx := t.Context()
	b := e.newBrowser(t)

	entered := b.enter(ctx, e.issuer, code, "none")
	require.Equal(t, http.StatusSeeOther, entered.status, entered.body)
	require.Equal(t, "/login", entered.location.Path, "the browser is sent to the consumer's login page")
	handle := entered.location.Query().Get(oidcprovider.HandleParam)
	require.NotEmpty(t, handle)

	// The consumer's login page authenticated the user and resumes the parked request.
	s, err := e.sessions.Create(ctx, durUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	login := b.resume(ctx, e.issuer, s.ID, map[string]any{"req": handle})
	require.Equal(t, http.StatusOK, login.status, login.body)
	assert.Equal(t, "/consent", login.redirectTo(t).Path, "the browser is sent to the consent page")

	// The consent page shows the scopes and the user approves them.
	granted := b.resume(ctx, e.issuer, s.ID,
		map[string]any{"req": handle, "scopes": strings.Fields(devE2EScope)})
	require.Equal(t, http.StatusOK, granted.status, granted.body)
	assert.Equal(t, "approved", granted.redirectTo(t).Query().Get(oidcprovider.DeviceResultParam))
}

// pollRaw asks the token endpoint once for deviceCode's tokens, as the device would, and
// returns the status and the error code of the answer.
func (e *devE2E) pollRaw(t *testing.T, deviceCode string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, e.issuer+"/oauth2/token",
		strings.NewReader(url.Values{
			"grant_type": {string(oidcprovider.GrantDeviceCode)}, "device_code": {deviceCode},
			"client_id": {devE2EClient},
		}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := e.srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	var doc map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	code, _ := doc["error"].(string)

	return res.StatusCode, code
}

func TestOIDCProvider_DeviceGrantEndToEnd(t *testing.T) {
	t.Parallel()

	// grantEndToEnd is the whole grant: the device asks for codes, a browser enters the user
	// code, signs in and approves, and the device polls to tokens, refreshes, and then is
	// refused when it replays its device code.
	grantEndToEnd := func(t *testing.T, e *devE2E) {
		ctx, cancel := context.WithTimeout(e.oauthCtx, 30*time.Second)
		defer cancel()

		da, err := e.conf.DeviceAuth(ctx)
		require.NoError(t, err)
		require.Equal(t, e.issuer+devE2EEntryPath, da.VerificationURI)
		require.NotEmpty(t, da.UserCode)
		assert.Empty(t, da.VerificationURIComplete, "the client did not opt in to a complete URI")

		// The device polls while the user is at the browser.
		type polled struct {
			tok *oauth2.Token
			err error
		}
		done := make(chan polled, 1)
		go func() {
			tok, err := e.conf.DeviceAccessToken(ctx, da)
			done <- polled{tok, err}
		}()

		e.approve(t, da.UserCode)

		var got polled
		select {
		case got = <-done:
		case <-ctx.Done():
			require.FailNow(t, "the device never received tokens", "the poll stayed pending: %v", ctx.Err())
		}
		require.NoError(t, got.err)
		tok := got.tok
		require.NotEmpty(t, tok.AccessToken)
		require.NotEmpty(t, tok.RefreshToken, "offline_access was approved")
		idToken, _ := tok.Extra("id_token").(string)
		assert.NotEmpty(t, idToken, "openid was approved")

		// A refresh through TokenSource, of a token whose access token has run out.
		expired := *tok
		expired.Expiry = time.Now().Add(-time.Hour)
		refreshed, err := e.conf.TokenSource(ctx, &expired).Token()
		require.NoError(t, err)
		assert.NotEqual(t, tok.AccessToken, refreshed.AccessToken)
		require.NotEmpty(t, refreshed.RefreshToken)

		// Replaying the device code is refused, and it ends the grant's family.
		status, code := e.pollRaw(t, da.DeviceCode)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", code)

		stale := *refreshed
		stale.Expiry = time.Now().Add(-time.Hour)
		_, err = e.conf.TokenSource(ctx, &stale).Token()
		var refused *oauth2.RetrieveError
		require.ErrorAs(t, err, &refused, "the refresh fails after the replay")
		assert.Equal(t, "invalid_grant", refused.ErrorCode)
	}

	// crossSiteLinkClaimsNothing is the phishing gate: a cross-site navigation to the
	// code-entry endpoint with a user code claims nothing and goes to the entry page, so the
	// device keeps waiting, and the same code is still claimable by a navigation of the user's own.
	crossSiteLinkClaimsNothing := func(t *testing.T, e *devE2E) {
		ctx := e.oauthCtx
		da, err := e.conf.DeviceAuth(ctx)
		require.NoError(t, err)

		b := e.newBrowser(t)
		gated := b.enter(t.Context(), e.issuer, da.UserCode, "cross-site")
		require.Equal(t, http.StatusSeeOther, gated.status, gated.body)
		assert.Equal(t, devE2EEntryPath, gated.location.Path, "the browser is sent to the entry page")
		assert.Equal(t, da.UserCode, gated.location.Query().Get("user_code"), "with the code prefilled")
		assert.Empty(t, gated.location.Query().Get(oidcprovider.HandleParam), "no request is parked")
		assert.Empty(t, b.client.Jar.Cookies(&url.URL{Scheme: "https", Host: strings.TrimPrefix(e.issuer, "https://")}),
			"no flow cookie is set")

		status, code := e.pollRaw(t, da.DeviceCode)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "authorization_pending", code, "the code was not claimed")

		// The user's own navigation, as the entry page's submit makes it, claims the code.
		claimed := b.enter(t.Context(), e.issuer, da.UserCode, "none")
		require.Equal(t, http.StatusSeeOther, claimed.status, claimed.body)
		assert.Equal(t, "/login", claimed.location.Path)
	}

	type testCase struct {
		name    string
		durable bool
		assert  func(t *testing.T, e *devE2E)
	}

	cases := []testCase{
		{name: "in-memory stores: the grant end to end", assert: grantEndToEnd},
		{name: "sqlstore on PostgreSQL: the grant end to end", durable: true, assert: grantEndToEnd},
		{name: "in-memory stores: a cross-site link claims nothing", assert: crossSiteLinkClaimsNothing},
		{name: "sqlstore on PostgreSQL: a cross-site link claims nothing", durable: true, assert: crossSiteLinkClaimsNothing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newDevE2E(t, tc.durable))
		})
	}
}
