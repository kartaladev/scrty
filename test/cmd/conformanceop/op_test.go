package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSuiteURL = "https://suite.example.test:8443"
	testAlias    = "scrty"
)

// op is a running conformance provider and a browser that trusts its certificate.
type op struct {
	issuer  string
	server  *server
	browser *http.Client
}

// startOP serves the provider over TLS on a loopback port, with the certificate it makes for itself.
func startOP(t *testing.T) *op {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	issuer := "https://" + ln.Addr().String()

	cert, err := selfSignedCertificate([]string{"127.0.0.1", "localhost"})
	require.NoError(t, err)

	srv, err := newServer(t.Context(), config{Issuer: issuer, SuiteURL: testSuiteURL, Alias: testAlias})
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()

		assert.NoError(t, srv.Shutdown(ctx))
	})

	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	go func() { _ = hs.ServeTLS(ln, "", "") }()

	t.Cleanup(func() { _ = hs.Close() })

	pool := x509.NewCertPool()
	require.NotNil(t, cert.Leaf, "the certificate must carry its parsed leaf, so a client can trust exactly it")
	pool.AddCert(cert.Leaf)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &op{
		issuer: issuer,
		server: srv,
		browser: &http.Client{
			Jar:       jar,
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// page is one response, read.
type page struct {
	status   int
	location string
	body     string
	url      *url.URL
}

func (o *op) do(t *testing.T, req *http.Request) page {
	t.Helper()

	res, err := o.browser.Do(req)
	require.NoError(t, err)

	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	return page{status: res.StatusCode, location: res.Header.Get("Location"), body: string(body), url: req.URL}
}

func (o *op) get(t *testing.T, target string) page {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	require.NoError(t, err)

	return o.do(t, req)
}

func (o *op) postForm(t *testing.T, target string, form url.Values) page {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return o.do(t, req)
}

// follow goes where redirects lead while they stay on the provider, as a browser would, and
// returns the first response that does not redirect there: a page, or a redirect to a relying
// party.
func (o *op) follow(t *testing.T, p page) page {
	t.Helper()

	for range 10 {
		if p.status < 300 || p.status > 399 || !strings.HasPrefix(p.location, o.issuer) {
			return p
		}

		p = o.get(t, p.location)
	}

	require.FailNow(t, "too many redirects")

	return p
}

var (
	formAction = regexp.MustCompile(`<form[^>]*action="([^"]*)"`)
	hiddenReq  = regexp.MustCompile(`<input[^>]*type="hidden"[^>]*name="req"[^>]*value="([^"]*)"`)
)

// submit fills in the form on p and posts it, the way a browser does: to the form's action, with
// its hidden fields and the given ones.
func (o *op) submit(t *testing.T, p page, fields url.Values) page {
	t.Helper()

	action := formAction.FindStringSubmatch(p.body)
	require.NotNil(t, action, "no form on the page at %s: %s", p.url, p.body)

	target, err := p.url.Parse(action[1])
	require.NoError(t, err)

	form := url.Values{}

	if m := hiddenReq.FindStringSubmatch(p.body); m != nil {
		form.Set("req", m[1])
	}

	for k, v := range fields {
		form[k] = v
	}

	return o.postForm(t, target.String(), form)
}

func (o *op) authorizeURL(t *testing.T, clientID string, extra url.Values) string {
	t.Helper()

	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {testSuiteURL + "/test/a/" + testAlias + "/callback"},
		"scope":         {"openid profile email address phone offline_access"},
		"state":         {"state-0123456789"},
		"nonce":         {"nonce-0123456789"},
	}
	for k, v := range extra {
		q[k] = v
	}

	return o.issuer + "/oauth2/authorize?" + q.Encode()
}

// login runs a request up to the code, signing in and consenting on the plain forms.
func (o *op) login(t *testing.T, authorize string) *url.URL {
	t.Helper()

	p := o.follow(t, o.get(t, authorize))
	require.Equal(t, http.StatusOK, p.status, "the login page: %s", p.body)
	require.Contains(t, p.body, "Sign-in")

	p = o.follow(t, o.submit(t, p, url.Values{"username": {userName}, "password": {userPassword}}))
	if p.status == http.StatusOK {
		require.Contains(t, p.body, "consent", "the consent page: %s", p.body)
		p = o.follow(t, o.submit(t, p, url.Values{"decision": {"allow"}}))
	}

	require.Equal(t, http.StatusSeeOther, p.status, "the redirect to the relying party: %s", p.body)

	loc, err := url.Parse(p.location)
	require.NoError(t, err)

	return loc
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
}

func (o *op) token(t *testing.T, clientID, secret string, post bool, form url.Values) (int, tokenResponse) {
	t.Helper()

	if post {
		form.Set("client_id", clientID)
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, o.issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if !post {
		req.SetBasicAuth(clientID, secret)
	}

	res, err := o.browser.Do(req)
	require.NoError(t, err)

	defer func() { _ = res.Body.Close() }()

	var tr tokenResponse

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(body, &tr), string(body))

	return res.StatusCode, tr
}

func TestConformanceOP_BrowserFlow(t *testing.T) {
	t.Parallel()

	o := startOP(t)

	var disc struct {
		Issuer     string `json:"issuer"`
		Userinfo   string `json:"userinfo_endpoint"`
		EndSession string `json:"end_session_endpoint"`
	}

	t.Run("discovery is https and names the endpoints", func(t *testing.T) {
		p := o.get(t, o.issuer+"/.well-known/openid-configuration")
		require.Equal(t, http.StatusOK, p.status, p.body)
		require.NoError(t, json.Unmarshal([]byte(p.body), &disc))
		assert.Equal(t, o.issuer, disc.Issuer)
		assert.True(t, strings.HasPrefix(disc.Userinfo, "https://"))
		assert.True(t, strings.HasPrefix(disc.EndSession, "https://"))
	})

	var tokens tokenResponse

	t.Run("a code after a form login and a form consent, exchanged for tokens", func(t *testing.T) {
		loc := o.login(t, o.authorizeURL(t, clientBasic, nil))
		assert.Equal(t, testSuiteURL+"/test/a/"+testAlias+"/callback", loc.Scheme+"://"+loc.Host+loc.Path)
		assert.Equal(t, "state-0123456789", loc.Query().Get("state"))
		require.NotEmpty(t, loc.Query().Get("code"))

		status, tr := o.token(t, clientBasic, secretBasic, false, url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {loc.Query().Get("code")},
			"redirect_uri": {testSuiteURL + "/test/a/" + testAlias + "/callback"},
		})
		require.Equal(t, http.StatusOK, status)
		require.NotEmpty(t, tr.IDToken)
		require.NotEmpty(t, tr.AccessToken)
		require.NotEmpty(t, tr.RefreshToken, "the client is registered for the refresh grant")

		tokens = tr
	})

	t.Run("UserInfo releases the user's claims, email_verified true", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, disc.Userinfo, http.NoBody)
		require.NoError(t, err)

		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

		p := o.do(t, req)
		require.Equal(t, http.StatusOK, p.status, p.body)

		var claims map[string]any
		require.NoError(t, json.Unmarshal([]byte(p.body), &claims))

		assert.Equal(t, userID, claims["sub"])
		assert.Equal(t, userName, claims["preferred_username"])
		assert.Equal(t, true, claims["email_verified"])
		assert.Equal(t, true, claims["phone_number_verified"])
		assert.NotEmpty(t, claims["name"])
		assert.NotEmpty(t, claims["email"])
		assert.NotEmpty(t, claims["phone_number"])
		assert.IsType(t, map[string]any{}, claims["address"])
	})

	t.Run("a refresh token is exchanged for new tokens", func(t *testing.T) {
		status, tr := o.token(t, clientBasic, secretBasic, false, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {tokens.RefreshToken},
		})
		require.Equal(t, http.StatusOK, status)
		assert.NotEmpty(t, tr.AccessToken)
	})

	t.Run("the browser session answers prompt=none without a page", func(t *testing.T) {
		p := o.follow(t, o.get(t, o.authorizeURL(t, clientBasic, url.Values{"prompt": {"none"}})))
		require.Equal(t, http.StatusSeeOther, p.status, p.body)
		assert.Contains(t, p.location, "code=", "single sign-on answers from the cookie the login page set")
	})

	t.Run("end-session with the hint ends the sign-in and returns to the registered URI", func(t *testing.T) {
		post := testSuiteURL + "/test/a/" + testAlias + "/post_logout_redirect"
		p := o.follow(t, o.get(t, disc.EndSession+"?"+url.Values{
			"id_token_hint":            {tokens.IDToken},
			"post_logout_redirect_uri": {post},
			"state":                    {"bye-0123456789"},
		}.Encode()))
		require.Equal(t, http.StatusSeeOther, p.status, p.body)
		assert.True(t, strings.HasPrefix(p.location, post+"?state=bye-0123456789"), p.location)

		after := o.follow(t, o.get(t, o.authorizeURL(t, clientBasic, url.Values{"prompt": {"none"}})))
		require.Equal(t, http.StatusSeeOther, after.status, after.body)
		assert.Contains(t, after.location, "error=login_required")
	})
}

func TestConformanceOP_LogoutWithoutHintAsksOnAPlainForm(t *testing.T) {
	t.Parallel()

	o := startOP(t)

	loc := o.login(t, o.authorizeURL(t, clientPost, nil))
	require.NotEmpty(t, loc.Query().Get("code"))

	p := o.follow(t, o.get(t, o.issuer+"/oauth2/logout"))
	require.Equal(t, http.StatusOK, p.status, "the logout page asks: %s", p.body)

	p = o.follow(t, o.submit(t, p, url.Values{"confirmed": {"true"}}))
	require.Equal(t, http.StatusOK, p.status, p.body)
	assert.Contains(t, p.body, "Sign-out Success")

	after := o.follow(t, o.get(t, o.authorizeURL(t, clientPost, url.Values{"prompt": {"none"}})))
	require.Equal(t, http.StatusSeeOther, after.status, after.body)
	assert.Contains(t, after.location, "error=login_required")
}

func TestConformanceOP_RefusesAWrongPasswordOnTheForm(t *testing.T) {
	t.Parallel()

	o := startOP(t)

	p := o.follow(t, o.get(t, o.authorizeURL(t, clientBasic, nil)))
	require.Equal(t, http.StatusOK, p.status, p.body)

	p = o.follow(t, o.submit(t, p, url.Values{"username": {userName}, "password": {"wrong"}}))
	assert.Equal(t, http.StatusUnauthorized, p.status)
	assert.Contains(t, p.body, "Sign-in", "the form is shown again")
}

// The configuration the suite is given must name what the provider registers.
func TestConformanceConfig_MatchesTheProvider(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../conformance/oidcc.json")
	require.NoError(t, err)

	var cfg struct {
		Server     map[string]string         `json:"server"`
		Alias      string                    `json:"alias"`
		Client     map[string]string         `json:"client"`
		Client2    map[string]string         `json:"client2"`
		ClientPost map[string]string         `json:"client_secret_post"`
		Override   map[string]map[string]any `json:"override"`
	}
	require.NoError(t, json.Unmarshal(raw, &cfg))

	assert.Equal(t, testAlias, cfg.Alias)
	assert.Equal(t, clientBasic, cfg.Client["client_id"])
	assert.Equal(t, secretBasic, cfg.Client["client_secret"])
	assert.Equal(t, clientBasic2, cfg.Client2["client_id"])
	assert.Equal(t, secretBasic2, cfg.Client2["client_secret"])

	assert.Equal(t, clientPost, cfg.ClientPost["client_id"], "the secret_post module reads its own client")
	assert.Equal(t, secretPost, cfg.ClientPost["client_secret"])

	bcl, ok := cfg.Override["oidcc-backchannel-rp-initiated-logout"]["client"].(map[string]any)
	require.True(t, ok, "the back-channel module takes the client that registers the logout URI")
	assert.Equal(t, clientBCL, bcl["client_id"])
	assert.Equal(t, secretBCL, bcl["client_secret"])

	assert.Contains(t, cfg.Override, "oidcc-prompt-login")

	expected, err := os.ReadFile("../../conformance/expected-failures.json")
	require.NoError(t, err)

	var entries []map[string]any
	require.NoError(t, json.Unmarshal(expected, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "oidcc-ensure-request-without-nonce-succeeds-for-code-flow", entries[0]["test-name"])
}
