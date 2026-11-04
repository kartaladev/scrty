package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	tokenURL          = opIssuer + "/oauth2/token"
	rpCallback        = "https://rp.example.com/cb"
	tokenSecret       = "0123456789abcdef0123456789abcdef"
	pkceChallengeS256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	pkceVerifierS256  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	tokenAddr         = "192.0.2.10:4711"
	tokenOtherAddr    = "192.0.2.77:4711"
	tokenWeb          = "web"
	tokenCodeOnly     = "code-only"
	tokenPublic       = "public"
	tokenDPoPWeb      = "dpop-web"
	tokenMTLSWeb      = "mtls-web"
	tokenPostWeb      = "post-web"
	tokenNonceBytes   = "0123456789abcdef0123456789abcdef"

	// tokenPastGrace is longer than a refresh token's default grace. A later success proves a token
	// unrotated only from here: inside the grace, a token that did rotate is answered too, and
	// inside the same-successor window it is answered the very token its first refresh would get.
	tokenPastGrace = 31 * time.Second
)

// tokenKeys is one set of signing keys for every endpoint in this file. Generating
// them is the slow part, and these tests only read what the tokens say.
var tokenKeys = sync.OnceValue(func() *signingkey.Keys {
	return must.Must(signingkey.New(context.Background(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
})

// tokenSetup is what a row asks of its endpoint.
type tokenSetup struct {
	dpop     func(t *testing.T) *httpsec.DPoP
	cert     bool
	chain    []httpsec.Option
	endpoint func(t *testing.T) []httpsec.OIDCProviderOption
}

// tokenEndpoint is a provider's token endpoint on a chain, with what a code is issued from.
type tokenEndpoint struct {
	p        *oidcprovider.Provider
	chain    *httpsec.Chain
	clk      *clockwork.FakeClock
	consents *oidcprovider.MemoryConsentStore
	outage   *atomic.Bool
}

func newTokenEndpoint(t *testing.T, setup tokenSetup) *tokenEndpoint {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())
	consents := must.Must(oidcprovider.NewMemoryConsentStore())
	outage := &atomic.Bool{}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			if outage.Load() {
				return nil, errors.New("user store secret text")
			}

			return &identity.Details{ID: user, Active: true}, nil
		},
	).AnyTimes()

	secret := []byte(tokenSecret)
	scopes := []string{"openid", "profile", "offline_access"}
	both := []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken}
	clients := []oidcprovider.Client{
		{
			ID: tokenWeb, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{rpCallback},
			Scopes: scopes, GrantTypes: both,
		},
		{
			ID: tokenCodeOnly, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{rpCallback},
			Scopes: scopes,
		},
		{
			ID: tokenPublic, Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
			RedirectURIs: []string{rpCallback}, Scopes: scopes, GrantTypes: both,
		},
		{
			ID: tokenPostWeb, Type: oidcprovider.Confidential, Secret: secret, AuthMethod: oidcprovider.ClientSecretPost,
			RedirectURIs: []string{rpCallback}, Scopes: scopes,
		},
	}

	popts := []oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithoutBrowserSessions(),
	}
	chainOpts := []httpsec.Option{httpsec.WithClock(clk)}
	if setup.dpop != nil {
		popts = append(popts, oidcprovider.WithDPoP())
		chainOpts = append(chainOpts, httpsec.EnableDPoP(*setup.dpop(t)))
		clients = append(clients, oidcprovider.Client{
			ID: tokenDPoPWeb, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{rpCallback},
			Scopes: scopes, GrantTypes: both, RequireBinding: oidcprovider.BindingDPoP,
		})
	}
	if setup.cert {
		chainOpts = append(chainOpts, httpsec.EnableCertificateBinding())
		clients = append(clients, oidcprovider.Client{
			ID: tokenMTLSWeb, Type: oidcprovider.Confidential, Secret: secret, RedirectURIs: []string{rpCallback},
			Scopes: scopes, GrantTypes: both, RequireBinding: oidcprovider.BindingMTLS,
		})
	}

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       opIssuer,
		Clients:      clients,
		Keys:         tokenKeys(),
		Users:        users,
		LoginURL:     opIssuer + "/login",
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout-page",
		LoggedOutURL: opIssuer + "/bye",
	}, popts...)
	require.NoError(t, err)

	var endpoint []httpsec.OIDCProviderOption
	if setup.endpoint != nil {
		endpoint = setup.endpoint(t)
	}

	f := &opFixture{keys: tokenKeys()}
	chainOpts = append(chainOpts, f.wired(t, p)...)
	chainOpts = append(chainOpts, setup.chain...)
	chainOpts = append(chainOpts, httpsec.EnableOIDCProvider(p, endpoint...))

	chain, err := httpsec.New(chainOpts...)
	require.NoError(t, err)

	return &tokenEndpoint{p: p, chain: chain, clk: clk, consents: consents, outage: outage}
}

// issue is a code for clientID from a fresh sign-in, for the scopes it asks, with change
// applied to the authorization request.
func (e *tokenEndpoint) issue(t *testing.T, clientID string, change func(url.Values)) string {
	t.Helper()

	const scope = "openid profile offline_access"

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {rpCallback},
		"scope":                 {scope},
		"state":                 {"xyz"},
		"code_challenge":        {pkceChallengeS256},
		"code_challenge_method": {"S256"},
	}
	if change != nil {
		change(params)
	}

	parked, err := e.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: params})
	require.NoError(t, err)
	require.NotEmpty(t, parked.FlowSecret, "the request was parked: %s", parked.Location)

	login, err := url.Parse(parked.Location)
	require.NoError(t, err)

	user := identity.UserID("u-1")
	require.NoError(t, e.consents.Give(t.Context(), user, clientID, strings.Fields(params.Get("scope")), true, e.clk.Now()))

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	res, err := e.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle:     login.Query().Get("req"),
		FlowSecret: parked.FlowSecret,
		SignIn: &oidcprovider.SignIn{
			User:              user,
			Family:            family,
			AuthenticatedAt:   e.clk.Now(),
			AMR:               []string{"pwd"},
			AbsoluteExpiresAt: e.clk.Now().Add(8 * time.Hour),
		},
		IdleTimeout: 15 * time.Minute,
	})
	require.NoError(t, err)

	location, err := url.Parse(res.RedirectTo)
	require.NoError(t, err)
	code := location.Query().Get("code")
	require.NotEmpty(t, code, res.RedirectTo)

	return code
}

// tokenAnswer is the endpoint's whole response.
type tokenAnswer struct {
	status   int
	header   http.Header
	body     string
	passedOn bool
}

// tokenChange alters a request before it is sent.
type tokenChange func(r *http.Request)

// exchangeOf is the form exchanging code.
func exchangeOf(code string, extra ...string) url.Values {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rpCallback},
		"code_verifier": {pkceVerifierS256},
	}
	addPairs(form, extra)

	return form
}

// refreshOf is the form refreshing raw.
func refreshOf(raw string, extra ...string) url.Values {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}
	addPairs(form, extra)

	return form
}

func addPairs(form url.Values, pairs []string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		form.Add(pairs[i], pairs[i+1])
	}
}

// asClient authenticates by Basic, under clientID's secret.
func asClient(clientID string) tokenChange {
	return func(r *http.Request) { r.SetBasicAuth(clientID, tokenSecret) }
}

// withSecret authenticates by Basic, with secret.
func withSecret(clientID, secret string) tokenChange {
	return func(r *http.Request) { r.SetBasicAuth(clientID, secret) }
}

// fromAddr sends from another source.
func fromAddr(addr string) tokenChange {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// withCertificate presents c over the connection.
func withCertificate(c *x509.Certificate) tokenChange {
	return func(r *http.Request) {
		r.TLS.PeerCertificates = []*x509.Certificate{c}
	}
}

// signedProof is a proof from k for the token endpoint, at the endpoint's present,
// with claims set over a valid one's.
func (e *tokenEndpoint) signedProof(t *testing.T, k dpopKey, jti string, claims map[string]any) string {
	t.Helper()

	parts := k.validProof(jti).with(map[string]any{
		"htm": http.MethodPost,
		"htu": tokenURL,
		"iat": e.clk.Now().Unix(),
	})
	if claims != nil {
		parts = parts.with(claims)
	}

	return parts.sign(t)
}

// withProof carries a proof from k.
func (e *tokenEndpoint) withProof(t *testing.T, k dpopKey, jti string, claims map[string]any) tokenChange {
	t.Helper()

	proof := e.signedProof(t, k, jti, claims)

	return func(r *http.Request) { r.Header.Add("DPoP", proof) }
}

// send posts form to the token endpoint over TLS.
func (e *tokenEndpoint) send(t *testing.T, form url.Values, change ...tokenChange) tokenAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = tokenAddr
	for _, c := range change {
		c(r)
	}

	return e.serve(t, r)
}

func (e *tokenEndpoint) serve(t *testing.T, r *http.Request) tokenAnswer {
	t.Helper()

	var passedOn bool

	h := e.chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passedOn = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	return tokenAnswer{status: rec.Code, header: rec.Header(), body: rec.Body.String(), passedOn: passedOn}
}

// document is a success's JSON body.
func (a tokenAnswer) document(t *testing.T) map[string]any {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)

	return doc
}

// confirmation is the cnf claim of a success's access token, read and not verified: these
// tests pin what the endpoint asked the token to carry.
func (a tokenAnswer) confirmation(t *testing.T) map[string]any {
	t.Helper()

	raw, _ := a.document(t)["access_token"].(string)
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3, "a signed access token")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))

	cnf, _ := claims["cnf"].(map[string]any)

	return cnf
}

// assertTokenHeaders pins what every answer of the endpoint carries.
func assertTokenHeaders(t *testing.T, a tokenAnswer) {
	t.Helper()

	assert.False(t, a.passedOn, "the application never sees a request meant for the provider")
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", a.header.Get("Pragma"))
}

// assertTokenRefused pins a protocol refusal: the code alone, and no other member.
func assertTokenRefused(t *testing.T, a tokenAnswer, code string) {
	t.Helper()

	assertTokenHeaders(t, a)

	status := http.StatusBadRequest
	if code == oidcprovider.CodeInvalidClient {
		status = http.StatusUnauthorized
		assert.Equal(t, `Basic realm="oauth2"`, a.header.Get("WWW-Authenticate"))
	} else {
		assert.Empty(t, a.header.Get("WWW-Authenticate"))
	}

	assert.Equal(t, status, a.status)
	assert.Equal(t, "application/json", a.header.Get("Content-Type"))
	assert.Equal(t, `{"error":"`+code+`"}`, a.body)
}

// assertTokenIssued pins a success, and returns its document.
func assertTokenIssued(t *testing.T, a tokenAnswer, tokenType string) map[string]any {
	t.Helper()

	assertTokenHeaders(t, a)
	require.Equal(t, http.StatusOK, a.status, a.body)
	assert.Equal(t, "application/json", a.header.Get("Content-Type"))

	doc := a.document(t)
	assert.NotEmpty(t, doc["access_token"])
	assert.Equal(t, tokenType, doc["token_type"])
	assert.NotZero(t, doc["expires_in"])
	assert.NotContains(t, doc, "error")

	return doc
}

// assertTokenFailed pins a failure that is no refusal: no text, and nothing a client could read.
func assertTokenFailed(t *testing.T, a tokenAnswer) {
	t.Helper()

	assertTokenHeaders(t, a)
	assert.Equal(t, http.StatusInternalServerError, a.status)
	assert.NotContains(t, a.body, "secret text")
	assert.NotContains(t, a.body, "access_token")
}

// memoryLimit is a limiter of its own for one row's endpoint.
func memoryLimit(t *testing.T, limit int) []httpsec.OIDCProviderOption {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(limit, time.Hour)
	require.NoError(t, err)

	return []httpsec.OIDCProviderOption{httpsec.WithOIDCTokenLimiter(l)}
}

func limitedTo(limit int) func(*testing.T) []httpsec.OIDCProviderOption {
	return func(t *testing.T) []httpsec.OIDCProviderOption {
		t.Helper()

		return memoryLimit(t, limit)
	}
}

// TestOIDCToken pins the token endpoint's protocol: what it accepts, what it answers, and that no
// answer can be cached.
func TestOIDCToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup tokenSetup
		// send makes the row's one request, of whatever shape, and returns its answer.
		send   func(t *testing.T, e *tokenEndpoint) tokenAnswer
		assert func(t *testing.T, e *tokenEndpoint, a tokenAnswer)
	}

	// exchangeWeb is a good exchange for the web client, with change applied.
	exchangeWeb := func(t *testing.T, e *tokenEndpoint, change ...tokenChange) tokenAnswer {
		t.Helper()

		return e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), append([]tokenChange{asClient(tokenWeb)}, change...)...)
	}

	refused := func(code string) func(*testing.T, *tokenEndpoint, tokenAnswer) {
		return func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
			t.Helper()
			assertTokenRefused(t, a, code)
		}
	}

	// wrongSecrets charges the source n times.
	wrongSecrets := func(t *testing.T, e *tokenEndpoint, n int) {
		t.Helper()

		for range n {
			a := e.send(t, refreshOf("rt.none"), withSecret(tokenWeb, "wrong"))
			assertTokenRefused(t, a, oidcprovider.CodeInvalidClient)
		}
	}

	cases := []testCase{
		{
			name: "GET is refused and issues nothing",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tokenURL+"?code=x&grant_type=authorization_code", nil)
				r.RemoteAddr = tokenAddr

				return e.serve(t, r)
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenHeaders(t, a)
				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, http.MethodPost, a.header.Get("Allow"))
				assert.NotContains(t, a.body, "access_token")
			},
		},
		{
			name: "the password grant is not supported",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, url.Values{"grant_type": {"password"}, "username": {"u"}, "password": {"p"}}, asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeUnsupportedGrantType),
		},
		{
			name: "a grant the client is not registered for",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, refreshOf("rt.none"), asClient(tokenCodeOnly))
			},
			assert: refused(oidcprovider.CodeUnauthorizedClient),
		},
		{
			name: "a repeated parameter",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, exchangeOf(e.issue(t, tokenWeb, nil), "code", "again"), asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a repeated Authorization header",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e, func(r *http.Request) { r.Header.Add("Authorization", "Basic b3RoZXI6b3RoZXI=") })
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a wrong secret leaves the code to exchange",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				a := e.send(t, exchangeOf(code), withSecret(tokenWeb, "wrong"))
				assertTokenRefused(t, a, oidcprovider.CodeInvalidClient)

				return e.send(t, exchangeOf(code), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "a secret in the form authenticates a client registered for it",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, exchangeOf(e.issue(t, tokenPostWeb, nil), "client_id", tokenPostWeb, "client_secret", tokenSecret))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "two methods at once",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, exchangeOf(e.issue(t, tokenWeb, nil), "client_secret", tokenSecret), asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "an expired code",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				e.clk.Advance(time.Hour)

				return e.send(t, exchangeOf(code), asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidGrant),
		},
		{
			name: "a success holds the five fields",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e)
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()

				doc := assertTokenIssued(t, a, "Bearer")
				assert.Equal(t, "openid profile offline_access", doc["scope"])
				assert.NotEmpty(t, doc["id_token"])
				assert.NotEmpty(t, doc["refresh_token"])
				assert.ElementsMatch(t,
					[]string{"access_token", "token_type", "expires_in", "scope", "id_token", "refresh_token"},
					slices.Collect(maps.Keys(doc)))
			},
		},
		{
			name: "no refresh token for a client without the grant, and no ID token without openid",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenCodeOnly, func(v url.Values) { v.Set("scope", "profile") })

				return e.send(t, exchangeOf(code), asClient(tokenCodeOnly))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()

				doc := assertTokenIssued(t, a, "Bearer")
				assert.NotContains(t, doc, "refresh_token")
				assert.NotContains(t, doc, "id_token")
			},
		},
		{
			name: "a refresh is served too",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				first := assertTokenIssued(t, exchangeWeb(t, e), "Bearer")

				return e.send(t, refreshOf(first["refresh_token"].(string)), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assert.NotEmpty(t, assertTokenIssued(t, a, "Bearer")["refresh_token"])
			},
		},

		// R11: what the query may and may not do.
		{
			name: "client_secret in the query",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL+"?client_secret="+tokenSecret,
					strings.NewReader(exchangeOf(code, "client_id", tokenWeb).Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.RemoteAddr = tokenAddr

				return e.serve(t, r)
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "client_assertion in the query",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL+"?client_assertion=x",
					strings.NewReader(exchangeOf(e.issue(t, tokenWeb, nil)).Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.RemoteAddr = tokenAddr
				r.SetBasicAuth(tokenWeb, tokenSecret)

				return e.serve(t, r)
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "client_id in the query authenticates no one",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL+"?client_id="+tokenPublic,
					strings.NewReader(exchangeOf(e.issue(t, tokenPublic, nil)).Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.RemoteAddr = tokenAddr

				return e.serve(t, r)
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name: "a code in the query is not read",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				form := exchangeOf(code)
				form.Del("code")
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL+"?code="+url.QueryEscape(code),
					strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.RemoteAddr = tokenAddr
				r.SetBasicAuth(tokenWeb, tokenSecret)
				assertTokenRefused(t, e.serve(t, r), oidcprovider.CodeInvalidRequest)

				return e.send(t, exchangeOf(code), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "an empty parameter counts as omitted",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, exchangeOf(e.issue(t, tokenWeb, nil), "client_secret", "", "scope", ""), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "an empty grant type is a missing one",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, url.Values{"grant_type": {""}}, asClient(tokenWeb))
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},

		// R11: the transport, and what a body must be.
		{
			name: "plain HTTP is refused, with the code left to exchange",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				a := e.send(t, exchangeOf(code), asClient(tokenWeb), func(r *http.Request) { r.TLS = nil })
				assertTokenRefused(t, a, oidcprovider.CodeInvalidRequest)

				return e.send(t, exchangeOf(code), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name:  "a deployment declared HTTPS is served behind its proxy",
			setup: tokenSetup{chain: []httpsec.Option{httpsec.WithHTTPSDeployment()}},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e, func(r *http.Request) { r.TLS = nil })
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "a body that is not a form",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e, func(r *http.Request) { r.Header.Set("Content-Type", "application/json") })
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a form that does not parse",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, nil, asClient(tokenWeb), func(r *http.Request) {
					r.Body = io.NopCloser(strings.NewReader("grant_type=refresh_token&a=%zz"))
				})
			},
			assert: refused(oidcprovider.CodeInvalidRequest),
		},
		{
			name: "a body over the default bound",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, url.Values{"grant_type": {strings.Repeat("x", int(httpsec.DefaultLoginBodyLimit))}}, asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenHeaders(t, a)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
			},
		},
		{
			name: "a consumer's bound replaces the default",
			setup: tokenSetup{endpoint: func(*testing.T) []httpsec.OIDCProviderOption {
				return []httpsec.OIDCProviderOption{httpsec.WithOIDCTokenBodyLimit(16)}
			}},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e)
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenHeaders(t, a)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
			},
		},

		// Failed client authentication is charged to the source.
		{
			name: "past the default limit, the right secret is refused unchecked",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				wrongSecrets(t, e, 10)

				return exchangeWeb(t, e)
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name:  "below the limit, the right secret is served",
			setup: tokenSetup{endpoint: limitedTo(3)},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				wrongSecrets(t, e, 2)

				return exchangeWeb(t, e)
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name:  "a consumer's limiter replaces the default",
			setup: tokenSetup{endpoint: limitedTo(2)},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				wrongSecrets(t, e, 2)
				code := e.issue(t, tokenWeb, nil)
				assertTokenRefused(t, e.send(t, exchangeOf(code), asClient(tokenWeb)), oidcprovider.CodeInvalidClient)

				return e.send(t, exchangeOf(code), asClient(tokenWeb), fromAddr(tokenOtherAddr))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "a limiter that cannot answer fails closed, charging nothing",
			setup: tokenSetup{endpoint: func(t *testing.T) []httpsec.OIDCProviderOption {
				t.Helper()

				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errors.New("limiter secret text")).Times(1)

				return []httpsec.OIDCProviderOption{httpsec.WithOIDCTokenLimiter(limiter)}
			}},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e)
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name:  "a source that cannot be attributed is refused",
			setup: tokenSetup{endpoint: limitedTo(3)},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return exchangeWeb(t, e, fromAddr("not an address"))
			},
			assert: refused(oidcprovider.CodeInvalidClient),
		},
		{
			name:  "a grant refused is not charged",
			setup: tokenSetup{endpoint: limitedTo(1)},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				a := e.send(t, refreshOf("rt.none"), asClient(tokenWeb))
				assertTokenRefused(t, a, oidcprovider.CodeInvalidGrant)

				return exchangeWeb(t, e)
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},

		// What is no refusal goes to the chain's error handling.
		{
			name:  "a dependency's failure is 500 with no text, charged to no one",
			setup: tokenSetup{endpoint: limitedTo(1)},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				e.outage.Store(true)
				a := e.send(t, exchangeOf(code), asClient(tokenWeb))
				assertTokenFailed(t, a)
				e.outage.Store(false)

				return e.send(t, exchangeOf(code), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name:  "a caller who has left spends nothing, and is charged nothing",
			setup: tokenSetup{endpoint: limitedTo(1)},
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				a := e.send(t, exchangeOf(code), asClient(tokenWeb), func(r *http.Request) {
					ctx, cancel := context.WithCancel(r.Context())
					cancel()
					*r = *r.WithContext(ctx)
				})
				assertTokenHeaders(t, a)
				assert.NotEqual(t, http.StatusOK, a.status)
				assert.NotContains(t, a.body, "access_token")

				return e.send(t, exchangeOf(code), asClient(tokenWeb))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
			},
		},
		{
			name: "a request elsewhere passes through",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL+"/below", nil))
			},
			assert: func(t *testing.T, _ *tokenEndpoint, a tokenAnswer) {
				t.Helper()
				assert.True(t, a.passedOn)
				assert.Empty(t, a.header.Get("Pragma"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newTokenEndpoint(t, tc.setup)
			tc.assert(t, e, tc.send(t, e))
		})
	}
}

// TestOIDCToken_Options pins what the endpoint's options refuse, at construction.
func TestOIDCToken_Options(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opt    httpsec.OIDCProviderOption
		assert func(t *testing.T, err error)
	}

	refused := func(option string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, option)
		}
	}

	var typedNil *ratelimit.MemoryLimiter

	cases := []testCase{
		{name: "a nil limiter", opt: httpsec.WithOIDCTokenLimiter(nil), assert: refused("WithOIDCTokenLimiter")},
		{name: "a typed nil limiter", opt: httpsec.WithOIDCTokenLimiter(typedNil), assert: refused("WithOIDCTokenLimiter")},
		{name: "a bound of zero", opt: httpsec.WithOIDCTokenBodyLimit(0), assert: refused("WithOIDCTokenBodyLimit")},
		{name: "a negative bound", opt: httpsec.WithOIDCTokenBodyLimit(-1), assert: refused("WithOIDCTokenBodyLimit")},
		{
			name: "a positive bound",
			opt:  httpsec.WithOIDCTokenBodyLimit(1),
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	f := &opFixture{keys: tokenKeys()}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			_, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, tc.opt))...)
			tc.assert(t, err)
		})
	}
}

// TestOIDCToken_SecurityEvents pins that the endpoint reports through the provider alone: a chain's
// sink hears each outcome once.
func TestOIDCToken_SecurityEvents(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		send   func(t *testing.T, e *tokenEndpoint) tokenAnswer
		assert func(t *testing.T, rec *eventRecorder, a tokenAnswer)
	}

	cases := []testCase{
		{
			name: "a refused client",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, refreshOf("rt.none"), withSecret(tokenWeb, "wrong"))
			},
			assert: func(t *testing.T, rec *eventRecorder, a tokenAnswer) {
				t.Helper()
				assertTokenRefused(t, a, oidcprovider.CodeInvalidClient)
				got := rec.named(event.ClientAuthRefused)
				require.Len(t, got, 1)
				assert.Equal(t, tokenWeb, got[0].Client)
			},
		},
		{
			name: "a grant created",
			send: func(t *testing.T, e *tokenEndpoint) tokenAnswer {
				t.Helper()

				return e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb))
			},
			assert: func(t *testing.T, rec *eventRecorder, a tokenAnswer) {
				t.Helper()
				assertTokenIssued(t, a, "Bearer")
				assert.Len(t, rec.named(event.GrantCreated), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &eventRecorder{}
			e := newTokenEndpoint(t, tokenSetup{chain: []httpsec.Option{httpsec.EnableSecurityEvents(rec.sink)}})
			tc.assert(t, rec, tc.send(t, e))
		})
	}
}

// TestOIDCToken_FlushesItsGuard pins that a chain's flush reaches the throttle's sampled records.
func TestOIDCToken_FlushesItsGuard(t *testing.T) {
	t.Parallel()

	var (
		mu         sync.Mutex
		suppressed = map[string]int{}
	)

	e := newTokenEndpoint(t, tokenSetup{
		endpoint: limitedTo(1),
		chain: []httpsec.Option{httpsec.WithRefusalLogReporter(func(key string, n int) {
			mu.Lock()
			defer mu.Unlock()
			suppressed[key] += n
		}), httpsec.WithLogger(slog.New(slog.DiscardHandler))},
	})

	for range 4 {
		e.send(t, refreshOf("rt.none"), withSecret(tokenWeb, "wrong"))
	}

	require.NoError(t, e.chain.FlushRefusalLogs())

	mu.Lock()
	defer mu.Unlock()

	var total int
	for key, n := range suppressed {
		if strings.Contains(key, "oidc-token") {
			total += n
		}
	}
	assert.Positive(t, total, "the throttled source's suppressed records are reported: %v", suppressed)
}

// plainDPoP is DPoP for the token endpoint's URLs.
func plainDPoP(*testing.T) *httpsec.DPoP { return &httpsec.DPoP{PublicURL: opIssuer} }

// requiredDPoP is DPoP that a chain requires of every request.
func requiredDPoP(*testing.T) *httpsec.DPoP { return &httpsec.DPoP{PublicURL: opIssuer, Require: true} }

// noncedDPoP is DPoP with server nonces.
func noncedDPoP(t *testing.T) *httpsec.DPoP {
	t.Helper()

	return &httpsec.DPoP{PublicURL: opIssuer, Nonce: true, NonceCipher: newNonceCipher(t, []byte(tokenNonceBytes))}
}

// sealFailingDPoP is DPoP with server nonces, whose cipher cannot reach its keys.
func sealFailingDPoP(t *testing.T) *httpsec.DPoP {
	t.Helper()

	cipher := NewMockNonceCipher(gomock.NewController(t))
	cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("cipher secret text")).AnyTimes()

	return &httpsec.DPoP{PublicURL: opIssuer, Nonce: true, NonceCipher: cipher}
}

// TestOIDCToken_SenderConstrained pins what the endpoint binds, and the order the binding rests on: a proof
// is judged before a code is spent or a token rotated. Each "unspent" and "unrotated" is proved by a later
// request with the same code or token succeeding.
func TestOIDCToken_SenderConstrained(t *testing.T) {
	t.Parallel()

	k1 := newDPoPKey(t, elliptic.P256())
	k2 := newDPoPKey(t, elliptic.P256())
	cert := newClientCert(t, "client-c")

	type testCase struct {
		name  string
		setup tokenSetup
		run   func(t *testing.T, e *tokenEndpoint)
	}

	// publicExchange is a public client's exchange of a new code, with change applied.
	publicExchange := func(t *testing.T, e *tokenEndpoint, change ...tokenChange) tokenAnswer {
		t.Helper()

		return e.send(t, exchangeOf(e.issue(t, tokenPublic, nil), "client_id", tokenPublic), change...)
	}

	cases := []testCase{
		{
			name:  "a public client binds to its key: another key cannot refresh, and its own can",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				first := publicExchange(t, e, e.withProof(t, k1, "j1", nil))
				doc := assertTokenIssued(t, first, "DPoP")
				assert.Equal(t, map[string]any{"jkt": k1.jkt}, first.confirmation(t))

				raw := doc["refresh_token"].(string)
				refused := e.send(t, refreshOf(raw, "client_id", tokenPublic), e.withProof(t, k2, "j2", nil))
				assertTokenRefused(t, refused, oidcprovider.CodeInvalidDPoPProof)

				none := e.send(t, refreshOf(raw, "client_id", tokenPublic))
				assertTokenRefused(t, none, oidcprovider.CodeInvalidDPoPProof)

				e.clk.Advance(tokenPastGrace)

				again := e.send(t, refreshOf(raw, "client_id", tokenPublic), e.withProof(t, k1, "j3", nil))
				next := assertTokenIssued(t, again, "DPoP")
				assert.NotEqual(t, raw, next["refresh_token"])
				assert.Equal(t, map[string]any{"jkt": k1.jkt}, again.confirmation(t))
			},
		},
		{
			name:  "a proof with another htu leaves the code to exchange",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				bad := e.send(t, exchangeOf(code), asClient(tokenWeb),
					e.withProof(t, k1, "j1", map[string]any{"htu": opIssuer + "/elsewhere"}))
				assertTokenRefused(t, bad, oidcprovider.CodeInvalidDPoPProof)

				good := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j2", nil))
				assertTokenIssued(t, good, "DPoP")
				assert.Equal(t, map[string]any{"jkt": k1.jkt}, good.confirmation(t))
			},
		},
		{
			name:  "a proof carrying ath, with no token to hash, leaves the code to exchange",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				bad := e.send(t, exchangeOf(code), asClient(tokenWeb),
					e.withProof(t, k1, "j1", map[string]any{"ath": tokenHash("anything")}))
				assertTokenRefused(t, bad, oidcprovider.CodeInvalidDPoPProof)

				assertTokenIssued(t, e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j2", nil)), "DPoP")
			},
		},
		{
			name:  "a replayed proof is refused, with the code left to exchange",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				proof := e.withProof(t, k1, "j-once", nil)
				assertTokenIssued(t, e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb), proof), "DPoP")

				code := e.issue(t, tokenWeb, nil)
				assertTokenRefused(t, e.send(t, exchangeOf(code), asClient(tokenWeb), proof), oidcprovider.CodeInvalidDPoPProof)

				assertTokenIssued(t, e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j-new", nil)), "DPoP")
			},
		},
		{
			name:  "a confidential client is not bound to a key: a new one refreshes, and none gets Bearer",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				first := e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb), e.withProof(t, k1, "j1", nil))
				doc := assertTokenIssued(t, first, "DPoP")
				assert.Equal(t, map[string]any{"jkt": k1.jkt}, first.confirmation(t))

				withNew := e.send(t, refreshOf(doc["refresh_token"].(string)), asClient(tokenWeb), e.withProof(t, k2, "j2", nil))
				next := assertTokenIssued(t, withNew, "DPoP")
				assert.Equal(t, map[string]any{"jkt": k2.jkt}, withNew.confirmation(t))

				bare := e.send(t, refreshOf(next["refresh_token"].(string)), asClient(tokenWeb))
				assertTokenIssued(t, bare, "Bearer")
				assert.Nil(t, bare.confirmation(t))
			},
		},
		{
			name:  "a client required to use DPoP is refused without a proof, at both grants",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenDPoPWeb, nil)
				bare := e.send(t, exchangeOf(code), asClient(tokenDPoPWeb))
				assertTokenRefused(t, bare, oidcprovider.CodeInvalidDPoPProof)

				first := e.send(t, exchangeOf(code), asClient(tokenDPoPWeb), e.withProof(t, k1, "j1", nil))
				raw := assertTokenIssued(t, first, "DPoP")["refresh_token"].(string)

				assertTokenRefused(t, e.send(t, refreshOf(raw), asClient(tokenDPoPWeb)), oidcprovider.CodeInvalidDPoPProof)
				e.clk.Advance(tokenPastGrace)

				again := e.send(t, refreshOf(raw), asClient(tokenDPoPWeb), e.withProof(t, k1, "j2", nil))
				assert.NotEqual(t, raw, assertTokenIssued(t, again, "DPoP")["refresh_token"])
			},
		},
		{
			name:  "a chain requiring DPoP refuses a request without a proof, in the protocol's form",
			setup: tokenSetup{dpop: requiredDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				assertTokenRefused(t, e.send(t, exchangeOf(code), asClient(tokenWeb)), oidcprovider.CodeInvalidDPoPProof)
				assertTokenIssued(t, e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j1", nil)), "DPoP")
			},
		},
		{
			name:  "a dpop_jkt code holds the key it names",
			setup: tokenSetup{dpop: plainDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, func(v url.Values) { v.Set("dpop_jkt", k1.jkt) })

				other := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k2, "j1", nil))
				assertTokenRefused(t, other, oidcprovider.CodeInvalidGrant)

				bare := e.send(t, exchangeOf(code), asClient(tokenWeb))
				assertTokenRefused(t, bare, oidcprovider.CodeInvalidGrant)

				own := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j2", nil))
				assertTokenIssued(t, own, "DPoP")
				assert.Equal(t, map[string]any{"jkt": k1.jkt}, own.confirmation(t))
			},
		},
		{
			name:  "a certificate with no proof binds the access token",
			setup: tokenSetup{cert: true},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				a := e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb), withCertificate(cert.cert))
				assertTokenIssued(t, a, "Bearer")
				assert.Equal(t, map[string]any{"x5t#S256": cert.thumb}, a.confirmation(t))
			},
		},
		{
			name:  "a proof and a certificate bind the proof's key alone",
			setup: tokenSetup{dpop: plainDPoP, cert: true},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				a := e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb),
					withCertificate(cert.cert), e.withProof(t, k1, "j1", nil))
				assertTokenIssued(t, a, "DPoP")
				assert.Equal(t, map[string]any{"jkt": k1.jkt}, a.confirmation(t))
			},
		},
		{
			name:  "a client required to use a certificate is refused without one",
			setup: tokenSetup{dpop: plainDPoP, cert: true},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenMTLSWeb, nil)
				assertTokenRefused(t, e.send(t, exchangeOf(code), asClient(tokenMTLSWeb)), oidcprovider.CodeInvalidRequest)

				withBoth := e.send(t, exchangeOf(code), asClient(tokenMTLSWeb),
					withCertificate(cert.cert), e.withProof(t, k1, "j1", nil))
				assertTokenRefused(t, withBoth, oidcprovider.CodeInvalidRequest)

				a := e.send(t, exchangeOf(code), asClient(tokenMTLSWeb), withCertificate(cert.cert))
				assertTokenIssued(t, a, "Bearer")
				assert.Equal(t, map[string]any{"x5t#S256": cert.thumb}, a.confirmation(t))
			},
		},
		{
			name:  "a nonce needed at an exchange: 400 in the protocol's form, and the code exchanges with it",
			setup: tokenSetup{dpop: noncedDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				asked := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j1", nil))
				assertTokenRefused(t, asked, oidcprovider.CodeUseDPoPNonce)

				nonce := asked.header.Get("DPoP-Nonce")
				require.NotEmpty(t, nonce)

				good := e.send(t, exchangeOf(code), asClient(tokenWeb),
					e.withProof(t, k1, "j2", map[string]any{"nonce": nonce}))
				assertTokenIssued(t, good, "DPoP")
			},
		},
		{
			name:  "a nonce needed at a refresh: the token stays unrotated",
			setup: tokenSetup{dpop: noncedDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				asked := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j1", nil))
				nonce := asked.header.Get("DPoP-Nonce")
				proof := func(jti string) tokenChange { return e.withProof(t, k1, jti, map[string]any{"nonce": nonce}) }

				raw := assertTokenIssued(t, e.send(t, exchangeOf(code), asClient(tokenWeb), proof("j2")), "DPoP")["refresh_token"].(string)

				again := e.send(t, refreshOf(raw), asClient(tokenWeb), e.withProof(t, k1, "j3", nil))
				assertTokenRefused(t, again, oidcprovider.CodeUseDPoPNonce)
				assert.NotEmpty(t, again.header.Get("DPoP-Nonce"))
				e.clk.Advance(tokenPastGrace)

				next := e.send(t, refreshOf(raw), asClient(tokenWeb), proof("j4"))
				assert.NotEqual(t, raw, assertTokenIssued(t, next, "DPoP")["refresh_token"])
			},
		},
		{
			name:  "a nonce cipher that fails is a failure, and not a refusal",
			setup: tokenSetup{dpop: sealFailingDPoP},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				assertTokenFailed(t, e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j1", nil)))
			},
		},
		{
			name: "a DPoP header while DPoP is off is ignored",
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				a := e.send(t, exchangeOf(e.issue(t, tokenWeb, nil)), asClient(tokenWeb),
					func(r *http.Request) { r.Header.Set("DPoP", "not even a proof") })
				assertTokenIssued(t, a, "Bearer")
				assert.Nil(t, a.confirmation(t))
			},
		},
		{
			name:  "an invalid proof is charged to the source",
			setup: tokenSetup{dpop: plainDPoP, endpoint: limitedTo(2)},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)
				for i := range 2 {
					bad := e.send(t, exchangeOf(code), asClient(tokenWeb),
						e.withProof(t, k1, "j"+strconv.Itoa(i), map[string]any{"htu": opIssuer + "/elsewhere"}))
					assertTokenRefused(t, bad, oidcprovider.CodeInvalidDPoPProof)
				}

				throttled := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j-next", nil))
				assertTokenRefused(t, throttled, oidcprovider.CodeInvalidClient)

				assertTokenIssued(t, e.send(t, exchangeOf(code), asClient(tokenWeb), fromAddr(tokenOtherAddr),
					e.withProof(t, k1, "j-other", nil)), "DPoP")
			},
		},
		{
			name:  "asking for a nonce is not charged",
			setup: tokenSetup{dpop: noncedDPoP, endpoint: limitedTo(1)},
			run: func(t *testing.T, e *tokenEndpoint) {
				t.Helper()

				code := e.issue(t, tokenWeb, nil)

				var nonce string
				for i := range 3 {
					asked := e.send(t, exchangeOf(code), asClient(tokenWeb), e.withProof(t, k1, "j"+strconv.Itoa(i), nil))
					assertTokenRefused(t, asked, oidcprovider.CodeUseDPoPNonce)
					nonce = asked.header.Get("DPoP-Nonce")
				}

				assertTokenIssued(t, e.send(t, exchangeOf(code), asClient(tokenWeb),
					e.withProof(t, k1, "j-good", map[string]any{"nonce": nonce})), "DPoP")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newTokenEndpoint(t, tc.setup))
		})
	}
}
