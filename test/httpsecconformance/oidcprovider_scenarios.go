package httpsecconformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The OpenID Provider the provider scenarios are written against. Every name
// carries "oidcprovider", so that one -run filter selects the group on every
// adapter.
const (
	// OPIssuer is the issuer of the provider, and so the origin its pages are at.
	OPIssuer = "https://id.example.com"

	// OPClientSecret is the secret both clients authenticate with.
	OPClientSecret = "0123456789abcdef0123456789abcdef" //nolint:gosec // a fixture, not a credential

	// OPCallback is the one redirect URI both clients register.
	OPCallback = "https://rp.example.com/cb"

	// OPPostLogoutRedirect is the one post-logout redirect URI the clients register.
	OPPostLogoutRedirect = "https://rp.example.com/bye"

	// opFirstParty skips the consent stage; opThirdParty does not.
	opFirstParty = "conf-first-party"
	opThirdParty = "conf-third-party"

	// opPKCEVerifier and opPKCEChallenge are a code verifier and its S256 challenge.
	opPKCEVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	opPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	// The cookies the provider sets, under the __Host- prefix an https issuer gives them.
	opFlowCookie    = "__Host-scrty-op-flow"
	opSessionCookie = "__Host-scrty-op-session"

	opAuthorizePath = "/oauth2/authorize"
	opResumePath    = "/oauth2/authorize/resume"
	opTokenPath     = "/oauth2/token" //nolint:gosec // G101: a path, and no credential
	opUserInfoPath  = "/oauth2/userinfo"
	opLogoutPath    = "/oauth2/logout"
	opConfirmPath   = "/oauth2/logout/confirm"
	opMetadataPath  = "/.well-known/openid-configuration"
)

// opKeys is one set of signing keys for every provider scenario. Generating
// them is the slow part, and the scenarios read only what is answered.
var opKeys = sync.OnceValue(func() *signingkey.Keys {
	return must.Must(signingkey.New(context.Background(),
		signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
})

// OIDCProviderScenarios is every behaviour of the OpenID Provider's endpoints
// that must be identical on every adapter: what crosses the adapter, as status,
// each header, each cookie attribute and the body, with a provider over memory
// stores behind it.
//
// It is a group of its own, as ChallengeScenarios is: an adapter's suite runs it
// by name.
func OIDCProviderScenarios() []Scenario {
	return []Scenario{
		opAuthorizeRedirects(),
		opAuthorizeFormPostRedirects(),
		opAuthorizeRawQueryIsRefused(),
		opResumeAnswersJSON(),
		opTokenAnswersJSONNoStore(),
		opTokenFormQueryIsRefused(),
		opTokenWrongMethodIsRefused(),
		opUserInfoChallenges(),
		opMetadataIsServed(),
		opEndSessionRedirects(),
		opLogoutConfirmationAnswersJSON(),
		opMetadataHeadAnswersNoBody(),
		opMetadataWrongMethodIsRefused(),
		opUserInfoInvalidTokenChallenges(),
		opUserInfoWrongMethodIsRefused(),
		opUserInfoDPoPMalformedOffersBothSchemes(),
		opFlowsOverATrustedProxyAreSecure(),
		opPlainHTTPIsRefused(),
		opProxyForwardingHTTPIsRefused(),
	}
}

// opBuild wires a provider over memory stores and a chain in front of it, with
// a session whose secret a scenario presents as the signed-in user.
func opBuild(t *testing.T) ChainSpec {
	t.Helper()

	return opBuildOver(t, httpsec.WithHTTPSDeployment(), nil)
}

// opBuildOver is opBuild with transport as how the chain learns a request was
// secure, and nil leaving it to the connection, which no adapter's in-memory
// transport makes TLS. providerOptions are the provider's own options, and
// extra is appended to the chain's options.
func opBuildOver(t *testing.T, transport httpsec.Option, providerOptions []oidcprovider.Option, extra ...httpsec.Option) ChainSpec {
	t.Helper()

	effects := newEffects(t)

	secret := []byte(OPClientSecret)
	scopes := []string{"openid", "profile"}

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: OPIssuer,
		Clients: []oidcprovider.Client{
			{
				ID: opFirstParty, Type: oidcprovider.Confidential, Secret: secret, FirstParty: true,
				RedirectURIs: []string{OPCallback}, PostLogoutRedirectURIs: []string{OPPostLogoutRedirect},
				Scopes: scopes,
			},
			{
				ID: opThirdParty, Type: oidcprovider.Confidential, Secret: secret,
				RedirectURIs: []string{OPCallback}, Scopes: scopes,
			},
		},
		Keys:         opKeys(),
		Users:        fixtureUsers{},
		LoginURL:     OPIssuer + "/login",
		ConsentURL:   OPIssuer + "/consent",
		LogoutURL:    OPIssuer + "/logout-page",
		LoggedOutURL: OPIssuer + "/bye",
	}, providerOptions...)
	require.NoError(t, err)

	// The manager reports each sign-in's end to the provider, as a consumer wires it.
	effects.Sessions, err = session.New(session.WithStore(effects.Store), session.WithEndObserver(p))
	require.NoError(t, err)

	s, err := effects.Sessions.Create(t.Context(), UserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	effects.SessionID = s.ID

	options := []httpsec.Option{
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: effects.Sessions, Users: fixtureUsers{}}),
		httpsec.EnableJWKSEndpoint(opKeys()),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableOIDCProvider(p),
	}

	if transport != nil {
		options = append([]httpsec.Option{transport}, options...)
	}

	return ChainSpec{
		Options: append(options, extra...),
		Effects: effects,
		NoRoute: true,
	}
}

// opAuthorizeParams is a valid authorization request from clientID.
func opAuthorizeParams(clientID string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {OPCallback},
		"scope":                 {"openid profile"},
		"state":                 {"xyz"},
		"code_challenge":        {opPKCEChallenge},
		"code_challenge_method": {"S256"},
	}
}

// opGet is a GET of target.
func opGet(target string, header map[string]string) RequestSpec {
	return RequestSpec{Method: http.MethodGet, Path: target, Header: header, ClientAddress: ClientAddress}
}

// opBrowser is the cookies a browser holds, collected from the responses it saw.
type opBrowser map[string]string

// learn keeps each cookie a response set, and forgets one it cleared.
func (b opBrowser) learn(res Result) {
	for _, c := range responseCookies(res.Header) {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b, c.Name)

			continue
		}

		b[c.Name] = c.Value
	}
}

// header is the Cookie header of the browser, in a fixed order.
func (b opBrowser) header() string {
	var parts []string

	for _, name := range []string{opFlowCookie, opSessionCookie} {
		if v, ok := b[name]; ok {
			parts = append(parts, name+"="+v)
		}
	}

	return strings.Join(parts, "; ")
}

// with is the headers of a request from this browser, signed in as the pre-created session.
func (b opBrowser) with(extra map[string]string, spec ChainSpec, signedIn bool) map[string]string {
	h := map[string]string{}

	if c := b.header(); c != "" {
		h["Cookie"] = c
	}

	if signedIn {
		h["Authorization"] = "Bearer " + spec.Effects.SessionID
	}

	for k, v := range extra {
		h[k] = v
	}

	return h
}

// opJSON reads a JSON object response.
func opJSON(t *testing.T, res Result) map[string]any {
	t.Helper()

	var doc map[string]any

	require.NoError(t, json.Unmarshal([]byte(res.Body), &doc), res.Body)

	return doc
}

// assertOneSetCookiePerCookie pins that the adapter sent every cookie as a header
// of its own, none merged into another and none dropped.
func assertOneSetCookiePerCookie(t *testing.T, res Result, names ...string) []*http.Cookie {
	t.Helper()

	lines := res.Header.Values("Set-Cookie")
	require.Len(t, lines, len(names), "one Set-Cookie header per cookie: %q", lines)

	cookies := responseCookies(res.Header)
	require.Len(t, cookies, len(names), "each Set-Cookie header parses to one cookie: %q", lines)

	for i, name := range names {
		assert.Equal(t, name, cookies[i].Name)
	}

	return cookies
}

// assertHostCookie pins the attributes of a cookie under the __Host- prefix.
func assertHostCookie(t *testing.T, c *http.Cookie) {
	t.Helper()

	assert.NotEmpty(t, c.Value, "%s has a value", c.Name)
	assert.Equal(t, "/", c.Path, "%s", c.Name)
	assert.Empty(t, c.Domain, "%s: a __Host- cookie names no domain", c.Name)
	assert.True(t, c.Secure, "%s is Secure", c.Name)
	assert.True(t, c.HttpOnly, "%s is HttpOnly", c.Name)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, "%s is SameSite=Lax", c.Name)
}

// assertSessionCookie pins that a cookie lasts as long as the browser does: the record
// its secret names has the deadline that matters, so the cookie carries none.
func assertSessionCookie(t *testing.T, c *http.Cookie) {
	t.Helper()

	assert.Zero(t, c.MaxAge, "%s has no Max-Age", c.Name)
	assert.True(t, c.Expires.IsZero(), "%s has no Expires", c.Name)
}

// assertNoStore pins the headers a response carrying a secret must have.
func assertNoStore(t *testing.T, res Result) {
	t.Helper()

	assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
}

// opStartAuthorize sends the first-party client's request and returns the login
// page's handle, the browser holding the flow cookie, and the answer.
func opStartAuthorize(t *testing.T, send func(RequestSpec) Result, clientID string) (opBrowser, string, Result) {
	t.Helper()

	browser := opBrowser{}
	res := send(opGet(opAuthorizePath+"?"+opAuthorizeParams(clientID).Encode(), nil))
	require.Equal(t, http.StatusSeeOther, res.Status, res.Body)

	loc, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)

	handle := loc.Query().Get(oidcprovider.HandleParam)
	require.NotEmpty(t, handle)

	browser.learn(res)
	require.Contains(t, browser, opFlowCookie)

	return browser, handle, res
}

// opResume sends the login page's resume for handle, as the signed-in user.
func opResume(spec ChainSpec, send func(RequestSpec) Result, b opBrowser, body string) Result {
	return send(RequestSpec{
		Method:        http.MethodPost,
		Path:          opResumePath,
		Header:        b.with(map[string]string{"Content-Type": "application/json"}, spec, true),
		Body:          body,
		ClientAddress: ClientAddress,
	})
}

// opTokenRequest is the form-POST token request that spends code, as the first-party client.
func opTokenRequest(target, code string) RequestSpec {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {OPCallback},
		"code_verifier": {opPKCEVerifier},
	}

	return RequestSpec{
		Method: http.MethodPost,
		Path:   target,
		Header: map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": basicAuth(opFirstParty, OPClientSecret),
		},
		Body:          form.Encode(),
		ClientAddress: ClientAddress,
	}
}

// basicAuth is the Authorization header of an HTTP Basic credential.
func basicAuth(user, secret string) string {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.SetBasicAuth(user, secret)

	return r.Header.Get("Authorization")
}

// opSignedIn runs a first-party login to its code, and returns the browser, the
// resume's answer and the code it carries.
func opSignedIn(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) (opBrowser, Result, string) {
	t.Helper()

	browser, handle, _ := opStartAuthorize(t, send, opFirstParty)

	res := opResume(spec, send, browser, opDoc(t, map[string]any{"req": handle}))
	require.Equal(t, http.StatusOK, res.Status, res.Body)

	browser.learn(res)

	to, err := url.Parse(opJSON(t, res)["redirect_to"].(string))
	require.NoError(t, err)

	code := to.Query().Get("code")
	require.NotEmpty(t, code, res.Body)

	return browser, res, code
}

// opDoc is doc as a JSON document, marshalled whole, so no value is spliced into
// the text by hand.
func opDoc(t *testing.T, doc map[string]any) string {
	t.Helper()

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	return string(b)
}

func opAuthorizeRedirects() Scenario {
	return Scenario{
		Name:    "oidcprovider authorize redirects 303 to the login page with a flow cookie",
		Build:   opBuild,
		Request: sending(opGet(opAuthorizePath+"?"+opAuthorizeParams(opThirdParty).Encode(), nil)),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusSeeOther, res.Status, res.Body)
			assert.False(t, res.NoRouteRan, "the chain answered the authorize endpoint itself")
			assert.Empty(t, res.Body)
			assertNoStore(t, res)

			loc, err := url.Parse(res.Header.Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, OPIssuer+"/login", loc.Scheme+"://"+loc.Host+loc.Path)
			assert.NotEmpty(t, loc.Query().Get(oidcprovider.HandleParam), "the page is given a handle")

			cookies := assertOneSetCookiePerCookie(t, res, opFlowCookie)
			assertHostCookie(t, cookies[0])
			assertSessionCookie(t, cookies[0])
		},
	}
}

func opAuthorizeFormPostRedirects() Scenario {
	return Scenario{
		Name:  "oidcprovider authorize by form POST redirects 303 with a flow cookie",
		Build: opBuild,
		Request: sending(RequestSpec{
			Method:        http.MethodPost,
			Path:          opAuthorizePath,
			Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:          opAuthorizeParams(opThirdParty).Encode(),
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusSeeOther, res.Status, res.Body)
			assert.False(t, res.NoRouteRan)

			loc, err := url.Parse(res.Header.Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "/login", loc.Path)
			assert.NotEmpty(t, loc.Query().Get(oidcprovider.HandleParam))

			assertHostCookie(t, assertOneSetCookiePerCookie(t, res, opFlowCookie)[0])
		},
	}
}

func opAuthorizeRawQueryIsRefused() Scenario {
	return Scenario{
		Name:  "oidcprovider authorize with a query pair that does not parse is 400 with no redirect",
		Build: opBuild,
		// The pair would be dropped by a parser that skips what it cannot read, leaving a
		// request that names a client and a redirect it never checked.
		Request: sending(opGet(opAuthorizePath+"?"+opAuthorizeParams(opThirdParty).Encode()+
			"&redirect_uri=https://evil.example/%zz", nil)),
		Assert: func(t *testing.T, res Result) {
			require.ErrorIs(t, res.Refusal, httpsec.ErrOIDCInvalidAuthorization)
			assert.Equal(t, http.StatusBadRequest, res.Status)
			assert.Empty(t, res.Header.Get("Location"), "the browser is not redirected")
			assert.Empty(t, res.Header.Values("Set-Cookie"), "nothing is parked")
			assert.Empty(t, res.Body)
			assert.False(t, res.NoRouteRan)
		},
	}
}

func opResumeAnswersJSON() Scenario {
	return Scenario{
		Name:  "oidcprovider resume answers JSON with the browser-session cookie and keeps the flow cookie",
		Build: opBuild,
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			browser, handle, _ := opStartAuthorize(t, send, opFirstParty)

			res := opResume(spec, send, browser, opDoc(t, map[string]any{"req": handle}))

			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status, res.Body)
			assert.False(t, res.NoRouteRan)
			assertNoStore(t, res)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))

			doc := opJSON(t, res)
			assert.Len(t, doc, 1, "the document holds only where the browser goes")

			to, err := url.Parse(doc["redirect_to"].(string))
			require.NoError(t, err)
			assert.Equal(t, OPCallback, to.Scheme+"://"+to.Host+to.Path)
			assert.NotEmpty(t, to.Query().Get("code"))
			assert.Equal(t, "xyz", to.Query().Get("state"))

			cookies := assertOneSetCookiePerCookie(t, res, opSessionCookie)
			assertHostCookie(t, cookies[0])
			assertSessionCookie(t, cookies[0])
			assert.Equal(t, 1, res.Effects.ActiveSessions(t), "the resume opens no session of its own")
		},
	}
}

func opTokenAnswersJSONNoStore() Scenario {
	return Scenario{
		Name:  "oidcprovider token by form POST answers JSON with no-store",
		Build: opBuild,
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			_, _, code := opSignedIn(t, spec, send)

			res := send(opTokenRequest(opTokenPath, code))

			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status, res.Body)
			assert.False(t, res.NoRouteRan)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Empty(t, res.Header.Values("Set-Cookie"))

			doc := opJSON(t, res)
			assert.Equal(t, "Bearer", doc["token_type"])
			assert.NotEmpty(t, doc["access_token"])
			assert.NotEmpty(t, doc["id_token"], "openid was granted")
			assert.NotZero(t, doc["expires_in"])
		},
	}
}

func opTokenFormQueryIsRefused() Scenario {
	return Scenario{
		Name:  "oidcprovider token with the code in the query is 400 invalid_request and spends nothing",
		Build: opBuild,
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			_, _, code := opSignedIn(t, spec, send)

			// The code in the query and not in the form: the query is not read.
			req := opTokenRequest(opTokenPath+"?code="+url.QueryEscape(code), code)
			form, err := url.ParseQuery(req.Body)
			require.NoError(t, err)

			form.Del("code")
			req.Body = form.Encode()

			res := send(req)

			require.NoError(t, res.Refusal, "a protocol refusal is the provider's own answer")
			assert.Equal(t, http.StatusBadRequest, res.Status)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.JSONEq(t, `{"error":"invalid_request"}`, res.Body)

			// The code was not spent by the refusal: it is spent here, by the form.
			ok := send(opTokenRequest(opTokenPath, code))
			require.Equal(t, http.StatusOK, ok.Status, ok.Body)
		},
	}
}

func opTokenWrongMethodIsRefused() Scenario {
	return Scenario{
		Name:    "oidcprovider token by GET is 405 with Allow: POST and no-store",
		Build:   opBuild,
		Request: sending(opGet(opTokenPath, nil)),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusMethodNotAllowed, res.Status)
			assert.Equal(t, http.MethodPost, res.Header.Get("Allow"))
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.False(t, res.NoRouteRan, "the chain answered, and the application did not")
		},
	}
}

func opUserInfoChallenges() Scenario {
	return Scenario{
		Name:    "oidcprovider userinfo without a token is 401 with a Bearer challenge",
		Build:   opBuild,
		Request: sending(opGet(opUserInfoPath, nil)),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Equal(t, []string{`Bearer realm="oauth2"`}, res.Header.Values("WWW-Authenticate"))
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.Equal(t, "no-cache", res.Header.Get("Pragma"))
			assert.Empty(t, res.Body)
			assert.False(t, res.NoRouteRan)
		},
	}
}

func opMetadataIsServed() Scenario {
	return Scenario{
		Name:    "oidcprovider metadata is served as JSON naming the issuer and its endpoints",
		Build:   opBuild,
		Request: sending(opGet(opMetadataPath, nil)),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status, res.Body)
			assert.False(t, res.NoRouteRan)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Equal(t, opMetadataCacheControl, res.Header.Get("Cache-Control"))
			assert.Empty(t, res.Header.Values("Set-Cookie"))

			doc := opJSON(t, res)
			assert.Equal(t, OPIssuer, doc["issuer"])
			assert.Equal(t, OPIssuer+opAuthorizePath, doc["authorization_endpoint"])
			assert.Equal(t, OPIssuer+opTokenPath, doc["token_endpoint"])
			assert.Equal(t, OPIssuer+opUserInfoPath, doc["userinfo_endpoint"])
			assert.Equal(t, OPIssuer+opLogoutPath, doc["end_session_endpoint"])
			assert.Equal(t, OPIssuer+KeySetPath, doc["jwks_uri"])
		},
	}
}

func opEndSessionRedirects() Scenario {
	return Scenario{
		Name:    "oidcprovider end-session redirects 303 to the logout page with a flow cookie",
		Build:   opBuild,
		Request: sending(opGet(opLogoutPath, nil)),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusSeeOther, res.Status, res.Body)
			assert.False(t, res.NoRouteRan)
			assert.Empty(t, res.Body)
			assertNoStore(t, res)

			loc, err := url.Parse(res.Header.Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, OPIssuer+"/logout-page", loc.Scheme+"://"+loc.Host+loc.Path)
			assert.NotEmpty(t, loc.Query().Get(oidcprovider.HandleParam), "the page is given a handle")

			assertHostCookie(t, assertOneSetCookiePerCookie(t, res, opFlowCookie)[0])
		},
	}
}

func opLogoutConfirmationAnswersJSON() Scenario {
	return Scenario{
		Name:  "oidcprovider logout confirmation answers JSON, clears the browser-session cookie and ends the sign-in",
		Build: opBuild,
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			browser, _, _ := opSignedIn(t, spec, send)
			require.Contains(t, browser, opSessionCookie, "the login set a browser session")

			// The end-session request, from the browser that holds the session.
			asked := send(opGet(opLogoutPath, browser.with(nil, spec, false)))
			require.Equal(t, http.StatusSeeOther, asked.Status, asked.Body)

			loc, err := url.Parse(asked.Header.Get("Location"))
			require.NoError(t, err)

			handle := loc.Query().Get(oidcprovider.HandleParam)
			require.NotEmpty(t, handle)

			browser.learn(asked)

			res := send(RequestSpec{
				Method:        http.MethodPost,
				Path:          opConfirmPath,
				Header:        browser.with(map[string]string{"Content-Type": "application/json"}, spec, false),
				Body:          opDoc(t, map[string]any{"req": handle, "confirmed": true}),
				ClientAddress: ClientAddress,
			})

			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status, res.Body)
			assertNoStore(t, res)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))

			doc := opJSON(t, res)
			assert.Equal(t, map[string]any{"redirect_to": OPIssuer + "/bye"}, doc)

			// The cookie is cleared with the attributes it was set with, which is how a
			// browser matches it.
			cleared := assertOneSetCookiePerCookie(t, res, opSessionCookie)[0]
			assert.Empty(t, cleared.Value)
			assert.Negative(t, cleared.MaxAge)
			assert.Equal(t, "/", cleared.Path)
			assert.Empty(t, cleared.Domain)
			assert.True(t, cleared.Secure)
			assert.True(t, cleared.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, cleared.SameSite)

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "the sign-in the browser held is over")
		},
	}
}
