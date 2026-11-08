package httpsecconformance

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

const (
	// bpBase is the base path every scenario of this group moves the chain's
	// endpoints under, and bpIssuer the issuer whose path matches it.
	bpBase   = "/auth"
	bpIssuer = OPIssuer + bpBase

	// bpProjectsPrefix is the consumer's own route the rule scenario guards.
	bpProjectsPrefix = "/projects/"
)

// basePathScenarios is the behaviour of the base path that every adapter must
// agree on: the built-in endpoints answer under it, the unprefixed paths belong
// to the application, and a rule judges the path the consumer wrote.
func basePathScenarios() []Scenario {
	return []Scenario{
		basePathPasswordSignIn(),
		basePathKeySet(),
		basePathProviderToken(),
		basePathRuleJudgesConsumerPath(),
		basePathStrippedByProxy(),
	}
}

// bpFormLoginSpec is password sign-in under the base path, with a no-route
// handler so a request the chain did not answer is seen to reach the application.
func bpFormLoginSpec(t *testing.T) ChainSpec {
	t.Helper()

	effects := newEffects(t)

	return ChainSpec{
		Options: append(formLoginOptions(effects), httpsec.WithBasePath(bpBase)),
		Effects: effects,
		NoRoute: true,
	}
}

// bpSignIn is the password sign-in request to target.
func bpSignIn(target string) RequestSpec {
	r := formBody("username=" + Username + "&password=" + Password)
	r.Path = target

	return r
}

// assertPassedThrough pins that the chain left the request to the application.
func assertPassedThrough(t *testing.T, res Result) {
	t.Helper()

	assert.True(t, res.NoRouteRan, "the application handler received the request")
	assert.Equal(t, NoRouteBody, res.Body, "the body is the application's alone")
	assert.NoError(t, res.Refusal)
}

func basePathPasswordSignIn() Scenario {
	// Mirrors "Every adapter answers the same paths".
	return Scenario{
		Name:  "base path: every adapter answers password sign-in under /auth and passes /sign-in/password through",
		Build: bpFormLoginSpec,
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			res := send(bpSignIn(bpBase + LoginPath))

			require.Equal(t, http.StatusOK, res.Status, res.Body)
			assert.Contains(t, res.Body, `"access_token":"`+tokenPrefix+string(UserID)+`.`)
			assert.False(t, res.NoRouteRan, "the chain answered, not the application")
			assert.NoError(t, res.Refusal)
			assert.Equal(t, 1, spec.Effects.ActiveSessions(t), "the sign-in opened a session")

			passed := send(bpSignIn(LoginPath))

			assertPassedThrough(t, passed)
			assert.Equal(t, 1, spec.Effects.ActiveSessions(t), "the unprefixed path opened no further session")
			assert.Equal(t, 1, spec.Effects.AuthenticatorCalls(), "the unprefixed path checked no password")
		},
	}
}

func basePathKeySet() Scenario {
	// Mirrors "Every adapter answers the same paths", for the key set.
	return Scenario{
		Name: "base path: every adapter answers the key set under /auth and passes /.well-known/jwks.json through",
		Build: func(t *testing.T) ChainSpec {
			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableJWKSEndpoint(fixtureKeySet{}),
					httpsec.WithBasePath(bpBase),
				},
				Effects: newEffects(t),
				NoRoute: true,
			}
		},
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			get := func(target string) RequestSpec {
				return RequestSpec{Method: http.MethodGet, Path: target, ClientAddress: ClientAddress}
			}

			res := send(get(bpBase + KeySetPath))

			assert.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, KeySetBody, res.Body, "the body is exactly the key set")
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.False(t, res.NoRouteRan, "the chain answered, not the application")

			assertPassedThrough(t, send(get(KeySetPath)))
		},
	}
}

// bpProviderSpec is an OpenID Provider with issuer bpIssuer behind a chain whose
// base path is bpBase.
func bpProviderSpec(t *testing.T) ChainSpec {
	t.Helper()

	effects := newEffects(t)

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer: bpIssuer,
		Clients: []oidcprovider.Client{{
			ID: opFirstParty, Type: oidcprovider.Confidential, Secret: []byte(OPClientSecret), FirstParty: true,
			RedirectURIs: []string{OPCallback}, Scopes: []string{"openid", "profile"},
		}},
		Keys:         opKeys(),
		Users:        fixtureUsers{},
		LoginURL:     bpIssuer + "/login",
		ConsentURL:   bpIssuer + "/consent",
		LogoutURL:    bpIssuer + "/logout-page",
		LoggedOutURL: bpIssuer + "/bye",
	})
	require.NoError(t, err)

	effects.Sessions, err = session.New(session.WithStore(effects.Store), session.WithEndObserver(p))
	require.NoError(t, err)

	s, err := effects.Sessions.Create(t.Context(), UserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	effects.SessionID = s.ID

	return ChainSpec{
		Options: []httpsec.Option{
			httpsec.WithHTTPSDeployment(),
			httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: effects.Sessions, Users: fixtureUsers{}}),
			httpsec.EnableJWKSEndpoint(opKeys()),
			httpsec.EnableSecurityHeaders(),
			httpsec.EnableCSRFProtection(),
			httpsec.EnableOIDCProvider(p),
			httpsec.WithBasePath(bpBase),
		},
		Effects: effects,
		NoRoute: true,
	}
}

func basePathProviderToken() Scenario {
	// Mirrors "Every adapter answers the same paths", for the provider's token endpoint.
	return Scenario{
		Name:  "base path: every adapter answers the token endpoint under /auth and passes /oauth2/token through",
		Build: bpProviderSpec,
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			// A code that was never issued: the provider refuses it, and that
			// refusal in the provider's own JSON is what shows it answered.
			res := send(opTokenRequest(bpBase+opTokenPath, "never-issued"))

			assert.Equal(t, http.StatusBadRequest, res.Status, res.Body)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.JSONEq(t, `{"error":"invalid_grant"}`, res.Body)
			assert.False(t, res.NoRouteRan, "the provider answered, not the application")

			assertPassedThrough(t, send(opTokenRequest(opTokenPath, "never-issued")))
		},
	}
}

func basePathRuleJudgesConsumerPath() Scenario {
	// Mirrors "The base path covers only the endpoints the chain answers": a
	// rule is on the consumer's own path, so the base path does not move it.
	return Scenario{
		Name: "base path: a rule for GET /projects/{id} judges /projects/42 and not /auth/projects/42",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			liveSession(t, effects)

			options := append(formLoginOptions(effects), bearerOptions(effects)...)

			return ChainSpec{
				Options: append(options,
					httpsec.WithBasePath(bpBase),
					httpsec.EnableAuthorization(fixtureAuthorizer{}, authorize.Rule[httpsec.Request]{
						Match: func(r httpsec.Request) bool {
							id, ok := strings.CutPrefix(r.Path(), bpProjectsPrefix)

							return ok && r.Method() == http.MethodGet && id != "" && !strings.Contains(id, "/")
						},
						Require: authorize.DenyAll(),
					}, authorize.Rule[httpsec.Request]{
						// Everything else a signed-in caller may reach, so a request
						// the first rule does not match is visibly judged by this one.
						Match:   func(httpsec.Request) bool { return true },
						Require: authorize.Authenticated(),
					})),
				Effects: effects,
				Routes: []Route{
					{Method: http.MethodGet, Path: bpProjectsPrefix + "42"},
					{Method: http.MethodGet, Path: bpBase + bpProjectsPrefix + "42"},
				},
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			denied := send(authenticatedRequest(http.MethodGet, bpProjectsPrefix+"42")(spec))

			assert.Equal(t, http.StatusForbidden, denied.Status)
			require.ErrorIs(t, denied.Refusal, authorize.ErrAccessDenied, "the rule judged the consumer's own path")
			assert.False(t, denied.RouteRan)

			other := send(authenticatedRequest(http.MethodGet, bpBase+bpProjectsPrefix+"42")(spec))

			assert.NoError(t, other.Refusal, "the rule does not match the prefixed path")
			assert.True(t, other.RouteRan, "the application route under the base path ran")
		},
	}
}

func basePathStrippedByProxy() Scenario {
	// Mirrors "Prefix stripped before the chain".
	//
	// The adapters' Serve cannot express a layer in front of the chain, and the
	// ChainSpec has no field for one. The stripping layer is therefore built here,
	// on net/http alone, and its half does not exercise the adapter under test.
	// What each adapter does contribute is the request as the proxy delivers it,
	// "/sign-in/password", sent through its own framework to a chain with no
	// base path.
	return Scenario{
		Name: "base path: a chain with no base path answers a request a proxy stripped /auth from (stripping layer on net/http only)",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			return ChainSpec{Options: formLoginOptions(effects), Effects: effects, NoRoute: true}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			// The stripping layer, on net/http.
			var appRan bool

			app := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { appRan = true })
			handler := http.StripPrefix(bpBase, spec.NewChain(t).Middleware()(app))

			form := url.Values{"username": {Username}, "password": {Password}}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, bpBase+LoginPath, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = ClientAddress + ":40000"

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)

			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), `"access_token":"`)
			assert.False(t, appRan, "the chain answered the stripped request, not the application")
			assert.Equal(t, 1, spec.Effects.ActiveSessions(t))

			// The request as the chain receives it, through the adapter under test.
			res := send(bpSignIn(LoginPath))

			require.Equal(t, http.StatusOK, res.Status, res.Body)
			assert.Contains(t, res.Body, `"access_token":"`)
			assert.False(t, res.NoRouteRan)
			assert.Equal(t, 2, spec.Effects.ActiveSessions(t))
		},
	}
}
