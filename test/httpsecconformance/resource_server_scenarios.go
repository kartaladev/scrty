package httpsecconformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
)

// The APIs the resource-server scenarios protect, and the paths each one serves.
// Every name carries "resource server" in the scenario titles, so one -run
// filter selects the group on every adapter.
const (
	// rsOrdersAPI and rsBillingAPI are the resource identifiers of the two APIs.
	rsOrdersAPI  = "https://api.example.com/orders"
	rsBillingAPI = "https://api.example.com/billing"

	// rsOrdersPath and rsBillingPath are one route of each API, each under the
	// prefix its resource server is confined to.
	rsOrdersPath  = "/api/orders/o-1"
	rsBillingPath = "/billing/b-1"

	// rsRemoteClient is the client every remote token is issued to.
	rsRemoteClient = "web-app"
)

// resourceServerScenarios is the resource server on every adapter: a chain that
// serves its own provider and an API, an API-only chain that trusts a remote
// issuer, and two resource servers on one chain trusting the same issuer.
func resourceServerScenarios() []Scenario {
	return []Scenario{
		rsProviderAndAPIChain(),
		rsRemoteIssuerChain(),
		rsTwoPrefixesOneIssuer(),
	}
}

// rsIssuer is a TLS issuer that serves OpenID discovery and its key set, and
// signs access tokens, standing in for an identity provider in another process.
type rsIssuer struct {
	srv  *httptest.Server
	iss  string
	kid  string
	priv *ecdsa.PrivateKey
	out  *outbound.Client

	// down answers every key-set request 503.
	down atomic.Bool
}

func newRSIssuer(t *testing.T) *rsIssuer {
	t.Helper()

	priv := must.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	pub := must.Must(jwk.PublicKeyOf(priv.Public()))

	i := &rsIssuer{kid: "rs-k1", priv: priv}

	require.NoError(t, pub.Set(jwk.KeyIDKey, i.kid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256()))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, "sig"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		rsWriteJSON(w, map[string]any{"issuer": i.iss, "jwks_uri": i.iss + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if i.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		rsWriteJSON(w, set)
	})

	i.srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.srv.Close)
	i.iss = i.srv.URL

	i.out = must.Must(outbound.New(outbound.WithHTTPClient(i.srv.Client())))

	return i
}

func rsWriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(must.Must(json.Marshal(v)))
}

// source is the resource-server option that trusts the issuer: its tokens are
// unbound, since these scenarios run no DPoP, and fetched through the issuer's
// own certificate authority.
func (i *rsIssuer) source() httpsec.ResourceServerOption {
	return httpsec.FromIssuer(i.iss, httpsec.WithOutboundClient(i.out), httpsec.WithUnboundTokens())
}

// token is an at+jwt access token for audience, valid for five minutes, with
// change applied to its claims before it is signed.
func (i *rsIssuer) token(t *testing.T, audience string, change func(claims map[string]any)) string {
	t.Helper()

	now := time.Now()
	claims := map[string]any{
		"iss": i.iss, "sub": "42", "aud": audience, "client_id": rsRemoteClient, "jti": rand.Text(),
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "scope": "orders:read orders:write",
	}

	if change != nil {
		change(claims)
	}

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "at+jwt"))
	require.NoError(t, headers.Set(jws.KeyIDKey, i.kid))

	signed, err := jws.Sign(must.Must(json.Marshal(claims)),
		jws.WithKey(jwa.ES256(), i.priv, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

// rsGet is a GET of path presenting credential under the Bearer scheme, and no
// credential when that is empty.
func rsGet(path, credential string) RequestSpec {
	req := RequestSpec{Method: http.MethodGet, Path: path, ClientAddress: ClientAddress}
	if credential != "" {
		req.Header = map[string]string{"Authorization": "Bearer " + credential}
	}

	return req
}

// rsDPoPGet is a GET of path presenting credential under the DPoP scheme with proof.
func rsDPoPGet(path, credential, proof string) RequestSpec {
	return RequestSpec{
		Method: http.MethodGet, Path: path, ClientAddress: ClientAddress,
		Header: map[string]string{"Authorization": "DPoP " + credential, "DPoP": proof},
	}
}

// rsProof is key's DPoP proof for method on path of the provider's origin, with
// the access-token hash of credential unless that is empty.
func rsProof(t *testing.T, key dpopClientKey, method, path, credential string) string {
	t.Helper()

	claims := map[string]any{"jti": rand.Text(), "htm": method, "htu": OPIssuer + path, "iat": time.Now().Unix()}
	if credential != "" {
		sum := sha256.Sum256([]byte(credential))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, headers.Set(jws.JWKKey, key.pub))

	signed, err := jws.Sign(must.Must(json.Marshal(claims)),
		jws.WithKey(jwa.ES256(), key.priv, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	return string(signed)
}

// rsRoutes are one route per path, each answering 200 when reached.
func rsRoutes(paths ...string) []Route {
	routes := make([]Route, 0, len(paths))
	for _, p := range paths {
		routes = append(routes, Route{Method: http.MethodGet, Path: p})
	}

	return routes
}

// assertAccepted checks that the route ran for an access-token caller carrying
// scopes, and that the token the resource server accepted names resource.
func assertAccepted(t *testing.T, res Result, resource, caller string, scopes ...string) {
	t.Helper()

	assert.Equal(t, http.StatusOK, res.Status, res.Body)
	assert.True(t, res.RouteRan, "the route behind the chain ran")
	assert.NoError(t, res.Refusal)
	assert.Empty(t, res.Header.Values("WWW-Authenticate"))

	require.True(t, res.PrincipalKnown, "the chain published a caller")
	assert.Equal(t, caller, string(res.Principal.ID))
	assert.ElementsMatch(t, scopes, res.Principal.Scopes)

	require.NotNil(t, res.AccessToken, "the chain published the access token")
	assert.Equal(t, resource, res.AccessToken.Resource)
	assert.ElementsMatch(t, scopes, res.AccessToken.Scopes)
}

// assertRefused checks a 401 whose only challenge names errorCode, and that no
// route ran and no caller was published.
func assertRefused(t *testing.T, res Result, errorCode string) {
	t.Helper()

	assert.Equal(t, http.StatusUnauthorized, res.Status, res.Body)
	assert.False(t, res.RouteRan, "the route behind the chain must not run")
	assert.False(t, res.PrincipalKnown, "no caller is published for a refused token")
	assert.Nil(t, res.AccessToken)

	challenges := res.Header.Values("WWW-Authenticate")
	if assert.Len(t, challenges, 1, "exactly one challenge") && errorCode != "" {
		assert.Contains(t, challenges[0], `error="`+errorCode+`"`)
	}
}

// rsProviderAndAPIChain is the chain that serves its own provider and an API
// under a prefix: the token the provider issued opens the API, a session opens a
// path outside it, and neither is taken for the other.
func rsProviderAndAPIChain() Scenario {
	return Scenario{
		Name: "resource server on a provider-and-API chain accepts the provider's access token on the API only",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			effects := newEffects(t)

			p, err := oidcprovider.New(oidcprovider.Deps{
				Issuer: OPIssuer,
				Clients: []oidcprovider.Client{{
					ID: opFirstParty, Type: oidcprovider.Confidential, Secret: []byte(OPClientSecret), FirstParty: true,
					RedirectURIs: []string{OPCallback}, Scopes: []string{"openid", "profile"},
					DefaultAudience: []string{rsOrdersAPI},
				}},
				Keys:         opKeys(),
				Users:        fixtureUsers{},
				LoginURL:     OPIssuer + "/login",
				ConsentURL:   OPIssuer + "/consent",
				LogoutURL:    OPIssuer + "/logout-page",
				LoggedOutURL: OPIssuer + "/bye",
			}, oidcprovider.WithDPoP())
			require.NoError(t, err)

			effects.Sessions, err = session.New(session.WithStore(effects.Store), session.WithEndObserver(p))
			require.NoError(t, err)

			s, err := effects.Sessions.Create(t.Context(), UserID, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			effects.SessionID = s.ID

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.WithHTTPSDeployment(),
					httpsec.EnableDPoP(httpsec.DPoP{
						PublicURL: OPIssuer, Replay: &fixtureReplayStore{seen: map[string]time.Time{}},
					}),
					httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: effects.Sessions, Users: fixtureUsers{}}),
					httpsec.EnableJWKSEndpoint(opKeys()),
					httpsec.EnableSecurityHeaders(),
					httpsec.EnableCSRFProtection(),
					httpsec.EnableOIDCProvider(p),
					httpsec.EnableResourceServer(rsOrdersAPI,
						httpsec.WithPathPrefix("/api/"),
						httpsec.FromProvider(p)),
				},
				Effects: effects,
				Routes:  rsRoutes(rsOrdersPath, RoutePath),
				NoRoute: true,
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			t.Helper()

			key := newDPoPClientKey(t)

			_, _, code := opSignedIn(t, spec, send)

			// The provider binds the token to the client's key, because the token request carries a proof.
			tokenReq := opTokenRequest(opTokenPath, code)
			tokenReq.Header["DPoP"] = rsProof(t, key, http.MethodPost, opTokenPath, "")

			issued := send(tokenReq)
			require.Equal(t, http.StatusOK, issued.Status, issued.Body)

			doc := opJSON(t, issued)
			access, _ := doc["access_token"].(string)
			require.NotEmpty(t, access)
			assert.Equal(t, "DPoP", doc["token_type"])

			// The API takes the bound token with a proof for this request, and publishes its user and scopes.
			api := send(rsDPoPGet(rsOrdersPath, access, rsProof(t, key, http.MethodGet, rsOrdersPath, access)))
			assertAccepted(t, api, rsOrdersAPI, string(UserID), "openid", "profile")
			assert.Equal(t, OPIssuer, api.AccessToken.Issuer)
			assert.Equal(t, opFirstParty, api.AccessToken.ClientID)
			assert.Equal(t, key.jkt, api.AccessToken.Confirmation["jkt"])

			// A path outside the prefix is the session's: the session opens it, as a session,
			// and the access token does not.
			sessionRes := send(rsGet(RoutePath, spec.Effects.SessionID))
			assert.Equal(t, http.StatusOK, sessionRes.Status, sessionRes.Body)
			assert.True(t, sessionRes.SessionKnown)
			assert.Nil(t, sessionRes.AccessToken)

			assertRefused(t, send(rsDPoPGet(RoutePath, access, rsProof(t, key, http.MethodGet, RoutePath, access))), "")

			// The token without its proof is refused: it is bound, so it is no bearer token.
			assertRefused(t, send(rsGet(rsOrdersPath, access)), "invalid_dpop_proof")

			// A provider token with a damaged signature is refused as an invalid token.
			damaged := access[:len(access)-4] + "AAAA"
			assertRefused(t, send(rsDPoPGet(rsOrdersPath, damaged, rsProof(t, key, http.MethodGet, rsOrdersPath, damaged))), "invalid_token")

			// No credential at all is no caller: the chain authenticates, and a rule or guard decides
			// whether an anonymous request may pass.
			anonymous := send(rsGet(rsOrdersPath, ""))
			assert.Equal(t, http.StatusOK, anonymous.Status)
			assert.False(t, anonymous.PrincipalKnown)
			assert.Nil(t, anonymous.AccessToken)
		},
	}
}

// rsRemoteIssuerChain is an API-only chain: no provider, no session, one remote
// issuer whose key set the library fetches.
func rsRemoteIssuerChain() Scenario {
	return Scenario{
		Name: "resource server on an API-only chain verifies a remote issuer's access tokens",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			effects := newEffects(t)
			effects.resourceServer = newRSIssuer(t)

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableResourceServer(rsOrdersAPI,
						httpsec.WithPathPrefix("/api/"), effects.resourceServer.source()),
				},
				Effects: effects,
				Routes:  rsRoutes(rsOrdersPath),
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			t.Helper()

			issuer := spec.Effects.resourceServer

			// A claims-only caller: named by issuer and subject, never a local user, with the token's scopes.
			good := send(rsGet(rsOrdersPath, issuer.token(t, rsOrdersAPI, nil)))
			assertAccepted(t, good, rsOrdersAPI, issuer.iss+"#42", "orders:read", "orders:write")
			assert.Equal(t, issuer.iss, good.AccessToken.Issuer)
			assert.Equal(t, rsRemoteClient, good.AccessToken.ClientID)

			// A token for another API, and an expired one, are invalid tokens.
			assertRefused(t, send(rsGet(rsOrdersPath, issuer.token(t, rsBillingAPI, nil))), "invalid_token")
			assertRefused(t, send(rsGet(rsOrdersPath, issuer.token(t, rsOrdersAPI, func(c map[string]any) {
				c["iat"] = time.Now().Add(-time.Hour).Unix()
				c["exp"] = time.Now().Add(-time.Minute).Unix()
			}))), "invalid_token")

			// An unreachable key set is the library's dependency failing, never the caller's fault.
			issuer.down.Store(true)

			outage := send(rsGet(rsOrdersPath, issuer.token(t, rsOrdersAPI, nil)))
			assert.Equal(t, http.StatusInternalServerError, outage.Status, outage.Body)
			assert.False(t, outage.RouteRan)
		},
	}
}

// rsTwoPrefixesOneIssuer is two resource servers on one chain, each confined to
// its own prefix, both trusting one issuer: a token is judged for the API of the
// path it is sent to, and for no other.
func rsTwoPrefixesOneIssuer() Scenario {
	return Scenario{
		Name: "two resource servers by prefix trusting one issuer judge a token for the API it is sent to",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			effects := newEffects(t)
			effects.resourceServer = newRSIssuer(t)

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableResourceServer(rsOrdersAPI,
						httpsec.WithPathPrefix("/api/"), effects.resourceServer.source()),
					httpsec.EnableResourceServer(rsBillingAPI,
						httpsec.WithPathPrefix("/billing/"), effects.resourceServer.source()),
				},
				Effects: effects,
				Routes:  rsRoutes(rsOrdersPath, rsBillingPath),
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			t.Helper()

			issuer := spec.Effects.resourceServer
			orders := issuer.token(t, rsOrdersAPI, nil)
			billing := issuer.token(t, rsBillingAPI, nil)

			// Each API accepts the token made for it, and names itself as the one that accepted it.
			assertAccepted(t, send(rsGet(rsOrdersPath, orders)), rsOrdersAPI, issuer.iss+"#42", "orders:read", "orders:write")
			assertAccepted(t, send(rsGet(rsBillingPath, billing)), rsBillingAPI, issuer.iss+"#42", "orders:read", "orders:write")

			// A token made for one API opens nothing of the other, though the issuer is trusted by both.
			assertRefused(t, send(rsGet(rsBillingPath, orders)), "invalid_token")
			assertRefused(t, send(rsGet(rsOrdersPath, billing)), "invalid_token")

			// A token naming both APIs opens both.
			both := issuer.token(t, "", func(c map[string]any) { c["aud"] = []string{rsOrdersAPI, rsBillingAPI} })
			assertAccepted(t, send(rsGet(rsOrdersPath, both)), rsOrdersAPI, issuer.iss+"#42", "orders:read", "orders:write")
			assertAccepted(t, send(rsGet(rsBillingPath, both)), rsBillingAPI, issuer.iss+"#42", "orders:read", "orders:write")
		},
	}
}
