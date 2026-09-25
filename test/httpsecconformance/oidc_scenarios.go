package httpsecconformance

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/session"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// The federated identity every OIDC scenario is written against.
const (
	// OIDCProvider is the name the scenarios register the test identity
	// provider under, and so the last segment of every per-provider path.
	OIDCProvider = "corp"

	// OIDCSubject is the external subject the provider asserts, linked to
	// UserID before any request is sent.
	OIDCSubject = "sub-1"

	// OIDCSessionID is the provider's own session identifier on a federated
	// session a scenario pre-creates, and the sid a back-channel logout token
	// names to end it.
	OIDCSessionID = "sid-1"

	// OIDCIDToken is the raw ID token a pre-created federated session holds.
	// It is opaque to everything the scenarios reach except the end-session
	// URL, which carries it back to the provider as the hint.
	OIDCIDToken = "raw.id.token" //nolint:gosec // a fixture, not a credential

	// UnknownOIDCProvider names no registered provider.
	UnknownOIDCProvider = "nope"
)

// OIDCFixture is the federated-login wiring of one run, and what Build
// prepared at the provider before the request was sent.
//
// Build drives every step that happens away from the application — the
// browser at the provider, the provider's own callback — directly against the
// manager and the test provider, so the one request an adapter serves is the
// step the scenario is about, and the three frameworks are judged on that
// step alone.
type OIDCFixture struct {
	// IDP is the in-process provider, Manager and Handoffs the managers the
	// chain was given.
	IDP      *oidctest.IdentityProvider
	Manager  *oidc.Manager
	Handoffs *oidc.HandoffManager

	// FlowHandle is the flow cookie's value for a login Build started, and
	// CallbackPath the genuine callback, path and query, the provider sent the
	// browser back to.
	FlowHandle   string
	CallbackPath string

	// HandoffCode is a code a genuine callback conveyed and nothing redeemed.
	HandoffCode string

	// LogoutToken is the back-channel logout token the request carries.
	LogoutToken string
}

// newOIDCFixture wires a provider, a link from OIDCSubject to UserID, and the
// managers a chain's EnableOIDCLogin is given, and records them on e.
func newOIDCFixture(t *testing.T, e *Effects) *OIDCFixture {
	t.Helper()

	idp := oidctest.NewIdentityProvider(t)

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider:  OIDCProvider,
		Issuer:    idp.Issuer(),
		Subject:   OIDCSubject,
		UserID:    UserID,
		CreatedAt: time.Now(),
	}))

	broker, err := oidc.NewBroker(links, fixtureUsers{})
	require.NoError(t, err)

	registry, err := oidc.NewRegistry(idp.Provider(OIDCProvider, oidc.ClientSecretPost))
	require.NoError(t, err)

	manager, err := oidc.NewManager(registry, broker, oidc.WithOutboundClient(idp.Outbound(t)))
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), fixtureUsers{})
	require.NoError(t, err)

	fx := &OIDCFixture{IDP: idp, Manager: manager, Handoffs: handoffs}
	e.OIDC = fx

	return fx
}

// oidcOptions is the federated-login wiring every OIDC scenario shares: the
// chain's own defaults, with the fixture's token generator and session
// manager.
func oidcOptions(e *Effects) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableOIDCLogin(e.OIDC.Manager, e.OIDC.Handoffs,
			httpsec.WithOIDCTokens(fixtureTokens{}),
			httpsec.WithOIDCSessions(e.Sessions)),
	}
}

// oidcBuild is the Build of a scenario that needs only the wiring, with
// prepare run on the fixture before the request is sent.
func oidcBuild(prepare func(t *testing.T, e *Effects)) func(t *testing.T) ChainSpec {
	return func(t *testing.T) ChainSpec {
		effects := newEffects(t)
		newOIDCFixture(t, effects)

		if prepare != nil {
			prepare(t, effects)
		}

		return ChainSpec{
			Options: oidcOptions(effects),
			Effects: effects,
			NoRoute: true,
		}
	}
}

// beginLogin starts a login at the manager and plays the user at the
// provider, leaving the flow cookie and the genuine callback on the fixture.
func beginLogin(t *testing.T, e *Effects) {
	t.Helper()

	fx := e.OIDC

	auth, err := fx.Manager.Authorize(t.Context(), OIDCProvider, "")
	require.NoError(t, err)

	fx.FlowHandle = auth.Handle
	fx.CallbackPath = fx.IDP.Login(t, auth.RedirectURL, map[string]any{"sub": OIDCSubject})
}

// completeLogin completes the login beginLogin started, as the callback
// would, and issues the handoff code that callback conveys.
func completeLogin(t *testing.T, e *Effects) {
	t.Helper()

	beginLogin(t, e)

	fx := e.OIDC

	q := callbackQuery(t, fx.CallbackPath)

	res, err := fx.Manager.Callback(t.Context(), OIDCProvider, q.Get("code"), q.Get("state"), fx.FlowHandle)
	require.NoError(t, err)

	fx.HandoffCode, err = fx.Handoffs.Issue(t.Context(), res)
	require.NoError(t, err)
}

// federatedSession pre-creates a session a federated login opened, and
// records it on e.
func federatedSession(t *testing.T, e *Effects) {
	t.Helper()

	s, err := e.Sessions.Create(t.Context(), UserID, session.WithExternalSession(
		OIDCProvider, e.OIDC.IDP.Issuer(), OIDCSessionID, OIDCIDToken))
	require.NoError(t, err)

	e.SessionID = s.ID
}

// callbackQuery reads the query of a callback path.
func callbackQuery(t *testing.T, path string) url.Values {
	t.Helper()

	u, err := url.Parse(path)
	require.NoError(t, err)

	return u.Query()
}

// withFlowCookie is a GET of target from a browser holding the flow cookie.
func withFlowCookie(target, handle string) RequestSpec {
	return RequestSpec{
		Method:        http.MethodGet,
		Path:          target,
		Header:        map[string]string{"Cookie": httpsec.DefaultOIDCFlowCookieName + "=" + handle},
		ClientAddress: ClientAddress,
	}
}

// postForm is a URL-encoded POST of values to target.
func postForm(target string, values url.Values) RequestSpec {
	return RequestSpec{
		Method:        http.MethodPost,
		Path:          target,
		Header:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:          values.Encode(),
		ClientAddress: ClientAddress,
	}
}

// backchannelPath is where OIDCProvider posts its logout tokens.
const backchannelPath = httpsec.DefaultOIDCBackchannelPath + OIDCProvider

// signLogoutToken signs a logout token for the federated session, corrupted
// by opts.
func signLogoutToken(t *testing.T, e *Effects, opts ...oidctest.TokenOption) {
	t.Helper()

	fx := e.OIDC
	fx.LogoutToken = fx.IDP.LogoutToken(t, map[string]any{
		"aud": fx.IDP.Provider(OIDCProvider, oidc.ClientSecretPost).ClientID,
		"sub": OIDCSubject,
		"sid": OIDCSessionID,
	}, opts...)
}

// responseCookies parses the cookies a response set.
func responseCookies(h http.Header) []*http.Cookie {
	return (&http.Response{Header: h}).Cookies()
}

func oidcScenarios() []Scenario {
	return []Scenario{
		oidcAuthorizeRedirects(),
		oidcCallbackConveysAHandoff(),
		oidcForgedCallbackIsRefused(),
		oidcRedemptionOpensAFederatedSession(),
		oidcHandoffInTheQueryIsRefused(),
		oidcBackchannelEndsTheSession(),
		oidcForgedBackchannelIsRefused(),
		oidcUnknownProviderIsNotFound(),
		oidcEncodedSlashInProviderPassesThrough(),
		oidcLogoutAnswersEndSessionURL(),
	}
}

func oidcAuthorizeRedirects() Scenario {
	return Scenario{
		Name:  "OIDC authorize redirects with a flow cookie",
		Build: oidcBuild(nil),
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          httpsec.DefaultOIDCAuthorizePath + OIDCProvider,
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusFound, res.Status)
			assert.False(t, res.NoRouteRan, "the chain answered the authorize endpoint itself")

			loc, err := url.Parse(res.Header.Get("Location"))
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(loc.String(), res.Effects.OIDC.IDP.Issuer()),
				"the browser is sent to the provider: %s", loc)
			q := loc.Query()
			assert.NotEmpty(t, q.Get("state"))
			assert.NotEmpty(t, q.Get("nonce"))
			assert.NotEmpty(t, q.Get("code_challenge"))
			assert.Equal(t, "S256", q.Get("code_challenge_method"))

			cookies := responseCookies(res.Header)
			require.Len(t, cookies, 1, "exactly the flow cookie is set")
			assert.Equal(t, httpsec.DefaultOIDCFlowCookieName, cookies[0].Name)
			assert.NotEmpty(t, cookies[0].Value)
			assert.True(t, cookies[0].HttpOnly)
			assert.Equal(t, httpsec.DefaultOIDCCallbackPath, cookies[0].Path,
				"the cookie is sent to the callback and nowhere else")
		},
	}
}

func oidcCallbackConveysAHandoff() Scenario {
	return Scenario{
		Name:  "OIDC callback redirects with a handoff code",
		Build: oidcBuild(beginLogin),
		Request: func(spec ChainSpec) RequestSpec {
			fx := spec.Effects.OIDC

			return withFlowCookie(fx.CallbackPath, fx.FlowHandle)
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusFound, res.Status)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.Equal(t, "no-referrer", res.Header.Get("Referrer-Policy"))
			assert.False(t, res.NoRouteRan)

			loc, err := url.Parse(res.Header.Get("Location"))
			require.NoError(t, err)
			assert.Empty(t, loc.Host, "no destination is allowed, so the redirect stays on the application")
			assert.Equal(t, "/", loc.Path)
			code := loc.Query().Get(httpsec.DefaultOIDCHandoffParam)
			require.NotEmpty(t, code)

			cookies := responseCookies(res.Header)
			require.Len(t, cookies, 1, "the flow cookie is cleared")
			assert.Equal(t, httpsec.DefaultOIDCFlowCookieName, cookies[0].Name)
			assert.Negative(t, cookies[0].MaxAge)

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "the callback opens no session")

			redeemed, err := res.Effects.OIDC.Handoffs.Redeem(t.Context(), code)
			require.NoError(t, err, "the conveyed code is live")
			assert.Equal(t, UserID, redeemed.Principal.ID)
		},
	}
}

func oidcForgedCallbackIsRefused() Scenario {
	return Scenario{
		Name:  "OIDC callback with a forged state is 401 without clearing the cookie",
		Build: oidcBuild(beginLogin),
		Request: func(spec ChainSpec) RequestSpec {
			fx := spec.Effects.OIDC

			// The genuine callback with its state replaced: the code is the
			// provider's own, so only the state can be what is refused.
			u, _ := url.Parse(fx.CallbackPath) // Build's own path, parsed there already
			q := u.Query()
			q.Set("state", "forged")
			u.RawQuery = q.Encode()

			return withFlowCookie(u.String(), fx.FlowHandle)
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, oidc.ErrInvalidState)
			assert.Empty(t, res.Header.Values("Set-Cookie"), "no cookie-clearing header")
			assert.Empty(t, res.Header.Get("Location"))
			assert.False(t, res.NoRouteRan)

			fx := res.Effects.OIDC
			q := callbackQuery(t, fx.CallbackPath)
			_, err := fx.Manager.Callback(t.Context(), OIDCProvider, q.Get("code"), q.Get("state"), fx.FlowHandle)
			assert.NoError(t, err, "the refused callback left the browser's flow completable")
		},
	}
}

func oidcRedemptionOpensAFederatedSession() Scenario {
	return Scenario{
		Name:  "OIDC handoff redemption establishes a federated session",
		Build: oidcBuild(completeLogin),
		Request: func(spec ChainSpec) RequestSpec {
			return postForm(httpsec.DefaultOIDCHandoffPath,
				url.Values{httpsec.DefaultOIDCHandoffParam: {spec.Effects.OIDC.HandoffCode}})
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
			assert.False(t, res.NoRouteRan, "the chain answered the redemption itself")

			var body struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body))

			sessionID, ok := strings.CutPrefix(body.AccessToken, tokenPrefix+Username+".")
			require.True(t, ok, "the access token was issued for the linked user: %q", body.AccessToken)

			require.Equal(t, 1, res.Effects.ActiveSessions(t), "one session was opened")
			s := res.Effects.LoadSession(t, sessionID)
			assert.Equal(t, OIDCProvider, s.ExternalProvider)
			assert.Equal(t, res.Effects.OIDC.IDP.Issuer(), s.ExternalIssuer)
		},
	}
}

func oidcHandoffInTheQueryIsRefused() Scenario {
	// A code in the URL is one written into every log that saw the URL. It is
	// read from the form body alone, and a refusal must not spend it.
	return Scenario{
		Name:  "OIDC handoff code in the query string is refused",
		Build: oidcBuild(completeLogin),
		Request: func(spec ChainSpec) RequestSpec {
			return postForm(httpsec.DefaultOIDCHandoffPath+"?"+url.Values{
				httpsec.DefaultOIDCHandoffParam: {spec.Effects.OIDC.HandoffCode},
			}.Encode(), url.Values{})
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusUnauthorized, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, oidc.ErrInvalidHandoff)
			assert.False(t, res.NoRouteRan)

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "a refusal opens no session")

			_, err := res.Effects.OIDC.Handoffs.Redeem(t.Context(), res.Effects.OIDC.HandoffCode)
			assert.NoError(t, err, "the refused request did not spend the code")
		},
	}
}

func oidcBackchannelEndsTheSession() Scenario {
	return Scenario{
		Name: "OIDC back-channel logout ends the session named by sid",
		Build: oidcBuild(func(t *testing.T, e *Effects) {
			federatedSession(t, e)
			signLogoutToken(t, e)
		}),
		Request: func(spec ChainSpec) RequestSpec {
			return postForm(backchannelPath, url.Values{"logout_token": {spec.Effects.OIDC.LogoutToken}})
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			assert.Equal(t, http.StatusOK, res.Status)
			assert.Empty(t, res.Body, "the answer says nothing about what was ended")
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.False(t, res.NoRouteRan)

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "the named session was ended")
		},
	}
}

func oidcForgedBackchannelIsRefused() Scenario {
	return Scenario{
		Name: "OIDC back-channel with a forged token is 400",
		Build: oidcBuild(func(t *testing.T, e *Effects) {
			federatedSession(t, e)
			signLogoutToken(t, e, oidctest.BadSignature())
		}),
		Request: func(spec ChainSpec) RequestSpec {
			return postForm(backchannelPath, url.Values{"logout_token": {spec.Effects.OIDC.LogoutToken}})
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusBadRequest, res.Status)
			assert.Empty(t, res.Body, "the refusal names no check")
			require.ErrorIs(t, res.Refusal, oidc.ErrInvalidLogoutToken)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.False(t, res.NoRouteRan)

			assert.Equal(t, 1, res.Effects.ActiveSessions(t), "a forged token ends nothing")
		},
	}
}

func oidcUnknownProviderIsNotFound() Scenario {
	return Scenario{
		Name:  "OIDC authorize for an unknown provider is 404",
		Build: oidcBuild(nil),
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          httpsec.DefaultOIDCAuthorizePath + UnknownOIDCProvider,
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusNotFound, res.Status)
			assert.Empty(t, res.Body)
			require.ErrorIs(t, res.Refusal, oidc.ErrUnknownProvider)
			assert.Empty(t, res.Header.Values("Set-Cookie"), "no flow was started")
			assert.False(t, res.NoRouteRan, "the chain refused it before any no-route handler")
		},
	}
}

// oidcEncodedSlashInProviderPassesThrough pins that every adapter hands the
// chain the decoded path, as net/http's URL.Path is: an encoded slash in the
// provider segment decodes to a real one, so the path names no provider and the
// chain passes the request on rather than refusing an unknown provider.
func oidcEncodedSlashInProviderPassesThrough() Scenario {
	return Scenario{
		Name:  "OIDC authorize with an encoded slash in the provider segment passes through",
		Build: oidcBuild(nil),
		Request: sending(RequestSpec{
			Method:        http.MethodGet,
			Path:          httpsec.DefaultOIDCAuthorizePath + OIDCProvider + "%2F..",
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			require.NotErrorIs(t, res.Refusal, oidc.ErrUnknownProvider,
				"the chain refused a path that names no provider")
			require.NoError(t, res.Refusal)
			assert.True(t, res.NoRouteRan, "the chain passed the request on")
			assert.Equal(t, NoRouteBody, res.Body)
			assert.Empty(t, res.Header.Values("Set-Cookie"), "no flow was started")
		},
	}
}

func oidcLogoutAnswersEndSessionURL() Scenario {
	return Scenario{
		Name:    "logout of a federated session answers end_session_url",
		Request: authenticatedRequest(http.MethodPost, LogoutPath),
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			newOIDCFixture(t, effects)
			federatedSession(t, effects)

			opts := append(bearerOptions(effects),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: effects.Sessions}))

			return ChainSpec{
				Options: append(opts, oidcOptions(effects)...),
				Effects: effects,
				Routes: []Route{{
					Method: http.MethodPost, Path: LogoutPath,
					Status: http.StatusCreated, Body: RouteBody,
				}},
			}
		},
		Assert: func(t *testing.T, res Result) {
			require.NoError(t, res.Refusal)
			require.Equal(t, http.StatusOK, res.Status)
			assert.Equal(t, "no-store", res.Header.Get("Cache-Control"))
			assert.False(t, res.RouteRan, "the route on the logout path did not run")

			var body struct {
				EndSessionURL string `json:"end_session_url"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Body), &body), "body: %q", res.Body)

			u, err := url.Parse(body.EndSessionURL)
			require.NoError(t, err)
			assert.Equal(t, res.Effects.OIDC.IDP.Issuer()+"/logout", u.Scheme+"://"+u.Host+u.Path)
			assert.Equal(t, OIDCIDToken, u.Query().Get("id_token_hint"))

			assert.Equal(t, 0, res.Effects.ActiveSessions(t), "the local session was ended")
		},
	}
}
