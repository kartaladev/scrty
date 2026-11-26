package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// loadCounter is a session store that counts the sessions loaded from it.
type loadCounter struct {
	session.Store

	loads atomic.Int64
}

func (s *loadCounter) Load(ctx context.Context, id string) (*session.Session, error) {
	s.loads.Add(1)

	return s.Store.Load(ctx, id)
}

// cookieSessionOf is the cookie session over w's session manager and user
// loader, in place of a provider flow's session bearer.
func cookieSessionOf(_ *testing.T, w *opFlow) httpsec.Option {
	return httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users})
}

// withSessionCookie presents id as the session cookie.
func withSessionCookie(id string) flowChange {
	return flowCookieOf(httpsec.DefaultSessionCookieName, id)
}

// newCookieOP is a provider flow run on a cookie chain, its session store
// counting loads, with change applied to its setup; and the chain's
// construction error.
func newCookieOP(t *testing.T, change func(*flowSetup)) (*opFlow, *loadCounter, error) {
	t.Helper()

	store := &loadCounter{Store: must.Must(session.NewMemoryStore())}
	setup := flowSetup{bearer: cookieSessionOf, sessions: []session.Option{session.WithStore(store)}}

	if change != nil {
		change(&setup)
	}

	w, err := newOPFlowErr(t, setup)

	return w, store, err
}

// cookieTokenAnswer is a token endpoint's success document, as far as these
// tests read it.
type cookieTokenAnswer struct {
	AccessToken string `json:"access_token"`
}

// accessTokenOf runs a first-party authorization by a sign-in of s to its code
// and spends the code at the token endpoint, with change, returning the
// endpoint's answer.
func accessTokenOf(t *testing.T, w *opFlow, s *session.Session, change ...flowChange) flowAnswer {
	t.Helper()

	handle, flow := w.park(t, flowFirstParty)

	res, err := w.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle:     handle,
		FlowSecret: flow,
		SignIn: &oidcprovider.SignIn{
			User:              s.UserID,
			Family:            s.FamilyID,
			AuthenticatedAt:   s.AuthenticatedAt,
			AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		},
		IdleTimeout: w.sessions.IdleTimeout(),
	})
	require.NoError(t, err)

	redirect, err := url.Parse(res.RedirectTo)
	require.NoError(t, err)

	code := redirect.Query().Get("code")
	require.NotEmpty(t, code, "the first-party authorization answers with a code")

	return w.postForm(t, "/oauth2/token", exchangeOf(code),
		append([]flowChange{deviceBasic(flowFirstParty, tokenSecret)}, change...)...)
}

// cookieAccessToken is the access token accessTokenOf obtains, with no change.
func cookieAccessToken(t *testing.T, w *opFlow, s *session.Session) string {
	t.Helper()

	a := accessTokenOf(t, w, s)
	require.Equal(t, http.StatusOK, a.status, a.body)

	var doc cookieTokenAnswer
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc))
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// at sends a request by method to path on w's issuer origin, with change.
func (w *opFlow) at(t *testing.T, method, path string, change ...flowChange) flowAnswer {
	t.Helper()

	origin := strings.TrimSuffix(w.issuer, mustURL(t, w.issuer).EscapedPath())

	r := httptest.NewRequestWithContext(t.Context(), method, origin+path, nil)

	return w.serve(t, r, change)
}

// mustURL parses raw.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

// judgedByProvider asserts the both-credentials guard let a answer through: the
// provider (or the key set) answered the request itself, not the chain's error
// handling with the guard's refusal, and no session was loaded for it.
func judgedByProvider(t *testing.T, a flowAnswer, loads int64) {
	t.Helper()

	assert.NotErrorIs(t, a.err, httpsec.ErrAuthenticationRequired, "the guard did not refuse it")
	assert.False(t, a.passedOn, "the provider answered it")
	assert.Zero(t, loads, "no session was loaded")
}

// guarded asserts a was refused by the both-credentials guard: 401, with
// nothing loaded and nothing passed on.
func guarded(t *testing.T, a flowAnswer, loads int64) {
	t.Helper()

	assert.Equal(t, http.StatusUnauthorized, a.status)
	require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
	assert.False(t, a.passedOn)
	assert.Zero(t, loads, "no session was loaded")
}

// TestSessionCookie_ProviderOnCookieChain pins that a chain runs the OpenID
// Provider with the cookie session as the sign-in it depends on: the chain
// builds, under the same one-manager and end-report rules as with a bearer;
// the provider's outer endpoints (authorization, token, userinfo, revocation,
// introspection, end-session, device authorization, discovery and the key set)
// answer a request carrying the session cookie and an Authorization header
// themselves, loading no session, exactly at the paths the chain resolved for
// them and no variant of those; every other provider route stays behind the
// both-credentials guard; and server-side completion runs without a handoff
// manager, setting no session cookie.
func TestSessionCookie_ProviderOnCookieChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	// signedIn is a cookie chain running the provider, built without error,
	// with a sign-in of u-1 and the loads counted from zero.
	signedIn := func(t *testing.T, change func(*flowSetup)) (*opFlow, *loadCounter, *session.Session) {
		t.Helper()

		w, store, err := newCookieOP(t, change)
		require.NoError(t, err)

		s := w.session(t)
		store.loads.Store(0)

		return w, store, s
	}

	// both presents s as the session cookie beside an Authorization header.
	both := func(s *session.Session, authorization string) []flowChange {
		return []flowChange{
			withSessionCookie(s.ID),
			func(r *http.Request) { r.Header.Set("Authorization", authorization) },
		}
	}

	cases := []testCase{
		{
			name: "the chain builds",
			assert: func(t *testing.T) {
				t.Helper()

				_, _, err := newCookieOP(t, nil)
				require.NoError(t, err, "the cookie session is the provider's sign-in")
			},
		},
		{
			name: "a cookie session whose manager does not report ends to the provider is refused",
			assert: func(t *testing.T) {
				t.Helper()

				_, _, err := newCookieOP(t, func(s *flowSetup) {
					s.bearer = func(_ *testing.T, w *opFlow) httpsec.Option {
						return httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{
							Sessions: must.Must(session.New()), Users: w.users,
						})
					}
				})
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "session.WithEndObserver(provider)")
			},
		},
		{
			name: "a cookie session beside a bearer over another manager is refused, naming both",
			assert: func(t *testing.T) {
				t.Helper()

				_, _, err := newCookieOP(t, func(s *flowSetup) {
					s.chain = func(_ *testing.T, w *opFlow) []httpsec.Option {
						return []httpsec.Option{httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
							Sessions: must.Must(session.New(session.WithEndObserver(w.p))), Users: w.users,
						})}
					}
				})
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableSessionCookie")
				assert.Contains(t, err.Error(), "EnableSessionBearer")
			},
		},
		{
			name: "userinfo judges the access token beside the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)
				tok := cookieAccessToken(t, w, s)
				store.loads.Store(0)

				a := w.at(t, http.MethodGet, "/oauth2/userinfo", both(s, "Bearer "+tok)...)
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Contains(t, a.body, `"sub":"u-1"`, "the provider's claims for the token")
				judgedByProvider(t, a, store.loads.Load())
			},
		},
		{
			name: "the token endpoint judges the client beside the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)

				a := accessTokenOf(t, w, s, withSessionCookie(s.ID))
				require.Equal(t, http.StatusOK, a.status, a.body)
				judgedByProvider(t, a, store.loads.Load())
			},
		},
		{
			name: "revocation and introspection judge the client beside the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)
				tok := cookieAccessToken(t, w, s)

				for _, path := range []string{"/oauth2/introspect", "/oauth2/revoke"} {
					store.loads.Store(0)

					a := w.postForm(t, path, url.Values{"token": {tok}},
						withSessionCookie(s.ID), deviceBasic(flowFirstParty, tokenSecret))
					assert.Equal(t, http.StatusOK, a.status, "%s: %s", path, a.body)
					judgedByProvider(t, a, store.loads.Load())
				}
			},
		},
		{
			name: "authorization, end-session, discovery and the key set answer beside the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)

				for _, path := range []string{
					"/oauth2/authorize?" + flowParams(flowWeb).Encode(),
					"/oauth2/logout",
					"/.well-known/openid-configuration",
					"/.well-known/oauth-authorization-server",
					httpsec.DefaultJWKSPath,
				} {
					store.loads.Store(0)

					a := w.at(t, http.MethodGet, path, both(s, "Bearer anything")...)
					assert.NotEqual(t, http.StatusUnauthorized, a.status, "%s: %s", path, a.body)
					judgedByProvider(t, a, store.loads.Load())
				}
			},
		},
		{
			name: "device authorization judges the client beside the cookie",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, func(setup *flowSetup) {
					device := deviceSetup("")
					setup.clients = device.clients
					setup.provider = device.provider
				})

				a := w.postForm(t, deviceAuthorizationPath, url.Values{"scope": {"openid"}},
					withSessionCookie(s.ID), deviceBasic(deviceCLI, tokenSecret))
				assert.Equal(t, http.StatusOK, a.status, a.body)
				judgedByProvider(t, a, store.loads.Load())

				store.loads.Store(0)
				guarded(t, w.at(t, http.MethodGet, deviceEntryPath, both(s, "Bearer anything")...), store.loads.Load())
			},
		},
		{
			name: "the provider's inner routes stay behind the guard",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)

				for _, r := range []struct{ method, path string }{
					{http.MethodPost, flowResumePath},
					{http.MethodPost, "/oauth2/authorize/cancel"},
					{http.MethodGet, "/oauth2/consents"},
					{http.MethodDelete, "/oauth2/consents/" + flowWeb},
					{http.MethodPost, "/oauth2/logout/confirm"},
				} {
					store.loads.Store(0)

					a := w.at(t, r.method, r.path, both(s, "Bearer "+s.ID)...)
					guarded(t, a, store.loads.Load())
				}
			},
		},
		{
			name: "only the exact resolved path is exempt, not a variant of it",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)
				tok := cookieAccessToken(t, w, s)

				for _, path := range []string{"/oauth2/userinfo/", "/oauth2//userinfo", "/OAUTH2/userinfo", "/oauth2"} {
					store.loads.Store(0)
					guarded(t, w.at(t, http.MethodGet, path, both(s, "Bearer "+tok)...), store.loads.Load())
				}

				// The key set answers GET alone and passes every other method on,
				// so it is exempt for GET alone.
				store.loads.Store(0)
				guarded(t, w.at(t, http.MethodPost, httpsec.DefaultJWKSPath, both(s, "Bearer "+tok)...),
					store.loads.Load())

				// An escape the router decodes to the very path is that path: the
				// provider answers it, as it would without the cookie.
				store.loads.Store(0)
				a := w.at(t, http.MethodGet, "/oauth2/user%69nfo", both(s, "Bearer "+tok)...)
				require.Equal(t, http.StatusOK, a.status, a.body)
				judgedByProvider(t, a, store.loads.Load())

				// Another method on an exempt path reaches the provider, which
				// answers it itself.
				store.loads.Store(0)
				judgedByProvider(t, w.at(t, http.MethodHead, "/oauth2/userinfo", both(s, "Bearer "+tok)...),
					store.loads.Load())
			},
		},
		{
			name: "a moved userinfo is exempt at its own path, and the default path is not",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, func(setup *flowSetup) {
					setup.endpoint = append(setup.endpoint, httpsec.WithOIDCProviderPath(httpsec.OIDCUserInfo, "/me"))
				})
				tok := cookieAccessToken(t, w, s)

				store.loads.Store(0)
				a := w.at(t, http.MethodGet, "/me", both(s, "Bearer "+tok)...)
				require.Equal(t, http.StatusOK, a.status, a.body)
				judgedByProvider(t, a, store.loads.Load())

				store.loads.Store(0)
				guarded(t, w.at(t, http.MethodGet, "/oauth2/userinfo", both(s, "Bearer "+tok)...), store.loads.Load())
			},
		},
		{
			name: "under a base path the exempt paths are the ones the chain answers",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, func(setup *flowSetup) {
					setup.issuer = opIssuer + "/auth"
					setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
						return []httpsec.Option{httpsec.WithBasePath("/auth")}
					}
				})
				tok := cookieAccessToken(t, w, s)

				store.loads.Store(0)
				a := w.at(t, http.MethodGet, "/auth/oauth2/userinfo", both(s, "Bearer "+tok)...)
				require.Equal(t, http.StatusOK, a.status, a.body)
				judgedByProvider(t, a, store.loads.Load())

				store.loads.Store(0)
				guarded(t, w.at(t, http.MethodGet, "/oauth2/userinfo", both(s, "Bearer "+tok)...), store.loads.Load())
			},
		},
		{
			name: "a provider path colliding with a guarded route is refused",
			assert: func(t *testing.T) {
				t.Helper()

				_, _, err := newCookieOP(t, func(setup *flowSetup) {
					setup.endpoint = append(setup.endpoint,
						httpsec.WithOIDCProviderPath(httpsec.OIDCUserInfo, httpsec.DefaultLogoutPath))
					setup.chain = func(_ *testing.T, w *opFlow) []httpsec.Option {
						return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: w.sessions})}
					}
				})
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "completion builds without a handoff manager, and a completed login sets no session cookie",
			assert: func(t *testing.T) {
				t.Helper()

				f := newCompletionFlow(t, completionSetup{bearer: cookieSessionOf, noHandoff: true})
				handle, flow := f.park(t, flowWeb)

				a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
				require.NoError(t, a.err)
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Nil(t, a.cookie(httpsec.DefaultSessionCookieName), "no session cookie is set")
				assert.NotNil(t, a.cookie(flowSession), "the provider's own browser-session cookie is")
			},
		},
		{
			name: "under completion, a login owing a step is conveyed as the cookie chain conveys a login",
			assert: func(t *testing.T) {
				t.Helper()

				f := newCompletionFlow(t, completionSetup{bearer: cookieSessionOf, noHandoff: true, chain: mfaRequired})
				handle, flow := f.park(t, flowWeb)

				a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, parkedAt(handle), a.header.Get("Location"),
					"the browser returns to the login page carrying the handle")
				assert.Empty(t, a.location(t).Query().Get(httpsec.DefaultOIDCHandoffParam), "no handoff code")

				pending := a.cookie(httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending, "the pending sign-in's cookie is set")

				s, err := f.sessions.Load(t.Context(), pending.Value)
				require.NoError(t, err)
				assert.NotEqual(t, session.MFANone, s.MFA, "the sign-in still owes its second factor")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}
