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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
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

// exemptingResume is the construction error of a provider chain, on the cookie
// session when cookie is set and on the session bearer otherwise, whose CSRF
// protection exempts POST to pattern. opts are WithBasePath, applied to the
// chain, or WithOIDCProviderPrefix, applied to the provider.
func exemptingResume(t *testing.T, cookie bool, pattern string, opts ...any) error {
	t.Helper()

	change := func(s *flowSetup) {
		s.noCSRF = true
		s.chain = func(*testing.T, *opFlow) []httpsec.Option {
			chain := []httpsec.Option{
				httpsec.EnableCSRFProtection(httpsec.WithCSRFExemption(http.MethodPost, pattern)),
			}

			for _, o := range opts {
				if o, ok := o.(httpsec.Option); ok {
					chain = append(chain, o)
				}
			}

			return chain
		}

		for _, o := range opts {
			switch o := o.(type) {
			case httpsec.OIDCProviderOption:
				s.endpoint = append(s.endpoint, o)
			case httpsec.Option:
				// The provider's issuer is not under the base path these
				// rows move the endpoints to.
				s.endpoint = append(s.endpoint, httpsec.WithoutOIDCIssuerBasePathCheck())
			}
		}
	}

	if cookie {
		_, _, err := newCookieOP(t, change)

		return err
	}

	setup := flowSetup{}
	change(&setup)

	_, err := newOPFlowErr(t, setup)

	return err
}

// backchannelOverResume is the construction error of a cookie chain with the
// provider and an OIDC login whose back-channel logout endpoint answers under
// backchannel, with endpoint applied to the provider.
func backchannelOverResume(t *testing.T, backchannel string, endpoint ...httpsec.OIDCProviderOption) error {
	t.Helper()

	_, _, err := newCookieOP(t, func(s *flowSetup) {
		s.endpoint = append(s.endpoint, endpoint...)
		s.chain = func(t *testing.T, w *opFlow) []httpsec.Option {
			t.Helper()

			h := newOIDCHarness(t)

			return []httpsec.Option{httpsec.EnableOIDCLogin(
				httpsec.OIDCDeps{RelyingParty: h.manager},
				httpsec.WithOIDCSessions(w.sessions),
				httpsec.WithOIDCBackchannelLogoutPath(backchannel),
			)}
		}
	})

	return err
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
			name: "the cookie session and a session bearer are refused together, naming both",
			assert: func(t *testing.T) {
				t.Helper()

				// The bearer is over another manager, but this pins the
				// cookie-plus-bearer refusal, which comes first: the provider's
				// one-manager check cannot be reached on a cookie chain.
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
				assert.NotContains(t, err.Error(), "through one session manager",
					"the cookie-plus-bearer rule answers, not the provider's one-manager check")
			},
		},
		{
			name: "the provider without CSRF protection is refused, naming it, even without browser sessions",
			assert: func(t *testing.T) {
				t.Helper()

				_, _, err := newCookieOP(t, func(s *flowSetup) {
					s.noCSRF = true
					s.provider = append(s.provider, oidcprovider.WithoutBrowserSessions())
					s.chain = func(*testing.T, *opFlow) []httpsec.Option {
						return []httpsec.Option{httpsec.WithoutCSRFProtection()}
					}
				})
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableCSRFProtection")
				assert.Contains(t, err.Error(), "EnableSessionCookie")
			},
		},
		{
			name: "the cookie session without the provider still opts out of CSRF protection",
			assert: func(t *testing.T) {
				t.Helper()

				w := newOPFlow(t, flowSetup{})

				_, err := httpsec.New(
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}),
					httpsec.WithoutCSRFProtection(),
				)
				require.NoError(t, err)
			},
		},
		{
			name: "an exemption of the resume is refused, naming the endpoint",
			assert: func(t *testing.T) {
				t.Helper()

				err := exemptingResume(t, true, "/oauth2/authorize/resume")
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithCSRFExemption")
				assert.Contains(t, err.Error(), "POST /oauth2/authorize/resume")
			},
		},
		{
			name: "an exemption covering the resume through a wildcard segment is refused",
			assert: func(t *testing.T) {
				t.Helper()

				err := exemptingResume(t, true, "/oauth2/authorize/*")
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "POST /oauth2/authorize/resume")
			},
		},
		{
			name: "an exemption spelling the resume with an escape the router decodes is refused",
			assert: func(t *testing.T) {
				t.Helper()

				err := exemptingResume(t, true, "/oauth2/authorize/%72esume")
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "POST /oauth2/authorize/resume")
			},
		},
		{
			name: "an exemption of the resume under the base path is refused",
			assert: func(t *testing.T) {
				t.Helper()

				err := exemptingResume(t, true, "/x/oauth2/authorize/resume",
					httpsec.WithBasePath("/x"))
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "POST /x/oauth2/authorize/resume")
			},
		},
		{
			name: "an exemption of the resume under a renamed provider prefix is refused",
			assert: func(t *testing.T) {
				t.Helper()

				err := exemptingResume(t, true, "/idp/authorize/resume",
					httpsec.WithOIDCProviderPrefix("/idp"))
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "POST /idp/authorize/resume")
			},
		},
		{
			name: "a back-channel logout prefix over a moved resume is refused",
			assert: func(t *testing.T) {
				t.Helper()

				err := backchannelOverResume(t, "/bc", httpsec.WithOIDCProviderPath(httpsec.OIDCResume, "/bc/resume"))
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "a back-channel logout prefix over the authorize path is refused",
			assert: func(t *testing.T) {
				t.Helper()

				err := backchannelOverResume(t, "/oauth2/authorize")
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "the same exemption on a header-bearer provider chain builds",
			assert: func(t *testing.T) {
				t.Helper()

				require.NoError(t, exemptingResume(t, false, "/oauth2/authorize/resume"))
			},
		},
		{
			name: "an unrelated exemption on the cookie chain with the provider builds",
			assert: func(t *testing.T) {
				t.Helper()

				require.NoError(t, exemptingResume(t, true, "/webhooks/payments"))
			},
		},
		{
			name: "an exemption of the resume path under the default prefix builds once the prefix moved",
			assert: func(t *testing.T) {
				t.Helper()

				require.NoError(t, exemptingResume(t, true, "/oauth2/authorize/resume",
					httpsec.WithOIDCProviderPrefix("/idp")))
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
			name: "an endpoint the provider does not serve adds no exemption",
			assert: func(t *testing.T) {
				t.Helper()

				// No device grant: the device-authorization path is no route
				// of the provider's, so the cookie beside a client's
				// credentials there stays behind the guard.
				w, store, s := signedIn(t, nil)

				a := w.postForm(t, deviceAuthorizationPath, url.Values{"scope": {"openid"}},
					withSessionCookie(s.ID), deviceBasic(flowFirstParty, tokenSecret))
				guarded(t, a, store.loads.Load())
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

// cookieResumeCode is the code the second factor of mfaVerifiable accepts.
const cookieResumeCode = "246810"

// consumerCookieName is the cookie a consumer's own interceptor reads its
// session from in these rows.
const consumerCookieName = "consumer-session"

// sameOriginCSRF makes a request a same-origin page's, carrying csrf as the
// sign-in's CSRF token when it is not empty.
func sameOriginCSRF(csrf string) flowChange {
	return func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")

		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
	}
}

// cookieResume posts the resume of handle's login stage with the flow cookie,
// id as the session cookie and csrf as the sign-in's CSRF token (none when
// empty), from the same origin, with change.
func (w *opFlow) cookieResume(t *testing.T, handle, flow, id, csrf string, change ...flowChange) flowAnswer {
	t.Helper()

	send := []flowChange{flowCookieOf(flowCookie, flow), withSessionCookie(id), sameOriginCSRF(csrf)}

	return w.resume(t, flowLoginBody(handle), append(send, change...)...)
}

// resumedWithCode asserts a answered the resume with a redirect to the client
// carrying a code.
func resumedWithCode(t *testing.T, a flowAnswer) {
	t.Helper()

	require.NoError(t, a.err)
	require.Equal(t, http.StatusOK, a.status, a.body)
	assert.NotEmpty(t, a.redirectTo(t).Query().Get("code"), "the client is sent a code")
}

// consumerCookieSessions is a consumer's interceptor publishing the session its
// own cookie names, recording it as presented when record is set.
func consumerCookieSessions(w *opFlow, record bool) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		presented, ok := ex.Request.Cookie(consumerCookieName)
		if !ok {
			return next(ex)
		}

		s, err := w.sessions.Load(ex.Context(), presented)
		if err != nil {
			return err
		}

		if err := ex.PublishSession(&authenticate.Authentication{
			Principal: &identity.Principal{ID: s.UserID},
			Time:      w.clk.Now(),
		}, s); err != nil {
			return err
		}

		if record {
			ex.RecordPresentedToken(presented)
		}

		return next(ex)
	}), httpsec.OrderBearerToken)
}

// mfaVerifiable is mfaRequired with a method whose Verify accepts
// cookieResumeCode, so a row can finish the step a login owes.
func mfaVerifiable(t *testing.T, f *completionFlow) []httpsec.Option {
	t.Helper()

	method := NewMockMethod(gomock.NewController(t))
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	method.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, _ identity.UserID, response []byte) error {
			if string(response) != cookieResumeCode {
				return mfa.ErrInvalidCode
			}

			return nil
		})

	lookups := must.Must(mfa.LookupsFor(method))
	challenge := must.Must(policy.NewMFA(lookups))
	requirement := must.Must(policy.NewMFARequirement(nil, lookups,
		policy.WithMFARequiredForAll(), policy.WithFederatedAssuranceSource(f.rp)))

	return []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableMFA([]mfa.Method{method}),
	}
}

// TestSessionCookie_ProviderResume pins that on a cookie chain running the
// OpenID Provider the resume endpoint takes as its sign-in the session the
// built-in cookie session published, under CSRF protection and the checks a
// header sign-in passes; and refuses the cookie beside an Authorization line,
// a session a consumer's interceptor published or put in the cookie's place,
// and any method but POST. A header-bearer chain's resume is unchanged, and a
// login completed on the server that owes a step reaches the resume through
// the login page once the step is finished.
func TestSessionCookie_ProviderResume(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	// signedIn is a cookie chain running the provider, with change, a sign-in
	// of u-1 carrying a CSRF token, and the loads counted from zero.
	signedIn := func(t *testing.T, change func(*flowSetup)) (*opFlow, *loadCounter, *session.Session) {
		t.Helper()

		w, store, err := newCookieOP(t, change)
		require.NoError(t, err)

		s := w.session(t, session.WithCSRFToken())
		store.loads.Store(0)

		return w, store, s
	}

	// refusedUnspent asserts a was refused as needing a sign-in, and the handle
	// stays answerable.
	refusedUnspent := func(t *testing.T, w *opFlow, a flowAnswer, handle, flow string) {
		t.Helper()

		assert.Equal(t, http.StatusUnauthorized, a.status, a.body)
		require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
		flowUnspent(t, w, handle, flow)
	}

	cases := []testCase{
		{
			name: "the cookie and its CSRF token resume a pending authorization",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, s := signedIn(t, nil)
				handle, flow := w.park(t, flowFirstParty)

				a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken)
				resumedWithCode(t, a)
				assert.NotNil(t, a.cookie(flowSession), "the provider's browser session is set")
				assert.Nil(t, a.cookie(httpsec.DefaultSessionCookieName), "the session cookie is left alone")
			},
		},
		{
			name: "the cookie beside an Authorization line is refused by the guard, nothing loaded",
			assert: func(t *testing.T) {
				t.Helper()

				w, store, s := signedIn(t, nil)
				handle, flow := w.park(t, flowFirstParty)

				for _, authorization := range []string{"Bearer " + s.ID, "Basic dTpw", "Consumer x"} {
					store.loads.Store(0)

					a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken,
						func(r *http.Request) { r.Header.Set("Authorization", authorization) })
					guarded(t, a, store.loads.Load())
					flowUnspent(t, w, handle, flow)
				}
			},
		},
		{
			name: "the cookie without its CSRF token is refused as cross-site, nothing charged, the cookie kept",
			assert: func(t *testing.T) {
				t.Helper()

				var charged atomic.Int64

				w, _, s := signedIn(t, func(setup *flowSetup) {
					setup.endpoint = append(setup.endpoint,
						httpsec.WithOIDCResumeLimiter(resumeChargeCounter(t, &charged)))
				})
				handle, flow := w.park(t, flowFirstParty)

				for _, csrf := range []string{"", "wrong-" + s.CSRFToken} {
					a := w.cookieResume(t, handle, flow, s.ID, csrf)
					assert.Equal(t, http.StatusForbidden, a.status, a.body)
					require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)
					assert.Nil(t, a.cookie(httpsec.DefaultSessionCookieName), "the cookie is kept")
					flowUnspent(t, w, handle, flow)
				}

				assert.Zero(t, charged.Load(), "nothing is charged to the resume's source")
			},
		},
		{
			name: "GET and HEAD do not resume",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, s := signedIn(t, nil)
				handle, flow := w.park(t, flowFirstParty)

				for _, method := range []string{http.MethodGet, http.MethodHead} {
					r := httptest.NewRequestWithContext(t.Context(), method,
						w.issuer+flowResumePath+"?req="+url.QueryEscape(handle), nil)

					a := w.serve(t, r, []flowChange{
						flowCookieOf(flowCookie, flow), withSessionCookie(s.ID), sameOriginCSRF(s.CSRFToken),
					})
					assert.Equal(t, http.StatusMethodNotAllowed, a.status, "%s: %s", method, a.body)
					assert.Nil(t, a.cookie(flowSession), "%s: no browser session", method)
					flowUnspent(t, w, handle, flow)
				}
			},
		},
		{
			name: "a session a consumer's interceptor published from its own cookie is refused",
			assert: func(t *testing.T) {
				t.Helper()

				for _, record := range []bool{false, true} {
					w, _, s := signedIn(t, func(setup *flowSetup) {
						setup.chain = func(_ *testing.T, w *opFlow) []httpsec.Option {
							return []httpsec.Option{consumerCookieSessions(w, record)}
						}
					})
					handle, flow := w.park(t, flowFirstParty)

					a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow),
						flowCookieOf(consumerCookieName, s.ID), sameOriginCSRF(s.CSRFToken))
					refusedUnspent(t, w, a, handle, flow)
				}
			},
		},
		{
			name: "a session put in place of the one the cookie published is refused",
			assert: func(t *testing.T) {
				t.Helper()

				var other atomic.Pointer[session.Session]

				w, _, s := signedIn(t, func(setup *flowSetup) {
					setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
						return []httpsec.Option{httpsec.RegisterInterceptor(
							httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
								if o := other.Load(); o != nil && ex.Session != nil {
									ex.Session = o
								}

								return next(ex)
							}), httpsec.OrderSessionTouch-1)}
					}
				})
				other.Store(w.session(t))
				handle, flow := w.park(t, flowFirstParty)

				refusedUnspent(t, w, w.cookieResume(t, handle, flow, s.ID, s.CSRFToken), handle, flow)
			},
		},
		{
			name: "the cookie sign-in beside a credential a consumer's interceptor recorded is refused",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, s := signedIn(t, func(setup *flowSetup) {
					setup.chain = func(*testing.T, *opFlow) []httpsec.Option {
						return []httpsec.Option{httpsec.RegisterInterceptor(
							httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
								if presented := ex.Request.Header(flowConsumerMachineHeader); presented != "" {
									ex.RecordPresentedToken(presented)
								}

								return next(ex)
							}), httpsec.OrderSessionTouch-1)}
					}
				})
				handle, flow := w.park(t, flowFirstParty)

				a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken,
					func(r *http.Request) { r.Header.Set(flowConsumerMachineHeader, "machine-credential") })
				refusedUnspent(t, w, a, handle, flow)
			},
		},
		{
			name: "a cookie session owing a second factor is refused with its challenge on a chain with no gate",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, s := signedIn(t, nil)
				s.MFA = session.MFAPending
				require.NoError(t, w.sessions.Save(t.Context(), s))

				handle, flow := w.park(t, flowFirstParty)

				a := w.cookieResume(t, handle, flow, s.ID, s.CSRFToken)

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, a.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a cookie renewed between the login and the resume resumes with its successor",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, s := signedIn(t, nil)
				handle, flow := w.park(t, flowFirstParty)

				successor, _, err := w.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
				require.NoError(t, err)

				resumedWithCode(t, w.cookieResume(t, handle, flow, successor.ID, successor.CSRFToken))
			},
		},
		{
			name: "a superseded cookie inside its grace window resumes with the family's sign-in",
			assert: func(t *testing.T) {
				t.Helper()

				w, _, s := signedIn(t, nil)
				handle, flow := w.park(t, flowFirstParty)

				_, _, err := w.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
				require.NoError(t, err)

				resumedWithCode(t, w.cookieResume(t, handle, flow, s.ID, s.CSRFToken))
			},
		},
		{
			name: "a header-bearer chain reads no session cookie at the resume, and its bearer still resumes",
			assert: func(t *testing.T) {
				t.Helper()

				w := newOPFlow(t, flowSetup{})
				s := w.session(t, session.WithCSRFToken())
				handle, flow := w.park(t, flowFirstParty)

				refusedUnspent(t, w, w.cookieResume(t, handle, flow, s.ID, s.CSRFToken), handle, flow)

				resumedWithCode(t, w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow)))
			},
		},
		{
			name: "a completed login owing a step resumes through the login page once the step is finished",
			assert: func(t *testing.T) {
				t.Helper()

				f := newCompletionFlow(t, completionSetup{bearer: cookieSessionOf, noHandoff: true, chain: mfaVerifiable})
				handle, flow := f.park(t, flowFirstParty)

				a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				require.Equal(t, parkedAt(handle), a.header.Get("Location"))

				pending := a.cookie(httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending, "the pending sign-in's cookie is set")

				owing, err := f.sessions.Load(t.Context(), pending.Value)
				require.NoError(t, err)

				// Owing its step, the pending sign-in cannot resume.
				refused := f.cookieResume(t, handle, flow, pending.Value, owing.CSRFToken)

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, refused.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				flowUnspent(t, f.opFlow, handle, flow)

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+testMFAVerifyPath,
					strings.NewReader(url.Values{"code": {cookieResumeCode}}.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				verified := f.serve(t, r, []flowChange{withSessionCookie(pending.Value), sameOriginCSRF(owing.CSRFToken)})
				require.NoError(t, verified.err)
				require.Equal(t, http.StatusSeeOther, verified.status, "a form post is sent on: %s", verified.body)

				full := verified.cookie(httpsec.DefaultSessionCookieName)
				require.NotNil(t, full, "the verified sign-in's cookie is set")

				s, err := f.sessions.Load(t.Context(), full.Value)
				require.NoError(t, err)

				resumedWithCode(t, f.cookieResume(t, handle, flow, full.Value, s.CSRFToken))
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
