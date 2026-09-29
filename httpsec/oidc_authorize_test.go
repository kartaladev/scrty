package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
)

// TestOIDCAuthorize pins the authorize endpoint: a GET on the authorize
// prefix followed by a registered provider's name starts a flow, hands the
// browser only the flow handle, in a cookie scoped to the callback, and
// redirects to the provider. Everything else passes through, and nothing that
// is not exactly one registered name ever starts a login with a provider.
func TestOIDCAuthorize(t *testing.T) {
	t.Parallel()

	get := func(target string) func(t *testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			return httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		}
	}

	corp := httpsec.DefaultOIDCAuthorizePath + testOIDCProvider

	type testCase struct {
		name        string
		managerOpts []oidc.ManagerOption
		opts        []httpsec.OIDCOption
		request     func(t *testing.T) *http.Request
		assert      func(t *testing.T, h *oidcHarness, out served)
	}

	// notAProvider is the outcome of a path that must never start a login:
	// either refused as an unknown provider or passed through untouched, and
	// in neither case a flow or a redirect.
	notAProvider := func(t *testing.T, h *oidcHarness, out served) {
		if out.err != nil {
			require.ErrorIs(t, out.err, oidc.ErrUnknownProvider)
			assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
		} else {
			assert.True(t, out.handlerRan, "a path that names no provider is passed through")
		}
		assert.Empty(t, out.rec.Header().Get("Location"))
		assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
		assert.Zero(t, h.liveFlows(t))
	}

	passedThrough := func(t *testing.T, h *oidcHarness, out served) {
		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
		assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
		assert.Zero(t, h.liveFlows(t))
	}

	cases := []testCase{
		{
			name:    "a GET redirects to the provider with a flow cookie",
			request: get(corp),
			assert: func(t *testing.T, h *oidcHarness, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the endpoint answers the request itself")
				require.Equal(t, http.StatusFound, out.rec.Code)
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))

				loc, err := url.Parse(out.rec.Header().Get("Location"))
				require.NoError(t, err)
				assert.Equal(t, h.provider.srv.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
				assert.Equal(t, "S256", loc.Query().Get("code_challenge_method"))
				assert.NotEmpty(t, loc.Query().Get("state"))

				cookies := out.rec.Header().Values("Set-Cookie")
				require.Len(t, cookies, 1)
				raw := cookies[0]
				assert.True(t, strings.HasPrefix(raw, httpsec.DefaultOIDCFlowCookieName+"="), raw)
				assert.Contains(t, raw, "Path="+httpsec.DefaultOIDCCallbackPath)
				assert.Contains(t, raw, "Max-Age=600")
				assert.Contains(t, raw, "HttpOnly")
				assert.Contains(t, raw, "Secure")
				assert.Contains(t, raw, "SameSite=Lax")

				cookie := cookieNamed(out.rec, httpsec.DefaultOIDCFlowCookieName)
				require.NotNil(t, cookie)
				assert.NotEmpty(t, cookie.Value)
				assert.NotContains(t, loc.RawQuery, cookie.Value, "the handle never reaches the provider")

				assert.Equal(t, 1, h.liveFlows(t))
			},
		},
		{
			name:    "an unknown provider is not found",
			request: get(httpsec.DefaultOIDCAuthorizePath + "nope"),
			assert: func(t *testing.T, h *oidcHarness, out served) {
				require.ErrorIs(t, out.err, oidc.ErrUnknownProvider)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
				assert.Zero(t, h.liveFlows(t))
			},
		},
		{
			name:    "an encoded slash in the provider segment is not a provider",
			request: get(corp + "%2F.."),
			assert:  notAProvider,
		},
		{
			name:    "an encoded slash ahead of the provider name is not a provider",
			request: get(httpsec.DefaultOIDCAuthorizePath + "x%2F" + testOIDCProvider),
			assert:  notAProvider,
		},
		{
			name:    "a trailing slash is not a provider",
			request: get(corp + "/"),
			assert:  notAProvider,
		},
		{
			name:    "a dot segment is not a provider",
			request: get(httpsec.DefaultOIDCAuthorizePath + ".."),
			assert:  notAProvider,
		},
		{
			name:    "the bare prefix is not a provider",
			request: get(httpsec.DefaultOIDCAuthorizePath),
			assert:  notAProvider,
		},
		{
			name: "a POST passes through",
			request: func(t *testing.T) *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodPost, corp, nil)
			},
			assert: passedThrough,
		},
		{
			name:    "an off-route GET passes through",
			request: get("/elsewhere/" + testOIDCProvider),
			assert:  passedThrough,
		},
		{
			name: "the requested destination is recorded untrusted",
			request: get(corp + "?" + url.Values{
				httpsec.DefaultOIDCNextParam: {"https://evil.example/"},
			}.Encode()),
			assert: func(t *testing.T, h *oidcHarness, out served) {
				require.NoError(t, out.err)
				require.Equal(t, http.StatusFound, out.rec.Code)

				cookie := cookieNamed(out.rec, httpsec.DefaultOIDCFlowCookieName)
				require.NotNil(t, cookie)
				loc, err := url.Parse(out.rec.Header().Get("Location"))
				require.NoError(t, err)

				f, err := h.flows.Complete(t.Context(), cookie.Value, testOIDCProvider, loc.Query().Get("state"))
				require.NoError(t, err)
				assert.Equal(t, "https://evil.example/", f.Next, "stored as given, resolved at the callback")
			},
		},
		{
			name:        "a flow expiry already passed clamps Max-Age to 1",
			managerOpts: []oidc.ManagerOption{oidc.WithClock(clockwork.NewFakeClockAt(time.Now().Add(-oidc.DefaultFlowTTL)))},
			request:     get(corp),
			assert: func(t *testing.T, _ *oidcHarness, out served) {
				require.NoError(t, out.err)
				require.Equal(t, http.StatusFound, out.rec.Code)

				cookies := out.rec.Header().Values("Set-Cookie")
				require.Len(t, cookies, 1)
				assert.Contains(t, cookies[0], "Max-Age=1")
				assert.NotContains(t, cookies[0], "Max-Age=0")
			},
		},
		{
			name:    "a consumer cookie name is used",
			opts:    []httpsec.OIDCOption{httpsec.WithOIDCFlowCookieName("idp_login")},
			request: get(corp),
			assert: func(t *testing.T, _ *oidcHarness, out served) {
				require.NoError(t, out.err)
				assert.NotNil(t, cookieNamed(out.rec, "idp_login"))
				assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultOIDCFlowCookieName))
			},
		},
		{
			name:    "a consumer callback path scopes the cookie",
			opts:    []httpsec.OIDCOption{httpsec.WithOIDCCallbackPath("/auth/back")},
			request: get(corp),
			assert: func(t *testing.T, _ *oidcHarness, out served) {
				require.NoError(t, out.err)

				cookie := cookieNamed(out.rec, httpsec.DefaultOIDCFlowCookieName)
				require.NotNil(t, cookie)
				assert.Equal(t, "/auth/back/", cookie.Path)
			},
		},
		{
			name:    "a consumer authorize path is answered",
			opts:    []httpsec.OIDCOption{httpsec.WithOIDCAuthorizePath("/sso/start")},
			request: get("/sso/start/" + testOIDCProvider),
			assert: func(t *testing.T, _ *oidcHarness, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusFound, out.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t, tc.managerOpts...)
			out := serve(t, h.chain(t, tc.opts...), tc.request(t))
			tc.assert(t, h, out)
		})
	}
}
