package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
)

// conveyanceCall is what a consumer's CallbackSuccess was handed.
type conveyanceCall struct {
	mu     sync.Mutex
	called bool
	res    oidc.CallbackResult
	next   string
}

// TestOIDCCallback pins the callback endpoint: a genuine callback conveys
// the login by a single-use handoff code and creates no session; every callback
// that cannot prove it belongs to the browser's flow is an invalid state that
// leaves the flow, and the cookie naming it, exactly as they were; and the flow
// cookie is cleared only once the flow is spent.
func TestOIDCCallback(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// opts configure the chain beside the harness's required wiring.
		opts []httpsec.OIDCOption

		// conveyance, when set, is the consumer's CallbackSuccess; the chain
		// then has no handoff manager. It is handed the case's recorder.
		conveyance func(rec *conveyanceCall) httpsec.CallbackSuccess

		// next is the destination the login is started with.
		next string

		// setup runs after the login started and before the callback.
		setup func(h *oidcHarness)

		// request builds the callback; nil means the genuine callback.
		request func(t *testing.T, l oidcLogin) *http.Request

		assert func(t *testing.T, h *oidcHarness, c *httpsec.Chain, l oidcLogin, out served, rec *conveyanceCall)
	}

	withQuery := func(query func(l oidcLogin) string) func(t *testing.T, l oidcLogin) *http.Request {
		return func(t *testing.T, l oidcLogin) *http.Request {
			return callbackRequest(t.Context(), query(l), l.handle)
		}
	}

	// handoffIn reads the handoff code out of a redirect's Location.
	handoffIn := func(t *testing.T, out served) (*url.URL, string) {
		t.Helper()

		loc, err := url.Parse(out.rec.Header().Get("Location"))
		require.NoError(t, err)

		return loc, loc.Query().Get(httpsec.DefaultOIDCHandoffParam)
	}

	// clearsCookie asserts the response deletes the flow cookie.
	clearsCookie := func(t *testing.T, out served) {
		t.Helper()

		cookies := out.rec.Header().Values("Set-Cookie")
		require.Len(t, cookies, 1)
		assert.True(t, strings.HasPrefix(cookies[0], httpsec.DefaultOIDCFlowCookieName+"=;"), cookies[0])
		assert.Contains(t, cookies[0], "Max-Age=0")
		assert.Contains(t, cookies[0], "Path="+httpsec.DefaultOIDCCallbackPath)
	}

	// untouched is the outcome of every callback that cannot prove it belongs
	// to the browser's flow: an invalid state, no cookie-clearing header, and
	// the flow still live, which the genuine callback that follows proves.
	untouched := func(t *testing.T, h *oidcHarness, c *httpsec.Chain, l oidcLogin, out served, _ *conveyanceCall) {
		t.Helper()

		require.ErrorIs(t, out.err, oidc.ErrInvalidState)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Empty(t, out.rec.Header().Values("Set-Cookie"), "no cookie-clearing header")
		assert.Empty(t, out.rec.Header().Get("Location"))
		assert.Zero(t, h.storedHandoffs(t))

		genuine := serve(t, c, callbackRequest(t.Context(), l.genuineCallback(), l.handle))
		require.NoError(t, genuine.err, "the flow survived the refused callback")
		assert.Equal(t, http.StatusFound, genuine.rec.Code)
	}

	cases := []testCase{
		{
			name: "a successful callback redirects with a handoff and creates no session",
			assert: func(t *testing.T, h *oidcHarness, _ *httpsec.Chain, l oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				require.Equal(t, http.StatusFound, out.rec.Code)
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				loc, code := handoffIn(t, out)
				assert.Equal(t, "/", loc.Path)
				assert.Empty(t, loc.Host)
				assert.NotEmpty(t, code)

				clearsCookie(t, out)
				assert.Zero(t, h.activeSessions(t), "the callback creates no session")
				assert.Equal(t, 1, h.storedHandoffs(t))

				logs := h.logs.String()
				for _, secret := range []string{code, l.state, l.nonce, l.handle} {
					assert.NotContains(t, logs, secret)
				}
			},
		},
		{
			name: "the stored handoff record carries the asserted assurance, in order and without duplicates",
			setup: func(h *oidcHarness) {
				h.provider.assert([]string{"pwd", "mfa", "mfa"}, "urn:corp:loa:2")
			},
			assert: func(t *testing.T, h *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)
				require.Equal(t, http.StatusFound, out.rec.Code)

				_, code := handoffIn(t, out)
				tokenID, _, found := strings.Cut(code, ".")
				require.True(t, found, "a handoff code names its record")

				rec, err := h.store.FindByTokenID(t.Context(), tokenID)
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, rec.AMR)
				assert.Equal(t, "urn:corp:loa:2", rec.ACR)

				logs := h.logs.String()
				for _, value := range []string{"pwd", "urn:corp:loa:2"} {
					assert.NotContains(t, logs, value, "no asserted value is logged")
				}
			},
		},
		{
			name: "an allowlisted destination is used",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome")},
			next: "/welcome",
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)

				loc, code := handoffIn(t, out)
				assert.Equal(t, "/welcome", loc.Path)
				assert.NotEmpty(t, code)
			},
		},
		{
			name: "an allowlisted destination on a declared origin keeps its query",
			opts: []httpsec.OIDCOption{
				httpsec.WithOIDCAllowedOrigins("https://app.example"),
				httpsec.WithOIDCAllowedRedirects("https://app.example/welcome?tab=home"),
			},
			next: "https://app.example/welcome?tab=home",
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)

				loc, code := handoffIn(t, out)
				assert.Equal(t, "https://app.example/welcome", loc.Scheme+"://"+loc.Host+loc.Path)
				assert.Equal(t, "home", loc.Query().Get("tab"))
				assert.NotEmpty(t, code)
			},
		},
		{
			name: "an allowlisted destination's own handoff parameter is replaced",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome?handoff=planted")},
			next: "/welcome?handoff=planted",
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)

				loc, _ := handoffIn(t, out)
				values := loc.Query()[httpsec.DefaultOIDCHandoffParam]
				require.Len(t, values, 1, "set, not appended")
				assert.NotEqual(t, "planted", values[0])
			},
		},
		{
			name: "an unlisted destination falls back to /",
			next: "https://evil.example/",
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)

				loc, code := handoffIn(t, out)
				assert.Empty(t, loc.Host)
				assert.Equal(t, "/", loc.Path)
				assert.NotEmpty(t, code)
			},
		},
		{
			name: "a forged callback does not clear the cookie",
			request: withQuery(func(l oidcLogin) string {
				return url.Values{"code": {l.nonce}, "state": {"forged"}}.Encode()
			}),
			assert: untouched,
		},
		{
			name: "a forged error link does not clear the cookie",
			request: withQuery(func(oidcLogin) string {
				return url.Values{"error": {"access_denied"}, "error_description": {"forged-text"}}.Encode()
			}),
			assert: func(t *testing.T, h *oidcHarness, c *httpsec.Chain, l oidcLogin, out served, rec *conveyanceCall) {
				assert.NotContains(t, h.logs.String(), "forged-text", "an unbound error's text is never logged")
				untouched(t, h, c, l, out, rec)
			},
		},
		{
			name: "a forged error link with a wrong state does not clear the cookie",
			request: withQuery(func(oidcLogin) string {
				return url.Values{"error": {"access_denied"}, "state": {"forged"}}.Encode()
			}),
			assert: untouched,
		},
		{
			name: "a genuine denial ends the flow and clears the cookie",
			request: withQuery(func(l oidcLogin) string {
				return url.Values{
					"error": {"access_denied"}, "error_description": {"user-said-no"}, "state": {l.state},
				}.Encode()
			}),
			assert: func(t *testing.T, h *oidcHarness, c *httpsec.Chain, l oidcLogin, out served, _ *conveyanceCall) {
				require.ErrorIs(t, out.err, oidc.ErrInvalidState)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "user-said-no", "the provider's text is never returned")
				assert.Empty(t, out.rec.Body.String())
				clearsCookie(t, out)

				logs := h.logs.String()
				assert.Contains(t, logs, "access_denied")
				assert.Contains(t, logs, "user-said-no")
				assert.NotContains(t, logs, l.state)

				after := serve(t, c, callbackRequest(t.Context(), l.genuineCallback(), l.handle))
				require.ErrorIs(t, after.err, oidc.ErrInvalidState, "the denial spent the flow")
			},
		},
		{
			name: "no flow cookie is an invalid state",
			request: func(t *testing.T, l oidcLogin) *http.Request {
				return callbackRequest(t.Context(), l.genuineCallback(), "")
			},
			assert: untouched,
		},
		{
			name: "an empty state is an invalid state",
			request: withQuery(func(l oidcLogin) string {
				return url.Values{"code": {l.nonce}, "state": {""}}.Encode()
			}),
			assert: untouched,
		},
		{
			name: "an absent state is an invalid state",
			request: withQuery(func(l oidcLogin) string {
				return url.Values{"code": {l.nonce}}.Encode()
			}),
			assert: untouched,
		},
		{
			name: "an empty code is an invalid state",
			request: withQuery(func(l oidcLogin) string {
				return url.Values{"code": {""}, "state": {l.state}}.Encode()
			}),
			assert: untouched,
		},
		{
			name: "an absent code is an invalid state",
			request: withQuery(func(l oidcLogin) string {
				return url.Values{"state": {l.state}}.Encode()
			}),
			assert: untouched,
		},
		{
			name: "a repeated state parameter led by a forged value is an invalid state",
			request: withQuery(func(l oidcLogin) string {
				return "code=" + url.QueryEscape(l.nonce) + "&state=forged&state=" + url.QueryEscape(l.state)
			}),
			assert: untouched,
		},
		{
			name: "a repeated state with the real value first is refused",
			request: withQuery(func(l oidcLogin) string {
				return "code=" + url.QueryEscape(l.nonce) + "&state=" + url.QueryEscape(l.state) + "&state=forged"
			}),
			assert: untouched,
		},
		{
			name: "a repeated code is refused",
			request: withQuery(func(l oidcLogin) string {
				return "code=" + url.QueryEscape(l.nonce) + "&code=forged&state=" + url.QueryEscape(l.state)
			}),
			assert: untouched,
		},
		{
			name: "a repeated error is refused",
			request: withQuery(func(l oidcLogin) string {
				return "error=access_denied&error=forged&state=" + url.QueryEscape(l.state)
			}),
			assert: untouched,
		},
		{
			name: "a provider outage is a server error",
			setup: func(h *oidcHarness) {
				h.provider.tokenDown.Store(true)
			},
			assert: func(t *testing.T, h *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.ErrorIs(t, out.err, oidc.ErrExchangeFailed)
				assert.False(t, errors.Is(out.err, authenticate.ErrAuthenticationFailed))
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				clearsCookie(t, out)
				assert.Zero(t, h.storedHandoffs(t))
			},
		},
		{
			name: "a callback for an unknown provider is not found",
			request: func(t *testing.T, l oidcLogin) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					httpsec.DefaultOIDCCallbackPath+"nope?"+l.genuineCallback(), nil)
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultOIDCFlowCookieName, Value: l.handle}) //nolint:gosec // G124: a request cookie, never set

				return req
			},
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.ErrorIs(t, out.err, oidc.ErrUnknownProvider)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(out.err))
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
			},
		},
		{
			name: "a callback for an unknown provider with no cookie is not found",
			request: func(t *testing.T, _ oidcLogin) *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					httpsec.DefaultOIDCCallbackPath+"nope?error=access_denied", nil)
			},
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.ErrorIs(t, out.err, oidc.ErrUnknownProvider)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
			},
		},
		{
			name: "a POST to the callback passes through",
			request: func(t *testing.T, l oidcLogin) *http.Request {
				req := callbackRequest(t.Context(), l.genuineCallback(), l.handle)
				req.Method = http.MethodPost

				return req
			},
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Empty(t, out.rec.Header().Values("Set-Cookie"))
			},
		},
		{
			name: "a consumer cookie name is read and cleared",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCFlowCookieName("idp_login")},
			request: func(t *testing.T, l oidcLogin) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					httpsec.DefaultOIDCCallbackPath+testOIDCProvider+"?"+l.genuineCallback(), nil)
				req.AddCookie(&http.Cookie{Name: "idp_login", Value: l.handle}) //nolint:gosec // G124: a request cookie, never set

				return req
			},
			assert: func(t *testing.T, _ *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusFound, out.rec.Code)

				cleared := cookieNamed(out.rec, "idp_login")
				require.NotNil(t, cleared)
				assert.Negative(t, cleared.MaxAge)
			},
		},
		{
			name: "the consumer conveyance receives the login and no handoff is stored",
			next: "https://evil.example/",
			conveyance: func(rec *conveyanceCall) httpsec.CallbackSuccess {
				return func(ex *httpsec.Exchange, res oidc.CallbackResult, next string) error {
					rec.mu.Lock()
					defer rec.mu.Unlock()

					rec.called, rec.res, rec.next = true, res, next
					ex.Writer.WriteHeader(http.StatusNoContent)

					return nil
				}
			},
			assert: func(t *testing.T, h *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, rec *conveyanceCall) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Empty(t, out.rec.Header().Get("Location"))

				rec.mu.Lock()
				defer rec.mu.Unlock()

				require.True(t, rec.called)
				require.NotNil(t, rec.res.Principal)
				assert.Equal(t, oidcTestUserID, rec.res.Principal.ID)
				assert.Equal(t, h.provider.srv.URL, rec.res.Issuer)
				assert.Equal(t, oidcTestSessionID, rec.res.SessionID)
				assert.Equal(t, "/", rec.next, "the allowlist-resolved destination, never the requested one")
				assert.Empty(t, rec.res.AMR, "the token asserted no amr")
				assert.Empty(t, rec.res.ACR, "nor an acr")

				clearsCookie(t, out)
				assert.Zero(t, h.storedHandoffs(t))
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name: "the consumer conveyance receives the asserted assurance",
			conveyance: func(rec *conveyanceCall) httpsec.CallbackSuccess {
				return func(ex *httpsec.Exchange, res oidc.CallbackResult, next string) error {
					rec.mu.Lock()
					defer rec.mu.Unlock()

					rec.called, rec.res, rec.next = true, res, next
					ex.Writer.WriteHeader(http.StatusNoContent)

					return nil
				}
			},
			setup: func(h *oidcHarness) {
				h.provider.assert([]string{"mfa"}, "urn:corp:loa:2")
			},
			assert: func(t *testing.T, h *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, rec *conveyanceCall) {
				require.NoError(t, out.err)

				rec.mu.Lock()
				defer rec.mu.Unlock()

				require.True(t, rec.called)
				assert.Equal(t, []string{"mfa"}, rec.res.AMR)
				assert.Equal(t, "urn:corp:loa:2", rec.res.ACR)
				assert.Zero(t, h.storedHandoffs(t))
			},
		},
		{
			name: "a consumer conveyance error is the request's refusal",
			conveyance: func(*conveyanceCall) httpsec.CallbackSuccess {
				return func(*httpsec.Exchange, oidc.CallbackResult, string) error {
					return authenticate.ErrAuthenticationFailed
				}
			},
			assert: func(t *testing.T, h *oidcHarness, _ *httpsec.Chain, _ oidcLogin, out served, _ *conveyanceCall) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Zero(t, h.storedHandoffs(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			rec := &conveyanceCall{}

			var c *httpsec.Chain
			if tc.conveyance != nil {
				c = h.conveyedChain(t, tc.conveyance(rec), tc.opts...)
			} else {
				c = h.chain(t, tc.opts...)
			}

			l := startLogin(t, c, tc.next)

			if tc.setup != nil {
				tc.setup(h)
			}

			var req *http.Request
			if tc.request != nil {
				req = tc.request(t, l)
			} else {
				req = callbackRequest(t.Context(), l.genuineCallback(), l.handle)
			}

			tc.assert(t, h, c, l, serve(t, c, req), rec)
		})
	}
}
