package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// formPost sends body to path as a form POST.
func (w *opFlow) formPost(t *testing.T, path, body string, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return w.serve(t, r, change)
}

// servedPost sends body as a form POST to the path the chain serves, on the issuer's origin. It is
// what reaches a chain behind a router that strips the issuer's path, where formPost's request,
// holding that path, would name no route.
func (w *opFlow) servedPost(t *testing.T, served, body string) flowAnswer {
	t.Helper()

	issuer, err := url.Parse(w.issuer)
	require.NoError(t, err)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		issuer.Scheme+"://"+issuer.Host+served, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return w.serve(t, r, nil)
}

// assertBounced pins the whole of a bounce: a 303 to endpoint, the address the provider publishes,
// holding params in the query, with the headers that keep them out of a cache and a referrer, and
// nothing set or parked.
func assertBounced(t *testing.T, w *opFlow, a flowAnswer, endpoint string, params url.Values) {
	t.Helper()

	require.Equal(t, http.StatusSeeOther, a.status, a.body)
	assert.False(t, a.passedOn)
	assert.Empty(t, a.body)
	assert.Empty(t, a.header.Values("Set-Cookie"), "the browser's cookies are left alone")
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))
	assert.Zero(t, w.pending.creates.Load(), "nothing is parked")

	loc := a.location(t)
	assert.Equal(t, endpoint, loc.Scheme+"://"+loc.Host+loc.Path)

	got, err := url.ParseQuery(loc.RawQuery)
	require.NoError(t, err)
	assert.Equal(t, params, got)
}

func TestOIDCFormPost_NoFlowCookie(t *testing.T) {
	t.Parallel()

	const (
		authorize  = flowAuthorizePath
		endSession = logoutEndSessionPath
	)

	// A limit of one means a single charge shows: the next request would answer 429.
	limited := []httpsec.OIDCProviderOption{
		httpsec.WithOIDCAuthorizeLimiter(must.Must(ratelimit.NewMemoryLimiter(1, time.Minute))),
		httpsec.WithOIDCEndSessionLimiter(must.Must(ratelimit.NewMemoryLimiter(1, time.Minute))),
	}

	// A request the provider would otherwise park, so that only the bounce keeps it from doing so.
	valid := flowParams(flowWeb)

	// A client that needs no consent, so that a browser session alone can answer it.
	firstParty := flowParams(flowFirstParty)

	carried := flowParams(flowWeb, func(p url.Values) {
		p["resource"] = []string{"https://api.example.com/a", "https://api.example.com/b"}
		p.Set("state", "a&b=c #d")
		p.Set("id_token_hint", "header.payload.signature")
	})

	type testCase struct {
		name   string
		setup  flowSetup
		send   func(t *testing.T, w *opFlow) flowAnswer
		assert func(t *testing.T, w *opFlow, a flowAnswer)
	}

	cases := []testCase{
		{
			name: "an empty POST to end-session goes to the endpoint with no query",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, endSession, "")
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, opIssuer+endSession, url.Values{})
				assert.Equal(t, opIssuer+endSession, a.header.Get("Location"), "an empty query leaves no question mark")
			},
		},
		{
			name: "a POST to authorize carries every value into the query",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, authorize, carried.Encode())
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, opIssuer+authorize, carried)
			},
		},
		{
			name: "a POST to end-session carries every value into the query",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, endSession, carried.Encode())
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, opIssuer+endSession, carried)
			},
		},
		{
			name: "a POST's query is not carried, as it is not read",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, authorize+"?nonce=from-the-query", valid.Encode())
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, opIssuer+authorize, valid)
			},
		},
		{
			name: "the bounce goes to where the endpoint was moved",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCAuthorize, "/moved/authorize"),
			}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, "/moved/authorize", valid.Encode())
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, opIssuer+"/moved/authorize", valid)
			},
		},
		{
			name:  "behind a router stripping the issuer's path, end-session bounces to its published address",
			setup: flowSetup{issuer: mdPathIssuer},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.servedPost(t, endSession, "")
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, mdPathIssuer+endSession, a.header.Get("Location"))
			},
		},
		{
			name:  "behind a router stripping the issuer's path, authorize bounces to its published address",
			setup: flowSetup{issuer: mdPathIssuer},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.servedPost(t, authorize, valid.Encode())
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, mdPathIssuer+authorize+"?"+valid.Encode(), a.header.Get("Location"))
			},
		},
		{
			name: "a chain mounted under the issuer's path bounces to its published address",
			setup: flowSetup{issuer: mdPathIssuer, endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPrefix("/auth/oauth2"),
			}},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.servedPost(t, "/auth/oauth2/logout", "")
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, mdPathIssuer+endSession, a.header.Get("Location"))
			},
		},
		{
			name:  "the loopback issuer's bounce goes to its published address",
			setup: flowSetup{issuer: flowLoopback},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, endSession, "", flowPlainHTTP)
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, flowLoopback+endSession, url.Values{})
			},
		},
		{
			name: "an empty flow cookie is no flow cookie",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, endSession, "", flowCookieOf(flowCookie, ""))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				assertBounced(t, w, a, opIssuer+endSession, url.Values{})
			},
		},
		{
			name: "a POST holding a flow cookie to authorize is answered directly",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				_, flow := w.park(t, flowWeb)

				return w.authorizePOST(t, flowParams(flowWeb), flowCookieOf(flowCookie, flow))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/login", a.location(t).Path)
				assert.NotEmpty(t, a.location(t).Query().Get(oidcprovider.HandleParam))
				assert.Equal(t, int64(2), w.pending.creates.Load(), "it parks")
			},
		},
		{
			name: "a POST holding a flow cookie to end-session is answered directly",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				_, flow := w.park(t, flowWeb)

				return w.formPost(t, endSession, "", flowCookieOf(flowCookie, flow))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/logout-page", a.location(t).Path)
				assert.NotEmpty(t, a.location(t).Query().Get(oidcprovider.HandleParam))
				assert.Equal(t, int64(2), w.pending.creates.Load(), "it parks")
			},
		},
		{
			name:  "the loopback issuer's flow cookie is read by the name it goes by",
			setup: flowSetup{issuer: flowLoopback},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				_, flow := w.parkIn(t, flowCookiePlain, flowWeb)

				return w.formPost(t, endSession, "", flowPlainHTTP, flowCookieOf(flowCookiePlain, flow))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/logout-page", a.location(t).Path)
			},
		},
		{
			name: "a GET to authorize with no cookie is not bounced, and sets the cookie",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/login", a.location(t).Path)
				assert.NotNil(t, a.cookie(flowCookie))
				assert.Equal(t, int64(1), w.pending.creates.Load())
			},
		},
		{
			name: "a GET to end-session with no cookie is not bounced, and sets the cookie",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, w.issuer+endSession, nil)

				return w.serve(t, r, nil)
			},
			assert: func(t *testing.T, w *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/logout-page", a.location(t).Path)
				assert.NotNil(t, a.cookie(flowCookie))
				assert.Equal(t, int64(1), w.pending.creates.Load())
			},
		},
		{
			name: "a malformed body to authorize is refused, with no Location",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, authorize, "client_id=%zz")
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCInvalidAuthorization)
				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Empty(t, a.header.Get("Location"))
				assert.Empty(t, a.header.Values("Set-Cookie"))
			},
		},
		{
			name: "a malformed body to end-session is refused, with no Location",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.formPost(t, endSession, "id_token_hint=%zz")
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCInvalidEndSession)
				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Empty(t, a.header.Get("Location"))
				assert.Empty(t, a.header.Values("Set-Cookie"))
			},
		},
		{
			name:  "bounces at authorize park nothing and charge nothing",
			setup: flowSetup{endpoint: limited},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				for range 3 {
					assertBounced(t, w, w.formPost(t, authorize, valid.Encode()), opIssuer+authorize, valid)
				}

				// The one charge the limit allows is still there to spend.
				a := w.authorizeGET(t, flowParams(flowWeb))
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/login", a.location(t).Path)

				return w.authorizeGET(t, flowParams(flowWeb))
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusTooManyRequests, a.status, "the limit does count what parks")
			},
		},
		{
			name:  "bounces at end-session park nothing and charge nothing",
			setup: flowSetup{endpoint: limited},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				for range 3 {
					assertBounced(t, w, w.formPost(t, endSession, ""), opIssuer+endSession, url.Values{})
				}

				get := func() flowAnswer {
					return w.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodGet, w.issuer+endSession, nil), nil)
				}

				a := get()
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/logout-page", a.location(t).Path)

				return get()
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				assert.Equal(t, http.StatusTooManyRequests, a.status, "the limit does count what parks")
			},
		},
		{
			name: "the redirected GET holding a browser session is answered from it with a code",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				secret := w.browserSession(t, w.session(t))
				before := w.pending.creates.Load()

				// The browser holds the session, but a cross-site POST does not send it.
				a := w.formPost(t, authorize, firstParty.Encode())
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, opIssuer+authorize, a.location(t).Scheme+"://"+a.location(t).Host+a.location(t).Path)
				assert.Empty(t, a.header.Values("Set-Cookie"))
				assert.Equal(t, before, w.pending.creates.Load(), "the POST parks nothing")

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, a.header.Get("Location"), nil)

				return w.serve(t, r, []flowChange{flowCookieOf(flowSession, secret)})
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, rpCallback, a.location(t).Scheme+"://"+a.location(t).Host+a.location(t).Path)
				assert.NotEmpty(t, a.location(t).Query().Get("code"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)
			tc.assert(t, w, tc.send(t, w))
		})
	}
}

// TestOIDCFormPost_ParkedRequestSurvives is the attack itself: any page can make a browser send
// the empty POST, and it must not cost the browser the request parked in another tab.
func TestOIDCFormPost_ParkedRequestSurvives(t *testing.T) {
	t.Parallel()

	w := newOPFlow(t, flowSetup{})
	handle, flow := w.park(t, flowFirstParty)

	a := w.formPost(t, logoutEndSessionPath, "")
	assert.Empty(t, a.header.Values("Set-Cookie"), "the browser keeps the cookie the parked request is bound to")

	res := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.NotEmpty(t, res.redirectTo(t).Query().Get("code"))
}

// TestOIDCFormPost_HintEndsTheSignInOnTheGET shows a hint sent by POST doing what it does by GET,
// on the request that carries the browser session, and not before.
func TestOIDCFormPost_HintEndsTheSignInOnTheGET(t *testing.T) {
	t.Parallel()

	w := newLogoutFlow(t, logoutSetup{})
	in := w.signIn(t)
	params := logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID))

	a := w.formPost(t, logoutEndSessionPath, params.Encode())
	assertBounced(t, w.opFlow, a, opIssuer+logoutEndSessionPath, params)
	assert.Zero(t, w.parked.count(), "nothing is parked")
	w.assertStands(t, in)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, a.header.Get("Location"), nil)

	followed := w.serve(t, r, []flowChange{flowCookieOf(flowSession, in.browser)})
	require.Equal(t, http.StatusSeeOther, followed.status, followed.body)
	assert.Equal(t, logoutByePath, followed.location(t).Path)
	w.assertEnded(t, in)
}
