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
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// confirm posts a logout page's answer to the confirmation endpoint.
func (w *logoutFlow) confirm(t *testing.T, body string, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+logoutConfirmPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	return w.serve(t, r, change)
}

// logoutConfirmed is the document confirming handle, and logoutDeclined the one declining.
func logoutConfirmed(handle string) string {
	return `{"req":` + logoutQuote(handle) + `,"confirmed":true}`
}

func logoutDeclined(handle string) string {
	return `{"req":` + logoutQuote(handle) + `,"confirmed":false}`
}

// asked is a request that end-session parked, from a browser holding browser, and its
// flow secret.
func (w *logoutFlow) asked(t *testing.T, params url.Values, browser string) (string, string) {
	t.Helper()

	var change []flowChange
	if browser != "" {
		change = append(change, flowCookieOf(flowSession, browser))
	}

	a := w.endSessionGET(t, params, change...)
	w.assertParked(t, a)

	return a.location(t).Query().Get(oidcprovider.HandleParam), a.cookie(flowCookie).Value
}

// assertLogoutAnswer checks the answer's shape, and where it sends the browser.
func assertLogoutAnswer(t *testing.T, a flowAnswer, target string) {
	t.Helper()

	require.Equal(t, http.StatusOK, a.status, a.body)
	assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
	assert.Equal(t, "application/json", a.header.Get("Content-Type"))
	assert.Equal(t, target, a.redirectTo(t).String())
	assert.Len(t, logoutDoc(t, a), 1)
	assert.False(t, a.passedOn)
}

func TestOIDCLogoutConfirm(t *testing.T) {
	t.Parallel()

	bye := opIssuer + logoutByePath

	type testCase struct {
		name  string
		setup logoutSetup
		run   func(t *testing.T, w *logoutFlow)
	}

	cases := []testCase{
		{
			name: "a confirmation in a browser holding a session ends that sign-in",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, bye)
				assertClearsBrowser(t, a)
				w.assertEnded(t, in)
			},
		},
		{
			name: "a hint for another sign-in ends the browser's, and never the one it names",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				browsers, named := w.signIn(t), w.signIn(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, named.session.FamilyID)), browsers.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, browsers.browser))
				assertLogoutAnswer(t, a, bye)
				w.assertEnded(t, browsers)
				w.assertStands(t, named)
			},
		},
		{
			name: "a hint held in a browser with no session ends nothing, and is no error",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				named := w.signIn(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, named.session.FamilyID)), "")

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow))
				assertLogoutAnswer(t, a, bye)
				assert.Nil(t, a.cookie(flowSession), "no sign-in ended, so no cookie is touched")
				w.assertStands(t, named)
			},
		},
		{
			name: "a hint whose sign-in has already ended, in a browser with no session, is no error",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				_, err := w.sessions.RevokeFamily(t.Context(), in.session.FamilyID)
				require.NoError(t, err)

				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)), "")
				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow)), bye)
			},
		},
		{
			name: "a browser session's secret no record holds is no session, and is no error",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, "")

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, "not-a-secret"))
				assertLogoutAnswer(t, a, bye)
				w.assertStands(t, in)
			},
		},
		{
			name:  "with browser sessions off, a confirmation ends the sign-in a valid hint names",
			setup: logoutSetup{withoutBrowsers: true},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)), "")

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow))
				assertLogoutAnswer(t, a, bye)
				assert.Nil(t, a.cookie(flowSession), "no such cookie is ever set")
				w.assertEnded(t, in)
			},
		},
		{
			name:  "with browser sessions off, a confirmation with no valid hint ends nothing",
			setup: logoutSetup{withoutBrowsers: true},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, "")

				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow)), bye)
				w.assertStands(t, in)
			},
		},
		{
			name: "a retired key's hint names nothing a confirmation could end, with browser sessions on",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				hint := w.logoutHintFrom(t, w.issuer, logoutRetiredKeys(), w.clk, in.session.FamilyID)
				handle, flow := w.asked(t, logoutParams("id_token_hint", hint, "post_logout_redirect_uri", logoutRPBye), "")

				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow)), bye)
				w.assertStands(t, in)
			},
		},
		{
			name: "a valid hint and a registered URI get the browser back, with its state",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				other := w.session(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, other.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "state", "s-1"), in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, logoutRPBye+"?state=s-1")
			},
		},
		{
			name: "a registered URI with no hint never gets the browser back",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, logoutParams("client_id", flowWeb, "post_logout_redirect_uri", logoutRPBye, "state", "s-1"), in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, bye)
				w.assertEnded(t, in)
			},
		},
		{
			name: "a URI unregistered since the request parked no longer gets the browser back",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				other := w.session(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, other.FamilyID),
					"post_logout_redirect_uri", logoutRPBye), in.browser)

				require.NoError(t, w.registry.Put(t.Context(), flowClients()[0]))

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, bye)
				w.assertEnded(t, in)
			},
		},
		{
			name: "a client removed since the request parked no longer gets the browser back",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				other := w.session(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, other.FamilyID),
					"post_logout_redirect_uri", logoutRPBye), in.browser)

				require.NoError(t, w.registry.Delete(t.Context(), flowWeb))

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, bye)
				w.assertEnded(t, in)
			},
		},
		{
			name: "a declined answer ends nothing, goes nowhere near the relying party, and spends the handle",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				other := w.session(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, other.FamilyID),
					"post_logout_redirect_uri", logoutRPBye, "state", "s-1"), in.browser)

				a := w.confirm(t, logoutDeclined(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, bye)
				assert.Nil(t, a.cookie(flowSession))
				w.assertStands(t, in)

				again := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, again.err, httpsec.ErrOIDCUnknownHandle)
				w.assertStands(t, in)
			},
		},
		{
			name: "an answer not saying it confirms is a decline",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)

				a := w.confirm(t, `{"req":`+logoutQuote(handle)+`}`, flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				assertLogoutAnswer(t, a, bye)
				w.assertStands(t, in)
			},
		},
		{
			name: "no flow cookie is an unknown handle, ending nothing, with the handle left to answer",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Empty(t, a.body)
				w.assertStands(t, in)

				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser)), bye)
			},
		},
		{
			name: "another browser's flow cookie is an unknown handle",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, _ := w.asked(t, url.Values{}, in.browser)
				_, otherFlow := w.asked(t, url.Values{}, "")

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, otherFlow), flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				w.assertStands(t, in)
			},
		},
		{
			name: "a spent handle is an unknown handle",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)
				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser)), bye)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
			},
		},
		{
			name: "an expired handle is an unknown handle",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				handle, flow := w.asked(t, url.Values{}, "")
				w.clk.Advance(time.Hour)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
			},
		},
		{
			name: "a handle waiting at login is no logout's, and is left to answer",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.park(t, flowWeb)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Equal(t, oidcprovider.StageLogin, w.stage(t, handle, flow))
				w.assertStands(t, in)
			},
		},
		{
			name: "a logout's handle cannot resume a login",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				handle, flow := w.asked(t, url.Values{}, "")

				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
			},
		},
		{
			name: "a cross-site confirmation is refused by CSRF protection",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser),
					func(r *http.Request) {
						r.Header.Set("Sec-Fetch-Site", "cross-site")
						r.Header.Set("Origin", "https://evil.example.com")
					})
				require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)
				assert.Equal(t, http.StatusForbidden, a.status)
				w.assertStands(t, in)

				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser)), bye)
			},
		},
		{
			name: "a method other than POST is answered here, ending nothing",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, w.issuer+logoutConfirmPath, nil)
				a := w.serve(t, r, []flowChange{flowCookieOf(flowSession, in.browser)})
				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, http.MethodPost, a.header.Get("Allow"))
				assert.False(t, a.passedOn)
				w.assertStands(t, in)
			},
		},
		{
			name: "a request not made over TLS is refused",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, in.browser), flowPlainHTTP)
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				w.assertStands(t, in)
			},
		},
		{
			name: "a body not declared as JSON says nothing, as a cross-site form could be neither",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser),
					func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				w.assertStands(t, in)
			},
		},
		{
			name: "a body that is no document says nothing",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				a := w.confirm(t, `{"req":`)
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
			},
		},
		{
			name:  "a body past the limit is refused",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCLogoutConfirmBodyLimit(4)}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				a := w.confirm(t, logoutConfirmed("rh.long-enough"))
				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
			},
		},
		{
			name: "a grant store failing answers 500, with the session loadable and the handle unspent",
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, url.Values{}, in.browser)
				w.grantsAt.outage.Store(true)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, in.browser))
				require.ErrorIs(t, a.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				assert.NotContains(t, a.body, "secret-store-text")

				_, err := w.sessions.Load(t.Context(), in.session.ID)
				require.NoError(t, err, "the sign-in's session is not deleted past a failure")

				w.grantsAt.outage.Store(false)

				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow)), bye)
			},
		},
		{
			name:  "with browser sessions off, a retry after a failure ends the sign-in",
			setup: logoutSetup{withoutBrowsers: true},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				in := w.signIn(t)
				handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)), "")
				w.grantsAt.outage.Store(true)

				a := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, oidcprovider.ErrDependency)

				w.grantsAt.outage.Store(false)

				assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow)), bye)
				w.assertEnded(t, in)
			},
		},
		{
			name: "an unknown handle is charged to its source, and a source past its limit is refused unread",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCLogoutConfirmLimiter(must1(ratelimit.NewMemoryLimiter(1, time.Minute))),
			}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				first := w.confirm(t, logoutConfirmed("rh.guess.guess"))
				require.ErrorIs(t, first.err, httpsec.ErrOIDCUnknownHandle)

				a := w.confirm(t, logoutConfirmed("rh.guess.guess"))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
			},
		},
		{
			name: "a limiter that cannot answer is refused, failing closed",
			setup: logoutSetup{flowSetup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCLogoutConfirmLimiter(flowDownLimiter{}),
			}}},
			run: func(t *testing.T, w *logoutFlow) {
				t.Helper()

				a := w.confirm(t, logoutConfirmed("rh.guess.guess"))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newLogoutFlow(t, tc.setup))
		})
	}
}
