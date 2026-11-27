package httpsec_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// answeredHTML asserts out delivered the sign-in as the session cookie alone
// (deliveredOnlyInCookie) and answered it as a browser's: 303 See Other to
// location, no-store, no body.
func answeredHTML(t *testing.T, sessions *session.Sessions, out served, location string) {
	t.Helper()

	require.NoError(t, out.err)
	deliveredOnlyInCookie(t, sessions, out)
	assert.Equal(t, http.StatusSeeOther, out.rec.Code)
	assert.Equal(t, location, out.rec.Header().Get("Location"))
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"), "the redirect is never cached")
	assert.Empty(t, out.rec.Body.String(), "a redirect carries no document")
	assert.False(t, out.handlerRan, "the endpoint answered the sign-in itself")
}

// answeredJSON asserts out delivered the sign-in as the session cookie alone
// and answered it as a script's: 200, a JSON document whose members are
// exactly want plus idle_expires_at, the stored session's idle expiry in RFC
// 3339. It returns the document.
func answeredJSON(t *testing.T, sessions *session.Sessions, out served, want ...string) map[string]json.RawMessage {
	t.Helper()

	require.NoError(t, out.err)
	id := deliveredOnlyInCookie(t, sessions, out)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"), "the document is never cached")
	assert.Empty(t, out.rec.Header().Get("Location"))

	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

	members := make([]string, 0, len(doc))
	for name := range doc {
		members = append(members, name)
	}

	assert.ElementsMatch(t, append([]string{"idle_expires_at"}, want...), members,
		"the document carries no credential member, empty or not")

	var idle string
	require.NoError(t, json.Unmarshal(doc["idle_expires_at"], &idle))

	at, err := time.Parse(time.RFC3339, idle)
	require.NoError(t, err, "the idle expiry is RFC 3339")

	s, err := sessions.Load(t.Context(), id)
	require.NoError(t, err)
	assert.True(t, s.IdleExpiresAt.Equal(at), "the idle expiry is the stored session's")

	return doc
}

// multipartNext is a multipart/form-data body, delimited by boundary, whose
// one field is next, set to value.
func multipartNext(boundary, value string) string {
	return "--" + boundary + "\r\nContent-Disposition: form-data; name=\"next\"\r\n\r\n" + value +
		"\r\n--" + boundary + "--\r\n"
}

// browserRequest is a POST of body to path with contentType, carrying the
// session cookie when cookie is not empty and accept when it is not empty.
func browserRequest(t *testing.T, path, contentType, body, cookie, accept string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
	if body != "" {
		req = jsonPost(t.Context(), path, body)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if cookie != "" {
		req.Header.Set("Cookie", named(cookie))
	}

	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	req.RemoteAddr = e2eSource + ":51000"

	return req
}

// loginJSON is the JSON sign-in of the browser world's user, with extra
// members beside the credentials.
func loginJSON(t *testing.T, extra map[string]any) string {
	t.Helper()

	doc := map[string]any{
		httpsec.DefaultLoginUsernameParam: e2eAddress,
		httpsec.DefaultLoginPasswordParam: e2ePassword,
	}
	for k, v := range extra {
		doc[k] = v
	}

	b, err := json.Marshal(doc)
	require.NoError(t, err)

	return string(b)
}

// passwordlessCookieLogin signs in with a passkey on a cookie chain, the
// finish request carrying accept when it is not empty.
func passwordlessCookieLogin(t *testing.T, accept string) (served, *session.Sessions) {
	t.Helper()

	d := newPwlDeployment(t)
	_ = d.options(t)

	chain, err := httpsec.New(
		httpsec.WithoutCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: d.sessions, Users: d.users}),
		httpsec.EnablePasskeys(
			httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions, Users: d.users},
			httpsec.WithPasskeyPasswordlessLogin()),
	)
	require.NoError(t, err)

	d.chain = chain
	handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)

	cookie, challenge := d.begun(t)

	req := jsonPost(t.Context(), passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
	req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	return serve(t, chain, req), d.sessions
}

// TestSessionCookie_Answers pins how every issuing endpoint of a cookie chain
// answers a sign-in by default: a form post, or a request whose Accept ranks
// text/html above application/json, is sent 303 See Other to its destination;
// any other request is answered 200 with a JSON document carrying the
// session's idle expiry and no credential member at all. Each endpoint's
// consumer responder still answers instead, the cookie set all the same.
//
// An endpoint reads the variants its body format allows: magic link
// redemption, second-factor verification by TOTP and password
// re-authentication read a form only, so a JSON request never reaches their
// answer, and passwordless passkey login reads JSON only. Recovery completion
// answers a document whatever was preferred when it reissued the user's saved
// codes, which a redirect would lose: they exist in readable form only in
// this response.
func TestSessionCookie_Answers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// issue runs the issuing request, and returns what it answered and the
		// manager its session lives in.
		issue func(t *testing.T) (served, *session.Sessions)

		assert func(t *testing.T, out served, sessions *session.Sessions)
	}

	html := func(location string) func(*testing.T, served, *session.Sessions) {
		return func(t *testing.T, out served, sessions *session.Sessions) {
			t.Helper()
			answeredHTML(t, sessions, out, location)
		}
	}

	plainJSON := func(t *testing.T, out served, sessions *session.Sessions) {
		t.Helper()
		answeredJSON(t, sessions, out)
	}

	consumer := func(t *testing.T, out served, sessions *session.Sessions) {
		t.Helper()
		require.NoError(t, out.err)
		deliveredOnlyInCookie(t, sessions, out)
		assert.Equal(t, http.StatusNoContent, out.rec.Code, "the consumer's responder answered")
		assert.Empty(t, out.rec.Header().Get("Location"))
	}

	answer204 := func(ex *httpsec.Exchange) error {
		ex.Writer.WriteHeader(http.StatusNoContent)

		return nil
	}

	cases := []testCase{
		{
			name: "form login: form post",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)

				return w.post(t.Context(), t, httpsec.DefaultLoginPath, "", url.Values{
					httpsec.DefaultLoginUsernameParam:     {e2eAddress},
					httpsec.DefaultLoginPasswordParam:     {e2ePassword},
					httpsec.DefaultSessionCookieNextParam: {"/orders"},
				}), w.sessions
			},
			assert: html("/orders"),
		},
		{
			name: "form login: Accept with an empty q-value fraction prefers HTML",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				req := browserRequest(t, httpsec.DefaultLoginPath, "application/json",
					loginJSON(t, map[string]any{"next": "/orders"}), "", "text/html;q=1., application/json;q=0.5")

				return serve(t, w.chain, req), w.sessions
			},
			assert: html("/orders"),
		},
		{
			name: "form login: JSON preferring HTML",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				req := browserRequest(t, httpsec.DefaultLoginPath, "application/json",
					loginJSON(t, map[string]any{"next": "/orders"}), "", "text/html")

				return serve(t, w.chain, req), w.sessions
			},
			assert: html("/orders"),
		},
		{
			name: "form login: JSON",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				req := browserRequest(t, httpsec.DefaultLoginPath, "application/json",
					loginJSON(t, map[string]any{"next": "/orders"}), "", "application/json")

				return serve(t, w.chain, req), w.sessions
			},
			assert: plainJSON,
		},
		{
			name: "form login: consumer responder",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t)
				w.loginOpts = append(w.loginOpts, httpsec.WithLoginResponder(
					func(ex *httpsec.Exchange, _ httpsec.LoginResult) error { return answer204(ex) }))
				w.build(t)

				return w.login(t), w.sessions
			},
			assert: consumer,
		},
		{
			name: "second-factor verification: form post",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t)
				w.enrol(t)
				w.build(t)

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				return w.post(t.Context(), t, testMFAVerifyPath, pending.Value,
					url.Values{"code": {w.code(t)}, "next": {"/orders"}}), w.sessions
			},
			assert: html("/orders"),
		},
		{
			name: "second-factor verification: consumer responder",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t)
				w.mfaOpts = append(w.mfaOpts, httpsec.WithMFAResponder(
					func(ex *httpsec.Exchange, _ httpsec.MFAResult) error { return answer204(ex) }))
				w.enrol(t)
				w.build(t)

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				return w.post(t.Context(), t, testMFAVerifyPath, pending.Value,
					url.Values{"code": {w.code(t)}}), w.sessions
			},
			assert: consumer,
		},
		{
			name: "re-authentication: form post",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, reauthPasswordPath, id,
					url.Values{"password": {e2ePassword}, "next": {"/settings"}}), w.sessions
			},
			assert: html("/settings"),
		},
		{
			name: "re-authentication: consumer responder",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t)
				w.reauthOpts = append(w.reauthOpts, httpsec.WithReauthenticationResponder(
					func(ex *httpsec.Exchange, _ httpsec.ReauthenticationResult) error { return answer204(ex) }))
				w.build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, reauthPasswordPath, id,
					url.Values{"password": {e2ePassword}}), w.sessions
			},
			assert: consumer,
		},
		{
			name: "session renewal: form post",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil), w.sessions
			},
			assert: html("/"),
		},
		{
			name: "session renewal: Accept preferring HTML",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				return serve(t, w.chain, browserRequest(t, httpsec.DefaultSessionRenewalPath, "", "", id,
					"text/html,application/xhtml+xml,*/*;q=0.8")), w.sessions
			},
			assert: html("/"),
		},
		{
			name: "session renewal: JSON",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t).build(t)
				id := w.signedIn(t)

				return serve(t, w.chain, browserRequest(t, httpsec.DefaultSessionRenewalPath, "", "", id, "")), w.sessions
			},
			assert: plainJSON,
		},
		{
			name: "session renewal: consumer responder",
			issue: func(t *testing.T) (served, *session.Sessions) {
				w := newBrowserWorld(t)
				w.renewalOpts = append(w.renewalOpts, httpsec.WithRenewalResponder(
					func(ex *httpsec.Exchange, _ httpsec.RenewalResult) error { return answer204(ex) }))
				w.build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil), w.sessions
			},
			assert: consumer,
		},
		{
			name: "magic link redemption: form post to its allowlisted destination",
			issue: func(t *testing.T) (served, *session.Sessions) {
				h := newMagicLinkHarness(t)
				h.tokens = nil
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkAllowedRedirects("/inbox"))
				h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))

				chain, err := h.build()
				require.NoError(t, err)

				tok, nonce := h.link(t, chain)

				return serve(t, chain, consumeWithNext(t, tok, nonce, "/inbox")), h.sessions
			},
			assert: html("/inbox"),
		},
		{
			name: "magic link redemption: a destination off its allowlist",
			issue: func(t *testing.T) (served, *session.Sessions) {
				h := newMagicLinkHarness(t)
				h.tokens = nil
				h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))

				chain, err := h.build()
				require.NoError(t, err)

				tok, nonce := h.link(t, chain)

				return serve(t, chain, consumeWithNext(t, tok, nonce, "/orders")), h.sessions
			},
			assert: html("/"),
		},
		{
			name: "passwordless passkey login: JSON preferring HTML",
			issue: func(t *testing.T) (served, *session.Sessions) {
				return passwordlessCookieLogin(t, "text/html")
			},
			assert: html("/"),
		},
		{
			name: "passwordless passkey login: JSON",
			issue: func(t *testing.T) (served, *session.Sessions) {
				return passwordlessCookieLogin(t, "")
			},
			assert: plainJSON,
		},
		{
			name: "recovery completion reissuing saved codes: answered a document even to a form",
			issue: func(t *testing.T) (served, *session.Sessions) {
				h := newRecoveryHarness(t)
				h.cookie = true
				h.build(t)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword)), h.sessions
			},
			assert: func(t *testing.T, out served, sessions *session.Sessions) {
				t.Helper()

				doc := answeredJSON(t, sessions, out, "recovery_codes", "remaining", "low")

				var codes []string
				require.NoError(t, json.Unmarshal(doc["recovery_codes"], &codes))
				assert.NotEmpty(t, codes, "the new saved codes are shown")
			},
		},
		{
			name: "recovery completion without reissued codes: form post is redirected",
			issue: func(t *testing.T) (served, *session.Sessions) {
				h := newRecoveryHarness(t)
				h.cookie = true
				h.enrolTOTP(t)
				h.build(t)

				return h.complete(t, recoveryForm(
					httpsec.RecoveryIssuedCodeParam, h.issued(t),
					httpsec.RecoveryMFAMethodParam, "totp",
					httpsec.RecoveryMFACodeParam, h.totpCode(t))), h.sessions
			},
			assert: html("/"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, sessions := tc.issue(t)
			tc.assert(t, out, sessions)
		})
	}
}

// TestSessionCookie_Destination pins where a browser sign-in on a cookie chain
// is sent: the requested next (a form field, or a JSON member) only when it
// is a path on this origin beginning with exactly one "/", or a target the
// consumer allowlisted exactly; anything else, however it is encoded or
// disguised, a missing, empty or repeated next included, is "/". An allowlist
// entry that is not an absolute https URL with a host, without userinfo or
// fragment, and an empty field name, fail construction.
func TestSessionCookie_Destination(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// opts are the cookie session's options.
		opts []httpsec.SessionCookieOption

		// form is the sign-in form's further fields; json, when not nil,
		// replaces the form with a JSON sign-in carrying these members,
		// preferring HTML.
		form url.Values
		json map[string]any

		// request, when not nil, replaces both with the request it returns,
		// built once the chain is: a session renewal, which needs no field of
		// its own, so the case is about how next is read and nothing else.
		request func(t *testing.T, w *browserWorld) *http.Request

		assert func(t *testing.T, w *browserWorld, out served, buildErr error)
	}

	allowlisted := httpsec.WithSessionCookieRedirects("https://app.example.com/home")

	to := func(location string) func(*testing.T, *browserWorld, served, error) {
		return func(t *testing.T, w *browserWorld, out served, buildErr error) {
			t.Helper()
			require.NoError(t, buildErr)
			answeredHTML(t, w.sessions, out, location)
		}
	}

	refused := func(t *testing.T, _ *browserWorld, _ served, buildErr error) {
		t.Helper()
		require.ErrorIs(t, buildErr, httpsec.ErrConfig)
	}

	next := func(values ...string) url.Values { return url.Values{"next": values} }

	// renewal is a session renewal carrying body as contentType, to a path
	// with query, preferring HTML.
	renewal := func(query, contentType, body string) func(*testing.T, *browserWorld) *http.Request {
		return func(t *testing.T, w *browserWorld) *http.Request {
			t.Helper()

			return browserRequest(t, httpsec.DefaultSessionRenewalPath+query, contentType, body,
				w.signedIn(t), "text/html")
		}
	}

	cases := []testCase{
		{name: "same-origin path", form: next("/orders"), assert: to("/orders")},
		{name: "same-origin path with a query", form: next("/orders?page=2&sort=asc"), assert: to("/orders?page=2&sort=asc")},
		{name: "root", form: next("/"), assert: to("/")},
		{name: "absolute URL off-site", form: next("https://evil.example/"), assert: to("/")},
		{name: "scheme-relative URL", form: next("//evil.example/"), assert: to("/")},
		{name: "backslash after the slash", form: next(`/\evil`), assert: to("/")},
		{name: "backslash anywhere", form: next(`/orders\..\x`), assert: to("/")},
		{name: "encoded double slash", form: next("%2F%2Fevil.example"), assert: to("/")},
		{name: "slash then encoded slash", form: next("/%2F/evil.example"), assert: to("/")},
		{name: "slash then lower-case encoded slash", form: next("/%2f/evil.example"), assert: to("/")},
		{name: "encoded backslash", form: next("/%5Cevil"), assert: to("/")},
		{name: "literal tab between slashes", form: next("/\t/evil"), assert: to("/")},
		{name: "encoded tab between slashes", form: next("/%09/evil"), assert: to("/")},
		{name: "literal NUL", form: next("/orders\x00"), assert: to("/")},
		{name: "scheme without slashes", form: next("https:evil"), assert: to("/")},
		{name: "javascript URL", form: next("javascript:alert(1)"), assert: to("/")},
		{name: "encoded CRLF header injection", form: next("/%0d%0aSet-Cookie:x"), assert: to("/")},
		{name: "literal CRLF", form: next("/\r\nSet-Cookie:x"), assert: to("/")},
		{name: "malformed escape", form: next("/orders%zz"), assert: to("/")},
		{name: "relative path without a slash", form: next("orders"), assert: to("/")},
		{name: "space", form: next("/ /evil"), assert: to("/")},
		{name: "non-ASCII", form: next("/ordérs"), assert: to("/")},
		{name: "empty", form: next(""), assert: to("/")},
		{name: "missing", assert: to("/")},
		{name: "duplicated next", form: next("/orders", "/settings"), assert: to("/")},
		{name: "duplicated next, one hostile", form: next("/orders", "//evil.example"), assert: to("/")},
		{
			name:    "renewal control: next in a URL-encoded body is read",
			request: renewal("", "application/x-www-form-urlencoded", "next=/orders"), assert: to("/orders"),
		},
		{
			name:    "multipart body is never read",
			request: renewal("", "multipart/form-data; boundary=x", multipartNext("x", "/orders")), assert: to("/"),
		},
		{
			name: "body over 64 KiB names no destination",
			request: renewal("", "application/x-www-form-urlencoded",
				"next=/orders&pad="+strings.Repeat("a", 64<<10)), assert: to("/"),
		},
		{
			name:    "next in the URL is ignored",
			request: renewal("?next=/orders", "application/x-www-form-urlencoded", ""), assert: to("/"),
		},
		{
			name:    "next in the URL is ignored beside a body that names none",
			request: renewal("?next=/orders", "application/x-www-form-urlencoded", "other=1"), assert: to("/"),
		},
		{
			name:    "renewal control: JSON member is read",
			request: renewal("", "application/json", `{"next":"/orders"}`), assert: to("/orders"),
		},
		{
			name:    "JSON member followed by trailing data",
			request: renewal("", "application/json", `{"next":"/orders"} garbage`), assert: to("/"),
		},
		{
			name:    "JSON member followed by a second value",
			request: renewal("", "application/json", `{"next":"/orders"}{"next":"/other"}`), assert: to("/"),
		},
		{
			name: "allowlisted absolute target", opts: []httpsec.SessionCookieOption{allowlisted},
			form: next("https://app.example.com/home"), assert: to("https://app.example.com/home"),
		},
		{
			name: "allowlist near-miss: longer path", opts: []httpsec.SessionCookieOption{allowlisted},
			form: next("https://app.example.com/home/x"), assert: to("/"),
		},
		{
			name: "allowlist near-miss: host suffix", opts: []httpsec.SessionCookieOption{allowlisted},
			form: next("https://app.example.com.evil/home"), assert: to("/"),
		},
		{
			name: "allowlist near-miss: case", opts: []httpsec.SessionCookieOption{allowlisted},
			form: next("https://APP.example.com/home"), assert: to("/"),
		},
		{
			name: "consumer field name",
			opts: []httpsec.SessionCookieOption{httpsec.WithSessionCookieNextParam("return_to")},
			form: url.Values{"return_to": {"/orders"}, "next": {"/settings"}}, assert: to("/orders"),
		},
		{name: "JSON member", json: map[string]any{"next": "/orders"}, assert: to("/orders")},
		{name: "JSON member off-site", json: map[string]any{"next": "//evil.example"}, assert: to("/")},
		{name: "JSON member not a string", json: map[string]any{"next": []string{"/orders"}}, assert: to("/")},
		{name: "JSON member null", json: map[string]any{"next": nil}, assert: to("/")},
		{
			name: "allowlist entry over http", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("http://app.example.com/home"),
			}, assert: refused,
		},
		{
			name: "allowlist entry relative", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("/home"),
			}, assert: refused,
		},
		{
			name: "allowlist entry with a fragment", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("https://app.example.com/home#top"),
			}, assert: refused,
		},
		{
			name: "allowlist entry with an empty fragment", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("https://app.example.com/home#"),
			}, assert: refused,
		},
		{
			name: "allowlist entry with userinfo", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("https://user@app.example.com/home"),
			}, assert: refused,
		},
		{
			name: "allowlist entry without a host", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("https:///home"),
			}, assert: refused,
		},
		{
			name: "allowlist entry opaque", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("https:app.example.com"),
			}, assert: refused,
		},
		{
			name: "allowlist entry empty", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects(""),
			}, assert: refused,
		},
		{
			name: "allowlist entry with a control character", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieRedirects("https://app.example.com/ho\tme"),
			}, assert: refused,
		},
		{
			name: "empty field name", opts: []httpsec.SessionCookieOption{
				httpsec.WithSessionCookieNextParam(""),
			}, assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)
			w.cookieOpts = tc.opts

			if err := w.tryBuild(t); err != nil {
				tc.assert(t, w, served{}, err)

				return
			}

			var out served

			switch {
			case tc.request != nil:
				out = serve(t, w.chain, tc.request(t, w))
			case tc.json != nil:
				out = serve(t, w.chain, browserRequest(t, httpsec.DefaultLoginPath, "application/json",
					loginJSON(t, tc.json), "", "text/html"))
			default:
				values := url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				}
				for k, v := range tc.form {
					values[k] = v
				}

				out = w.post(t.Context(), t, httpsec.DefaultLoginPath, "", values)
			}

			tc.assert(t, w, out, nil)
		})
	}
}
