package httpsec_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// TestMagicLinkRequestEndpoint pins that asking for a link tells the caller
// nothing. Every body shape — a known address, an unknown one, none at all, a
// JSON document and two that do not parse — has to produce the same status,
// the same body and a cookie with the same attributes, because any difference
// between them is a way to ask whether an address has an account.
//
// The cases are not parallel: each is compared against the first, which is the
// baseline the uniformity is measured from.
func TestMagicLinkRequestEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		body func() (contentType string, body io.Reader)
	}

	form := func(values url.Values) func() (string, io.Reader) {
		return func() (string, io.Reader) {
			return "application/x-www-form-urlencoded", strings.NewReader(values.Encode())
		}
	}

	cases := []testCase{
		{
			name: "a known address",
			body: form(url.Values{"email": {magicLinkKnown}, "next": {"/dashboard"}}),
		},
		{name: "an unknown address", body: form(url.Values{"email": {magicLinkUnknown}})},
		{name: "no address at all", body: form(url.Values{})},
		{
			name: "a JSON body",
			body: func() (string, io.Reader) {
				return "application/json",
					strings.NewReader(`{"email":"` + magicLinkKnown + `","next":"/dashboard"}`)
			},
		},
		{
			name: "an unparsable body",
			body: func() (string, io.Reader) {
				return "application/json", strings.NewReader(`{{{not json`)
			},
		},
		{
			name: "an unparsable form body",
			body: func() (string, io.Reader) {
				return "application/x-www-form-urlencoded", strings.NewReader("%%%")
			},
		},
	}

	type answer struct {
		status int
		body   string
		cookie *http.Cookie
	}

	var baseline answer

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMagicLinkHarness(t)

			contentType, body := tc.body()
			out := serve(t, h.chain(t),
				postBody(t.Context(), httpsec.DefaultMagicLinkRequestPath, contentType, body))

			require.NoError(t, out.err)
			assert.False(t, out.handlerRan,
				"the request endpoint is this library's own, so the application never sees it")
			assert.Equal(t, http.StatusAccepted, out.rec.Code)

			cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName)
			require.NotNil(t, cookie, "the cookie is set whatever the outcome")

			got := answer{status: out.rec.Code, body: out.rec.Body.String(), cookie: cookie}

			if i == 0 {
				baseline = got

				return
			}

			assert.Equal(t, baseline.status, got.status)
			assert.Equal(t, baseline.body, got.body)
			assert.Equal(t, baseline.cookie.Name, got.cookie.Name)
			assert.Equal(t, baseline.cookie.Path, got.cookie.Path)
			assert.Equal(t, baseline.cookie.MaxAge, got.cookie.MaxAge)
			assert.Equal(t, baseline.cookie.HttpOnly, got.cookie.HttpOnly)
			assert.Equal(t, baseline.cookie.Secure, got.cookie.Secure)
			assert.Equal(t, baseline.cookie.SameSite, got.cookie.SameSite)
			assert.Len(t, got.cookie.Value, len(baseline.cookie.Value),
				"a decoy is the same shape as the real thing")
		})
	}
}

// TestMagicLinkRequestMethodAndPath pins that only a POST on the request path
// is a link request. Everything else is the application's.
func TestMagicLinkRequestMethodAndPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func(ctx context.Context) *http.Request
	}

	cases := []testCase{
		{
			name: "a GET on the request path",
			request: func(ctx context.Context) *http.Request {
				return getFrom(ctx, httpsec.DefaultMagicLinkRequestPath, magicLinkSource)
			},
		},
		{
			name: "a POST on another path",
			request: func(ctx context.Context) *http.Request {
				return postValues(ctx, "/orders", magicLinkSource,
					url.Values{"email": {magicLinkKnown}})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)

			out := serve(t, h.chain(t), tc.request(t.Context()))

			require.NoError(t, out.err)
			assert.True(t, out.handlerRan, "the request continues to the application untouched")
			assert.Zero(t, h.sender.count(), "and no link is sent")
			assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultBindingCookieName))
		})
	}
}

// TestBindingCookieIsConstant pins the cookie's attributes and that its
// presence says nothing. A response that carries a cookie only when a link went
// out would answer the question the whole endpoint refuses to answer.
func TestBindingCookieIsConstant(t *testing.T) {
	t.Parallel()

	h := newMagicLinkHarness(t)
	c := h.chain(t)

	known := h.requestLink(t, c, magicLinkKnown)
	unknown := h.requestLink(t, c, magicLinkUnknown)

	require.NoError(t, known.err)
	require.NoError(t, unknown.err)

	a := cookieNamed(known.rec, httpsec.DefaultBindingCookieName)
	b := cookieNamed(unknown.rec, httpsec.DefaultBindingCookieName)

	require.NotNil(t, a)
	require.NotNil(t, b)

	assert.Equal(t, a.Name, b.Name)
	assert.Len(t, b.Value, len(a.Value))
	assert.NotEqual(t, a.Value, b.Value, "the decoy is random, not a fixed string")

	assert.True(t, a.HttpOnly, "script cannot read the binding")
	assert.True(t, a.Secure)
	assert.Equal(t, http.SameSiteLaxMode, a.SameSite)
	assert.Equal(t, httpsec.DefaultMagicLinkConsumePath, a.Path,
		"the cookie is scoped to the redemption endpoint")
	assert.Equal(t, int(magicLinkTTL/time.Second), a.MaxAge,
		"the lifetime comes from configuration, never from the result")
}
