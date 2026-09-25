package httpsec_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

func TestHTTPRequest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) *http.Request
		assert func(t *testing.T, r httpsec.Request)
	}

	cases := []testCase{
		{
			name: "method, path, header and query",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?next=/home", nil)
				req.Header.Set("Authorization", "Bearer abc")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, http.MethodPost, r.Method())
				assert.Equal(t, "/login", r.Path())
				assert.Equal(t, "Bearer abc", r.Header("Authorization"))
				assert.Equal(t, "/home", r.Query("next"))
			},
		},
		{
			name: "every value of a repeated query parameter, in order",
			build: func(t *testing.T) *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/cb?state=a&code=c&state=b", nil)
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, []string{"a", "b"}, r.QueryValues("state"))
				assert.Equal(t, []string{"c"}, r.QueryValues("code"))
				assert.Nil(t, r.QueryValues("error"), "an absent parameter has no values")
			},
		},
		{
			name: "a present cookie is reported present",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{
					Name: "sid", Value: "abc",
					HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
				})
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				v, ok := r.Cookie("sid")
				assert.True(t, ok)
				assert.Equal(t, "abc", v)
			},
		},
		{
			name: "absent cookie is reported absent, not empty",
			build: func(t *testing.T) *http.Request {
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			},
			assert: func(t *testing.T, r httpsec.Request) {
				v, ok := r.Cookie("sid")
				assert.False(t, ok)
				assert.Empty(t, v)
			},
		},
		{
			name: "form value",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login",
					strings.NewReader("username=alice&password=s3cret"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "alice", r.FormValue("username"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, httpsec.NewHTTPRequest(tc.build(t)))
		})
	}
}

func TestHTTPRequestClientIP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) *http.Request
		assert func(t *testing.T, r httpsec.Request)
	}

	cases := []testCase{
		{
			name: "peer host is the client address and the forwarding header is ignored",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.RemoteAddr = "198.51.100.7:51234"
				req.Header.Set("X-Forwarded-For", "203.0.113.9")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "198.51.100.7", r.ClientIP())
			},
		},
		{
			name: "X-Real-IP is ignored too",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.RemoteAddr = "198.51.100.7:51234"
				req.Header.Set("X-Real-Ip", "203.0.113.9")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "198.51.100.7", r.ClientIP())
			},
		},
		{
			name: "peer without a port yields no client address",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.RemoteAddr = "@"
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Empty(t, r.ClientIP())
			},
		},
		{
			name: "IPv6 peer keeps its host only",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				req.RemoteAddr = "[2001:db8::1]:443"
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "2001:db8::1", r.ClientIP())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, httpsec.NewHTTPRequest(tc.build(t)))
		})
	}
}

func TestHTTPRequestBody(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		body   string
		assert func(t *testing.T, req *http.Request, r httpsec.Request)
	}

	cases := []testCase{
		{
			name: "within the limit and readable twice",
			body: `{"username":"alice"}`,
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				first, err := r.Body(64 << 10)
				require.NoError(t, err)
				assert.JSONEq(t, `{"username":"alice"}`, string(first))

				// The downstream handler must still see the body.
				rest, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{"username":"alice"}`, string(rest))
			},
		},
		{
			name: "one byte over the limit is refused unparsed",
			body: strings.Repeat("a", 65),
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				b, err := r.Body(64)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)
				assert.Empty(t, b)
			},
		},
		{
			name: "exactly at the limit is accepted",
			body: strings.Repeat("a", 64),
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				b, err := r.Body(64)
				require.NoError(t, err)
				assert.Len(t, b, 64)
			},
		},
		{
			name: "buffered once: a second call does not re-read",
			body: "hello",
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				first, err := r.Body(64)
				require.NoError(t, err)
				second, err := r.Body(64)
				require.NoError(t, err)
				assert.Equal(t, first, second)
				assert.Equal(t, "hello", string(second))
			},
		},
		{
			name: "the refusal is remembered, so a second call does not let an oversized body through",
			body: strings.Repeat("a", 65),
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				_, err := r.Body(64)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)

				b, err := r.Body(1 << 20)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)
				assert.Empty(t, b)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(tc.body))
			tc.assert(t, req, httpsec.NewHTTPRequest(req))
		})
	}
}

func TestHTTPResponseWriter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(w httpsec.ResponseWriter)
		assert func(t *testing.T, rec *httptest.ResponseRecorder, w httpsec.ResponseWriter)
	}

	cases := []testCase{
		{
			name: "header and status",
			act: func(w httpsec.ResponseWriter) {
				w.SetHeader("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, _ httpsec.ResponseWriter) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Equal(t, `Basic realm="Restricted"`, rec.Header().Get("WWW-Authenticate"))
				assert.Empty(t, rec.Body.String())
			},
		},
		{
			name: "body",
			act: func(w httpsec.ResponseWriter) {
				w.SetHeader("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"t"}`))
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, _ httpsec.ResponseWriter) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
				assert.JSONEq(t, `{"access_token":"t"}`, rec.Body.String())
			},
		},
		{
			name: "cookie",
			act: func(w httpsec.ResponseWriter) {
				w.SetCookie(&httpsec.Cookie{Name: "sid", Value: "abc", HttpOnly: true})
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, _ httpsec.ResponseWriter) {
				assert.Contains(t, rec.Header().Get("Set-Cookie"), "sid=abc")
				assert.Contains(t, rec.Header().Get("Set-Cookie"), "HttpOnly")
			},
		},
		{
			name: "a second status does not overwrite the first",
			act: func(w httpsec.ResponseWriter) {
				w.WriteHeader(http.StatusUnauthorized)
				w.WriteHeader(http.StatusInternalServerError)
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, _ httpsec.ResponseWriter) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
			},
		},
		{
			name: "nothing written is not committed",
			act:  func(httpsec.ResponseWriter) {},
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, w httpsec.ResponseWriter) {
				assert.False(t, httpsec.Committed(w))
			},
		},
		{
			name: "a status commits the response",
			act:  func(w httpsec.ResponseWriter) { w.WriteHeader(http.StatusNoContent) },
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, w httpsec.ResponseWriter) {
				assert.True(t, httpsec.Committed(w))
			},
		},
		{
			name: "a body commits the response even with no explicit status",
			act:  func(w httpsec.ResponseWriter) { _, _ = w.Write([]byte("hi")) },
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, w httpsec.ResponseWriter) {
				assert.True(t, httpsec.Committed(w))
			},
		},
		{
			name: "a header alone does not commit the response",
			act:  func(w httpsec.ResponseWriter) { w.SetHeader("WWW-Authenticate", "Basic") },
			assert: func(t *testing.T, _ *httptest.ResponseRecorder, w httpsec.ResponseWriter) {
				assert.False(t, httpsec.Committed(w))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			w := httpsec.NewHTTPResponseWriter(rec)
			tc.act(w)
			tc.assert(t, rec, w)
		})
	}
}
