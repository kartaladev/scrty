package httpsec_test

import (
	"bytes"
	"io"
	"math"
	"mime/multipart"
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
		{
			// The posted form wins over the same field in the query, on every
			// adapter the library provides.
			name: "a URL-encoded posted field wins over the same field in the query",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?x=query",
					strings.NewReader("x=body"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "body", r.FormValue("x"))
			},
		},
		{
			// net/http's own FormValue appends the posted form's values after the
			// query's, so this is the row that would catch a regression back to
			// that order for a multipart body.
			name: "a multipart posted field wins over the same field in the query",
			build: func(t *testing.T) *http.Request {
				body, contentType := multipartField(t, "x", "body")
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?x=query",
					strings.NewReader(body))
				req.Header.Set("Content-Type", contentType)
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "body", r.FormValue("x"))
			},
		},
		{
			name: "a field only in the query is read",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?x=query", nil)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "query", r.FormValue("x"))
			},
		},
		{
			// A posted field present with an empty value still counts as present,
			// so it must answer the same as fiber's own FormValue, which returns
			// the empty posted value rather than falling through to the query.
			name: "an empty posted value still wins over a non-empty query value, matching fiber",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?x=query",
					strings.NewReader("x="))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Empty(t, r.FormValue("x"))
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

// TestHTTPRequestFormValueBodyOrder pins that FormValue and Body see the same
// bytes whichever runs first, and that a GET carrying a body still answers
// from the query alone, on either order.
func TestHTTPRequestFormValueBodyOrder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) *http.Request
		assert func(t *testing.T, r httpsec.Request)
	}

	cases := []testCase{
		{
			name: "Body after FormValue still reads the full posted body",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login",
					strings.NewReader("x=body"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "body", r.FormValue("x"))

				body, err := r.Body(64 << 10)
				require.NoError(t, err)
				assert.Equal(t, "x=body", string(body))
			},
		},
		{
			name: "FormValue after Body still reads the posted field",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login",
					strings.NewReader("x=body"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				body, err := r.Body(64 << 10)
				require.NoError(t, err)
				assert.Equal(t, "x=body", string(body))

				assert.Equal(t, "body", r.FormValue("x"))
			},
		},
		{
			name: "a GET with a body reads the query, and the body stays readable",
			build: func(t *testing.T) *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login?x=query",
					strings.NewReader("x=body"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "query", r.FormValue("x"))

				body, err := r.Body(64 << 10)
				require.NoError(t, err)
				assert.Equal(t, "x=body", string(body))
			},
		},
		{
			name: "multipart FormValue after Body still reads the posted field",
			build: func(t *testing.T) *http.Request {
				body, contentType := multipartField(t, "x", "body")
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(body))
				req.Header.Set("Content-Type", contentType)
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				b, err := r.Body(64 << 10)
				require.NoError(t, err)
				assert.NotEmpty(t, b)

				assert.Equal(t, "body", r.FormValue("x"))
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

// TestHTTPRequestFormValueEdges holds the rows on which the adapters once
// disagreed, or on which a field read once changed what a later body read
// sees. fibersec's TestFiberRequestFormValueEdges carries the same rows with
// the same answers: a row changed here is changed there.
func TestHTTPRequestFormValueEdges(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func() (body, contentType string)
		act     func(r httpsec.Request) formRead
		assert  func(t *testing.T, got formRead)
	}

	cases := []testCase{
		{
			name:    "an upper-case form media type is a form",
			request: fixedBody("x=body", "APPLICATION/X-WWW-FORM-URLENCODED"),
			act:     readFieldX,
			assert:  answers("body"),
		},
		{
			name:    "a form media type with parameters is a form",
			request: fixedBody("x=body", "application/x-www-form-urlencoded; charset=UTF-8"),
			act:     readFieldX,
			assert:  answers("body"),
		},
		{
			name:    "a media type that only begins with the form's is not a form",
			request: fixedBody("x=body", "application/x-www-form-urlencodedX"),
			act:     readFieldX,
			assert:  answers("query"),
		},
		{
			name:    "a content type that does not parse is not a form",
			request: fixedBody("x=body", "application/x-www-form-urlencoded; bad"),
			act:     readFieldX,
			assert:  answers("query"),
		},
		{
			name:    "a malformed escape in the field answers the query",
			request: fixedBody("x=%zz", "application/x-www-form-urlencoded"),
			act:     readFieldX,
			assert:  answers("query"),
		},
		{
			name:    "a malformed escape anywhere in the body answers the query",
			request: fixedBody("y=%zz&x=body", "application/x-www-form-urlencoded"),
			act:     readFieldX,
			assert:  answers("query"),
		},
		{
			name:    "a semicolon separator answers the query",
			request: fixedBody("x=body;y=1", "application/x-www-form-urlencoded"),
			act:     readFieldX,
			assert:  answers("query"),
		},
		{
			name: "an upper-case multipart media type is a form",
			request: func() (string, string) {
				body, contentType := multipartBody("x", "body", 0)
				return body, strings.Replace(contentType, "multipart/form-data", "MULTIPART/FORM-DATA", 1)
			},
			act:    readFieldX,
			assert: answers("body"),
		},
		{
			name: "a multipart body without a boundary answers the query",
			request: func() (string, string) {
				body, _ := multipartBody("x", "body", 0)
				return body, "multipart/form-data"
			},
			act:    readFieldX,
			assert: answers("query"),
		},
		{
			name:    "a field read after a refused body read still reads the field",
			request: fixedBody("x=body&pad=aaaaaaaaaa", "application/x-www-form-urlencoded"),
			act: func(r httpsec.Request) formRead {
				_, err := r.Body(8)
				return formRead{value: r.FormValue("x"), bodyErr: err}
			},
			assert: func(t *testing.T, got formRead) {
				require.ErrorIs(t, got.bodyErr, httpsec.ErrRequestTooLarge)
				assert.Equal(t, "body", got.value)
			},
		},
		{
			name:    "a field read does not widen a later body limit",
			request: fixedBody("x=body&pad="+strings.Repeat("a", 8<<10), "application/x-www-form-urlencoded"),
			act:     fieldThenBody(4 << 10),
			assert: func(t *testing.T, got formRead) {
				assert.Equal(t, "body", got.value)
				require.ErrorIs(t, got.bodyErr, httpsec.ErrRequestTooLarge)
				assert.Empty(t, got.body)
			},
		},
		{
			name:    "a larger body read then a smaller one is refused",
			request: fixedBody("x=body&pad="+strings.Repeat("a", 8<<10), "application/x-www-form-urlencoded"),
			act:     bodyTwice(false, 64<<10, 4<<10),
			assert: func(t *testing.T, got formRead) {
				require.NoError(t, got.firstBodyErr)
				require.ErrorIs(t, got.bodyErr, httpsec.ErrRequestTooLarge)
				assert.Empty(t, got.body)
			},
		},
		{
			name:    "a refused smaller body read then a larger one is read",
			request: fixedBody("x=body&pad=aaaaaaaaaa", "application/x-www-form-urlencoded"),
			act:     bodyTwice(false, 8, 1<<20),
			assert: func(t *testing.T, got formRead) {
				require.ErrorIs(t, got.firstBodyErr, httpsec.ErrRequestTooLarge)
				require.NoError(t, got.bodyErr)
				assert.Equal(t, "x=body&pad=aaaaaaaaaa", string(got.body))
			},
		},
		{
			name:    "a field read, a larger body read, then a smaller one is refused",
			request: fixedBody("x=body&pad="+strings.Repeat("a", 8<<10), "application/x-www-form-urlencoded"),
			act:     bodyTwice(true, 64<<10, 4<<10),
			assert: func(t *testing.T, got formRead) {
				assert.Equal(t, "body", got.value)
				require.NoError(t, got.firstBodyErr)
				require.ErrorIs(t, got.bodyErr, httpsec.ErrRequestTooLarge)
				assert.Empty(t, got.body)
			},
		},
		{
			name:    "a URL-encoded body of exactly 10 MiB is read",
			request: fixedBody(paddedForm(10<<20), "application/x-www-form-urlencoded"),
			act:     fieldThenBody(64 << 20),
			assert: func(t *testing.T, got formRead) {
				assert.Equal(t, "body", got.value)
				require.NoError(t, got.bodyErr)
				assert.Len(t, got.body, 10<<20)
			},
		},
		{
			name:    "a URL-encoded body over 10 MiB answers the query and stays whole",
			request: fixedBody(paddedForm(10<<20+1), "application/x-www-form-urlencoded"),
			act:     fieldThenBody(64 << 20),
			assert: func(t *testing.T, got formRead) {
				assert.Equal(t, "query", got.value)
				require.NoError(t, got.bodyErr)
				assert.Len(t, got.body, 10<<20+1)
			},
		},
		{
			name: "a multipart body over 32 MiB answers the query and stays whole",
			request: func() (string, string) {
				return multipartBody("x", "body", 32<<20)
			},
			act: fieldThenBody(64 << 20),
			assert: func(t *testing.T, got formRead) {
				assert.Equal(t, "query", got.value)
				require.NoError(t, got.bodyErr)
				assert.Greater(t, len(got.body), 32<<20)
				assert.True(t, bytes.HasSuffix(got.body, []byte("--\r\n")), "the upload's closing boundary was read")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body, contentType := tc.request()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/form?x=query", strings.NewReader(body))
			req.Header.Set("Content-Type", contentType)

			tc.assert(t, tc.act(httpsec.NewHTTPRequest(req)))
		})
	}
}

// TestHTTPRequestFormValueReadCap pins how far a field read reads a body over
// its form cap. The rows are net/http's alone: the fiber adapter holds the
// body in memory before the chain runs, so it has no read to count.
func TestHTTPRequestFormValueReadCap(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func() (body, contentType string)
		assert  func(t *testing.T, value string, read int64)
	}

	cases := []testCase{
		{
			name:    "a URL-encoded body over 10 MiB is read no further than 10 MiB and one byte",
			request: fixedBody(paddedForm(11<<20), "application/x-www-form-urlencoded"),
			assert: func(t *testing.T, value string, read int64) {
				assert.Equal(t, "query", value)
				assert.LessOrEqual(t, read, int64(10<<20+1))
			},
		},
		{
			name: "a multipart body over 32 MiB is read no further than 32 MiB and one byte",
			request: func() (string, string) {
				return multipartBody("x", "body", 33<<20)
			},
			assert: func(t *testing.T, value string, read int64) {
				assert.Equal(t, "query", value)
				assert.LessOrEqual(t, read, int64(32<<20+1))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body, contentType := tc.request()
			counter := &countingReader{r: strings.NewReader(body)}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/form?x=query", counter)
			req.Header.Set("Content-Type", contentType)

			value := httpsec.NewHTTPRequest(req).FormValue("x")
			tc.assert(t, value, counter.n.Load())
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
			name: "a refusal leaves the whole body for the handler",
			body: strings.Repeat("a", 65),
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				_, err := r.Body(64)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)

				rest, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, strings.Repeat("a", 65), string(rest))
			},
		},
		{
			name: "each call judges its own limit, and the handler still reads the whole body",
			body: strings.Repeat("a", 65),
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				_, err := r.Body(64)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)

				b, err := r.Body(1 << 20)
				require.NoError(t, err)
				assert.Equal(t, strings.Repeat("a", 65), string(b))

				_, err = r.Body(64)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)

				rest, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, strings.Repeat("a", 65), string(rest))
			},
		},
		{
			name: "closing the body after a read closes the original body",
			body: "hello",
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				original := &closeRecorder{Reader: strings.NewReader("hello")}
				req.Body = original

				_, err := r.Body(64)
				require.NoError(t, err)

				require.NoError(t, req.Body.Close())
				assert.True(t, original.closed, "the original body was closed")
			},
		},
		{
			name: "a truncated body is refused on every read",
			body: "code=12",
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				original := &closeRecorder{Reader: &truncatedBody{data: []byte("code=12")}}
				req.Body = original

				b, err := r.Body(64)
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				assert.Empty(t, b)

				b, err = r.Body(64)
				require.ErrorIs(t, err, io.ErrUnexpectedEOF, "the partial body must not be accepted as complete")
				assert.Empty(t, b)

				assert.Equal(t, "", r.FormValue("code"), "no field is read from a partial body")

				rest, err := io.ReadAll(req.Body)
				require.ErrorIs(t, err, io.ErrUnexpectedEOF, "the handler sees the transport failure too")
				assert.Equal(t, "code=12", string(rest), "the handler gets the bytes that arrived before the failure")

				require.NoError(t, req.Body.Close())
				assert.True(t, original.closed, "closing the body after a transport failure closes the original body")
			},
		},
		{
			name: "a limit at the largest integer reads the whole body",
			body: "hello",
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				b, err := r.Body(math.MaxInt64)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(b))

				rest, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(rest))
			},
		},
		{
			name: "the returned bytes are a copy",
			body: "hello",
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				b, err := r.Body(64)
				require.NoError(t, err)
				b[0] = 'X'

				again, err := r.Body(64)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(again))

				rest, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.Equal(t, "hello", string(rest))
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

// multipartField builds a one-field multipart body and the content type that
// names its boundary.
func multipartField(t *testing.T, name, value string) (body, contentType string) {
	t.Helper()

	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	require.NoError(t, w.WriteField(name, value))
	require.NoError(t, w.Close())

	return buf.String(), w.FormDataContentType()
}

// formRead is what one edge row read through the abstraction. It is recorded
// inside the request and asserted after it, so the same rows run unchanged on
// an adapter whose request is released when the request ends.
type formRead struct {
	value        string
	body         []byte
	bodyErr      error
	firstBodyErr error
}

// bodyTwice reads field "x" when readField is set, then the body under first,
// then under second, and reports the second read with the first's error.
func bodyTwice(readField bool, first, second int64) func(r httpsec.Request) formRead {
	return func(r httpsec.Request) formRead {
		var value string
		if readField {
			value = r.FormValue("x")
		}

		_, firstErr := r.Body(first)
		body, err := r.Body(second)

		return formRead{value: value, body: body, bodyErr: err, firstBodyErr: firstErr}
	}
}

// readFieldX reads field "x" and nothing else.
func readFieldX(r httpsec.Request) formRead { return formRead{value: r.FormValue("x")} }

// fieldThenBody reads field "x", then the body under limit.
func fieldThenBody(limit int64) func(r httpsec.Request) formRead {
	return func(r httpsec.Request) formRead {
		value := r.FormValue("x")
		body, err := r.Body(limit)

		return formRead{value: value, body: body, bodyErr: err}
	}
}

// answers asserts the field read answered want.
func answers(want string) func(t *testing.T, got formRead) {
	return func(t *testing.T, got formRead) {
		t.Helper()
		assert.Equal(t, want, got.value)
	}
}

// fixedBody is a request body and content type given as they are.
func fixedBody(body, contentType string) func() (string, string) {
	return func() (string, string) { return body, contentType }
}

// paddedForm is a URL-encoded body of exactly size bytes whose first field is
// x=body.
func paddedForm(size int) string {
	const head = "x=body&pad="

	return head + strings.Repeat("a", size-len(head))
}

// multipartBody is a multipart body carrying field name=value and, when
// fileSize is positive, a file part of fileSize bytes after it.
func multipartBody(name, value string, fileSize int) (body, contentType string) {
	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	if err := w.WriteField(name, value); err != nil {
		panic(err)
	}

	if fileSize > 0 {
		part, err := w.CreateFormFile("upload", "upload.bin")
		if err != nil {
			panic(err)
		}

		if _, err := part.Write(bytes.Repeat([]byte("a"), fileSize)); err != nil {
			panic(err)
		}
	}

	if err := w.Close(); err != nil {
		panic(err)
	}

	return buf.String(), w.FormDataContentType()
}

// closeRecorder is a request body that records whether it was closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true

	return nil
}

// truncatedBody reports an early end of body the way net/http's request body
// does: the bytes that arrived, then io.ErrUnexpectedEOF once, then io.EOF on
// every later read.
type truncatedBody struct {
	data     []byte
	reported bool
}

func (b *truncatedBody) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]

		return n, nil
	}

	if !b.reported {
		b.reported = true

		return 0, io.ErrUnexpectedEOF
	}

	return 0, io.EOF
}
