package fibersec_test

// The tests in this file do not share one table. TestFiberExchange drives the
// accessors through a whole chain, because that is how an interceptor reads
// them; TestFiberRequestBodyCopy and TestFiberBuildsNoHTTPRequest each need a
// setup of their own — a bare fiber handler holding the context, and the
// package's own source — so folding them in would hide what they check.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/httpsec"
)

// loginBodyLimit is the bound the body rows judge against. It is small so a
// row can be one byte either side of it without carrying a fixture.
const loginBodyLimit int64 = 32

// observed is everything an interceptor read through the abstraction.
//
// It is recorded inside the request and asserted after it, because fiber
// recycles its context the moment the request ends: an accessor called later
// reads a released buffer, and testify must not fail a test from fiber's own
// goroutine.
type observed struct {
	method   string
	path     string
	header   string
	query    string
	states   []string
	errors   []string
	form     string
	clientIP string

	cookie      string
	cookieFound bool

	body    []byte
	bodyErr error
}

// observe reads every accessor once, so one interceptor serves every row.
func observe(r httpsec.Request, limit int64) observed {
	cookie, found := r.Cookie("sid")
	body, bodyErr := r.Body(limit)

	return observed{
		method:      r.Method(),
		path:        r.Path(),
		header:      r.Header("Authorization"),
		query:       r.Query("next"),
		states:      r.QueryValues("state"),
		errors:      r.QueryValues("error"),
		form:        r.FormValue("username"),
		clientIP:    r.ClientIP(),
		cookie:      cookie,
		cookieFound: found,
		body:        body,
		bodyErr:     bodyErr,
	}
}

// TestFiberExchange pins what an interceptor reads when the chain runs on
// fiber: every accessor answers what the client sent, and the body is bounded
// by the caller's limit rather than by whatever fiber already buffered.
func TestFiberExchange(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, got observed)
	}

	cases := []testCase{
		{
			name: "method, path, header and query",
			request: func(ctx context.Context) *http.Request {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login?next=/home", nil)
				req.Header.Set("Authorization", "Bearer abc")

				return req
			},
			assert: func(t *testing.T, got observed) {
				assert.Equal(t, http.MethodPost, got.method)
				assert.Equal(t, "/login", got.path)
				assert.Equal(t, "Bearer abc", got.header)
				assert.Equal(t, "/home", got.query)
			},
		},
		{
			name: "the path is decoded as net/http decodes it, an encoded slash included",
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/authorization/corp%2F..", nil)
			},
			assert: func(t *testing.T, got observed) {
				assert.Equal(t, "/oauth2/authorization/corp/..", got.path)
			},
		},
		{
			name: "a plus sign stays a plus and an encoded space decodes, as in net/http",
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/a+b/c%20d", nil)
			},
			assert: func(t *testing.T, got observed) {
				assert.Equal(t, "/a+b/c d", got.path)
			},
		},
		{
			name: "every value of a repeated query parameter, in order",
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/login?state=a&next=/home&state=b", nil)
			},
			assert: func(t *testing.T, got observed) {
				assert.Equal(t, []string{"a", "b"}, got.states)
				assert.Nil(t, got.errors, "an absent parameter has no values")
			},
		},
		{
			name: "a cookie the client sent",
			request: func(ctx context.Context) *http.Request {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", nil)
				req.Header.Set("Cookie", "sid=abc")

				return req
			},
			assert: func(t *testing.T, got observed) {
				assert.True(t, got.cookieFound)
				assert.Equal(t, "abc", got.cookie)
			},
		},
		{
			name: "a cookie nobody sent is absent",
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", nil)
			},
			assert: func(t *testing.T, got observed) {
				assert.False(t, got.cookieFound)
				assert.Empty(t, got.cookie)
			},
		},
		{
			name: "a submitted form field",
			request: func(ctx context.Context) *http.Request {
				return bodyRequest(ctx, "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, got observed) {
				assert.Equal(t, "ada", got.form)
			},
		},
		{
			name: "a body at the limit is accepted",
			request: func(ctx context.Context) *http.Request {
				return bodyRequest(ctx, strings.Repeat("a", int(loginBodyLimit)))
			},
			assert: func(t *testing.T, got observed) {
				require.NoError(t, got.bodyErr)
				assert.Len(t, got.body, int(loginBodyLimit))
			},
		},
		{
			name: "one byte over the limit is refused unparsed",
			request: func(ctx context.Context) *http.Request {
				return bodyRequest(ctx, strings.Repeat("a", int(loginBodyLimit)+1))
			},
			assert: func(t *testing.T, got observed) {
				require.ErrorIs(t, got.bodyErr, httpsec.ErrRequestTooLarge)
				assert.Empty(t, got.body, "nothing over the bound is handed back to be parsed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				got  observed
				read bool
			)

			app := fiber.New()
			app.Use(fibersec.Middleware(newChain(t,
				httpsec.RegisterInterceptor(
					inspecting(func(r httpsec.Request) {
						got, read = observe(r, loginBodyLimit), true
					}),
					httpsec.OrderBearerToken))))
			app.All("/*", func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusNoContent) })

			res := serve(t, app, tc.request(t.Context()))
			require.Equal(t, http.StatusNoContent, res.status,
				"the chain passed the request through to the route")
			require.True(t, read, "the chain handed an interceptor its own request")

			tc.assert(t, got)
		})
	}
}

// TestFiberRequestBodyCopy pins that the body leaves the adapter copied.
//
// fiber's accessors are zero-copy into the buffer fasthttp reuses, so a slice
// returned as it came aliases memory the next request writes over. The check is
// direct rather than a race against the pool: the test writes into fiber's own
// buffer and reads the value the adapter already handed out.
func TestFiberRequestBodyCopy(t *testing.T) {
	t.Parallel()

	// Everything the fiber handler observes is recorded and asserted out here:
	// a failed assertion inside it would stop fiber's own goroutine rather than
	// the test.
	var (
		handed  []byte
		bodyErr error
		rawLen  int
		rawHead byte
	)

	app := fiber.New()
	app.Post("/login", func(fc fiber.Ctx) error {
		handed, bodyErr = fibersec.NewRequest(fc).Body(loginBodyLimit)

		// fiber's own buffer, which every accessor hands out a view of.
		raw := fc.Body()
		if rawLen = len(raw); rawLen > 0 {
			raw[0] = 'X'
			rawHead = raw[0]
		}

		return fc.SendStatus(http.StatusNoContent)
	})

	res := serve(t, app, bodyRequest(t.Context(), "hello"))
	require.Equal(t, http.StatusNoContent, res.status)
	require.NoError(t, bodyErr)
	require.Equal(t, len("hello"), rawLen)
	require.Equal(t, byte('X'), rawHead, "the test wrote into the buffer it meant to")

	assert.Equal(t, "hello", string(handed),
		"the body the adapter returned must not alias the buffer fiber reuses")
}

// TestFiberBuildsNoHTTPRequest pins the spec's "fiber without conversion": a
// secured request is judged over fiber's own context, and nothing in the
// package turns it into a net/http request first.
func TestFiberBuildsNoHTTPRequest(t *testing.T) {
	t.Parallel()

	t.Run("the request the chain judges holds no net/http request", func(t *testing.T) {
		t.Parallel()

		var seen reflect.Type

		app := fiber.New()
		app.Use(fibersec.Middleware(newChain(t,
			httpsec.RegisterInterceptor(
				inspecting(func(r httpsec.Request) { seen = reflect.TypeOf(r) }),
				httpsec.OrderBearerToken))))
		app.Get("/*", func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusNoContent) })

		res := serve(t, app, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))
		require.Equal(t, http.StatusNoContent, res.status)
		require.NotNil(t, seen, "the chain handed an interceptor its own request")

		assertNoHTTPRequest(t, seen, 0)
	})

	t.Run("no source file converts a request", func(t *testing.T) {
		t.Parallel()

		// adaptor is fiber's net/http bridge, and ConvertRequest is the call
		// that would allocate and copy every header and the whole body on every
		// secured request. Nothing in this package may import it.
		for _, file := range packageSources(t) {
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				require.NoError(t, err)

				assert.NotContains(t, path, "middleware/adaptor",
					"the fiber integration converts no request into a net/http one")
			}
		}
	})
}

// assertNoHTTPRequest walks t's structure and fails on a net/http request held
// anywhere inside it.
//
// It walks types rather than values, so it reaches unexported fields without
// reflecting on memory, and it stops at interfaces and at a small depth: the
// adapter is a struct over one fiber context, and anything deeper than this is
// already not the shape this test is about.
func assertNoHTTPRequest(t *testing.T, typ reflect.Type, depth int) {
	t.Helper()

	if typ == nil || depth > 4 {
		return
	}

	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	assert.NotEqual(t, reflect.TypeOf(http.Request{}), typ,
		"a net/http request was built for a request served through fiber")

	if typ.Kind() != reflect.Struct {
		return
	}

	for i := range typ.NumField() {
		assertNoHTTPRequest(t, typ.Field(i).Type, depth+1)
	}
}

// packageSources parses every non-test Go file of this package.
func packageSources(t *testing.T) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()

	var files []*ast.File

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		require.NoError(t, parseErr)

		files = append(files, file)
	}

	require.NotEmpty(t, files, "the package has source files to check")

	return files
}

// TestFiberResponseWriter pins what an interceptor writes: the header, the
// status and the body reach fiber's response, and a cookie is carried over
// field by field rather than re-derived from fiber's own defaults.
func TestFiberResponseWriter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(w httpsec.ResponseWriter)
		assert func(t *testing.T, res response)
	}

	cases := []testCase{
		{
			name: "header and status",
			act: func(w httpsec.ResponseWriter) {
				w.SetHeader("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusUnauthorized, res.status)
				assert.Equal(t, `Basic realm="Restricted"`, res.header.Get("WWW-Authenticate"))
				assert.Empty(t, res.body)
			},
		},
		{
			name: "body",
			act: func(w httpsec.ResponseWriter) {
				w.SetHeader("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"t"}`))
			},
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusOK, res.status)
				assert.Equal(t, "application/json", res.header.Get("Content-Type"))
				assert.JSONEq(t, `{"access_token":"t"}`, res.body)
			},
		},
		{
			name: "a session cookie keeps its flags and gains no expiry",
			act: func(w httpsec.ResponseWriter) {
				w.SetCookie(&httpsec.Cookie{
					Name: "sid", Value: "abc", Path: "/", HttpOnly: true, Secure: true,
				})
			},
			assert: func(t *testing.T, res response) {
				set := res.header.Get("Set-Cookie")
				assert.Contains(t, set, "sid=abc")
				assert.Contains(t, set, "HttpOnly")
				assert.Contains(t, set, "secure")
				assert.NotContains(t, set, "expires")
				assert.NotContains(t, set, "max-age")
				assert.NotContains(t, strings.ToLower(set), "samesite",
					"a cookie that named no SameSite gets none, as it does on net/http")
			},
		},
		{
			name: "an expiring cookie keeps its bound and its SameSite",
			act: func(w httpsec.ResponseWriter) {
				w.SetCookie(&httpsec.Cookie{
					Name: "sid", Value: "abc", Path: "/", MaxAge: 600,
					Expires:  time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC),
					SameSite: http.SameSiteStrictMode,
				})
			},
			assert: func(t *testing.T, res response) {
				set := strings.ToLower(res.header.Get("Set-Cookie"))
				assert.Contains(t, set, "max-age=600")
				assert.Contains(t, set, "samesite=strict")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New()
			app.Get("/orders", func(fc fiber.Ctx) error {
				tc.act(fibersec.NewResponseWriter(fc))

				return nil
			})

			tc.assert(t, serve(t, app,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)))
		})
	}
}

// bodyRequest is a POST carrying body as a form-encoded document, which is what
// a login submits.
func bodyRequest(ctx context.Context, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}
