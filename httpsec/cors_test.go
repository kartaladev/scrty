package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

const allowedOrigin = "https://app.example.com"

// corsRun is one request through a chain built with CORS.
type corsRun struct {
	rec        *httptest.ResponseRecorder
	handlerRan bool
}

// serveCORS sends req through chain with a handler that records it ran.
func serveCORS(t *testing.T, chain *httpsec.Chain, req *http.Request) corsRun {
	t.Helper()

	var run corsRun

	run.rec = httptest.NewRecorder()
	chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		run.handlerRan = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(run.rec, req)

	return run
}

// corsRequest is a request with method and, when not "", an Origin header.
func corsRequest(t *testing.T, method, origin string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, "/api/orders", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}

	return req
}

func TestCORS_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(t *testing.T, _ *httpsec.Chain, err error) {
		return func(t *testing.T, _ *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)

			for _, n := range names {
				assert.ErrorContains(t, err, n)
			}
		}
	}

	origins := func(o ...string) httpsec.CORSPolicy { return httpsec.CORSPolicy{AllowedOrigins: o} }

	cases := []testCase{
		{
			name: "origin normalised to lower case without the default port",
			opts: []httpsec.Option{httpsec.EnableCORS(origins("HTTPS://App.Example.com:443"))},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				run := serveCORS(t, chain, corsRequest(t, http.MethodGet, allowedOrigin))
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
			},
		},
		{
			name: "http origin normalised without port 80",
			opts: []httpsec.Option{httpsec.EnableCORS(origins("http://App.Example.com:80"))},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)

				run := serveCORS(t, chain, corsRequest(t, http.MethodGet, "http://app.example.com"))
				assert.Equal(t, "http://app.example.com", run.rec.Header().Get("Access-Control-Allow-Origin"))
			},
		},
		{name: "no origin", opts: []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{})}, assert: refused("AllowedOrigins")},
		{name: "null origin", opts: []httpsec.Option{httpsec.EnableCORS(origins("null"))}, assert: refused(`"null"`)},
		{name: "another scheme", opts: []httpsec.Option{httpsec.EnableCORS(origins("ftp://app.example.com"))}, assert: refused(`"ftp://app.example.com"`)},
		{name: "a path", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com/app"))}, assert: refused(`"https://app.example.com/app"`)},
		{name: "a trailing slash", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com/"))}, assert: refused(`"https://app.example.com/"`)},
		{name: "a query", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com?a=1"))}, assert: refused(`"https://app.example.com?a=1"`)},
		{name: "an empty query", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com?"))}, assert: refused(`"https://app.example.com?"`)},
		{name: "a fragment", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com#top"))}, assert: refused(`"https://app.example.com#top"`)},
		{name: "an empty fragment", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com#"))}, assert: refused(`"https://app.example.com#"`)},
		{name: "userinfo", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://user@app.example.com"))}, assert: refused(`"https://user@app.example.com"`)},
		{name: "no host", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://"))}, assert: refused(`"https://"`)},
		{name: "a malformed port", opts: []httpsec.Option{httpsec.EnableCORS(origins("https://app.example.com:x"))}, assert: refused(`"https://app.example.com:x"`)},
		{
			name:   "wildcard with credentials",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{"*"}, AllowCredentials: true})},
			assert: refused("AllowCredentials"),
		},
		{name: "wildcard beside another origin", opts: []httpsec.Option{httpsec.EnableCORS(origins("*", allowedOrigin))}, assert: refused(`"*"`)},
		{
			name:   "a pattern without WithOriginPattern",
			opts:   []httpsec.Option{httpsec.EnableCORS(origins("https://*.example.com"))},
			assert: refused(`"https://*.example.com"`, "WithOriginPattern"),
		},
		{
			name:   "a wildcard inside a label",
			opts:   []httpsec.Option{httpsec.EnableCORS(origins(allowedOrigin), httpsec.WithOriginPattern("https://a*.example.com"))},
			assert: refused(`"https://a*.example.com"`),
		},
		{
			name:   "a wildcard not leftmost",
			opts:   []httpsec.Option{httpsec.EnableCORS(origins(allowedOrigin), httpsec.WithOriginPattern("https://app.*.com"))},
			assert: refused(`"https://app.*.com"`),
		},
		{
			name:   "a pattern with no wildcard",
			opts:   []httpsec.Option{httpsec.EnableCORS(origins(allowedOrigin), httpsec.WithOriginPattern(allowedOrigin))},
			assert: refused(allowedOrigin),
		},
		{
			name:   "a pattern with a path",
			opts:   []httpsec.Option{httpsec.EnableCORS(origins(allowedOrigin), httpsec.WithOriginPattern("https://*.example.com/x"))},
			assert: refused(`"https://*.example.com/x"`),
		},
		{
			name:   "a pattern alone is an allowed origin",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{}, httpsec.WithOriginPattern("https://*.example.com"))},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) { require.NoError(t, err) },
		},
		{
			name:   "a pattern with one label after its wildcard",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{}, httpsec.WithOriginPattern("https://*.com"))},
			assert: refused(`"https://*.com"`, "two labels"),
		},
		{
			name:   "a pattern with one label after its wildcard and a port",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{}, httpsec.WithOriginPattern("http://*.localhost:8080"))},
			assert: refused(`"http://*.localhost:8080"`, "two labels"),
		},
		{
			name:   "a max age below one second",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, MaxAge: 500 * time.Millisecond})},
			assert: refused("MaxAge", "WithoutPreflightCaching"),
		},
		{
			name: "a max age with preflight caching turned off",
			opts: []httpsec.Option{httpsec.EnableCORS(
				httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, MaxAge: time.Hour},
				httpsec.WithoutPreflightCaching(),
			)},
			assert: refused("MaxAge", "WithoutPreflightCaching"),
		},
		{
			name:   "a negative max age",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, MaxAge: -1})},
			assert: refused("MaxAge"),
		},
		{
			name:   "an empty header name",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowedHeaders: []string{""}})},
			assert: refused("AllowedHeaders"),
		},
		{
			name:   "a method that is not a token",
			opts:   []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowedMethods: []string{"GET, PUT"}})},
			assert: refused("AllowedMethods"),
		},
		{
			name: "enabled twice",
			opts: []httpsec.Option{
				httpsec.EnableCORS(origins(allowedOrigin)),
				httpsec.EnableCORS(origins(allowedOrigin)),
			},
			assert: refused("EnableCORS"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts...)
			tc.assert(t, chain, err)
		})
	}
}

// corsHeaderNames are every CORS response header the layer may set.
var corsHeaderNames = []string{
	"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers",
	"Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Max-Age",
}

// assertNoCORS checks h carries no CORS header but Vary: Origin.
func assertNoCORS(t *testing.T, h http.Header) {
	t.Helper()

	for _, n := range corsHeaderNames {
		assert.Empty(t, h.Values(n), n)
	}
}

func TestCORS_Origins(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		policy httpsec.CORSPolicy
		opts   []httpsec.CORSOption
		origin string
		assert func(t *testing.T, run corsRun)
	}

	exact := httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}}
	pattern := []httpsec.CORSOption{httpsec.WithOriginPattern("https://*.example.com")}
	notAllowed := func(t *testing.T, run corsRun) {
		assert.True(t, run.handlerRan, "a request from another origin is otherwise unaffected")
		assert.Equal(t, http.StatusOK, run.rec.Code)
		assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
		assertNoCORS(t, run.rec.Header())
	}

	cases := []testCase{
		{
			name:   "an allowed origin",
			policy: exact,
			origin: allowedOrigin,
			assert: func(t *testing.T, run corsRun) {
				assert.True(t, run.handlerRan)
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
				assert.Empty(t, run.rec.Header().Values("Access-Control-Allow-Credentials"), "credentials are off by default")
				assert.Empty(t, run.rec.Header().Values("Access-Control-Expose-Headers"), "nothing is exposed by default")
			},
		},
		{name: "a look-alike origin", policy: exact, origin: "https://app.example.com.evil.example", assert: notAllowed},
		{name: "another scheme", policy: exact, origin: "http://app.example.com", assert: notAllowed},
		{name: "another port", policy: exact, origin: "https://app.example.com:8443", assert: notAllowed},
		{name: "the null origin", policy: exact, origin: "null", assert: notAllowed},
		{name: "no origin", policy: exact, assert: notAllowed},
		{
			name:   "a pattern matches one label",
			policy: httpsec.CORSPolicy{},
			opts:   pattern,
			origin: "https://a.example.com",
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "https://a.example.com", run.rec.Header().Get("Access-Control-Allow-Origin"))
			},
		},
		{name: "a pattern does not match two labels", opts: pattern, origin: "https://a.b.example.com", assert: notAllowed},
		{name: "a pattern does not match the bare domain", opts: pattern, origin: "https://example.com", assert: notAllowed},
		{name: "a pattern does not match another scheme", opts: pattern, origin: "http://a.example.com", assert: notAllowed},
		{
			name:   "every origin without credentials",
			policy: httpsec.CORSPolicy{AllowedOrigins: []string{"*"}},
			origin: "https://anywhere.example",
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "*", run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:   "every origin includes the null origin",
			policy: httpsec.CORSPolicy{AllowedOrigins: []string{"*"}},
			origin: "null",
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "*", run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:   "every origin includes a malformed one, which is never reflected",
			policy: httpsec.CORSPolicy{AllowedOrigins: []string{"*"}},
			origin: "https://evil.example/<script>",
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "*", run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Empty(t, run.rec.Header().Values("Access-Control-Allow-Credentials"))
			},
		},
		{name: "every origin, and no origin sent", policy: httpsec.CORSPolicy{AllowedOrigins: []string{"*"}}, assert: notAllowed},
		{
			name:   "credentials echo the origin",
			policy: httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true},
			origin: allowedOrigin,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", run.rec.Header().Get("Access-Control-Allow-Credentials"))
			},
		},
		{
			name:   "credentials are not sent to another origin",
			policy: httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true},
			origin: "https://evil.example",
			assert: notAllowed,
		},
		{
			name:   "exposed headers on an actual response",
			policy: httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, ExposedHeaders: []string{"WWW-Authenticate", "X-Request-Id"}},
			origin: allowedOrigin,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "WWW-Authenticate, X-Request-Id", run.rec.Header().Get("Access-Control-Expose-Headers"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.EnableCORS(tc.policy, tc.opts...))
			require.NoError(t, err)

			tc.assert(t, serveCORS(t, chain, corsRequest(t, http.MethodGet, tc.origin)))
		})
	}
}

func TestCORS_RefusalReadable(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		origin string
		later  httpsec.Option
		assert func(t *testing.T, run corsRun)
	}

	cases := []testCase{
		{
			name:   "an allowed origin reads the refusal",
			origin: allowedOrigin,
			later:  unauthenticated,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
				assert.False(t, run.handlerRan)
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "WWW-Authenticate", run.rec.Header().Get("Access-Control-Expose-Headers"))
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:   "a later interceptor's own answer carries the allowed origin",
			origin: allowedOrigin,
			later: httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
				ex.Writer.WriteHeader(http.StatusOK)

				return nil
			}), httpsec.After(httpsec.OrderCORS)),
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, http.StatusOK, run.rec.Code)
				assert.False(t, run.handlerRan)
				// The recorder's Header is the live map; Result holds what was
				// sent when the status was written.
				sent := run.rec.Result().Header
				assert.Equal(t, allowedOrigin, sent.Get("Access-Control-Allow-Origin"),
					"the headers are set before the next interceptor writes its answer")
				assert.Equal(t, "WWW-Authenticate", sent.Get("Access-Control-Expose-Headers"))
			},
		},
		{
			name:   "another origin's refusal carries no CORS header",
			origin: "https://evil.example",
			later:  unauthenticated,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
				assertNoCORS(t, run.rec.Header())
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(
				httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, ExposedHeaders: []string{"WWW-Authenticate"}}),
				tc.later,
			)
			require.NoError(t, err)

			tc.assert(t, serveCORS(t, chain, corsRequest(t, http.MethodGet, tc.origin)))
		})
	}
}

// preflightVary is the Vary value every preflight answer carries.
const preflightVary = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"

func TestCORS_Preflight(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		policy httpsec.CORSPolicy
		opts   []httpsec.CORSOption
		method string // "" is OPTIONS
		header http.Header
		assert func(t *testing.T, run corsRun, bearerCalls int64)
	}

	base := func() httpsec.CORSPolicy {
		return httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowedHeaders: []string{"Authorization", "Content-Type"}}
	}
	withMaxAge := base()
	withMaxAge.MaxAge = time.Hour
	withMethods := base()
	withMethods.AllowedMethods = []string{"PUT", "DELETE"}
	withCredentials := base()
	withCredentials.AllowCredentials = true

	preflight := func(method string, headers ...string) http.Header {
		h := http.Header{"Origin": {allowedOrigin}, "Access-Control-Request-Method": {method}}
		for _, v := range headers {
			h.Add("Access-Control-Request-Headers", v)
		}

		return h
	}
	answeredBare := func(t *testing.T, run corsRun, bearerCalls int64) {
		assert.Equal(t, http.StatusNoContent, run.rec.Code)
		assert.False(t, run.handlerRan)
		assert.Zero(t, bearerCalls, "a preflight never reaches authentication")
		assert.Equal(t, preflightVary, run.rec.Header().Get("Vary"))
		assertNoCORS(t, run.rec.Header())
	}

	cases := []testCase{
		{
			name:   "an allowed preflight for an authenticated API",
			policy: base(),
			header: preflight("GET", "authorization"),
			assert: func(t *testing.T, run corsRun, bearerCalls int64) {
				h := run.rec.Header()
				assert.Equal(t, http.StatusNoContent, run.rec.Code)
				assert.Zero(t, bearerCalls, "no authentication runs")
				assert.False(t, run.handlerRan)
				assert.Equal(t, allowedOrigin, h.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "GET, HEAD, POST", h.Get("Access-Control-Allow-Methods"))
				assert.Equal(t, "Authorization", h.Get("Access-Control-Allow-Headers"))
				assert.Equal(t, "600", h.Get("Access-Control-Max-Age"))
				assert.Equal(t, preflightVary, h.Get("Vary"))
				assert.Empty(t, h.Values("Access-Control-Allow-Credentials"))
			},
		},
		{
			name:   "a preflight asking for no header",
			policy: base(),
			header: preflight("POST"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, http.StatusNoContent, run.rec.Code)
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Empty(t, run.rec.Header().Values("Access-Control-Allow-Headers"))
			},
		},
		{
			name:   "a consumer max age",
			policy: withMaxAge,
			header: preflight("GET"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, "3600", run.rec.Header().Get("Access-Control-Max-Age"))
			},
		},
		{
			name:   "preflight caching turned off",
			policy: base(),
			opts:   []httpsec.CORSOption{httpsec.WithoutPreflightCaching()},
			header: preflight("GET"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, []string{"0"}, run.rec.Header().Values("Access-Control-Max-Age"))
			},
		},
		{name: "a method not allowed by default", policy: base(), header: preflight("DELETE"), assert: answeredBare},
		{name: "methods are compared case-sensitively", policy: base(), header: preflight("get"), assert: answeredBare},
		{
			name:   "the consumer's methods replace the default",
			policy: withMethods,
			header: preflight("DELETE"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "PUT, DELETE", run.rec.Header().Get("Access-Control-Allow-Methods"))
			},
		},
		{name: "a default method the consumer's list leaves out", policy: withMethods, header: preflight("GET"), assert: answeredBare},
		{name: "a header not allowed", policy: base(), header: preflight("GET", "x-debug"), assert: answeredBare},
		{name: "one header not allowed among allowed ones", policy: base(), header: preflight("GET", "authorization, x-debug"), assert: answeredBare},
		{
			name:   "headers across lines and cases",
			policy: base(),
			header: preflight("GET", "content-type", "AUTHORIZATION"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Content-Type, Authorization", run.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name:   "spaces and empty entries in the header list",
			policy: base(),
			header: preflight("GET", " content-type ,, authorization ,content-type"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Content-Type, Authorization", run.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name:   "credentials on an allowed preflight",
			policy: withCredentials,
			header: preflight("GET"),
			assert: func(t *testing.T, run corsRun, _ int64) {
				assert.Equal(t, "true", run.rec.Header().Get("Access-Control-Allow-Credentials"))
			},
		},
		{
			name:   "a preflight from another origin",
			policy: base(),
			header: http.Header{"Origin": {"https://evil.example"}, "Access-Control-Request-Method": {"GET"}},
			assert: answeredBare,
		},
		{
			name:   "a plain OPTIONS continues through the chain",
			policy: base(),
			header: http.Header{"Origin": {allowedOrigin}},
			assert: func(t *testing.T, run corsRun, bearerCalls int64) {
				assert.Equal(t, int64(1), bearerCalls, "authentication runs")
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:   "an OPTIONS with a request method but no origin continues through the chain",
			policy: base(),
			header: http.Header{"Access-Control-Request-Method": {"GET"}},
			assert: func(t *testing.T, run corsRun, bearerCalls int64) {
				assert.Equal(t, int64(1), bearerCalls)
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
			},
		},
		{
			name:   "a GET carrying a request method is not a preflight",
			policy: base(),
			method: http.MethodGet,
			header: preflight("GET"),
			assert: func(t *testing.T, run corsRun, bearerCalls int64) {
				assert.Equal(t, int64(1), bearerCalls)
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var bearerCalls atomic.Int64

			chain, err := httpsec.New(
				httpsec.EnableCORS(tc.policy, tc.opts...),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
					bearerCalls.Add(1)
					return httpsec.ErrAuthenticationRequired
				}), httpsec.OrderBearerToken),
			)
			require.NoError(t, err)

			method := tc.method
			if method == "" {
				method = http.MethodOptions
			}

			req := corsRequest(t, method, "")
			req.Header = tc.header

			run := serveCORS(t, chain, req)
			tc.assert(t, run, bearerCalls.Load())
		})
	}
}

// TestCORS_Vary pins that the layer adds to a Vary an outer middleware or an
// earlier interceptor set, rather than replacing it: a cache that lost the
// earlier value could serve one variant to a client that cannot read it.
func TestCORS_Vary(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		outer   string // Vary set by middleware outside the chain
		earlier string // Vary set by an interceptor before OrderCORS
		header  http.Header
		assert  func(t *testing.T, run corsRun)
	}

	actual := http.Header{"Origin": {allowedOrigin}}
	preflight := http.Header{"Origin": {allowedOrigin}, "Access-Control-Request-Method": {http.MethodGet}}

	cases := []testCase{
		{
			name:   "an outer middleware's Vary is kept on an actual response",
			outer:  "Accept-Encoding",
			header: actual,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, []string{"Accept-Encoding", "Origin"}, run.rec.Header().Values("Vary"))
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
			},
		},
		{
			name:    "an earlier interceptor's Vary is kept on an actual response",
			earlier: "Accept-Encoding",
			header:  actual,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, []string{"Accept-Encoding", "Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:   "an outer middleware's Vary is kept on a preflight answer",
			outer:  "Accept-Encoding",
			header: preflight,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, http.StatusNoContent, run.rec.Code)
				assert.Equal(t, []string{"Accept-Encoding", preflightVary}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:    "an earlier interceptor's Vary is kept on a preflight answer",
			earlier: "Accept-Encoding",
			header:  preflight,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, []string{"Accept-Encoding", preflightVary}, run.rec.Header().Values("Vary"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}})}
			if tc.earlier != "" {
				opts = append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					ex.Writer.SetHeader("Vary", tc.earlier)

					return next(ex)
				}), httpsec.Before(httpsec.OrderCORS)))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			method := http.MethodGet
			if tc.header.Get("Access-Control-Request-Method") != "" {
				method = http.MethodOptions
			}

			req := corsRequest(t, method, "")
			req.Header = tc.header.Clone()

			var run corsRun

			run.rec = httptest.NewRecorder()
			inner := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				run.handlerRan = true
				w.WriteHeader(http.StatusOK)
			}))
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.outer != "" {
					w.Header().Set("Vary", tc.outer)
				}

				inner.ServeHTTP(w, r)
			}).ServeHTTP(run.rec, req)

			tc.assert(t, run)
		})
	}
}

func TestCORS_FollowsChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		header http.Header
		method string
		assert func(t *testing.T, run corsRun)
	}

	policy := httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowedHeaders: []string{"Authorization"}}
	exposing := httpsec.CORSPolicy{
		AllowedOrigins: []string{allowedOrigin},
		ExposedHeaders: []string{"X-Request-Id", "www-authenticate"},
	}
	preflight := func(headers string) http.Header {
		return http.Header{
			"Origin":                         {allowedOrigin},
			"Access-Control-Request-Method":  {"GET"},
			"Access-Control-Request-Headers": {headers},
		}
	}
	actual := http.Header{"Origin": {allowedOrigin}}
	refused := func(t *testing.T, run corsRun) {
		assert.Equal(t, http.StatusNoContent, run.rec.Code)
		assertNoCORS(t, run.rec.Header())
	}

	cases := []testCase{
		{
			name:   "DPoP allows its request header",
			opts:   []httpsec.Option{httpsec.EnableCORS(policy), httpsec.DeclareDPoPForTest()},
			header: preflight("authorization, dpop"),
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "Authorization, DPoP", run.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name:   "DPoP declared before CORS is enabled",
			opts:   []httpsec.Option{httpsec.DeclareDPoPForTest(), httpsec.EnableCORS(policy)},
			header: preflight("dpop"),
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "DPoP", run.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name:   "DPoP exposes its response headers",
			opts:   []httpsec.Option{httpsec.EnableCORS(policy), httpsec.DeclareDPoPForTest()},
			method: http.MethodGet,
			header: actual,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "DPoP-Nonce, WWW-Authenticate", run.rec.Header().Get("Access-Control-Expose-Headers"))
			},
		},
		{
			name:   "DPoP adds to the consumer's exposed headers once",
			opts:   []httpsec.Option{httpsec.EnableCORS(exposing), httpsec.DeclareDPoPForTest()},
			method: http.MethodGet,
			header: actual,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, "X-Request-Id, www-authenticate, DPoP-Nonce", run.rec.Header().Get("Access-Control-Expose-Headers"))
			},
		},
		{name: "without DPoP its header is not allowed", opts: []httpsec.Option{httpsec.EnableCORS(policy)}, header: preflight("dpop"), assert: refused},
		{
			name:   "the CSRF token header is allowed",
			opts:   []httpsec.Option{httpsec.EnableCORS(policy), httpsec.DeclareCSRFTokenHeaderForTest("X-CSRF-Token")},
			header: preflight("x-csrf-token"),
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "X-CSRF-Token", run.rec.Header().Get("Access-Control-Allow-Headers"))
			},
		},
		{
			name: "the additions turned off leave DPoP's header out",
			opts: []httpsec.Option{
				httpsec.EnableCORS(policy, httpsec.WithoutAutomaticCORSHeaders()),
				httpsec.DeclareDPoPForTest(),
			},
			header: preflight("dpop"),
			assert: refused,
		},
		{
			name: "the additions turned off expose nothing of DPoP's",
			opts: []httpsec.Option{
				httpsec.EnableCORS(policy, httpsec.WithoutAutomaticCORSHeaders()),
				httpsec.DeclareDPoPForTest(),
			},
			method: http.MethodGet,
			header: actual,
			assert: func(t *testing.T, run corsRun) {
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Empty(t, run.rec.Header().Values("Access-Control-Expose-Headers"))
			},
		},
		{
			name: "the additions turned off leave the CSRF header out",
			opts: []httpsec.Option{
				httpsec.EnableCORS(policy, httpsec.WithoutAutomaticCORSHeaders()),
				httpsec.DeclareCSRFTokenHeaderForTest("X-CSRF-Token"),
			},
			header: preflight("x-csrf-token"),
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts...)
			require.NoError(t, err)

			method := tc.method
			if method == "" {
				method = http.MethodOptions
			}

			req := corsRequest(t, method, "")
			req.Header = tc.header

			tc.assert(t, serveCORS(t, chain, req))
		})
	}
}

func TestCORS_OriginsReadByTheChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		origin string
		assert func(t *testing.T, exact []string, matches bool, err error)
	}

	cases := []testCase{
		{
			name: "normalised exact origins and a pattern",
			opts: []httpsec.Option{httpsec.EnableCORS(
				httpsec.CORSPolicy{AllowedOrigins: []string{"HTTPS://App.Example.com:443", "http://localhost:8080"}},
				httpsec.WithOriginPattern("https://*.example.com"),
			)},
			origin: "https://a.example.com",
			assert: func(t *testing.T, exact []string, matches bool, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{allowedOrigin, "http://localhost:8080"}, exact)
				assert.True(t, matches)
			},
		},
		{
			name:   "nothing without CORS",
			origin: "https://a.example.com",
			assert: func(t *testing.T, exact []string, matches bool, err error) {
				require.NoError(t, err)
				assert.Nil(t, exact)
				assert.False(t, matches)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			exact, matches, err := httpsec.CORSOrigins(tc.origin, tc.opts...)
			tc.assert(t, exact, matches, err)
		})
	}
}

func TestCORS_PreflightInTheChain(t *testing.T) {
	t.Parallel()

	type observed struct {
		beforeRan, beforeSawNonce, afterRan atomic.Bool
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, run corsRun, o *observed)
	}

	cases := []testCase{
		{
			name: "the preflight answer carries the security headers",
			assert: func(t *testing.T, run corsRun, _ *observed) {
				assert.Equal(t, http.StatusNoContent, run.rec.Code)
				assert.Equal(t, allowedOrigin, run.rec.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "nosniff", run.rec.Header().Get("X-Content-Type-Options"))
			},
		},
		{
			name: "an interceptor before the CORS slot runs after the security headers and before CORS",
			assert: func(t *testing.T, _ corsRun, o *observed) {
				assert.True(t, o.beforeRan.Load(), "it runs before CORS answers the preflight")
				assert.True(t, o.beforeSawNonce.Load(), "the security-headers layer has already run")
				assert.False(t, o.afterRan.Load(), "nothing after the CORS slot runs on a preflight")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var o observed

			chain, err := httpsec.New(
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}}),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					o.beforeRan.Store(true)
					_, ok := httpsec.CSPNonce(ex.Context())
					o.beforeSawNonce.Store(ok)

					return next(ex)
				}), httpsec.Before(httpsec.OrderCORS)),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					o.afterRan.Store(true)

					return next(ex)
				}), httpsec.After(httpsec.OrderCORS)),
			)
			require.NoError(t, err)

			req := corsRequest(t, http.MethodOptions, allowedOrigin)
			req.Header.Set("Access-Control-Request-Method", "GET")

			tc.assert(t, serveCORS(t, chain, req), &o)
		})
	}
}

// TestCORS_VaryOnRefusalsBeforeTheSlot pins that Vary: Origin is on every
// response of a CORS-enabled chain, including the two refusals written before
// the CORS interceptor runs: a forwarded host that is not allowed, which no
// interceptor sees, and a security-headers nonce that could not be generated,
// which fails outside the CORS slot. A cache that stored either without it
// could serve one origin's refusal to another.
func TestCORS_VaryOnRefusalsBeforeTheSlot(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options []httpsec.Option

		// header is the request's extra headers; remote its peer, when set.
		header http.Header
		remote string
		assert func(t *testing.T, run corsRun)
	}

	proxy := httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
	}

	cases := []testCase{
		{
			name:    "a forwarded host that is not allowed",
			options: []httpsec.Option{httpsec.EnableTrustedProxies(proxy)},
			header:  http.Header{"Origin": {allowedOrigin}, "X-Forwarded-For": {"203.0.113.7"}, "X-Forwarded-Host": {"evil.example"}},
			remote:  "10.20.0.2:41000",
			assert: func(t *testing.T, run corsRun) {
				assert.False(t, run.handlerRan)
				assert.Equal(t, http.StatusBadRequest, run.rec.Code)
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name: "a security-headers nonce that could not be generated",
			options: []httpsec.Option{httpsec.EnableSecurityHeaders(
				httpsec.SecurityHeadersRandom(iotest.ErrReader(errors.New("entropy exhausted"))))},
			header: http.Header{"Origin": {allowedOrigin}},
			assert: func(t *testing.T, run corsRun) {
				assert.False(t, run.handlerRan)
				assert.Equal(t, http.StatusInternalServerError, run.rec.Code)
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
		{
			name:    "a response that reaches the CORS interceptor carries Vary: Origin once, beside the same options",
			options: []httpsec.Option{httpsec.EnableTrustedProxies(proxy), httpsec.EnableSecurityHeaders()},
			header:  http.Header{"Origin": {allowedOrigin}},
			assert: func(t *testing.T, run corsRun) {
				assert.True(t, run.handlerRan)
				assert.Equal(t, []string{"Origin"}, run.rec.Header().Values("Vary"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(append(
				[]httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}})},
				tc.options...)...)
			require.NoError(t, err)

			req := corsRequest(t, http.MethodGet, "")
			req.Header = tc.header.Clone()

			if tc.remote != "" {
				req.RemoteAddr = tc.remote
			}

			tc.assert(t, serveCORS(t, chain, req))
		})
	}
}
