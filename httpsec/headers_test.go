package httpsec_test

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

func TestOrder_OuterSlots(t *testing.T) {
	t.Parallel()

	assert.Equal(t, httpsec.Order(25), httpsec.OrderSecurityHeaders)
	assert.Equal(t, httpsec.Order(50), httpsec.OrderCORS)
	assert.Equal(t, httpsec.Order(75), httpsec.OrderCSRF)
	assert.Less(t, httpsec.OrderCSRF, httpsec.OrderJWKS, "every outer slot is outside the key set slot")
}

// headerRun is one request through the net/http entrypoint.
type headerRun struct {
	rec        *httptest.ResponseRecorder
	handlerRan bool
	nonce      string
	nonceOK    bool
}

// serveHeaders runs req through a chain built from opts, with a handler that
// records the nonce it can read.
func serveHeaders(t *testing.T, req *http.Request, opts ...httpsec.Option) headerRun {
	t.Helper()

	chain, err := httpsec.New(opts...)
	require.NoError(t, err)

	var run headerRun

	run.rec = httptest.NewRecorder()
	chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		run.handlerRan = true
		run.nonce, run.nonceOK = httpsec.CSPNonce(r.Context())
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(run.rec, req)

	return run
}

func getRequest(t *testing.T, path string) *http.Request {
	t.Helper()

	return httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
}

// unauthenticated refuses every request in the bearer token's slot, as a
// bearer refusal does.
var unauthenticated = httpsec.RegisterInterceptor(
	httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
		return httpsec.ErrAuthenticationRequired
	}), httpsec.OrderBearerToken)

// nonceOf reads the nonce out of a Content-Security-Policy value.
func nonceOf(t *testing.T, csp string) string {
	t.Helper()

	m := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(csp)
	require.Len(t, m, 2, "the policy carries a nonce: %q", csp)

	return m[1]
}

const defaultDocumentCSP = `script-src 'nonce-%s' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`

func TestSecurityHeaders_Defaults(t *testing.T) {
	t.Parallel()

	proxy := httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		req    func(t *testing.T) *http.Request
		assert func(t *testing.T, run headerRun, err error)
	}

	notSent := []string{"X-Xss-Protection", "X-Frame-Options", "Cross-Origin-Embedder-Policy", "Origin-Agent-Cluster"}

	assertOtherDefaults := func(t *testing.T, h http.Header) {
		t.Helper()

		assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
		assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
		assert.Equal(t, "same-origin-allow-popups", h.Get("Cross-Origin-Opener-Policy"))

		for _, name := range notSent {
			assert.Empty(t, h.Values(name), "%s is never sent by default", name)
		}
	}

	carriesDefaults := func(t *testing.T, run headerRun) {
		t.Helper()

		h := run.rec.Header()
		nonce := nonceOf(t, h.Get("Content-Security-Policy"))
		assert.Equal(t, fmt.Sprintf(defaultDocumentCSP, nonce), h.Get("Content-Security-Policy"))
		assertOtherDefaults(t, h)
	}

	// A host refusal never reaches a handler, so its policy carries no nonce
	// and admits no script.
	carriesDefaultsWithoutNonce := func(t *testing.T, run headerRun) {
		t.Helper()

		h := run.rec.Header()
		assert.Equal(t, "script-src 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
			h.Get("Content-Security-Policy"))
		assertOtherDefaults(t, h)
	}

	cases := []testCase{
		{
			name: "default document response",
			opts: []httpsec.Option{httpsec.EnableSecurityHeaders()},
			req:  func(t *testing.T) *http.Request { return getRequest(t, "/page") },
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.True(t, run.handlerRan)
				carriesDefaults(t, run)
			},
		},
		{
			name: "a 401 refusal carries the headers",
			opts: []httpsec.Option{httpsec.EnableSecurityHeaders(), unauthenticated},
			req:  func(t *testing.T) *http.Request { return getRequest(t, "/page") },
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.False(t, run.handlerRan)
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
				carriesDefaults(t, run)
			},
		},
		{
			name: "a host-not-allowed 400 carries the headers, with no interceptor run",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(proxy), httpsec.EnableSecurityHeaders()},
			req: func(t *testing.T) *http.Request {
				r := getRequest(t, "/page")
				r.RemoteAddr = "10.20.0.2:41000"
				r.Header.Set("X-Forwarded-For", "203.0.113.7")
				r.Header.Set("X-Forwarded-Host", "evil.example")

				return r
			},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.False(t, run.handlerRan)
				assert.Equal(t, http.StatusBadRequest, run.rec.Code)
				carriesDefaultsWithoutNonce(t, run)
			},
		},
		{
			name: "a host refusal reaches the consumer's error handler with the headers already set",
			opts: []httpsec.Option{
				httpsec.EnableTrustedProxies(proxy), httpsec.EnableSecurityHeaders(),
				httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) {
					// What the consumer's handler sees on the writer it owns.
					w.Header().Set("X-Seen-Nosniff", w.Header().Get("X-Content-Type-Options"))
					w.WriteHeader(http.StatusBadRequest)
				}),
			},
			req: func(t *testing.T) *http.Request {
				r := getRequest(t, "/page")
				r.RemoteAddr = "10.20.0.2:41000"
				r.Header.Set("X-Forwarded-Host", "evil.example")

				return r
			},
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)
				assert.Equal(t, "nosniff", run.rec.Header().Get("X-Seen-Nosniff"))
			},
		},
		{
			name: "without the layer, none of the headers",
			opts: nil,
			req:  func(t *testing.T) *http.Request { return getRequest(t, "/page") },
			assert: func(t *testing.T, run headerRun, err error) {
				require.NoError(t, err)

				for _, name := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
					"Referrer-Policy", "Cross-Origin-Opener-Policy"} {
					assert.Empty(t, run.rec.Header().Values(name), name)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			run := serveHeaders(t, tc.req(t), tc.opts...)
			tc.assert(t, run, nil)
		})
	}

	t.Run("enabled twice fails construction", func(t *testing.T) {
		t.Parallel()

		_, err := httpsec.New(httpsec.EnableSecurityHeaders(), httpsec.EnableSecurityHeaders())
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "EnableSecurityHeaders")
	})
}

func TestSecurityHeaders_Directives(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.HeaderOption
		assert func(t *testing.T, h http.Header, err error)
	}

	csp := func(t *testing.T, h http.Header) string {
		t.Helper()

		return strings.ReplaceAll(h.Get("Content-Security-Policy"), nonceOf(t, h.Get("Content-Security-Policy")), "N")
	}

	cases := []testCase{
		{
			name: "a directive is added alongside the defaults",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'", "data:")))},
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Equal(t, "script-src 'nonce-N' 'strict-dynamic'; object-src 'none'; base-uri 'none'; "+
					"frame-ancestors 'none'; img-src 'self' data:", csp(t, h))
			},
		},
		{
			name: "a default directive is replaced, not duplicated",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("frame-ancestors", "'self'")))},
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				got := csp(t, h)
				assert.Equal(t, 1, strings.Count(got, "frame-ancestors"))
				assert.Contains(t, got, "frame-ancestors 'self'")
				assert.NotContains(t, got, "frame-ancestors 'none'")
			},
		},
		{
			name: "a replacement matches the directive name case-insensitively",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("Frame-Ancestors", "'self'")))},
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, strings.Count(strings.ToLower(csp(t, h)), "frame-ancestors"))
			},
		},
		{
			name: "a header is removed",
			opts: []httpsec.HeaderOption{httpsec.WithoutHeader("cross-origin-opener-policy")},
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Empty(t, h.Values("Cross-Origin-Opener-Policy"))
				assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), "the others stay")
			},
		},
		{
			name: "a header value is replaced, and one the default does not send is added",
			opts: []httpsec.HeaderOption{
				httpsec.WithHeader("Referrer-Policy", "no-referrer"),
				httpsec.WithHeader("Cross-Origin-Embedder-Policy", "require-corp"),
			},
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
				assert.Equal(t, "require-corp", h.Get("Cross-Origin-Embedder-Policy"))
			},
		},
		{
			name: "the policy header is removed",
			opts: []httpsec.HeaderOption{httpsec.WithoutHeader("Content-Security-Policy")},
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Empty(t, h.Values("Content-Security-Policy"))
			},
		},
		{
			name: "a source holding a semicolon is refused, naming the policy",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'; script-src *")))},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithCSP")
			},
		},
		{
			name: "a source holding a comma is refused",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "a, b")))},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "a source holding a line break is refused",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "a\nX-Evil: 1")))},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "a source holding the nonce stand-in's control character is refused",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'nonce-\x00'")))},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "a directive name holding a semicolon is refused",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src; script-src", "*")))},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "an empty directive name is refused",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("", "*")))},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
		{
			name: "a header value holding a line break is refused, naming the option",
			opts: []httpsec.HeaderOption{httpsec.WithHeader("Referrer-Policy", "no-referrer\r\nX-Evil: 1")},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithHeader")
			},
		},
		{
			name: "a header name that is not a token is refused",
			opts: []httpsec.HeaderOption{httpsec.WithHeader("X Bad", "1")},
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.EnableSecurityHeaders(tc.opts...))
			if err != nil {
				tc.assert(t, nil, err)

				return
			}

			rec := httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
				ServeHTTP(rec, getRequest(t, "/page"))

			tc.assert(t, rec.Header(), nil)
		})
	}
}

func TestSecurityHeaders_Nonce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.HeaderOption
		extra  []httpsec.Option
		path   string
		assert func(t *testing.T, run headerRun)
	}

	cases := []testCase{
		{
			name: "the handler reads the nonce the header carries, 16 bytes, base64",
			path: "/page",
			assert: func(t *testing.T, run headerRun) {
				require.True(t, run.nonceOK)
				assert.Equal(t, nonceOf(t, run.rec.Header().Get("Content-Security-Policy")), run.nonce)

				raw, err := base64.StdEncoding.DecodeString(run.nonce)
				require.NoError(t, err)
				assert.Len(t, raw, 16)
			},
		},
		{
			name: "a failing random source fails the request and the handler does not run",
			opts: []httpsec.HeaderOption{httpsec.SecurityHeadersRandom(iotest.ErrReader(errors.New("entropy exhausted")))},
			path: "/page",
			assert: func(t *testing.T, run headerRun) {
				assert.Equal(t, http.StatusInternalServerError, run.rec.Code)
				assert.False(t, run.handlerRan)
				assert.NotContains(t, run.rec.Header().Get("Content-Security-Policy"), "nonce-",
					"a predictable nonce is never served")
				assert.NotEmpty(t, run.rec.Header().Get("Content-Security-Policy"), "the refusal still carries a policy")
			},
		},
		{
			// The nonce failure answers before any later interceptor runs, so
			// the chain's refusal steps are what carry no-store here.
			name:  "a failing nonce source on a session-management path still answers no-store",
			opts:  []httpsec.HeaderOption{httpsec.SecurityHeadersRandom(iotest.ErrReader(errors.New("entropy exhausted")))},
			extra: managementOptions(t),
			path:  httpsec.DefaultSessionManagementPrefix,
			assert: func(t *testing.T, run headerRun) {
				assert.Equal(t, http.StatusInternalServerError, run.rec.Code)
				assert.False(t, run.handlerRan)
				assert.Equal(t, "no-store", run.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name:  "a failing nonce source off the session-management prefix sets no cache directive",
			opts:  []httpsec.HeaderOption{httpsec.SecurityHeadersRandom(iotest.ErrReader(errors.New("entropy exhausted")))},
			extra: managementOptions(t),
			path:  "/page",
			assert: func(t *testing.T, run headerRun) {
				assert.Equal(t, http.StatusInternalServerError, run.rec.Code)
				assert.Empty(t, run.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name: "a short random source fails the request",
			opts: []httpsec.HeaderOption{httpsec.SecurityHeadersRandom(strings.NewReader("short"))},
			path: "/page",
			assert: func(t *testing.T, run headerRun) {
				assert.Equal(t, http.StatusInternalServerError, run.rec.Code)
				assert.False(t, run.handlerRan)
			},
		},
		{
			name: "no nonce on an API route",
			opts: []httpsec.HeaderOption{httpsec.WithHeaderProfile(httpsec.APIHeaders(), httpsec.PathPrefix("/api/"))},
			path: "/api/orders",
			assert: func(t *testing.T, run headerRun) {
				assert.True(t, run.handlerRan)
				assert.False(t, run.nonceOK)
				assert.Empty(t, run.nonce)
				assert.NotContains(t, run.rec.Header().Get("Content-Security-Policy"), "nonce-")
			},
		},
		{
			name: "no nonce when the policy was replaced by one that does not use it",
			opts: []httpsec.HeaderOption{httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("script-src", "'self'")))},
			path: "/page",
			assert: func(t *testing.T, run headerRun) {
				assert.False(t, run.nonceOK)
				assert.Contains(t, run.rec.Header().Get("Content-Security-Policy"), "script-src 'self'")
			},
		},
		{
			name:  "no nonce without the layer",
			extra: nil,
			path:  "/page",
			assert: func(t *testing.T, run headerRun) {
				assert.False(t, run.nonceOK)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.extra
			if tc.name != "no nonce without the layer" {
				opts = append(opts, httpsec.EnableSecurityHeaders(tc.opts...))
			}

			tc.assert(t, serveHeaders(t, getRequest(t, tc.path), opts...))
		})
	}

	t.Run("two responses carry different nonces", func(t *testing.T) {
		t.Parallel()

		chain, err := httpsec.New(httpsec.EnableSecurityHeaders())
		require.NoError(t, err)

		seen := map[string]bool{}

		for range 50 {
			rec := httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
				ServeHTTP(rec, getRequest(t, "/page"))

			seen[nonceOf(t, rec.Header().Get("Content-Security-Policy"))] = true
		}

		assert.Len(t, seen, 50)
	})
}

func TestSecurityHeaders_Profiles(t *testing.T) {
	t.Parallel()

	custom := httpsec.WithHeaderProfile(
		httpsec.APIHeaders(), httpsec.PathPrefix("/api/"))

	adminOnly := httpsec.HeaderProfile{}

	type testCase struct {
		name   string
		opts   []httpsec.HeaderOption
		path   string
		assert func(t *testing.T, h http.Header, err error)
	}

	isAPI := func(t *testing.T, h http.Header, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"))
		assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
		assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
		assert.Empty(t, h.Values("Cross-Origin-Opener-Policy"))
	}

	isDocument := func(t *testing.T, h http.Header, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Contains(t, h.Get("Content-Security-Policy"), "'strict-dynamic'")
		assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
	}

	cases := []testCase{
		{name: "a path under the prefix gets the API profile", opts: []httpsec.HeaderOption{custom}, path: "/api/orders", assert: isAPI},
		{name: "the prefix itself gets it", opts: []httpsec.HeaderOption{custom}, path: "/api", assert: isAPI},
		{name: "a sibling segment sharing the prefix's letters does not", opts: []httpsec.HeaderOption{custom}, path: "/apix", assert: isDocument},
		{name: "a path outside every prefix gets the document set", opts: []httpsec.HeaderOption{custom}, path: "/page", assert: isDocument},
		{
			name: "a prefix without a leading slash is read as rooted",
			opts: []httpsec.HeaderOption{httpsec.WithHeaderProfile(httpsec.APIHeaders(), httpsec.PathPrefix("api"))},
			path: "/api/orders", assert: isAPI,
		},
		{
			name: "a function matcher selects by the request",
			opts: []httpsec.HeaderOption{httpsec.WithHeaderProfile(httpsec.APIHeaders(), func(r httpsec.Request) bool {
				return r.Method() == http.MethodGet && r.Path() == "/anything"
			})},
			path:   "/anything",
			assert: isAPI,
		},
		{
			name: "the first matching profile wins",
			opts: []httpsec.HeaderOption{
				httpsec.WithHeaderProfile(adminOnly, httpsec.PathPrefix("/api/admin/")),
				custom,
			},
			path: "/api/admin/users",
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Empty(t, h.Values("Content-Security-Policy"), "the admin profile, which sends none, applied")
			},
		},
		{
			name: "a later profile applies to what the first does not select",
			opts: []httpsec.HeaderOption{
				httpsec.WithHeaderProfile(adminOnly, httpsec.PathPrefix("/api/admin/")),
				custom,
			},
			path:   "/api/orders",
			assert: isAPI,
		},
		{
			name: "a nil matcher fails construction naming the option",
			opts: []httpsec.HeaderOption{httpsec.WithHeaderProfile(httpsec.APIHeaders(), nil)},
			path: "/",
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithHeaderProfile")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(httpsec.EnableSecurityHeaders(tc.opts...))
			if err != nil {
				tc.assert(t, nil, err)

				return
			}

			rec := httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
				ServeHTTP(rec, getRequest(t, tc.path))

			tc.assert(t, rec.Header(), nil)
		})
	}
}

func TestSecurityHeaders_HSTS(t *testing.T) {
	t.Parallel()

	proxies := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto),
	})

	const hsts = "Strict-Transport-Security"

	secure := func(r *http.Request) *http.Request {
		r.TLS = &tls.ConnectionState{}

		return r
	}

	forwarded := func(peer string) func(r *http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			r.RemoteAddr = peer
			r.Header.Set("X-Forwarded-For", "203.0.113.7")
			r.Header.Set("X-Forwarded-Proto", "https")

			return r
		}
	}

	type testCase struct {
		name   string
		opts   []httpsec.HeaderOption
		chain  []httpsec.Option
		req    func(r *http.Request) *http.Request
		assert func(t *testing.T, h http.Header, err error)
	}

	sent := func(want string) func(t *testing.T, h http.Header, err error) {
		return func(t *testing.T, h http.Header, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, want, h.Get(hsts))
		}
	}

	refused := func(t *testing.T, _ http.Header, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "WithHSTS")
	}

	cases := []testCase{
		{name: "a secure request gets the default", req: secure, assert: sent("max-age=31536000; includeSubDomains")},
		{name: "a plain-HTTP request gets none", assert: sent("")},
		{
			name: "a trusted proxy forwarding https", chain: []httpsec.Option{proxies},
			req: forwarded("10.20.0.2:41000"), assert: sent("max-age=31536000; includeSubDomains"),
		},
		{
			name: "an untrusted peer's forged scheme gets none", chain: []httpsec.Option{proxies},
			req: forwarded("198.51.100.9:41000"), assert: sent(""),
		},
		{
			name: "zero withdraws the policy", opts: []httpsec.HeaderOption{httpsec.WithHSTS(0)}, req: secure,
			assert: sent("max-age=0; includeSubDomains"),
		},
		{
			name: "the age and subdomains are the consumer's",
			opts: []httpsec.HeaderOption{httpsec.WithHSTS(time.Hour, httpsec.WithoutHSTSSubdomains())}, req: secure,
			assert: sent("max-age=3600"),
		},
		{
			name: "preload is opt-in",
			opts: []httpsec.HeaderOption{httpsec.WithHSTS(365*24*time.Hour, httpsec.HSTSIncludeSubdomains(), httpsec.HSTSPreload())},
			req:  secure, assert: sent("max-age=31536000; includeSubDomains; preload"),
		},
		{
			name: "the header can be removed", opts: []httpsec.HeaderOption{httpsec.WithoutHeader(hsts)}, req: secure,
			assert: sent(""),
		},
		{name: "a negative age is refused", opts: []httpsec.HeaderOption{httpsec.WithHSTS(-time.Second)}, assert: refused},
		{name: "a fraction of a second is refused", opts: []httpsec.HeaderOption{httpsec.WithHSTS(time.Millisecond)}, assert: refused},
		{
			name: "preload below a year is refused",
			opts: []httpsec.HeaderOption{httpsec.WithHSTS(24*time.Hour, httpsec.HSTSPreload())}, assert: refused,
		},
		{
			name:   "preload without subdomains is refused",
			opts:   []httpsec.HeaderOption{httpsec.WithHSTS(365*24*time.Hour, httpsec.WithoutHSTSSubdomains(), httpsec.HSTSPreload())},
			assert: refused,
		},
		{
			name: "setting the header by hand is refused, pointing at WithHSTS",
			opts: []httpsec.HeaderOption{httpsec.WithHeader(hsts, "max-age=1")}, assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(append(slices.Clone(tc.chain), httpsec.EnableSecurityHeaders(tc.opts...))...)
			if err != nil {
				tc.assert(t, nil, err)

				return
			}

			req := getRequest(t, "/page")
			if tc.req != nil {
				req = tc.req(req)
			}

			rec := httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

			tc.assert(t, rec.Header(), nil)
		})
	}
}

// TestSecurityHeaders_ConsumerInterceptorPlacement pins the documented limit of
// the layer: it is outside every built-in interceptor, but a consumer
// interceptor registered ahead of OrderSecurityHeaders runs outside it, and a
// response that interceptor writes carries no security headers. One registered
// behind the layer, in its slot or after it, has them.
func TestSecurityHeaders_ConsumerInterceptorPlacement(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		order  httpsec.Order
		assert func(t *testing.T, run headerRun)
	}

	hasNoHeaders := func(t *testing.T, run headerRun) {
		t.Helper()

		assert.Equal(t, http.StatusTeapot, run.rec.Code, "the interceptor answered")
		assert.False(t, run.handlerRan)

		for _, name := range []string{
			"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy",
		} {
			assert.Empty(t, run.rec.Header().Values(name), "%s: the interceptor runs outside the layer", name)
		}
	}

	hasHeaders := func(t *testing.T, run headerRun) {
		t.Helper()

		assert.Equal(t, http.StatusTeapot, run.rec.Code, "the interceptor answered")
		assert.NotEmpty(t, run.rec.Header().Get("Content-Security-Policy"))
		assert.Equal(t, "nosniff", run.rec.Header().Get("X-Content-Type-Options"))
	}

	cases := []testCase{
		{name: "registered ahead of the layer", order: httpsec.Before(httpsec.OrderSecurityHeaders), assert: hasNoHeaders},
		{name: "registered behind the layer", order: httpsec.After(httpsec.OrderSecurityHeaders), assert: hasHeaders},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			answers := httpsec.RegisterInterceptor(
				httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
					ex.Writer.WriteHeader(http.StatusTeapot)

					return nil
				}), tc.order)

			tc.assert(t, serveHeaders(t, getRequest(t, "/page"), httpsec.EnableSecurityHeaders(), answers))
		})
	}
}
