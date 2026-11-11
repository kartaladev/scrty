package httpsec_test

import (
	"cmp"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
)

// escapedOverride is a Request whose EscapedPath is fixed, for paths no
// net/http request can carry: net/http refuses an escape that does not decode
// before any handler runs, where another adapter may pass it on.
type escapedOverride struct {
	httpsec.Request
	escaped string
}

func (r escapedOverride) EscapedPath() string { return r.escaped }

// dotSegmentResult is what one request through the chain produced.
type dotSegmentResult struct {
	status  int
	body    string
	header  http.Header
	reached bool
	matched bool
	err     error
}

// TestChain_RefusesDotSegments pins that a request whose path holds a "." or
// ".." segment, as sent or decoded once, or whose path does not decode, is
// answered 400 before any interceptor, a rule or the handler runs, and that a path merely holding dots inside a segment, or
// repeated slashes, is let through.
func TestChain_RefusesDotSegments(t *testing.T) {
	t.Parallel()

	// The peer httptest.NewRequest gives every request.
	peer := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}

	type testCase struct {
		name   string
		method string
		target string
		// escaped, when set, replaces the request's EscapedPath and runs the
		// chain through Assemble, as an adapter passing such a path on would.
		escaped string
		// forceEscaped takes the escaped path route even when escaped is empty.
		forceEscaped bool
		header       map[string]string
		opts         []httpsec.Option
		assert       func(t *testing.T, r dotSegmentResult)
	}

	refused := func(t *testing.T, r dotSegmentResult) {
		t.Helper()
		assert.False(t, r.reached, "the handler ran")
		assert.False(t, r.matched, "an authorization rule was consulted")
		assert.Equal(t, http.StatusBadRequest, r.status)
		assert.Empty(t, r.body)
		require.ErrorIs(t, r.err, httpsec.ErrMalformedRequest)
	}
	served := func(t *testing.T, r dotSegmentResult) {
		t.Helper()
		assert.True(t, r.reached, "the handler did not run (status %d)", r.status)
		assert.Equal(t, http.StatusOK, r.status)
	}

	cases := []testCase{
		{name: "parent segment", target: "/a/../b", assert: refused},
		{name: "current segment", target: "/a/./b", assert: refused},
		{name: "encoded parent segment", target: "/a/%2e%2e/b", assert: refused},
		{name: "upper-case encoded parent segment", target: "/a/%2E%2E/b", assert: refused},
		{name: "mixed encoded parent segment", target: "/a/.%2e/b", assert: refused},
		{name: "encoded current segment", target: "/account/%2e/delete", assert: refused},
		{name: "spec current segment", target: "/account/./delete", assert: refused},
		{name: "segments joined by an encoded slash", target: "/a%2F..%2Fb", assert: refused},
		{name: "trailing parent segment", target: "/a/..", assert: refused},
		{name: "HEAD with parent segment", method: http.MethodHead, target: "/a/../b", assert: refused},
		{
			name: "trusted proxies and a forwarded prefix are ignored", target: "/a/../b",
			header: map[string]string{"X-Forwarded-Prefix": "/x", "X-Forwarded-For": "203.0.113.9"},
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: peer, Headers: httpsec.XForwarded(httpsec.ForwardedFor),
			})},
			assert: refused,
		},
		{name: "undecodable escape", escaped: "/a/%zz", assert: refused},
		{name: "truncated escape", escaped: "/a/%2", assert: refused},
		{
			name: "refusal carries the security headers", target: "/a/../b",
			opts: []httpsec.Option{httpsec.EnableSecurityHeaders()},
			assert: func(t *testing.T, r dotSegmentResult) {
				t.Helper()
				refused(t, r)
				assert.Equal(t, "nosniff", r.header.Get("X-Content-Type-Options"))
			},
		},
		{name: "dots inside a segment", target: "/files/report..v2.txt", assert: served},
		{name: "dot-prefixed segment", target: "/.well-known/jwks.json", assert: served},
		{name: "repeated slashes", target: "/a//b", assert: served},
		{name: "triple dot segment", target: "/a/.../b", assert: served},
		{name: "double-encoded parent segment decodes once only", target: "/a/%252e%252e/b", assert: served},
		{name: "root", target: "/", assert: served},
		{name: "empty escaped path", escaped: "", forceEscaped: true, assert: served},
		{name: "OPTIONS asterisk", method: http.MethodOptions, target: "*", assert: served},
		{name: "absolute-form target with a parent segment", target: "http://example.test/a/../b", assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var reached, matched atomic.Bool

			// A rule set that permits everything, consulted on every request
			// the chain lets reach the authorization stage.
			rule := authorize.Rule[httpsec.Request]{
				Match:   func(httpsec.Request) bool { matched.Store(true); return true },
				Require: authorize.PermitAll(),
			}
			// The error the Middleware path hands its error handler, kept so a
			// row can assert the refusal's cause and not only its status.
			var handled atomic.Pointer[error]

			opts := append([]httpsec.Option{
				httpsec.EnableAuthorization(NewMockAuthorizer(gomock.NewController(t)), rule),
				httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
					handled.Store(&err)
					w.WriteHeader(httpsec.StatusForError(err))
				}),
			}, tc.opts...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			method := tc.method
			if method == "" {
				method = http.MethodGet
			}

			rec := httptest.NewRecorder()
			res := dotSegmentResult{}

			if tc.escaped != "" || tc.forceEscaped {
				req := httptest.NewRequestWithContext(t.Context(), method, "/", nil)
				ex := httpsec.NewExchange(t.Context(),
					escapedOverride{Request: httpsec.NewHTTPRequest(req), escaped: tc.escaped},
					httpsec.NewHTTPResponseWriter(rec))

				res.err = chain.Assemble(func(*httpsec.Exchange) error {
					reached.Store(true)
					return nil
				})(ex)
				res.status = rec.Code
				if res.err != nil {
					res.status = httpsec.StatusForError(res.err)
				}
			} else {
				req := httptest.NewRequestWithContext(t.Context(), method, tc.target, nil)
				for k, v := range tc.header {
					req.Header.Set(k, v)
				}

				chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached.Store(true)
					w.WriteHeader(http.StatusOK)
				})).ServeHTTP(rec, req)
				res.status = rec.Code

				if e := handled.Load(); e != nil {
					res.err = *e
				}
			}

			res.body = rec.Body.String()
			res.header = rec.Header()
			res.reached = reached.Load()
			res.matched = matched.Load()
			tc.assert(t, res)
		})
	}
}

// TestChain_RefusesDotSegmentsAtEntry pins where the dot-segment refusal sits
// in the chain's entry: after client resolution, whose own refusal answers a
// request both would refuse, and ahead of the outermost interceptor.
func TestChain_RefusesDotSegmentsAtEntry(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string // defaults to a dot-segment path
		header map[string]string
		opts   func(ran *atomic.Bool) []httpsec.Option
		assert func(t *testing.T, err error, ran bool)
	}

	cases := []testCase{
		{
			name:   "client resolution refuses first",
			header: map[string]string{"X-Forwarded-Host": "evil.example"},
			opts: func(*atomic.Bool) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
					Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
					Headers:  httpsec.XForwarded(httpsec.ForwardedHost("app.example")),
				})}
			},
			assert: func(t *testing.T, err error, _ bool) {
				require.ErrorIs(t, err, httpsec.ErrHostNotAllowed)
				assert.NotErrorIs(t, err, httpsec.ErrMalformedRequest)
			},
		},
		{
			name:   "control: the same wiring refuses the host on a clean path",
			path:   "/a/b",
			header: map[string]string{"X-Forwarded-Host": "evil.example"},
			opts: func(*atomic.Bool) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
					Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
					Headers:  httpsec.XForwarded(httpsec.ForwardedHost("app.example")),
				})}
			},
			assert: func(t *testing.T, err error, _ bool) {
				require.ErrorIs(t, err, httpsec.ErrHostNotAllowed)
			},
		},
		{
			name: "refused before the outermost interceptor",
			opts: func(ran *atomic.Bool) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						ran.Store(true)
						return next(ex)
					}), httpsec.Order(math.MinInt))}
			},
			assert: func(t *testing.T, err error, ran bool) {
				assert.False(t, ran, "an interceptor ran for a refused path")
				require.ErrorIs(t, err, httpsec.ErrMalformedRequest)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ran, reached atomic.Bool

			chain, err := httpsec.New(tc.opts(&ran)...)
			require.NoError(t, err)

			path := cmp.Or(tc.path, "/a/../b")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}

			ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req),
				httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))

			err = chain.Assemble(func(*httpsec.Exchange) error {
				reached.Store(true)
				return nil
			})(ex)

			if tc.path == "" {
				assert.False(t, reached.Load(), "the handler ran")
			}
			tc.assert(t, err, ran.Load())
		})
	}
}

// TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy pins that the
// 400 for a dot-segment path is written after client resolution: behind a
// trusted TLS-terminating proxy it carries the secure-only headers a clean
// path gets, a forged scheme from an untrusted peer does not turn them on, and
// a request client resolution refuses gets that refusal, not the dot-segment
// one.
func TestChain_EntryRefusalCarriesSecureHeadersBehindTrustedProxy(t *testing.T) {
	t.Parallel()

	const (
		hsts          = "Strict-Transport-Security"
		trustedPeer   = "10.20.0.2:41000"
		untrustedPeer = "198.51.100.9:41000"
	)

	type result struct {
		status  int
		header  http.Header
		err     error
		reached bool
	}

	type testCase struct {
		name   string
		target string
		peer   string
		// forwardedHost, when set, is sent as X-Forwarded-Host to a chain that
		// trusts only "app.example".
		forwardedHost string
		assert        func(t *testing.T, r result)
	}

	cases := []testCase{
		{
			name: "control: clean path through the proxy carries HSTS", target: "/a/admin", peer: trustedPeer,
			assert: func(t *testing.T, r result) {
				t.Helper()
				assert.Equal(t, http.StatusOK, r.status)
				assert.True(t, r.reached, "the handler did not run")
				assert.NotEmpty(t, r.header.Get(hsts), "control: the fixture must make the request secure")
			},
		},
		{
			name: "control: untrusted peer's forged scheme gets no HSTS on the refusal", target: "/a/%2e%2e/admin",
			peer: untrustedPeer,
			assert: func(t *testing.T, r result) {
				t.Helper()
				assert.Equal(t, http.StatusBadRequest, r.status)
				require.ErrorIs(t, r.err, httpsec.ErrMalformedRequest)
				assert.Empty(t, r.header.Get(hsts))
			},
		},
		{
			name: "dot-segment 400 behind the trusted proxy carries HSTS", target: "/a/%2e%2e/admin", peer: trustedPeer,
			assert: func(t *testing.T, r result) {
				t.Helper()
				assert.Equal(t, http.StatusBadRequest, r.status)
				require.ErrorIs(t, r.err, httpsec.ErrMalformedRequest)
				assert.False(t, r.reached, "the handler ran")
				assert.NotEmpty(t, r.header.Get(hsts),
					"the refusal lacks the secure-only header the same request gets on a clean path")
			},
		},
		{
			name: "client resolution refuses first", target: "/a/../b", peer: trustedPeer, forwardedHost: "evil.example",
			assert: func(t *testing.T, r result) {
				t.Helper()
				assert.Equal(t, httpsec.StatusForError(httpsec.ErrHostNotAllowed), r.status)
				require.ErrorIs(t, r.err, httpsec.ErrHostNotAllowed)
				assert.NotErrorIs(t, r.err, httpsec.ErrMalformedRequest)
				assert.False(t, r.reached, "the handler ran")
			},
		},
		{
			name:   "an allowed forwarded host on a dot-segment path is refused as a dot segment, with HSTS",
			target: "/a/../b", peer: trustedPeer, forwardedHost: "app.example",
			assert: func(t *testing.T, r result) {
				t.Helper()
				assert.Equal(t, http.StatusBadRequest, r.status)
				require.ErrorIs(t, r.err, httpsec.ErrMalformedRequest)
				assert.NotEmpty(t, r.header.Get(hsts))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fields := []httpsec.ForwardedField{httpsec.ForwardedFor, httpsec.ForwardedProto}
			if tc.forwardedHost != "" {
				fields = append(fields, httpsec.ForwardedHost("app.example"))
			}

			var (
				res     result
				handled error
			)

			chain, err := httpsec.New(
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
					Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
					Headers:  httpsec.XForwarded(fields...),
				}),
				httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
					handled = err
					w.WriteHeader(httpsec.StatusForError(err))
				}),
			)
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.target, nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("X-Forwarded-For", "203.0.113.7")
			req.Header.Set("X-Forwarded-Proto", "https")
			if tc.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tc.forwardedHost)
			}

			rec := httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				res.reached = true
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)

			res.status, res.header, res.err = rec.Code, rec.Header(), handled
			tc.assert(t, res)
		})
	}
}
