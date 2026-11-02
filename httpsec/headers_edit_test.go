package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

func TestSecurityHeaders_EditedProfiles(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.HeaderOption
		path   string
		assert func(t *testing.T, h http.Header, err error)
	}

	api := func(opts ...httpsec.HeaderOption) httpsec.HeaderOption {
		return httpsec.WithHeaderProfile(httpsec.APIHeaders(opts...), httpsec.PathPrefix("/api/"))
	}

	cases := []testCase{
		{
			name: "an edited API profile serves its own policy",
			opts: []httpsec.HeaderOption{api(httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'"))))},
			path: "/api/orders",
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Contains(t, h.Get("Content-Security-Policy"), "img-src 'self'")
				assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"), "what was not edited stays")
			},
		},
		{
			name: "a header removed from the API profile is not sent on its routes",
			opts: []httpsec.HeaderOption{api(httpsec.WithoutHeader("Referrer-Policy"))},
			path: "/api/orders",
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Empty(t, h.Values("Referrer-Policy"))
				assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"))
			},
		},
		{
			name: "a header set on the API profile is sent on its routes only",
			opts: []httpsec.HeaderOption{api(httpsec.WithHeader("Cache-Control", "no-store"))},
			path: "/page",
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Empty(t, h.Values("Cache-Control"))
			},
		},
		{
			name: "the default API profile is unchanged",
			opts: []httpsec.HeaderOption{api()},
			path: "/api/orders",
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"))
				assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
				assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
			},
		},
		{
			name: "a policy that cannot be sent fails construction naming the profile option",
			opts: []httpsec.HeaderOption{api(httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'; script-src *"))))},
			path: "/",
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithCSP")
			},
		},
		{
			name: "a layer-wide option inside a profile fails construction",
			opts: []httpsec.HeaderOption{api(httpsec.WithHSTS(time.Hour))},
			path: "/",
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithHSTS")
			},
		},
		{
			name: "a consumer profile starts empty and sends only what it is given",
			opts: []httpsec.HeaderOption{httpsec.WithHeaderProfile(
				httpsec.NewHeaderProfile(httpsec.WithHeader("X-Robots-Tag", "noindex")), httpsec.PathPrefix("/private/"))},
			path: "/private/x",
			assert: func(t *testing.T, h http.Header, err error) {
				require.NoError(t, err)
				assert.Equal(t, "noindex", h.Get("X-Robots-Tag"))
				assert.Empty(t, h.Values("Content-Security-Policy"))
				assert.Empty(t, h.Values("X-Content-Type-Options"))
			},
		},
		{
			name: "removing HSTS inside a profile fails construction",
			opts: []httpsec.HeaderOption{api(httpsec.WithoutHeader("Strict-Transport-Security"))},
			path: "/",
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "Strict-Transport-Security")
			},
		},
		{
			name: "a profile editor given a bad header name fails construction",
			opts: []httpsec.HeaderOption{api(httpsec.WithHeader("Bad Name", "x"))},
			path: "/",
			assert: func(t *testing.T, _ http.Header, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithHeader")
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

// serveOverHTTP serves handler behind a chain built from opts on a real
// listener, because a recorder can neither hijack nor show a flush reaching
// the client.
func serveOverHTTP(t *testing.T, handler http.HandlerFunc, opts ...httpsec.Option) *httptest.Server {
	t.Helper()

	chain, err := httpsec.New(opts...)
	require.NoError(t, err)

	srv := httptest.NewServer(chain.Middleware()(handler))
	t.Cleanup(srv.Close)

	return srv
}

func TestSecurityHeaders_HandlerWins(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		handler http.HandlerFunc
		assert  func(t *testing.T, h http.Header)
	}

	cases := []testCase{
		{
			name: "a handler's own Referrer-Policy is the one sent",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Referrer-Policy", "no-referrer")
				w.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, h http.Header) {
				assert.Equal(t, []string{"no-referrer"}, h.Values("Referrer-Policy"))
				assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), "what it did not set is still the layer's")
			},
		},
		{
			name: "a handler's own Content-Security-Policy replaces the layer's",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
				_, _ = w.Write([]byte("ok"))
			},
			assert: func(t *testing.T, h http.Header) {
				assert.Equal(t, []string{"default-src 'self'"}, h.Values("Content-Security-Policy"))
			},
		},
		{
			name: "a header the handler leaves alone is the layer's",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, h http.Header) {
				assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := serveOverHTTP(t, tc.handler, httpsec.EnableSecurityHeaders())

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			tc.assert(t, resp.Header)
		})
	}
}

func TestSecurityHeaders_Streaming(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		handler func(done chan<- error) http.HandlerFunc
		assert  func(t *testing.T, srv *httptest.Server, done <-chan error)
	}

	cases := []testCase{
		{
			name: "a flush reaches the client before the handler returns",
			handler: func(done chan<- error) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("first"))
					done <- http.NewResponseController(w).Flush()
					<-r.Context().Done()
				}
			},
			assert: func(t *testing.T, srv *httptest.Server, done <-chan error) {
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
				require.NoError(t, err)

				resp, err := srv.Client().Do(req)
				require.NoError(t, <-done, "Flush works through the layer")
				require.NoError(t, err, "the flushed headers reach the client")

				defer func() { _ = resp.Body.Close() }()

				buf := make([]byte, 5)
				_, err = resp.Body.Read(buf)
				require.NoError(t, err)
				assert.Equal(t, "first", string(buf))
			},
		},
		{
			name: "a connection can be hijacked",
			handler: func(done chan<- error) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					conn, _, err := http.NewResponseController(w).Hijack()
					if err == nil {
						_ = conn.Close()
					}

					done <- err
				}
			},
			assert: func(t *testing.T, srv *httptest.Server, done <-chan error) {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
				require.NoError(t, err)

				if resp, err := srv.Client().Do(req); err == nil {
					_ = resp.Body.Close()
				}

				require.NoError(t, <-done, "Hijack works through the layer")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan error, 1)
			srv := serveOverHTTP(t, tc.handler(done), httpsec.EnableSecurityHeaders())

			tc.assert(t, srv, done)
		})
	}
}
