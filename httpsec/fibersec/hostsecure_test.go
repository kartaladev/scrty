package fibersec_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
)

// hostAndSecure is what the chain read from the fiber adapter's request.
type hostAndSecure struct {
	host   string
	secure bool
}

// TestRequest_HostAndSecure pins that the fiber adapter reads the host from the
// request's own Host and the transport security from the connection, never
// from fiber's proxy-aware helpers (Hostname, Secure, Scheme), which follow a
// forwarded header once fiber's proxy trust is enabled.
func TestRequest_HostAndSecure(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		config  fiber.Config
		overTLS bool
		header  map[string]string
		assert  func(t *testing.T, got hostAndSecure)
	}

	// trustingEveryone makes fiber believe its proxy header from any peer,
	// fiber's in-memory and loopback peers included.
	trustingEveryone := fiber.Config{
		TrustProxy:       true,
		TrustProxyConfig: fiber.TrustProxyConfig{Loopback: true, Proxies: []string{"0.0.0.0"}},
		ProxyHeader:      "X-Forwarded-Host",
	}

	cases := []testCase{
		{
			name:    "a TLS connection is secure and keeps its Host",
			overTLS: true,
			assert: func(t *testing.T, got hostAndSecure) {
				assert.Equal(t, hostAndSecure{host: "app.example.com", secure: true}, got)
			},
		},
		{
			name: "a plain connection is not secure",
			assert: func(t *testing.T, got hostAndSecure) {
				assert.Equal(t, hostAndSecure{host: "app.example.com", secure: false}, got)
			},
		},
		{
			name:   "fiber's proxy header does not change the host",
			config: trustingEveryone,
			header: map[string]string{"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"},
			assert: func(t *testing.T, got hostAndSecure) {
				assert.Equal(t, hostAndSecure{host: "app.example.com", secure: false}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got hostAndSecure

			chain := newChain(t, httpsec.RegisterInterceptor(inspecting(func(r httpsec.Request) {
				got = hostAndSecure{host: r.Host(), secure: r.Secure()}
			}), httpsec.OrderJWKS))

			app := fiber.New(tc.config)
			app.Use(fibersec.Middleware(chain))
			app.Get("/r", func(c fiber.Ctx) error { return c.SendStatus(http.StatusOK) })

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/r", nil)
			req.Host = "app.example.com"
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}

			if tc.overTLS {
				require.Equal(t, http.StatusOK, serveOverTLS(t, app, req))
			} else {
				require.Equal(t, http.StatusOK, serve(t, app, req).status)
			}

			tc.assert(t, got)
		})
	}
}

// serveOverTLS runs req through app over a real TLS connection, because
// fiber's in-memory transport is never TLS, and returns the status.
func serveOverTLS(t *testing.T, app *fiber.App, req *http.Request) int {
	t.Helper()

	// The test server is started only for its certificate and a client that
	// trusts it; it serves nothing.
	certs := httptest.NewUnstartedServer(http.NotFoundHandler())
	certs.StartTLS()
	t.Cleanup(certs.Close)

	ln, err := (&net.ListenConfig{}).Listen(req.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- app.Listener(tls.NewListener(ln, certs.TLS.Clone()), fiber.ListenConfig{DisableStartupMessage: true})
	}()

	t.Cleanup(func() {
		require.NoError(t, app.Shutdown())

		if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("fiber listener: %v", err)
		}
	})

	out := req.Clone(context.WithoutCancel(req.Context()))
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = ln.Addr().String()

	res, err := certs.Client().Do(out)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	return res.StatusCode
}

// TestRequest_RepeatedForwardedLines pins that the fiber adapter hands the
// chain every line of a repeated header, so trusted-proxy resolution joins
// them rather than reading the first line, which a client may have sent.
func TestRequest_RepeatedForwardedLines(t *testing.T) {
	t.Parallel()

	var ip string

	chain := newChain(t,
		httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
			// fiber's in-memory transport reports this peer.
			Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")},
			Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
		}),
		httpsec.RegisterInterceptor(inspecting(func(r httpsec.Request) { ip = r.ClientIP() }), httpsec.OrderJWKS),
	)

	app := fiber.New()
	app.Use(fibersec.Middleware(chain))
	app.Get("/r", func(c fiber.Ctx) error { return c.SendStatus(http.StatusOK) })

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/r", nil)
	req.Header.Add("X-Forwarded-For", "1.2.3.4")
	req.Header.Add("X-Forwarded-For", "203.0.113.7")

	require.Equal(t, http.StatusOK, serve(t, app, req).status)
	assert.Equal(t, "203.0.113.7", ip)
}
