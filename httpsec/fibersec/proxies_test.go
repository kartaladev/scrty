package fibersec_test

import (
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

// TestTrustedProxies_RemovesHeaders pins that the forwarded headers the chain
// consumed are removed from the request fiber hands to its handlers after the
// chain, from trusted and untrusted peers alike, unless the consumer keeps
// them, and that without trusted proxies they are left alone.
func TestTrustedProxies_RemovesHeaders(t *testing.T) {
	t.Parallel()

	tp := httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com")),
	}

	forwarded := map[string]string{
		"Forwarded":          "for=203.0.113.7",
		"X-Forwarded-For":    "203.0.113.7",
		"X-Forwarded-Proto":  "https",
		"X-Forwarded-Host":   "app.example.com",
		"X-Forwarded-Port":   "443",
		"X-Forwarded-Prefix": "/app",
		"X-Client-Cert":      "-----BEGIN%20CERTIFICATE-----",
	}

	type observed struct {
		client  httpsec.Client
		headers map[string]string
	}

	removed := func(t *testing.T, got observed) {
		for name := range forwarded {
			assert.Empty(t, got.headers[name], "%s is removed", name)
		}

		assert.Equal(t, "r-1", got.headers["X-Request-Id"], "an unrelated header is left alone")
	}

	untouched := func(t *testing.T, got observed) {
		for name, v := range forwarded {
			assert.Equal(t, v, got.headers[name], "%s is left as sent", name)
		}
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		peer   string
		assert func(t *testing.T, got observed)
	}

	cases := []testCase{
		{
			name: "removed from a trusted peer's request",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil))},
			peer: "10.20.0.2:41000",
			assert: func(t *testing.T, got observed) {
				removed(t, got)
				assert.Equal(t, httpsec.Client{IP: "203.0.113.7", Secure: true, Host: "app.example.com", ViaProxy: true},
					got.client)
			},
		},
		{
			name: "removed from an untrusted peer's request too",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil))},
			peer:   "198.51.100.9:41000",
			assert: removed,
		},
		{
			name: "kept with KeepForwardedHeaders",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil), httpsec.KeepForwardedHeaders())},
			peer:   "10.20.0.2:41000",
			assert: untouched,
		},
		{
			name: "untouched without trusted proxies",
			peer: "10.20.0.2:41000",
			assert: func(t *testing.T, got observed) {
				untouched(t, got)
				assert.Equal(t, httpsec.Client{IP: "10.20.0.2", Host: "app.example.com"}, got.client)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				got observed
				ran bool
			)

			app := fiber.New()
			app.Use(fibersec.Middleware(newChain(t, tc.opts...)))
			app.Get("/r", func(fc fiber.Ctx) error {
				ran = true
				got.client, _ = httpsec.ClientFromContext(fc.Context())
				got.headers = map[string]string{"X-Request-Id": fc.Get("X-Request-Id")}

				for name := range forwarded {
					got.headers[name] = fc.Get(name)
				}

				return fc.SendStatus(http.StatusOK)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/r", nil)
			req.Host = "app.example.com"
			req.Header.Set("X-Request-Id", "r-1")

			for name, v := range forwarded {
				req.Header.Set(name, v)
			}

			require.Equal(t, http.StatusOK, serveFrom(t, app, req, tc.peer).status)
			require.True(t, ran, "the fiber handler ran")

			tc.assert(t, got)
		})
	}
}
