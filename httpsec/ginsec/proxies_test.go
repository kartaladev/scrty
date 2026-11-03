package ginsec_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

// TestGin_UntrustedPeerCannotPoseAsTrustedProxy pins that gin's own client
// address never reaches the chain: gin trusts every proxy until configured, so
// a direct peer that names a trusted proxy's address in its own
// X-Forwarded-For would otherwise be resolved as if that proxy had sent it,
// and its forwarded scheme believed.
func TestGin_UntrustedPeerCannotPoseAsTrustedProxy(t *testing.T) {
	t.Parallel()

	var (
		ip     string
		secure bool
	)

	chain := newChain(t,
		httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
			Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto),
		}),
		httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
			ip, secure = ex.Request.ClientIP(), ex.Request.Secure()

			return next(ex)
		}), httpsec.OrderJWKS))

	// gin.New trusts every proxy: the configuration under test.
	eng := gin.New()
	eng.Use(ginsec.Middleware(chain))
	eng.GET("/r", func(*gin.Context) {})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/r", nil)
	req.RemoteAddr = "198.51.100.9:5000" // untrusted, direct
	req.Header.Set("X-Forwarded-For", "10.20.0.2")
	req.Header.Set("X-Forwarded-Proto", "https")

	rec := serve(eng, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "198.51.100.9", ip, "the transport peer, not an address the client named")
	assert.False(t, secure, "an untrusted peer's forwarded scheme is ignored")
}

// TestTrustedProxies_RemovesHeaders pins that the forwarded headers the chain
// consumed are removed from the request gin hands to its handlers after the
// chain, from trusted and untrusted peers alike, unless the consumer keeps
// them, and that without trusted proxies they are left alone. It also pins
// that every line of a repeated forwarded header reaches the resolver.
func TestTrustedProxies_RemovesHeaders(t *testing.T) {
	t.Parallel()

	tp := httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers: httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto,
			httpsec.ForwardedHost("app.example.com")),
	}

	forwarded := map[string]string{
		"Forwarded":          "for=203.0.113.7",
		"X-Forwarded-Proto":  "https",
		"X-Forwarded-Host":   "app.example.com",
		"X-Forwarded-Port":   "443",
		"X-Forwarded-Prefix": "/app",
		"X-Client-Cert":      "-----BEGIN%20CERTIFICATE-----",
	}

	type observed struct {
		client  httpsec.Client
		headers http.Header
	}

	removed := func(t *testing.T, got observed) {
		for name := range forwarded {
			assert.Empty(t, got.headers.Values(name), "%s is removed", name)
		}

		assert.Empty(t, got.headers.Values("X-Forwarded-For"), "X-Forwarded-For is removed")
		assert.Equal(t, "r-1", got.headers.Get("X-Request-Id"), "an unrelated header is left alone")
	}

	untouched := func(t *testing.T, got observed) {
		for name, v := range forwarded {
			assert.Equal(t, v, got.headers.Get(name), "%s is left as sent", name)
		}

		assert.Equal(t, []string{"1.2.3.4", "203.0.113.7"}, got.headers.Values("X-Forwarded-For"))
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		peer   string
		assert func(t *testing.T, got observed)
	}

	cases := []testCase{
		{
			name: "removed from a trusted peer's request, after reading every line",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(tp,
				httpsec.WithClientCertificateHeader("X-Client-Cert", nil))},
			peer: "10.20.0.2:41000",
			assert: func(t *testing.T, got observed) {
				removed(t, got)
				assert.Equal(t, httpsec.Client{IP: "203.0.113.7", Secure: true, Host: "app.example.com", ViaProxy: true},
					got.client, "the client is the last line's, the proxy's")
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

			eng := gin.New()
			eng.Use(ginsec.Middleware(newChain(t, tc.opts...)))
			eng.GET("/r", func(gc *gin.Context) {
				ran = true
				got.client, _ = httpsec.ClientFromContext(gc.Request.Context())
				got.headers = gc.Request.Header.Clone()
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/r", nil)
			req.Host = "app.example.com"
			req.RemoteAddr = tc.peer
			req.Header.Add("X-Forwarded-For", "1.2.3.4")
			req.Header.Add("X-Forwarded-For", "203.0.113.7")
			req.Header.Set("X-Request-Id", "r-1")

			for name, v := range forwarded {
				req.Header.Set(name, v)
			}

			rec := serve(eng, req)
			require.Equal(t, http.StatusOK, rec.Code)
			require.True(t, ran, "the gin handler ran")

			tc.assert(t, got)
		})
	}
}
