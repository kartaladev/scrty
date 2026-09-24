package ginsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ginsec"
	"github.com/kartaladev/scrty/httpsec"
)

// TestGinClientIP pins the one thing the adapter decides about attribution:
// which address it hands the chain. What the chain then does with an address it
// cannot attribute is the chain's own rule, applied identically behind every
// framework, so nothing here reimplements it.
func TestGinClientIP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// opts are the adapter options under test.
		opts []ginsec.Option

		// trustedProxies is what the consumer told gin to trust, and nil means
		// the consumer told it nothing — which is gin's trust-every-proxy
		// default.
		trustedProxies []string

		// peer is the transport peer, and forwarded is what the client put in
		// the forwarding header.
		peer      string
		forwarded string

		assert func(t *testing.T, addr string)
	}

	cases := []testCase{
		{
			name:      "the default ignores a forwarding header",
			peer:      "198.51.100.7:51234",
			forwarded: "203.0.113.9",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, "198.51.100.7", addr,
					"the peer is the one address the client cannot choose")
			},
		},
		{
			name:           "the opt-in takes the address gin's trusted proxy forwarded",
			opts:           []ginsec.Option{ginsec.WithForwardedClientIP()},
			trustedProxies: []string{"10.0.0.2"},
			peer:           "10.0.0.2:41000",
			forwarded:      "198.51.100.7",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, "198.51.100.7", addr)
			},
		},
		{
			name:           "the opt-in still ignores a header from a peer gin does not trust",
			opts:           []ginsec.Option{ginsec.WithForwardedClientIP()},
			trustedProxies: []string{"10.0.0.2"},
			peer:           "198.51.100.7:51234",
			forwarded:      "203.0.113.9",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, "198.51.100.7", addr)
			},
		},
		{
			// The hazard the option's godoc names, pinned rather than described:
			// with gin told to trust nothing in particular, it trusts every
			// proxy, so the client's own header decides.
			name:      "the opt-in before trusted proxies are set lets the client choose",
			opts:      []ginsec.Option{ginsec.WithForwardedClientIP()},
			peer:      "198.51.100.7:51234",
			forwarded: "203.0.113.9",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, "203.0.113.9", addr,
					"set the trusted proxy list before enabling the option")
			},
		},
		{
			name: "an address gin cannot attribute is passed on as none",
			opts: []ginsec.Option{ginsec.WithForwardedClientIP()},
			peer: "@",
			assert: func(t *testing.T, addr string) {
				assert.Empty(t, addr,
					"nothing is invented here: refusing an unattributable address is the chain's rule")
			},
		},
		{
			name: "the default reports no address for a peer that is not a network client",
			peer: "@",
			assert: func(t *testing.T, addr string) {
				assert.Empty(t, addr)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := &served{}

			eng := gin.New()
			if tc.trustedProxies != nil {
				require.NoError(t, eng.SetTrustedProxies(tc.trustedProxies))
			}

			eng.Use(ginsec.Middleware(
				newChain(t, httpsec.RegisterInterceptor(observing(out), httpsec.OrderJWKS)),
				tc.opts...))
			eng.GET("/reports", out.route())

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/reports", nil)
			req.RemoteAddr = tc.peer

			if tc.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tc.forwarded)
			}

			out.rec = serve(eng, req)

			require.True(t, out.routeRan, "the chain passed the request through")
			tc.assert(t, out.clientAddr)
		})
	}
}
