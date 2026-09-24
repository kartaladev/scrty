package fibersec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// routeRead is what the fiber route behind the chain read out of the handler
// context's request context.
//
// It is recorded inside the request and asserted after it, because fiber
// recycles its context the moment the request ends.
type routeRead struct {
	ran bool

	principal     *identity.Principal
	hasPrincipal  bool
	auth          *authenticate.Authentication
	hasAuth       bool
	sess          *session.Session
	hasSession    bool
	hasAuthorizer bool

	trace any
}

// reading is the fiber route the context tests put behind the chain. It reads
// everything the chain publishes, the way a consumer's own handler would.
func reading(out *routeRead) fiber.Handler {
	return func(fc fiber.Ctx) error {
		ctx := fc.Context()

		out.ran = true
		out.principal, out.hasPrincipal = identity.PrincipalFromContext(ctx)
		out.auth, out.hasAuth = authenticate.AuthenticationFromContext(ctx)
		out.sess, out.hasSession = httpsec.SessionFromContext(ctx)
		_, out.hasAuthorizer = authorize.AuthorizerFromContext(ctx)
		out.trace = ctx.Value(traceKey{})

		return fc.SendStatus(http.StatusNoContent)
	}
}

// tracing is fiber middleware outside the chain that puts a value on the
// request context before the chain ever sees it.
func tracing(id string) fiber.Handler {
	return func(fc fiber.Ctx) error {
		fc.SetContext(context.WithValue(fc.Context(), traceKey{}, id))

		return fc.Next()
	}
}

// TestFiberContext pins that everything the chain resolved reaches a fiber
// route through the handler context's request context, and that what was on
// that context before the chain is still there behind it.
func TestFiberContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// options builds the chain under test.
		options func(t *testing.T) []httpsec.Option

		// before is fiber middleware registered ahead of the chain.
		before []fiber.Handler

		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, out routeRead)
	}

	cases := []testCase{
		{
			name: "the route reads the principal an interceptor published",
			options: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(
					publishing(testPrincipal()), httpsec.OrderBearerToken)}
			},
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
			},
			assert: func(t *testing.T, out routeRead) {
				require.True(t, out.hasPrincipal,
					"a fiber route reads the caller through the handler context")
				assert.Equal(t, identity.UserID("u-1"), out.principal.ID)
			},
		},
		{
			name: "an upstream trace identifier survives the chain",
			options: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(
					publishing(testPrincipal()), httpsec.OrderBearerToken)}
			},
			before: []fiber.Handler{tracing("t-1")},
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/orders", nil)
			},
			assert: func(t *testing.T, out routeRead) {
				assert.Equal(t, "t-1", out.trace,
					"the chain derives the context it was seeded with, never replaces it")
				assert.True(t, out.hasPrincipal,
					"and what the chain added is there beside it")
			},
		},
		{
			name: "everything a first factor resolved reaches the route",
			options: func(t *testing.T) []httpsec.Option {
				t.Helper()

				az := NewMockAuthorizer(gomock.NewController(t))
				az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				opts, _ := authenticated(t)

				return append(opts, httpsec.EnableAuthorization(az))
			},
			request: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, http.MethodGet, "/orders")
			},
			assert: func(t *testing.T, out routeRead) {
				require.True(t, out.hasPrincipal)
				assert.Equal(t, identity.UserID("u-1"), out.principal.ID)

				require.True(t, out.hasAuth, "the route reads what authenticated the request")
				assert.Same(t, out.principal, out.auth.Principal)

				require.True(t, out.hasSession, "and the session the chain resolved")
				assert.Equal(t, "u-1", string(out.sess.UserID))

				assert.True(t, out.hasAuthorizer,
					"and the judge every guard behind the route asks")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out routeRead

			app := fiber.New()
			for _, mw := range tc.before {
				app.Use(mw)
			}

			app.Use(fibersec.Middleware(newChain(t, tc.options(t)...)))
			app.Get("/orders", reading(&out))

			res := serve(t, app, tc.request(t.Context()))
			require.Equal(t, http.StatusNoContent, res.status)
			require.True(t, out.ran, "the chain passed the request through to the route")

			tc.assert(t, out)
		})
	}
}

// TestFiberClientIP pins the one thing the adapter decides about attribution:
// which address it hands the chain. It is fiber's own, so what a deployment
// gets depends entirely on fiber's proxy trust, and the rows are the
// configurations the package documentation tells a consumer to use.
//
// What the chain then does with an address it cannot attribute is the chain's
// own rule, applied identically behind every framework, so nothing here
// reimplements it.
func TestFiberClientIP(t *testing.T) {
	t.Parallel()

	// inMemoryPeer is what fiber's in-memory test transport reports as the
	// peer. It is the unspecified address, which names no client at all.
	const inMemoryPeer = "0.0.0.0"

	type testCase struct {
		name      string
		config    fiber.Config
		forwarded string
		assert    func(t *testing.T, addr string)
	}

	cases := []testCase{
		{
			name:      "with no proxy trust the in-memory transport names no client",
			forwarded: "203.0.113.9",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, inMemoryPeer, addr,
					"the forwarding header is ignored until the consumer trusts a proxy")

				parsed, err := netip.ParseAddr(addr)
				require.NoError(t, err)
				assert.True(t, parsed.IsUnspecified(),
					"the chain refuses such an address rather than pooling every "+
						"caller behind it into one rate-limit bucket")
			},
		},
		{
			name: "a trusted proxy's forwarded address is used",
			config: fiber.Config{
				TrustProxy: true,
				// 0.0.0.0 is in the list because fiber's in-memory transport
				// reports that peer, which is also what a proxy reaching the
				// app over a Unix socket looks like.
				TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: []string{"10.0.0.2", inMemoryPeer}},
				ProxyHeader:        fiber.HeaderXForwardedFor,
				EnableIPValidation: true,
			},
			forwarded: "198.51.100.7",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, "198.51.100.7", addr)
			},
		},
		{
			name: "a header from a peer the consumer did not trust is ignored",
			config: fiber.Config{
				TrustProxy:         true,
				TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: []string{"10.0.0.2"}},
				ProxyHeader:        fiber.HeaderXForwardedFor,
				EnableIPValidation: true,
			},
			forwarded: "198.51.100.7",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, inMemoryPeer, addr,
					"a client cannot name its own address through an untrusted peer")
			},
		},
		{
			name: "trusting a proxy without naming the header changes nothing",
			config: fiber.Config{
				TrustProxy:       true,
				TrustProxyConfig: fiber.TrustProxyConfig{Proxies: []string{inMemoryPeer}},
			},
			forwarded: "198.51.100.7",
			assert: func(t *testing.T, addr string) {
				assert.Equal(t, inMemoryPeer, addr,
					"fiber reads no forwarding header until ProxyHeader names one")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				addr string
				seen bool
			)

			app := fiber.New(tc.config)
			app.Use(fibersec.Middleware(newChain(t,
				httpsec.RegisterInterceptor(
					inspecting(func(r httpsec.Request) { addr, seen = r.ClientIP(), true }),
					httpsec.OrderJWKS))))
			app.Get("/orders", func(fc fiber.Ctx) error {
				return fc.SendStatus(http.StatusNoContent)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
			if tc.forwarded != "" {
				req.Header.Set(fiber.HeaderXForwardedFor, tc.forwarded)
			}

			res := serve(t, app, req)
			require.Equal(t, http.StatusNoContent, res.status)
			require.True(t, seen, "the chain was handed the request's address")

			tc.assert(t, addr)
		})
	}
}
