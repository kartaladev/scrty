package fibersec_test

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
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
//
// It stands apart from TestFiberContext: each case builds its own fiber app
// configuration, and reads the address the chain was handed.
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

// TestFiber_ChainContextEndsWithTheRequest pins that the context the chain runs
// on ends when the request's handling ends, as net/http's does when ServeHTTP
// returns, so work an interceptor started on it does not outlive the request.
// The context fiber's own handlers outside the chain read is left alone.
//
// It stands apart from TestFiberContext: it reads the chain's context once the
// request has been handled, from fiber middleware outside the chain.
func TestFiber_ChainContextEndsWithTheRequest(t *testing.T) {
	t.Parallel()

	var (
		kept    context.Context
		outside context.Context
	)

	app := fiber.New()
	app.Use(func(fc fiber.Ctx) error {
		err := fc.Next()
		outside = fc.Context()

		return err
	})
	app.Use(fibersec.Middleware(newChain(t,
		httpsec.RegisterInterceptor(
			httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				kept = ex.Context()

				return next(ex)
			}),
			httpsec.OrderJWKS))))
	app.Get("/orders", func(fc fiber.Ctx) error {
		return fc.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
	res := serve(t, app, req)
	require.Equal(t, http.StatusNoContent, res.status)

	require.NotNil(t, kept, "the interceptor ran")
	assert.Error(t, kept.Err(), "the chain's context is done once the request has been handled")

	require.NotNil(t, outside)
	assert.NoError(t, outside.Err(), "the context code outside the chain reads is not cancelled")
}

// TestFiber_RouteContextSurvivesTheChainWhileTheBodyStreams pins that a route
// behind the chain reads a live request context for as long as its body is
// written. fiber writes a streamed body after the handlers return, so the
// chain's own end-of-request cancellation must not reach the context the route
// holds. The values the chain resolved are still readable there.
//
// It stands apart from TestFiberContext: its route streams a body, read once
// the handlers have returned.
func TestFiber_RouteContextSurvivesTheChainWhileTheBodyStreams(t *testing.T) {
	t.Parallel()

	type key struct{}

	for _, withChain := range []bool{false, true} {
		t.Run(map[bool]string{false: "without the chain", true: "behind the chain"}[withChain], func(t *testing.T) {
			t.Parallel()

			var causeAtStream error

			app := fiber.New()
			if withChain {
				app.Use(fibersec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
							ex.SetContext(context.WithValue(ex.Context(), key{}, "seen"))

							return next(ex)
						}),
						httpsec.OrderJWKS))))
			}

			var value any

			app.Get("/export", func(fc fiber.Ctx) error {
				ctx := fc.Context()
				value = ctx.Value(key{})

				return fc.SendStreamWriter(func(w *bufio.Writer) {
					for range 200000 {
						_, _ = w.WriteString("row-row-row-row-row-row-row-row\n")
					}

					_ = w.Flush()
					causeAtStream = context.Cause(ctx)
				})
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/export", nil)
			res := serve(t, app, req)
			require.Equal(t, http.StatusOK, res.status)
			assert.NoError(t, causeAtStream, "the route's context is alive while its body is written")

			if withChain {
				assert.Equal(t, "seen", value, "a value the chain added is readable behind it")
			}
		})
	}
}

// TestFiber_RouteContextStaysBoundedByWhatBoundedTheRequest pins that the
// context a route reads behind the chain is still bounded by a deadline or a
// cancellation fiber middleware outside the chain set before it, so an upstream
// timeout keeps bounding the route, while the chain's values stay readable.
//
// It stands apart from TestFiberContext: each case bounds the request in fiber
// middleware outside the chain and settles that bound from the route.
func TestFiber_RouteContextStaysBoundedByWhatBoundedTheRequest(t *testing.T) {
	t.Parallel()

	type key struct{}

	type observed struct {
		deadline    time.Time
		hasDeadline bool
		err         error
		value       any
	}

	tests := []struct {
		name   string
		bound  func(ctx context.Context) (context.Context, context.CancelFunc)
		settle func(ctx context.Context, cancel context.CancelFunc)
		assert func(t *testing.T, o observed)
	}{
		{
			name: "an upstream deadline",
			bound: func(ctx context.Context) (context.Context, context.CancelFunc) {
				return context.WithTimeout(ctx, 50*time.Millisecond)
			},
			settle: func(ctx context.Context, _ context.CancelFunc) {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			},
			assert: func(t *testing.T, o observed) {
				t.Helper()
				assert.True(t, o.hasDeadline, "the route sees the deadline the upstream middleware set")
				assert.ErrorIs(t, o.err, context.DeadlineExceeded)
			},
		},
		{
			name: "an upstream cancellation",
			bound: func(ctx context.Context) (context.Context, context.CancelFunc) {
				return context.WithCancel(ctx)
			},
			settle: func(_ context.Context, cancel context.CancelFunc) { cancel() },
			assert: func(t *testing.T, o observed) {
				t.Helper()
				assert.ErrorIs(t, o.err, context.Canceled)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got observed

			app := fiber.New()
			app.Use(func(fc fiber.Ctx) error {
				ctx, cancel := tc.bound(fc.Context())
				defer cancel()

				fc.SetContext(context.WithValue(ctx, cancelKey{}, cancel))

				return fc.Next()
			})
			app.Use(fibersec.Middleware(newChain(t,
				httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
						ex.SetContext(context.WithValue(ex.Context(), key{}, "seen"))

						return next(ex)
					}),
					httpsec.OrderJWKS))))
			app.Get("/orders", func(fc fiber.Ctx) error {
				ctx := fc.Context()
				// The upstream bound is whatever the middleware before the chain
				// set, so the test settles it through the same context.
				cancelOuter := func() {}
				if c, ok := ctx.Value(cancelKey{}).(context.CancelFunc); ok {
					cancelOuter = c
				}

				tc.settle(ctx, cancelOuter)

				got.value = ctx.Value(key{})
				got.err = ctx.Err()
				got.deadline, got.hasDeadline = ctx.Deadline()

				return fc.SendStatus(http.StatusNoContent)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
			res := serve(t, app, req)
			require.Equal(t, http.StatusNoContent, res.status)
			assert.Equal(t, "seen", got.value, "a value the chain added is readable behind it")
			tc.assert(t, got)
		})
	}
}

// cancelKey carries the upstream middleware's cancel function to the route.
type cancelKey struct{}

// TestFiber_OuterMiddlewareSeesWhatTheChainPublished pins that fiber middleware
// mounted before the chain, which is where logging and metrics belong, still
// reads the caller and the session the chain resolved once Next returns, and
// that the context it reads is not cancelled by the chain's end-of-request
// cancellation.
//
// It stands apart from TestFiberContext: it reads from fiber middleware mounted
// before the chain, after Next returns.
func TestFiber_OuterMiddlewareSeesWhatTheChainPublished(t *testing.T) {
	t.Parallel()

	opts, live := authenticated(t)

	var (
		principal    *identity.Principal
		hasPrincipal bool
		sess         *session.Session
		hasSession   bool
		afterErr     error
		afterCause   error
	)

	app := fiber.New()
	app.Use(func(fc fiber.Ctx) error {
		err := fc.Next()

		ctx := fc.Context()
		principal, hasPrincipal = identity.PrincipalFromContext(ctx)
		sess, hasSession = httpsec.SessionFromContext(ctx)
		afterErr = ctx.Err()
		afterCause = context.Cause(ctx)

		return err
	})
	app.Use(fibersec.Middleware(newChain(t, opts...)))
	app.Get("/orders", func(fc fiber.Ctx) error {
		return fc.SendStatus(http.StatusNoContent)
	})

	res := serve(t, app, bearerRequest(t.Context(), http.MethodGet, "/orders"))
	require.Equal(t, http.StatusNoContent, res.status)

	require.True(t, hasPrincipal, "the outer middleware reads the caller the chain published")
	assert.Equal(t, identity.UserID("u-1"), principal.ID)
	require.True(t, hasSession, "the outer middleware reads the session the chain published")
	assert.Equal(t, live.ID, sess.ID)
	assert.NoError(t, afterErr, "the context the outer middleware reads is not cancelled")
	assert.NoError(t, afterCause, "no cause from the chain's cancellation reaches the outer middleware")
}

// TestFiber_RouteContextReportsTheUpstreamCause pins that a route behind the
// chain sees the cause an outer middleware gave its cancellation, as a route
// without the chain does, even when the cancel lands while a body streams.
//
// It stands apart from
// TestFiber_RouteContextSurvivesTheChainWhileTheBodyStreams: an outer
// middleware cancels with a cause while the body streams.
func TestFiber_RouteContextReportsTheUpstreamCause(t *testing.T) {
	t.Parallel()

	errUpstream := errors.New("upstream gave up")

	type testCase struct {
		name      string
		withChain bool
		assert    func(t *testing.T, err, cause error)
	}

	sameAsUpstream := func(t *testing.T, err, cause error) {
		t.Helper()
		assert.ErrorIs(t, err, context.Canceled)
		assert.ErrorIs(t, cause, errUpstream, "the route reports the upstream's cause")
	}

	cases := []testCase{
		{name: "without the chain", assert: sameAsUpstream},
		{name: "behind the chain", withChain: true, assert: sameAsUpstream},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				errAt, causeAt error
				cancel         context.CancelCauseFunc
			)

			app := fiber.New()
			app.Use(func(fc fiber.Ctx) error {
				var ctx context.Context
				ctx, cancel = context.WithCancelCause(fc.Context())
				fc.SetContext(ctx)

				return fc.Next()
			})
			if tc.withChain {
				app.Use(fibersec.Middleware(newChain(t)))
			}
			app.Get("/export", func(fc fiber.Ctx) error {
				ctx := fc.Context()

				return fc.SendStreamWriter(func(w *bufio.Writer) {
					_, _ = w.WriteString("x\n")
					cancel(errUpstream)
					errAt, causeAt = ctx.Err(), context.Cause(ctx)
				})
			})

			_ = serve(t, app, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/export", nil))
			tc.assert(t, errAt, causeAt)
		})
	}
}
