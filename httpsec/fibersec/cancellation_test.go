package fibersec_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestFiber_ChainContextEndsWithTheRequest pins that the context the chain runs
// on ends when the request's handling ends, as net/http's does when ServeHTTP
// returns, so work an interceptor started on it does not outlive the request.
// The context fiber's own handlers outside the chain read is left alone.
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
