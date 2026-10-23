package fibersec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/httpsec"
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
