package fibersec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/httpsec"
)

// TestFiber_ErrorHandlerKeepsNonRefusalStatuses pins that an error a route, or
// fiber's own router, returns behind the chain keeps its own status through
// fibersec.ErrorHandler, and that a refusal still gets its mapped one.
func TestFiber_ErrorHandlerKeepsNonRefusalStatuses(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options []httpsec.Option
		path    string
		assert  func(t *testing.T, res response)
	}

	cases := []testCase{
		{
			name: "a route's own 422 is answered as 422",
			path: "/item",
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusUnprocessableEntity, res.status)
				assert.Empty(t, res.body, "the bare-status handler writes no body")
			},
		},
		{
			name: "an unrouted path is answered as 404",
			path: "/nowhere",
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusNotFound, res.status)
			},
		},
		{
			name:    "a refusal still gets its mapped status",
			options: []httpsec.Option{httpsec.RegisterInterceptor(refusing(authorize.ErrAuthenticationRequired, nil), httpsec.OrderBearerToken)},
			path:    "/item",
			assert: func(t *testing.T, res response) {
				assert.Equal(t, http.StatusUnauthorized, res.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(newChain(t, tc.options...)))
			app.Get("/item", func(fiber.Ctx) error {
				return fiber.NewError(http.StatusUnprocessableEntity, "bad item")
			})

			tc.assert(t, serve(t, app, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil)))
		})
	}
}

// TestFiber_DefaultErrorHandlerKeepsRouteErrorText pins that on an app using
// fiber's built-in error handler a route's own error is answered with its own
// status and text, as it would be without the chain.
func TestFiber_DefaultErrorHandlerKeepsRouteErrorText(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Use(fibersec.Middleware(newChain(t)))
	app.Get("/item", func(fiber.Ctx) error {
		return fiber.NewError(http.StatusUnprocessableEntity, "bad item")
	})

	res := serve(t, app, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/item", nil))

	assert.Equal(t, http.StatusUnprocessableEntity, res.status)
	assert.Equal(t, "bad item", res.body)
}
