package fibersec_test

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/httpsec/fibersec"
)

// TestFiber_RouteContextReportsTheUpstreamCause pins that a route behind the
// chain sees the cause an outer middleware gave its cancellation, as a route
// without the chain does, even when the cancel lands while a body streams.
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
