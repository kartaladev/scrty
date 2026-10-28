package fibersec_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute pins
// that a route marked for the recovery cool-down stays refused under every
// spelling fiber's default routing sends to it: letter case and trailing
// slashes are the same route to fiber, so they must be to the cool-down.
func TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, res response, routeRan bool)
	}

	refused := func(t *testing.T, res response, routeRan bool) {
		t.Helper()

		assert.Equal(t, http.StatusForbidden, res.status)
		assert.False(t, routeRan, "the marked route did not run during the cool-down")
	}

	cases := []testCase{
		{name: "the marked spelling", path: "/account/email", assert: refused},
		{name: "upper case", path: "/Account/Email", assert: refused},
		{name: "one trailing slash", path: "/account/email/", assert: refused},
		{name: "two trailing slashes", path: "/account/email//", assert: refused},
		{
			name: "a route that is not marked is served",
			path: "/account/name",
			assert: func(t *testing.T, res response, _ bool) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, res.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			records := recovery.NewMemoryRecordStore()

			rid, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			completedAt := time.Now().Add(-time.Hour)
			require.NoError(t, records.Insert(t.Context(), recovery.Record{
				ID: rid, User: "u-1", StartedAt: completedAt, NotBefore: completedAt, CompletedAt: completedAt,
			}))

			opts, _ := authenticated(t)
			opts = append(opts, httpsec.EnableRecoveryCooldown(
				records, 48*time.Hour, httpsec.Route{Method: http.MethodGet, Path: "/account/email"}))

			var routeRan bool

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(newChain(t, opts...)))

			handler := func(fc fiber.Ctx) error {
				routeRan = true

				return fc.SendStatus(http.StatusNoContent)
			}
			app.Get("/account/email", handler)
			app.Get("/account/name", handler)

			res := serve(t, app, bearerRequest(t.Context(), http.MethodGet, tc.path))

			tc.assert(t, res, routeRan)
		})
	}
}
