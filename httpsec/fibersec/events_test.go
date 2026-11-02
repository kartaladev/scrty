package fibersec_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/security"
)

// TestSecurityEvents_FiberGuardDenied pins that a fiber route guard behind
// the chain reports its authorization denial to the chain's sink as
// authz_fail, naming the caller, and reports nothing for an authorizer that
// could not answer.
func TestSecurityEvents_FiberGuardDenied(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		judged error
		assert func(t *testing.T, events []security.Event, status int)
	}

	cases := []testCase{
		{
			name:   "a denial is reported, naming the caller",
			judged: fmt.Errorf("%w: not yours", authorize.ErrAccessDenied),
			assert: func(t *testing.T, events []security.Event, status int) {
				assert.Equal(t, http.StatusForbidden, status)
				require.Len(t, events, 1)
				assert.Equal(t, security.AuthzFail, events[0].Name)
				assert.Equal(t, identity.UserID("u-1"), events[0].User)
				assert.Equal(t, security.OutcomeFailure, events[0].Outcome)
			},
		},
		{
			name:   "an authorizer that could not answer reports nothing",
			judged: errors.New("test: the authorizer is down"),
			assert: func(t *testing.T, events []security.Event, status int) {
				assert.Equal(t, http.StatusInternalServerError, status)
				assert.Empty(t, events)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				mu     sync.Mutex
				events []security.Event
			)

			sink := func(_ context.Context, e security.Event) {
				mu.Lock()
				defer mu.Unlock()

				events = append(events, e)
			}

			opts, _ := authenticated(t)
			g := mustGuards(t, refusingAuthorizer(t, tc.judged))

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(newChain(t, append(opts, httpsec.EnableSecurityEvents(sink))...)))
			app.Get("/invoices", g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
				func(fiber.Ctx) error {
					t.Error("the route must not run")

					return nil
				})

			res := serve(t, app, bearerRequest(t.Context(), http.MethodGet, "/invoices"))

			mu.Lock()
			defer mu.Unlock()

			tc.assert(t, events, res.status)
		})
	}
}
