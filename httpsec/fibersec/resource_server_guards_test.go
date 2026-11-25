package fibersec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
)

// TestFiber_AccessTokenGuards pins the fiber guards for a caller a resource server authenticated to
// the core guards (design 14, 16): a missing scope is 403 with one insufficient_scope challenge
// naming the scopes, and a stale or auth_time-less token at a recency guard is 401 with one
// insufficient_user_authentication challenge carrying max_age, the refusal reaching fiber's error
// handler as every fiber guard refusal does.
func TestFiber_AccessTokenGuards(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name     string
		scope    string
		authTime time.Time

		// staleSession presents a live session, not a token, judged an hour after it authenticated, on a route outside the resource server's prefix.
		staleSession bool

		guard  func(t *testing.T, g *fibersec.Guards) fiber.Handler
		assert func(t *testing.T, res response, handled error, routeRan bool)
	}

	requiring := func(req authorize.Requirement) func(t *testing.T, g *fibersec.Guards) fiber.Handler {
		return func(t *testing.T, g *fibersec.Guards) fiber.Handler {
			t.Helper()

			h, err := g.Require(req)
			require.NoError(t, err)

			return h
		}
	}

	recent := func(_ *testing.T, g *fibersec.Guards) fiber.Handler { return g.RequireRecentAuthentication() }

	stale := func(t *testing.T, res response, handled error, routeRan bool) {
		t.Helper()
		assert.False(t, routeRan)
		assert.Equal(t, http.StatusUnauthorized, res.status)
		assert.Equal(t, []string{`Bearer error="insufficient_user_authentication", max_age=900`},
			res.header.Values("WWW-Authenticate"), "exactly one challenge")
		assert.Empty(t, res.body)
		require.ErrorIs(t, handled, httpsec.ErrInsufficientUserAuthentication)
		require.ErrorIs(t, handled, httpsec.ErrReauthenticationRequired)

		var refusal *httpsec.InsufficientUserAuthenticationError
		require.ErrorAs(t, handled, &refusal)
		assert.Equal(t, 15*time.Minute, refusal.Window)
	}

	passes := func(t *testing.T, res response, handled error, routeRan bool) {
		t.Helper()
		assert.True(t, routeRan)
		assert.Equal(t, http.StatusOK, res.status)
		assert.NoError(t, handled)
	}

	cases := []testCase{
		{
			name:  "a missing scope is 403 with one insufficient_scope challenge",
			scope: "orders:read",
			guard: requiring(authorize.HasAllScopes("orders:read", "orders:export")),
			assert: func(t *testing.T, res response, handled error, routeRan bool) {
				assert.False(t, routeRan)
				assert.Equal(t, http.StatusForbidden, res.status)
				assert.Equal(t, []string{`Bearer error="insufficient_scope", scope="orders:read orders:export"`},
					res.header.Values("WWW-Authenticate"), "exactly one challenge")
				assert.ErrorIs(t, handled, httpsec.ErrInsufficientScope)

				var missing *authorize.MissingScopesError
				assert.ErrorAs(t, handled, &missing)
			},
		},
		{
			name:   "a granted scope passes",
			scope:  "orders:read",
			guard:  requiring(authorize.HasAnyScope("orders:read")),
			assert: passes,
		},
		{
			name:     "a stale access token is 401 with max_age",
			scope:    "orders:read",
			authTime: now.Add(-20 * time.Minute),
			guard:    recent,
			assert:   stale,
		},
		{
			name:   "an access token without auth_time is stale",
			scope:  "orders:read",
			guard:  recent,
			assert: stale,
		},
		{
			name:         "a stale session is still 403 with no body and no challenge",
			staleSession: true,
			guard:        recent,
			assert: func(t *testing.T, res response, handled error, routeRan bool) {
				t.Helper()
				assert.False(t, routeRan)
				assert.Equal(t, http.StatusForbidden, res.status)
				assert.Empty(t, res.header.Values("WWW-Authenticate"))
				assert.Empty(t, res.body)
				require.ErrorIs(t, handled, httpsec.ErrReauthenticationRequired)
				assert.NotErrorIs(t, handled, httpsec.ErrInsufficientUserAuthentication)
			},
		},
		{
			name:     "a fresh access token passes",
			scope:    "orders:read",
			authTime: now.Add(-10 * time.Minute),
			guard:    recent,
			assert:   passes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			iss := newRSIssuer(t, now)
			chainOpts := iss.opts
			path := "/api/orders"

			guardClock := fibersec.WithGuardClock(iss.clk)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/api/orders", nil)
			if tc.staleSession {
				sessionOpts, live := authenticated(t)
				chainOpts = append(sessionOpts, iss.opts...)
				path = "/invoices"
				guardClock = fibersec.WithGuardClock(&sessionClock{now: live.AuthenticatedAt.Add(time.Hour)})
				req = bearerRequest(t.Context(), http.MethodGet, path)
			} else {
				req.Header.Set("Authorization", "Bearer "+iss.token(t, tc.scope, tc.authTime))
			}

			g := mustGuards(t, permittingAuthorizer(t), guardClock)

			var (
				handled  error
				routeRan bool
			)

			app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
				handled = err

				return fibersec.ErrorHandler(c, err)
			}})

			app.Use(fibersec.Middleware(newChain(t, chainOpts...)))
			app.Get(path, tc.guard(t, g), func(c fiber.Ctx) error {
				routeRan = true

				return c.SendStatus(http.StatusOK)
			})

			tc.assert(t, serveFrom(t, app, req, referencePeer), handled, routeRan)
		})
	}
}
