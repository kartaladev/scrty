package ginsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

// TestGin_AccessTokenGuards pins the gin guards for a caller a resource server authenticated to the
// core guards (design 14, 16): a missing scope is 403 with one insufficient_scope challenge naming
// the scopes, and a stale or auth_time-less token at a recency guard is 401 with one
// insufficient_user_authentication challenge carrying max_age, the refusal reaching gin's error
// channel as every gin guard refusal does.
func TestGin_AccessTokenGuards(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name     string
		scope    string
		authTime time.Time

		// staleSession presents a live session, not a token, judged an hour after it authenticated, on a route outside the resource server's prefix.
		staleSession bool

		guard  func(t *testing.T, g *ginsec.Guards) gin.HandlerFunc
		assert func(t *testing.T, rec *httptest.ResponseRecorder, errs []error, routeRan bool)
	}

	requiring := func(req authorize.Requirement) func(t *testing.T, g *ginsec.Guards) gin.HandlerFunc {
		return func(t *testing.T, g *ginsec.Guards) gin.HandlerFunc {
			t.Helper()

			h, err := g.Require(req)
			require.NoError(t, err)

			return h
		}
	}

	recent := func(_ *testing.T, g *ginsec.Guards) gin.HandlerFunc { return g.RequireRecentAuthentication() }

	stale := func(t *testing.T, rec *httptest.ResponseRecorder, errs []error, routeRan bool) {
		t.Helper()
		assert.False(t, routeRan)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, []string{`Bearer error="insufficient_user_authentication", max_age=900`},
			rec.Header().Values("WWW-Authenticate"), "exactly one challenge")
		require.Len(t, errs, 1)
		require.ErrorIs(t, errs[0], httpsec.ErrInsufficientUserAuthentication)
		require.ErrorIs(t, errs[0], httpsec.ErrReauthenticationRequired)

		var refusal *httpsec.InsufficientUserAuthenticationError
		require.ErrorAs(t, errs[0], &refusal)
		assert.Equal(t, 15*time.Minute, refusal.Window)
	}

	passes := func(t *testing.T, rec *httptest.ResponseRecorder, errs []error, routeRan bool) {
		t.Helper()
		assert.True(t, routeRan)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, errs)
	}

	cases := []testCase{
		{
			name:  "a missing scope is 403 with one insufficient_scope challenge",
			scope: "orders:read",
			guard: requiring(authorize.HasAllScopes("orders:read", "orders:export")),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, errs []error, routeRan bool) {
				assert.False(t, routeRan)
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Equal(t, []string{`Bearer error="insufficient_scope", scope="orders:read orders:export"`},
					rec.Header().Values("WWW-Authenticate"), "exactly one challenge")
				require.Len(t, errs, 1)
				assert.ErrorIs(t, errs[0], httpsec.ErrInsufficientScope)

				var missing *authorize.MissingScopesError
				assert.ErrorAs(t, errs[0], &missing)
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
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, errs []error, routeRan bool) {
				t.Helper()
				assert.False(t, routeRan)
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Empty(t, rec.Header().Values("WWW-Authenticate"))
				assert.Empty(t, rec.Body.String())
				require.Len(t, errs, 1)
				require.ErrorIs(t, errs[0], httpsec.ErrReauthenticationRequired)
				assert.NotErrorIs(t, errs[0], httpsec.ErrInsufficientUserAuthentication)
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

			var guardClock ginsec.GuardOption = ginsec.WithGuardClock(iss.clk)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/api/orders", nil)
			if tc.staleSession {
				sessionOpts, live := authenticated(t)
				chainOpts = append(sessionOpts, iss.opts...)
				path = "/invoices"
				guardClock = ginsec.WithGuardClock(fixedClock{at: live.AuthenticatedAt.Add(time.Hour)})
				req = bearerRequest(t.Context(), http.MethodGet, path)
			} else {
				req.Header.Set("Authorization", "Bearer "+iss.token(t, tc.scope, tc.authTime))
			}

			g := mustGuards(t, deciding(t, nil), guardClock)

			var (
				errs     []error
				routeRan bool
			)

			eng := gin.New()
			eng.Use(func(gc *gin.Context) {
				gc.Next()

				for _, e := range gc.Errors {
					errs = append(errs, e.Err)
				}
			})

			eng.Use(ginsec.Middleware(newChain(t, chainOpts...)))
			eng.GET(path, tc.guard(t, g), func(gc *gin.Context) {
				routeRan = true
				gc.Status(http.StatusOK)
			})

			tc.assert(t, serve(eng, req), errs, routeRan)
		})
	}
}
