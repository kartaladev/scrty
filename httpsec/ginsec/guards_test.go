package ginsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
)

// deciding is an authorizer that answers every question with err, so a case
// says what the judge decided and nothing else.
func deciding(t *testing.T, err error) *MockAuthorizer {
	t.Helper()

	az := NewMockAuthorizer(gomock.NewController(t))
	az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(err).AnyTimes()

	return az
}

// mustGuards builds gin guards a test needs to exist, failing the test when
// the wiring it was handed is refused.
func mustGuards(t *testing.T, az authorize.Authorizer, opts ...ginsec.GuardOption) *ginsec.Guards {
	t.Helper()

	g, err := ginsec.NewGuards(az, opts...)
	require.NoError(t, err)

	return g
}

// TestGin_NewGuards_Authorizer pins that gin guards follow the core guards'
// construction rule: an authorizer, a declared reliance on the chain's, or
// both, and a refusal at construction for neither.
func TestGin_NewGuards_Authorizer(t *testing.T) {
	t.Parallel()

	var typedNil *MockAuthorizer

	errBuiltIn := errors.New("guards_test: the built-in authorizer was asked")

	// guarded serves one request through a gin chain that publishes the test
	// principal, with opts added to the chain, onto a route behind g's guard.
	guarded := func(t *testing.T, g *ginsec.Guards, out *served, opts ...httpsec.Option) {
		t.Helper()

		eng := gin.New()
		eng.Use(ginsec.Middleware(newChain(t, append([]httpsec.Option{
			httpsec.RegisterInterceptor(publishing(testPrincipal()), httpsec.OrderBearerToken),
		}, opts...)...)))
		eng.GET("/invoices", g.ResourcePrivileges("billing", "invoice").RequireOne("read"), out.route())

		require.NotPanics(t, func() {
			out.rec = serve(eng, httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, "/invoices", nil))
		}, "a guard never calls a method on a nil authorizer")
	}

	type testCase struct {
		name   string
		az     func(t *testing.T) authorize.Authorizer
		opts   []ginsec.GuardOption
		assert func(t *testing.T, g *ginsec.Guards, err error, refusal *error)
	}

	cases := []testCase{
		{
			name: "nil authorizer",
			az:   func(*testing.T) authorize.Authorizer { return nil },
			assert: func(t *testing.T, g *ginsec.Guards, err error, _ *error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, g)
			},
		},
		{
			name: "typed-nil authorizer",
			az:   func(*testing.T) authorize.Authorizer { return typedNil },
			assert: func(t *testing.T, g *ginsec.Guards, err error, _ *error) {
				require.ErrorIs(t, err, httpsec.ErrConfig,
					"an interface holding a nil value is no authorizer")
				assert.Nil(t, g)
			},
		},
		{
			name: "gin guards rely on the chain",
			az:   func(*testing.T) authorize.Authorizer { return nil },
			opts: []ginsec.GuardOption{ginsec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *ginsec.Guards, err error, refusal *error) {
				require.NoError(t, err)

				chainAz := NewMockAuthorizer(gomock.NewController(t))
				chainAz.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil).Times(1)

				out := &served{}
				guarded(t, g, out, httpsec.EnableAuthorization(chainAz))

				require.NoError(t, *refusal)
				assert.True(t, out.routeRan, "the guard judged with the chain's authorizer")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "typed nil beside declared reliance",
			az:   func(*testing.T) authorize.Authorizer { return typedNil },
			opts: []ginsec.GuardOption{ginsec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *ginsec.Guards, err error, refusal *error) {
				require.NoError(t, err)

				out := &served{}
				guarded(t, g, out)

				require.ErrorIs(t, *refusal, authorize.ErrAccessDenied)
				assert.False(t, out.routeRan)
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
			},
		},
		{
			name: "declared reliance, no chain authorizer",
			az:   func(*testing.T) authorize.Authorizer { return nil },
			opts: []ginsec.GuardOption{ginsec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *ginsec.Guards, err error, refusal *error) {
				require.NoError(t, err)

				out := &served{}
				guarded(t, g, out)

				require.ErrorIs(t, *refusal, authorize.ErrAccessDenied)
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "both given",
			az:   func(t *testing.T) authorize.Authorizer { return deciding(t, errBuiltIn) },
			opts: []ginsec.GuardOption{ginsec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *ginsec.Guards, err error, refusal *error) {
				require.NoError(t, err)

				preferred := &served{}
				guarded(t, g, preferred, httpsec.EnableAuthorization(deciding(t, nil)))
				assert.True(t, preferred.routeRan,
					"the request's authorizer is preferred over the one built in")

				fallback := &served{}
				guarded(t, g, fallback)
				assert.False(t, fallback.routeRan,
					"the one built in is the fallback when the request carries none")
				require.ErrorIs(t, *refusal, errBuiltIn)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Every row's refusal is captured and answered with the status the
			// default would set, so a row names what it was refused with.
			var refusal error

			capturing := ginsec.WithGuardErrorHandler(func(gc *gin.Context, err error) {
				refusal = err
				gc.Status(httpsec.StatusForError(err))
			})

			g, err := ginsec.NewGuards(tc.az(t), append([]ginsec.GuardOption{capturing}, tc.opts...)...)
			tc.assert(t, g, err, &refusal)
		})
	}
}

// TestGinGuards pins that a per-endpoint guard on gin refuses the way the chain
// does: the refusal on gin's error channel, the mapped status set but not
// committed, and the route never reached.
func TestGinGuards(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, out *served) *gin.Engine
		assert func(t *testing.T, out *served)
	}

	cases := []testCase{
		{
			// Registering the refusal and aborting alone would answer 200 here,
			// which is a refusal served as a success.
			name: "a guard refuses with no error middleware",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, nil, ginsec.WithChainAuthorizer())

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						publishing(testPrincipal()), httpsec.OrderBearerToken),
					httpsec.EnableAuthorization(deciding(t, authorize.ErrAccessDenied)))))
				eng.GET("/invoices",
					g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "the guard's refusal is on gin's error channel",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, nil, ginsec.WithChainAuthorizer())

				eng := gin.New()
				eng.Use(out.collecting())
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						publishing(testPrincipal()), httpsec.OrderBearerToken),
					httpsec.EnableAuthorization(deciding(t, authorize.ErrAccessDenied)))))
				eng.GET("/invoices",
					g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				require.Len(t, out.ginErrors, 1)
				assert.ErrorIs(t, out.ginErrors[0], authorize.ErrAccessDenied)
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
			},
		},
		{
			name: "consumer error middleware renders the guard's refusal",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, nil, ginsec.WithChainAuthorizer())

				eng := gin.New()
				eng.Use(rendering(http.StatusTeapot, "application/problem+json", `{"detail":"no"}`))
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						publishing(testPrincipal()), httpsec.OrderBearerToken),
					httpsec.EnableAuthorization(deciding(t, authorize.ErrAccessDenied)))))
				eng.GET("/invoices",
					g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				res := out.rec.Result()
				defer func() { _ = res.Body.Close() }()

				assert.Equal(t, http.StatusTeapot, res.StatusCode)
				assert.Equal(t, "application/problem+json", res.Header.Get("Content-Type"))
				assert.JSONEq(t, `{"detail":"no"}`, out.rec.Body.String())
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "a guard judges by the authorizer the chain published",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				// Nothing of its own: the judge can only be the chain's.
				g := mustGuards(t, nil, ginsec.WithChainAuthorizer())

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						publishing(testPrincipal()), httpsec.OrderBearerToken),
					httpsec.EnableAuthorization(deciding(t, nil)))))
				eng.GET("/invoices",
					g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.True(t, out.routeRan)
			},
		},
		{
			name: "a request with no caller is told to authenticate",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, deciding(t, nil))

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t)))
				eng.GET("/invoices", g.RequireAuthenticated(), out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusUnauthorized, out.rec.Code)
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "a guard that found no judge refuses",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, nil, ginsec.WithChainAuthorizer())

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, httpsec.RegisterInterceptor(
					publishing(testPrincipal()), httpsec.OrderBearerToken))))
				eng.GET("/invoices", g.RequireAuthenticated(), out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.False(t, out.routeRan, "a route whose wiring is incomplete is shut")
			},
		},
		{
			name: "an authorizer that is a typed nil is no judge",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, (*MockAuthorizer)(nil), ginsec.WithChainAuthorizer())

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, httpsec.RegisterInterceptor(
					publishing(testPrincipal()), httpsec.OrderBearerToken))))
				eng.GET("/invoices", g.RequireAuthenticated(), out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "a consumer's guard error handler owns the answer",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, nil, ginsec.WithChainAuthorizer(), ginsec.WithGuardErrorHandler(
					func(gc *gin.Context, err error) {
						gc.Data(http.StatusTeapot, "application/problem+json",
							[]byte(`{"status":`+http.StatusText(httpsec.StatusForError(err))+`}`))
					}))

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						publishing(testPrincipal()), httpsec.OrderBearerToken),
					httpsec.EnableAuthorization(deciding(t, authorize.ErrAccessDenied)))))
				eng.GET("/invoices",
					g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				res := out.rec.Result()
				defer func() { _ = res.Body.Close() }()

				assert.Equal(t, http.StatusTeapot, res.StatusCode)
				assert.Equal(t, "application/problem+json", res.Header.Get("Content-Type"))
				assert.Contains(t, out.rec.Body.String(), "Forbidden")
				assert.False(t, out.routeRan, "the route is skipped whoever writes the answer")
			},
		},
		{
			name: "an ownership guard refuses a record the caller does not own",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				g := mustGuards(t, nil, ginsec.WithChainAuthorizer())
				own := ginsec.ResourceOwnerships(g, "billing", "invoice",
					func(_ context.Context, _ *identity.Principal, _ string) (bool, error) {
						return false, nil
					})

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						publishing(testPrincipal()), httpsec.OrderBearerToken),
					httpsec.EnableAuthorization(deciding(t, authorize.ErrAccessDenied)))))
				eng.GET("/invoices",
					own.ForResource(func(r httpsec.Request) (string, error) {
						return r.Query("id"), nil
					}),
					out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.False(t, out.routeRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := &served{}
			eng := tc.build(t, out)
			out.rec = serve(eng, httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, "/invoices?id=inv-1", nil))

			tc.assert(t, out)
		})
	}
}

// ownedByAnyone is a checker that is never reached: the wiring cases fail first.
func ownedByAnyone(context.Context, *identity.Principal, string) (bool, error) { return true, nil }

// TestGin_OwnershipGuardFailsAtWiring pins that a guard built without what
// it cannot work without panics when it is wired, naming the missing
// dependency, instead of refusing every request once traffic arrives.
func TestGin_OwnershipGuardFailsAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "with nil checker",
			assert: func(t *testing.T) {
				assert.PanicsWithValue(t, "ginsec: ResourceOwnerships needs a non-nil checker", func() {
					ginsec.ResourceOwnerships[string](mustGuards(t, nil, ginsec.WithChainAuthorizer()), "orders", "order", nil)
				})
			},
		},
		{
			name: "with nil extractor",
			assert: func(t *testing.T) {
				owned := ginsec.ResourceOwnerships[string](mustGuards(t, nil, ginsec.WithChainAuthorizer()), "orders", "order", ownedByAnyone)

				assert.PanicsWithValue(t, "ginsec: ForResource needs a non-nil extractor", func() {
					owned.ForResource(nil)
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// TestGin_GuardsBuildersWithNilGuardsFailAtWiring stands apart from
// TestGin_OwnershipGuardFailsAtWiring: its cases are named after the builder
// called on nil Guards, and folding them would need a nested group.
func TestGin_GuardsBuildersWithNilGuardsFailAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func()
		panics string
	}

	cases := []testCase{
		{
			name:   "RequireAuthenticated",
			build:  func() { (*ginsec.Guards)(nil).RequireAuthenticated() },
			panics: "ginsec: RequireAuthenticated needs non-nil Guards",
		},
		{
			name:   "ResourcePrivileges",
			build:  func() { (*ginsec.Guards)(nil).ResourcePrivileges("orders", "order") },
			panics: "ginsec: ResourcePrivileges needs non-nil Guards",
		},
		{
			name:   "RequireRecentAuthentication",
			build:  func() { (*ginsec.Guards)(nil).RequireRecentAuthentication() },
			panics: "ginsec: RequireRecentAuthentication needs non-nil Guards",
		},
		{
			name:   "RequireAuthenticationWithin",
			build:  func() { (*ginsec.Guards)(nil).RequireAuthenticationWithin(time.Minute) },
			panics: "ginsec: RequireAuthenticationWithin needs non-nil Guards",
		},
		{
			name: "ResourceOwnerships",
			build: func() {
				ginsec.ResourceOwnerships[string](nil, "orders", "order", ownedByAnyone)
			},
			panics: "ginsec: ResourceOwnerships needs non-nil Guards",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.PanicsWithValue(t, tc.panics, tc.build)
		})
	}
}

// fixedClock is a clock that reads one moment, so a case says when "now" is.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

var _ clock.Clock = fixedClock{}

// TestGin_RecencyGuard pins the gin recency guard to the core guard's
// judgement: the same window, the same default, the same refusal.
func TestGin_RecencyGuard(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	// authenticatedAgo reports a consumer's authentication time d before base.
	authenticatedAgo := func(d time.Duration) ginsec.GuardOption {
		return ginsec.WithAuthenticationTime(func(context.Context) (time.Time, bool) {
			return base.Add(-d), true
		})
	}

	type testCase struct {
		name string

		// opts are the guards' options. The clock is base unless clockAt says
		// otherwise.
		opts    []ginsec.GuardOption
		clockAt func() time.Time

		// mw is the guard under test, nil meaning RequireRecentAuthentication.
		mw func(g *ginsec.Guards) gin.HandlerFunc

		// session serves the request through the chain's bearer fixture, so
		// the guard reads the session the chain resolved.
		session      bool
		noPrincipal  bool
		noAuthorizer bool

		assert func(t *testing.T, out *served)
	}

	refusedWithin := func(window time.Duration) func(*testing.T, *served) {
		return func(t *testing.T, out *served) {
			t.Helper()

			assert.False(t, out.routeRan, "the route does not run for a stale authentication")
			require.Len(t, out.ginErrors, 1)
			require.ErrorIs(t, out.ginErrors[0], httpsec.ErrReauthenticationRequired)

			var refusal *httpsec.ReauthenticationRequiredError
			require.ErrorAs(t, out.ginErrors[0], &refusal)
			assert.Equal(t, window, refusal.Window)
			assert.Equal(t, http.StatusForbidden, out.rec.Code)
		}
	}

	letThrough := func(t *testing.T, out *served) {
		t.Helper()

		assert.True(t, out.routeRan, "the route runs for a recent authentication")
		assert.Empty(t, out.ginErrors)
		assert.Equal(t, http.StatusOK, out.rec.Code)
	}

	within := func(d time.Duration) func(g *ginsec.Guards) gin.HandlerFunc {
		return func(g *ginsec.Guards) gin.HandlerFunc { return g.RequireAuthenticationWithin(d) }
	}

	cases := []testCase{
		{
			name:   "stale by 16 minutes is refused with the default window",
			opts:   []ginsec.GuardOption{authenticatedAgo(16 * time.Minute)},
			assert: refusedWithin(15 * time.Minute),
		},
		{
			name:   "fresh by 5 minutes runs the route",
			opts:   []ginsec.GuardOption{authenticatedAgo(5 * time.Minute)},
			assert: letThrough,
		},
		{
			name:   "the window is inclusive",
			opts:   []ginsec.GuardOption{authenticatedAgo(15 * time.Minute)},
			assert: letThrough,
		},
		{
			name: "the guards' window replaces the default",
			opts: []ginsec.GuardOption{
				ginsec.WithRecentAuthenticationWindow(time.Hour), authenticatedAgo(45 * time.Minute),
			},
			assert: letThrough,
		},
		{
			name: "a shorter guards' window refuses with that window",
			opts: []ginsec.GuardOption{
				ginsec.WithRecentAuthenticationWindow(time.Minute), authenticatedAgo(5 * time.Minute),
			},
			assert: refusedWithin(time.Minute),
		},
		{
			name:   "a per-route window of 5 minutes refuses at 6 minutes",
			opts:   []ginsec.GuardOption{authenticatedAgo(6 * time.Minute)},
			mw:     within(5 * time.Minute),
			assert: refusedWithin(5 * time.Minute),
		},
		{
			name: "a per-route window wins over the guards' window",
			opts: []ginsec.GuardOption{
				ginsec.WithRecentAuthenticationWindow(5 * time.Minute), authenticatedAgo(45 * time.Minute),
			},
			mw:     within(time.Hour),
			assert: letThrough,
		},
		{
			name: "a consumer time source reporting none is refused",
			opts: []ginsec.GuardOption{ginsec.WithAuthenticationTime(
				func(context.Context) (time.Time, bool) { return time.Time{}, false })},
			assert: refusedWithin(15 * time.Minute),
		},
		{
			name: "a consumer time source reporting a zero time is refused",
			opts: []ginsec.GuardOption{ginsec.WithAuthenticationTime(
				func(context.Context) (time.Time, bool) { return time.Time{}, true })},
			assert: refusedWithin(15 * time.Minute),
		},
		{
			// The session was authenticated at the real now, and the clock is
			// base, so only the consumer's time source can make this stale.
			name:    "a consumer time source replaces a fresh session",
			opts:    []ginsec.GuardOption{authenticatedAgo(16 * time.Minute)},
			session: true,
			assert:  refusedWithin(15 * time.Minute),
		},
		{
			name:    "a fresh session runs the route",
			session: true,
			clockAt: func() time.Time { return time.Now().Add(5 * time.Minute) },
			assert:  letThrough,
		},
		{
			name:    "a stale session is refused",
			session: true,
			clockAt: func() time.Time { return time.Now().Add(16 * time.Minute) },
			assert:  refusedWithin(15 * time.Minute),
		},
		{
			name:   "a request with no session is refused",
			assert: refusedWithin(15 * time.Minute),
		},
		{
			name:        "no principal is told to authenticate",
			opts:        []ginsec.GuardOption{authenticatedAgo(time.Minute)},
			noPrincipal: true,
			assert: func(t *testing.T, out *served) {
				assert.False(t, out.routeRan)
				require.Len(t, out.ginErrors, 1)
				require.ErrorIs(t, out.ginErrors[0], httpsec.ErrAuthenticationRequired)
				assert.NotErrorIs(t, out.ginErrors[0], httpsec.ErrReauthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, out.rec.Code)
			},
		},
		{
			name:         "no authorizer is access denied before recency is judged",
			opts:         []ginsec.GuardOption{authenticatedAgo(time.Hour)},
			noAuthorizer: true,
			assert: func(t *testing.T, out *served) {
				assert.False(t, out.routeRan)
				require.Len(t, out.ginErrors, 1)
				require.ErrorIs(t, out.ginErrors[0], authorize.ErrAccessDenied)
				assert.NotErrorIs(t, out.ginErrors[0], httpsec.ErrReauthenticationRequired)
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := base
			if tc.clockAt != nil {
				now = tc.clockAt()
			}

			g := mustGuards(t, nil, append([]ginsec.GuardOption{
				ginsec.WithChainAuthorizer(), ginsec.WithGuardClock(fixedClock{at: now}),
			}, tc.opts...)...)

			mw := g.RequireRecentAuthentication
			if tc.mw != nil {
				mw = func() gin.HandlerFunc { return tc.mw(g) }
			}

			var chainOpts []httpsec.Option

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)

			if tc.session {
				chainOpts, _ = authenticated(t)
				req = bearerRequest(t.Context(), http.MethodGet, "/invoices")
			} else if !tc.noPrincipal {
				chainOpts = append(chainOpts, httpsec.RegisterInterceptor(
					publishing(testPrincipal()), httpsec.OrderBearerToken))
			}

			if !tc.noAuthorizer {
				chainOpts = append(chainOpts, httpsec.EnableAuthorization(deciding(t, nil)))
			}

			out := &served{}

			eng := gin.New()
			eng.Use(out.collecting())
			eng.Use(ginsec.Middleware(newChain(t, chainOpts...)))
			eng.GET("/invoices", mw(), out.route())

			out.rec = serve(eng, req)

			tc.assert(t, out)
		})
	}
}

// fixedClockPtr is a clock whose nil pointer is a typed-nil interface value.
type fixedClockPtr struct{}

func (*fixedClockPtr) Now() time.Time { return time.Time{} }

// TestGin_NewGuards_Recency pins that gin guards refuse recency options no
// guard could judge with, at construction, naming the option.
func TestGin_NewGuards_Recency(t *testing.T) {
	t.Parallel()

	var typedNil *fixedClockPtr

	type testCase struct {
		name string
		// noAuthorizer builds the guards with neither an authorizer nor
		// WithChainAuthorizer, so a second wiring mistake is judged against
		// the missing one.
		noAuthorizer bool
		opts         []ginsec.GuardOption
		assert       func(t *testing.T, g *ginsec.Guards, err error)
	}

	refused := func(option string) func(*testing.T, *ginsec.Guards, error) {
		return func(t *testing.T, g *ginsec.Guards, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, option)
			assert.Nil(t, g)
		}
	}

	cases := []testCase{
		{
			name: "defaults build",
			assert: func(t *testing.T, g *ginsec.Guards, err error) {
				require.NoError(t, err)
				assert.NotNil(t, g)
			},
		},
		{
			name:   "window of zero",
			opts:   []ginsec.GuardOption{ginsec.WithRecentAuthenticationWindow(0)},
			assert: refused("WithRecentAuthenticationWindow"),
		},
		{
			name:   "negative window",
			opts:   []ginsec.GuardOption{ginsec.WithRecentAuthenticationWindow(-time.Second)},
			assert: refused("WithRecentAuthenticationWindow"),
		},
		{
			// "One wiring mistake, one error on every adapter": the recency
			// options are judged before the missing authorizer.
			name:         "a zero window and no authorizer reports the window",
			noAuthorizer: true,
			opts:         []ginsec.GuardOption{ginsec.WithRecentAuthenticationWindow(0)},
			assert:       refused("WithRecentAuthenticationWindow"),
		},
		{
			name:   "nil clock",
			opts:   []ginsec.GuardOption{ginsec.WithGuardClock(nil)},
			assert: refused("WithGuardClock"),
		},
		{
			name:   "typed-nil clock",
			opts:   []ginsec.GuardOption{ginsec.WithGuardClock(typedNil)},
			assert: refused("WithGuardClock"),
		},
		{
			name:   "nil authentication time",
			opts:   []ginsec.GuardOption{ginsec.WithAuthenticationTime(nil)},
			assert: refused("WithAuthenticationTime"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			if !tc.noAuthorizer {
				opts = append([]ginsec.GuardOption{ginsec.WithChainAuthorizer()}, opts...)
			}

			g, err := ginsec.NewGuards(nil, opts...)
			tc.assert(t, g, err)
		})
	}
}

// TestGin_RequireAuthenticationWithinFailsAtWiring pins that a route window no
// caller could meet is a wiring panic naming the window.
func TestGin_RequireAuthenticationWithinFailsAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		window time.Duration
		panics string
	}

	cases := []testCase{
		{
			name:   "zero",
			window: 0,
			panics: "ginsec: RequireAuthenticationWithin needs a window above zero, got 0s",
		},
		{
			name:   "negative",
			window: -time.Second,
			panics: "ginsec: RequireAuthenticationWithin needs a window above zero, got -1s",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := mustGuards(t, nil, ginsec.WithChainAuthorizer())

			assert.PanicsWithValue(t, tc.panics, func() { g.RequireAuthenticationWithin(tc.window) })
		})
	}
}

// TestGin_GuardsDPoPChallenge pins that a gin guard behind a chain with DPoP
// on refuses a caller nothing authenticated with the challenge the chain's
// own refusal carries, and that without DPoP it answers as it always did.
//
// It stands on its own: a whole chain with DPoP configured in front of the
// guard, which no other gin guard test has.
func TestGin_GuardsDPoPChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		dpop   []httpsec.Option
		opts   func(seen *http.Header) []ginsec.GuardOption
		assert func(t *testing.T, rec *httptest.ResponseRecorder, seen http.Header)
	}

	challenged := func(challenges ...string) func(*testing.T, *httptest.ResponseRecorder, http.Header) {
		return func(t *testing.T, rec *httptest.ResponseRecorder, _ http.Header) {
			t.Helper()

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Equal(t, challenges, rec.Header().Values("WWW-Authenticate"))
		}
	}

	cases := []testCase{
		{
			name:   "DPoP optional: the DPoP and Bearer challenges",
			dpop:   []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "http://example.com"})},
			assert: challenged(`DPoP algs="ES256"`, "Bearer"),
		},
		{
			name:   "DPoP required: the DPoP challenge alone",
			dpop:   []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "http://example.com", Require: true})},
			assert: challenged(`DPoP algs="ES256"`),
		},
		{
			name:   "DPoP off: no challenge, as before",
			assert: challenged(),
		},
		{
			name: "a consumer's error handler finds the challenge set",
			dpop: []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "http://example.com"})},
			opts: func(seen *http.Header) []ginsec.GuardOption {
				return []ginsec.GuardOption{ginsec.WithGuardErrorHandler(func(gc *gin.Context, err error) {
					*seen = gc.Writer.Header().Clone()

					gc.Status(httpsec.StatusForError(err))
				})}
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, seen http.Header) {
				challenged(`DPoP algs="ES256"`, "Bearer")(t, rec, seen)
				assert.Equal(t, []string{`DPoP algs="ES256"`, "Bearer"}, seen.Values("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts, _ := authenticated(t)

			var seen http.Header

			var guardOpts []ginsec.GuardOption
			if tc.opts != nil {
				guardOpts = tc.opts(&seen)
			}

			g := mustGuards(t, deciding(t, nil), guardOpts...)

			eng := gin.New()
			eng.Use(ginsec.Middleware(newChain(t, append(opts, tc.dpop...)...)))
			eng.GET("/api/orders", g.RequireAuthenticated(), func(*gin.Context) { t.Error("the route must not run") })

			rec := serve(eng, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/api/orders", nil))

			tc.assert(t, rec, seen)
		})
	}
}
