package ginsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
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
