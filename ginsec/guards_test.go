package ginsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/ginsec"
	"github.com/kartaladev/scrty/httpsec"
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

				g := ginsec.NewGuards(nil)

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

				g := ginsec.NewGuards(nil)

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

				g := ginsec.NewGuards(nil)

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
				g := ginsec.NewGuards(nil)

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

				g := ginsec.NewGuards(deciding(t, nil))

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

				g := ginsec.NewGuards(nil)

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

				g := ginsec.NewGuards((*MockAuthorizer)(nil))

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

				g := ginsec.NewGuards(nil, ginsec.WithGuardErrorHandler(
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

				g := ginsec.NewGuards(nil)
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
