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

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/ginsec"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// errStoreDown is an internal fault a refusal must neither render nor answer as
// a success. Its text names a host and a port on purpose: that is what leaks.
var errStoreDown = errors.New("connection refused to db-primary:5432")

// TestGinRefusal pins how a refused request is answered on gin: the error on
// gin's own channel, a status that is set but not committed, and the route
// never reached.
func TestGinRefusal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// build assembles the gin engine for this case. The chain middleware is
		// registered by the case itself, because where it sits relative to the
		// consumer's own middleware is what several rows are about.
		build func(t *testing.T, out *served) *gin.Engine

		assert func(t *testing.T, out *served)
	}

	cases := []testCase{
		{
			// The row the whole design rests on. The status is set lazily, so
			// error middleware registered outside the chain still owns the
			// status, the content type and the body. Committing the header
			// block here — which is what AbortWithStatus does — would leave the
			// consumer unable to render anything at all.
			name: "consumer error middleware renders the refusal",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(rendering(http.StatusTeapot, "application/problem+json", `{"detail":"no"}`))
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						refusing(authorize.ErrAccessDenied, nil), httpsec.OrderAuthorizer))))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				res := out.rec.Result()
				defer func() { _ = res.Body.Close() }()

				assert.Equal(t, http.StatusTeapot, res.StatusCode,
					"the consumer's status, not the adapter's")
				assert.Equal(t, "application/problem+json", res.Header.Get("Content-Type"),
					"the header block was still open when the consumer rendered")
				assert.JSONEq(t, `{"detail":"no"}`, out.rec.Body.String())
				assert.False(t, out.routeRan)
			},
		},
		{
			// With nothing registered to render, the request must still be
			// refused. Registering the error and aborting alone would answer
			// 200: a refusal served as a success.
			name: "no error middleware fails closed",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						refusing(authorize.ErrAccessDenied, nil), httpsec.OrderAuthorizer))))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
				assert.Empty(t, out.rec.Body.String(), "the library renders no body for a refusal")
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "the refusal is on gin's error channel",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(out.collecting())
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						refusing(authorize.ErrAccessDenied, nil), httpsec.OrderAuthorizer))))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				require.Len(t, out.ginErrors, 1)
				assert.ErrorIs(t, out.ginErrors[0], authorize.ErrAccessDenied,
					"the refusal reaches the consumer as itself, not as a rewritten error")
				assert.Equal(t, http.StatusForbidden, out.rec.Code)
			},
		},
		{
			name: "a response an interceptor already wrote is not overwritten",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						refusing(authorize.ErrAccessDenied, func(ex *httpsec.Exchange) {
							ex.Writer.WriteHeader(http.StatusCreated)
							_, _ = ex.Writer.Write([]byte("made"))
						}), httpsec.OrderAuthorizer))))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Equal(t, "made", out.rec.Body.String())
				assert.False(t, out.routeRan)
			},
		},
		{
			name: "an unrecognised fault is a server fault and leaks nothing",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(
						refusing(errStoreDown, nil), httpsec.OrderAuthorizer))))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusInternalServerError, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
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
				t.Context(), http.MethodGet, "/reports", nil))

			tc.assert(t, out)
		})
	}
}

// TestGinContext pins what a gin route behind the chain reads: what the chain
// resolved, what gin middleware outside the chain had already put there, and
// the client's own cancellation.
func TestGinContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		build  func(t *testing.T, out *served) *gin.Engine
		assert func(t *testing.T, out *served)
	}

	cases := []testCase{
		{
			name: "a route reads the caller the chain authenticated",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				opts, _ := authenticated(t)
				// The chain publishes the authentication result; the principal
				// under identity's own key is published by an interceptor, as
				// it is behind net/http.
				opts = append(opts, httpsec.RegisterInterceptor(
					publishing(testPrincipal()), httpsec.After(httpsec.OrderBearerToken)))

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, opts...)))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				require.True(t, out.routeRan)

				a, ok := authenticate.AuthenticationFromContext(out.routeCtx)
				require.True(t, ok, "the route reads the authentication result through c.Request.Context()")
				assert.Equal(t, "ada", a.Principal.Username)

				p, ok := identity.PrincipalFromContext(out.routeCtx)
				require.True(t, ok, "the route reads the caller through c.Request.Context()")
				assert.Equal(t, "ada", p.Username)
			},
		},
		{
			name: "a route reads the session the chain resolved",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				opts, live := authenticated(t)
				out.sessionID = live.ID

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, opts...)))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				require.True(t, out.routeRan)

				s, ok := httpsec.SessionFromContext(out.routeCtx)
				require.True(t, ok, "the route reads the session through c.Request.Context()")
				assert.Equal(t, out.sessionID, s.ID)
			},
		},
		{
			name: "a value gin middleware set before the chain survives it",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				opts, _ := authenticated(t)

				eng := gin.New()
				eng.Use(tracing("r-1"))
				eng.Use(ginsec.Middleware(newChain(t, opts...)))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				require.True(t, out.routeRan)
				assert.Equal(t, "r-1", out.routeCtx.Value(traceKey{}),
					"the chain derives from the incoming context and never replaces it")

				a, ok := authenticate.AuthenticationFromContext(out.routeCtx)
				require.True(t, ok, "and what the chain resolved is there too")
				assert.Equal(t, "ada", a.Principal.Username)
			},
		},
		{
			name: "the client's own cancellation reaches the route",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t)))
				eng.GET("/reports", out.route())

				return eng
			},
			assert: func(t *testing.T, out *served) {
				require.True(t, out.routeRan)
				require.ErrorIs(t, out.routeCtx.Err(), context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			out := &served{}
			eng := tc.build(t, out)

			out.rec = serve(eng, bearerRequest(ctx, http.MethodGet, "/reports"))

			tc.assert(t, out)
		})
	}
}

// TestGinSelfAnswered pins that a request an interceptor answered itself stops
// the gin handlers without a status of its own, so nothing registered behind
// the chain can overwrite the status or append to the body.
func TestGinSelfAnswered(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, out *served) *gin.Engine
		req    func(ctx context.Context) *http.Request
		assert func(t *testing.T, out *served)
	}

	cases := []testCase{
		{
			name: "a matched route does not overwrite the status the chain set",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				opts, _ := authenticated(t)

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, opts...)))
				eng.POST(httpsec.DefaultLogoutPath, out.writingRoute(http.StatusCreated, "routed"))

				return eng
			},
			req: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, http.MethodPost, httpsec.DefaultLogoutPath)
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Empty(t, out.rec.Body.String())
				assert.False(t, out.routeRan, "logout is the chain's own endpoint")
			},
		},
		{
			name: "a no-route handler does not append to what the chain wrote",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				keys := NewMockKeySetProvider(gomock.NewController(t))
				keys.EXPECT().JWKS().Return([]byte(`{"keys":[]}`), nil).AnyTimes()

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, httpsec.EnableJWKSEndpoint(keys))))
				eng.NoRoute(func(gc *gin.Context) {
					out.noRouteRan = true
					gc.Data(http.StatusNotFound, "text/plain; charset=utf-8", []byte("not found"))
				})

				return eng
			},
			req: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, httpsec.DefaultJWKSPath, nil)
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, `{"keys":[]}`, out.rec.Body.String(),
					"exactly the key set, with nothing appended")
				assert.False(t, out.noRouteRan)
			},
		},
		{
			name: "a route behind an interceptor that answered the request does not run",
			build: func(t *testing.T, out *served) *gin.Engine {
				t.Helper()

				eng := gin.New()
				eng.Use(ginsec.Middleware(newChain(t, httpsec.RegisterInterceptor(
					answering(http.StatusOK, `{"access_token":"t"}`), httpsec.OrderFormLogin))))
				eng.GET("/reports", out.writingRoute(http.StatusTeapot, "routed"))

				return eng
			},
			req: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/reports", nil)
			},
			assert: func(t *testing.T, out *served) {
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.JSONEq(t, `{"access_token":"t"}`, out.rec.Body.String())
				assert.False(t, out.routeRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := &served{}
			eng := tc.build(t, out)
			out.rec = serve(eng, tc.req(t.Context()))

			tc.assert(t, out)
		})
	}
}
