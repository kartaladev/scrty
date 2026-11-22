package ginsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
)

// renderedBody is what errorRenderer writes for every refusal.
const renderedBody = `{"error":"rendered"}`

// errorRenderer is consumer error middleware, registered before ginsec, that
// renders every entry on gin's error channel with the status already set,
// unless something has already been written.
func errorRenderer() gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Next()

		if len(gc.Errors) == 0 || gc.Writer.Written() {
			return
		}

		gc.Data(gc.Writer.Status(), "application/json", []byte(renderedBody))
	}
}

// TestMiddleware_RefusalsRendered pins WithRefusalsRendered: it leaves the 404
// on a path gin has no route for open for the consumer's error middleware, and
// changes nothing else.
func TestMiddleware_RefusalsRendered(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []ginsec.Option

		// chain builds the chain under test. nil means the real OIDC login chain,
		// which refuses /sso/login/nope with a 404 and has no gin route for it.
		chain func(t *testing.T) *httpsec.Chain

		// errorMiddleware registers errorRenderer before ginsec.
		errorMiddleware bool

		// route registers a gin route at path, so gin matches the request.
		route bool
		path  string

		assert func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool)
	}

	refusedWith := func(err error) func(t *testing.T) *httpsec.Chain {
		return func(t *testing.T) *httpsec.Chain {
			t.Helper()

			return newChain(t, httpsec.RegisterInterceptor(refusing(err, nil), httpsec.OrderAuthorizer))
		}
	}

	emptyNotFound := func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
		t.Helper()

		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Empty(t, rec.Body.String(), "the default commits an empty 404")
		assert.False(t, handlerRan)
	}

	renderedNotFound := func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
		t.Helper()

		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, renderedBody, rec.Body.String(), "the error middleware's body")
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.False(t, handlerRan)
	}

	cases := []testCase{
		{
			name:   "default, no error middleware",
			path:   "/sso/login/nope",
			assert: emptyNotFound,
		},
		{
			// Without the declaration the 404 is committed before the error
			// middleware runs, so it cannot render it: the settled default.
			name:            "default, with error middleware",
			errorMiddleware: true,
			path:            "/sso/login/nope",
			assert:          emptyNotFound,
		},
		{
			name:            "declared, with error middleware",
			opts:            []ginsec.Option{ginsec.WithRefusalsRendered()},
			errorMiddleware: true,
			path:            "/sso/login/nope",
			assert:          renderedNotFound,
		},
		{
			// The declaration broken: nothing renders the refusal, so gin's own
			// no-route fallback writes its text. It still fails closed and
			// carries no refusal text.
			name: "declared, no error middleware",
			opts: []ginsec.Option{ginsec.WithRefusalsRendered()},
			path: "/sso/login/nope",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
				t.Helper()

				assert.Equal(t, http.StatusNotFound, rec.Code)
				assert.Equal(t, "404 page not found", rec.Body.String())
				assert.NotContains(t, rec.Body.String(), oidc.ErrUnknownProvider.Error())
				assert.False(t, handlerRan, "neither the no-route handler nor a route ran")
			},
		},
		{
			// A 404 on a route gin matched was always left open; the option
			// does not change that.
			name:            "declared, matched route 404",
			opts:            []ginsec.Option{ginsec.WithRefusalsRendered()},
			chain:           refusedWith(oidc.ErrUnknownProvider),
			errorMiddleware: true,
			route:           true,
			path:            "/v1/admin",
			assert:          renderedNotFound,
		},
		{
			name:   "declared, matched route denied, no error middleware",
			opts:   []ginsec.Option{ginsec.WithRefusalsRendered()},
			chain:  refusedWith(authorize.ErrAccessDenied),
			route:  true,
			path:   "/v1/admin",
			assert: statusOnly(http.StatusForbidden),
		},
		{
			// Only the unrouted 404 was ever committed early, so another status
			// on an unrouted path stays open with or without the option.
			name:            "declared, unrouted 400 with error middleware",
			opts:            []ginsec.Option{ginsec.WithRefusalsRendered()},
			chain:           refusedWith(httpsec.ErrMalformedRequest),
			errorMiddleware: true,
			path:            "/nowhere",
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Equal(t, renderedBody, rec.Body.String(), "left open for the error middleware")
				assert.False(t, handlerRan)
			},
		},
		{
			name:   "declared, unrouted 400, no error middleware",
			opts:   []ginsec.Option{ginsec.WithRefusalsRendered()},
			chain:  refusedWith(httpsec.ErrMalformedRequest),
			path:   "/nowhere",
			assert: statusOnly(http.StatusBadRequest),
		},
		{
			name:            "option twice is the option once",
			opts:            []ginsec.Option{ginsec.WithRefusalsRendered(), ginsec.WithRefusalsRendered()},
			errorMiddleware: true,
			path:            "/sso/login/nope",
			assert:          renderedNotFound,
		},
		{
			name:   "nil option is the default",
			opts:   []ginsec.Option{nil},
			path:   "/sso/login/nope",
			assert: emptyNotFound,
		},
		{
			name:            "nil option beside the option is the option",
			opts:            []ginsec.Option{nil, ginsec.WithRefusalsRendered()},
			errorMiddleware: true,
			path:            "/sso/login/nope",
			assert:          renderedNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var chain *httpsec.Chain
			if tc.chain != nil {
				chain = tc.chain(t)
			} else {
				chain = oidcLoginChain(t)
			}

			handlerRan := false

			eng := gin.New()
			if tc.errorMiddleware {
				eng.Use(errorRenderer())
			}

			eng.Use(ginsec.Middleware(chain, tc.opts...))
			eng.NoRoute(func(*gin.Context) { handlerRan = true })

			if tc.route {
				eng.GET(tc.path, func(*gin.Context) { handlerRan = true })
			}

			rec := serve(eng, httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, nil))

			tc.assert(t, rec, handlerRan)
		})
	}
}

// statusOnly asserts the status with an empty body and no handler reached.
func statusOnly(status int) func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
	return func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool) {
		t.Helper()

		assert.Equal(t, status, rec.Code)
		assert.Empty(t, rec.Body.String())
		assert.False(t, handlerRan)
	}
}
