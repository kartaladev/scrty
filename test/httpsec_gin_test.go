package test_test

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/kartaladev/scrty/ginsec"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
)

// TestMain puts gin in test mode, so the output of a failing row is the row's
// and not gin's start-up banner.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	os.Exit(m.Run())
}

// ginAdapter runs the conformance table on the gin integration.
//
// Nothing here configures error handling: gin's own error channel is where a
// refusal goes, and the collecting middleware only reads it. What a client is
// answered is therefore whatever the adapter's default does, which is what the
// table compares against net/http.
type ginAdapter struct{}

func (ginAdapter) Serve(
	t *testing.T,
	spec httpsecconformance.ChainSpec,
	req httpsecconformance.RequestSpec,
) httpsecconformance.Result {
	t.Helper()

	var res httpsecconformance.Result

	chain := spec.NewChain(t)

	engine := gin.New()

	if spec.Upstream {
		engine.Use(ginUpstream())
	}

	// Outside the chain, so it still sees a refused request: it runs the rest
	// of the handlers and reads what they left on gin's error channel.
	engine.Use(ginCollecting(&res))
	engine.Use(ginsec.Middleware(chain))

	for _, route := range spec.Routes {
		engine.Handle(route.Method, route.Path, ginRoute(&res, route, spec)...)
	}

	if spec.NoRoute {
		engine.NoRoute(func(gc *gin.Context) {
			res.NoRouteRan = true

			_, _ = gc.Writer.WriteString(httpsecconformance.NoRouteBody)
		})
	}

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, nethttpRequest(t, req))

	res.Status, res.Header, res.Body = rec.Code, rec.Header(), rec.Body.String()

	return res
}

// ginRoute is one application route, preceded by the guard the scenario asked
// for.
func ginRoute(
	res *httpsecconformance.Result,
	route httpsecconformance.Route,
	spec httpsecconformance.ChainSpec,
) []gin.HandlerFunc {
	var handlers []gin.HandlerFunc

	if spec.Guard.Kind != httpsecconformance.GuardNone && spec.Guard.Path == route.Path {
		handlers = append(handlers, ginGuard(spec.Guard))
	}

	return append(handlers, func(gc *gin.Context) {
		res.RouteRan = true
		httpsecconformance.ReadContext(gc.Request.Context(), res)

		if route.Status != 0 {
			gc.Status(route.Status)
		}

		if route.Body != "" {
			_, _ = gc.Writer.WriteString(route.Body)
		}
	})
}

// ginGuard builds the guard the scenario named, with gin's own defaults: the
// refusal on the error channel and the mapped status set but not committed.
func ginGuard(spec httpsecconformance.GuardSpec) gin.HandlerFunc {
	guards := ginsec.NewGuards(spec.Authorizer)

	if spec.Kind == httpsecconformance.GuardAuthenticated {
		return guards.RequireAuthenticated()
	}

	return guards.
		ResourcePrivileges(httpsecconformance.GuardGroup, httpsecconformance.GuardResource).
		RequireOne(httpsecconformance.GuardPrivilegeName)
}

// ginCollecting reads gin's error channel once everything behind it has run,
// which is where a gin consumer already handles every other error. It writes
// nothing, so the adapter's own answer stands.
func ginCollecting(res *httpsecconformance.Result) gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Next()

		if len(gc.Errors) > 0 {
			res.Refusal = gc.Errors[0].Err
		}
	}
}

// ginUpstream is middleware outside the chain, standing in for a consumer's own
// tracing: what it publishes must still be readable behind the chain.
func ginUpstream() gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Request = gc.Request.WithContext(context.WithValue(gc.Request.Context(),
			httpsecconformance.UpstreamKey{}, httpsecconformance.UpstreamValue))

		gc.Next()
	}
}

// TestConformanceGin runs the reference table on gin. A row that fails here and
// passes on net/http is a defect in the gin integration, which is the whole
// reason the table is shared.
func TestConformanceGin(t *testing.T) {
	t.Parallel()

	httpsecconformance.Run(t, ginAdapter{})
}
