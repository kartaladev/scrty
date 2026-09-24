package test_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kartaladev/scrty/httpsec"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
)

// nethttpAdapter runs the conformance table on the library's own net/http
// entrypoint. It is the reference the other two adapters are compared against:
// gin reuses these same request and response implementations, and fiber
// implements the abstraction itself, so a row that differs there differs from
// this.
//
// It serves through a recorder rather than a listening server because the
// client address is one of the things the table pins, and a real listener
// always reports a loopback peer — there would be no way to send the
// unattributable-address row.
type nethttpAdapter struct{}

func (nethttpAdapter) Serve(
	t *testing.T,
	spec httpsecconformance.ChainSpec,
	req httpsecconformance.RequestSpec,
) httpsecconformance.Result {
	t.Helper()

	var res httpsecconformance.Result

	// The refusal is captured the only way net/http exposes one, through the
	// chain's error handler. What it writes is the library's own default —
	// the mapped status and no body — so the response the table compares is
	// the one a consumer who configured nothing would get.
	chain := spec.NewChain(t, httpsec.WithErrorHandler(
		func(w http.ResponseWriter, _ *http.Request, err error) {
			res.Refusal = err

			w.WriteHeader(httpsec.StatusForError(err))
		}))

	mux := http.NewServeMux()

	for _, route := range spec.Routes {
		mux.Handle(route.Method+" "+route.Path, nethttpRoute(&res, route, spec))
	}

	if spec.NoRoute {
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			res.NoRouteRan = true

			_, _ = w.Write([]byte(httpsecconformance.NoRouteBody))
		})
	}

	handler := chain.Middleware()(mux)
	if spec.Upstream {
		handler = nethttpUpstream(handler)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, nethttpRequest(t, req))

	res.Status, res.Header, res.Body = rec.Code, rec.Header(), rec.Body.String()

	return res
}

// nethttpRoute is one application route, guarded where the scenario asked for a
// guard.
func nethttpRoute(
	res *httpsecconformance.Result,
	route httpsecconformance.Route,
	spec httpsecconformance.ChainSpec,
) http.Handler {
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res.RouteRan = true
		httpsecconformance.ReadContext(r.Context(), res)

		if route.Status != 0 {
			w.WriteHeader(route.Status)
		}

		if route.Body != "" {
			_, _ = w.Write([]byte(route.Body))
		}
	})

	if spec.Guard.Kind != httpsecconformance.GuardNone && spec.Guard.Path == route.Path {
		handler = nethttpGuard(res, spec.Guard)(handler)
	}

	return handler
}

// nethttpGuard builds the guard the scenario named.
//
// Its error handler records the refusal and then writes exactly what the guard
// writes with no handler at all, so recording it does not change the response
// the table compares.
func nethttpGuard(
	res *httpsecconformance.Result,
	spec httpsecconformance.GuardSpec,
) func(http.Handler) http.Handler {
	guards := httpsec.NewGuards(spec.Authorizer, httpsec.WithGuardErrorHandler(
		func(w http.ResponseWriter, _ *http.Request, err error) {
			res.Refusal = err

			w.WriteHeader(httpsec.StatusForError(err))
		}))

	if spec.Kind == httpsecconformance.GuardAuthenticated {
		return guards.RequireAuthenticated()
	}

	return guards.
		ResourcePrivileges(httpsecconformance.GuardGroup, httpsecconformance.GuardResource).
		RequireOne(httpsecconformance.GuardPrivilegeName)
}

// nethttpUpstream is middleware outside the chain, standing in for a
// consumer's own tracing: what it publishes must still be readable behind the
// chain.
func nethttpUpstream(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(),
			httpsecconformance.UpstreamKey{}, httpsecconformance.UpstreamValue)

		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

// nethttpRequest builds the request the scenario described.
//
// The peer is set explicitly in both directions: httptest seeds one of its own,
// so an unattributable address has to be written as well as an attributable
// one.
func nethttpRequest(t *testing.T, spec httpsecconformance.RequestSpec) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(
		t.Context(), spec.Method, spec.Path, strings.NewReader(spec.Body))

	for name, value := range spec.Header {
		req.Header.Set(name, value)
	}

	req.RemoteAddr = ""
	if spec.ClientAddress != "" {
		req.RemoteAddr = spec.ClientAddress + ":54321"
	}

	return req
}

// TestConformanceNetHTTP is the reference run: every behaviour the table
// describes, produced by httpsec's own net/http middleware.
func TestConformanceNetHTTP(t *testing.T) {
	t.Parallel()

	httpsecconformance.Run(t, nethttpAdapter{})
}
