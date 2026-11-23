package test_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
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
		res.RouteHeader = r.Header.Clone()
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

// Listen serves spec's chain on a real server. Its shutdown does not end an open
// stream by itself: net/http's waits for the handler, whose context it leaves
// alone, so a stream ends through what the application closes.
func (nethttpAdapter) Listen(
	t *testing.T,
	spec httpsecconformance.ChainSpec,
	writeTimeout time.Duration,
) httpsecconformance.StreamServer {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+httpsecconformance.SlowWritePath, func(w http.ResponseWriter, _ *http.Request) {
		httpsecconformance.WriteSlowly(w)
	})

	handler := spec.NewChain(t).Middleware()(mux)
	if spec.Compress {
		handler = httpsecconformance.Gzip(handler)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)

	return httpsecconformance.StreamServer{URL: srv.URL, CompressesStream: true}
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
	// The scenario's nil authorizer means the guards rely on what the chain
	// published, so the reliance is declared for every scenario, and a non-nil
	// one is the fallback beside it. Declared, construction cannot fail.
	guardOpts := []httpsec.GuardOption{httpsec.WithChainAuthorizer(),
		httpsec.WithGuardErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			res.Refusal = err

			w.WriteHeader(httpsec.StatusForError(err))
		})}
	if spec.Clock != nil {
		guardOpts = append(guardOpts, httpsec.WithGuardClock(spec.Clock))
	}

	guards, err := httpsec.NewGuards(spec.Authorizer, guardOpts...)
	if err != nil {
		panic(err)
	}

	if spec.Kind == httpsecconformance.GuardRecent {
		return guards.RequireRecentAuthentication()
	}

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
	httpsecconformance.RunScenarios(t, nethttpAdapter{}, httpsecconformance.OIDCProviderScenarios())
}

// TestChallengeNetHTTP runs the automation-challenge rows, which
// TestConformanceNetHTTP leaves out so that each runs once, and so they can be
// run by name.
func TestChallengeNetHTTP(t *testing.T) {
	t.Parallel()

	httpsecconformance.RunScenarios(t, nethttpAdapter{}, httpsecconformance.ChallengeScenarios())
}

// TestCertificateBindingNetHTTP runs the certificate-binding scenarios on
// net/http, through a trusted proxy that forwards the client's certificate.
func TestCertificateBindingNetHTTP(t *testing.T) {
	t.Parallel()

	httpsecconformance.RunCertificateBinding(t, nethttpAdapter{})
}

// requireParityJudge grants read on crm/lead and denies every other resource,
// or fails with outage when it is set.
type requireParityJudge struct{ outage error }

func (j requireParityJudge) Authorize(_ context.Context, a authorize.Attributes) error {
	if j.outage != nil {
		return j.outage
	}

	if p, ok := a.(authorize.PrivilegeAttributes); ok && p.Resource == "lead" {
		return nil
	}

	return authorize.ErrAccessDenied
}

// requireParityChain builds a chain that resolves the request as ada, or as
// nobody when anonymous, and publishes judge as the chain's authorizer.
func requireParityChain(t *testing.T, anonymous bool, judge authorize.Authorizer) *httpsec.Chain {
	t.Helper()

	principal := &identity.Principal{ID: "u-1", Username: "ada", Name: "Ada"}

	chain, err := httpsec.New(
		httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(ex *httpsec.Exchange, next httpsec.Next) error {
				if !anonymous {
					ex.Authentication = &authenticate.Authentication{Principal: principal}
					ex.SetContext(identity.WithPrincipal(ex.Context(), principal))
				}

				return next(ex)
			}), httpsec.OrderBearerToken),
		httpsec.EnableAuthorization(judge))
	require.NoError(t, err)

	return chain
}

// TestGuards_RequireParity runs one composed requirement, all of read on
// crm/lead and crm/deal, through the net/http, gin and fiber guards and
// compares what each answers: the status, and the sentinels the refusal
// matches.
func TestGuards_RequireParity(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("parity: the role loader is unreachable")

	requirement := authorize.AllOf(
		authorize.HasPrivilege("crm", "lead", "read"),
		authorize.HasPrivilege("crm", "deal", "read"))

	type answer struct {
		status   int
		routeRan bool
		refusal  error
	}

	type testCase struct {
		name      string
		anonymous bool
		judge     authorize.Authorizer
		assert    func(t *testing.T, framework string, a answer)
	}

	cases := []testCase{
		{
			name:  "all-of with one resource not granted is access denied",
			judge: requireParityJudge{},
			assert: func(t *testing.T, fw string, a answer) {
				assert.Equal(t, http.StatusForbidden, a.status, fw)
				assert.False(t, a.routeRan, fw)
				assert.ErrorIs(t, a.refusal, authorize.ErrAccessDenied, fw)
			},
		},
		{
			name:      "anonymous is authentication required",
			anonymous: true,
			judge:     requireParityJudge{},
			assert: func(t *testing.T, fw string, a answer) {
				assert.Equal(t, http.StatusUnauthorized, a.status, fw)
				assert.False(t, a.routeRan, fw)
				assert.ErrorIs(t, a.refusal, httpsec.ErrAuthenticationRequired, fw)
			},
		},
		{
			name:  "an outage is a dependency failure, not a denial",
			judge: requireParityJudge{outage: errOutage},
			assert: func(t *testing.T, fw string, a answer) {
				assert.NotEqual(t, http.StatusForbidden, a.status, fw)
				assert.False(t, a.routeRan, fw)
				assert.ErrorIs(t, a.refusal, errOutage, fw)
				assert.NotErrorIs(t, a.refusal, authorize.ErrAccessDenied, fw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			answers := map[string]answer{}

			// net/http
			{
				var a answer

				g, err := httpsec.NewGuards(nil, httpsec.WithChainAuthorizer(),
					httpsec.WithGuardErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
						a.refusal = err
						w.WriteHeader(httpsec.StatusForError(err))
					}))
				require.NoError(t, err)

				guard, err := g.Require(requirement)
				require.NoError(t, err)

				route := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { a.routeRan = true })
				handler := requireParityChain(t, tc.anonymous, tc.judge).Middleware()(guard(route))

				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/leads", nil))
				a.status = rec.Code
				answers["net/http"] = a
			}

			// gin
			{
				var a answer

				g, err := ginsec.NewGuards(nil, ginsec.WithChainAuthorizer())
				require.NoError(t, err)

				guard, err := g.Require(requirement)
				require.NoError(t, err)

				eng := gin.New()
				eng.Use(func(gc *gin.Context) {
					gc.Next()

					if len(gc.Errors) > 0 {
						a.refusal = gc.Errors[0].Err
					}
				})
				eng.Use(ginsec.Middleware(requireParityChain(t, tc.anonymous, tc.judge)))
				eng.GET("/leads", guard, func(*gin.Context) { a.routeRan = true })

				rec := httptest.NewRecorder()
				eng.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/leads", nil))
				a.status = rec.Code
				answers["gin"] = a
			}

			// fiber
			{
				var a answer

				g, err := fibersec.NewGuards(nil, fibersec.WithChainAuthorizer())
				require.NoError(t, err)

				guard, err := g.Require(requirement)
				require.NoError(t, err)

				app := fiber.New(fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) error {
					a.refusal = err

					return fibersec.ErrorHandler(fc, err)
				}})
				app.Use(fibersec.Middleware(requireParityChain(t, tc.anonymous, tc.judge)))
				app.Get("/leads", guard, func(fc fiber.Ctx) error {
					a.routeRan = true

					return fc.SendStatus(http.StatusNoContent)
				})

				res, err := app.Test(
					httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/leads", nil),
					fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
				require.NoError(t, err)
				require.NoError(t, res.Body.Close())

				a.status = res.StatusCode
				answers["fiber"] = a
			}

			for fw, a := range answers {
				tc.assert(t, fw, a)
			}

			// One status across the three.
			assert.Equal(t, answers["net/http"].status, answers["gin"].status)
			assert.Equal(t, answers["net/http"].status, answers["fiber"].status)
		})
	}
}
