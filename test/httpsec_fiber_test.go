package test_test

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/session"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
)

// unattributedPeer is the transport peer a row that asks for no client
// address is served from: the unspecified address, which is what fiber's
// in-memory test transport reports and which the chain refuses to attribute a
// request to.
const unattributedPeer = "0.0.0.0:0"

// fiberAdapter runs the conformance table on the fiber integration.
//
// fibersec.ErrorHandler is configured because it is the library's own
// equivalent of what net/http answers a refusal with — the bare mapped status
// and an empty body. fiber's built-in handler writes the status text into the
// body instead, which is fiber's decision about an unconfigured app rather than
// a difference in what the chain decided, and comparing against it would
// compare the two frameworks' defaults instead of the chain's behaviour.
type fiberAdapter struct{}

func (fiberAdapter) Serve(
	t *testing.T,
	spec httpsecconformance.ChainSpec,
	req httpsecconformance.RequestSpec,
) httpsecconformance.Result {
	t.Helper()

	var res httpsecconformance.Result

	cfg := fiber.Config{
		ErrorHandler: func(fc fiber.Ctx, err error) error {
			res.Refusal = err

			return fibersec.ErrorHandler(fc, err)
		},

		// Above the 32 MiB form cap, so the oversized-upload scenario reaches
		// the chain instead of fiber's default 4 MiB refusal.
		BodyLimit: 64 << 20,
	}

	if spec.FrameworkTrustsProxies {
		// fiber's own trust in every peer, so c.IP() would read the
		// forwarding header: the chain must not care.
		cfg.TrustProxy = true
		cfg.TrustProxyConfig = fiber.TrustProxyConfig{Proxies: []string{"0.0.0.0/0", "::/0"}}
		cfg.ProxyHeader = fiber.HeaderXForwardedFor
		cfg.EnableIPValidation = true
	}

	app := fiber.New(cfg)

	if spec.Upstream {
		app.Use(fiberUpstream())
	}

	app.Use(fibersec.Middleware(spec.NewChain(t)))

	for _, route := range spec.Routes {
		// The guard comes first and the route handler last, which is the order
		// fiber runs the handlers a route was registered with.
		handlers := fiberRoute(&res, route, spec)
		rest := make([]any, 0, len(handlers)-1)

		for _, h := range handlers[1:] {
			rest = append(rest, h)
		}

		app.Add([]string{route.Method}, route.Path, handlers[0], rest...)
	}

	if spec.NoRoute {
		// Registered last, so it answers whatever no route matched — fiber's
		// equivalent of a consumer's no-route handler.
		app.Use(func(fc fiber.Ctx) error {
			res.NoRouteRan = true

			return fc.SendString(httpsecconformance.NoRouteBody)
		})
	}

	fiberRead(t, app, req, &res)

	return res
}

// Listen serves spec's chain on a real server, behind fiber. Its shutdown ends an
// open stream, because a stream's body ends with fasthttp's own shutdown signal.
func (fiberAdapter) Listen(
	t *testing.T,
	spec httpsecconformance.ChainSpec,
	writeTimeout time.Duration,
) httpsecconformance.StreamServer {
	t.Helper()

	app := fiber.New(fiber.Config{WriteTimeout: writeTimeout, ErrorHandler: fibersec.ErrorHandler})
	if spec.Compress {
		app.Use(compress.New())
	}

	app.Use(fibersec.Middleware(spec.NewChain(t)))
	app.Get(httpsecconformance.SlowWritePath, func(fc fiber.Ctx) error {
		return fc.SendStreamWriter(func(w *bufio.Writer) {
			_, _ = w.WriteString(httpsecconformance.SlowWriteChunk)
			_ = w.Flush()

			// The sleep is the behaviour under test: time passing with no stream
			// of the library's to move the deadline.
			time.Sleep(httpsecconformance.StreamWriteTimeout + time.Second)

			_, _ = w.WriteString(httpsecconformance.SlowWriteChunk)
			_ = w.Flush()
		})
	})

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		defer close(done)

		_ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	}()

	t.Cleanup(func() {
		_ = app.ShutdownWithTimeout(time.Second)
		_ = ln.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})

	return httpsecconformance.StreamServer{URL: "http://" + ln.Addr().String(), Shutdown: app.ShutdownWithContext, BodyRunsLater: true}
}

// fiberRoute is one application route, preceded by the guard the scenario asked
// for.
func fiberRoute(
	res *httpsecconformance.Result,
	route httpsecconformance.Route,
	spec httpsecconformance.ChainSpec,
) []fiber.Handler {
	var handlers []fiber.Handler

	if spec.Guard.Kind != httpsecconformance.GuardNone && spec.Guard.Path == route.Path {
		handlers = append(handlers, fiberGuard(spec.Guard))
	}

	return append(handlers, func(fc fiber.Ctx) error {
		res.RouteRan = true
		res.RouteHeader = http.Header{}

		for k, v := range fc.Request().Header.All() {
			res.RouteHeader.Add(string(k), string(v))
		}

		httpsecconformance.ReadContext(fc.Context(), res)

		if route.Status != 0 {
			fc.Status(route.Status)
		}

		if route.Body == "" {
			return nil
		}

		return fc.SendString(route.Body)
	})
}

// fiberGuard builds the guard the scenario named, with fibersec's own default:
// the refusal returned, and the route never reached.
func fiberGuard(spec httpsecconformance.GuardSpec) fiber.Handler {
	// The scenario's nil authorizer means the guards rely on what the chain
	// published, so the reliance is declared for every scenario, and a non-nil
	// one is the fallback beside it. Declared, construction cannot fail.
	guardOpts := []fibersec.GuardOption{fibersec.WithChainAuthorizer()}
	if spec.Clock != nil {
		guardOpts = append(guardOpts, fibersec.WithGuardClock(spec.Clock))
	}

	guards, err := fibersec.NewGuards(spec.Authorizer, guardOpts...)
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

// fiberUpstream is middleware outside the chain, standing in for a consumer's
// own tracing: what it publishes must still be readable behind the chain.
func fiberUpstream() fiber.Handler {
	return func(fc fiber.Ctx) error {
		fc.SetContext(context.WithValue(fc.Context(),
			httpsecconformance.UpstreamKey{}, httpsecconformance.UpstreamValue))

		return fc.Next()
	}
}

// fiberRead sends the scenario's request to fiber from the transport peer the
// scenario asked for, and reads the response out in full. A row that asked for
// no address is served from the unspecified address, which is exactly the
// unattributable address that row is about.
func fiberRead(
	t *testing.T,
	app *fiber.App,
	spec httpsecconformance.RequestSpec,
	res *httpsecconformance.Result,
) {
	t.Helper()

	peer := unattributedPeer
	if spec.ClientAddress != "" {
		peer = net.JoinHostPort(spec.ClientAddress, "54321")
	}

	res.Status, res.Header, res.Body = fiberServeFrom(t, app, nethttpRequest(t, spec), peer)
}

// fiberServeFrom runs req through app as if it arrived over TCP from peer, an
// address and port.
//
// fiber's in-memory transport (app.Test) always reports the unspecified
// address as the peer, and the adapters hand the chain the transport peer and
// nothing else, so the request is handed to fiber's fasthttp handler on a
// request context initialised with the peer instead.
func fiberServeFrom(t *testing.T, app *fiber.App, req *http.Request, peer string) (int, http.Header, string) {
	t.Helper()

	addr, err := netip.ParseAddrPort(peer)
	require.NoError(t, err)

	req.RequestURI = ""
	if req.ContentLength > 0 && req.Header.Get("Content-Length") == "" {
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}

	dump, err := httputil.DumpRequest(req, true)
	require.NoError(t, err)

	// The body is read without pre-parsing a multipart form, which would
	// consume it into a form the request context's copy does not carry.
	var freq fasthttp.Request

	br := bufio.NewReader(bytes.NewReader(dump))
	require.NoError(t, freq.Header.Read(br))
	require.NoError(t, freq.ContinueReadBody(br, 0, false))

	var ctx fasthttp.RequestCtx
	ctx.Init(&freq, net.TCPAddrFromAddrPort(addr), nil)

	app.Handler()(&ctx)

	header := http.Header{}
	for k, v := range ctx.Response.Header.All() {
		header.Add(string(k), string(v))
	}

	return ctx.Response.StatusCode(), header, string(ctx.Response.Body())
}

// TestConformanceFiber runs the reference table on fiber. A row that fails here
// and passes on net/http is a defect in the fiber integration, which is the
// whole reason the table is shared.
func TestConformanceFiber(t *testing.T) {
	t.Parallel()

	httpsecconformance.Run(t, fiberAdapter{})
	httpsecconformance.RunScenarios(t, fiberAdapter{}, httpsecconformance.OIDCProviderScenarios())
}

// TestChallengeFiber runs the automation-challenge rows on fiber, which
// TestConformanceFiber leaves out so that each runs once, and so they can be
// run by name.
func TestChallengeFiber(t *testing.T) {
	t.Parallel()

	httpsecconformance.RunScenarios(t, fiberAdapter{}, httpsecconformance.ChallengeScenarios())
}

// The adapters are held to the one interface the table is written against, so a
// change to it is a compile error here rather than a row that quietly stops
// running.
var (
	_ httpsecconformance.Adapter = nethttpAdapter{}
	_ httpsecconformance.Adapter = ginAdapter{}
	_ httpsecconformance.Adapter = fiberAdapter{}
)

// TestSessionBearerFiber runs the session-reference bearer through the fiber
// integration: a live reference reaches the route with its session, and a
// reused one is refused 401. The integration needs no change for the mode.
func TestSessionBearerFiber(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		reference func(f sessionReferenceFixture) string
		assert    func(t *testing.T, f sessionReferenceFixture, status int, seen string)
	}

	cases := []testCase{
		{
			name:      "a live reference authenticates",
			reference: func(f sessionReferenceFixture) string { return f.live },
			assert: func(t *testing.T, f sessionReferenceFixture, status int, seen string) {
				assert.Equal(t, http.StatusOK, status)
				assert.Equal(t, f.live, seen, "the route sees the referenced session")
			},
		},
		{
			name:      "a reused reference is refused",
			reference: func(f sessionReferenceFixture) string { return f.reused },
			assert: func(t *testing.T, f sessionReferenceFixture, status int, seen string) {
				assert.Equal(t, http.StatusUnauthorized, status)
				assert.Empty(t, seen, "the route never ran")

				_, err := f.sessions.Load(t.Context(), f.successor)
				require.ErrorIs(t, err, session.ErrNotFound, "the family was revoked, successor included")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSessionReferenceFixture(t)

			var seen string

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(f.chain))
			app.Get("/orders", func(fc fiber.Ctx) error {
				if s, ok := httpsec.SessionFromContext(fc.Context()); ok {
					seen = s.ID
				}

				return fc.SendStatus(http.StatusOK)
			})

			// The throttle needs an attributable client address, so the
			// request comes from a real transport peer.
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
			req.Header.Set("Authorization", "Bearer "+tc.reference(f))

			status, _, _ := fiberServeFrom(t, app, req, "203.0.113.7:51000")

			tc.assert(t, f, status, seen)
		})
	}
}

// TestSessionBearerFloodedSourceFiber runs the per-source throttle through the
// fiber integration: a source that presented 100 unknown references is refused
// even with a live one, and a source that did not is served.
func TestSessionBearerFloodedSourceFiber(t *testing.T) {
	t.Parallel()

	f := newSessionReferenceFixture(t)

	app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
	app.Use(fibersec.Middleware(f.chain))
	app.Get("/orders", func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusOK) })

	send := func(source, reference string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil)
		req.Header.Set("Authorization", "Bearer "+reference)

		status, _, _ := fiberServeFrom(t, app, req, source+":51000")

		return status
	}

	for i := range 100 {
		require.Equal(t, http.StatusUnauthorized, send("203.0.113.7", referenceUnknownTo(i)))
	}

	assert.Equal(t, http.StatusUnauthorized, send("203.0.113.7", f.live), "the flooded source is refused")
	assert.Equal(t, http.StatusOK, send("198.51.100.4", f.live), "another source is served")
}

// TestCertificateBindingFiber runs the certificate-binding scenarios on
// fiber, through a trusted proxy that forwards the client's certificate.
func TestCertificateBindingFiber(t *testing.T) {
	t.Parallel()

	httpsecconformance.RunCertificateBinding(t, fiberAdapter{})
}
