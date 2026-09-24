package test_test

import (
	"context"
	"io"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/fibersec"
	httpsecconformance "github.com/kartaladev/scrty/test/httpsecconformance"
)

// inMemoryPeer is what fiber's in-memory test transport reports as the peer: an
// unspecified address, which the chain refuses rather than pooling every caller
// behind it into one rate-limit bucket. Every row that needs an attributable
// address therefore trusts that peer as a proxy and forwards the address the
// scenario asked for.
const inMemoryPeer = "0.0.0.0"

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

	app := fiber.New(fiber.Config{
		ErrorHandler: func(fc fiber.Ctx, err error) error {
			res.Refusal = err

			return fibersec.ErrorHandler(fc, err)
		},

		// The four settings fiber needs before a forwarded address may be
		// believed. The in-memory transport's peer is the trusted proxy, which
		// is the same shape as a proxy reaching the app over a Unix socket.
		TrustProxy:         true,
		TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: []string{inMemoryPeer}},
		ProxyHeader:        fiber.HeaderXForwardedFor,
		EnableIPValidation: true,
	})

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
	guards := fibersec.NewGuards(spec.Authorizer)

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

// fiberRead sends the scenario's request over fiber's in-memory transport and
// reads the response out in full.
//
// The address the scenario asked for is forwarded rather than set as the peer,
// because the in-memory transport names the peer itself. A row that asked for
// no address forwards none, and fiber reports the unspecified peer — which is
// exactly the unattributable address that row is about.
//
// The timeout is disabled: a row that deadlocks is better reported by the test
// framework's own timeout, with every goroutine's stack, than by fiber
// returning a timeout error that hides where the request stopped.
func fiberRead(
	t *testing.T,
	app *fiber.App,
	spec httpsecconformance.RequestSpec,
	res *httpsecconformance.Result,
) {
	t.Helper()

	req := nethttpRequest(t, spec)
	req.RemoteAddr = ""

	if spec.ClientAddress != "" {
		req.Header.Set(fiber.HeaderXForwardedFor, spec.ClientAddress)
	}

	out, err := app.Test(req, fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
	require.NoError(t, err)

	defer func() { require.NoError(t, out.Body.Close()) }()

	body, err := io.ReadAll(out.Body)
	require.NoError(t, err)

	res.Status, res.Header, res.Body = out.StatusCode, out.Header, string(body)
}

// TestConformanceFiber runs the reference table on fiber. A row that fails here
// and passes on net/http is a defect in the fiber integration, which is the
// whole reason the table is shared.
func TestConformanceFiber(t *testing.T) {
	t.Parallel()

	httpsecconformance.Run(t, fiberAdapter{})
}

// The adapters are held to the one interface the table is written against, so a
// change to it is a compile error here rather than a row that quietly stops
// running.
var (
	_ httpsecconformance.Adapter = nethttpAdapter{}
	_ httpsecconformance.Adapter = ginAdapter{}
	_ httpsecconformance.Adapter = fiberAdapter{}
)
