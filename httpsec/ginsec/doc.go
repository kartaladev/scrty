// Package ginsec runs scrty's security chain in front of gin handlers.
//
// It is the gin half of the same chain a net/http consumer mounts: the chain is
// built once with httpsec.New and the options that deployment wants, and
// Middleware puts it in front of the gin engine. Nothing about the decisions
// changes — the same request, the same configuration and the same refusal —
// because gin's context carries both net/http types, so the chain's own
// net/http request and response implementations are reused here rather than
// reimplemented.
//
//	chain, err := httpsec.New(
//		httpsec.EnableFormLogin(deps),
//		httpsec.EnableBearerToken(bearer),
//	)
//	if err != nil {
//		return err
//	}
//
//	engine := gin.New()
//	engine.Use(logging(), metrics())     // before the chain: see below
//	engine.Use(ginsec.Middleware(chain))
//	engine.GET("/reports", handler)
//
// # Register logging and metrics before the chain
//
// gin middleware registered after this one does not run for a request the chain
// refused, or for one the chain answered itself — a login, a logout, the key
// set. Both stop the remaining gin handlers, which is what keeps a route from
// overwriting the answer. Anything that must see every request, such as access
// logging or metrics, therefore goes before the chain, where it still observes
// the response the chain wrote on the way back out.
//
// # Refusals
//
// A refusal is registered on gin's error channel and answered with the status
// httpsec.StatusForError gives, set but not committed. So a consumer's own gin
// error middleware — registered before the chain, reading c.Errors after
// c.Next() — still owns the status, the headers and the body, and a deployment
// with no error middleware at all is still answered the mapped status with an
// empty body rather than 200.
//
// The chain's httpsec.WithErrorHandler is the net/http entrypoint's and does
// not run here. gin's error channel is this adapter's equivalent, and it is
// where a gin application already handles every other error.
//
// One refusal is committed instead of left open for that error middleware: a
// 404 for a request gin matched no route for at all, such as a federated
// login path naming an unregistered provider. Left open, gin's own no-route
// fallback would write its default "404 page not found" body there, which the
// net/http and fiber adapters never send for the same refusal. This adapter
// commits that one case with an empty body instead, so a consumer's own gin
// error middleware cannot re-render it — every other refusal, including a 404
// on a route gin did match, keeps the rule above.
//
// # Client addresses
//
// A request is attributed to its transport peer, which is the one address a
// client cannot choose for itself. WithForwardedClientIP opts into gin's own
// proxy-aware address instead; read its documentation before enabling it, since
// gin trusts every proxy until the consumer calls engine.SetTrustedProxies.
//
// # Per-endpoint authorization
//
// NewGuards builds the guards a consumer puts on individual routes, mirroring
// httpsec.Guards and refusing the same way: the error on gin's channel, the
// mapped status, and the route never reached.
package ginsec
