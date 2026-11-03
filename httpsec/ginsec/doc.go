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
// The adapter hands the chain the raw transport peer, the Host header, the
// connection's TLS state and the headers as received. A request is therefore
// attributed to its transport peer, the one address a client cannot choose for
// itself, unless the chain's own httpsec.EnableTrustedProxies trusts a proxy
// in front of it, which resolves the client, scheme and host the same way on
// every adapter.
//
// gin's own proxy settings have no effect on the chain: engine.SetTrustedProxies,
// c.ClientIP() and gin's forwarded-header options are never consulted. gin
// trusts every proxy until configured, so its client address is one a client
// can choose. A handler that wants the address the chain resolved reads
// httpsec.ClientFromContext(c.Request.Context()).
//
// A transport that is not a TCP connection, such as an in-memory test
// transport or a Unix socket, reports an unspecified peer: one that is not in
// host and port form, and the chain attributes such a request to no address.
// The chain's refusal of an empty, malformed or unspecified address applies to
// it, and a proxy on a Unix socket cannot be trusted by EnableTrustedProxies,
// which matches prefixes of addresses.
//
// # Per-endpoint authorization
//
// NewGuards builds the guards a consumer puts on individual routes, mirroring
// httpsec.Guards and refusing the same way: the error on gin's channel, the
// mapped status, and the route never reached.
//
// Guards are built with an authorizer, with WithChainAuthorizer to rely on the
// one the chain publishes on each request, or with both. Building them with
// neither fails with an error wrapping httpsec.ErrConfig.
package ginsec
