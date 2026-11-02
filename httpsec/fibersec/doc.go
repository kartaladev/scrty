// Package fibersec runs scrty's security chain in front of fiber handlers.
//
// It is the fiber half of the same chain a net/http consumer mounts: the chain
// is built once with httpsec.New and the options that deployment wants, and
// Middleware puts it in front of the fiber app. Nothing about the decisions
// changes — the same request, the same configuration and the same refusal —
// but nothing is converted either: the request and response abstractions the
// chain reads and writes through are implemented over fiber's own context, so
// a secured request never becomes a net/http request.
//
//	chain, err := httpsec.New(
//		httpsec.EnableFormLogin(deps),
//		httpsec.EnableBearerToken(bearer),
//	)
//	if err != nil {
//		return err
//	}
//
//	app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
//	app.Use(logging(), metrics())     // before the chain: see below
//	app.Use(fibersec.Middleware(chain))
//	app.Get("/reports", handler)
//
// # Register logging and metrics before the chain
//
// fiber middleware registered after this one does not run for a request the
// chain refused, or for one the chain answered itself — a login, a logout, the
// key set. Both stop the remaining handlers, which is what keeps a route from
// overwriting the answer. Anything that must see every request, such as access
// logging or metrics, therefore goes before the chain, where it still observes
// the response the chain wrote on the way back out.
//
// # Request cancellation
//
// The chain runs on a context derived from fiber's request context, which ends
// when Middleware's handler returns, as net/http's request context ends when
// ServeHTTP returns. On fiber a mid-request client disconnect is not detected:
// fasthttp's RequestCtx.Done() fires only at server shutdown, so the chain's
// context ends when the request's handling ends, not earlier. fiber's own
// request context is never cancelled for code outside the chain, and after the
// chain returns it keeps the values the chain published, so middleware mounted
// before the chain reads the caller and the session through c.Context() after
// c.Next(), with the deadline and cancellation it set itself.
// A route behind the chain reads the values the chain added through a context
// whose deadline and cancellation are fiber's own, as found on entry. The
// chain's end-of-request cancellation does not reach it, so a body it streams
// after the handlers return still sees a live request context, and a timeout
// that middleware outside the chain set keeps bounding the route.
//
// # Refusals
//
// A refused request returns a RefusalError from the chain's handler, so fiber's
// error handling answers it and the route never runs. The refusal is still
// matchable with errors.Is and errors.As — including a *httpsec.ChallengeError,
// with the session and the token a prompt needs — and it carries the mapped
// status as a *fiber.Error, which is what fiber itself reads.
//
// Its own text is only the standard status text. fiber's built-in
// DefaultErrorHandler writes the error's text into the response body, so a
// deployment that configures no handler at all still answers, for example, 500
// with the body "Internal Server Error" and never the cause behind it. Setting
// ErrorHandler as fiber.Config.ErrorHandler answers the bare status with an
// empty body instead, and MapError gives the status and a minimal body to a
// consumer's own handler.
//
// The chain's own httpsec.WithErrorHandler governs the net/http chain only. It
// does not run here: on fiber a refusal goes to fiber's error handler, which is
// where a fiber application already handles every other error.
//
// # Client addresses
//
// The adapter hands the chain the connection's own peer, the Host header, the
// connection's TLS state and the headers as received. A request is therefore
// attributed to its transport peer, the one address a client cannot choose
// for itself, unless the chain's own httpsec.EnableTrustedProxies trusts a
// proxy in front of it, which resolves the client, scheme and host the same
// way on every adapter:
//
//	chain, err := httpsec.New(
//		httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
//			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
//			Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto),
//		}),
//		// ...
//	)
//
// fiber's own proxy settings have no effect on the chain: TrustProxy,
// TrustProxyConfig and ProxyHeader change what c.IP(), c.Hostname(),
// c.Secure() and c.Scheme() return, and the adapter calls none of them. A
// handler that wants the values the chain resolved reads
// httpsec.ClientFromContext(c.Context()).
//
// A transport that is not a TCP connection reports a peer the chain cannot
// attribute. fiber's in-memory test transport (app.Test) and a Unix-socket
// listener both report an unspecified peer, and the chain's refusal of an
// empty, malformed or unspecified address applies to it. A proxy on a Unix
// socket therefore cannot be trusted by EnableTrustedProxies, which matches
// prefixes of addresses, and its forwarded headers are never read.
//
// # What fiber's context does not promise
//
// fiber's string and body accessors are zero-copy views into the buffer
// fasthttp reuses, and fiber recycles the context itself as soon as the request
// ends. Everything the chain reads it reads during the request, and Request's
// Body copies before returning, so nothing the chain publishes outlives the
// buffer it came from. An interceptor or a route handler that keeps a value
// past the request — in a queued job, a goroutine, a cache — copies it first,
// or sets fiber's own Config.Immutable.
//
// fiber cannot tell an empty cookie from an absent one: it answers "" for both,
// so Request.Cookie reports an empty cookie as absent. No interceptor keys a
// decision on the difference, and a consumer's should not either.
//
// The login body limit is a length check here rather than a bounded read.
// fasthttp has read the whole request before a handler runs, so there is
// nothing left to bound: an oversized body is refused with
// httpsec.ErrRequestTooLarge, but the bytes were already read. Set fiber's own
// Config.BodyLimit to cap what the server reads at all.
//
// # Per-endpoint authorization
//
// NewGuards builds the guards a consumer puts on individual routes, mirroring
// httpsec.Guards and refusing the same way: the refusal returned, and the route
// never reached.
//
// Guards are built with an authorizer, with WithChainAuthorizer to rely on the
// one the chain publishes on each request, or with both. Building them with
// neither fails with an error wrapping httpsec.ErrConfig.
package fibersec
