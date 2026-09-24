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
// A request is attributed to fiber's own client address, which is the transport
// peer until the consumer enables fiber's proxy trust. The chain's refusal of
// an empty, malformed or unspecified address applies to whatever that returns.
//
// Behind a proxy, all four of these are needed before a forwarded address may
// be believed:
//
//	app := fiber.New(fiber.Config{
//		TrustProxy: true,
//		TrustProxyConfig: fiber.TrustProxyConfig{
//			Proxies: []string{"10.0.0.2"}, // every proxy, named explicitly
//		},
//		ProxyHeader:        fiber.HeaderXForwardedFor,
//		EnableIPValidation: true,
//	})
//
// TrustProxy turns the whole mechanism on; without it fiber reads no forwarding
// header at all. TrustProxyConfig.Proxies names the peers whose header may be
// believed. ProxyHeader names the header, and until it is set fiber reads none,
// so trusting a proxy without it changes nothing. EnableIPValidation makes
// fiber walk the chain and skip the proxies it trusts, rather than taking a
// value whole.
//
// When the proxy reaches the app over a Unix socket, set
// TrustProxyConfig.UnixSocket as well, and keep an explicit Proxies list —
// "0.0.0.0" is the entry for a socket-only proxy, which is also what fiber's
// in-memory test transport reports as the peer. UnixSocket on its own is not
// enough: fiber treats a configuration with no Proxies, ranges, Loopback,
// Private or LinkLocal as having no trusted-proxy list, and then selects the
// leftmost address in the header — the one the client wrote. That is the
// address an attacker chooses for themselves.
//
// Loopback, Private and LinkLocal are the other trap. They trust every address
// in those ranges as a proxy, which means a real client inside one of them —
// an internal service, a VPN client, a container network — is skipped rather
// than attributed. Name the proxies instead.
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
package fibersec
