package ginsec

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/kartaladev/scrty/httpsec"
)

// Middleware runs the chain in front of the gin handlers registered after it.
//
// gin's context carries both net/http types, so the chain's own net/http
// request and response implementations are reused rather than reimplemented:
// one abstraction, adapted once, behaves the same here as it does behind
// net/http.
//
// A gin route behind it reads everything the chain resolved — the caller, the
// session, the authorizer — through c.Request.Context() as usual, because the
// chain's context is written back onto the request immediately before the rest
// of the gin handlers run. It is derived from the incoming request's context
// and never replaces it, so a value gin middleware outside the chain set, and
// the client's own cancellation, both survive.
//
// A refusal is registered on gin's error channel and answered with the mapped
// status, set but not committed, so the consumer's own error middleware still
// owns the status, the headers and the body. A request the chain answered
// itself — a login, a logout, the key set — stops the gin handlers with no
// status of its own, so neither a matched route nor a no-route handler can
// overwrite what the chain wrote.
//
// One refusal is committed instead of left open: a 404 for a request gin
// matched no route for at all, such as a path a chain endpoint would own but
// that names an unregistered provider. gin's own no-route fallback writes its
// default "404 page not found" body there whenever nothing has been written,
// which the other adapters never send for the same refusal; committing an
// empty body keeps the three answering alike, at the cost that a consumer's
// own gin error middleware cannot re-render that one case. Every other
// refusal, and every 404 on a route gin did match, still leaves the status
// open for it.
//
// The chain's own WithErrorHandler is the net/http entrypoint's, and does not
// run here: on gin the refusal goes to gin's error channel instead, which is
// where a gin consumer already handles every other error. An error middleware
// that answers authenticate.ErrUnavailable with 503 reopens the oracles
// httpsec.StatusForError warns of.
//
// A stream goes through gin's writer, and through whatever a gin middleware outside
// this one replaced c.Writer with. A replacement that adds a FlushError is asked to
// flush before a status is named, so on a path with no route it can send a live stream
// under the 404 gin holds there. Otherwise the stream flushes with the replacement's
// Flush, or with gin's if that is what it unwraps to, and one that does nothing cannot
// be told from one that delivered.
//
// Handlers registered after this one do not run for a refused or self-answered
// request, so logging and metrics belong before it.
//
// Routes registered before this middleware is added are not guarded by the
// chain. Mounting one chain twice on a request, for example on the engine and again
// on a group, runs it once: the second mount lets the request through. Two
// different chains both run, each counting its own attempts.
//
// The second mount lets the request through as the first mount judged it, so a
// middleware between the two mounts that changes what a rule reads (the host, a
// header, the query) is not judged again, nor is a request HandleContext
// re-dispatches on the same path. Put such middleware before the first mount.
//
// A nil chain is a wiring mistake and panics here, at wiring time, rather than
// on the first request a server takes.
//
// When the chain passes the request on, c.Request carries the chain's context
// afterwards, so a gin middleware registered before the chain reads that context
// after c.Next() returns. A request refused before the chain reached the gin
// handlers keeps its c.Request; one refused after them (an interceptor that
// returns an error after next) keeps the chain's context.
func Middleware(chain *httpsec.Chain) gin.HandlerFunc {
	if chain == nil {
		panic("ginsec: Middleware needs a chain; a nil one would serve every request unguarded")
	}

	return func(gc *gin.Context) {
		// The raw transport peer and headers, never gin's ClientIP: gin trusts
		// every proxy until configured, and which proxies may name a client is
		// the chain's decision (httpsec.EnableTrustedProxies), made the same
		// way on every adapter.
		request := httpsec.NewHTTPRequest(gc.Request)

		// reached reports whether the chain ran the gin handlers behind it. It
		// separates a request the chain passed through from one an interceptor
		// answered itself, which are told apart by nothing else: both leave the
		// chain with no error.
		reached := false

		// The fold is built once per chain; only this request's terminal, the
		// step that runs the remaining gin handlers, is recorded per request,
		// because that step is the only place that still holds gin's own
		// context, and smuggling it through the exchange would let every
		// interceptor reach past the abstraction the chain exists to present.
		//nolint:contextcheck // ex.Context() derives from gc.Request.Context(), which is what is written back here
		run := chain.Assemble(func(ex *httpsec.Exchange) error {
			reached = true

			// Written back before the rest of the gin handlers run, so a route
			// reads the caller and the session through c.Request.Context() as
			// usual.
			gc.Request = gc.Request.WithContext(ex.Context())
			gc.Next()

			return nil
		})

		ex := httpsec.NewExchange(
			gc.Request.Context(), request, httpsec.NewHTTPResponseWriter(streamWriter{gc.Writer}))

		if err := run(ex); err != nil {
			refuse(gc, err)

			return
		}

		if !reached {
			// A request the chain answered itself. A bare abort, with no status
			// of its own: the chain has already written what it wanted, and
			// anything set here would be a second answer over the first.
			gc.Abort()
		}
	}
}

// refuse answers a refusal the one way this adapter answers one.
//
// The error goes on gin's channel first, so a consumer's error middleware
// handles it the way it handles every other error of their application.
//
// The status is set with Status rather than AbortWithStatus: Status is lazy and
// Abort does not commit it, so error middleware further out can still choose
// the status, set its own headers and write its own body. AbortWithStatus
// writes the header block there and then, and would leave a consumer unable to
// render anything at all.
//
// The status is set, and not merely the error registered, because with no error
// middleware at all registering and aborting answers 200 with an empty body —
// a refusal served as a success. A response an interceptor already committed is
// left alone: it chose that status, and this is not the place to take it back.
//
// One case is committed here instead of left open: a 404 for a request gin
// matched no route for at all. gin's own no-route fallback writes its default
// "404 page not found" body whenever a 404 reaches it with nothing written —
// a body the net/http and fiber adapters never send for the same refusal, and
// the only way to keep the three answering alike. The cost is that a
// consumer's own gin error middleware cannot re-render this one case: by the
// time it runs, the empty body is already on the wire. Every other refusal,
// and every 404 on a route gin did match, is left exactly as above.
func refuse(gc *gin.Context, err error) {
	_ = gc.Error(err)

	if !gc.Writer.Written() {
		status := httpsec.StatusForError(err)
		gc.Status(status)

		if status == http.StatusNotFound && gc.FullPath() == "" {
			gc.Writer.WriteHeaderNow()
		}
	}

	gc.Abort()
}
