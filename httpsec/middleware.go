package httpsec

import "net/http"

// Middleware runs the chain in front of an ordinary net/http handler.
//
// It is the entrypoint a consumer who wires nothing of their own gets: the
// request and the response writer are adapted with NewHTTPRequest and
// NewHTTPResponseWriter, every interceptor runs in slot order, and the handler
// is reached only when none of them refused.
//
// The handler reads everything the chain resolved — the caller, the session,
// the authorizer — through r.Context() as usual, because the chain's context is
// written back onto the request at the innermost point, immediately before the
// handler runs. It is derived from the incoming request's context and never
// replaces it, so a value an outer middleware set and the client's own
// cancellation both survive.
//
// A refusal is answered by the error handler: the mapped status and no body by
// default, and whatever WithErrorHandler was given instead.
func (c *Chain) Middleware() func(http.Handler) http.Handler {
	return func(downstream http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Seeded from the incoming context, never replaced, so values and
			// cancellation set before the chain survive it.
			ex := NewExchange(r.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(w))

			// The chain is folded around this request's handler rather than once
			// per mount, because the terminal is the only place that still holds
			// the framework's own writer and request, and smuggling them through
			// the exchange would make every interceptor able to reach past the
			// abstraction the chain exists to present.
			//nolint:contextcheck // ex.Context() is derived from r.Context(), which is what is written back here
			run := c.Assemble(func(ex *Exchange) error {
				downstream.ServeHTTP(w, r.WithContext(ex.Context()))

				return nil
			})

			if err := run(ex); err != nil {
				c.handleError(ex, w, r, err)
			}
		})
	}
}

// handleError answers a refusal.
//
// The default is the mapped status and nothing else: a body would either leak
// what the refusal knew — a driver's error text, whether an account exists — or
// invent a format the consumer must then work around. Rendering is the
// consumer's, through WithErrorHandler; this library's job is to fail closed.
//
// The default writes through the exchange's own writer, which ignores a second
// status, so an interceptor that already answered the request keeps the status
// it chose. A consumer's handler is handed the framework's writer and owns the
// whole response, including that decision.
func (c *Chain) handleError(ex *Exchange, w http.ResponseWriter, r *http.Request, err error) {
	if c.errorHandler != nil {
		c.errorHandler(w, r, err)

		return
	}

	ex.Writer.WriteHeader(StatusForError(err))
}
