package fibersec

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v3"

	"github.com/kartaladev/scrty/httpsec"
)

// Middleware runs the chain in front of the fiber handlers registered after it.
//
// The chain is built once with httpsec.New and the options that deployment
// wants, and this puts it in front of the fiber app. Nothing about the
// decisions changes from the net/http chain: the request and the response are
// read and written through fiber's own context, so a secured request is never
// turned into a net/http request first.
//
// A fiber route behind it reads everything the chain resolved — the caller, the
// authentication result, the session, the authorizer — through the handler
// context's request context, c.Context(), because the chain's context is
// written back there immediately before the remaining fiber handlers run. It is
// derived from the incoming context and never replaces it, so a value fiber
// middleware outside the chain set is still readable behind it.
//
// An error the route or a later fiber handler returns is not a refusal. It
// passes back unchanged, so fiber answers it as it would without the chain.
//
// A refusal is returned as an error, which is what fiber's own error handling
// reads. The route does not run. The error still matches the original refusal
// through errors.Is and errors.As, and carries the mapped status as a
// *fiber.Error, while its own text is only the standard status text — see
// RefusalError for why. Set ErrorHandler as fiber.Config.ErrorHandler to answer
// it with the bare status and an empty body.
//
// The chain's own httpsec.WithErrorHandler governs the net/http entrypoint and
// does not run here: on fiber a refusal goes to fiber's error handler, which is
// where a fiber application already handles every other error.
//
// Handlers registered after this one do not run for a refused request, or for
// one the chain answered itself — a login, a logout, the key set — so logging
// and metrics belong before it.
//
// # Request cancellation
//
// The chain runs on a context derived from fiber's request context that ends
// when this handler returns, so work an interceptor started on it stops with
// the request, as it does under net/http. fiber's own request context is not
// cancelled for code outside the chain.
//
// After the chain returns, fiber's request context stays the one the route
// read, so a fiber middleware mounted before the chain sees, through
// c.Context() after c.Next(), the caller, the session and everything else the
// chain published. Its deadline, cancellation and cause remain those of the
// context that middleware set up, never the chain's end-of-request
// cancellation.
//
// A route behind the chain reads a context that carries every value the chain
// added, while its deadline and cancellation are those of fiber's own context
// as this handler found it. The chain's end-of-request cancellation does not
// reach it, so a body the route streams with SendStreamWriter, which fiber
// writes after the handlers return, still sees a live request context while it
// is written, and a deadline or cancellation that middleware outside the chain
// set before it keeps bounding the route.
//
// A client that disconnects mid-request is not detected on fiber. fasthttp
// gives the handler no disconnect signal: its RequestCtx.Done() fires only at
// server shutdown. The chain's context therefore ends when the request's
// handling ends, not earlier, and a long-running interceptor must bound itself
// with its own deadline.
//
// A nil chain is a wiring mistake and panics here, at wiring time, rather than
// on the first request a server takes.
func Middleware(chain *httpsec.Chain) fiber.Handler {
	if chain == nil {
		panic("fibersec: Middleware needs a chain; a nil one would serve every request unguarded")
	}

	return func(fc fiber.Ctx) error {
		// The chain is folded around this request rather than once per mount,
		// because the innermost step is the only place that still holds fiber's
		// own context, and smuggling it through the exchange would let every
		// interceptor reach past the abstraction the chain exists to present.
		//
		// nextErr is what the remaining fiber handlers returned. It is kept
		// apart from the chain's own refusals, because a route's error is the
		// route's to answer and is not a refusal of the request.
		var nextErr error

		outer := fc.Context()

		//nolint:contextcheck // ex.Context() derives from fc.Context(), which is what is written back here
		run := chain.Assemble(func(ex *httpsec.Exchange) error {
			// Written back before the remaining fiber handlers run, so a route
			// reads the caller and the session through c.Context() as usual.
			//
			// The chain's own context ends when this handler returns, but the
			// route's must not: fiber writes a streamed body after the handlers
			// have returned, so the route would see "context canceled" while it
			// is still writing. The route's context therefore reads values from
			// the chain's context but its deadline and cancellation from
			// fiber's original one, so an upstream timeout still bounds it. The
			// chain's side is WithoutCancel so the context package's cause
			// lookup falls through to fiber's context, not the chain's cancel.
			fc.SetContext(routeContext{Context: outer, chain: context.WithoutCancel(ex.Context())})

			nextErr = fc.Next()

			return nextErr
		})

		// Seeded from fiber's own request context, so a value middleware outside
		// the chain set survives it. The chain runs on a child of it that ends
		// when this handler returns, as net/http ends r.Context() when
		// ServeHTTP returns. fiber's context is left as the route saw it: its
		// values come from the chain, but Deadline, Done, Err and the cause
		// come from outer, which the cancel below never reaches, so middleware
		// outside the chain reads what the chain published after Next without
		// seeing the chain's cancellation.
		ctx, cancel := context.WithCancel(outer)
		defer cancel()

		ex := httpsec.NewExchange(ctx, request{c: fc}, &responseWriter{c: fc})

		if err := run(ex); err != nil {
			// What the route or a later handler returned goes back as it came,
			// so fiber's own handling reads its status and text. Matching with
			// errors.Is also covers an interceptor that wrapped it on the way
			// out, and never a refusal the chain made itself.
			if nextErr != nil && errors.Is(err, nextErr) {
				return err
			}

			return newRefusal(err)
		}

		// A request the chain answered itself returns no error and called no
		// Next, which is what stops the remaining fiber handlers: the chain has
		// already written its answer, and anything written here would be a
		// second one over the first.
		return nil
	}
}

// routeContext is the request context a route behind the chain reads. Values
// are looked up on the chain's context first, so the caller, the session and
// anything an interceptor added are visible, and then on fiber's original
// context. Deadline, Done and Err come only from the embedded original context:
// the chain's context is cancelled when the middleware returns, which is before
// fiber writes a streamed body, and taking its cancellation would end the route's
// context while it is still writing. Taking fiber's original one instead keeps
// whatever bounded the request before the chain, such as a timeout an outer
// fiber middleware set.
type routeContext struct {
	context.Context

	chain context.Context
}

// Value reads the chain's context before fiber's original one.
func (c routeContext) Value(key any) any {
	if v := c.chain.Value(key); v != nil {
		return v
	}

	return c.Context.Value(key)
}
