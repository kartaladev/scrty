package fibersec

import (
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
		//nolint:contextcheck // ex.Context() derives from fc.Context(), which is what is written back here
		run := chain.Assemble(func(ex *httpsec.Exchange) error {
			// Written back before the remaining fiber handlers run, so a route
			// reads the caller and the session through c.Context() as usual.
			fc.SetContext(ex.Context())

			return fc.Next()
		})

		// Seeded from fiber's own request context, never replaced, so a value
		// middleware outside the chain set survives it.
		ex := httpsec.NewExchange(fc.Context(), request{c: fc}, &responseWriter{c: fc})

		if err := run(ex); err != nil {
			return newRefusal(err)
		}

		// A request the chain answered itself returns no error and called no
		// Next, which is what stops the remaining fiber handlers: the chain has
		// already written its answer, and anything written here would be a
		// second one over the first.
		return nil
	}
}
