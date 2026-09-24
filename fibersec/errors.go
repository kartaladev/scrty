package fibersec

import (
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/kartaladev/scrty/httpsec"
)

// RefusalError is what the chain returns to fiber when it refuses a request.
//
// It wraps two things through Unwrap() []error: the refusal itself, so
// errors.Is and errors.As still reach it and a *httpsec.ChallengeError is still
// readable by a consumer rendering a prompt; and a *fiber.Error carrying the
// status httpsec.StatusForError gave, so fiber's own error handling reads the
// status the way it expects.
//
// Its own text is only the standard status text for that status. fiber's
// built-in DefaultErrorHandler writes err.Error() straight into the response
// body, so a raw refusal would put internal detail — a driver's message, a
// provider's hostname — in front of any consumer who configured no handler at
// all. The status text says what happened without saying anything a client
// should not learn, and the refusal is still there, as a field, for a consumer
// who asks for it.
type RefusalError struct {
	refusal error
	status  *fiber.Error
}

// Error is the standard text for the mapped status and nothing else.
func (e *RefusalError) Error() string { return http.StatusText(e.status.Code) }

// Unwrap exposes the refusal and the status to errors.Is and errors.As.
func (e *RefusalError) Unwrap() []error { return []error{e.refusal, e.status} }

// newRefusal wraps a refusal the chain returned so fiber can answer it.
func newRefusal(err error) error {
	status := httpsec.StatusForError(err)

	return &RefusalError{refusal: err, status: fiber.NewError(status)}
}

// ErrorHandler answers a refusal with the mapped status and an empty body.
//
// Set it as fiber.Config.ErrorHandler to get the same fail-closed default the
// net/http chain has:
//
//	app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
//
// Default: without it, fiber's built-in handler answers the same status but
// writes the status text as the body, because fiber owns that handler and this
// library cannot make it write nothing. Either way no refusal's own text
// reaches a client.
//
// It writes no body of its own, and it leaves whatever an interceptor already
// wrote — a WWW-Authenticate header, say — in place. A consumer who wants a
// rendered body writes their own handler and calls MapError, or reads the
// refusal with errors.Is and errors.As and renders from that.
func ErrorHandler(c fiber.Ctx, err error) error {
	c.Status(httpsec.StatusForError(err))

	return nil
}

// MapError returns the status and a minimal body for a consumer's own error
// handler to send once it has logged or enriched the refusal.
//
// The body holds only the standard status text, never the error's own, for the
// same reason ErrorHandler sends no body at all: what a refusal knows is the
// deployment's, not the client's.
//
//	app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
//		log.Error("refused", "err", err)
//		status, body := fibersec.MapError(err)
//		return c.Status(status).JSON(body)
//	}})
func MapError(err error) (int, any) {
	status := httpsec.StatusForError(err)

	return status, fiber.Map{"error": http.StatusText(status)}
}
