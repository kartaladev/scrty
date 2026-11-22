package fibersec

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v3"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/internal/porterr"
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

// Error is the standard text for the mapped status and nothing else. A
// RefusalError the adapter did not build carries no status, and its text is
// the 500 status text.
func (e *RefusalError) Error() string { return http.StatusText(e.code()) }

// code is the status the chain mapped, or 500 for a RefusalError the adapter
// did not build.
func (e *RefusalError) code() int {
	if e == nil || e.status == nil {
		return http.StatusInternalServerError
	}

	return e.status.Code
}

// classified returns the status the adapter stored in err when err is, as it
// stands, a refusal the adapter built, so it is answered without classifying
// it again. Anything else, a zero RefusalError included, reports false.
func classified(err error) (int, bool) {
	refusal, ok := err.(*RefusalError) //nolint:errorlint // the chain's own value, read as it stands
	if !ok || refusal == nil || refusal.status == nil {
		return 0, false
	}

	return refusal.status.Code, true
}

// Unwrap exposes the refusal and the status to errors.Is and errors.As.
func (e *RefusalError) Unwrap() []error { return []error{e.refusal, e.status} }

// newRefusal wraps a refusal the chain returned so fiber can answer it.
//
// The status is classified here, once, and carried in the RefusalError, so the
// error handler that answers it does not walk the chain again. A chain whose
// walk aborts — a cycle, too many links, a panicking method — is answered 500
// and reported once, here, without calling anything on it.
func newRefusal(ctx context.Context, err error) error {
	var buf [walkBuffer]error

	if _, abort := errwalk.FlattenInto(buf[:], err); abort != nil {
		return abortedRefusal(ctx, err, abort)
	}

	// fibersec's walk succeeded, so it writes no record. The core's own
	// classification can still abort, on an Is or As method that panics, which
	// Flatten never calls; the core then writes the record itself. Either way
	// the request has one.
	status := statusFor(ctx, err)

	return &RefusalError{refusal: err, status: fiber.NewError(status)}
}

// abortedRefusal answers a refusal whose chain could not be walked with a 500
// and writes the one record of it. The record carries the reason only: the
// error's text is never read, since a hostile node's Error method is not
// trusted either.
func abortedRefusal(ctx context.Context, err, abort error) error {
	reportAbort(ctx, abort)

	return &RefusalError{refusal: err, status: fiber.NewError(http.StatusInternalServerError)}
}

// reportAbort writes the Error record for an aborted classification through
// porterr.ReportAbort, as the core's own lookup does: a constant message, the
// reason, and for a recovered panic its Go type and the frames the walk
// captured where it panicked, never its value or the error's text. The record
// goes to the logger of the chain handling the request, read from ctx, else to
// slog.Default() when it is written.
func reportAbort(ctx context.Context, abort error) {
	porterr.ReportAbort(ctx, nil, abort)
}

// ErrorHandler answers a refusal with the mapped status and an empty body.
//
// Set it as fiber.Config.ErrorHandler to get the same fail-closed default the
// net/http chain has:
//
//	app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
//
// An error that carries a fiber status and is not a refusal, such as a route's
// own fiber.NewError(422, ...) or the router's 404, is answered with that
// status, so the handler can stand as the app's only one.
//
// Default: without it, fiber's built-in handler answers the same status but
// writes the status text as the body, because fiber owns that handler and this
// library cannot make it write nothing. Either way no refusal's own text
// reaches a client.
//
// It writes no body of its own, and it leaves whatever an interceptor already
// wrote — a WWW-Authenticate header, say — in place. A consumer who wants a
// rendered body writes their own handler and calls MapError, or reads the
// refusal with errors.Is and errors.As and renders from that. A handler that
// answers authenticate.ErrUnavailable with 503 reopens the oracles
// httpsec.StatusForError warns of.
func ErrorHandler(ctx fiber.Ctx, err error) error {
	ctx.Status(handlerStatus(ctx.Context(), err))

	return nil
}

// handlerStatus is the status ErrorHandler answers err with.
//
// A refusal the chain made, as it stands, carries the status it was classified
// with, and is answered with it, without a second classification. Anything
// else is flattened once: a refusal found anywhere in it is answered with the
// core's classification of the whole error, so an outage joined with a refusal
// still reads as the failed authentication it conceals; with no refusal, a
// fiber status keeps its status; and anything else is classified by the core.
//
// An abort in fibersec's own walk or matching is answered 500 and reported
// here, and the core is never asked about that error. An abort in the core's
// classification is reported by the core. So the handler never reports one
// error twice.
func handlerStatus(ctx context.Context, err error) int {
	if status, ok := classified(err); ok {
		return status
	}

	var buf [walkBuffer]error

	chain, abort := errwalk.FlattenInto(buf[:], err)
	if abort != nil {
		return failClosed(ctx, abort)
	}

	if _, found, abort := errwalk.As[*RefusalError](chain); abort != nil {
		return failClosed(ctx, abort)
	} else if found {
		return statusFor(ctx, err)
	}

	// An error carrying a fiber status that is not a refusal — a route's own
	// 422, the router's 404 — keeps that status.
	if fe, found, abort := errwalk.As[*fiber.Error](chain); abort != nil {
		return failClosed(ctx, abort)
	} else if found {
		return fe.Code
	}

	return statusFor(ctx, err)
}

// walkBuffer is how many chain nodes fibersec's walks hold on the caller's
// stack. A chain that fits takes no heap allocation; a longer one still
// walks, and only grows onto the heap.
const walkBuffer = 16

// failClosed reports an abort in fibersec's own walk and answers 500.
func failClosed(ctx context.Context, abort error) int {
	reportAbort(ctx, abort)

	return http.StatusInternalServerError
}

// MapError returns the status and a minimal body for a consumer's own error
// handler to send once it has logged or enriched the refusal.
//
// The body holds only the standard status text, never the error's own, for the
// same reason ErrorHandler sends no body at all: what a refusal knows is the
// deployment's, not the client's. For a rendered RFC 9457 problem body
// instead, use fiberprblm.ErrorHandler with the prblmsec module's option
// (github.com/kartaladev/scrty/httpsec/prblmsec).
//
//	app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
//		log.Error("refused", "err", err)
//		status, body := fibersec.MapError(err)
//		return c.Status(status).JSON(body)
//	}})
func MapError(err error) (int, any) {
	// A refusal the chain made keeps the status it was classified with, and is
	// not classified a second time.
	status, ok := classified(err)
	if !ok {
		status = httpsec.StatusForError(err)
	}

	return status, fiber.Map{"error": http.StatusText(status)}
}

// statusFor is the status the core classifies err with, for a request whose
// context is ctx. The core's lookup takes no context, so an abort it meets
// would be written to slog.Default(): the chain's own lookup is asked first,
// and an abort it meets is written to the logger of the chain handling the
// request and answered 500, as the core answers it, without asking again.
func statusFor(ctx context.Context, err error) int {
	if guardauth.ReportLookupAbort(ctx, err) {
		return http.StatusInternalServerError
	}

	return httpsec.StatusForError(err) //nolint:contextcheck // the core's lookup takes no context, and it reports no abort here
}
