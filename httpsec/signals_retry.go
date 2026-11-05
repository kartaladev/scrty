package httpsec

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
)

// orderSessionSignalsRetry is where a request for the stream that cannot be served now is answered
// with only a retry: After(OrderCORS).
//
// It has to wrap every read of a store on the stream's path, and the first of them is an
// authenticator's, far below the endpoint's own slot. A consumer's CookieAuthenticator can be
// registered anywhere after OrderCSRF, so this slot sits above all of those. What CORS and the security
// headers set, they set before calling next, so it is on what this writes: a cross-origin EventSource
// could not read a 200 with no CORS headers, and would give up for good, which is what this answer
// exists to prevent.
const orderSessionSignalsRetry = OrderCORS + 1

// streamClosingRetryLeast is the least retry a closing replica states.
const streamClosingRetryLeast = time.Second

// The records of a request answered with only a retry. Neither holds an error's text, which can
// quote a store's address or what it was asked.
const (
	msgStreamCapReached       = "httpsec: session signal stream refused: a cap is reached"
	msgStreamDependencyFailed = "httpsec: session signal stream refused: a dependency failed"
	msgStreamThrottled        = "httpsec: session signal stream refused: a sign-in is throttled"
)

// sessionSignalsRetry answers what a retry could fix on the stream's path. It is registered with
// EnableSessionSignals, so a chain with no stream has none, and it looks only at GET on that path,
// so every other answer of the chain stands.
type sessionSignalsRetry struct{ e *sessionSignals }

// Intercept passes every request on, and answers on the way out. The context is taken on the way in,
// because whether the client has left is a question about it: one read after next can have been ended
// by an interceptor inside this slot, with its client still there.
func (s sessionSignalsRetry) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodGet || ex.Request.Path() != s.e.cfg.Path {
		return next(ex)
	}

	entered := ex.Context()

	err := next(ex)
	if err == nil {
		return nil
	}

	return s.e.answerRetryOnly(entered, ex, err)
}

// answerRetryOnly answers err with 200 and only a retry when a retry could fix it, because an
// EventSource gives up for good on any other status and cannot tell one from another. It returns what
// the chain's error mapping should then answer, nil when nothing. entered is the context the request
// had on its way in (see isDependencyFailure).
//
// Stream is what guards a response that has begun: it refuses, having written nothing, and err is
// left to the chain's mapping, whose status a writer ignores by then. A writer that cannot stream never
// could, so that stays 501: no retry would change it.
func (e *sessionSignals) answerRetryOnly(entered context.Context, ex *Exchange, err error) error {
	if errors.Is(err, ErrStreamingUnsupported) || errors.Is(err, ErrStreamingStarted) {
		return err
	}

	closing, overCap := errors.Is(err, errStreamsClosed), errors.Is(err, ErrTooManyStreams)
	throttled := e.isThrottledSignIn(entered, ex, err)

	if !closing && !overCap && !throttled && !e.isDependencyFailure(entered, ex, err) {
		return err
	}

	if closing || (!overCap && e.registry.isClosed()) {
		// Closing is what this replica was told to do, so it is no refusal to report, and a store
		// failing on the way here changes none of that. The connection goes too, or a client would
		// reconnect over it to the replica it is leaving.
		ex.Writer.SetHeader("Connection", "close")

		return e.retryOnlyOr(err, e.streamOnlyRetry(ex, e.closingRetry())) //nolint:contextcheck // the answer and its records go on the exchange's current context; entered only classifies the failure
	}

	delay := jittered(e.cfg.BusyDelay, streamRetryJitter, rand.Float64()) //nolint:gosec // jitter, not a secret

	if streamErr := e.streamOnlyRetry(ex, delay); streamErr != nil { //nolint:contextcheck // the answer and its records go on the exchange's current context; entered only classifies the failure
		return e.retryOnlyOr(err, streamErr)
	}

	if overCap {
		e.logRetryOnly(ex.Context(), "cap-reached", msgStreamCapReached) //nolint:contextcheck // the answer and its records go on the exchange's current context; entered only classifies the failure

		return nil
	}

	if throttled {
		// Nothing failed, so this is no reload failure: it is a consumer's limit doing its work.
		e.throttled.Add(1)
		e.logRetryOnly(ex.Context(), "throttled", msgStreamThrottled) //nolint:contextcheck // the answer and its records go on the exchange's current context; entered only classifies the failure

		return nil
	}

	// It hides from a status-code dashboard, and a tenant-scoped store with no hook fails here and
	// never as a reload, so this is where an operator sees either.
	e.reloads.failures.Add(1)
	e.logRetryOnly(ex.Context(), "dependency-failed", msgStreamDependencyFailed, //nolint:contextcheck // the answer and its records go on the exchange's current context; entered only classifies the failure
		slog.String("error_type", fmt.Sprintf("%T", err)))

	return nil
}

// retryOnlyOr is what the chain's error mapping answers once streamOnlyRetry has returned streamErr:
// nothing when it answered, 501 for a writer that cannot stream, and otherwise the refusal it could not
// write over a response that had begun.
func (e *sessionSignals) retryOnlyOr(err, streamErr error) error {
	switch {
	case streamErr == nil:
		return nil
	case errors.Is(streamErr, ErrStreamingUnsupported):
		return streamErr
	default:
		return err
	}
}

// closingRetry is the retry a closing replica states: fresh, between 1 second and 3 × ReconnectDelay.
// That range is empty for a ReconnectDelay under a third of a second, and the floor then stands: a
// replica that is going away is a poor place to come back to sooner.
func (e *sessionSignals) closingRetry() time.Duration {
	spread := max(3*e.cfg.ReconnectDelay-streamClosingRetryLeast, 0)

	return streamClosingRetryLeast + time.Duration(float64(spread)*rand.Float64()) //nolint:gosec // jitter, not a secret
}

// streamOnlyRetry answers with the stream's headers and a body of one retry, and then the response
// ends. It returns what Stream returned.
func (e *sessionSignals) streamOnlyRetry(ex *Exchange, delay time.Duration) error {
	ex.Writer.SetHeader("Cache-Control", signalsCacheControl)
	ex.Writer.SetHeader("X-Accel-Buffering", "no")

	// The context can have ended without the client leaving: an interceptor's deferred cancel, or a
	// deadline a server set. So the body writes whatever it says. Where nothing can be written, a client
	// gone or a chain on fiber that refused after this, the writer fails and this stops.
	return ex.Writer.Stream(cancelOnly{ex.Context()}, signalsContentType, func(_ context.Context, w EventWriter) error {
		if err := writeRetry(w, delay); err != nil {
			return nil //nolint:nilerr // the client has gone, and it was only ever told when to come back
		}

		_ = w.Flush()

		return nil
	})
}

// isThrottledSignIn reports whether err is a throttle on a sign-in that has been published, which a
// retry could fix, unless SessionSignals.RetryableError says otherwise. A policy cannot write an answer
// of its own, so its ratelimit.ErrThrottled would otherwise be a 401 that ends an EventSource for good.
//
// Only a published sign-in qualifies. Before one, a request has proved nothing, and an answer that told
// Basic over its limit from a wrong password would sit beside a concealed lock as an oracle, so those
// keep the 401 every refused credential gets. Only what the chain's mapping answers 401 qualifies, so
// that an outage that also wraps a throttle stays an outage, and an error mapping to a 429 is not this:
// a consumer chose that answer. A client that has left is told nothing, as isDependencyFailure says.
func (e *sessionSignals) isThrottledSignIn(entered context.Context, ex *Exchange, err error) bool {
	if ex.Session == nil || !errors.Is(err, ratelimit.ErrThrottled) || errors.Is(entered.Err(), context.Canceled) {
		return false
	}

	return StatusForError(err) == http.StatusUnauthorized && e.retryable(ex, err) //nolint:contextcheck // only the classification above reads entered; a panic in RetryableError is logged on the exchange's current context
}

// isDependencyFailure reports whether err is a failure of something the request depends on, and not
// an answer: whatever the chain's error mapping would answer with a 5xx, because each such error is
// one no client's request could have caused, and it may pass, unless SessionSignals.RetryableError
// says otherwise.
//
// What maps to 400, 401, 403, 405 or 429 is an answer, and stands. So does a request whose own client
// hung up, which says nothing about a store. A cancelled entered, the context the request came into
// this slot with, is what a client's leaving looks like here: an interceptor below this slot cannot
// end it, and a deadline that ended it is a server's, with its client still there, since hanging up has
// no deadline to pass.
//
// Once the client has left, any error is taken for its leaving, because a store answers a cancellation
// in its own words as often as in the context's. So a real outage on a request whose client has already
// left goes uncounted. Others will count it, and this client would hear nothing of it anyway.
//
// A consumer's error the mapping does not know is taken for a failure, so an interceptor refusing with
// one of its own answers the request itself, sets RetryableError, or the client is told to come back.
func (e *sessionSignals) isDependencyFailure(entered context.Context, ex *Exchange, err error) bool {
	if errors.Is(entered.Err(), context.Canceled) {
		return false
	}

	return StatusForError(err) >= http.StatusInternalServerError && e.retryable(ex, err) //nolint:contextcheck // only the classification above reads entered; a panic in RetryableError is logged on the exchange's current context
}

// retryable asks a consumer's SessionSignals.RetryableError about err. A panic in it is logged as a
// stream's is, without its value, and the failure is retried, since it has said nothing to the
// contrary and a final answer would stop a browser for good. The record names the family of the session
// the request reached this far with, which a failure in an authenticator's own read has not got, so
// that one's family is all zeros.
func (e *sessionSignals) retryable(ex *Exchange, err error) (retry bool) {
	if e.cfg.RetryableError == nil {
		return true
	}

	defer func() {
		if v := recover(); v != nil {
			var family id.ID
			if ex.Session != nil {
				family = ex.Session.FamilyID
			}

			e.logStreamPanic(ex.Context(), panicPhaseStream, family, v)

			retry = true
		}
	}()

	return e.cfg.RetryableError(err)
}

// logRetryOnly writes one of the records above, with sampling. A flood of requests over a cap or
// during an outage writes one per window.
func (e *sessionSignals) logRetryOnly(ctx context.Context, key, msg string, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("flow", streamFlow))

	logSampled(ctx, e.sampler, e.log, slog.LevelWarn, e.clock.Now(), streamFlow+sampleKeySeparator+key, msg, attrs...)
}
