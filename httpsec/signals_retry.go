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
	if !s.e.onStreamPath(ex) {
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

	if throttled {
		// This slot is above the endpoint, so the cross-site rule has not run, and neither has the line
		// that sets the endpoint's Cache-Control. A throttled request from a site nothing trusts is refused
		// as an unthrottled one is, before it is counted or answered, so that a foreign page cannot tell a
		// signed-in browser by a 200, or make the library log or count a throttle. It cannot stop the event:
		// the policy has already run, so such a request has emitted its one unsampled authz_fail, as any
		// per-request denial does, where an unthrottled refusal emits none.
		if refused := e.crossSiteAllowed(ex, streamByCookie(ex)); refused != nil { //nolint:contextcheck // the refusal is logged on the exchange's current context; entered only classifies the failure
			ex.Writer.SetHeader("Cache-Control", signalsCacheControl)

			return refused
		}
	}

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
	// The context can have ended without the client leaving: an interceptor's deferred cancel, or a
	// deadline a server set. So the body writes whatever it says. Where nothing can be written, a client
	// gone or a chain on fiber that refused after this, the writer fails and this stops.
	return startStream(ex, func(_ context.Context, w EventWriter) error {
		if err := writeRetry(w, delay); err != nil {
			return nil //nolint:nilerr // the client has gone, and it was only ever told when to come back
		}

		_ = w.Flush()

		return nil
	})
}

// perRequestThrottle marks a ratelimit.ErrThrottled as the answer of the chain's per-request policy
// phase about the sign-in it judged. It reads as what it wraps, to errors.Is, errors.As and in its text.
//
// The mark is on the error, and not on the exchange, because the question is about this refusal: a
// consumer's interceptor may be told of a throttle and go on to another credential, whose own refusal
// then carries no mark and cannot be read as this one. It is a pointer so that errors.Is can compare it
// whatever the reason it wraps is made of.
type perRequestThrottle struct{ error }

// Unwrap returns the policy's reason.
func (t *perRequestThrottle) Unwrap() error { return t.error }

// markPerRequestThrottle is what evaluatePerRequest returns for a denial with reason err: err itself,
// unless it is a throttle isThrottledSignIn could answer on this very request. So every other path of
// the chain, and every other denial, gets the policy's reason as the very value it gave. What the mapping
// answers otherwise than 401 is not marked either, so that a record naming an outage's type names the
// outage's.
func (ex *Exchange) markPerRequestThrottle(err error) error {
	ph := ex.perRequest
	if ph == nil || ph.signals == nil || !ph.signals.onStreamPath(ex) {
		return err
	}

	if !errors.Is(err, ratelimit.ErrThrottled) || StatusForError(err) != http.StatusUnauthorized {
		return err
	}

	return &perRequestThrottle{err}
}

// recordThrottledBearer records presented, the credential a built-in bearer read from the request, when
// err carries the mark of a per-request throttle, so that the stream's cross-site rule judges the request
// as a bearer, as it judges the same request unthrottled (streamByCookie).
//
// The mark says the credential verified and its caller was published, so what is recorded is a credential
// the chain accepted. Every other refusal records nothing: other code reads what is recorded, and a
// credential that failed has no business being there.
func (ex *Exchange) recordThrottledBearer(err error, presented string) {
	var throttle *perRequestThrottle
	if errors.As(err, &throttle) {
		ex.RecordPresentedToken(presented)
	}
}

// onStreamPath reports whether ex asks for the stream, the only request sessionSignalsRetry answers.
func (e *sessionSignals) onStreamPath(ex *Exchange) bool {
	return ex.Request.Method() == http.MethodGet && ex.Request.Path() == e.cfg.Path
}

// isThrottledSignIn reports whether err is the chain's per-request policy throttling the sign-in it just
// judged, which a retry could fix, unless SessionSignals.RetryableError says otherwise. A policy cannot
// write an answer of its own, so its ratelimit.ErrThrottled would otherwise be a 401 that ends an
// EventSource for good.
//
// Only that throttle qualifies, and a session on the exchange does not: it says who is signed in, not
// whose credential was refused. A caller with a sign-in of their own can present another account's
// password, key or name beside it, and an answer telling that refusal's throttle from any other refusal
// would be an oracle on that credential. So every other ErrThrottled keeps what the chain's mapping
// answers, a source guard's and a pre-authentication or stateless policy's as a consumer's interceptor's,
// which a consumer can answer itself. Only what the mapping answers 401 qualifies, so that an outage
// that also wraps a throttle stays an outage, and an error mapping to a 429 is not this: a consumer chose
// that answer. A client that has left is told nothing, as isDependencyFailure says.
//
// RetryableError is handed the policy's own reason, with the mark taken off, so that a callback comparing
// it to ratelimit.ErrThrottled by identity or by type still reads it. A wrap a consumer made outside
// EvaluatePerRequest is not in what it is handed.
func (e *sessionSignals) isThrottledSignIn(entered context.Context, ex *Exchange, err error) bool {
	var throttle *perRequestThrottle
	if !errors.As(err, &throttle) || errors.Is(entered.Err(), context.Canceled) {
		return false
	}

	return StatusForError(err) == http.StatusUnauthorized && e.retryable(ex, throttle.error) //nolint:contextcheck // only the classification above reads entered; a panic in RetryableError is logged on the exchange's current context
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
