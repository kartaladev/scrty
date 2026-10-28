package httpsec

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/session"
)

// sessionKey is this package's own context key for the session.
//
// The session package exports no context helper, so the chain owns the key.
// It is an unexported empty struct type, so no other package can collide with
// it or overwrite what the chain published, and nothing outside this package
// can put a value under it that a later interceptor would trust.
type sessionKey struct{}

// withSession publishes s on a context derived from ctx, so every later
// interceptor and the downstream handler read the session the chain resolved.
//
// It derives rather than replaces: everything already on ctx, including an
// upstream request identifier and the client's cancellation, is still there.
func withSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext returns the session the chain resolved for this request.
//
// It is how a handler reads the session without the consumer having to know
// how the chain stores it. An absent session is reported absent rather than as
// an empty one, and a nil session published by an interceptor reads the same
// way, so a caller that ignores ok is never handed something it could mistake
// for a live session.
func SessionFromContext(ctx context.Context) (*session.Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*session.Session)
	return s, ok && s != nil
}

// sessionTouch records that a session was used, after everything inside it has
// returned.
type sessionTouch struct {
	// sessions is the manager the chain was wired with, and nil when no
	// built-in was given one. A chain that resolves no session has no activity
	// to record.
	sessions *session.Sessions

	log *slog.Logger
}

// wire takes the settings the chain resolved, once every option has been
// applied.
func (s *sessionTouch) wire(c *Chain) { s.log = c.logger }

// Intercept records activity after everything inside it has returned.
//
// It runs the rest of the chain first, so a request refused by an inner stage
// is recorded too: a caller whose request was refused was still there, and a
// session whose idle deadline stops moving on every refusal is logged out for
// asking for something it was not allowed.
func (s *sessionTouch) Intercept(ex *Exchange, next Next) error {
	err := next(ex)

	if s.sessions == nil || ex.Session == nil {
		return err
	}

	// Detached from the request's own cancellation: the work this records is
	// already done, and a client that hung up after being served has still been
	// active. Cancelling here would make a disconnect the one way to use a
	// session without extending it.
	ctx := context.WithoutCancel(ex.Context())

	if tErr := s.sessions.Touch(ctx, ex.Session); tErr != nil {
		// Deliberately not returned. This is bookkeeping: a store that cannot
		// record activity must not mask the handler's result, nor turn a served
		// request into a fault, and a session a concurrent logout has just
		// ended makes a failure here ordinary. The absolute deadline still
		// bounds the session either way.
		s.log.LogAttrs(ctx, slog.LevelDebug, msgSessionNotTouched,
			diag.Failure("session-store", tErr)...)
	}

	return err
}

// msgSessionNotTouched reports a write-back that did not land. It is at debug
// rather than error because a session ended while its last request was in
// flight fails here as a matter of course, and the outcome is unchanged.
//
// The record carries a fixed reason and the session store's error type, never
// its text: a consumer whose store quotes a row's own wording back logs that
// detail inside their own implementation of session.Store instead.
const msgSessionNotTouched = "httpsec: session activity could not be recorded"
