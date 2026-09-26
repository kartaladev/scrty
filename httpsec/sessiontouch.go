package httpsec

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/session"
)

// sessionTouch records that a session was used, after everything inside it has
// returned.
type sessionTouch struct {
	// sessions is the manager the chain was wired with, and nil when no
	// built-in was given one. A chain that resolves no session has no activity
	// to record.
	sessions *session.Manager

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
