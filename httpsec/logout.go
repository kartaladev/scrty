package httpsec

import (
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/session"
)

// DefaultLogoutPath is the path logout answers POST requests on when the
// consumer names none. It is a constant rather than a bare literal so a client,
// a test or a proxy rule naming the same endpoint names the same thing this
// package does.
const DefaultLogoutPath = "/logout"

// logout ends the session the request was authenticated with.
type logout struct {
	sessions *session.Manager

	path string
}

// Intercept ends the caller's session and answers the request itself.
//
// Only POST, and only on the configured path: ending a session is a change,
// and a logout a link could trigger is one another site can trigger for a
// caller who never asked. Everything else passes through untouched.
func (l *logout) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost || ex.Request.Path() != l.path {
		return next(ex)
	}

	// There must be a caller. Without an authentication result this request has
	// shown nothing to end, and answering it 200 would say a session was ended
	// that nobody had.
	if ex.Authentication == nil {
		return ErrAuthenticationRequired
	}

	// A stateless first factor establishes no session, so there is nothing to
	// delete: the caller simply stops presenting its credential. Guessing at an
	// identifier to delete would end a session this request never named.
	if ex.Session != nil {
		if err := l.sessions.Delete(ex.Context(), ex.Session.ID); err != nil &&
			!errors.Is(err, session.ErrSessionNotFound) {
			return err
		}
	}

	// Already gone is the outcome logout wanted. Two clients ending one session
	// is ordinary, and reporting the loser an error would only have it retry.
	//
	// The body is empty: what a logged-out client should be shown, a redirect
	// or a page, is the consumer's decision, and writing one here would be one
	// they cannot take back.
	ex.Writer.WriteHeader(http.StatusOK)

	return nil
}
