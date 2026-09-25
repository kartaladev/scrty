package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -destination=endsessionbuilder_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec EndSessionBuilder

// DefaultLogoutPath is the path logout answers POST requests on when the
// consumer names none. It is a constant rather than a bare literal so a client,
// a test or a proxy rule naming the same endpoint names the same thing this
// package does.
const DefaultLogoutPath = "/logout"

// EndSessionBuilder produces the identity provider's end-session URL for a
// session that a local logout has just deleted.
//
// Logout alone uses none: with LogoutDeps.EndSession nil, logout ends the
// local session and answers 200 with an empty body, exactly as it does for a
// session no identity provider was involved in. EnableOIDCLogin on the same
// chain supplies the OIDC manager's end-session step in that case, unless
// WithOIDCRPInitiatedLogout(false) turns it off; a LogoutDeps.EndSession the
// consumer sets always takes precedence.
type EndSessionBuilder interface {
	// EndSessionURL returns the URL to send the browser to, or "" when the
	// provider offers none. It is called only for a session that records an
	// identity provider, and only after that session was deleted. state is the
	// logout request's own "state" form value, passed through unread.
	EndSessionURL(ctx context.Context, s *session.Session, state string) (string, error)
}

// logout ends the session the request was authenticated with.
type logout struct {
	sessions *session.Manager

	// endSession is the optional end-session step, nil for none.
	endSession EndSessionBuilder

	// log is the chain's logger, handed over by wire.
	log *slog.Logger

	path string
}

// logoutDocument is the body logout answers with when an end-session URL was
// produced. Its member name is the documented contract of that answer.
type logoutDocument struct {
	EndSessionURL string `json:"end_session_url"`
}

// wire takes the settings the chain resolved, so a logger wired after
// EnableLogout is still the one this interceptor uses.
func (l *logout) wire(c *Chain) {
	l.log = c.logger
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

		// Only a session a federated login created has a provider session to
		// end, and only once the local one is gone: a provider logout that
		// ran first would leave a live local session behind a failed delete.
		if l.endSession != nil && ex.Session.ExternalProvider != "" {
			if target := l.endSessionURL(ex); target != "" {
				// The URL carries the client's state; no cache may replay it.
				ex.Writer.SetHeader("Cache-Control", "no-store")

				return writeSuccessDocument(ex, logoutDocument{EndSessionURL: target})
			}
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

// endSessionURL asks the end-session step for the provider's URL.
//
// A failure is logged and swallowed: the session is already deleted, and
// answering an error would tell the client its logout did not happen. The log
// names the provider and never the state, which is the client's.
func (l *logout) endSessionURL(ex *Exchange) string {
	ctx := ex.Context()

	target, err := l.endSession.EndSessionURL(ctx, ex.Session, logoutState(ex.Request))
	if err != nil {
		l.log.WarnContext(ctx,
			"httpsec: the session was ended but the provider's end-session URL could not be built",
			slog.String("provider", ex.Session.ExternalProvider), slog.Any("error", err))

		return ""
	}

	return target
}

// logoutState reads the "state" field of a form-encoded logout body, read under
// DefaultLoginBodyLimit, and "" for any other body. Like a login, it reads only
// the body and never the query, so a value is what the client posted.
func logoutState(r Request) string {
	if !declaresForm(r.Header("Content-Type")) {
		return ""
	}

	body, err := r.Body(DefaultLoginBodyLimit)
	if err != nil {
		return ""
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}

	return values.Get("state")
}
