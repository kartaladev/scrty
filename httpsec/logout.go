package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/kartaladev/scrty/internal/diag"
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

// logout ends the sign-in the request was authenticated with: every session of
// the authenticating session's family. A session with no family is refused:
// nothing is deleted and the caller gets a 500.
type logout struct {
	sessions *session.Sessions

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

// Intercept ends the caller's sign-in and answers the request itself.
//
// The sign-in is the session's whole family (Sessions.RevokeFamily), so a
// logout bearing an identifier that was renewed inside its window also ends
// its successor. A family already gone is not an error.
//
// Only POST, and only on the configured path: ending a session is a change,
// and a logout a link could trigger is one another site can trigger for a
// caller who never asked. Everything else passes through untouched.
//
// A session the store could not delete is refused behind fixed text, never the
// store's own, and the store's error still matches through errors.Is and
// errors.As.
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
		if err := l.end(ex.Context(), ex.Session); err != nil {
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

// end ends the sign-in s belongs to by revoking its family, the superseded
// predecessor and the successor a renewal issued included, so logging out
// with an identifier inside its renewal window does not leave the successor
// live. Every stored session belongs to a family; one with none is refused by
// the manager rather than deleted alone. Nothing left to end is not an error.
func (l *logout) end(ctx context.Context, s *session.Session) error {
	// Detached so a client hanging up cannot leave the family live;
	// WithoutCancel keeps the context's values, so a consumer's transaction is
	// still joined.
	_, err := l.sessions.RevokeFamily(context.WithoutCancel(ctx), s.FamilyID)
	if err != nil && !errors.Is(err, session.ErrNotFound) {
		return err
	}

	return nil
}

// endSessionURL asks the end-session step for the provider's URL.
//
// A failure is logged and swallowed: the session is already deleted, and
// answering an error would tell the client its logout did not happen. The log
// names the provider and never the state, which is the client's, and records
// the failure by a fixed reason and its Go type, never its text: the step may
// word it with what its own store holds for the session.
func (l *logout) endSessionURL(ex *Exchange) string {
	ctx := ex.Context()

	target, err := l.endSession.EndSessionURL(ctx, ex.Session, logoutState(ex.Request))
	if err != nil {
		l.log.LogAttrs(ctx, slog.LevelWarn,
			"httpsec: the session was ended but the provider's end-session URL could not be built",
			append([]slog.Attr{slog.String("provider", ex.Session.ExternalProvider)},
				diag.Failure("end-session", err)...)...)

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

// LogoutDeps are the collaborators logout is wired to.
//
// The session manager is required. Logout exists to end a session, and one
// wired without a store to end it in would answer every caller 200 while
// leaving every session live — a logout that reports success and does nothing
// is worse than no logout at all.
type LogoutDeps struct {
	// Sessions is where the caller's session is deleted. Supply the same
	// manager the authentication interceptors load sessions from, or a logout
	// deletes from a store nothing reads.
	Sessions *session.Sessions

	// EndSession builds the identity provider's end-session URL for a session
	// a federated login created. It is optional: nil means no end-session
	// step, and logout answers every caller as it answers a password session,
	// unless EnableOIDCLogin on the same chain supplies its manager's step
	// (see WithOIDCRPInitiatedLogout). A step set here always takes precedence.
	EndSession EndSessionBuilder
}

// LogoutOption configures logout. Each replaces one of the defaults named on
// EnableLogout.
type LogoutOption func(*logout) error

// EnableLogout ends the caller's session at the logout slot.
//
// Default: POST on DefaultLogoutPath, answered 200 with an empty body. The
// downstream handler is never called, because logout is this library's own
// endpoint. A request with no authentication result is refused with
// ErrAuthenticationRequired, and a session that is already gone is a success:
// two clients ending one session is ordinary.
//
// Every other request, including a GET on that path, passes through untouched.
//
// With LogoutDeps.EndSession set, a session that records an identity provider
// is deleted first, then the builder is asked for the provider's end-session
// URL, handed the deleted session and the request's "state" form value. A URL
// is answered 200 with {"end_session_url": ...} and Cache-Control: no-store;
// an empty URL, or a builder error, which is logged, keeps the empty 200. The
// default is nil: no end-session step, and every logout answers as above,
// unless EnableOIDCLogin is on the chain, which supplies its manager's step
// when this one is nil (WithOIDCRPInitiatedLogout turns that off).
func EnableLogout(d LogoutDeps, opts ...LogoutOption) Option {
	const option = "EnableLogout"

	return func(c *config) error {
		l := &logout{sessions: d.Sessions, endSession: d.EndSession, path: DefaultLogoutPath}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(l); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			return requireDep(option, "session manager", d.Sessions)
		})

		// Recorded for the gates, which exempt this path so a session stranded
		// mid-challenge can still be ended. See wireMFA and wirePasswordChange.
		c.logoutPath = l.path
		c.logout = l

		c.useSessions(d.Sessions)
		c.wire(l.wire)
		c.register(l, OrderLogout)

		return nil
	}
}

// WithLogoutRequestPath answers logouts on path instead.
//
// Default: DefaultLogoutPath, which keeps passing through once the consumer
// moves the endpoint. An empty path is refused: it would match nothing, so the
// endpoint the consumer asked for would silently not exist.
func WithLogoutRequestPath(path string) LogoutOption {
	return func(l *logout) error {
		if path == "" {
			return newConfigError("WithLogoutRequestPath was given no path, so logout would " +
				"answer nothing")
		}

		l.path = path

		return nil
	}
}
