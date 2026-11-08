package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -destination=endsessionbuilder_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec EndSessionBuilder

// DefaultLogoutPath is the path logout answers POST requests on when the
// consumer names none. It is a constant rather than a bare literal so a client,
// a test or a proxy rule naming the same endpoint names the same thing this
// package does.
const DefaultLogoutPath = "/sign-out"

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
	pathDeclarations

	sessions *session.Sessions

	// provider is the OpenID Provider on the same chain, handed over by the
	// chain's wiring, and nil for none.
	provider *oidcprovider.Provider

	// endSession is the optional end-session step, nil for none.
	endSession EndSessionBuilder

	// log is the chain's logger, handed over by wire.
	log *slog.Logger

	// declaredPath is where the options placed the endpoint, without the base
	// path; path is where it answers, settled by resolvePaths.
	declaredPath string
	path         string

	// clearSiteData is the Clear-Site-Data value sent on a secure, successful
	// logout, or "" for none.
	clearSiteData string
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
// The sign-in is the session's whole family (Sessions.Logout), so a
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
//
// With the OpenID Provider on the chain, the sign-in ends there first (see end).
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
				l.clearBrowserData(ex)

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
	l.clearBrowserData(ex)
	ex.Writer.WriteHeader(http.StatusOK)

	return nil
}

// clearBrowserData sets Clear-Site-Data when the consumer asked for it and the
// request is secure, where browsers honour it.
func (l *logout) clearBrowserData(ex *Exchange) {
	if l.clearSiteData != "" && ex.Request.Secure() {
		ex.Writer.SetHeader("Clear-Site-Data", l.clearSiteData)
	}
}

// end ends the sign-in s belongs to by revoking its family, the superseded
// predecessor and the successor a renewal issued included, so logging out
// with an identifier inside its renewal window does not leave the successor
// live. Every stored session belongs to a family; one with none is refused by
// the manager rather than deleted alone. Nothing left to end is not an error.
//
// With the OpenID Provider on the chain, the sign-in ends there first: a grant
// that cannot be revoked refuses the logout with the session still in place, so
// asking again finishes it, where the manager's report could only log the failure
// with the session already gone. The clients to tell are handed on without waiting,
// so a delivery that fails costs the logout nothing. The manager's report of the
// logout then finds nothing left to end, and tells no client twice.
func (l *logout) end(ctx context.Context, s *session.Session) error {
	// Detached so a client hanging up cannot leave the family live;
	// WithoutCancel keeps the context's values, so a consumer's transaction is
	// still joined.
	detached := context.WithoutCancel(ctx)

	if l.provider != nil && !s.FamilyID.IsZero() {
		if _, err := l.provider.EndSignIn(detached, oidcprovider.SignInSelector{Family: s.FamilyID}); err != nil {
			return err
		}
	}

	n, err := l.sessions.Logout(detached, s.UserID, s.FamilyID)
	if err != nil && !errors.Is(err, session.ErrNotFound) {
		return err
	}

	// Reported only for a family this logout revoked: one already gone, which
	// the manager answers with nothing revoked and no error, was ended by
	// something else, which reported it.
	if err == nil && n > 0 {
		emitEvent(ctx, sessionEvent(event.SessionLogout, event.OutcomeSuccess, s))
		emitEvent(ctx, sessionEvent(event.AuthnTokenRevoked, event.OutcomeSuccess, s))
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
//
// With EnableOIDCProvider on the same chain, the sign-in ends through the provider
// before its sessions are deleted: its grants without offline_access are revoked,
// its browser sessions go, and the clients that held a grant from it are told. A
// store of the provider's that fails refuses the logout with
// oidcprovider.ErrDependency, 500 by default, with the session still in place, so
// that the logout can be retried. A client that could not be told fails nothing. This
// has no override, because a logout that left an online grant alive would report
// an end that had not happened.
func EnableLogout(d LogoutDeps, opts ...LogoutOption) Option {
	const option = "EnableLogout"

	return func(c *config) error {
		l := &logout{sessions: d.Sessions, endSession: d.EndSession, declaredPath: DefaultLogoutPath}

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

		// Kept for the gates, which exempt its path so a session stranded
		// mid-challenge can still be ended. resolvePaths records where it
		// answers in c.logoutPath once the base path is known. See wireMFA and
		// wirePasswordChange.
		c.logout = l

		c.useSessions(d.Sessions)
		c.wire(l.wire)
		// Read once every option has applied, as the provider may be enabled after
		// logout.
		c.wire(func(*Chain) {
			if c.oidcProvider != nil {
				l.provider = c.oidcProvider.provider
			}
		})
		c.register(l, OrderLogout)

		return nil
	}
}

// WithLogoutRequestPath answers logouts on path instead.
//
// Default: DefaultLogoutPath, "/sign-out", which keeps passing through once the
// consumer moves the endpoint. The path is within the base path
// (WithBasePath): with a base path of "/auth", the default answers
// "/auth/sign-out". An empty path is refused: it would match nothing, so the
// endpoint the consumer asked for would silently not exist.
func WithLogoutRequestPath(path string) LogoutOption {
	return func(l *logout) error {
		if err := checkEndpointPath("WithLogoutRequestPath", path); err != nil {
			return err
		}

		l.declaredPath = path
		l.declare("WithLogoutRequestPath", path)

		return nil
	}
}

// WithLogoutClearSiteData has a successful logout send Clear-Site-Data with
// directives, so the browser drops what it stored for the origin: "cache",
// "cookies" or "storage". The wildcard and "clientHints" are not accepted.
//
// Default: the header is not sent. When set, it is sent only on a successful
// logout over a request the chain judges secure (Request.Secure): browsers
// ignore the header over plain HTTP, and a refused logout ended nothing. No
// directive, an unknown or repeated one, or one not written as the bare name
// ("cache", not "\"cache\"") fails construction, because the header would
// otherwise be ignored by the browser without a sign. Note that "cookies"
// clears cookies for the whole registrable domain, sibling subdomains
// included.
func WithLogoutClearSiteData(directives ...string) LogoutOption {
	return func(l *logout) error {
		if len(directives) == 0 {
			return newConfigError("WithLogoutClearSiteData was given no directive, so it would send nothing")
		}

		quoted := make([]string, 0, len(directives))

		for i, d := range directives {
			if !slices.Contains(clearSiteDataDirectives, d) {
				return newConfigError("WithLogoutClearSiteData was given %q, which is not one of %s",
					d, strings.Join(clearSiteDataDirectives, ", "))
			}

			if slices.Contains(directives[:i], d) {
				return newConfigError("WithLogoutClearSiteData was given %q twice", d)
			}

			quoted = append(quoted, `"`+d+`"`)
		}

		l.clearSiteData = strings.Join(quoted, ", ")

		return nil
	}
}

// clearSiteDataDirectives are the directives the Clear-Site-Data header
// a logout may send. "clientHints", "executionContexts" and the "*" wildcard
// are left out: the wildcard would also reload every tab where supported and
// drop more than a logout should unasked.
var clearSiteDataDirectives = []string{"cache", "cookies", "storage"}

// endpoints declares sign-out.
func (l *logout) endpoints() []Endpoint {
	return []Endpoint{
		declare("EnableLogout", "WithLogoutRequestPath", OperationSignOut, l.path,
			MatchExact, OtherMethodsPassThrough, RequiresAuthentication, http.MethodPost),
	}
}
