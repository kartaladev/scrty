package httpsec

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/session"
)

// DefaultSessionManagementPrefix is where EnableSessionManagement answers
// when the consumer names no prefix (WithSessionManagementPrefix).
const DefaultSessionManagementPrefix = "/sessions"

// OrderSessionManagement is the session management endpoints
// (EnableSessionManagement). They sit inside the bearers and the gates, so a
// request reaching them has resolved its session and passed every gate the
// chain enables, and outside the renewal endpoint and logout.
const OrderSessionManagement = OrderSessionRenewal - 1

// OrderSessionManagementNoStore is where EnableSessionManagement marks every
// response under its prefix Cache-Control: no-store: just inside the security
// headers, outside every layer that could refuse such a request first, such
// as a bearer refusing a revoked session reference. It leaves
// After(OrderSecurityHeaders) to the consumer.
const OrderSessionManagementNoStore = OrderSecurityHeaders + 2

// ErrSessionHandleNotFound refuses a request to end a sign-in by a handle
// that names no live sign-in of the session's user: a malformed handle, an
// unknown one and another user's are deliberately the same refusal, so a
// caller learns nothing about other users' sign-ins. Nothing was revoked. It
// maps to 404. Its text names no handle, session or user.
var ErrSessionHandleNotFound = errors.New("httpsec: sign-in not found")

// SessionManagementOption configures the session management endpoints.
type SessionManagementOption func(*sessionManagement) error

// SignInListResponder writes the listing of the session user's live sign-ins
// (session.Sessions.ListSignIns). Cache-Control: no-store is already set when
// it runs. It is called instead of the downstream handler; an error it
// returns leaves the chain as the request's refusal.
type SignInListResponder func(ex *Exchange, list []session.SignIn) error

// SignInEndResponder writes the answer to ending one sign-in or every other
// sign-in, after they were ended. Cache-Control: no-store is already set when
// it runs. It is called instead of the downstream handler; an error it
// returns leaves the chain as the request's refusal, and the sign-ins stay
// ended.
type SignInEndResponder func(ex *Exchange) error

// sessionManagement answers the session management endpoints and passes
// every other request through.
type sessionManagement struct {
	sessions *session.Sessions
	now      func() time.Time

	prefix  string
	window  time.Duration
	list    SignInListResponder
	respEnd SignInEndResponder
}

// WithSessionManagementPrefix replaces the path prefix the endpoints answer
// under.
//
// Default: DefaultSessionManagementPrefix, "/sessions". The prefix must start
// with "/", must not end with one, and must not be "/" alone; anything else is
// refused with a configuration error.
func WithSessionManagementPrefix(prefix string) SessionManagementOption {
	return func(m *sessionManagement) error {
		if prefix == "" || prefix[0] != '/' || strings.HasSuffix(prefix, "/") {
			return newConfigError("WithSessionManagementPrefix needs a path starting with \"/\" "+
				"and not ending with one, got %q", prefix)
		}

		m.prefix = prefix

		return nil
	}
}

// WithSessionManagementRecency replaces how recently the session's user must
// have proved their identity to end a sign-in. Listing needs no recent proof.
//
// Default: DefaultRecentAuthenticationWindow, 15 minutes, the recency guard's
// own default. A window of zero or less is refused with a configuration
// error.
func WithSessionManagementRecency(window time.Duration) SessionManagementOption {
	return func(m *sessionManagement) error {
		if window <= 0 {
			return newConfigError("WithSessionManagementRecency needs a window above zero, got %s", window)
		}

		m.window = window

		return nil
	}
}

// WithSignInListResponder replaces how the listing is answered.
//
// Default: 200 with {"sessions":[{"handle","created_at","last_used_at",
// "first_factor","pending","current","client_ip","user_agent"}]} as JSON. A
// nil function is refused; omit the option to keep the default.
func WithSignInListResponder(fn SignInListResponder) SessionManagementOption {
	return func(m *sessionManagement) error {
		if fn == nil {
			return newConfigError("WithSignInListResponder was given no function; omit the " +
				"option to keep the default document")
		}

		m.list = fn

		return nil
	}
}

// WithSignInEndResponder replaces how ending sign-ins is answered.
//
// Default: 204 with no body. A nil function is refused; omit the option to
// keep the default answer.
func WithSignInEndResponder(fn SignInEndResponder) SessionManagementOption {
	return func(m *sessionManagement) error {
		if fn == nil {
			return newConfigError("WithSignInEndResponder was given no function; omit the " +
				"option to keep the default answer")
		}

		m.respEnd = fn

		return nil
	}
}

// EnableSessionManagement lets a user list and end their own sign-ins, under
// DefaultSessionManagementPrefix ("/sessions") unless
// WithSessionManagementPrefix replaces it. It is off until called.
//
//	GET    /sessions          the user's live sign-ins (session.Sessions.ListSignIns)
//	DELETE /sessions/{handle} ends that sign-in's family (session.Sessions.EndSignIn)
//	DELETE /sessions          ends every sign-in but the current one (session.Sessions.EndOtherSignIns)
//
// A sign-in is a session family, so a renewed session is one sign-in, and its
// handle is the family identifier: never a session identifier, which no
// response carries. The sign-in the request's own session belongs to is
// marked current, also when the request presents a predecessor still inside
// its renewal grace window. A sign-in still owing a second factor, an
// enrolment or a recovery step is listed and marked pending.
//
// Only a full session reaches the endpoints. A request with no session or no
// caller is ErrAuthenticationRequired, and a session owing a second factor,
// an enrolment, a recovery step or a password change is refused with a
// ChallengeError of the kind it owes, as the chain's gates refuse it on any
// other route. Ending a sign-in, one or the others, also needs a recent
// authentication: the session must have proved its user's identity within
// DefaultRecentAuthenticationWindow (15 minutes), or the window
// WithSessionManagementRecency sets, judged by the recency guard's rule
// (session.AuthenticatedWithin) against the chain's clock. A stale session is
// refused with a *ReauthenticationRequiredError (403) and nothing is ended.
// Listing needs no recent authentication.
//
// Ending the current sign-in by its own handle is accepted and ends it, as a
// logout does. A handle that is malformed, unknown, or another user's is
// ErrSessionHandleNotFound (404), and nothing is revoked. Ending the others
// when the current sign-in is the only one succeeds and ends nothing.
//
// Every response to a request under the prefix carries Cache-Control:
// no-store, whatever answers it: the endpoints, their refusals, and an earlier
// layer's refusal such as a bearer's for a revoked session reference. It is
// set at OrderSessionManagementNoStore, just inside the security headers; a
// client-resolution refusal, such as a forwarded host on none of the allowed
// hosts, is written before any layer runs and carries it too. A session-store
// failure is a dependency failure with fixed text, answered 500 (session.ErrListUnavailable for the listing),
// and a request whose own context ended fails with the context's error.
//
// The endpoints use the chain's session manager: the one WithSessions sets,
// or the first an enabled built-in was wired to. A chain with none is refused
// with a configuration error naming this option, and so is a second call.
// Other methods and paths pass through.
func EnableSessionManagement(opts ...SessionManagementOption) Option {
	const option = "EnableSessionManagement"

	return func(c *config) error {
		m := &sessionManagement{
			now:     c.now,
			prefix:  DefaultSessionManagementPrefix,
			window:  DefaultRecentAuthenticationWindow,
			list:    writeSignInList,
			respEnd: writeSignInsEnded,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(m); err != nil {
				return err
			}
		}

		if err := eachInterceptor(c, func(*sessionManagement) error {
			return newConfigError("%s was given twice; one chain has one set of session "+
				"management endpoints", option)
		}); err != nil {
			return err
		}

		c.enable(option, func() error {
			if c.sessions == nil {
				return newConfigError("%s needs a session manager: give the chain one with "+
					"WithSessions, or enable a built-in wired to one", option)
			}

			m.sessions = c.sessions

			return nil
		})
		c.register(m, OrderSessionManagement)
		c.register(sessionManagementNoStore{m: m}, OrderSessionManagementNoStore)
		c.wire(func(ch *Chain) {
			// The client-resolution refusal runs no interceptor, so the
			// no-store step is applied to it here as well.
			ch.refusalSteps = append(ch.refusalSteps, func(ex *Exchange) {
				if m.under(ex.Request.Path()) {
					ex.Writer.SetHeader("Cache-Control", "no-store")
				}
			})
		})

		return nil
	}
}

// sessionRoute is which endpoint a request is.
type sessionRoute uint8

const (
	routeNone sessionRoute = iota
	routeList
	routeEndOne
	routeEndOthers
)

// route reports which endpoint r is and, for ending one sign-in, the handle
// its path names, which may be malformed.
func (m *sessionManagement) route(r Request) (sessionRoute, string) {
	path := r.Path()

	switch r.Method() {
	case http.MethodGet:
		if path == m.prefix {
			return routeList, ""
		}
	case http.MethodDelete:
		if path == m.prefix {
			return routeEndOthers, ""
		}
		if handle, ok := strings.CutPrefix(path, m.prefix+"/"); ok {
			return routeEndOne, handle
		}
	}

	return routeNone, ""
}

// under reports whether path is the prefix or below it.
func (m *sessionManagement) under(path string) bool {
	return path == m.prefix || strings.HasPrefix(path, m.prefix+"/")
}

// sessionManagementNoStore marks every response under the endpoints' prefix
// Cache-Control: no-store, from an outer slot, so a refusal no endpoint wrote
// is not cached either.
type sessionManagementNoStore struct {
	m *sessionManagement
}

// Intercept sets Cache-Control: no-store on a request under the prefix, and
// passes every request on.
func (n sessionManagementNoStore) Intercept(ex *Exchange, next Next) error {
	if n.m.under(ex.Request.Path()) {
		ex.Writer.SetHeader("Cache-Control", "no-store")
	}

	return next(ex)
}

// Intercept answers the endpoints and passes everything else through.
func (m *sessionManagement) Intercept(ex *Exchange, next Next) error {
	route, handle := m.route(ex.Request)
	if route == routeNone {
		return next(ex)
	}

	// Set first, so every answer, a refusal included, is never cached.
	ex.Writer.SetHeader("Cache-Control", "no-store")

	s := ex.Session
	if s == nil || ex.Authentication == nil || ex.Authentication.Principal == nil {
		return ErrAuthenticationRequired
	}

	if err := fullSessionOnly(s); err != nil {
		return err
	}

	if err := raisedChallengeRefusal(ex, s); err != nil {
		return err
	}

	if err := requireSessionUser(ex, s); err != nil {
		return err
	}

	if route == routeList {
		list, err := m.sessions.ListSignIns(ex.Context(), s.UserID, s)
		if err != nil {
			return err
		}

		return m.list(ex, list)
	}

	// Ending needs a recent proof of identity, judged before anything is read
	// or revoked.
	if !session.AuthenticatedWithin(s.AuthenticatedAt, m.now(), m.window) {
		return &ReauthenticationRequiredError{Window: m.window}
	}

	if route == routeEndOne {
		if err := m.sessions.EndSignIn(ex.Context(), s.UserID, handle); err != nil {
			if errors.Is(err, session.ErrNotFound) {
				return ErrSessionHandleNotFound
			}

			return err
		}

		emitEvent(ex.Context(), sessionEvent(security.SignInEnded, security.OutcomeSuccess, s))

		return m.respEnd(ex)
	}

	n, err := m.sessions.EndOtherSignIns(ex.Context(), s.UserID, s)
	if err != nil {
		return err
	}

	// Reported only when a sign-in ended: a caller with no other sign-in
	// ended nothing.
	if n > 0 {
		emitEvent(ex.Context(), sessionEvent(security.SignInEnded, security.OutcomeSuccess, s))
	}

	return m.respEnd(ex)
}

// signInListDocument is the listing's default answer. Its member names are
// the endpoint's documented contract.
type signInListDocument struct {
	Sessions []signInDocument `json:"sessions"`
}

// signInDocument is one listed sign-in.
type signInDocument struct {
	Handle      string    `json:"handle"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	FirstFactor string    `json:"first_factor"`
	Pending     *string   `json:"pending"`
	Current     bool      `json:"current"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
}

// writeSignInList is the default list responder.
func writeSignInList(ex *Exchange, list []session.SignIn) error {
	doc := signInListDocument{Sessions: make([]signInDocument, 0, len(list))}
	sort.SliceStable(list, func(i, j int) bool { return list[i].LastUsedAt.After(list[j].LastUsedAt) })

	for _, si := range list {
		item := signInDocument{
			Handle:      si.Handle.String(),
			CreatedAt:   si.CreatedAt,
			LastUsedAt:  si.LastUsedAt,
			FirstFactor: string(si.FirstFactor),
			Current:     si.Current,
			ClientIP:    si.ClientIP,
			UserAgent:   si.UserAgent,
		}

		if si.Pending != session.MFANone {
			pending := si.Pending.String()
			item.Pending = &pending
		}

		doc.Sessions = append(doc.Sessions, item)
	}

	return writeSuccessDocument(ex, doc)
}

// writeSignInsEnded is the default end responder: 204.
func writeSignInsEnded(ex *Exchange) error {
	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}
