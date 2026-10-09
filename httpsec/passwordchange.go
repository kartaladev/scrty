package httpsec

import (
	"context"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// ChangePasswordFunc changes the caller's own password.
//
// There is no default, because the library ships no user store to change a
// password in and no rules about what a new one must look like. With none
// supplied there is no resolve endpoint at all, and a session that owes a
// change is refused until a new login clears it — see
// WithChangePasswordEndpoint. It is called
// with the exchange, and it owns the response: the library writes nothing on
// this path, so whatever a consumer's clients expect to read is what they
// read. An error it returns is the request's refusal, unchanged.
//
// When it succeeds, the chain clears the caller's lockout failures in the
// attempt stores of its form login and Basic authentication, under the
// principal's username exactly as stored: guesses at the old password protect
// nothing once it has changed. Failures recorded under another spelling of
// the username stay until they leave the lockout window. A consumer who
// changes passwords outside the chain clears them with
// policy.AccountLockoutPolicy.Reset.
type ChangePasswordFunc func(ex *Exchange) error

// passwordChangeGate holds every session that owes a password change, and lets
// the consumer's resolve endpoint through so the debt can be paid.
type passwordChangeGate struct {
	sessions *session.Manager

	// path and change are the consumer's resolve endpoint, and are empty when
	// they registered none. Without one, only a new login clears the challenge.
	path   string
	change ChangePasswordFunc

	// logoutPath is the chain's logout endpoint, handed over at assembly and
	// never configured here, so a consumer who moves logout moves the gate's
	// exemption with it. It is empty when the chain has no logout.
	logoutPath string

	// attempts are the stores the chain's password logins record failures
	// into, each once, handed over at assembly. A successful change clears the
	// caller's username in each. It is empty on a chain with no password
	// login, which has no password lockout to clear.
	attempts []policy.AttemptStore

	// log is the chain's logger, handed over at assembly, which a store that
	// cannot clear is reported through.
	log *slog.Logger
}

// wirePasswordChange hands every password-change gate the chain's logout path,
// the attempt stores of its password logins, and its logger.
//
// It runs at assembly rather than when EnablePasswordChangeGate is applied,
// because EnableLogout, the logins, or the options that move the path or set
// the logger may come after it.
func (c *config) wirePasswordChange() {
	stores := c.passwordAttemptStores()

	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		g.logoutPath = c.logoutPath
		g.attempts = stores
		g.log = c.logger

		return nil
	})
}

// passwordAttemptStores is every attempt store the chain's password logins
// record failures into, each once: form login's and Basic's, which a consumer
// usually wires to the same store.
func (c *config) passwordAttemptStores() []policy.AttemptStore {
	var stores []policy.AttemptStore

	add := func(s policy.AttemptStore) {
		if nilcheck.IsNil(s) {
			return
		}

		for _, have := range stores {
			if sameStore(have, s) {
				return
			}
		}

		stores = append(stores, s)
	}

	_ = eachInterceptor(c, func(l *formLogin) error {
		add(l.attempts)

		return nil
	})
	_ = eachInterceptor(c, func(b *basicAuth) error {
		add(b.attempts)

		return nil
	})

	return stores
}

// sameStore reports whether a and b are one store.
//
// Comparing two interfaces panics when their dynamic value cannot be compared,
// and a type can be comparable while its value is not: a struct with an
// interface field is comparable by type, yet == panics when that field holds a
// struct with a slice. So comparability is asked of the values, which looks
// inside interface fields, and a store that cannot be compared is never taken
// for another: it is cleared once for each login that holds it, which is
// harmless, where a panic at assembly would not be.
func sameStore(a, b policy.AttemptStore) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)

	return va.Type() == vb.Type() && va.Comparable() && vb.Comparable() && a == b
}

// isLogoutPost reports whether r is the chain's logout: a POST on exactly
// logoutPath. An empty logoutPath is a chain without logout, which matches
// nothing, so a gate on such a chain lets nothing extra through.
func isLogoutPost(logoutPath string, r Request) bool {
	return logoutPath != "" && r.Method() == http.MethodPost && r.Path() == logoutPath
}

// Intercept refuses any session that owes a password change, and lets the
// consumer's resolve endpoint through so the debt can be paid.
//
// The chain's logout passes too, so a caller stranded mid-challenge can always
// end the session; logging out pays no debt, it only ends what owed it.
//
// A request carrying no session passes: the gate guards sessions, and whether
// an anonymous request may go on is the business of the authentication
// interceptors outside it.
func (g *passwordChangeGate) Intercept(ex *Exchange, next Next) error {
	if g.isResolveRequest(ex.Request) {
		return g.resolve(ex)
	}

	if ex.Session != nil && ex.Session.PasswordChangePending {
		if isLogoutPost(g.logoutPath, ex.Request) {
			return next(ex)
		}

		// No token: the caller already holds the credential this session was
		// reached with, and a gate issues nothing.
		return &ChallengeError{Kind: policy.ChallengePasswordChange, Session: ex.Session}
	}

	return next(ex)
}

// isResolveRequest reports whether r is the consumer's resolve endpoint.
//
// Only POST, and only on the exact path: a request that merely reads something
// under that path is not a password change, and letting it through would open
// a hole in the gate the size of one URL.
func (g *passwordChangeGate) isResolveRequest(r Request) bool {
	return g.change != nil && r.Method() == http.MethodPost && r.Path() == g.path
}

// resolve runs the consumer's change, and records the debt as paid only when
// it reports that it was.
//
// On a recovery-pending session a successful change also completes the
// recovery: the session's deadlines are restored, its second-factor state
// becomes none, and the security policies decide on the next request what it
// owes, such as an MFA challenge or an enrolment. The session is saved, not
// rotated. The consumer's function owns the response, so there is nowhere to
// hand a new credential back; and nothing is lost by keeping the handle, since
// the recovery created this session for this caller moments ago and it has
// had no earlier holder. A change that fails leaves the session
// recovery-pending. A session already past its lowered deadline is refused
// before the consumer's function runs, so no password is changed on a request
// that is then refused; and a session that cannot be saved afterwards is left
// in memory as it was.
//
// A successful change also clears the caller's lockout failures, at once and
// before the save, since the password has changed whether or not the save then
// succeeds; see clearFailures.
func (g *passwordChangeGate) resolve(ex *Exchange) error {
	// The endpoint changes this caller's own password, so there has to be a
	// caller: without a session it would be an unauthenticated password change
	// on an account named by nothing but the request body.
	if ex.Session == nil {
		return ErrAuthenticationRequired
	}

	s := ex.Session

	// What the session becomes is worked out before the consumer's function
	// runs, so that a recovery-pending session already past its lowered
	// deadline is refused before any password is changed: it has ended, is
	// not revived, and the caller is answered as for any session that no
	// longer loads.
	resolved := *s
	if s.MFA == session.MFARecoveryPending {
		if err := g.sessions.RestoreEnrolmentDeadlines(&resolved); err != nil {
			return ErrAuthenticationRequired
		}

		resolved.MFA = session.MFANone
	}

	resolved.PasswordChangePending = false

	// Who to clear is read before the consumer's function runs: it may replace
	// the exchange's context, and what it leaves there is not this caller's
	// say in whose failures are cleared.
	ctx, username := ex.Context(), g.clearableUsername(ex.Context())

	if err := g.change(ex); err != nil {
		// The consumer's error is the refusal, unchanged: they know why they
		// refused, and restating it here would lose that.
		return err
	}

	g.clearFailures(ctx, username)

	previous := *s
	adoptResolution(s, &resolved)

	// Persisted before the response returns, because the marker is what every
	// later request is judged on: a change that cleared the flag in memory
	// alone would be owed again on the next request. A session that cannot be
	// saved keeps, in memory too, the state it was stored in.
	if err := g.sessions.Save(ex.Context(), s); err != nil {
		adoptResolution(s, &previous)

		return err
	}

	return nil
}

// msgFailuresNotCleared is the record for a store that could not clear the
// failures a password change superseded. The change stands; only the
// bookkeeping failed.
const msgFailuresNotCleared = "httpsec: lockout failures could not be cleared after a password change"

// clearFailures clears the caller's lockout failures in every password-login
// store, once their password has changed: the failures were guesses at a
// password that no longer exists, and keeping them only locks out the user
// who has just proved they hold the account.
//
// The username is the principal's, which the bearer step loaded the user by,
// so it is the identifier this user signs in with. Only that exact string is
// cleared; failures recorded under another spelling stay until they leave the
// window, as they do after a successful login.
//
// The client's cancellation is not passed on: a client that hangs up after
// changing its password must still be cleared, and a store that honours
// cancellation would otherwise keep the old guesses against the new password.
//
// A store that cannot clear is bookkeeping that failed, not a refusal: the
// password has changed and the consumer's response stands. The record carries
// a fixed reason and the store's error type, never its text and never the
// username.
func (g *passwordChangeGate) clearFailures(reqCtx context.Context, username string) {
	if username == "" {
		return
	}

	ctx := context.WithoutCancel(reqCtx)
	for _, store := range g.attempts {
		if err := store.Reset(ctx, username); err != nil {
			g.log.LogAttrs(reqCtx, slog.LevelError, msgFailuresNotCleared,
				diag.Failure("attempt-store", err)...)
		}
	}
}

// clearableUsername is the username of the principal ctx carries, or "" when
// there is none.
func (g *passwordChangeGate) clearableUsername(ctx context.Context) string {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return ""
	}

	return p.Username
}

// adoptResolution copies onto dst the fields resolve changes, from src: the
// second-factor state, the password-change marker and the deadlines a
// recovery-pending session's resolution restores. Every other field is left
// as dst holds it, including anything the consumer's function set.
func adoptResolution(dst, src *session.Session) {
	dst.MFA = src.MFA
	dst.PasswordChangePending = src.PasswordChangePending
	dst.AbsoluteExpiresAt = src.AbsoluteExpiresAt
	dst.IdleExpiresAt = src.IdleExpiresAt
	dst.EnrolmentOriginDeadline = src.EnrolmentOriginDeadline
	dst.EnrolmentGeneration = src.EnrolmentGeneration
}
