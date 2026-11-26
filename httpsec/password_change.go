package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"time"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// ChangePasswordFunc changes the caller's own password.
//
// There is no default, because the library ships no user store to change a
// password in and no rules about what a new one must look like. With none
// supplied there is no resolve endpoint at all, and a session that owes a
// change is refused until a new login clears it — see
// WithPasswordChangeEndpoint. It is called
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
// lockout.Policy.Reset.
//
// A nil return also means the password is changed: on a chain with
// EnableSessionSignals the chain then raises credential_changed with kind
// "password" to every open stream of the user, and the signal cannot be
// recalled. A function that wrote a refusal to the response itself must
// therefore not return nil, since nil would tell the user's other streams of
// a change that did not happen: return the refusal as an error instead.
type ChangePasswordFunc func(ex *Exchange) error

// passwordChangeGrantCause is the cause a password change revokes grants with.
const passwordChangeGrantCause = "password_change"

// userGrantRevoker revokes every grant an application holds for a user, those
// with offline access included. *oidcprovider.Provider satisfies it, and it is
// what the chain hands the endpoints that revoke them when EnableOIDCProvider is
// on. There is none on a chain without a provider, and nothing to revoke.
type userGrantRevoker interface {
	RevokeUserGrants(ctx context.Context, user identity.UserID, cause string) error
}

// grantRevoker is the chain's provider as the port its endpoints revoke through,
// and nil on a chain without one.
func (c *config) grantRevoker() userGrantRevoker {
	if c.oidcProvider == nil {
		return nil
	}

	return c.oidcProvider.provider
}

// passwordChangeGate holds every session that owes a password change, and lets
// the consumer's resolve endpoint through so the debt can be paid.
type passwordChangeGate struct {
	sessions *session.Sessions

	// path and change are the consumer's resolve endpoint, and are zero when
	// they registered none. Without one, only a new login clears the challenge.
	// path also holds where the endpoint answers under the base path, once
	// resolved; an unset path answers nowhere.
	path   endpointPath
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

	// revokeGrants is WithPasswordChangeGrantRevocation, and grants the chain's
	// provider it revokes through, handed over at assembly.
	revokeGrants bool
	grants       userGrantRevoker

	// deliver is the chain's credential delivery and grace the window a
	// rotation keeps the old identifier working for, both handed over at
	// assembly. On a cookie chain a change rotates the session and re-sets
	// the cookie through deliver; on any other chain it rotates nothing.
	deliver credentialDelivery
	grace   time.Duration
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
		g.grants = c.grantRevoker()
		g.deliver = c.delivery()
		g.grace = privilegeRotationGrace(c.renewal)

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

	if s := requestSession(ex); s != nil && s.PasswordChangePending {
		if isLogoutPost(g.logoutPath, ex.Request) {
			return next(ex)
		}

		// No token: the caller already holds the credential this session was
		// reached with, and a gate issues nothing.
		return &ChallengeError{Kind: policy.ChallengePasswordChange, Session: s}
	}

	return next(ex)
}

// isResolveRequest reports whether r is the consumer's resolve endpoint.
//
// Only POST, and only on the exact path: a request that merely reads something
// under that path is not a password change, and letting it through would open
// a hole in the gate the size of one URL.
func (g *passwordChangeGate) isResolveRequest(r Request) bool {
	return g.change != nil && r.Method() == http.MethodPost && r.Path() == g.path.at()
}

// resolve runs the consumer's change, and records the debt as paid only when
// it reports that it was.
//
// On a recovery-pending session a successful change also completes the
// recovery: the session's deadlines are restored, its second-factor state
// becomes none, and the security policies decide on the next request what it
// owes, such as an MFA challenge or an enrolment. On a chain without the
// cookie session the session is saved, not rotated: the consumer's function
// owns the response, so there is nowhere to hand a new credential back. On a
// cookie chain the session is rotated and the cookie re-set before the
// consumer's function runs, a recovery-pending one included, and the
// resolution is saved on the successor. A persistent cookie of a
// recovery-pending session is set with the Max-Age of the absolute deadline
// the change restores, not of the lowered recovery deadline, and so is the
// cookie a role switch inside the consumer's function re-sets. A change that
// fails leaves the session recovery-pending. A session already past its
// lowered deadline is refused before the consumer's function runs, so no
// password is changed on a request that is then refused.
//
// The resolution is saved on the latest session of the request's sign-in as
// the chain holds it in memory: the gate's own session, its rotation's
// successor, or the successor of the last role switch the consumer's function
// made. Nothing is loaded to save it, since Save keeps the role the switch
// recorded in the store. The exchange's Session, which the consumer's
// function may overwrite, never names the session saved; a target that is not
// of the sign-in the gate resolved (another user or family) is refused and
// nothing is saved. A session that cannot be saved afterwards is left in
// memory as it was, and the error is returned: the password has changed, the
// session still owes the change, and the caller is answered as for the
// store's failure.
//
// A successful change also clears the caller's lockout failures, at once and
// before the save, since the password has changed whether or not the save then
// succeeds; see clearFailures.
//
// With WithPasswordChangeGrantRevocation the user's grants are revoked just
// before the consumer's function runs.
func (g *passwordChangeGate) resolve(ex *Exchange) error {
	// The endpoint changes this caller's own password, so there has to be a
	// caller: without a session it would be an unauthenticated password change
	// on an account named by nothing but the request body.
	if ex.Session == nil {
		return ErrAuthenticationRequired
	}

	s := ex.Session
	gated := s

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

	// The role source is read before the consumer's function runs, which may
	// replace the exchange's context, and only when it is the one that
	// resolved the session the gate holds. It is where the resolution is saved
	// from: the exchange's Session is the consumer's to overwrite, so it never
	// names the session saved.
	src := requestRoleSource(ex.Context(), s)

	// On a cookie chain a password change is a privilege change, so the
	// session moves to a new identifier and the cookie is re-set to it. It
	// happens before anything else changes and before the consumer's function
	// runs, since that function owns the response and a cookie set once the
	// response has begun would never reach the browser. A rotation that fails
	// has stored nothing and set no cookie: no grant is revoked, no password
	// changed, and the old cookie keeps working.
	//
	// A recovery-pending session gets its origin deadlines back once the change
	// is saved, so a cookie set on this request, by this rotation or a role
	// switch inside the consumer's function, is set for those, not the lowered
	// ones the session is stored with; any other session keeps its own.
	var deadline time.Time
	if g.deliver.cookie != nil && s.MFA == session.MFARecoveryPending {
		deadline = resolved.AbsoluteExpiresAt
	}

	switch {
	case g.deliver.cookie != nil && !g.deliver.cookie.rotatesAt(RotateOnPasswordChange):
		// The consumer turned this rotation off (WithoutSessionRotation): the
		// session keeps its identifier and the cookie is left as it is, but a
		// switch inside the function still sets its cookie for the deadline
		// the change restores.
		if src != nil && !deadline.IsZero() {
			src.moveTo(s, deadline)
		}
	case g.deliver.cookie != nil:
		rotated, err := g.deliver.rotateCookie(ex.Context(), ex, g.sessions, s, g.grace, deadline,
			cookieRotationTexts{failed: textChangeNotRotated, ended: textChangeRotationEnded})
		if err != nil {
			return err
		}

		s = rotated
		ex.Session = rotated
		ex.SetContext(withSession(ex.Context(), rotated))

		// A role switch the consumer's function makes on this request goes on
		// from the successor, not from the session the request arrived on,
		// and sets its cookie for the deadline the change restores.
		if src != nil {
			src.moveTo(rotated, deadline)
		}
	}

	// Who to clear is read before the consumer's function runs: it may replace
	// the exchange's context, and what it leaves there is not this caller's
	// say in whose failures are cleared.
	ctx, username := ex.Context(), g.clearableUsername(ex.Context())

	// Before the change, as the option promises: a revocation that fails leaves
	// the password as it was, and the caller can try again.
	if g.revokeGrants {
		if err := g.grants.RevokeUserGrants(ctx, s.UserID, passwordChangeGrantCause); err != nil {
			return err
		}
	}

	if err := g.change(ex); err != nil {
		// The consumer's error is the refusal, unchanged: they know why they
		// refused, and restating it here would lose that. Only a refusal is
		// reported: a store the function could not reach decided nothing.
		if refused(ctx, ex.answeringChain(), err) {
			emitEvent(ctx, sessionEvent(event.AuthnPasswordChangeFail, event.OutcomeFailure, s))
		}

		return err
	}

	// The password is changed by now, whether or not the session then saves.
	emitEvent(ctx, sessionEvent(event.AuthnPasswordChange, event.OutcomeSuccess, s))
	ex.credentialChanged(s.UserID, CredentialPassword)

	g.clearFailures(ctx, username)

	// A function that switched the active role rotated the session again, so
	// the resolution is saved on the latest successor, as the role source holds
	// it in memory. Save keeps the selection the switch recorded in the store,
	// so nothing is loaded, and the successor's first presentation is left to
	// the browser.
	target, err := resolutionTarget(gated, s, src)
	if err != nil {
		return err
	}

	previous := *target
	adoptResolution(target, &resolved)

	// Persisted before the response returns, because the marker is what every
	// later request is judged on: a change that cleared the flag in memory
	// alone would be owed again on the next request. A session that cannot be
	// saved keeps, in memory too, the state it was stored in.
	if err := g.sessions.Save(ex.Context(), target); err != nil {
		adoptResolution(target, &previous)

		return err
	}

	return nil
}

// errResolutionNotOwn refuses to save a password change's resolution on a
// session that is not of the sign-in the gate resolved. Nothing the chain does
// leads there; it guards the save against a role source that holds another
// sign-in.
var errResolutionNotOwn = errors.New("httpsec: the password change's session is not the request's own sign-in")

// requestRoleSource is the role source ctx carries, when it resolved s or
// rotated it on this request, and nil otherwise: on a chain without
// switching, or when what the gate holds is not the session the chain
// resolved.
func requestRoleSource(ctx context.Context, s *session.Session) *roleSource {
	src, ok := ctx.Value(roleSourceKey{}).(*roleSource)
	if !ok || src == nil || src.session == nil || !src.isRequestSession(s.ID) {
		return nil
	}

	return src
}

// resolutionTarget is the session a password change's resolution is saved on:
// the latest successor src holds, when a role switch rotated s into one, and
// s itself otherwise, so on a chain that rotates nothing it is the very
// session the gate resolved. A target that is not of gated's sign-in, the
// same user and family, is refused with errResolutionNotOwn, and so is a nil
// gated or s, so that nothing is saved.
func resolutionTarget(gated, s *session.Session, src *roleSource) (*session.Session, error) {
	if gated == nil || s == nil {
		return nil, errResolutionNotOwn
	}

	target := s
	if src != nil {
		if current := src.latest(); current != nil && current.ID != s.ID {
			target = current
		}
	}

	if target.UserID != gated.UserID || target.FamilyID != gated.FamilyID {
		return nil, errResolutionNotOwn
	}

	return target, nil
}

// The fixed texts a cookie chain's rotation at a password change that reached
// no verdict is answered with.
const (
	textChangeNotRotated    = "httpsec: the session could not be rotated for the password change"
	textChangeRotationEnded = "httpsec: the request ended while its session rotated for the password change"
)

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

	for _, store := range g.attempts {
		err := resetBounded(reqCtx, store, username)
		// Only logged, but sanitized so an error that cannot be walked is
		// recorded as an abort too.
		if err = porterr.SanitizeTo(reqCtx, g.log, err, porterr.ErrUnwalkable); err != nil {
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

// PasswordChangeOption configures the password-change gate. Each replaces one
// of the defaults named on EnablePasswordChangeGate.
type PasswordChangeOption func(*passwordChangeGate) error

// EnablePasswordChangeGate holds every session that owes a password change at
// the password-change slot.
//
// Default: no resolve endpoint, under which a session that owes a change is
// refused until a new login clears it. Register one with
// WithPasswordChangeEndpoint to let a caller pay the debt without logging in
// again. A request carrying no session passes the gate untouched.
//
// A successful resolve also clears the caller's lockout failures (see
// ChangePasswordFunc); there is no option to keep them, since they were
// guesses at a password that no longer exists. It keeps the user's application
// grants unless WithPasswordChangeGrantRevocation revokes them.
//
// On a chain with EnableSessionCookie, a POST to the resolve endpoint is a
// privilege change: before the grants are revoked and before the consumer's
// function runs, the session is rotated into a successor in the same sign-in
// and the session cookie is re-set to it, so the function, which owns the
// response, sees the successor on the exchange and answers with the cookie
// already set. The old identifier keeps working for the renewal grace window
// (WithRenewalGrace, or session.DefaultRenewalGrace without renewal) and is
// reuse after it, which revokes the sign-in. The rotation happens whether or
// not the change then succeeds. One that cannot be written stores nothing,
// sets no cookie and runs no function: the request fails as a dependency
// failure and the old cookie keeps working. A function that writes its own
// cookies must not write the session cookie. WithoutSessionRotation
// (RotateOnPasswordChange) turns the rotation off: the change is then recorded
// on the session the request arrived on, which keeps its identifier, and no
// cookie is set.
//
// A POST to the chain's logout path always passes, so a caller owing a change
// can end the session; the path is the one EnableLogout configured, read when
// the chain is built, and nothing extra passes on a chain without logout.
// There is no option to refuse it: refusing logout protects nothing.
//
// The session manager is required and is the one the marker is cleared in: a
// gate that could not record the change would refuse the next request just the
// same, and the caller would have changed their password for nothing.
func EnablePasswordChangeGate(sessions *session.Sessions, opts ...PasswordChangeOption) Option {
	const option = "EnablePasswordChangeGate"

	return func(c *config) error {
		g := &passwordChangeGate{sessions: sessions}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(g); err != nil {
				return err
			}
		}

		c.enable(option, func() error {
			if err := requireDep(option, "session manager", sessions); err != nil {
				return err
			}

			return g.checkGrantRevocation(c)
		})

		c.useSessions(sessions)
		c.register(g, OrderPasswordChange)
		c.enableGate(policy.ChallengePasswordChange)

		return nil
	}
}

// WithPasswordChangeGrantRevocation revokes every application grant of the user,
// offline access included, each time the resolve endpoint runs, before the
// consumer's function writes the new password.
//
// Default: off. A password change keeps the user's grants, as no standard
// requires otherwise and surveyed providers do likewise; a consumer who treats a
// change as a sign of compromise opts in here.
//
// A revocation that fails fails the change: the function does not run, so the
// password stays as it was, and the error goes to the chain's handling, a 500 by
// default, so the caller can try again. Since the revocation comes first, one
// that succeeded stands even when the function then refuses the new password.
//
// It revokes through the chain's provider, so a chain without EnableOIDCProvider
// is refused with a configuration error, and so is one without
// WithPasswordChangeEndpoint, which has no change to revoke on.
func WithPasswordChangeGrantRevocation() PasswordChangeOption {
	return func(g *passwordChangeGate) error {
		g.revokeGrants = true

		return nil
	}
}

// checkGrantRevocation refuses WithPasswordChangeGrantRevocation on a chain where
// it could revoke nothing.
func (g *passwordChangeGate) checkGrantRevocation(c *config) error {
	switch {
	case !g.revokeGrants:
		return nil
	case g.change == nil:
		return newConfigError("WithPasswordChangeGrantRevocation needs WithPasswordChangeEndpoint: " +
			"with no resolve endpoint there is no change to revoke the grants on")
	case c.oidcProvider == nil:
		return newConfigError("WithPasswordChangeGrantRevocation needs EnableOIDCProvider: " +
			"with no provider on the chain there are no grants to revoke")
	}

	return nil
}

// WithPasswordChangeEndpoint answers POST requests on path with fn.
//
// Default: no endpoint at all, under which only a new login clears the
// challenge. The path is within the base path (WithBasePath), and the gate
// lets through the resolved path. Requests to path pass the gate, so the one endpoint a caller who
// owes a password change can reach is the one that resolves it; every other
// method on that path is gated like anything else.
//
// An empty path, or no function, is refused: either would be an endpoint that
// cannot answer, while the consumer believed their callers had a way out of
// the gate.
//
// When fn returns nil the password is taken as changed, and a chain with
// EnableSessionSignals raises credential_changed with kind "password"; see
// ChangePasswordFunc. A function that refused the request must not return nil.
func WithPasswordChangeEndpoint(path string, fn ChangePasswordFunc) PasswordChangeOption {
	return func(g *passwordChangeGate) error {
		if err := checkEndpointPath("WithPasswordChangeEndpoint", path); err != nil {
			return err
		}

		if fn == nil {
			return newConfigError("WithPasswordChangeEndpoint was given no function to change "+
				"the password with for %q", path)
		}

		g.path.give("WithPasswordChangeEndpoint", path)
		g.change = fn

		return nil
	}
}

// endpoints declares the consumer's password change, which the gate answers
// only when it was given one (WithPasswordChangeEndpoint).
func (g *passwordChangeGate) endpoints() []Endpoint {
	if g.change == nil {
		return nil
	}

	return []Endpoint{
		declare("EnablePasswordChangeGate", "WithPasswordChangeEndpoint", OperationPasswordChange, g.path.at(),
			MatchExact, OtherMethodsPassThrough, RequiresSession, http.MethodPost),
	}
}

// resetBounded clears username in store under a context the caller cannot
// cancel and that ends after detach.WriteTimeout, so one store's clearing
// neither holds the request for ever nor spends the next store's budget.
func resetBounded(ctx context.Context, store policy.AttemptStore, username string) error {
	bounded, cancel := detach.Bounded(ctx, detach.WriteTimeout)
	defer cancel()

	return store.Reset(bounded, username)
}
