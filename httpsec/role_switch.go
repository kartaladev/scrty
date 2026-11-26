package httpsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/session"
)

var (
	// ErrRoleSwitchingDisabled is returned by Chain.SwitchActiveRole on a chain
	// built without WithSwitchableRoles. It is returned to the consumer's
	// own call, and has no status of its own: a handler that returns it is
	// answered 500, since it means the chain was wired without the feature the
	// handler relies on.
	ErrRoleSwitchingDisabled = errors.New("httpsec: active-role switching is not enabled")

	// ErrRoleNotHeld refuses a switch to a role the user does not hold a grant
	// of, in force at the chain's clock. It matches authorize.ErrAccessDenied,
	// so it is answered 403 as any other denial is, and
	// authorize.ErrNoActiveRole, the reason a caller cannot act under that
	// role. Its text never names the role.
	ErrRoleNotHeld = fmt.Errorf("httpsec: the role is not held: %w: %w",
		authorize.ErrAccessDenied, authorize.ErrNoActiveRole)
)

// maxRoleNameBytes bounds the role name Chain.SwitchActiveRole accepts. A
// longer name is refused as not held before anything is loaded, so a caller
// cannot make the chain compare or store an arbitrarily long name.
const maxRoleNameBytes = 256

// changedActiveRole is what a role-switch event's Changed names: the field
// the switch changed, never its value.
const changedActiveRole = "active_role"

// The fixed texts a switch that reached no verdict is answered with.
const (
	textRoleNotRecorded    = "httpsec: the selected role could not be recorded"
	textRoleSwitchEnded    = "httpsec: the request ended while its role was switched"
	textRoleNotRotated     = "httpsec: the session could not be rotated for the role switch"
	textRoleSwitchAfterRun = "on a cookie chain the switch re-sets the session cookie on the request's " +
		"response, so it must be called while the chain is still handling the request"
	textRoleNotResolvedBy = "the request's session was not resolved by one of this chain's " +
		"session-bound authenticators (EnableBearerToken, EnableSessionBearer, EnableSessionCookie), so its role " +
		"cannot be switched"
)

// roleSourceKey is this package's own context key for the resolution that
// authenticated the request, which only the resolution core sets.
type roleSourceKey struct{}

// roleSource is the resolution that authenticated a request on a chain with
// switching on: the chain, the resolution core that resolved the session,
// and the session it published. Chain.SwitchActiveRole reloads the user and
// records the selection through the same loader and manager.
//
// On a cookie session it also holds the request's exchange, whose response
// the rotated session's cookie is set on, and the run that tells whether that
// response is still being written; both are nil for a bearer.
type roleSource struct {
	chain    *Chain
	resolver *sessionResolver
	session  *session.Session

	ex  *Exchange
	run *chainRun

	// mu serialises the switches made on this request, and guards current,
	// the session the request's sign-in is on now: session itself until a
	// switch rotates it, and deadline.
	mu      sync.Mutex
	current *session.Session

	// deadline is the absolute deadline current will have once a change
	// pending on the request is saved, which a switch sets the re-set cookie
	// for instead of current's own; zero when none is pending. A password
	// change on a recovery-pending sign-in sets it: the deadlines it restores
	// are saved after the consumer's function, and a switch inside that
	// function would otherwise set the cookie for the lowered recovery one.
	deadline time.Time
}

// isRequestSession reports whether id is the identifier the chain resolved the
// request on, or the one an earlier switch on it rotated that into.
func (src *roleSource) isRequestSession(id string) bool {
	src.mu.Lock()
	defer src.mu.Unlock()

	return id == src.session.ID || (src.current != nil && id == src.current.ID)
}

// moveTo records that the request is on s now, the successor of a rotation
// other than a switch's own (the password change's), so a switch made after it
// rotates s, and the context carrying s is recognised as the request's.
// deadline is the absolute deadline the sign-in will have once that change is
// saved, which a later switch's cookie is set for; zero keeps the successor's
// own.
func (src *roleSource) moveTo(s *session.Session, deadline time.Time) {
	src.mu.Lock()
	defer src.mu.Unlock()

	src.current = s
	src.deadline = deadline
}

// latest returns the session the request's sign-in is on now: the one the
// chain resolved, or the successor of the last rotation made on the request.
func (src *roleSource) latest() *session.Session {
	src.mu.Lock()
	defer src.mu.Unlock()

	return src.current
}

// withRoleSource returns a copy of ctx carrying src.
func withRoleSource(ctx context.Context, src *roleSource) context.Context {
	return context.WithValue(ctx, roleSourceKey{}, src)
}

// SwitchActiveRole records role as the active role of the session the request
// ctx belongs to was authenticated on, so the caller acts under it from the
// next request on, for as long as they still hold it.
//
// ctx is the context of a request this chain authenticated through one of its
// session-bound authenticators (EnableBearerToken, EnableSessionBearer or
// EnableSessionCookie), as a handler behind the chain receives it. The user is
// reloaded, and the switch succeeds only when they hold a grant named role
// that is in force at the chain's clock, as for the grants a request is built
// with. For a bearer, only the session's selected role is written, through the
// session manager that resolved it. The empty role clears the selection, so
// the primary grant applies again. The request in progress keeps the
// principal it was authenticated with; every later request on the session
// applies the selection while the grant stays in force, and the primary grant
// otherwise. A successful switch is reported as event.ActiveRoleSwitched,
// with the user as both User and Actor, the role now
// active (the primary grant's name, or empty, for a cleared selection) as
// Target, and "active_role" in Changed.
//
// On a session the cookie session resolved, a switch is a privilege change,
// so the session is first rotated into a successor in the same sign-in, the
// session cookie is re-set to it on the request's response, and the selection
// is recorded on the successor. The old identifier keeps working for a grace
// window (the renewal endpoint's, WithRenewalGrace, when the chain has one,
// and session.DefaultRenewalGrace otherwise), so a request already in flight
// with it is not signed out; presented after the window it is reuse, which
// revokes the sign-in. The successor keeps the sign-in's CSRF token, so the
// browser's token stays valid. The request's exchange and context then carry
// the successor, so a later switch on the request is made on it. Call it from the handler's own goroutine,
// before the handler writes its response: a response already begun drops the
// re-set cookie, and the browser, left with the old identifier, is signed out
// once the window ends. A rotation that cannot be written stores nothing,
// switches nothing and sets no cookie. A second switch on the same request
// rotates the successor of the first. Bearer sessions are not rotated: the
// credential a bearer client holds cannot be replaced by the response. Neither
// is a cookie session on a chain built with
// WithoutSessionRotation(RotateOnRoleSwitch): the selection is recorded on the
// session the request is on now, as for a bearer, no cookie is set, and the
// identifier the browser holds carries the new role (session fixation at the
// switch, which that option documents).
//
// It returns:
//   - ErrRoleSwitchingDisabled on a chain built without
//     WithSwitchableRoles, whatever ctx carries;
//   - ErrAuthenticationRequired when ctx carries no session this chain
//     authenticated, or when the session or its user is no longer live: not
//     found, expired, superseded by a renewal, or the user not active;
//   - an error wrapping ErrConfig when ctx carries a session this chain did not
//     resolve itself, such as one a consumer interceptor published, or when
//     the session ctx carries is no longer the one the chain resolved, as
//     when an interceptor published another after it, and, for a cookie
//     session that a switch rotates, when the chain has finished handling the
//     request;
//   - ErrSessionRenewalConflict when a concurrent rotation of a cookie session
//     won, and ErrAuthenticationRequired joined to session.ErrReused when its
//     identifier was already reused;
//   - ErrRoleNotHeld when the user holds no grant named role in force now, and
//     for a name over 256 bytes, not valid UTF-8 or holding a NUL byte, which
//     no store can hold; the session is left unchanged;
//   - a failure matching ctx's error when the request ended first;
//   - otherwise a dependency failure behind fixed text, matching its cause
//     through errors.Is.
//
// For a bearer session, a context kept past its request, such as one from
// context.WithoutCancel, can still switch afterwards: nothing in it ends with
// the request, and so can a cookie session's whose switch does not rotate. A
// cookie session's that a switch rotates cannot, since its response is gone. The user
// is reloaded on every call and only a live session accepts the write, so a
// session or user that has ended since is refused with
// ErrAuthenticationRequired.
//
// Default: switching is off (WithSwitchableRoles).
func (c *Chain) SwitchActiveRole(ctx context.Context, role string) error {
	if c.perRequest == nil || !c.perRequest.roleSwitching {
		return ErrRoleSwitchingDisabled
	}

	src, ok := ctx.Value(roleSourceKey{}).(*roleSource)
	if !ok || src == nil || src.chain != c || src.resolver == nil || src.session == nil {
		if _, has := SessionFromContext(ctx); has {
			return newConfigError("SwitchActiveRole: %s", textRoleNotResolvedBy)
		}

		return ErrAuthenticationRequired
	}

	// The session the request is on now must be the one the chain resolved: a
	// consumer interceptor that published another since would otherwise make
	// the switch write, and report, a session the request is not on.
	// It may also be the successor of an earlier switch on this request, which
	// is what the exchange's context carries after one.
	if now, has := SessionFromContext(ctx); !has || now == nil ||
		now.UserID != src.session.UserID || !src.isRequestSession(now.ID) {
		return newConfigError("SwitchActiveRole: %s", textRoleNotResolvedBy)
	}

	if !storableRoleName(role) {
		return ErrRoleNotHeld
	}

	r, s := src.resolver, src.session

	details, err := r.users.LoadByUserID(ctx, s.UserID)
	err = porterr.SanitizeTo(ctx, r.log, err, porterr.ErrUnwalkable)

	if err != nil {
		return classifyReload(ctx, err)
	}

	if err := ownActiveUser(s, details); err != nil {
		return err
	}

	principal := identity.PrincipalFromDetailsAt(details, r.phase.now())

	var target string

	switch {
	case role != "":
		if grantNamed(principal, role) == nil {
			return ErrRoleNotHeld
		}

		target = role
	case principal.ActiveRole != nil:
		target = principal.ActiveRole.Name
	}

	if r.cookie != nil && r.cookie.rotatesAt(RotateOnRoleSwitch) {
		// A cookie session moves to a new identifier before the selection is
		// recorded, so the role never changes on an identifier that existed
		// before the switch (session fixation).
		s, err = src.rotateForSwitch(ctx, role)
		if err != nil {
			return err
		}
	} else {
		// Recorded on the session the request is on now: the one the chain
		// resolved, or, on a cookie chain that rotates at a password change
		// but not here, the successor that change moved the request to, since
		// the identifier it arrived on is superseded by then.
		s = src.latest()
		if err := r.sessions.SelectRole(ctx, s.ID, role); err != nil {
			return classifySelect(ctx, err)
		}
	}

	if c.events != nil {
		e := sessionEvent(event.ActiveRoleSwitched, event.OutcomeSuccess, s)
		e.Actor = string(details.ID)
		e.Target = target
		e.Changed = []string{changedActiveRole}

		c.events.emit(ctx, e)
	}

	return nil
}

// rotateForSwitch rotates the cookie session the request is on now into a
// successor in the same sign-in, re-sets the cookie to it on the request's
// response, and records role as the successor's selection. It returns the
// successor.
//
// The rotation keeps the old identifier working for a grace window, the
// renewal endpoint's when the chain has one and session.DefaultRenewalGrace
// otherwise, so a request already in flight with it is not signed out; past
// the window it is reuse, which revokes the sign-in. The successor carries
// everything the rotation carries over, the sign-in's CSRF token and its
// persistent-cookie choice included. A persistent cookie is set for the
// deadline a change pending on the request will restore (moveTo), when one is
// pending, rather than for the successor's own.
//
// It refuses with an error wrapping ErrConfig, and changes nothing, once the
// chain's run of the request is over (a context kept past its request): the
// response the cookie would be set on is gone, and a rotation the browser
// never learns of would turn its next request into reuse.
//
// A rotation that fails stores nothing and sets no cookie, so the old
// identifier keeps working, unswitched: a refusal (the session gone, expired
// or reused, or a concurrent rotation won) as refusedRenewal words it, the
// request's own end as matching its context's error, anything else as a
// dependency failure behind fixed text, its cause reachable. A cookie that
// cannot be delivered ends the sign-in (credentialDelivery.deliver). A
// selection that cannot be recorded after the cookie was re-set is answered
// as classifySelect answers it, with the cookie re-set and the role
// unchanged.
func (src *roleSource) rotateForSwitch(ctx context.Context, role string) (*session.Session, error) {
	if src.ex == nil || src.run == nil || src.run.done.Load() {
		return nil, newConfigError("SwitchActiveRole: %s", textRoleSwitchAfterRun)
	}

	src.mu.Lock()
	defer src.mu.Unlock()

	r := src.resolver

	successor, err := (credentialDelivery{cookie: r.cookie, log: r.log}).rotateCookie(ctx, src.ex, r.sessions,
		src.current, privilegeRotationGrace(r.renewal), src.deadline,
		cookieRotationTexts{failed: textRoleNotRotated, ended: textRoleSwitchEnded})
	if err != nil {
		return nil, err
	}

	src.current = successor

	// The request is on the successor from here on, as after a password
	// change's rotation, so what a later step of it reads (ex.Session, the
	// context's session) names the identifier the browser now holds, and a
	// further switch is made on it.
	src.ex.Session = successor
	src.ex.SetContext(withSession(src.ex.Context(), successor)) //nolint:contextcheck // the request's own exchange context, extended, not a new root

	if err := r.sessions.SelectRole(ctx, successor.ID, role); err != nil {
		return nil, classifySelect(ctx, err)
	}

	return successor, nil
}

// storableRoleName reports whether role is a name a switch may record: at most
// maxRoleNameBytes long, valid UTF-8 and free of NUL bytes, which no durable
// store holds unchanged. A name that is not is refused as not held, since a
// grant the stores cannot hold is not a grant anyone holds.
func storableRoleName(role string) bool {
	return len(role) <= maxRoleNameBytes && utf8.ValidString(role) && strings.IndexByte(role, 0) < 0
}

// classifySelect answers a selection write that failed with err, on the
// request whose own context is ctx, as classifyLoad answers a session load:
// a session not found, expired or superseded is refused with
// ErrAuthenticationRequired, since the session the request was authenticated
// on is no longer the live one; a hang-up matches ctx's error; anything else
// is a dependency failure behind fixed text, err reachable through errors.Is.
// The session manager has already bounded the walk of the store's error.
func classifySelect(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired),
		errors.Is(err, session.ErrSuperseded):
		return ErrAuthenticationRequired
	case hangup.ByCaller(ctx, err):
		return diag.Wrap(err, textRoleSwitchEnded, ctx.Err())
	default:
		return diag.Wrap(err, textRoleNotRecorded)
	}
}
