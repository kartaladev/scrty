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
	textRoleSwitchInDelivery = "a session delivery must not switch the active role: the switch that " +
		"delivers through it holds the request's role-switch lock"
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
// once the window ends. The handler's return waits for a switch in progress
// on the request, so a switch the handler started on another goroutine and
// did not wait for still stores its rotation and sets its cookie before any
// interceptor's code after the handler runs, and that code sees the
// successor. The wait is bounded by the user loader's and the session store's
// own timeouts and the ctx given to the switch, not by the request's context,
// which net/http cancels only after the chain has returned. A switch made once
// the handler has returned, from an interceptor after it or on a context kept
// past the request, is refused. A switch waiting behind another on the same
// request gives up when its ctx ends. A rotation that cannot be written stores nothing,
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
//     session that a switch rotates, once the request's handler has returned,
//     or when ctx is that of the exchange a SessionDelivery is handed, or one
//     derived from it (a delivery must not switch);
//   - ErrSessionRenewalConflict when a concurrent rotation of a cookie session
//     won, and ErrAuthenticationRequired joined to session.ErrReused when its
//     identifier was already reused;
//   - ErrRoleNotHeld when the user holds no grant named role in force now, and
//     for a name over 256 bytes, not valid UTF-8 or holding a NUL byte, which
//     no store can hold; the session is left unchanged;
//   - a failure matching ctx's error when the request ended first, or ctx
//     ended while the switch waited behind another on the same request;
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

	// A switch that rotates a cookie session holds the request's role-switch
	// lock from here, before anything that waits on a switch in progress (the
	// source's lock), through its rotation and cookie write, so a switch
	// queued behind another gives up when ctx ends (holdRun).
	var held *roleSwitchGuard

	rotates := src.resolver.cookie != nil && src.resolver.cookie.rotatesAt(RotateOnRoleSwitch)
	if rotates {
		if err := src.holdRun(ctx); err != nil {
			return err
		}

		// Released once the rotation is done, before the event is emitted,
		// or on any earlier return.
		held = src.run.guard
		defer func() {
			if held != nil {
				held.release()
			}
		}()
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

	if rotates {
		// A cookie session records the selection on a new identifier, in the
		// rotation's own write (session.WithSuccessorRole), so the role never
		// changes on an identifier that existed before the switch (session
		// fixation).
		s, err = src.rotateForSwitch(ctx, role)

		held.release()
		held = nil

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
// successor in the same sign-in that carries role as its selection, written by
// the rotation itself (session.WithSuccessorRole), and re-sets the cookie to it
// on the request's response. It returns the successor.
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
// request's handler has returned, to this chain or to a chain nested inside
// it, or the run is over (a context kept past its request): the interceptors
// after the handler, and then the response's writer, are past the point the
// cookie and the request's session can be changed under them, and a rotation
// the browser never learns of would turn its next request into reuse. A switch begun
// before the handler's return holds that return off until the rotation is
// stored and the cookie set, the return then waiting no longer than the
// switch's reload of the user and its rotation, which the loader's and the
// store's own timeouts and ctx bound. A switch waiting behind another on the
// same request gives up when ctx ends, with ctx's error, and changes nothing.
//
// A rotation that fails sets no cookie and, but for session.ErrStoreContract
// below, stores nothing, so the old identifier keeps working, unswitched: a
// refusal (the session gone, expired
// or reused, or a concurrent rotation won) as refusedRenewal words it, the
// request's own end as matching its context's error, anything else as a
// dependency failure behind fixed text, its cause reachable. A cookie that
// cannot be delivered ends the sign-in (credentialDelivery.deliver).
//
// The role is recorded by the rotation's own write (session.WithSuccessorRole),
// never by a later selection, so no successor is stored without it and no
// cookie is set for one that is not. A store that supersedes the session but
// writes the successor back with another role fails the rotation with
// session.ErrStoreContract, a dependency failure, after the store has written:
// the old record is superseded and an unheld successor is live. No cookie is
// set, and the old identifier keeps working, with the role unchanged, through
// its grace window only; past it, it is reuse, which revokes the sign-in
// unless session.WithUnusedSuccessorRecovery recovers it.
//
// The caller holds the request's role-switch lock (holdRun).
func (src *roleSource) rotateForSwitch(ctx context.Context, role string) (*session.Session, error) {
	src.mu.Lock()
	defer src.mu.Unlock()

	r := src.resolver

	successor, err := (credentialDelivery{cookie: r.cookie, log: r.log}).rotateCookie(ctx, src.ex, r.sessions,
		src.current, privilegeRotationGrace(r.renewal), src.deadline,
		cookieRotationTexts{failed: textRoleNotRotated, ended: textRoleSwitchEnded},
		session.WithSuccessorRole(role))
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

	return successor, nil
}

// holdRun takes the request's role-switch lock (roleSwitchGuard), for a
// switch that rotates a cookie session, and checks under it that the
// request's handler has not returned and the run whose response the cookie is
// re-set on is not over. On success the caller holds the lock and releases it
// once its rotation and cookie write are done; on any error it holds nothing.
//
// The lock is taken before the source's (mu), and held through the switch's
// reload of the user, its rotation and its cookie write, so no handler on the
// exchange can return to the interceptors after it, of any chain, and the run
// cannot end, between the check below and the cookie landing on its
// response: the handler's return (runTerminal) and the run's end
// (chainRun.end) wait for the switch. They take only this lock, and a switch
// made synchronously from the handler completes before the handler returns,
// so neither waits on the other in a cycle. It is taken before anything else
// that waits on a switch in progress, the source's lock included, so a switch
// queued behind another gives up when ctx ends, with ctx's error, having
// stored nothing.
//
// The run is src.run, the run of the chain that resolved the session (runOf
// in the resolution), and the guard is the one that run carries: a chain
// whose cookie session rotates at a role switch gave its exchange the guard
// before that run began (Chain.Assemble). A run without one, which that
// wiring never makes, is refused rather than switched unguarded.
//
// A switch whose ctx is, or derives from, a session delivery's detached copy
// (detachedBoundary) is refused at once, before the lock is taken: the
// delivery runs inside a switch's rotation, under that lock, so waiting for
// it would last until ctx ends, and the request's context ends only after the
// chain, waiting on the outer switch, has returned.
func (src *roleSource) holdRun(ctx context.Context) error {
	if src.ex == nil || src.run == nil || src.run.guard == nil {
		return newConfigError("SwitchActiveRole: %s", textRoleSwitchAfterRun)
	}

	if _, ok := ctx.Value(detachedBoundaryKey{}).(*detachedBoundary); ok {
		return newConfigError("SwitchActiveRole: %s", textRoleSwitchInDelivery)
	}

	g := src.run.guard
	if err := g.acquire(ctx); err != nil {
		return err
	}

	if g.handled || src.run.done.Load() {
		g.release()

		return newConfigError("SwitchActiveRole: %s", textRoleSwitchAfterRun)
	}

	return nil
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
