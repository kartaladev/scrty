package httpsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	textRoleNotRecorded   = "httpsec: the selected role could not be recorded"
	textRoleSwitchEnded   = "httpsec: the request ended while its role was switched"
	textRoleNotResolvedBy = "the request's session was not resolved by one of this chain's " +
		"session-bound authenticators (EnableBearerToken, EnableSessionBearer), so its role " +
		"cannot be switched"
)

// roleSourceKey is this package's own context key for the resolution that
// authenticated the request, which only the resolution core sets.
type roleSourceKey struct{}

// roleSource is the resolution that authenticated a request on a chain with
// switching on: the chain, the resolution core that resolved the session,
// and the session it published. Chain.SwitchActiveRole reloads the user and
// records the selection through the same loader and manager.
type roleSource struct {
	chain    *Chain
	resolver *sessionResolver
	session  *session.Session
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
// session-bound authenticators (EnableBearerToken or EnableSessionBearer), as a
// handler behind the chain receives it. The user is reloaded, and the switch
// succeeds only when they hold a grant named role that is in force at the
// chain's clock, as for the grants a request is built with. Only the session's
// selected role is written, through the session manager that resolved it. The
// empty role clears the selection, so the primary grant applies again. The
// request in progress keeps the principal it was authenticated with; every
// later request on the session applies the selection while the grant stays in
// force, and the primary grant otherwise. A successful switch is reported as
// event.ActiveRoleSwitched, with the user as both User and Actor, the role now
// active (the primary grant's name, or empty, for a cleared selection) as
// Target, and "active_role" in Changed.
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
//     when an interceptor published another after it;
//   - ErrRoleNotHeld when the user holds no grant named role in force now, and
//     for a name over 256 bytes, not valid UTF-8 or holding a NUL byte, which
//     no store can hold; the session is left unchanged;
//   - a failure matching ctx's error when the request ended first;
//   - otherwise a dependency failure behind fixed text, matching its cause
//     through errors.Is.
//
// A context kept past its request, such as one from context.WithoutCancel,
// can still switch afterwards: nothing in it ends with the request. The user
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
	if now, has := SessionFromContext(ctx); !has || now == nil ||
		now.ID != src.session.ID || now.UserID != src.session.UserID {
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

	if err := r.sessions.SelectRole(ctx, s.ID, role); err != nil {
		return classifySelect(ctx, err)
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
