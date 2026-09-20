package authorize

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

// Requirement decides whether the request carried by ctx may proceed.
//
// It answers from the context alone — the principal an authentication step put
// there, and whatever else the consumer attached — so the same requirement
// guards an operation wherever that operation is reached from, and a guard
// cannot be given a different caller than the rest of the request sees.
//
// nil means allowed. A non-nil error matching ErrAuthenticationRequired means
// the caller has not said who they are and may succeed once they do; anything
// else matching ErrAccessDenied means they may not proceed as who they are. A
// requirement that fails for some third reason — an unreachable store, say —
// returns that error as it came, so it is not read as a decision.
//
// A consumer writes their own by writing a function of this type. Nothing here
// is privileged: the requirements below are the ones scrty found worth naming,
// not the only ones a rule set can hold.
type Requirement func(ctx context.Context) error

// PermitAll allows every request, including an anonymous one.
//
// It exists to be written down. A rule set denies whatever no rule matched, and
// a consumer who wants the remainder open says so with a trailing rule that
// matches everything and requires this — a line that is visible when the rules
// are read, rather than a default nobody chose.
func PermitAll() Requirement {
	return func(context.Context) error { return nil }
}

// DenyAll denies every request, whoever is making it.
//
// It refuses rather than asking for authentication, because no credential
// changes the answer: telling an anonymous caller to log in first would send
// them to do work that cannot help them.
func DenyAll() Requirement {
	return func(context.Context) error {
		return fmt.Errorf("%w: this operation is closed to everyone", ErrAccessDenied)
	}
}

// Authenticated requires that the request carry a principal, whoever it is.
func Authenticated() Requirement {
	return func(ctx context.Context) error {
		if _, err := subjectOf(ctx); err != nil {
			return err
		}

		return nil
	}
}

// HasAnyRole requires that the caller's active role be one of roles.
//
// Only the active role counts, which is the same rule the privilege authorizer
// follows: a caller who holds a powerful role but is acting under a lesser one
// must not pass a guard that their privileges would fail, or the two halves of
// the library would disagree about the same request. A principal with no active
// role therefore meets no role requirement — a closed failure a consumer sees
// at once, rather than an open one they find later.
//
// Role names are compared exactly. They are the consumer's own identifiers, and
// scrty does not fold their case anywhere else either; matching loosely here
// would let a role nobody granted satisfy a guard.
//
// Naming no roles denies, because a caller cannot hold one of none.
func HasAnyRole(roles ...string) Requirement {
	return func(ctx context.Context) error {
		subject, err := subjectOf(ctx)
		if err != nil {
			return err
		}

		if subject.ActiveRole != nil && slices.Contains(roles, subject.ActiveRole.Name) {
			return nil
		}

		return fmt.Errorf("%w: the caller's active role is not one of %v", ErrAccessDenied, roles)
	}
}

// HasAnyScope requires that the caller hold at least one of scopes.
//
// Scopes are matched exactly, and a caller holding none meets no scope
// requirement. Naming no scopes denies: a requirement listing nothing is a
// requirement someone meant to fill in, and allowing it would turn that typo
// into an open operation.
func HasAnyScope(scopes ...string) Requirement {
	return func(ctx context.Context) error {
		subject, err := subjectOf(ctx)
		if err != nil {
			return err
		}

		for _, scope := range scopes {
			if slices.Contains(subject.Scopes, scope) {
				return nil
			}
		}

		return fmt.Errorf("%w: the caller holds none of the scopes %v", ErrAccessDenied, scopes)
	}
}

// HasAllScopes requires that the caller hold every one of scopes.
//
// Naming no scopes denies, for the same reason HasAnyScope does — and here the
// reading that "every one of nothing is held" is exactly the one that would
// open the operation, so it is refused rather than taken.
func HasAllScopes(scopes ...string) Requirement {
	return func(ctx context.Context) error {
		subject, err := subjectOf(ctx)
		if err != nil {
			return err
		}

		if len(scopes) == 0 {
			return fmt.Errorf("%w: a requirement for all of no scopes names nothing to check",
				ErrAccessDenied)
		}

		for _, scope := range scopes {
			if !slices.Contains(subject.Scopes, scope) {
				return fmt.Errorf("%w: the caller does not hold scope %q", ErrAccessDenied, scope)
			}
		}

		return nil
	}
}

// AnyOf requires that at least one of requirements be met.
//
// Members are evaluated in order and the first one that allows decides, so a
// cheap check placed first spares an expensive one behind it.
//
// The refusal it returns is chosen rather than joined. ErrAuthenticationRequired
// comes back only when every member asked for authentication, because that is
// the only case where authenticating can turn this refusal into an allow;
// where one member would have refused the caller whoever they are, the answer
// is a denial, and an error matching both sentinels would let a caller be sent
// to log in for nothing.
//
// Naming no members denies: none of nothing is satisfiable. An absent member is
// treated as one that cannot be satisfied rather than skipped, so a set that
// was meant to hold a check and holds a nil does not quietly become one check
// shorter.
func AnyOf(requirements ...Requirement) Requirement {
	return func(ctx context.Context) error {
		allAnonymous := len(requirements) > 0

		for _, required := range requirements {
			if required == nil {
				allAnonymous = false

				continue
			}

			err := required(ctx)
			if err == nil {
				return nil
			}

			if !errors.Is(err, ErrAuthenticationRequired) {
				allAnonymous = false
			}
		}

		if allAnonymous {
			return fmt.Errorf("%w: every alternative needs a caller to be identified first",
				ErrAuthenticationRequired)
		}

		return fmt.Errorf("%w: the caller meets none of the %d alternatives",
			ErrAccessDenied, len(requirements))
	}
}

// HasPrivilege requires the named privileges on group/resource, as judged by
// the authorizer the request context carries.
//
// It delegates rather than deciding, so a guard written at an operation and a
// check made deep in a service reach the same answer from the same role data,
// and a consumer who replaced the privilege authorizer sees their replacement
// honoured here too. The authorizer's answer is returned unchanged, including
// an outage inside it, which therefore does not become a denial.
//
// Every named privilege must be granted. With one name — the usual case — the
// two matching modes agree; with several, demanding all of them is the reading
// that cannot hand out more than the call site asks for. A consumer who wants
// any-of writes AnyOf over one HasPrivilege per name, or supplies
// PrivilegeAttributes with MatchAnyOf to an authorizer directly.
//
// It denies when the context carries no authorizer, including one that is
// absent. A guard that allowed because nothing was there to refuse would turn a
// missing middleware into an open operation — and the missing middleware is
// exactly what a wiring mistake removes.
func HasPrivilege(group, resource string, required ...string) Requirement {
	return func(ctx context.Context) error {
		authorizer, ok := AuthorizerFromContext(ctx)
		if !ok {
			return fmt.Errorf("%w: the request carries no authorizer to judge %s/%s",
				ErrAccessDenied, group, resource)
		}

		return authorizer.Authorize(ctx, PrivilegeAttributes{
			Group:    group,
			Resource: resource,
			Required: required,
			Mode:     MatchAllOf,
		})
	}
}

// subjectOf returns the principal ctx carries, or the error that asks the
// caller to identify themselves.
//
// Every requirement that needs a caller goes through it, so they all tell an
// anonymous request apart from a refused one in the same way — the distinction
// a consumer turns into 401 rather than 403.
func subjectOf(ctx context.Context) (*identity.Principal, error) {
	subject, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: the request carries no principal", ErrAuthenticationRequired)
	}

	return subject, nil
}
