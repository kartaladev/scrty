package authorize

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/kartaladev/scrty/identity"
)

// plainAccept is what attributes that name no scope requirement accept: only a
// grant that reaches every record. An own-only grant behind a plain check would
// otherwise let a caller whose handler forgot the ownership check read every
// record of the resource.
var plainAccept = []identity.Scope{identity.ScopeAll}

// anyAccept returns what the any-scope and record checks accept: every scope
// this package defines, strongest first. It is a fresh slice on every call,
// because it travels inside attributes an authorizer of the consumer's may
// write to, and a shared one would carry that write into every later check.
func anyAccept() []identity.Scope {
	return []identity.Scope{identity.ScopeAll, identity.ScopeOwn}
}

// scopeRank orders the defined scopes from the strongest, which reaches the
// most records, to the weakest. A scope it does not list is undefined and
// covers nothing.
func scopeRank(scope identity.Scope) (int, bool) {
	switch scope {
	case identity.ScopeAll:
		return 0, true
	case identity.ScopeOwn:
		return 1, true
	default:
		return 0, false
	}
}

// stronger reports whether a reaches more records than b. Both must be defined.
func stronger(a, b identity.Scope) bool {
	ra, _ := scopeRank(a)
	rb, _ := scopeRank(b)

	return ra < rb
}

// strongestHeld returns the strongest scope with which entry grants name,
// among the scopes accept lists, and reports whether there is one.
//
// A privilege refused, a scope accept does not list and a scope this package
// does not define are all never held. Stored scopes are read through
// EffectiveScope, so a loader that records no scope grants with ScopeAll, and
// are compared exactly: a scope is a value this package defines, not a name a
// person types, so "ALL" is undefined rather than a spelling of "all". The
// order is all before own. A role whose data lists one privilege twice, with
// two scopes, holds it with the stronger one.
func strongestHeld(
	entry *identity.ResourcePrivileges,
	name string,
	accept []identity.Scope,
	same func(a, b string) bool,
) (identity.Scope, bool) {
	if entry == nil {
		return "", false
	}

	var (
		best  identity.Scope
		found bool
	)

	for _, held := range entry.Privileges {
		if !held.Granted || !same(held.Name, name) {
			continue
		}

		scope := held.EffectiveScope()
		if _, defined := scopeRank(scope); !defined || !slices.Contains(accept, scope) {
			continue
		}

		if !found || stronger(scope, best) {
			best, found = scope, true
		}
	}

	return best, found
}

// grantedWithAnyScope reports whether entry grants name with any scope at all,
// defined or not. It tells a privilege granted with the wrong scope apart from
// one that is not granted, which only changes the reason a denial gives.
func grantedWithAnyScope(entry *identity.ResourcePrivileges, name string, same func(a, b string) bool) bool {
	if entry == nil {
		return false
	}

	for _, held := range entry.Privileges {
		if held.Granted && same(held.Name, name) {
			return true
		}
	}

	return false
}

// scopeReport carries the scope a privilege check allowed with, from the
// privilege authorizer back to the check that asked. It travels inside the
// attributes rather than in the context, so a nested check made with the same
// context, for another resource, cannot overwrite the answer.
type scopeReport struct {
	mu    sync.Mutex
	scope identity.Scope
	set   bool
}

func (r *scopeReport) record(scope identity.Scope) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.scope, r.set = scope, true
}

func (r *scopeReport) read() (identity.Scope, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.scope, r.set
}

// HasPrivilegeAnyScope requires the named privileges on group/resource with
// any scope this package defines — all or own — as judged by the authorizer
// the request context carries.
//
// It is for a route whose handler narrows what it returns to the caller's own
// records when that is all they hold, such as a list endpoint; the handler
// learns which scope is held from CheckAnyScope. It is never the default
// reading of a privilege: HasPrivilege accepts only all, so a route guard
// cannot let an own-only caller see every record by accident.
//
// Every named privilege must be granted, as with HasPrivilege. A scope this
// package does not define covers nothing. A context with no authorizer denies.
func HasPrivilegeAnyScope(group, resource string, required ...string) Requirement {
	required = slices.Clone(required)

	return func(ctx context.Context) error {
		_, err := checkScope(ctx, group, resource, required, false)

		return err
	}
}

// CheckAnyScope reports the strongest scope with which the caller holds
// privilege on group/resource, all before own, as judged by the authorizer the
// request context carries.
//
// It returns ScopeAll when the caller may act on every record and ScopeOwn
// when only on their own, so a list endpoint filters to own records exactly
// when it must. A caller who holds the privilege with no defined scope is
// denied, with the reason the authorizer gives.
//
// The scope comes from the privilege authorizer of this package, reached
// directly or through a FirstOf. An authorizer that allows without reporting a
// scope — a consumer's own, which knows nothing of scopes — gets an error
// matching ErrConfig rather than a guess: guessing all would show every record
// to an own-only caller, and guessing own would hide records from everyone
// else.
func CheckAnyScope(ctx context.Context, group, resource, privilege string) (identity.Scope, error) {
	return checkScope(ctx, group, resource, []string{privilege}, true)
}

// HasPrivilegeFor requires the named privileges on one record of
// group/resource: granted with all, or granted with own and owned by the
// caller as owned reports.
//
// The privilege is judged by the authorizer the request context carries,
// accepting all and own. With all, the record's owner does not matter and
// owned's functions are not called. With own, they are, through this package's
// OwnershipAuthorizer: a record the caller does not own is denied with
// ErrNotOwner, and a failure of either function is returned wrapped, as an
// outage and not as a denial.
//
// owned is validated on every check, whatever scope is held, so an ownership
// check missing a function fails for an all-scope caller too, rather than only
// on the first own-scope caller. Its Group and Resource default to group and
// resource when left blank, and are refused as ErrInvalidAttributes when they
// name a different resource. The consumer's override is owned itself: the two
// functions decide what owning a record means.
func HasPrivilegeFor(group, resource string, owned OwnershipAttributes, required ...string) Requirement {
	required = slices.Clone(required)

	return func(ctx context.Context) error {
		record, err := recordOwnership(group, resource, owned)
		if err != nil {
			return err
		}

		scope, err := checkScope(ctx, group, resource, required, true)
		if err != nil {
			return err
		}

		if scope == identity.ScopeAll {
			return nil
		}

		return NewOwnershipAuthorizer().Authorize(ctx, record)
	}
}

// recordOwnership completes and validates the ownership attributes of a record
// check, before any privilege is loaded. It compares the group and resource
// names with the package's default comparison, not the comparer a consumer gave
// the privilege authorizer, because the requirement does not know which
// authorizer the request carries.
func recordOwnership(group, resource string, owned OwnershipAttributes) (OwnershipAttributes, error) {
	if isBlank(owned.Group) {
		owned.Group = group
	} else if !equalNamesFolded(owned.Group, group) {
		return owned, fmt.Errorf("%w: the ownership attributes name another group than the privilege",
			ErrInvalidAttributes)
	}

	if isBlank(owned.Resource) {
		owned.Resource = resource
	} else if !equalNamesFolded(owned.Resource, resource) {
		return owned, fmt.Errorf("%w: the ownership attributes name another resource than the privilege",
			ErrInvalidAttributes)
	}

	return ownershipAttributes(owned)
}

// checkScope asks the context's authorizer whether the caller holds required
// on group/resource with all or own, and returns the scope it allowed with.
// needScope says whether the caller reads that scope: a guard that only needs
// the yes or no does not fail when the authorizer reports none.
func checkScope(
	ctx context.Context,
	group, resource string,
	required []string,
	needScope bool,
) (identity.Scope, error) {
	authorizer, ok := AuthorizerFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("%w: %w: the request carries no authorizer to judge %s/%s",
			ErrAccessDenied, ErrNotGranted, group, resource)
	}

	report := &scopeReport{}

	err := authorizer.Authorize(ctx, PrivilegeAttributes{
		Group:    group,
		Resource: resource,
		Required: slices.Clone(required),
		Mode:     MatchAllOf,
		Accept:   anyAccept(),
		report:   report,
	})
	if err != nil {
		return "", err
	}

	scope, reported := report.read()
	if !reported {
		if !needScope {
			return "", nil
		}

		return "", fmt.Errorf("%w: the authorizer allowed %s/%s without reporting the scope held",
			ErrConfig, group, resource)
	}

	return scope, nil
}

// isBlank reports whether name is empty once surrounding whitespace is
// trimmed, the same test the attribute validation of this package applies.
func isBlank(name string) bool {
	return strings.TrimSpace(name) == ""
}
