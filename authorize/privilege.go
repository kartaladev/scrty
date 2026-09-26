package authorize

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// PrivilegeAuthorizer judges PrivilegeAttributes against the privileges the
// subject's active role grants.
//
// It reads the subject from the request context and nothing else, so a request
// that arrived anonymously is denied rather than dereferenced. Only the active
// role counts: a user holding a role they have not activated is, for this
// authorizer, a user without it, which is what makes switching roles a real
// change in what the user may do rather than a label on a session.
//
// It declines every other kind of attributes, so it can sit in a Manager beside
// authorizers that judge them.
//
//go:generate mockgen -destination=roleloader_mock_test.go -package=authorize_test -typed github.com/kartaladev/scrty/identity RoleLoader
type PrivilegeAuthorizer struct {
	roles identity.RoleLoader
	same  func(a, b string) bool
}

var _ Authorizer = (*PrivilegeAuthorizer)(nil)

// PrivilegeOption customises a PrivilegeAuthorizer at construction.
type PrivilegeOption func(*PrivilegeAuthorizer)

// WithPrivilegeNameComparer replaces how group, resource and privilege names
// are compared.
//
// The default compares them ignoring surrounding whitespace and letter case,
// which suits role data entered by hand. A consumer whose data is generated and
// canonical may want exact comparison, and one whose data is normalised some
// other way — a locale-aware fold, a prefix convention — supplies that instead.
// Replacing the comparison changes nothing else: the default remains what an
// authorizer built without this option uses.
//
// A nil comparer is refused at construction rather than quietly restoring the
// default. The two readings of a nil argument — "I want no comparison" and "the
// value I computed was empty" — call for opposite behaviour, and only the
// consumer can tell them apart.
func WithPrivilegeNameComparer(same func(a, b string) bool) PrivilegeOption {
	return func(a *PrivilegeAuthorizer) { a.same = same }
}

// NewPrivilegeAuthorizer returns an authorizer that resolves the active role's
// privileges through roles.
//
// There is no default role loader. Substituting an empty one would make every
// privilege check deny for a reason that looks like a decision about the
// caller, and substituting a permissive one is unthinkable, so a missing loader
// is a wiring mistake reported here rather than a mystery at the first request.
func NewPrivilegeAuthorizer(roles identity.RoleLoader, opts ...PrivilegeOption) (*PrivilegeAuthorizer, error) {
	if nilcheck.IsNil(roles) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("role loader"))
	}

	a := &PrivilegeAuthorizer{roles: roles, same: equalNamesFolded}

	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}

	if a.same == nil {
		return nil, fmt.Errorf("%w: the privilege name comparer must not be nil", ErrConfig)
	}

	return a, nil
}

// equalNamesFolded is the default name comparison: surrounding whitespace is
// ignored and letters are compared without case.
//
// Role data is frequently typed by a person into an administration screen, and
// "Write" or " write" there must not silently become a different privilege from
// the one an attempt names — a mismatch that reads, to whoever is refused, as
// the system having lost their permissions.
func equalNamesFolded(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// Authorize reports whether the subject's active role grants what attrs
// require.
//
// Attributes of another kind are declined so the manager can offer them
// elsewhere; attributes of this kind that cannot be used are refused, and the
// chain ends. Everything that follows — a missing subject, a missing role, a
// role the loader knows nothing about — is a denial, because each of them is a
// caller who has not been shown to hold the privilege.
func (a *PrivilegeAuthorizer) Authorize(ctx context.Context, attrs Attributes) error {
	required, err := privilegeAttributes(attrs)
	if err != nil {
		return err
	}

	subject, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return fmt.Errorf("%w: the request carries no subject", ErrAccessDenied)
	}

	role := subject.ActiveRole
	if role == nil {
		return fmt.Errorf("%w: the subject has no active role", ErrAccessDenied)
	}

	// A super role is the consumer's own statement that this role is not
	// subject to privilege checks, so the loader is never asked: a role that
	// bypasses matching must not be able to be denied by an outage in the store
	// whose answer is not going to be read.
	if role.SuperRole {
		return nil
	}

	// A blank role name is not a role. Asking the loader for it would either
	// fail for a reason that has nothing to do with this caller or, in a store
	// that treats the empty name as a row, hand back privileges nobody granted.
	if strings.TrimSpace(role.Name) == "" {
		return fmt.Errorf("%w: the subject's active role has no name", ErrAccessDenied)
	}

	granted, err := a.roles.LoadPrivileges(ctx, role.Name)
	if err != nil {
		if errors.Is(err, identity.ErrPrivilegesNotFound) {
			return fmt.Errorf("%w: role %q grants no privileges", ErrAccessDenied, role.Name)
		}

		// Anything else is an outage: the check did not happen. It is wrapped
		// rather than turned into a denial, because a caller that logs denials
		// as refused attempts would otherwise record a store failure as a
		// caller trying something they may not do. The loader's own error is
		// never rendered into the text — it can quote whatever the loader's
		// backing store holds — but stays reachable through errors.Is and
		// errors.As, so a consumer can still match it deliberately.
		return diag.Wrap(err, "authorize: the role's privileges could not be loaded")
	}

	if a.satisfied(a.entryFor(granted, required), required) {
		return nil
	}

	return fmt.Errorf("%w: role %q does not grant %s of %v on %s/%s",
		ErrAccessDenied, role.Name, required.Mode, required.Required, required.Group, required.Resource)
}

// privilegeAttributes narrows attrs to the kind this authorizer judges and
// reports whether their content can be used.
//
// Both the value and the pointer form are accepted, because a consumer who
// stores attributes in a variable naturally passes the address of one, and a
// declination there would send well-formed attributes to an authorizer that
// never meant to judge them. A nil pointer is a refusal rather than a
// declination for the same reason: it is this kind of attributes, built wrongly.
//
// Blankness is judged by trimming whitespace, not by the configured comparer:
// this is about attributes being well-formed, which is the same question
// whatever a consumer's names look like, and a comparer is free to consider two
// non-empty names equal but cannot make an empty one meaningful.
func privilegeAttributes(attrs Attributes) (PrivilegeAttributes, error) {
	var required PrivilegeAttributes

	switch v := attrs.(type) {
	case PrivilegeAttributes:
		required = v
	case *PrivilegeAttributes:
		if v == nil {
			return required, fmt.Errorf("%w: the privilege attributes are absent", ErrInvalidAttributes)
		}

		required = *v
	default:
		return required, fmt.Errorf("%w: %T is not privilege attributes", ErrUnsupportedAttributes, attrs)
	}

	if strings.TrimSpace(required.Group) == "" {
		return required, fmt.Errorf("%w: the privilege attributes name no group", ErrInvalidAttributes)
	}

	if strings.TrimSpace(required.Resource) == "" {
		return required, fmt.Errorf("%w: the privilege attributes name no resource", ErrInvalidAttributes)
	}

	// Requiring nothing is refused rather than read as "nothing is required": a
	// check that requires nothing allows everyone while looking, at the call
	// site, exactly like a check.
	if len(required.Required) == 0 {
		return required, fmt.Errorf("%w: the privilege attributes require no privileges", ErrInvalidAttributes)
	}

	for i, name := range required.Required {
		if strings.TrimSpace(name) == "" {
			return required, fmt.Errorf("%w: required privilege %d has no name", ErrInvalidAttributes, i)
		}
	}

	// An undefined mode is refused rather than treated as one of the two, since
	// guessing would decide in the consumer's place how many privileges an
	// attempt needs.
	if required.Mode != MatchAllOf && required.Mode != MatchAnyOf {
		return required, fmt.Errorf("%w: match mode %d is not defined", ErrInvalidAttributes, required.Mode)
	}

	return required, nil
}

// entryFor returns the role's privileges on the resource the attributes name,
// or nil when the role holds none there.
//
// The first matching entry decides. A role loader describes a role's privileges
// on one resource with one entry, so a second entry for the same resource is
// the consumer's data contradicting itself; taking the first keeps the answer
// deterministic rather than making it depend on which contradiction is read
// last. Absent entries are skipped, so a loader with a hole in its slice denies
// rather than panics.
func (a *PrivilegeAuthorizer) entryFor(
	granted []*identity.ResourcePrivileges,
	required PrivilegeAttributes,
) *identity.ResourcePrivileges {
	for _, entry := range granted {
		if entry == nil {
			continue
		}

		if a.same(entry.Group, required.Group) && a.same(entry.Resource, required.Resource) {
			return entry
		}
	}

	return nil
}

// satisfied reports whether entry grants what required asks for.
//
// Only granted privileges count. A privilege the role carries as refused is
// deliberately not the same as one it never mentions — the identity model keeps
// them apart — but neither of them permits anything, so both fail here.
func (a *PrivilegeAuthorizer) satisfied(entry *identity.ResourcePrivileges, required PrivilegeAttributes) bool {
	if entry == nil {
		return false
	}

	for _, name := range required.Required {
		held := a.grants(entry, name)

		if required.Mode == MatchAnyOf && held {
			return true
		}

		if required.Mode == MatchAllOf && !held {
			return false
		}
	}

	// Every name was checked: under all-of none failed, and under any-of none
	// succeeded.
	return required.Mode == MatchAllOf
}

// grants reports whether entry holds name as granted.
func (a *PrivilegeAuthorizer) grants(entry *identity.ResourcePrivileges, name string) bool {
	for _, held := range entry.Privileges {
		if held.Granted && a.same(held.Name, name) {
			return true
		}
	}

	return false
}
