package authorize

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/porterr"
)

// ErrInspectionUnsupported reports that the authorizer the request context
// carries cannot say which privileges are held: neither it nor, for a FirstOf,
// the member that would judge privilege attributes implements
// PrivilegeInspector.
//
// It is a wiring answer, not a denial, and it does not match ErrAccessDenied.
// HeldPrivileges does not fall back to calling Authorize once per name, which
// would load once per name outside the memo and could not report a scope.
var ErrInspectionUnsupported = errors.New("authorize: the authorizer cannot report held privileges")

// Holding is the answer for one privilege name in a bulk check.
type Holding struct {
	// Privilege is the name as the caller asked for it.
	Privilege string

	// Held reports whether the active role grants the privilege with a scope
	// this package defines.
	Held bool

	// Scope is the strongest scope held, identity.ScopeAll before
	// identity.ScopeOwn. It is empty when Held is false.
	Scope identity.Scope
}

// Holdings are the answers of one bulk check, one per name asked for, in the
// order asked. The slice is the caller's own: changing it changes nothing any
// other check sees.
type Holdings []Holding

// Lookup returns the holding for name, compared exactly as the caller spelled
// it in the bulk check, and reports whether that name was asked for. When a
// name was asked for twice, the first holding is returned.
func (h Holdings) Lookup(name string) (Holding, bool) {
	for _, holding := range h {
		if holding.Privilege == name {
			return holding, true
		}
	}

	return Holding{}, false
}

// PrivilegeInspector reports, for a list of privilege names on one resource,
// which the caller in ctx holds and with what scope.
//
// PrivilegeAuthorizer and FirstOf implement it. A consumer's own authorizer
// implements it to take part in HeldPrivileges: it answers for the names, or
// returns an error matching ErrUnsupportedAttributes to decline, so that a
// FirstOf asks its next member. An implementation reports a caller with no
// subject or no active role as holding nothing, with no error, and returns an
// error only when the answer could not be reached.
//
// An answer holds one Holding per name asked, in the order asked, each
// Privilege the name exactly as it was passed. A held name carries
// identity.ScopeAll or identity.ScopeOwn; a name not held carries no scope.
// HeldPrivileges and FirstOf refuse an answer that breaks this with an error
// matching ErrConfig, and report nothing held: a broken inspector is a wiring
// fault, never a reason to grant or to deny. An implementation may change the
// names slice it is given; the caller's own is not affected.
type PrivilegeInspector interface {
	InspectPrivileges(ctx context.Context, group, resource string, names []string) (Holdings, error)
}

var (
	_ PrivilegeInspector = (*PrivilegeAuthorizer)(nil)
	_ PrivilegeInspector = (*FirstOf)(nil)
)

// HeldPrivileges reports which of names the caller holds on group/resource,
// and the strongest scope of each, as judged by the authorizer the request
// context carries. It is for the "allowed actions" a response lists beside a
// record, where one check per action would load the role once per action.
//
// The active role's privileges are loaded once, through the memo ctx carries
// when it carries one (WithRequestMemo). A super role holds every name with
// identity.ScopeAll. A caller with no subject or no active role holds nothing,
// and that is not an error: an empty list of allowed actions is the answer.
//
// It fails with ErrInvalidAttributes for an empty list, a blank name, group or
// resource; with an error matching ErrAccessDenied and ErrNotGranted when ctx
// carries no authorizer; with ErrInspectionUnsupported when the authorizer
// cannot report held privileges; with an error matching ErrConfig when a
// consumer's PrivilegeInspector answers outside its contract; and with the
// loader's error, wrapped, when the privileges could not be loaded. On an
// error no name is reported held.
//
// The authorizer, reached directly or through a FirstOf, decides; a consumer
// changes the answer by putting another authorizer in the context, one that
// implements PrivilegeInspector.
func HeldPrivileges(ctx context.Context, group, resource string, names ...string) (Holdings, error) {
	if err := inspectionAttributes(group, resource, names); err != nil {
		return nil, err
	}

	authorizer, ok := AuthorizerFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: %w: the request carries no authorizer to judge %s/%s",
			ErrAccessDenied, ErrNotGranted, group, resource)
	}

	inspector, ok := authorizer.(PrivilegeInspector)
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrInspectionUnsupported, authorizer)
	}

	holdings, err := inspector.InspectPrivileges(ctx, group, resource, slices.Clone(names))
	if err != nil {
		return nil, porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)
	}

	if err := checkAnswer(inspector, names, holdings); err != nil {
		return nil, err
	}

	// The caller's holdings are its own, even when a consumer's inspector
	// keeps the slice it answered with.
	return slices.Clone(holdings), nil
}

// checkAnswer refuses an inspector's answer that breaks the PrivilegeInspector
// contract for names. The error names the inspector's type and the position of
// the fault, never a privilege name.
func checkAnswer(inspector PrivilegeInspector, names []string, holdings Holdings) error {
	if len(holdings) != len(names) {
		return fmt.Errorf("%w: privilege inspector %T answered %d holdings for %d names",
			ErrConfig, inspector, len(holdings), len(names))
	}

	for i, holding := range holdings {
		switch {
		case holding.Privilege != names[i]:
			return fmt.Errorf("%w: privilege inspector %T answered holding %d for another name than asked",
				ErrConfig, inspector, i)
		case holding.Held && holding.Scope != identity.ScopeAll && holding.Scope != identity.ScopeOwn:
			return fmt.Errorf("%w: privilege inspector %T holds holding %d with an undefined scope",
				ErrConfig, inspector, i)
		case !holding.Held && holding.Scope != "":
			return fmt.Errorf("%w: privilege inspector %T gives holding %d a scope without holding it",
				ErrConfig, inspector, i)
		}
	}

	return nil
}

// inspectionAttributes refuses a bulk check that cannot be answered. It judges
// blankness by trimming, as privilegeAttributes does.
func inspectionAttributes(group, resource string, names []string) error {
	if strings.TrimSpace(group) == "" {
		return fmt.Errorf("%w: the bulk check names no group", ErrInvalidAttributes)
	}

	if strings.TrimSpace(resource) == "" {
		return fmt.Errorf("%w: the bulk check names no resource", ErrInvalidAttributes)
	}

	// An empty list is refused rather than answered with an empty list: a
	// caller who asks about nothing has built the question wrongly.
	if len(names) == 0 {
		return fmt.Errorf("%w: the bulk check names no privileges", ErrInvalidAttributes)
	}

	for i, name := range names {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: privilege %d of the bulk check has no name", ErrInvalidAttributes, i)
		}
	}

	return nil
}

// InspectPrivileges reports which of names the active role grants on
// group/resource, with the strongest defined scope of each, reading names with
// the authorizer's name comparer exactly as Authorize does.
//
// It loads the role once, through the memo ctx carries when it carries one.
// No subject, no active role, an active role with a blank name and a role the
// loader does not know all hold nothing, without error. A super role with a
// name holds every name with identity.ScopeAll, without a load. A loader
// failure is returned wrapped, as an outage, with no holdings.
func (a *PrivilegeAuthorizer) InspectPrivileges(
	ctx context.Context,
	group, resource string,
	names []string,
) (Holdings, error) {
	if err := inspectionAttributes(group, resource, names); err != nil {
		return nil, err
	}

	holdings := make(Holdings, len(names))
	for i, name := range names {
		holdings[i] = Holding{Privilege: name}
	}

	subject, ok := identity.PrincipalFromContext(ctx)
	if !ok || subject.ActiveRole == nil || strings.TrimSpace(subject.ActiveRole.Name) == "" {
		return holdings, nil
	}

	role := subject.ActiveRole
	if role.SuperRole {
		for i := range holdings {
			holdings[i].Held, holdings[i].Scope = true, identity.ScopeAll
		}

		return holdings, nil
	}

	granted, err := a.loadPrivileges(ctx, role.Name)
	if err != nil {
		if errors.Is(err, identity.ErrPrivilegesNotFound) {
			return holdings, nil
		}

		return nil, diag.Wrap(err, "authorize: the role's privileges could not be loaded")
	}

	entry := a.entryFor(granted, PrivilegeAttributes{Group: group, Resource: resource})
	accept := anyAccept()

	for i, name := range names {
		holdings[i].Scope, holdings[i].Held = strongestHeld(entry, name, accept, a.same)
	}

	return holdings, nil
}

// InspectPrivileges asks the member that would judge privilege attributes
// which of names the caller holds, and returns its answer unchanged once it
// is checked against the PrivilegeInspector contract, as a copy the caller owns; an answer that breaks it
// fails with an error matching ErrConfig. Each member is asked with its own
// copy of names, so a member that edits the slice and declines changes nothing
// the next is asked.
//
// Members are walked in order. A member implementing PrivilegeInspector
// answers, unless it declines with ErrUnsupportedAttributes, in which case the
// walk goes on. An OwnershipAuthorizer is passed over, since it declines every
// privilege attribute. Any other member that does not implement
// PrivilegeInspector stops the walk with ErrInspectionUnsupported: it may judge
// privilege attributes itself, and answering from a later member could then
// disagree with what Authorize decides. Such a consumer's authorizer takes
// part by implementing PrivilegeInspector, if only to decline.
func (m *FirstOf) InspectPrivileges(
	ctx context.Context,
	group, resource string,
	names []string,
) (Holdings, error) {
	for _, a := range m.authorizers {
		switch member := a.(type) {
		case PrivilegeInspector:
			holdings, err := member.InspectPrivileges(ctx, group, resource, slices.Clone(names))
			err = porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)

			if errors.Is(err, ErrUnsupportedAttributes) {
				continue
			}

			if err != nil {
				return nil, err
			}

			if err := checkAnswer(member, names, holdings); err != nil {
				return nil, err
			}

			// The caller's holdings are its own, even when the member keeps
			// the slice it answered with.
			return slices.Clone(holdings), nil
		case *OwnershipAuthorizer:
			continue
		default:
			return nil, fmt.Errorf("%w: %T may judge privileges and cannot report them", ErrInspectionUnsupported, a)
		}
	}

	return nil, fmt.Errorf("%w: no member of the manager reports held privileges", ErrInspectionUnsupported)
}
