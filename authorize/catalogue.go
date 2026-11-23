package authorize

import (
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
)

// CataloguePrivilege declares one privilege a resource has, and the scopes it
// may be granted with.
type CataloguePrivilege struct {
	// Name is the privilege name grants and checks use. It must not be blank,
	// and must not repeat another privilege of the same resource under the
	// default name comparison.
	Name string

	// DisplayName is the label an administration screen shows. It may be blank.
	DisplayName string

	// Scopes lists the scopes the privilege may be granted with. Empty, the
	// default, allows identity.ScopeAll and identity.ScopeOwn. A privilege that
	// makes no sense per record, such as create, restricts itself to
	// identity.ScopeAll. Only the scopes identity defines may be listed, each
	// once.
	Scopes []identity.Scope
}

// CatalogueResource declares one resource an application protects, and its
// privileges.
type CatalogueResource struct {
	// Group is the resource group, as grants and checks spell it. It must not
	// be blank.
	Group string

	// Name is the resource within the group. It must not be blank, and the
	// group and name together must not repeat another resource under the
	// default name comparison.
	Name string

	// DisplayName is the label an administration screen shows. It may be blank.
	DisplayName string

	// Privileges lists the resource's privileges, in the order a grant matrix
	// shows them. It must name at least one.
	Privileges []CataloguePrivilege
}

// Catalogue is the set of resources, privileges and scopes an application may
// grant, declared in code at start-up.
//
// It is what grant administration checks a grant against before writing it,
// so a typo becomes a refusal rather than a stored privilege nobody checks,
// and what an application draws a grant matrix from. The runtime privilege
// authorizer does not read it: a privilege the catalogue no longer lists still
// loads and is still judged.
//
// It does not change after construction and is safe for concurrent reads.
// Names are compared as the privilege authorizer compares them by default:
// ignoring surrounding ASCII whitespace and ASCII letter case only. The
// catalogue has no option to replace that comparison; it is the consumer's
// declaration, and the consumer controls it by what it declares.
type Catalogue struct {
	resources []CatalogueResource
}

// NewCatalogue returns a catalogue of resources, in the order given.
//
// It copies its input, so changing the slices it was given afterwards changes
// nothing. A privilege declared without scopes is recorded as allowing
// identity.ScopeAll and identity.ScopeOwn.
//
// It refuses, with an error matching ErrConfig: no resources, since a
// catalogue that allows no grant can only be a declaration that failed to load;
// a blank group, resource or privilege name; a resource with no privileges; a
// resource, or a privilege within one resource, declared twice under the
// default name comparison; and a scope that identity does not define, or one
// listed twice.
func NewCatalogue(resources ...CatalogueResource) (*Catalogue, error) {
	if len(resources) == 0 {
		return nil, fmt.Errorf("%w: a catalogue with no resources allows no grant", ErrConfig)
	}

	declared := make([]CatalogueResource, 0, len(resources))

	for i, resource := range resources {
		if isBlank(resource.Group) || isBlank(resource.Name) {
			return nil, fmt.Errorf("%w: catalogue resource %d has a blank group or name", ErrConfig, i)
		}

		for _, earlier := range declared {
			if equalNamesFolded(earlier.Group, resource.Group) && equalNamesFolded(earlier.Name, resource.Name) {
				return nil, fmt.Errorf("%w: catalogue resource %d repeats %s/%s",
					ErrConfig, i, earlier.Group, earlier.Name)
			}
		}

		privileges, err := cataloguePrivileges(resource)
		if err != nil {
			return nil, fmt.Errorf("%w: catalogue resource %d (%s/%s): %w",
				ErrConfig, i, resource.Group, resource.Name, err)
		}

		resource.Privileges = privileges
		declared = append(declared, resource)
	}

	return &Catalogue{resources: declared}, nil
}

// cataloguePrivileges validates and copies the privileges of one resource,
// filling in the default scopes.
func cataloguePrivileges(resource CatalogueResource) ([]CataloguePrivilege, error) {
	if len(resource.Privileges) == 0 {
		return nil, errors.New("the resource declares no privileges")
	}

	privileges := make([]CataloguePrivilege, 0, len(resource.Privileges))

	for j, privilege := range resource.Privileges {
		if isBlank(privilege.Name) {
			return nil, fmt.Errorf("privilege %d has a blank name", j)
		}

		for _, earlier := range privileges {
			if equalNamesFolded(earlier.Name, privilege.Name) {
				return nil, fmt.Errorf("privilege %d repeats %q", j, earlier.Name)
			}
		}

		if len(privilege.Scopes) == 0 {
			privilege.Scopes = anyAccept()
		} else {
			privilege.Scopes = slices.Clone(privilege.Scopes)
		}

		for k, scope := range privilege.Scopes {
			if _, defined := scopeRank(scope); !defined {
				return nil, fmt.Errorf("privilege %q: scope %d is not defined", privilege.Name, k)
			}

			if slices.Contains(privilege.Scopes[:k], scope) {
				return nil, fmt.Errorf("privilege %q: scope %q is listed twice", privilege.Name, scope)
			}
		}

		privileges = append(privileges, privilege)
	}

	return privileges, nil
}

// Resources returns the declared resources, in the declared order, with each
// privilege's scopes filled in. The result is a copy: changing it does not
// change the catalogue. An absent catalogue has no resources.
func (c *Catalogue) Resources() []CatalogueResource {
	if c == nil {
		return nil
	}

	resources := make([]CatalogueResource, len(c.resources))

	for i, resource := range c.resources {
		resource.Privileges = slices.Clone(resource.Privileges)
		for j := range resource.Privileges {
			resource.Privileges[j].Scopes = slices.Clone(resource.Privileges[j].Scopes)
		}

		resources[i] = resource
	}

	return resources
}

// Allows reports whether privilege on group/resource may be granted with
// scope.
//
// Names are compared as the privilege authorizer compares them by default. The
// empty scope reads as identity.ScopeAll, as it does in stored grants. An
// unknown resource or privilege, and a scope the privilege does not allow or
// that identity does not define, are not allowed. An absent catalogue allows
// nothing.
func (c *Catalogue) Allows(group, resource, privilege string, scope identity.Scope) bool {
	if c == nil {
		return false
	}

	scope = identity.Privilege{Scope: scope}.EffectiveScope()

	for _, declared := range c.resources {
		if !equalNamesFolded(declared.Group, group) || !equalNamesFolded(declared.Name, resource) {
			continue
		}

		for _, p := range declared.Privileges {
			if equalNamesFolded(p.Name, privilege) {
				return slices.Contains(p.Scopes, scope)
			}
		}

		return false
	}

	return false
}
