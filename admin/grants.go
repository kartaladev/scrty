package admin

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Bounds the grant service enforces before the store is called.
const (
	// MaxResourcesPerReplace bounds the resources one replacement names.
	MaxResourcesPerReplace = 256
	// MaxGrantsPerResource bounds the grants of one resource in a replacement.
	MaxGrantsPerResource = 256
)

// GrantsOption configures NewGrants. Every Option, such as WithEventSink, is
// one.
type GrantsOption interface {
	applyGrants(c *common) error
}

// Grants administers roles' grants: it reads them and replaces them per
// resource, conditional on the role's version.
//
// Every grant is checked against the catalogue before anything is written: a
// resource the catalogue does not list, a privilege it does not list for that
// resource, or a scope that privilege may not be granted with is
// ErrUnknownPrivilege, and nothing is written.
//
// Grants does not authorize. The application guards the routes that reach it.
// Every write requires an actor (ActorFrom) and is refused with ErrNoActor
// without one, before the store is called. Each committed replacement is
// reported as event.PrivilegePermissionsChanged, with Changed naming each
// replaced resource as group/resource. A Grants is safe for concurrent use
// when its store is.
type Grants struct {
	store     GrantStore
	catalogue *authorize.Catalogue
	resources map[string]declaredResource
	cfg       common
}

// declaredResource is a catalogue resource as declared, with its privileges
// keyed under the catalogue's name comparison.
type declaredResource struct {
	group, name string
	privileges  map[string]string
}

// NewGrants returns a Grants over store that checks grants against catalogue.
// The catalogue is required: without one, grant administration would store any
// typo as a privilege nobody checks. With a store and a catalogue it works: no
// event sink, no audit sink, the system clock and the routing logger; each
// option replaces one of those.
//
// A nil store or catalogue, or an option that cannot work, fails with an error
// matching ErrConfig. A nil option is ignored.
func NewGrants(store GrantStore, catalogue *authorize.Catalogue, opts ...GrantsOption) (*Grants, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: grant store is nil", ErrConfig)
	}

	if catalogue == nil {
		return nil, fmt.Errorf("%w: a grant service needs a resource catalogue", ErrConfig)
	}

	var cfg common

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt.applyGrants(&cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.finish(); err != nil {
		return nil, err
	}

	resources := map[string]declaredResource{}
	for _, r := range catalogue.Resources() {
		d := declaredResource{group: r.Group, name: r.Name, privileges: make(map[string]string, len(r.Privileges))}
		for _, p := range r.Privileges {
			d.privileges[foldName(p.Name)] = p.Name
		}

		resources[resourceKey(r.Group, r.Name)] = d
	}

	return &Grants{store: store, catalogue: catalogue, resources: resources, cfg: cfg}, nil
}

// Get returns every grant of the role and the role's version, which Replace
// names. An unknown role is ErrNotFound.
func (g *Grants) Get(ctx context.Context, role string) ([]Grant, int64, error) {
	if err := roleName(role); err != nil {
		return nil, 0, err
	}

	grants, version, err := g.store.GetGrants(ctx, role)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: get grants: %w", err)
	}

	return grants, version, nil
}

// Replace replaces the named resources' grants of the role, in one store
// call, conditional on the role's version, and returns the new version. Every
// other resource keeps its grants. Each ResourceGrants is the complete list of
// its resource; an empty list removes the resource's grants.
//
// No resources, a version below one, a resource named twice, a privilege
// named twice in one resource, or a grant naming a resource other than its
// ResourceGrants' is ErrInvalidInput; a grant the catalogue does not allow,
// including any grant on a resource it does not list, is ErrUnknownPrivilege.
// An empty list is allowed for any resource, listed or not, so the grants of a
// resource the catalogue no longer declares can be cleared. Either refusal
// writes nothing. Names are compared as the catalogue compares them, and
// reach the store as the catalogue declares them: "CRM", " Lead " and "VIEW "
// are written as the declared "crm", "lead" and "view". The names of a cleared
// resource the catalogue does not list are trimmed.
func (g *Grants) Replace(ctx context.Context, role string, version int64, resources ...ResourceGrants) (int64, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return 0, err
	}

	if err := roleWrite(role, version); err != nil {
		return 0, err
	}

	resources, changed, err := g.check(resources)
	if err != nil {
		return 0, err
	}

	var before []Grant

	if g.cfg.auditing() {
		got, v, err := g.store.GetGrants(ctx, role)
		if err != nil {
			return 0, fmt.Errorf("admin: replace grants: %w", err)
		}

		if v != version {
			return 0, fmt.Errorf("admin: replace grants: %w", ErrStaleUpdate)
		}

		before = slices.Clone(got)
	}

	next, err := g.store.ReplaceGrants(ctx, role, version, resources)
	if err != nil {
		return 0, fmt.Errorf("admin: replace grants: %w", err)
	}

	report := changeReport{actor: actor, name: event.PrivilegePermissionsChanged, target: role, changed: changed}

	if g.cfg.auditing() {
		report.before = before

		// A version other than the one written means another write landed
		// in between: that record is not this change's after.
		if got, v, err := g.store.GetGrants(ctx, role); err != nil || v != next {
			g.cfg.afterUnread(ctx, report)
		} else {
			report.after = slices.Clone(got)
		}
	}

	g.cfg.report(ctx, report)

	return next, nil
}

// check validates a replacement against the bounds and the catalogue, and
// returns a copy with each grant's group and resource filled in, and the
// replaced resources as group/resource.
func (g *Grants) check(in []ResourceGrants) ([]ResourceGrants, []string, error) {
	switch {
	case len(in) == 0:
		return nil, nil, invalid("a replacement names no resource")
	case len(in) > MaxResourcesPerReplace:
		return nil, nil, invalid("a replacement names more than %d resources", MaxResourcesPerReplace)
	}

	out := make([]ResourceGrants, 0, len(in))
	changed := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))

	for i, rg := range in {
		if err := nonBlank("resource group", rg.Group, MaxTextBytes); err != nil {
			return nil, nil, err
		}

		if err := nonBlank("resource name", rg.Resource, MaxTextBytes); err != nil {
			return nil, nil, err
		}

		key := resourceKey(rg.Group, rg.Resource)
		if _, dup := seen[key]; dup {
			return nil, nil, invalid("resource %d is named twice", i)
		}

		seen[key] = struct{}{}

		// Clearing a resource is allowed whether or not the catalogue lists
		// it, so grants on a resource the catalogue dropped can be removed;
		// granting on one is not. An unlisted resource's names are trimmed;
		// a listed one's reach the store as the catalogue declares them.
		declared, listed := g.resources[key]
		if !listed {
			if len(rg.Grants) > 0 {
				return nil, nil, fmt.Errorf("%w: resource %d is not in the catalogue", ErrUnknownPrivilege, i)
			}

			declared = declaredResource{group: trimName(rg.Group), name: trimName(rg.Resource)}
		}

		grants, err := g.checkGrants(i, rg, declared)
		if err != nil {
			return nil, nil, err
		}

		out = append(out, ResourceGrants{Group: declared.group, Resource: declared.name, Grants: grants})
		changed = append(changed, declared.group+"/"+declared.name)
	}

	return out, changed, nil
}

func (g *Grants) checkGrants(i int, rg ResourceGrants, declared declaredResource) ([]Grant, error) {
	if len(rg.Grants) > MaxGrantsPerResource {
		return nil, invalid("resource %d has more than %d grants", i, MaxGrantsPerResource)
	}

	grants := make([]Grant, 0, len(rg.Grants))
	seen := make(map[string]struct{}, len(rg.Grants))
	key := resourceKey(rg.Group, rg.Resource)

	for j, gr := range rg.Grants {
		if gr.Group == "" && gr.Resource == "" {
			gr.Group, gr.Resource = rg.Group, rg.Resource
		}

		if resourceKey(gr.Group, gr.Resource) != key {
			return nil, invalid("grant %d of resource %d names another resource", j, i)
		}

		if err := nonBlank("privilege", gr.Privilege, MaxTextBytes); err != nil {
			return nil, err
		}

		p := foldName(gr.Privilege)
		if _, dup := seen[p]; dup {
			return nil, invalid("grant %d of resource %d names its privilege twice", j, i)
		}

		seen[p] = struct{}{}

		if !g.catalogue.Allows(gr.Group, gr.Resource, gr.Privilege, gr.Scope) {
			return nil, fmt.Errorf("%w: grant %d of resource %d is not allowed by the catalogue", ErrUnknownPrivilege, j, i)
		}

		gr.Group, gr.Resource, gr.Privilege = declared.group, declared.name, declared.privileges[p]

		grants = append(grants, gr)
	}

	return grants, nil
}

// resourceKey is a resource's identity under the catalogue's name comparison.
func resourceKey(group, resource string) string {
	return foldName(group) + "\x00" + foldName(resource)
}

// trimName removes surrounding ASCII white space, which the catalogue's
// comparison ignores.
func trimName(s string) string { return strings.Trim(s, asciiSpace) }

const asciiSpace = " \t\n\v\f\r"

// foldName is a name under the catalogue's comparison: surrounding ASCII
// white space removed and ASCII letters lower-cased.
func foldName(s string) string {
	s = trimName(s)

	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}

		return r
	}, s)
}
