package admin

import (
	"context"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Bounds the role service enforces before the store is called.
const (
	// MaxDescriptionBytes bounds a role's description.
	MaxDescriptionBytes = 1024
	// MaxLabels bounds the labels of one role.
	MaxLabels = 64
)

// The field names a role event's Changed lists.
const (
	roleFieldName        = "name"
	roleFieldDisplayName = "display_name"
	roleFieldDescription = "description"
	roleFieldLabels      = "labels"
	roleFieldSuperRole   = "super_role"
)

// RolesOption configures NewRoles. Every Option, such as WithEventSink, is one.
type RolesOption interface {
	applyRoles(c *common) error
}

// Roles administers roles: it lists, reads, creates, updates and deletes them.
// A role's name is the immutable key of its grants and assignments; a
// "rename" changes its display name.
//
// Roles does not authorize. The application guards the routes that reach it.
// Every write requires an actor (ActorFrom) and is refused with ErrNoActor
// without one, before the store is called. Each committed write is reported as
// event.AuthzAdmin. A Roles is safe for concurrent use when its store is.
type Roles struct {
	store RoleStore
	cfg   common
}

// NewRoles returns a Roles over store. With only a store it works: no event
// sink, no audit sink, the system clock and the routing logger; each option
// replaces one of those. A nil store, or an option that cannot work, fails
// with an error matching ErrConfig. A nil option is ignored.
func NewRoles(store RoleStore, opts ...RolesOption) (*Roles, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: role store is nil", ErrConfig)
	}

	var cfg common

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt.applyRoles(&cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.finish(); err != nil {
		return nil, err
	}

	return &Roles{store: store, cfg: cfg}, nil
}

// List returns every role, with the number of live users assigned to each,
// or only the roles carrying label when it is not empty. A label beyond
// MaxTextBytes is ErrInvalidInput.
func (r *Roles) List(ctx context.Context, label string) ([]Role, error) {
	if err := text("label filter", label, MaxTextBytes); err != nil {
		return nil, err
	}

	roles, err := r.store.ListRoles(ctx, label)
	if err != nil {
		return nil, fmt.Errorf("admin: list roles: %w", err)
	}

	return roles, nil
}

// Get returns the role with the name. An unknown role is ErrNotFound.
func (r *Roles) Get(ctx context.Context, name string) (Role, error) {
	if err := roleName(name); err != nil {
		return Role{}, err
	}

	got, err := r.store.GetRole(ctx, name)
	if err != nil {
		return Role{}, fmt.Errorf("admin: get role: %w", err)
	}

	return got, nil
}

// Create creates the role at version one. A taken name is an error matching
// ErrAlreadyExists with the field FieldRole. Version and Assigned are ignored.
// The event's Changed lists "name" and each other field set.
func (r *Roles) Create(ctx context.Context, role Role) (Role, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return Role{}, err
	}

	role.Labels = slices.Clone(role.Labels)
	role.Version, role.Assigned = 0, 0

	if err := validateRole(role); err != nil {
		return Role{}, err
	}

	created, err := r.store.CreateRole(ctx, role)
	if err != nil {
		return Role{}, fmt.Errorf("admin: create role: %w", err)
	}

	report := changeReport{actor: actor, name: event.AuthzAdmin, target: role.Name, changed: createdRoleFields(role)}
	if r.cfg.auditing() {
		report.after = cloneRole(created)
	}

	r.cfg.report(ctx, report)

	return created, nil
}

// Update changes the fields the change names, conditional on version. The
// name never changes. An empty change, or a version below one, is
// ErrInvalidInput; a version that differs from the stored one is
// ErrStaleUpdate and changes nothing.
func (r *Roles) Update(ctx context.Context, name string, version int64, c RoleChange) (Role, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return Role{}, err
	}

	if err := roleWrite(name, version); err != nil {
		return Role{}, err
	}

	if c.Labels != nil {
		labels := slices.Clone(*c.Labels)
		c.Labels = &labels
	}

	changed, err := validateRoleChange(c)
	if err != nil {
		return Role{}, err
	}

	var before *Role

	if r.cfg.auditing() {
		got, err := r.store.GetRole(ctx, name)
		if err != nil {
			return Role{}, fmt.Errorf("admin: update role: %w", err)
		}

		if got.Version != version {
			return Role{}, fmt.Errorf("admin: update role: %w", ErrStaleUpdate)
		}

		before = &got
	}

	updated, err := r.store.UpdateRole(ctx, name, version, c)
	if err != nil {
		return Role{}, fmt.Errorf("admin: update role: %w", err)
	}

	report := changeReport{actor: actor, name: event.AuthzAdmin, target: name, changed: changed}
	if before != nil {
		report.before, report.after = cloneRole(*before), cloneRole(updated)
	}

	r.cfg.report(ctx, report)

	return updated, nil
}

// Delete removes the role, conditional on version. Without force, a role
// assigned to a live user is ErrStillAssigned and nothing changes; with force,
// its grants and assignments go with it in one transaction, and a user whose
// primary grant it was gets another remaining grant as primary.
func (r *Roles) Delete(ctx context.Context, name string, version int64, force bool) error {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return err
	}

	if err := roleWrite(name, version); err != nil {
		return err
	}

	var before *Role

	if r.cfg.auditing() {
		got, err := r.store.GetRole(ctx, name)
		if err != nil {
			return fmt.Errorf("admin: delete role: %w", err)
		}

		if got.Version != version {
			return fmt.Errorf("admin: delete role: %w", ErrStaleUpdate)
		}

		before = &got
	}

	if err := r.store.DeleteRole(ctx, name, version, force); err != nil {
		return fmt.Errorf("admin: delete role: %w", err)
	}

	report := changeReport{actor: actor, name: event.AuthzAdmin, target: name}
	if before != nil {
		report.before = cloneRole(*before)
	}

	r.cfg.report(ctx, report)

	return nil
}

// roleName checks a role name: a store matches it exactly, so it has no
// surrounding white space.
func roleName(name string) error { return exactName("role name", name, MaxTextBytes) }

func roleWrite(name string, version int64) error {
	if err := roleName(name); err != nil {
		return err
	}

	if version < 1 {
		return invalid("version must be at least 1")
	}

	return nil
}

func validateRole(role Role) error {
	if err := roleName(role.Name); err != nil {
		return err
	}

	if err := text("display name", role.DisplayName, MaxTextBytes); err != nil {
		return err
	}

	if err := noNUL("description", role.Description, MaxDescriptionBytes); err != nil {
		return err
	}

	return labelsValid(role.Labels)
}

func labelsValid(labels []string) error {
	if len(labels) > MaxLabels {
		return invalid("more than %d labels", MaxLabels)
	}

	for _, l := range labels {
		if err := exactName("label", l, MaxTextBytes); err != nil {
			return err
		}
	}

	return nil
}

// validateRoleChange checks a change and returns the names of its fields.
func validateRoleChange(c RoleChange) ([]string, error) {
	var changed []string

	if c.DisplayName != nil {
		if err := text("display name", *c.DisplayName, MaxTextBytes); err != nil {
			return nil, err
		}

		changed = append(changed, roleFieldDisplayName)
	}

	if c.Description != nil {
		if err := noNUL("description", *c.Description, MaxDescriptionBytes); err != nil {
			return nil, err
		}

		changed = append(changed, roleFieldDescription)
	}

	if c.Labels != nil {
		if err := labelsValid(*c.Labels); err != nil {
			return nil, err
		}

		changed = append(changed, roleFieldLabels)
	}

	if c.SuperRole != nil {
		changed = append(changed, roleFieldSuperRole)
	}

	if len(changed) == 0 {
		return nil, invalid("the change names no field")
	}

	return changed, nil
}

func createdRoleFields(role Role) []string {
	changed := []string{roleFieldName}

	if role.DisplayName != "" {
		changed = append(changed, roleFieldDisplayName)
	}

	if role.Description != "" {
		changed = append(changed, roleFieldDescription)
	}

	if len(role.Labels) > 0 {
		changed = append(changed, roleFieldLabels)
	}

	if role.SuperRole {
		changed = append(changed, roleFieldSuperRole)
	}

	return changed
}

func cloneRole(r Role) Role {
	r.Labels = slices.Clone(r.Labels)

	return r
}
