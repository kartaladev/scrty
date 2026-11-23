package admin

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// The field names an assignment event's Changed lists.
const (
	assignmentFieldRoles   = "roles"
	assignmentFieldPrimary = "primary"
)

// AssignmentsOption configures NewAssignments. Every Option, such as
// WithEventSink, is one.
type AssignmentsOption interface {
	applyAssignments(c *common) error
}

// Assignments administers users' role grants: it lists them, adds and removes
// one, and marks one primary, each conditional on the user's version.
//
// Assignments does not authorize. The application guards the routes that reach
// it. Every write requires an actor (ActorFrom) and is refused with ErrNoActor
// without one, before the store is called. Each committed write is reported as
// event.AuthzChange, with Changed "roles" for an addition or a removal and
// "primary" for a new primary grant. An Assignments is safe for concurrent use
// when its store is.
type Assignments struct {
	store AssignmentStore
	cfg   common
}

// NewAssignments returns an Assignments over store. With only a store it
// works: no event sink, no audit sink, the system clock and the routing
// logger; each option replaces one of those. A nil store, or an option that
// cannot work, fails with an error matching ErrConfig. A nil option is
// ignored.
func NewAssignments(store AssignmentStore, opts ...AssignmentsOption) (*Assignments, error) {
	if nilcheck.IsNil(store) {
		return nil, fmt.Errorf("%w: assignment store is nil", ErrConfig)
	}

	var cfg common

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt.applyAssignments(&cfg); err != nil {
			return nil, err
		}
	}

	if err := cfg.finish(); err != nil {
		return nil, err
	}

	return &Assignments{store: store, cfg: cfg}, nil
}

// List returns the user's role grants, with their dates and primary mark, and
// the user's version, which the writes name. An unknown or deleted user is
// ErrNotFound.
func (a *Assignments) List(ctx context.Context, userID identity.UserID) ([]*identity.AssignedRole, int64, error) {
	if err := userIDValid(userID); err != nil {
		return nil, 0, err
	}

	roles, version, err := a.store.ListAssignments(ctx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: list assignments: %w", err)
	}

	return roles, version, nil
}

// Add grants the role to the user and returns the user's new version. A zero
// Start or End leaves that side unbounded; an End not after Start, when both
// are set, is ErrInvalidInput. A role the store does not hold is ErrNotFound.
func (a *Assignments) Add(ctx context.Context, userID identity.UserID, version int64, as Assignment) (int64, error) {
	if _, err := ActorFrom(ctx); err != nil {
		return 0, err
	}

	if err := roleName(as.Role); err != nil {
		return 0, err
	}

	if !as.Start.IsZero() && !as.End.IsZero() && !as.End.After(as.Start) {
		return 0, invalid("the end of an assignment must be after its start")
	}

	return a.write(ctx, userID, version, assignmentFieldRoles, func(ctx context.Context) (int64, error) {
		return a.store.AddAssignment(ctx, userID, version, as)
	})
}

// Remove removes the grant with the identifier (identity.AssignedRole.ID) and
// returns the user's new version. When it was primary, another remaining
// grant becomes primary.
func (a *Assignments) Remove(ctx context.Context, userID identity.UserID, version int64, grantID string) (int64, error) {
	if _, err := ActorFrom(ctx); err != nil {
		return 0, err
	}

	if err := nonBlank("grant identifier", grantID, MaxTextBytes); err != nil {
		return 0, err
	}

	return a.write(ctx, userID, version, assignmentFieldRoles, func(ctx context.Context) (int64, error) {
		return a.store.RemoveAssignment(ctx, userID, version, grantID)
	})
}

// SetPrimary makes the grant with the identifier the user's only primary grant
// and returns the user's new version.
func (a *Assignments) SetPrimary(ctx context.Context, userID identity.UserID, version int64, grantID string) (int64, error) {
	if _, err := ActorFrom(ctx); err != nil {
		return 0, err
	}

	if err := nonBlank("grant identifier", grantID, MaxTextBytes); err != nil {
		return 0, err
	}

	return a.write(ctx, userID, version, assignmentFieldPrimary, func(ctx context.Context) (int64, error) {
		return a.store.SetPrimary(ctx, userID, version, grantID)
	})
}

// write checks the actor and the version, reads the before record when an
// audit sink will receive it, makes the change and reports it.
func (a *Assignments) write(ctx context.Context, userID identity.UserID, version int64, field string,
	change func(ctx context.Context) (int64, error),
) (int64, error) {
	actor, err := ActorFrom(ctx)
	if err != nil {
		return 0, err
	}

	if err := userWrite(userID, version); err != nil {
		return 0, err
	}

	var before []identity.AssignedRole

	if a.cfg.auditing() {
		roles, _, err := a.store.ListAssignments(ctx, userID)
		if err != nil {
			return 0, fmt.Errorf("admin: assignment: %w", err)
		}

		before = assignedValues(roles)
	}

	next, err := change(ctx)
	if err != nil {
		return 0, fmt.Errorf("admin: assignment: %w", err)
	}

	report := changeReport{
		actor: actor, name: event.AuthzChange, user: userID, target: string(userID), changed: []string{field},
	}

	if a.cfg.auditing() {
		report.before = before

		// A version other than the one written means another write landed
		// in between: that record is not this change's after.
		if roles, v, err := a.store.ListAssignments(ctx, userID); err != nil || v != next {
			a.cfg.afterUnread(ctx, report)
		} else {
			report.after = assignedValues(roles)
		}
	}

	a.cfg.report(ctx, report)

	return next, nil
}

// assignedValues copies role grants into values an audit sink may keep.
func assignedValues(roles []*identity.AssignedRole) []identity.AssignedRole {
	out := make([]identity.AssignedRole, 0, len(roles))

	for _, r := range roles {
		if r != nil {
			out = append(out, *r)
		}
	}

	return out
}
