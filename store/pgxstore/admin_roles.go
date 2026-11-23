package pgxstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/ascii"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// The role, grant and assignment administration ports. IdentityStore
// implements admin.RoleStore, admin.GrantStore and admin.AssignmentStore over
// scrty_roles, scrty_resource_privileges and scrty_assigned_roles, with the
// statements of internal/pgschema it shares with sqlstore.
//
// Every versioned write runs in one transaction (or, inside a caller's, under
// a savepoint) that locks the row whose version it names first: the role's
// for a role or grant write, the user's for an assignment write. Locks are
// taken roles first, then users in identifier order, so writers never wait on
// each other in a cycle. A role's grants share the role's version, and a
// user's role grants share the user's version.
//
// Every write to a user's grants keeps one rule: a user holding any grant has
// exactly one primary grant. When the primary grant goes (removed, or its
// role deleted), the remaining grant with the lowest position, the one
// assigned first, becomes primary; scrty_users.role follows the primary
// grant (empty for none), and the user's version increases.
//
// A role name PostgreSQL text cannot hold names no role (admin.ErrNotFound),
// as does a user or grant reference that is not canonical lowercase UUID
// text. Error text never carries a role name, a label or a user reference.
var (
	_ admin.RoleStore       = (*IdentityStore)(nil)
	_ admin.GrantStore      = (*IdentityStore)(nil)
	_ admin.AssignmentStore = (*IdentityStore)(nil)
)

// ListRoles implements admin.RoleStore.
func (s *IdentityStore) ListRoles(ctx context.Context, label string) ([]admin.Role, error) {
	const op = "list roles"

	if !storekit.Storable(label) {
		return nil, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.Query(ctx, pgschema.ListAdminRoles, label)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	var out []admin.Role
	for rows.Next() {
		r, err := scanAdminRole(op, rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// GetRole implements admin.RoleStore.
func (s *IdentityStore) GetRole(ctx context.Context, name string) (admin.Role, error) {
	const op = "get role"

	if !storekit.Storable(name) {
		return admin.Role{}, notFound(op)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return admin.Role{}, failed(op, err)
	}

	return readAdminRole(ctx, q, op, name)
}

// CreateRole implements admin.RoleStore. The role is stored at version one; a
// taken name is an admin.AlreadyExistsError naming admin.FieldRole, decided by
// the insert, so of concurrent creations of one name exactly one succeeds.
func (s *IdentityStore) CreateRole(ctx context.Context, in admin.Role) (admin.Role, error) {
	const op = "create role"

	if in.Name == "" {
		return admin.Role{}, invalidInput(op, "the role name is empty")
	}
	if !storekit.Storable(in.Name, in.DisplayName, in.Description) || !storekit.Storable(in.Labels...) {
		return admin.Role{}, invalidInput(op, "a field holds text that cannot be stored")
	}

	rid, err := idgen.New(s.c.ids)
	if err != nil {
		return admin.Role{}, failed(op, err)
	}

	var out admin.Role
	err = s.atomically(ctx, op, func(q DBTX) error {
		now := storekit.Time(s.c.clock.Now())
		tag, err := q.Exec(ctx, pgschema.InsertAdminRole, uuidArg(rid), in.Name, in.DisplayName, in.Description,
			labelsArg(in.Labels), in.SuperRole, now)
		if err != nil {
			return dbFailed(op, err)
		}
		if tag.RowsAffected() == 0 {
			return alreadyExists(op, admin.FieldRole)
		}

		out, err = readAdminRole(ctx, q, op, in.Name)

		return err
	})
	if err != nil {
		return admin.Role{}, err
	}

	return out, nil
}

// UpdateRole implements admin.RoleStore. Only the named fields change; the
// name never does.
//
// Each grant carries a copy of its role's super-role flag, which the
// authorizer reads. An update that changes the flag therefore locks the
// role's holders, live or deleted, in identifier order after the role, copies
// the new flag onto their grants and increases each holder's version, in the
// same transaction. An update that leaves the flag as it is touches no
// holder.
func (s *IdentityStore) UpdateRole(
	ctx context.Context, name string, version int64, change admin.RoleChange,
) (admin.Role, error) {
	const op = "update role"

	if !storekit.Storable(name) {
		return admin.Role{}, notFound(op)
	}

	var displayName, description, labels, superRole any
	if change.DisplayName != nil {
		displayName = *change.DisplayName
	}
	if change.Description != nil {
		description = *change.Description
	}
	if change.Labels != nil {
		if !storekit.Storable(*change.Labels...) {
			return admin.Role{}, invalidInput(op, "a label holds text that cannot be stored")
		}
		labels = labelsArg(*change.Labels)
	}
	if change.SuperRole != nil {
		superRole = *change.SuperRole
	}
	if (change.DisplayName != nil && !storekit.Storable(*change.DisplayName)) ||
		(change.Description != nil && !storekit.Storable(*change.Description)) {
		return admin.Role{}, invalidInput(op, "a field holds text that cannot be stored")
	}

	var out admin.Role
	err := s.atomically(ctx, op, func(q DBTX) error {
		stored, err := lockAdminRoleFlag(ctx, q, op, name, version)
		if err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())
		if _, err := q.Exec(ctx, pgschema.UpdateAdminRole, name, displayName, description, labels,
			superRole, now); err != nil {
			return dbFailed(op, err)
		}

		if change.SuperRole != nil && *change.SuperRole != stored {
			if err := copySuperRole(ctx, q, op, name, *change.SuperRole, now); err != nil {
				return err
			}
		}

		out, err = readAdminRole(ctx, q, op, name)

		return err
	})
	if err != nil {
		return admin.Role{}, err
	}

	return out, nil
}

// DeleteRole implements admin.RoleStore.
//
// Without force, a role a live user holds is admin.ErrStillAssigned and
// nothing changes; grants held only by soft-deleted users do not count, and go
// with the role. The role's privileges and every grant of it are removed in
// the same transaction. Each user who held a grant of it has their row locked
// first and their version increased, and, where the removed grant was
// primary, the remaining grant assigned first becomes primary.
func (s *IdentityStore) DeleteRole(ctx context.Context, name string, version int64, force bool) error {
	const op = "delete role"

	if !storekit.Storable(name) {
		return notFound(op)
	}

	return s.atomically(ctx, op, func(q DBTX) error {
		if err := lockAdminRole(ctx, q, op, name, version); err != nil {
			return err
		}

		if !force {
			var held bool
			if err := q.QueryRow(ctx, pgschema.RoleHeldByLiveUser, name).Scan(&held); err != nil {
				return scanFailed(op, err)
			}
			if held {
				return failed(op, admin.ErrStillAssigned)
			}
		}

		holders, err := lockRoleHolders(ctx, q, op, name)
		if err != nil {
			return err
		}

		for _, stmt := range []string{
			pgschema.DeleteAssignmentsOfRole, pgschema.DeletePrivilegesOfRole, pgschema.DeleteAdminRole,
		} {
			if _, err := q.Exec(ctx, stmt, name); err != nil {
				return dbFailed(op, err)
			}
		}

		if len(holders) == 0 {
			return nil
		}

		_, err = settleGrants(ctx, q, op, holders, storekit.Time(s.c.clock.Now()))

		return err
	})
}

// GetGrants implements admin.GrantStore. The grants and the version are read
// by one statement, so they agree.
func (s *IdentityStore) GetGrants(ctx context.Context, role string) ([]admin.Grant, int64, error) {
	const op = "get grants"

	if !storekit.Storable(role) {
		return nil, 0, notFound(op)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, 0, failed(op, err)
	}

	rows, err := q.Query(ctx, pgschema.GrantsOfRole, role)
	if err != nil {
		return nil, 0, dbFailed(op, err)
	}
	defer rows.Close()

	var (
		out     []admin.Grant
		version int64
		found   bool
	)
	for rows.Next() {
		var (
			group, resource, privilege, scope pgtype.Text
			granted                           pgtype.Bool
		)
		if err := rows.Scan(&version, &group, &resource, &privilege, &granted, &scope); err != nil {
			return nil, 0, scanFailed(op, err)
		}
		found = true
		if !privilege.Valid {
			continue
		}
		out = append(out, admin.Grant{
			Group: group.String, Resource: resource.String, Privilege: privilege.String,
			Granted: granted.Bool, Scope: identity.Scope(scope.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, dbFailed(op, err)
	}
	if !found {
		return nil, 0, notFound(op)
	}

	return out, version, nil
}

// ReplaceGrants implements admin.GrantStore. It locks the role's row, checks
// the version, then for each resource in turn removes its stored privileges,
// matching the stored group and resource with surrounding ASCII whitespace
// trimmed and ASCII case ignored, as the authorizer reads them, and writes
// the given ones under the names as given, and increases the role's version, all in one
// transaction: a failure or a cancelled context anywhere leaves every grant
// and the version as they were. An empty scope is stored as
// identity.ScopeAll. A resource named twice under that matching, a grant naming another resource
// than its ResourceGrants, or a privilege listed twice for one resource is
// admin.ErrInvalidInput.
func (s *IdentityStore) ReplaceGrants(
	ctx context.Context, role string, version int64, resources []admin.ResourceGrants,
) (int64, error) {
	const op = "replace grants"

	if !storekit.Storable(role) {
		return 0, notFound(op)
	}
	planned, err := planPrivileges(op, resources)
	if err != nil {
		return 0, err
	}

	var next int64
	err = s.atomically(ctx, op, func(q DBTX) error {
		if err := lockAdminRole(ctx, q, op, role, version); err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())
		for _, rg := range planned {
			if _, err := q.Exec(ctx, pgschema.DeleteResourcePrivileges, role, rg.Group, rg.Resource); err != nil {
				return dbFailed(op, err)
			}
			for _, g := range rg.Grants {
				pid, err := idgen.New(s.c.ids)
				if err != nil {
					return failed(op, err)
				}
				if _, err := q.Exec(ctx, pgschema.InsertResourcePrivilege, uuidArg(pid), role, rg.Group, rg.Resource,
					g.Privilege, g.Granted, string(g.Scope), now); err != nil {
					return dbFailed(op, err)
				}
			}
		}

		if err := q.QueryRow(ctx, pgschema.BumpRoleVersion, role, now).Scan(&next); err != nil {
			return scanFailed(op, err)
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return next, nil
}

// ListAssignments implements admin.AssignmentStore. The grants and the
// version are read by one statement, so they agree.
func (s *IdentityStore) ListAssignments(
	ctx context.Context, ref identity.UserID,
) ([]*identity.AssignedRole, int64, error) {
	const op = "list assignments"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return nil, 0, notFound(op)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, 0, failed(op, err)
	}

	rows, err := q.Query(ctx, pgschema.AssignmentsOfUser, uuidArg(uid))
	if err != nil {
		return nil, 0, dbFailed(op, err)
	}
	defer rows.Close()

	var (
		out     []*identity.AssignedRole
		version int64
		found   bool
	)
	for rows.Next() {
		var (
			rawGrant       pgtype.UUID
			name           pgtype.Text
			primary, super pgtype.Bool
			start, until   pgtype.Timestamptz
		)
		if err := rows.Scan(&version, &rawGrant, &name, &primary, &super, &start, &until); err != nil {
			return nil, 0, scanFailed(op, err)
		}
		found = true
		if !rawGrant.Valid {
			continue
		}
		g := &identity.AssignedRole{
			ID: id.ID(rawGrant.Bytes).String(), Name: name.String, Primary: primary.Bool, SuperRole: super.Bool,
		}
		if g.StartDate, err = fromNull(start); err != nil {
			return nil, 0, failed(op, err)
		}
		if g.ValidUntil, err = fromNull(until); err != nil {
			return nil, 0, failed(op, err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, dbFailed(op, err)
	}
	if !found {
		return nil, 0, notFound(op)
	}

	return out, version, nil
}

// AddAssignment implements admin.AssignmentStore. The grant takes the role's
// super-role flag and the position after the user's last grant. A primary
// assignment, or the first grant of a user who has no primary one, becomes
// the user's only primary grant.
func (s *IdentityStore) AddAssignment(
	ctx context.Context, ref identity.UserID, version int64, a admin.Assignment,
) (int64, error) {
	const op = "add assignment"

	uid, ok := storekit.ParseUserID(ref)
	if !ok || !storekit.Storable(a.Role) {
		return 0, notFound(op)
	}

	gid, err := idgen.New(s.c.ids)
	if err != nil {
		return 0, failed(op, err)
	}

	var next int64
	err = s.atomically(ctx, op, func(q DBTX) error {
		// The role first, then the user: the order every writer locks in.
		var super bool
		err := q.QueryRow(ctx, pgschema.ShareAdminRole, a.Role).Scan(&super)
		if errors.Is(err, pgx.ErrNoRows) {
			return failed(op, fmt.Errorf("%w: the role is not in the catalogue", admin.ErrNotFound))
		}
		if err != nil {
			return scanFailed(op, err)
		}

		if _, err := lockAdminUser(ctx, q, op, uid, version); err != nil {
			return err
		}

		now := storekit.Time(s.c.clock.Now())
		if a.Primary {
			if _, err := q.Exec(ctx, pgschema.ClearPrimaryGrant, uuidArg(uid), now); err != nil {
				return dbFailed(op, err)
			}
		}

		var position int
		if err := q.QueryRow(ctx, pgschema.NextGrantPosition, uuidArg(uid)).Scan(&position); err != nil {
			return scanFailed(op, err)
		}
		if _, err := q.Exec(ctx, pgschema.InsertGrant, uuidArg(gid), uuidArg(uid), a.Role, position, a.Primary, super,
			nullTs(a.Start), nullTs(a.End), now, now); err != nil {
			return dbFailed(op, err)
		}

		next, err = settleUser(ctx, q, op, uid, now)

		return err
	})
	if err != nil {
		return 0, err
	}

	return next, nil
}

// RemoveAssignment implements admin.AssignmentStore. When the removed grant
// was primary, the remaining grant assigned first becomes primary.
func (s *IdentityStore) RemoveAssignment(
	ctx context.Context, ref identity.UserID, version int64, grantID string,
) (int64, error) {
	const op = "remove assignment"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return 0, notFound(op)
	}

	var next int64
	err := s.atomically(ctx, op, func(q DBTX) error {
		if _, err := lockAdminUser(ctx, q, op, uid, version); err != nil {
			return err
		}

		gid, ok := storekit.ParseUserID(identity.UserID(grantID))
		if !ok {
			return notFound(op)
		}
		tag, err := q.Exec(ctx, pgschema.DeleteGrantOfUser, uuidArg(gid), uuidArg(uid))
		if err != nil {
			return dbFailed(op, err)
		}
		if tag.RowsAffected() == 0 {
			return notFound(op)
		}

		next, err = settleUser(ctx, q, op, uid, storekit.Time(s.c.clock.Now()))

		return err
	})
	if err != nil {
		return 0, err
	}

	return next, nil
}

// SetPrimary implements admin.AssignmentStore.
func (s *IdentityStore) SetPrimary(
	ctx context.Context, ref identity.UserID, version int64, grantID string,
) (int64, error) {
	const op = "set primary assignment"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return 0, notFound(op)
	}

	var next int64
	err := s.atomically(ctx, op, func(q DBTX) error {
		if _, err := lockAdminUser(ctx, q, op, uid, version); err != nil {
			return err
		}

		gid, ok := storekit.ParseUserID(identity.UserID(grantID))
		if !ok {
			return notFound(op)
		}
		var held bool
		if err := q.QueryRow(ctx, pgschema.GrantOfUser, uuidArg(gid), uuidArg(uid)).Scan(&held); err != nil {
			return scanFailed(op, err)
		}
		if !held {
			return notFound(op)
		}

		now := storekit.Time(s.c.clock.Now())
		if _, err := q.Exec(ctx, pgschema.MarkPrimaryGrant, uuidArg(uid), uuidArg(gid), now); err != nil {
			return dbFailed(op, err)
		}

		var err error
		next, err = settleUser(ctx, q, op, uid, now)

		return err
	})
	if err != nil {
		return 0, err
	}

	return next, nil
}

// scanAdminRole scans one row in the columns of pgschema.AdminRoleByName; no
// row is admin.ErrNotFound.
func scanAdminRole(op string, scan func(dest ...any) error) (admin.Role, error) {
	var (
		r        admin.Role
		labels   string
		assigned int64
	)
	if err := scan(&r.Name, &r.DisplayName, &r.Description, &labels, &r.SuperRole, &r.Version, &assigned); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return admin.Role{}, notFound(op)
		}
		return admin.Role{}, scanFailed(op, err)
	}
	var err error
	if r.Labels, err = pgschema.ParseLabels(labels); err != nil {
		return admin.Role{}, failed(op, err)
	}
	r.Assigned = int(assigned)

	return r, nil
}

// readAdminRole reads the role named name: admin.ErrNotFound with none.
func readAdminRole(ctx context.Context, q DBTX, op, name string) (admin.Role, error) {
	return scanAdminRole(op, q.QueryRow(ctx, pgschema.AdminRoleByName, name).Scan)
}

// lockAdminRole locks the role named name and checks that its version is
// version: admin.ErrNotFound with no role, admin.ErrStaleUpdate when the
// versions differ.
func lockAdminRole(ctx context.Context, q DBTX, op, name string, version int64) error {
	var stored int64
	err := q.QueryRow(ctx, pgschema.LockAdminRole, name).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound(op)
	}
	if err != nil {
		return scanFailed(op, err)
	}
	if stored != version {
		return failed(op, admin.ErrStaleUpdate)
	}

	return nil
}

// lockAdminRoleFlag is lockAdminRole that also returns the role's stored
// super-role flag.
func lockAdminRoleFlag(ctx context.Context, q DBTX, op, name string, version int64) (bool, error) {
	var (
		stored int64
		super  bool
	)
	err := q.QueryRow(ctx, pgschema.LockAdminRoleFlag, name).Scan(&stored, &super)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, notFound(op)
	}
	if err != nil {
		return false, scanFailed(op, err)
	}
	if stored != version {
		return false, failed(op, admin.ErrStaleUpdate)
	}

	return super, nil
}

// copySuperRole copies flag onto every grant of the role named name, whose
// row the caller has locked, and increases the version of every holder,
// locking them in identifier order first.
func copySuperRole(ctx context.Context, q DBTX, op, name string, flag bool, now time.Time) error {
	holders, err := lockRoleHolders(ctx, q, op, name)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return nil
	}

	if _, err := q.Exec(ctx, pgschema.SetHolderSuperRole, name, flag, now); err != nil {
		return dbFailed(op, err)
	}

	_, err = settleGrants(ctx, q, op, holders, now)

	return err
}

// lockRoleHolders locks, in identifier order, every user holding a grant of
// the role named name, and returns their identifiers.
func lockRoleHolders(ctx context.Context, q DBTX, op, name string) ([]id.ID, error) {
	rows, err := q.Query(ctx, pgschema.LockRoleHolders, name)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	var out []id.ID
	for rows.Next() {
		var raw pgtype.UUID
		if err := rows.Scan(&raw); err != nil {
			return nil, scanFailed(op, err)
		}
		uid, err := scanID(raw)
		if err != nil {
			return nil, failed(op, err)
		}
		out = append(out, uid)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// settleUser is settleGrants for one user, returning the user's new version.
func settleUser(ctx context.Context, q DBTX, op string, uid id.ID, now time.Time) (int64, error) {
	versions, err := settleGrants(ctx, q, op, []id.ID{uid}, now)
	if err != nil {
		return 0, err
	}
	v, ok := versions[uid]
	if !ok {
		// The caller holds the user's row lock, so the row cannot be gone.
		return 0, failed(op, errors.New("the locked user row is missing"))
	}

	return v, nil
}

// settleGrants ends every write to the grants of users, whose rows the caller
// has locked: it gives each user holding grants but no primary one the
// primary mark on the grant with the lowest position, sets scrty_users.role
// to the primary grant's name (empty for none), and increases each user's
// version. It returns each user's new version.
func settleGrants(ctx context.Context, q DBTX, op string, users []id.ID, now time.Time) (map[id.ID]int64, error) {
	ids := uuidArray(users)
	if _, err := q.Exec(ctx, pgschema.PromoteLowestGrant, ids, now); err != nil {
		return nil, dbFailed(op, err)
	}

	rows, err := q.Query(ctx, pgschema.SyncUserPrimaryRole, ids, now)
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer rows.Close()

	out := make(map[id.ID]int64, len(users))
	for rows.Next() {
		var (
			raw     pgtype.UUID
			version int64
		)
		if err := rows.Scan(&raw, &version); err != nil {
			return nil, scanFailed(op, err)
		}
		uid, err := scanID(raw)
		if err != nil {
			return nil, failed(op, err)
		}
		out[uid] = version
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// planPrivileges checks a replacement and returns it with every grant's
// group and resource set to its ResourceGrants' and an empty scope read as
// identity.ScopeAll.
func planPrivileges(op string, resources []admin.ResourceGrants) ([]admin.ResourceGrants, error) {
	type key struct{ group, resource string }

	seen := make(map[key]bool, len(resources))
	out := make([]admin.ResourceGrants, len(resources))
	for i, rg := range resources {
		if rg.Resource == "" {
			return nil, invalidInput(op, "a resource is unnamed")
		}
		if !storekit.Storable(rg.Group, rg.Resource) {
			return nil, invalidInput(op, "a resource holds text that cannot be stored")
		}
		// The key folds as the authorizer and DeleteResourcePrivileges do,
		// so two spellings of one resource cannot remove each other's rows.
		k := key{ascii.ToLower(ascii.TrimSpace(rg.Group)), ascii.ToLower(ascii.TrimSpace(rg.Resource))}
		if seen[k] {
			return nil, invalidInput(op, "a resource is named twice")
		}
		seen[k] = true

		privileges := make(map[string]bool, len(rg.Grants))
		grants := make([]admin.Grant, len(rg.Grants))
		for j, g := range rg.Grants {
			if (g.Group != "" || g.Resource != "") && (g.Group != rg.Group || g.Resource != rg.Resource) {
				return nil, invalidInput(op, "a grant names another resource than its list")
			}
			if g.Privilege == "" {
				return nil, invalidInput(op, "a grant names no privilege")
			}
			if !storekit.Storable(g.Privilege, string(g.Scope)) {
				return nil, invalidInput(op, "a grant holds text that cannot be stored")
			}
			if privileges[g.Privilege] {
				return nil, invalidInput(op, "a privilege is listed twice for one resource")
			}
			privileges[g.Privilege] = true

			g.Group, g.Resource = rg.Group, rg.Resource
			if g.Scope == "" {
				g.Scope = identity.ScopeAll
			}
			grants[j] = g
		}
		out[i] = admin.ResourceGrants{Group: rg.Group, Resource: rg.Resource, Grants: grants}
	}

	return out, nil
}

// labelsArg is labels as a text[] argument: never nil, since pgx binds a nil
// slice as NULL and the labels column is NOT NULL.
func labelsArg(labels []string) []string {
	if labels == nil {
		return []string{}
	}

	return labels
}
