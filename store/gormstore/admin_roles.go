package gormstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

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
// the role catalogue, the resource privileges and the users' role grants.
//
// A role and its grants share the role's version; a user and its role grants
// share the user's version. Every write runs in one transaction (or under a
// savepoint inside a caller's), locks the row that carries the version
// (SELECT ... FOR UPDATE), compares the version the caller read
// (admin.ErrStaleUpdate on a mismatch, admin.ErrNotFound for no such role or
// live user), writes, and increases that version. A write that touches both
// takes the role lock first and the user locks after it, users in identifier
// order, so two writers never wait on each other's second lock.
//
// Assigning a role takes a key-share lock on the role's row, so a role is
// never deleted between the check that it exists and the grant that names it.
// A role name never changes. A user's first grant is primary whatever the
// assignment says, so a user with grants always has a primary one. When a
// primary grant is removed, the remaining grant with the lowest position, the
// one assigned first, becomes primary and scrty_users.role follows the
// primary grant. Error text never carries a role name, a grant identifier or
// a privilege.
var (
	_ admin.RoleStore       = (*IdentityStore)(nil)
	_ admin.GrantStore      = (*IdentityStore)(nil)
	_ admin.AssignmentStore = (*IdentityStore)(nil)
)

// roleRow is a scanned role.
type roleRow struct {
	role   admin.Role
	labels string
}

func (r *roleRow) dest() []any {
	return []any{&r.role.Name, &r.role.DisplayName, &r.role.Description, &r.labels, &r.role.SuperRole,
		&r.role.Version, &r.role.Assigned}
}

func (r *roleRow) value(op string) (admin.Role, error) {
	labels, err := pgschema.ParseLabels(r.labels)
	if err != nil {
		return admin.Role{}, failed(op, errMalformedLabels)
	}
	r.role.Labels = labels

	return r.role, nil
}

var errMalformedLabels = errors.New("a stored role label list is malformed")

func roleText(op string, role admin.Role, texts ...string) error {
	if !storekit.Storable(append(texts, role.Name)...) {
		return invalidInput(op, "a field holds text that cannot be stored")
	}
	for _, l := range role.Labels {
		if !storekit.Storable(l) {
			return invalidInput(op, "a label holds text that cannot be stored")
		}
	}

	return nil
}

// ListRoles implements admin.RoleStore.
func (s *IdentityStore) ListRoles(ctx context.Context, label string) ([]admin.Role, error) {
	const op = "list roles"

	if !storekit.Storable(label) {
		return nil, invalidInput(op, "the label holds text that cannot be stored")
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}

	rows, err := q.Raw(pgschema.ListAdminRoles, label).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var roles []admin.Role
	for rows.Next() {
		var row roleRow
		if err := rows.Scan(row.dest()...); err != nil {
			return nil, scanFailed(op, err)
		}
		r, err := row.value(op)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	return roles, nil
}

// readRole reads the role with name.
func readRole(q *gorm.DB, op, name string) (admin.Role, error) {
	var row roleRow
	found, err := queryRow(q, op, pgschema.AdminRoleByName, []any{name}, row.dest()...)
	if err != nil {
		return admin.Role{}, err
	}
	if !found {
		return admin.Role{}, notFound(op)
	}

	return row.value(op)
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

	return readRole(q, op, name)
}

// CreateRole implements admin.RoleStore.
func (s *IdentityStore) CreateRole(ctx context.Context, in admin.Role) (admin.Role, error) {
	const op = "create role"

	if in.Name == "" {
		return admin.Role{}, invalidInput(op, "the name is empty")
	}
	if err := roleText(op, in, in.DisplayName, in.Description); err != nil {
		return admin.Role{}, err
	}

	rid, err := idgen.New(s.c.ids)
	if err != nil {
		return admin.Role{}, failed(op, err)
	}
	now := storekit.Time(s.c.clock.Now())

	var out admin.Role
	err = s.atomically(ctx, op, func(q *gorm.DB) error {
		res := q.Exec(pgschema.InsertAdminRole, rid, in.Name, in.DisplayName, in.Description,
			pgschema.TextArray(in.Labels), in.SuperRole, now)
		if res.Error != nil {
			return dbFailed(op, res.Error)
		}
		if res.RowsAffected == 0 {
			return alreadyExists(op, admin.FieldRole)
		}

		var err error
		out, err = readRole(q, op, in.Name)

		return err
	})

	return out, err
}

// lockRole locks the role with name and checks its version.
func lockRole(q *gorm.DB, op, name string, version int64) error {
	var stored int64
	found, err := queryRow(q, op, pgschema.LockAdminRole, []any{name}, &stored)
	if err != nil {
		return err
	}
	if !found {
		return notFound(op)
	}
	if stored != version {
		return failed(op, admin.ErrStaleUpdate)
	}

	return nil
}

// lockRoleFlag is lockRole that also returns the role's stored super-role
// flag.
func lockRoleFlag(q *gorm.DB, op, name string, version int64) (bool, error) {
	var (
		stored int64
		super  bool
	)
	found, err := queryRow(q, op, pgschema.LockAdminRoleFlag, []any{name}, &stored, &super)
	if err != nil {
		return false, err
	}
	if !found {
		return false, notFound(op)
	}
	if stored != version {
		return false, failed(op, admin.ErrStaleUpdate)
	}

	return super, nil
}

// copySuperRole copies flag onto every grant of the role named role, whose
// row the caller has locked, and increases the version of every holder,
// locking them in identifier order first.
func copySuperRole(q *gorm.DB, op, role string, flag bool, now time.Time) error {
	holders, err := lockRoleHolders(q, op, role)
	if err != nil {
		return err
	}
	if len(holders) == 0 {
		return nil
	}

	if err := q.Exec(pgschema.SetHolderSuperRole, role, flag, now).Error; err != nil {
		return dbFailed(op, err)
	}

	_, err = settleGrants(q, op, holders, now)

	return err
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

	// A nil argument is NULL, which UpdateAdminRole reads as unchanged.
	var displayName, description, labels, super any
	if change.DisplayName != nil {
		if !storekit.Storable(*change.DisplayName) {
			return admin.Role{}, invalidInput(op, "the display name holds text that cannot be stored")
		}
		displayName = *change.DisplayName
	}
	if change.Description != nil {
		if !storekit.Storable(*change.Description) {
			return admin.Role{}, invalidInput(op, "the description holds text that cannot be stored")
		}
		description = *change.Description
	}
	if change.Labels != nil {
		for _, l := range *change.Labels {
			if !storekit.Storable(l) {
				return admin.Role{}, invalidInput(op, "a label holds text that cannot be stored")
			}
		}
		labels = pgschema.TextArray(*change.Labels)
	}
	if change.SuperRole != nil {
		super = *change.SuperRole
	}

	var out admin.Role
	err := s.atomically(ctx, op, func(q *gorm.DB) error {
		stored, err := lockRoleFlag(q, op, name, version)
		if err != nil {
			return err
		}

		// Read after the lock: a writer that waited for it stamps the time it
		// wrote, not the time it started waiting.
		now := storekit.Time(s.c.clock.Now())

		if err := q.Exec(pgschema.UpdateAdminRole, name, displayName, description, labels, super, now).Error; err != nil {
			return dbFailed(op, err)
		}

		if change.SuperRole != nil && *change.SuperRole != stored {
			if err := copySuperRole(q, op, name, *change.SuperRole, now); err != nil {
				return err
			}
		}

		out, err = readRole(q, op, name)

		return err
	})

	return out, err
}

// DeleteRole implements admin.RoleStore.
func (s *IdentityStore) DeleteRole(ctx context.Context, name string, version int64, force bool) error {
	const op = "delete role"

	if !storekit.Storable(name) {
		return notFound(op)
	}

	return s.atomically(ctx, op, func(q *gorm.DB) error {
		if err := lockRole(q, op, name, version); err != nil {
			return err
		}

		if !force {
			var held bool
			if _, err := queryRow(q, op, pgschema.RoleHeldByLiveUser, []any{name}, &held); err != nil {
				return err
			}
			if held {
				return failed(op, admin.ErrStillAssigned)
			}
		}

		// Every holder, live or deleted, is locked: the rows of deleted users
		// go with the role and their versions move with them.
		holders, err := lockRoleHolders(q, op, name)
		if err != nil {
			return err
		}

		for _, stmt := range []string{
			pgschema.DeleteAssignmentsOfRole, pgschema.DeletePrivilegesOfRole, pgschema.DeleteAdminRole,
		} {
			if err := q.Exec(stmt, name).Error; err != nil {
				return dbFailed(op, err)
			}
		}

		if len(holders) == 0 {
			return nil
		}

		// Read after the locks, as every write of this file does.
		_, err = settleGrants(q, op, holders, storekit.Time(s.c.clock.Now()))

		return err
	})
}

// lockRoleHolders locks, in identifier order, every user holding a grant of the
// role, and returns their identifiers.
func lockRoleHolders(q *gorm.DB, op, role string) ([]id.ID, error) {
	rows, err := q.Raw(pgschema.LockRoleHolders, role).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var ids []id.ID
	for rows.Next() {
		var uid id.ID
		if err := rows.Scan(&uid); err != nil {
			return nil, scanFailed(op, err)
		}
		ids = append(ids, uid)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	return ids, nil
}

// settleGrants ends every write to the grants of users, whose rows the caller
// has locked: it gives each user holding grants but no primary one the primary
// mark on the grant with the lowest position, points scrty_users.role at the
// primary grant (empty for none) and increases each user's version. It returns
// each user's new version.
func settleGrants(q *gorm.DB, op string, users []id.ID, now time.Time) (map[id.ID]int64, error) {
	ids := uuidArray(users)
	if err := q.Exec(pgschema.PromoteLowestGrant, ids, now).Error; err != nil {
		return nil, dbFailed(op, err)
	}

	rows, err := q.Raw(pgschema.SyncUserPrimaryRole, ids, now).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[id.ID]int64, len(users))
	for rows.Next() {
		var (
			uid     id.ID
			version int64
		)
		if err := rows.Scan(&uid, &version); err != nil {
			return nil, scanFailed(op, err)
		}
		out[uid] = version
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
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

	rows, err := q.Raw(pgschema.GrantsOfRole, role).Rows()
	if err != nil {
		return nil, 0, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var (
		grants  []admin.Grant
		version int64
		found   bool
	)
	for rows.Next() {
		var (
			group, resource, privilege, scope sql.NullString
			granted                           sql.NullBool
		)
		if err := rows.Scan(&version, &group, &resource, &privilege, &granted, &scope); err != nil {
			return nil, 0, scanFailed(op, err)
		}
		found = true
		if !privilege.Valid {
			continue
		}
		grants = append(grants, admin.Grant{
			Group: group.String, Resource: resource.String, Privilege: privilege.String,
			Granted: granted.Bool, Scope: identity.Scope(scope.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, dbFailed(op, err)
	}
	if !found {
		return nil, 0, notFound(op)
	}

	return grants, version, nil
}

// ReplaceGrants implements admin.GrantStore. The rows of a resource are
// matched by group and resource as the authorizer reads them (surrounding
// ASCII space trimmed, ASCII case ignored); the rows it inserts carry the names
// as given.
func (s *IdentityStore) ReplaceGrants(
	ctx context.Context, role string, version int64, resources []admin.ResourceGrants,
) (int64, error) {
	const op = "replace grants"

	if !storekit.Storable(role) {
		return 0, notFound(op)
	}
	plan, err := planGrantWrites(op, resources)
	if err != nil {
		return 0, err
	}

	var next int64
	err = s.atomically(ctx, op, func(q *gorm.DB) error {
		if err := lockRole(q, op, role, version); err != nil {
			return err
		}

		// Read after the lock: the rows and the role carry the time of the write.
		now := storekit.Time(s.c.clock.Now())

		for _, rg := range plan {
			if err := q.Exec(pgschema.DeleteResourcePrivileges, role, rg.Group, rg.Resource).Error; err != nil {
				return dbFailed(op, err)
			}
			for _, g := range rg.Grants {
				gid, err := idgen.New(s.c.ids)
				if err != nil {
					return failed(op, err)
				}
				if err := q.Exec(pgschema.InsertResourcePrivilege, gid, role, g.Group, g.Resource, g.Privilege,
					g.Granted, string(g.Scope), now).Error; err != nil {
					return dbFailed(op, err)
				}
			}
		}

		found, err := queryRow(q, op, pgschema.BumpRoleVersion, []any{role, now}, &next)
		if err != nil {
			return err
		}
		if !found {
			return notFound(op)
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return next, nil
}

// planGrantWrites fills each grant's group, resource and scope, and refuses
// text the database cannot store, an empty resource or privilege name, a grant
// that names another resource than its list, a resource listed twice (two
// spellings of one resource count as one, as the authorizer reads them) and a
// privilege listed twice.
func planGrantWrites(op string, resources []admin.ResourceGrants) ([]admin.ResourceGrants, error) {
	seen := make(map[[2]string]bool, len(resources))
	plan := make([]admin.ResourceGrants, len(resources))

	for i, rg := range resources {
		if rg.Resource == "" {
			return nil, invalidInput(op, "a resource is unnamed")
		}
		if !storekit.Storable(rg.Group, rg.Resource) {
			return nil, invalidInput(op, "a resource holds text that cannot be stored")
		}
		key := [2]string{ascii.ToLower(ascii.TrimSpace(rg.Group)), ascii.ToLower(ascii.TrimSpace(rg.Resource))}
		if seen[key] {
			return nil, invalidInput(op, "a resource is listed twice")
		}
		seen[key] = true

		privileges := make(map[string]bool, len(rg.Grants))
		plan[i] = admin.ResourceGrants{Group: rg.Group, Resource: rg.Resource, Grants: make([]admin.Grant, len(rg.Grants))}
		for j, g := range rg.Grants {
			if g.Group == "" {
				g.Group = rg.Group
			}
			if g.Resource == "" {
				g.Resource = rg.Resource
			}
			if g.Group != rg.Group || g.Resource != rg.Resource {
				return nil, invalidInput(op, "a grant names another resource than its list")
			}
			if g.Privilege == "" {
				return nil, invalidInput(op, "a grant names no privilege")
			}
			if g.Scope == "" {
				g.Scope = identity.ScopeAll
			}
			if !storekit.Storable(g.Privilege, string(g.Scope)) {
				return nil, invalidInput(op, "a grant holds text that cannot be stored")
			}
			if privileges[g.Privilege] {
				return nil, invalidInput(op, "a privilege is listed twice")
			}
			privileges[g.Privilege] = true
			plan[i].Grants[j] = g
		}
	}

	return plan, nil
}

// ListAssignments implements admin.AssignmentStore. The grants and the version
// are read by one statement, so they agree.
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

	rows, err := q.Raw(pgschema.AssignmentsOfUser, uid).Rows()
	if err != nil {
		return nil, 0, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	var (
		out     []*identity.AssignedRole
		version int64
		found   bool
	)
	for rows.Next() {
		var (
			grantID        sql.Null[id.ID]
			name           sql.NullString
			primary, super sql.NullBool
			start, until   *time.Time
		)
		if err := rows.Scan(&version, &grantID, &name, &primary, &super, &start, &until); err != nil {
			return nil, 0, scanFailed(op, err)
		}
		found = true
		if !grantID.Valid {
			continue
		}
		out = append(out, &identity.AssignedRole{
			ID: grantID.V.String(), Name: name.String, Primary: primary.Bool, SuperRole: super.Bool,
			StartDate: fromNull(start), ValidUntil: fromNull(until),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, dbFailed(op, err)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, dbFailed(op, err)
	}
	if !found {
		return nil, 0, notFound(op)
	}

	return out, version, nil
}

// writeAssignment runs write on the locked live user at version, then settles
// the user's grants (a primary grant, scrty_users.role, the version) and
// returns the new version. When shareRole is not empty the role is key-share
// locked before the user's row, which a delete of the role waits for, and its
// super-role flag is handed to write; a role not in the catalogue is
// admin.ErrNotFound.
func (s *IdentityStore) writeAssignment(
	ctx context.Context, op string, ref identity.UserID, version int64, shareRole string,
	write func(q *gorm.DB, uid id.ID, now time.Time, super bool) error,
) (int64, error) {
	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return 0, notFound(op)
	}

	var next int64
	err := s.atomically(ctx, op, func(q *gorm.DB) error {
		// The role first, then the user: the order every writer locks in.
		var super bool
		if shareRole != "" {
			found, err := queryRow(q, op, pgschema.ShareAdminRole, []any{shareRole}, &super)
			if err != nil {
				return err
			}
			if !found {
				return failed(op, fmt.Errorf("%w: the role is not in the catalogue", admin.ErrNotFound))
			}
		}
		if _, err := lockAdminUser(q, op, uid, version); err != nil {
			return err
		}

		// Read after the locks, so the grant and the user carry the time of the write.
		now := storekit.Time(s.c.clock.Now())

		if err := write(q, uid, now, super); err != nil {
			return err
		}

		versions, err := settleGrants(q, op, []id.ID{uid}, now)
		if err != nil {
			return err
		}
		v, ok := versions[uid]
		if !ok {
			// The user's row lock is held, so the row cannot be gone.
			return failed(op, errors.New("the locked user row is missing"))
		}
		next = v

		return nil
	})
	if err != nil {
		return 0, err
	}

	return next, nil
}

// AddAssignment implements admin.AssignmentStore. The grant takes the role's
// super-role flag and the position after the user's last grant. A primary
// assignment, or the first grant of a user who has no primary one, becomes the
// user's only primary grant.
func (s *IdentityStore) AddAssignment(
	ctx context.Context, ref identity.UserID, version int64, a admin.Assignment,
) (int64, error) {
	const op = "add assignment"

	// An empty name is a role no catalogue holds: not found, as the other
	// adapters answer it.
	if !storekit.Storable(a.Role) || a.Role == "" {
		return 0, notFound(op)
	}

	return s.writeAssignment(ctx, op, ref, version, a.Role,
		func(q *gorm.DB, uid id.ID, now time.Time, super bool) error {
			if a.Primary {
				if err := q.Exec(pgschema.ClearPrimaryGrant, uid, now).Error; err != nil {
					return dbFailed(op, err)
				}
			}

			var position int64
			if _, err := queryRow(q, op, pgschema.NextGrantPosition, []any{uid}, &position); err != nil {
				return err
			}

			gid, err := idgen.New(s.c.ids)
			if err != nil {
				return failed(op, err)
			}
			if err := q.Exec(pgschema.InsertGrant, gid, uid, a.Role, position, a.Primary, super,
				nullTs(a.Start), nullTs(a.End), now, now).Error; err != nil {
				return dbFailed(op, err)
			}

			return nil
		})
}

// RemoveAssignment implements admin.AssignmentStore. When the removed grant was
// primary, the remaining grant assigned first becomes primary.
func (s *IdentityStore) RemoveAssignment(
	ctx context.Context, ref identity.UserID, version int64, grantID string,
) (int64, error) {
	const op = "remove assignment"

	return s.writeAssignment(ctx, op, ref, version, "", func(q *gorm.DB, uid id.ID, _ time.Time, _ bool) error {
		gid, ok := storekit.ParseUserID(identity.UserID(grantID))
		if !ok {
			return notFound(op)
		}

		res := q.Exec(pgschema.DeleteGrantOfUser, gid, uid)
		if res.Error != nil {
			return dbFailed(op, res.Error)
		}
		if res.RowsAffected == 0 {
			return notFound(op)
		}

		return nil
	})
}

// SetPrimary implements admin.AssignmentStore.
func (s *IdentityStore) SetPrimary(
	ctx context.Context, ref identity.UserID, version int64, grantID string,
) (int64, error) {
	const op = "set primary assignment"

	return s.writeAssignment(ctx, op, ref, version, "", func(q *gorm.DB, uid id.ID, now time.Time, _ bool) error {
		gid, ok := storekit.ParseUserID(identity.UserID(grantID))
		if !ok {
			return notFound(op)
		}

		var held bool
		if _, err := queryRow(q, op, pgschema.GrantOfUser, []any{gid, uid}, &held); err != nil {
			return err
		}
		if !held {
			return notFound(op)
		}

		if err := q.Exec(pgschema.MarkPrimaryGrant, uid, gid, now).Error; err != nil {
			return dbFailed(op, err)
		}

		return nil
	})
}
