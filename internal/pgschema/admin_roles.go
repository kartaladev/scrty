package pgschema

import (
	"encoding/json"
	"fmt"
)

// Administration statements for the role, grant and assignment ports of
// package admin, over the identity tables.
//
// Locks are always taken in one order, so no two writers wait on each other in
// a cycle: role rows first, then user rows, users in identifier order. A role
// write (update, grant replacement, deletion) locks the role row FOR UPDATE;
// a deletion, and an update that changes the super-role flag, then lock the
// role's holders with LockRoleHolders. An import takes its own advisory lock
// (LockImportIdentifier) before any of these. A write that reads a role to grant it to a user (an assignment, an import)
// locks the role row FOR KEY SHARE before the user's row, so a role being
// deleted cannot gain a holder the deletion did not see, while grant
// replacements and assignments of one role do not wait on each other for
// long. A write to a user's grants locks the user's row (LockAdminUser) and
// increases the user's version with SyncUserPrimaryRole; a role's grants
// share the role's version.
const (
	// adminRoleColumns is the column list every administration read of a
	// role selects, in this order: name, display_name, description, labels
	// as a JSON array (see ParseLabels), super_role, version, and the number
	// of live users holding a grant of the role.
	adminRoleColumns = `r.name, r.display_name, r.description, array_to_json(r.labels)::text, r.super_role,
  r.version,
  (SELECT count(DISTINCT a.user_id) FROM scrty_assigned_roles a JOIN scrty_users u ON u.id = a.user_id
   WHERE a.role_name = r.name AND u.deleted_at IS NULL)`

	// ListAdminRoles reads every role ordered by name, in the columns of
	// adminRoleColumns; only roles carrying label $1 when $1 is not ''.
	ListAdminRoles = `SELECT ` + adminRoleColumns + `
FROM scrty_roles r WHERE ($1::text = '' OR $1::text = ANY(r.labels)) ORDER BY r.name`

	// AdminRoleByName reads the role named $1 in the columns of
	// adminRoleColumns.
	AdminRoleByName = `SELECT ` + adminRoleColumns + `
FROM scrty_roles r WHERE r.name = $1`

	// InsertAdminRole stores a role at version 1: $1 id, $2 name,
	// $3 display_name, $4 description, $5 labels (text[]), $6 super_role,
	// $7 created_at and updated_at. A taken name inserts nothing and is no
	// error: zero rows affected is the collision.
	InsertAdminRole = `INSERT INTO scrty_roles (id, name, display_name, description, labels, super_role, version,
  created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::text[], $6, 1, $7, $7)
ON CONFLICT (name) DO NOTHING`

	// LockAdminRole reads the version of the role named $1 and locks the row
	// FOR UPDATE until the transaction ends. Every versioned role write takes
	// it first, then compares the version.
	LockAdminRole = `SELECT version FROM scrty_roles WHERE name = $1 FOR UPDATE`

	// ShareAdminRole reads the super-role flag of the role named $1 and
	// locks the row FOR KEY SHARE, so the role cannot be deleted until the
	// transaction ends. An assignment takes it before the user's row lock.
	ShareAdminRole = `SELECT super_role FROM scrty_roles WHERE name = $1 FOR KEY SHARE`

	// UpdateAdminRole writes the role named $1: $2 display_name,
	// $3 description, $4 labels (text[]), $5 super_role, each NULL when
	// unchanged, and $6 updated_at, and increases the version. Run it
	// holding LockAdminRole.
	UpdateAdminRole = `UPDATE scrty_roles SET display_name = COALESCE($2::text, display_name),
  description = COALESCE($3::text, description), labels = COALESCE($4::text[], labels),
  super_role = COALESCE($5::boolean, super_role), updated_at = $6, version = version + 1
WHERE name = $1`

	// LockAdminRoleFlag reads the version and the super-role flag of the role
	// named $1 and locks the row FOR UPDATE until the transaction ends. A role
	// update takes it in place of LockAdminRole, to tell whether the flag
	// changes.
	LockAdminRoleFlag = `SELECT version, super_role FROM scrty_roles WHERE name = $1 FOR UPDATE`

	// SetHolderSuperRole sets the super_role flag of every grant of the role
	// named $1 to $2, and its updated_at to $3, on the grants whose flag
	// differs. A role update that changes the flag runs it holding
	// LockAdminRoleFlag and LockRoleHolders, then increases each holder's
	// version, because the authorizer reads the flag from the grant.
	SetHolderSuperRole = `UPDATE scrty_assigned_roles SET super_role = $2, updated_at = $3
WHERE role_name = $1 AND super_role IS DISTINCT FROM $2`

	// BumpRoleVersion increases the version of the role named $1, sets its
	// updated_at to $2, and returns the new version. A grant replacement runs
	// it, holding LockAdminRole.
	BumpRoleVersion = `UPDATE scrty_roles SET updated_at = $2, version = version + 1 WHERE name = $1 RETURNING version`

	// RoleHeldByLiveUser reports whether a live user holds a grant of the
	// role named $1. Grants of soft-deleted users do not count.
	RoleHeldByLiveUser = `SELECT EXISTS (SELECT 1 FROM scrty_assigned_roles a JOIN scrty_users u ON u.id = a.user_id
  WHERE a.role_name = $1 AND u.deleted_at IS NULL)`

	// LockRoleHolders locks, in identifier order, the row of every user,
	// live or deleted, holding a grant of the role named $1, and returns
	// their ids. A role deletion takes it holding LockAdminRole, and a role
	// update that changes the super-role flag holding LockAdminRoleFlag.
	LockRoleHolders = `SELECT id FROM scrty_users
WHERE id IN (SELECT user_id FROM scrty_assigned_roles WHERE role_name = $1)
ORDER BY id FOR UPDATE`

	// DeleteAssignmentsOfRole removes every user's grant of the role named $1.
	DeleteAssignmentsOfRole = `DELETE FROM scrty_assigned_roles WHERE role_name = $1`

	// DeletePrivilegesOfRole removes every privilege of the role named $1.
	DeletePrivilegesOfRole = `DELETE FROM scrty_resource_privileges WHERE role_name = $1`

	// DeleteAdminRole removes the role named $1 from the catalogue.
	DeleteAdminRole = `DELETE FROM scrty_roles WHERE name = $1`

	// GrantsOfRole reads the version of the role named $1 and every one of
	// its privileges, in one statement so the two agree: version,
	// resource_group, resource, privilege, granted, scope. A role with no
	// privilege is one row whose privilege columns are NULL; no row is no
	// role.
	GrantsOfRole = `SELECT r.version, p.resource_group, p.resource, p.privilege, p.granted, p.scope
FROM scrty_roles r LEFT JOIN scrty_resource_privileges p ON p.role_name = r.name
WHERE r.name = $1
ORDER BY p.resource_group, p.resource, p.privilege`

	// DeleteResourcePrivileges removes the privileges of the role named $1
	// on resource $3 of group $2, matching the stored group and resource as
	// the authorizer reads them: surrounding ASCII whitespace trimmed and
	// ASCII case ignored, nothing wider (see asciiFold). translate() and
	// btrim() with an explicit set act on those bytes alone, unlike lower(),
	// which folds by the database's collation and can fold beyond ASCII.
	DeleteResourcePrivileges = `DELETE FROM scrty_resource_privileges
WHERE role_name = $1
  AND ` + asciiFoldResourceGroup + ` = ` + asciiFoldArg2 + `
  AND ` + asciiFoldResource + ` = ` + asciiFoldArg3

	// asciiSpace is the ASCII whitespace the authorizer trims: space, tab,
	// newline, vertical tab (chr(11)), form feed and carriage return.
	asciiSpace = `(E' \t\n\f\r' || chr(11))`
	// asciiUpper and asciiLower are the letters translate() maps one to one.
	asciiUpper = `'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`
	asciiLower = `'abcdefghijklmnopqrstuvwxyz'`

	asciiFoldResourceGroup = `translate(btrim(resource_group, ` + asciiSpace + `), ` + asciiUpper + `, ` + asciiLower + `)`
	asciiFoldResource      = `translate(btrim(resource, ` + asciiSpace + `), ` + asciiUpper + `, ` + asciiLower + `)`
	asciiFoldArg2          = `translate(btrim($2::text, ` + asciiSpace + `), ` + asciiUpper + `, ` + asciiLower + `)`
	asciiFoldArg3          = `translate(btrim($3::text, ` + asciiSpace + `), ` + asciiUpper + `, ` + asciiLower + `)`

	// InsertResourcePrivilege stores one privilege: $1 id, $2 role_name,
	// $3 resource_group, $4 resource, $5 privilege, $6 granted, $7 scope,
	// $8 created_at and updated_at.
	InsertResourcePrivilege = `INSERT INTO scrty_resource_privileges (id, role_name, resource_group, resource, privilege,
  granted, scope, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`

	// AssignmentsOfUser reads the version of the live user $1 and every one
	// of its grants, in one statement so the two agree: version, then the
	// columns of GrantsByUser, primary first, then in stored position. A user
	// with no grant is one row whose grant columns are NULL; no row is no
	// live user.
	AssignmentsOfUser = `SELECT u.version, a.id, a.role_name, a.is_primary, a.super_role, a.start_date, a.valid_until
FROM scrty_users u LEFT JOIN scrty_assigned_roles a ON a.user_id = u.id
WHERE u.id = $1 AND u.deleted_at IS NULL
ORDER BY a.is_primary DESC, a.position, a.id`

	// NextGrantPosition is the position after the last of user $1's grants:
	// 0 for a user with none.
	NextGrantPosition = `SELECT COALESCE(max(position) + 1, 0) FROM scrty_assigned_roles WHERE user_id = $1`

	// ClearPrimaryGrant removes the primary mark from user $1's grants,
	// setting updated_at $2 on each grant it changes.
	ClearPrimaryGrant = `UPDATE scrty_assigned_roles SET is_primary = false, updated_at = $2
WHERE user_id = $1 AND is_primary`

	// GrantOfUser reports whether user $2 holds the grant with id $1.
	GrantOfUser = `SELECT EXISTS (SELECT 1 FROM scrty_assigned_roles WHERE id = $1 AND user_id = $2)`

	// MarkPrimaryGrant makes grant $2 user $1's only primary grant, setting
	// updated_at $3 on each grant whose mark changes. Run it after
	// GrantOfUser found the grant.
	MarkPrimaryGrant = `UPDATE scrty_assigned_roles SET is_primary = (id = $2), updated_at = $3
WHERE user_id = $1 AND is_primary IS DISTINCT FROM (id = $2)`

	// DeleteGrantOfUser removes the grant with id $1 of user $2. Zero rows
	// affected is no such grant.
	DeleteGrantOfUser = `DELETE FROM scrty_assigned_roles WHERE id = $1 AND user_id = $2`

	// PromoteLowestGrant gives the primary mark, for every user in the
	// uuid[] $1 who holds grants but no primary one, to that user's grant
	// with the lowest position (the identifier breaks a tie), setting its
	// updated_at to $2. A user with no grant is left with none.
	PromoteLowestGrant = `UPDATE scrty_assigned_roles a SET is_primary = true, updated_at = $2
WHERE a.id IN (
  SELECT DISTINCT ON (g.user_id) g.id FROM scrty_assigned_roles g
  WHERE g.user_id = ANY($1::uuid[])
  ORDER BY g.user_id, g.position, g.id)
AND NOT EXISTS (SELECT 1 FROM scrty_assigned_roles p WHERE p.user_id = a.user_id AND p.is_primary)`

	// SyncUserPrimaryRole sets scrty_users.role of every user in the uuid[]
	// $1 to the name of that user's primary grant (empty for none), its
	// updated_at to $2, and increases its version; it returns the id and the
	// new version of each. Every write to a user's grants ends with it,
	// holding the user's row lock.
	SyncUserPrimaryRole = `UPDATE scrty_users u SET role = COALESCE((
    SELECT a.role_name FROM scrty_assigned_roles a WHERE a.user_id = u.id
    ORDER BY a.is_primary DESC, a.position, a.id LIMIT 1), ''),
  updated_at = $2, version = version + 1
WHERE u.id = ANY($1::uuid[])
RETURNING u.id, u.version`
)

// ParseLabels decodes the labels column as adminRoleColumns selects it, a
// JSON array of text. An empty array, or JSON null, is no labels (nil).
func ParseLabels(raw string) ([]string, error) {
	var labels []string
	if err := json.Unmarshal([]byte(raw), &labels); err != nil {
		return nil, fmt.Errorf("pgschema: decode role labels: %w", err)
	}
	if len(labels) == 0 {
		return nil, nil
	}

	return labels, nil
}
