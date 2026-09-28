package pgschema

// Identity statements: users, their role grants, organizations, groups,
// role privileges and password history. No identity table joins to another
// by a foreign key; the loaders below run as separate queries and treat a
// dangling organization, group or role reference as absent.
const (
	// UserByUsername reads the user row with username $1.
	UserByUsername = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at
FROM users WHERE username = $1`

	// UserByID reads the user row with id $1.
	UserByID = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at
FROM users WHERE id = $1`

	// GrantsByUser reads every role grant of user $1, the primary grant
	// first and otherwise in stored position order. Position, not the grant's
	// own identifier, decides that order: a replaceable identifier generator
	// need not sort in creation order. The identifier is only the final
	// tie-breaker, so two grants sharing a position still read back in the
	// same order every time.
	GrantsByUser = `SELECT id, role_name, position, is_primary, super_role, start_date, valid_until,
  created_at, updated_at
FROM assigned_roles WHERE user_id = $1 ORDER BY is_primary DESC, position, id`

	// GrantsByUserInPosition reads every role grant of user $1 in stored
	// position order, whichever is primary. An update's grant rebuild reads
	// it to keep the first stored grant of a repeated name: position, never
	// the identifier, decides which one is first.
	GrantsByUserInPosition = `SELECT id, role_name, position, is_primary, super_role, start_date, valid_until,
  created_at, updated_at
FROM assigned_roles WHERE user_id = $1 ORDER BY position, id`

	// OrganizationByID reads the organization with id $1. No row is not an
	// error: the caller treats a dangling reference as no organization.
	OrganizationByID = `SELECT id, name, group_id, created_at, updated_at FROM organizations WHERE id = $1`

	// GroupByID reads the group with id $1. No row is not an error: an
	// organization whose group_id resolves to nothing loads without one.
	GroupByID = `SELECT id, name, internal, created_at, updated_at FROM groups WHERE id = $1`

	// PrivilegesByRole reads every privilege entry of role $1, ordered by
	// resource group, resource and privilege. Denied entries are included;
	// the caller decides what an absence means.
	PrivilegesByRole = `SELECT id, role_name, resource_group, resource, privilege, granted, created_at, updated_at
FROM resource_privileges WHERE role_name = $1 ORDER BY resource_group, resource, privilege`

	// InsertUser stores a user: $1 id, $2 name, $3 username, $4 password,
	// $5 active, $6 role (the primary role name), $7 organization_id (NULL
	// when absent), $8 password_changed_at (NULL when the caller did not
	// name it), $9 mfa_required, $10 created_at, $11 updated_at. Zero rows
	// affected means the username is already taken; there is no preceding
	// SELECT, because the insert itself is the collision check.
	InsertUser = `INSERT INTO users (id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (username) DO NOTHING`

	// LockUserByUsername reads the id of the user with username $1 and locks
	// the row, so a concurrent update serializes behind it. No row is
	// user-not-found.
	LockUserByUsername = `SELECT id FROM users WHERE username = $1 FOR UPDATE`

	// DeleteGrantsByUser removes every role grant of user $1, the first half
	// of a grant rebuild that InsertGrant completes.
	DeleteGrantsByUser = `DELETE FROM assigned_roles WHERE user_id = $1`

	// InsertGrant stores one role grant: $1 id, $2 user_id, $3 role_name,
	// $4 position, $5 is_primary, $6 super_role, $7 start_date (NULL when
	// unset), $8 valid_until (NULL when unset), $9 created_at, $10 updated_at.
	InsertGrant = `INSERT INTO assigned_roles (id, user_id, role_name, position, is_primary, super_role,
  start_date, valid_until, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	// MFARequiredByID reads the MFA-required flag of the user with id $1. No
	// row is user-not-found: the caller never reads a missing user as "not
	// required".
	MFARequiredByID = `SELECT mfa_required FROM users WHERE id = $1`

	// NewestHistory reads the newest retired password hash of user $1, if
	// any. RetirePassword uses it to skip recording the same bytes twice in
	// a row.
	NewestHistory = `SELECT password FROM password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT 1`

	// InsertHistory retires one password hash: $1 id, $2 user_id, $3 password,
	// $4 retired_at. seq is assigned by the table itself, so the newest row
	// is always the one with the greatest seq.
	InsertHistory = `INSERT INTO password_history (id, user_id, password, retired_at) VALUES ($1, $2, $3, $4)`

	// PruneHistory keeps the newest $2 retired passwords of user $1, by seq,
	// and removes the rest. $2 must be >= 0 and never NULL: a NULL LIMIT
	// keeps every row, so a NULL $2 deletes nothing. A retire with keep 0
	// must not insert at all; the store runs ForgetHistory instead of
	// InsertHistory followed by PruneHistory with $2 = 0.
	PruneHistory = `DELETE FROM password_history WHERE user_id = $1 AND seq NOT IN (
  SELECT seq FROM password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT $2)`

	// RecentHistory reads up to $2 of user $1's retired password hashes,
	// newest first.
	RecentHistory = `SELECT password FROM password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT $2`

	// ForgetHistory removes every retired password of user $1.
	ForgetHistory = `DELETE FROM password_history WHERE user_id = $1`
)
