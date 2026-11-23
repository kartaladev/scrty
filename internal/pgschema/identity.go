package pgschema

import "strings"

// Identity statements: users, their role grants, organizations, groups,
// role privileges and password history. No identity table joins to another
// by a foreign key; the loaders below run as separate queries and treat a
// dangling organization, group or role reference as absent.
const (
	// UserByUsername reads the live user row with username $1, without the
	// email columns. A soft-deleted user (deleted_at set) is no row.
	UserByUsername = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at
FROM scrty_users WHERE username = $1 AND deleted_at IS NULL`

	// UserByID reads the live user row with id $1, without the email columns.
	// A soft-deleted user is no row.
	UserByID = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at
FROM scrty_users WHERE id = $1 AND deleted_at IS NULL`

	// UserRecordByUsername reads the live user row with username $1: the
	// columns of UserByUsername followed by email and email_verified_at. A
	// soft-deleted user is no row.
	UserRecordByUsername = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at, email, email_verified_at
FROM scrty_users WHERE username = $1 AND deleted_at IS NULL`

	// UserRecordByID reads the live user row with id $1, with the columns of
	// UserRecordByUsername. A soft-deleted user is no row.
	UserRecordByID = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at, email, email_verified_at
FROM scrty_users WHERE id = $1 AND deleted_at IS NULL`

	// UserRecordByVerifiedEmail reads the live user whose verified email is
	// $1, ignoring case, with the columns of UserRecordByUsername. An
	// unverified email, a deleted user and no match are all no row. The
	// predicate repeats the partial unique index scrty_users_email_live, so
	// the index serves it and at most one row matches.
	UserRecordByVerifiedEmail = `SELECT id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at, email, email_verified_at
FROM scrty_users
WHERE lower(email) = lower($1) AND email IS NOT NULL AND deleted_at IS NULL
  AND email_verified_at IS NOT NULL`

	// GrantsByUser reads every role grant of user $1, the primary grant
	// first and otherwise in stored position order. Position, not the grant's
	// own identifier, decides that order: a replaceable identifier generator
	// need not sort in creation order. The identifier is only the final
	// tie-breaker, so two grants sharing a position still read back in the
	// same order every time.
	GrantsByUser = `SELECT id, role_name, position, is_primary, super_role, start_date, valid_until,
  created_at, updated_at
FROM scrty_assigned_roles WHERE user_id = $1 ORDER BY is_primary DESC, position, id`

	// GrantsByUserInPosition reads every role grant of user $1 in stored
	// position order, whichever is primary. An update's grant rebuild reads
	// it to keep the first stored grant of a repeated name: position, never
	// the identifier, decides which one is first.
	GrantsByUserInPosition = `SELECT id, role_name, position, is_primary, super_role, start_date, valid_until,
  created_at, updated_at
FROM scrty_assigned_roles WHERE user_id = $1 ORDER BY position, id`

	// OrganizationByID reads the organization with id $1. No row is not an
	// error: the caller treats a dangling reference as no organization.
	OrganizationByID = `SELECT id, name, group_id, created_at, updated_at FROM scrty_organizations WHERE id = $1`

	// GroupByID reads the group with id $1. No row is not an error: an
	// organization whose group_id resolves to nothing loads without one.
	GroupByID = `SELECT id, name, internal, created_at, updated_at FROM scrty_groups WHERE id = $1`

	// PrivilegesByRole reads every privilege entry of role $1, ordered by
	// resource group, resource and privilege. Denied entries are included;
	// the caller decides what an absence means.
	PrivilegesByRole = `SELECT id, role_name, resource_group, resource, privilege, granted, created_at, updated_at
FROM scrty_resource_privileges WHERE role_name = $1 ORDER BY resource_group, resource, privilege`

	// ScopedPrivilegesByRole reads what PrivilegesByRole reads, with each
	// entry's scope as the last column. The scope is returned as stored: a
	// row written before the column existed holds its default, 'all'.
	ScopedPrivilegesByRole = `SELECT id, role_name, resource_group, resource, privilege, granted, created_at, updated_at,
  scope
FROM scrty_resource_privileges WHERE role_name = $1 ORDER BY resource_group, resource, privilege`

	// InsertUser stores a user, with no email: $1 id, $2 name, $3 username, $4 password,
	// $5 active, $6 role (the primary role name), $7 organization_id (NULL
	// when absent), $8 password_changed_at (NULL when the caller did not
	// name it), $9 mfa_required, $10 created_at, $11 updated_at. Zero rows
	// affected means the username is already taken; there is no preceding
	// SELECT, because the insert itself is the collision check.
	InsertUser = `INSERT INTO scrty_users (id, name, username, password, active, role, organization_id,
  password_changed_at, mfa_required, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (username) DO NOTHING`

	// LockUserByUsername reads the id of the user with username $1 and locks
	// the row, so a concurrent update serializes behind it. No row is
	// user-not-found.
	// A soft-deleted user is no row, so an update never reaches one.
	LockUserByUsername = `SELECT id FROM scrty_users WHERE username = $1 AND deleted_at IS NULL FOR UPDATE`

	// BumpUserVersion increases the version of user $1 by one. The identity
	// port's update runs it after every write it makes to the user, so an
	// administrator's earlier read of the user becomes stale; the port itself
	// never compares the version.
	BumpUserVersion = `UPDATE scrty_users SET version = version + 1 WHERE id = $1`

	// IdentifierLockKeys returns the advisory lock key of every identifier
	// (username or email) in the text[] $1: hashtextextended(lower(value), 0),
	// one row per distinct key, in ascending key order. Empty and NULL elements
	// guard nothing and are left out.
	//
	// Every write that sets a username or an email runs it for the values it
	// sets, then takes LockIdentifierKey for each returned key, in the order
	// returned, before it checks that a value is not another live user's
	// username or email: a constraint cannot span the two columns, so the
	// locks are what serialise a username and an email racing to coincide.
	// The order is the key's own, computed by the server from the very
	// expression the lock uses, so two writers locking overlapping values
	// always take them in the same order and cannot deadlock, whatever order
	// or letter case they named them in. The locks are taken one statement per
	// key rather than in this statement, because the order in which a single
	// SELECT evaluates a volatile function across its rows is planner
	// behaviour, not a documented guarantee. Two values that share a key only
	// serialise two unrelated writes.
	IdentifierLockKeys = `SELECT DISTINCT hashtextextended(lower(v), 0) AS lock_key
FROM unnest($1::text[]) AS v
WHERE v IS NOT NULL AND v <> ''
ORDER BY lock_key`

	// LockIdentifierKey takes the transaction-scoped advisory lock with key
	// $1, as IdentifierLockKeys returns it. It is held until the transaction
	// ends, and a session may hold it more than once.
	LockIdentifierKey = `SELECT pg_advisory_xact_lock($1::bigint)`

	// EmailHeldByLiveUser reports whether a live user other than the one with
	// id $2 holds $1 as its email, verified or not, ignoring case. A NULL $2
	// excludes nobody, as provisioning a user who has no id yet needs. Run it
	// holding the lock IdentifierLockKeys gives $1.
	EmailHeldByLiveUser = `SELECT EXISTS (SELECT 1 FROM scrty_users
WHERE lower(email) = lower($1) AND email IS NOT NULL AND deleted_at IS NULL
  AND id IS DISTINCT FROM $2::uuid)`

	// UsernameHeldByLiveUser reports whether a live user other than the one
	// with id $2 holds $1 as its username, ignoring case: the check a write
	// setting $1 as an email makes. A NULL $2 excludes nobody. Run it holding
	// the lock IdentifierLockKeys gives $1.
	UsernameHeldByLiveUser = `SELECT EXISTS (SELECT 1 FROM scrty_users
WHERE lower(username) = lower($1) AND deleted_at IS NULL AND id IS DISTINCT FROM $2::uuid)`

	// DeleteGrantsByUser removes every role grant of user $1, the first half
	// of a grant rebuild that InsertGrant completes.
	DeleteGrantsByUser = `DELETE FROM scrty_assigned_roles WHERE user_id = $1`

	// InsertGrant stores one role grant: $1 id, $2 user_id, $3 role_name,
	// $4 position, $5 is_primary, $6 super_role, $7 start_date (NULL when
	// unset), $8 valid_until (NULL when unset), $9 created_at, $10 updated_at.
	InsertGrant = `INSERT INTO scrty_assigned_roles (id, user_id, role_name, position, is_primary, super_role,
  start_date, valid_until, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	// MFARequiredByID reads the MFA-required flag of the user with id $1. No
	// row is user-not-found: the caller never reads a missing user as "not
	// required".
	// A soft-deleted user is no row, so it is reported as an unknown one.
	MFARequiredByID = `SELECT mfa_required FROM scrty_users WHERE id = $1 AND deleted_at IS NULL`

	// NewestHistory reads the newest retired password hash of user $1, if
	// any. RetirePassword uses it to skip recording the same bytes twice in
	// a row.
	NewestHistory = `SELECT password FROM scrty_password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT 1`

	// InsertHistory retires one password hash: $1 id, $2 user_id, $3 password,
	// $4 retired_at. seq is assigned by the table itself, so the newest row
	// is always the one with the greatest seq.
	InsertHistory = `INSERT INTO scrty_password_history (id, user_id, password, retired_at) VALUES ($1, $2, $3, $4)`

	// PruneHistory keeps the newest $2 retired passwords of user $1, by seq,
	// and removes the rest. $2 must be >= 0 and never NULL: a NULL LIMIT
	// keeps every row, so a NULL $2 deletes nothing. A retire with keep 0
	// must not insert at all; the store runs ForgetHistory instead of
	// InsertHistory followed by PruneHistory with $2 = 0.
	PruneHistory = `DELETE FROM scrty_password_history WHERE user_id = $1 AND seq NOT IN (
  SELECT seq FROM scrty_password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT $2)`

	// RecentHistory reads up to $2 of user $1's retired password hashes,
	// newest first.
	RecentHistory = `SELECT password FROM scrty_password_history WHERE user_id = $1 ORDER BY seq DESC LIMIT $2`

	// ForgetHistory removes every retired password of user $1.
	ForgetHistory = `DELETE FROM scrty_password_history WHERE user_id = $1`
)

// TextArray is values as a PostgreSQL text[] literal, for a driver that binds
// no Go slice as an array (database/sql in general). Every element is
// double-quoted, with its quotes and backslashes escaped, so no element is
// read as NULL or split. values must be storable text (no NUL byte); the
// writes refuse any other before they get here.
func TextArray(values []string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(arrayEscaper.Replace(v))
		b.WriteByte('"')
	}
	b.WriteByte('}')

	return b.String()
}

// arrayEscaper escapes the two characters a quoted array element cannot hold
// bare.
var arrayEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)
