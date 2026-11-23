package pgschema

import (
	"strconv"
	"strings"
)

// Administration statements: the user and import ports of package admin, over
// the identity tables. Every write that compares a version first locks the
// user's row with one of the Lock statements below, so writers to one user
// apply one after another; the identifier checks of identity.go
// (IdentifierLockKeys, LockIdentifierKey, EmailHeldByLiveUser,
// UsernameHeldByLiveUser) guard usernames and emails, as they do for
// provisioning.

// ImportLockClass is the first key of LockImportIdentifier's two-key advisory
// lock: the ASCII bytes "scrt" read as an int4. It marks the lock as scrty's
// import lock; the single-key locks the other statements take are in a
// different lock space and cannot collide with it.
const ImportLockClass int32 = 0x73637274

// importLockClassSQL is ImportLockClass as SQL text.
const importLockClassSQL = "1935897204::int4"

const (
	// adminUserColumns is the column list every administration read of a
	// user selects, in this order: id, username, name, email,
	// email_verified_at, active, organization_id, version, created_at,
	// updated_at.
	adminUserColumns = `id, username, name, email, email_verified_at, active, organization_id, version,
  created_at, updated_at`

	// AdminUserByID reads the live user with id $1, in the columns of
	// adminUserColumns. A soft-deleted user is no row.
	AdminUserByID = `SELECT ` + adminUserColumns + `
FROM scrty_users WHERE id = $1 AND deleted_at IS NULL`

	// LockAdminUser reads the version, email, password and active flag of the live user
	// with id $1 and locks the row until the transaction ends. A soft-deleted
	// user is no row. Every versioned write takes it first, then compares the
	// version.
	LockAdminUser = `SELECT version, email, password, active
FROM scrty_users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`

	// ListAdminUsers reads up to $8 live users ordered by (lower(username),
	// id), in the columns of adminUserColumns:
	//   - $1 is a LIKE pattern (LikePattern) matched with ILIKE against the
	//     username, the display name and the email; '' matches every user;
	//   - $2, when not NULL, keeps only users whose active flag equals it;
	//   - $3, when not '', keeps only users holding a grant of role $3;
	//   - $4, when not NULL, keeps only users with attribute $4 equal to $5;
	//   - $6, when not '', keeps only users strictly after the pair
	//     (lower($6), $7) in the list order.
	//
	// The order and the cursor comparison fold case with the same lower(), so
	// they agree for every script; the index scrty_users_username_lower serves
	// both.
	ListAdminUsers = `SELECT ` + adminUserColumns + `
FROM scrty_users u
WHERE u.deleted_at IS NULL
  AND ($1::text = '' OR u.username ILIKE $1 OR u.name ILIKE $1 OR u.email ILIKE $1)
  AND ($2::boolean IS NULL OR u.active = $2::boolean)
  AND ($3::text = '' OR EXISTS (SELECT 1 FROM scrty_assigned_roles r
       WHERE r.user_id = u.id AND r.role_name = $3::text))
  AND ($4::text IS NULL OR EXISTS (SELECT 1 FROM scrty_user_attributes a
       WHERE a.user_id = u.id AND a.name = $4::text AND a.value = $5::text))
  AND ($6::text = '' OR (lower(u.username), u.id) > (lower($6::text), $7::uuid))
ORDER BY lower(u.username), u.id
LIMIT $8`

	// GrantsByUsers reads every role grant of the users whose ids are in the
	// uuid[] $1, in the columns of GrantsByUser preceded by user_id, each
	// user's primary grant first and otherwise in stored position order.
	GrantsByUsers = `SELECT user_id, id, role_name, position, is_primary, super_role, start_date, valid_until,
  created_at, updated_at
FROM scrty_assigned_roles WHERE user_id = ANY($1::uuid[]) ORDER BY user_id, is_primary DESC, position, id`

	// AttributesByUsers reads every profile attribute of the users whose ids
	// are in the uuid[] $1: user_id, name, value.
	AttributesByUsers = `SELECT user_id, name, value FROM scrty_user_attributes WHERE user_id = ANY($1::uuid[])`

	// InsertAdminUser stores a new user: $1 id, $2 username, $3 name,
	// $4 email (NULL for none), $5 email_verified_at (NULL for none),
	// $6 password, $7 active, $8 role (the primary role name),
	// $9 organization_id (NULL for none), $10 created_at, $11 updated_at. The
	// version starts at its default, 1. It has no conflict target: a taken id,
	// username or live email all make it insert nothing, and the caller reads
	// which one it was. Zero rows affected is that collision, never an error,
	// so the transaction stays usable for the reads that tell which.
	InsertAdminUser = `INSERT INTO scrty_users (id, username, name, email, email_verified_at, password, active,
  role, organization_id, mfa_required, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, $10, $11)
ON CONFLICT DO NOTHING`

	// UsernameTaken reports whether a user other than the one with id $2,
	// deleted or not, holds the username $1 exactly: the username's unique
	// constraint compares byte for byte, and a deleted user keeps its
	// username. A NULL $2 excludes nobody.
	UsernameTaken = `SELECT EXISTS (SELECT 1 FROM scrty_users WHERE username = $1 AND id IS DISTINCT FROM $2::uuid)`

	// UserIDTaken reports whether a user, deleted or not, has the id $1.
	UserIDTaken = `SELECT EXISTS (SELECT 1 FROM scrty_users WHERE id = $1)`

	// SetUserActive sets the active flag of user $1 to $2, its updated_at to
	// $3, and increases its version. Run it holding LockAdminUser.
	SetUserActive = `UPDATE scrty_users SET active = $2, updated_at = $3, version = version + 1 WHERE id = $1`

	// SoftDeleteUser marks user $1 deleted at $2: inactive, with no email and
	// no verification time, and its version increased. The row and its
	// username stay. Run it holding LockAdminUser, with
	// DeleteAttributesByUser and ForgetHistory in the same transaction.
	SoftDeleteUser = `UPDATE scrty_users SET deleted_at = $2, updated_at = $2, active = false, email = NULL,
  email_verified_at = NULL, version = version + 1 WHERE id = $1`

	// SetUserPassword stores $2 as the password of user $1, with
	// password_changed_at $3 and updated_at $4, and increases its version. Run
	// it holding LockAdminUser.
	//nolint:gosec // G101: SQL statement text naming the password column, no credential
	SetUserPassword = `UPDATE scrty_users SET password = $2, password_changed_at = $3, updated_at = $4,
  version = version + 1 WHERE id = $1`

	// CurrentPassword reads the stored password hash of the live user $1.
	CurrentPassword = `SELECT password FROM scrty_users WHERE id = $1 AND deleted_at IS NULL`

	// DeleteAttributesByUser removes every profile attribute of user $1.
	DeleteAttributesByUser = `DELETE FROM scrty_user_attributes WHERE user_id = $1`

	// InsertAttribute stores one profile attribute: $1 user_id, $2 name,
	// $3 value.
	InsertAttribute = `INSERT INTO scrty_user_attributes (user_id, name, value) VALUES ($1, $2, $3)`

	// LockImportIdentifier takes the transaction-scoped advisory lock of the
	// imported user identifier $1 (UUID text). Every import takes it first,
	// before KnownRoles, LockImportUser and any identifier lock, so two
	// imports of one identifier queue on it rather than each holding a lock
	// the other waits for. It is reentrant within the transaction.
	//
	// It uses the two-key form, with ImportLockClass as the first key and
	// hashtext of the identifier as the second. PostgreSQL keeps the
	// single-key (bigint) and two-key (int4, int4) locks in separate spaces,
	// so no username, email or other single-key lock can equal it, whatever
	// text a consumer picks for them.
	LockImportIdentifier = `SELECT pg_advisory_xact_lock(` + importLockClassSQL + `, hashtext($1::text))`

	// LockImportUser reads the user with id $1, deleted or not, and locks the
	// row: username, name, email, email_verified_at, password, active,
	// created_at, updated_at, deleted_at. An import compares every given
	// value with these before it writes.
	LockImportUser = `SELECT username, name, email, email_verified_at, password, active, created_at, updated_at,
  deleted_at
FROM scrty_users WHERE id = $1 FOR UPDATE`

	// SetImportedUsername writes username $2 to user $1, alone. An import
	// that changes the username runs it before UpdateImportedUser, so a
	// unique violation of either statement names the one value that
	// collided: the username here, the email there (the username is then
	// already written). Run it holding LockImportUser.
	SetImportedUsername = `UPDATE scrty_users SET username = $2 WHERE id = $1`

	// ShareHistoryOwner reads whether the user with id $1 is soft-deleted and
	// locks the row FOR SHARE until the transaction ends. A password-history
	// write takes it before it records an entry: a deletion locks the row FOR
	// UPDATE and removes the history in its transaction, so the two serialise
	// and no entry recorded for the user outlives a deletion (D13). FOR SHARE
	// rather than FOR KEY SHARE, so it also waits for a write to the row that
	// takes no explicit lock first. It is a user-row lock, taken where D11's
	// order puts user rows: after any role lock, before any advisory lock.
	// No row is a reference to no user of this table: the history tables
	// declare no foreign key, so the write goes ahead.
	ShareHistoryOwner = `SELECT deleted_at IS NOT NULL FROM scrty_users WHERE id = $1 FOR SHARE`

	// UpdateImportedUser writes an import's values to user $1: $2 username,
	// $3 name, $4 email (NULL for none), $5 email_verified_at (NULL for
	// none), $6 password, $7 active, $8 role (the primary role name),
	// $9 created_at and $10 updated_at, each NULL when the import did not give
	// it, which keeps the stored time, and increases the version. Run it
	// holding LockImportUser.
	UpdateImportedUser = `UPDATE scrty_users SET username = $2, name = $3, email = $4, email_verified_at = $5,
  password = $6, active = $7, role = $8, created_at = COALESCE($9::timestamptz, created_at),
  updated_at = COALESCE($10::timestamptz, updated_at), version = version + 1
WHERE id = $1`

	// ShareOrganization reads the organization with id $1 and locks its row
	// FOR KEY SHARE until the transaction ends, so a user write that refers
	// to it cannot commit a reference to an organization deleted meanwhile.
	// No row is no such organization.
	ShareOrganization = `SELECT 1 FROM scrty_organizations WHERE id = $1 FOR KEY SHARE`

	// KnownRoles reads which of the role names in the text[] $1 the role
	// catalogue holds, with each one's super-role flag, and locks each row
	// FOR KEY SHARE, in name order, so a role being deleted cannot gain a
	// holder its deletion did not see (see ShareAdminRole). An import takes
	// it before the user's row lock.
	KnownRoles = `SELECT name, super_role FROM scrty_roles WHERE name = ANY($1::text[]) ORDER BY name FOR KEY SHARE`
)

// UpdateAdminUserColumns is the columns an administrative user update may
// write, in the fixed order UpdateAdminUserQuery writes them. Only these
// names ever reach the statement's text.
const (
	ColumnName            = "name"
	ColumnEmail           = "email"
	ColumnEmailVerifiedAt = "email_verified_at"
	ColumnOrganization    = "organization_id"
)

// UpdateAdminUserQuery is the UPDATE of user userArg that writes set, a list of
// (column, value) pairs whose columns are this file's Column constants, then
// updated_at = now and version = version + 1. A column not among those
// constants panics: it is a programming error, never input.
func UpdateAdminUserQuery(columns []string, values []any, now, userArg any) (string, []any) {
	var b strings.Builder
	b.WriteString("UPDATE scrty_users SET ")
	args := make([]any, 0, len(columns)+2)
	for i, c := range columns {
		switch c {
		case ColumnName, ColumnEmail, ColumnEmailVerifiedAt, ColumnOrganization:
		default:
			panic("pgschema: unknown administration column")
		}
		args = append(args, values[i])
		b.WriteString(c)
		b.WriteString(" = $")
		b.WriteString(strconv.Itoa(len(args)))
		b.WriteString(", ")
	}
	args = append(args, now)
	b.WriteString("updated_at = $")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString(", version = version + 1 WHERE id = $")
	args = append(args, userArg)
	b.WriteString(strconv.Itoa(len(args)))

	return b.String(), args
}

// LikePattern is search as an ILIKE pattern that matches it literally
// anywhere in the text: its %, _ and \ are escaped with \, PostgreSQL's
// default LIKE escape, which ListAdminUsers relies on (it names no ESCAPE
// clause), and the result is wrapped in %. An empty search is
// the empty pattern, which ListAdminUsers reads as "no search".
func LikePattern(search string) string {
	if search == "" {
		return ""
	}

	return "%" + likeEscaper.Replace(search) + "%"
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
