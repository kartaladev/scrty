// Package migrate holds scrty's embedded SQL migration sets.
//
// A Set is plain SQL in goose's annotated format ("-- +goose Up", "-- +goose
// Down"), embedded so applying it needs no files on disk. This package
// depends on nothing beyond the standard library: it only exposes the files
// as an fs.FS. Applying them is the consumer's job, with goose or any other
// tool that reads the format — see the compiled example in the test module
// for the goose recipe.
package migrate

import (
	"embed"
	"io/fs"
)

//go:embed securitystate/*.sql
var securityStateFS embed.FS

//go:embed identity/*.sql
var identityFS embed.FS

// SecurityStateVersionTable is the version table name SecurityState uses by
// default. A consumer may apply the set with any other name; the set never
// reads or changes another set's version table.
const SecurityStateVersionTable = "goose_security_state"

// Set is one embedded migration set: goose-annotated plain SQL files under
// Dir inside FS(), named with a UTC timestamp version
// (YYYYMMDDHHMMSS_name.sql). Every migration in a set runs in its own
// transaction and rolls back completely.
//
// Every table, index and sequence a set creates is named with the fixed
// scrty_ prefix, and no option changes it. To keep them apart from a
// consumer's own tables, put them in a PostgreSQL schema of their own and give
// the connection a search_path that reaches it.
type Set struct {
	fsys fs.FS

	// Dir is the directory inside FS() holding this set's migration files.
	Dir string

	// VersionTable is the version table name this set records its applied
	// migrations in by default. A consumer applying the set with their own
	// tool may record versions under any other name instead.
	VersionTable string
}

// FS returns the file system holding this set's migration files, with Dir as
// one of its top-level entries.
func (s Set) FS() fs.FS { return s.fsys }

// SecurityState returns the security-state migration set: sessions, signing
// keys, login attempts, MFA enrolments, API keys, one-time tokens, and the
// OIDC links, flows and handoffs tables. It creates no identity tables and no
// foreign key to one (see the schema-migrations spec).
//
// Its relations are named with the fixed scrty_ prefix (scrty_sessions,
// scrty_signing_keys and so on); a PostgreSQL schema plus a search_path is how
// a consumer isolates them.
//
// Its default version table is SecurityStateVersionTable.
func SecurityState() Set {
	return Set{fsys: securityStateFS, Dir: "securitystate", VersionTable: SecurityStateVersionTable}
}

// IdentityVersionTable is the version table name Identity uses by default. A
// consumer applying the set with their own tool may record versions under any
// other name instead.
const IdentityVersionTable = "goose_identity"

// Identity returns the identity migration set: groups, organizations, roles,
// users, assigned roles, resource privileges and password history. It
// creates no security-state table and no foreign key to or from one (see the
// schema-migrations spec): the identity set can be applied, or rolled back,
// without touching security state.
//
// Its relations are named with the fixed scrty_ prefix (scrty_users,
// scrty_roles and so on); a PostgreSQL schema plus a search_path is how a
// consumer isolates them.
//
// The catalogue tables (scrty_groups, scrty_organizations, scrty_roles,
// scrty_resource_privileges)
// are written only by the consumer's own tooling, which must supply
// created_at and updated_at: those columns have no database default.
//
// Apply it before deploying a release that wires the identity store — the
// core's sqlstore.IdentityStore, or an adapter's identity store — and keep it
// applied while that release runs. With a table missing, the store's
// operations fail with a database error, and its MFA-required lookup denies
// rather than reporting the requirement as absent, since the policy that
// calls it already denies on any lookup error.
//
// Its default version table is IdentityVersionTable.
func Identity() Set {
	return Set{fsys: identityFS, Dir: "identity", VersionTable: IdentityVersionTable}
}
