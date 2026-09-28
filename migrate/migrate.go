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
// The catalogue tables (groups, organizations, roles, resource_privileges)
// are written only by the consumer's own tooling, which must supply
// created_at and updated_at: those columns have no database default.
//
// Its default version table is IdentityVersionTable.
func Identity() Set {
	return Set{fsys: identityFS, Dir: "identity", VersionTable: IdentityVersionTable}
}
