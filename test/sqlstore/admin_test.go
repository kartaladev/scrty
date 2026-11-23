package sqlstore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/store/sqlstore"
	admintest "github.com/kartaladev/scrty/test/admin"
	"github.com/kartaladev/scrty/test/internal/adminfix"
)

// TestAdminUserStore runs the user and import store cases against the
// database/sql identity store over one migrated database.
func TestAdminUserStore(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)
	store := newIdentityStore(t, conn.DB)

	adminfix.Run(t, adminfix.Harness{Users: store, Imports: store, Assignments: store, Grants: store, DB: conn.DB,
		Ambient: adminfix.SQLAmbient(conn.DB, sqlstore.WithTx)})
}

// TestAdminStatementsMatchSchema prepares every administration statement
// against the migrated identity set, so a column or table the schema lacks
// fails here rather than at first use.
func TestAdminStatementsMatchSchema(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)
	stmts := map[string]string{
		"AdminUserByID":            pgschema.AdminUserByID,
		"LockAdminUser":            pgschema.LockAdminUser,
		"ListAdminUsers":           pgschema.ListAdminUsers,
		"GrantsByUsers":            pgschema.GrantsByUsers,
		"AttributesByUsers":        pgschema.AttributesByUsers,
		"InsertAdminUser":          pgschema.InsertAdminUser,
		"UsernameTaken":            pgschema.UsernameTaken,
		"UserIDTaken":              pgschema.UserIDTaken,
		"SetUserActive":            pgschema.SetUserActive,
		"SoftDeleteUser":           pgschema.SoftDeleteUser,
		"SetUserPassword":          pgschema.SetUserPassword,
		"CurrentPassword":          pgschema.CurrentPassword,
		"DeleteAttributesByUser":   pgschema.DeleteAttributesByUser,
		"InsertAttribute":          pgschema.InsertAttribute,
		"LockImportUser":           pgschema.LockImportUser,
		"LockImportIdentifier":     pgschema.LockImportIdentifier,
		"LockAdminRoleFlag":        pgschema.LockAdminRoleFlag,
		"SetHolderSuperRole":       pgschema.SetHolderSuperRole,
		"UpdateImportedUser":       pgschema.UpdateImportedUser,
		"ShareOrganization":        pgschema.ShareOrganization,
		"KnownRoles":               pgschema.KnownRoles,
		"ListAdminRoles":           pgschema.ListAdminRoles,
		"AdminRoleByName":          pgschema.AdminRoleByName,
		"InsertAdminRole":          pgschema.InsertAdminRole,
		"LockAdminRole":            pgschema.LockAdminRole,
		"ShareAdminRole":           pgschema.ShareAdminRole,
		"UpdateAdminRole":          pgschema.UpdateAdminRole,
		"BumpRoleVersion":          pgschema.BumpRoleVersion,
		"RoleHeldByLiveUser":       pgschema.RoleHeldByLiveUser,
		"LockRoleHolders":          pgschema.LockRoleHolders,
		"DeleteAssignmentsOfRole":  pgschema.DeleteAssignmentsOfRole,
		"DeletePrivilegesOfRole":   pgschema.DeletePrivilegesOfRole,
		"DeleteAdminRole":          pgschema.DeleteAdminRole,
		"GrantsOfRole":             pgschema.GrantsOfRole,
		"DeleteResourcePrivileges": pgschema.DeleteResourcePrivileges,
		"InsertResourcePrivilege":  pgschema.InsertResourcePrivilege,
		"AssignmentsOfUser":        pgschema.AssignmentsOfUser,
		"NextGrantPosition":        pgschema.NextGrantPosition,
		"ClearPrimaryGrant":        pgschema.ClearPrimaryGrant,
		"GrantOfUser":              pgschema.GrantOfUser,
		"MarkPrimaryGrant":         pgschema.MarkPrimaryGrant,
		"DeleteGrantOfUser":        pgschema.DeleteGrantOfUser,
		"PromoteLowestGrant":       pgschema.PromoteLowestGrant,
		"SyncUserPrimaryRole":      pgschema.SyncUserPrimaryRole,
	}
	q, _ := pgschema.UpdateAdminUserQuery([]string{pgschema.ColumnName, pgschema.ColumnEmail,
		pgschema.ColumnEmailVerifiedAt, pgschema.ColumnOrganization}, []any{1, 2, 3, 4}, 5, 6)
	stmts["UpdateAdminUserQuery"] = q

	for name, stmt := range stmts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, err := conn.DB.PrepareContext(t.Context(), stmt)
			require.NoError(t, err)
			require.NoError(t, s.Close())
		})
	}
}

// TestAdminConformance runs the whole administration conformance suite, the
// user, import, role, grant and assignment parts, against the database/sql
// identity store.
func TestAdminConformance(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)
	store := newIdentityStore(t, conn.DB)
	factory := func(t *testing.T) admintest.Fixture { return adminfix.Fixture{Store: store, DB: conn.DB, T: t} }

	admintest.RunConformanceSuite(t, factory)
}
