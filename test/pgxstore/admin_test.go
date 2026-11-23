package pgxstore_test

import (
	"testing"

	"github.com/kartaladev/scrty/store/pgxstore"
	admintest "github.com/kartaladev/scrty/test/admin"
	"github.com/kartaladev/scrty/test/internal/adminfix"
)

// TestAdminUserStore runs the user and import store cases against the pgx
// identity store over one migrated database.
func TestAdminUserStore(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)
	store := newIdentityStore(t, db.Pool)

	adminfix.Run(t, adminfix.Harness{Users: store, Imports: store, Assignments: store, Grants: store, DB: db.DB,
		Ambient: adminfix.PgxAmbient(db.Pool, pgxstore.WithTx)})
}

// TestAdminConformance runs the whole administration conformance suite, the
// user, import, role, grant and assignment parts, against the pgx identity
// store.
func TestAdminConformance(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)
	store := newIdentityStore(t, db.Pool)
	factory := func(t *testing.T) admintest.Fixture { return adminfix.Fixture{Store: store, DB: db.DB, T: t} }

	admintest.RunConformanceSuite(t, factory)
}
