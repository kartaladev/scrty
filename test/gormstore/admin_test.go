package gormstore_test

import (
	"testing"

	"github.com/kartaladev/scrty/store/gormstore"
	admintest "github.com/kartaladev/scrty/test/admin"
	"github.com/kartaladev/scrty/test/internal/adminfix"
)

// TestAdminUserStore runs the user and import store cases against the gorm
// identity store over one migrated database.
func TestAdminUserStore(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	store := newIdentityStore(t, d.db)

	adminfix.Run(t, adminfix.Harness{Users: store, Imports: store, DB: d.conn.DB,
		Ambient: adminfix.GormAmbient(d.db, gormstore.WithTx)})
}

// TestAdminConformance runs the whole administration conformance suite, the
// user, import, role, grant and assignment parts, against the gorm identity
// store.
func TestAdminConformance(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	store := newIdentityStore(t, d.db)
	factory := func(t *testing.T) admintest.Fixture {
		return adminfix.Fixture{Store: store, DB: d.conn.DB, T: t}
	}

	admintest.RunConformanceSuite(t, factory)
}
