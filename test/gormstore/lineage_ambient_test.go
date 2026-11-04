package gormstore_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestGormStore_LineageInACallersTransaction writes a lineage inside a caller's transaction,
// attached with WithTx or reported by a resolver, on a handle that prepares and one that does
// not: the write must land in the lineage table, never the sessions table, be invisible
// outside the transaction, and go with its rollback.
func TestGormStore_LineageInACallersTransaction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		prepared bool
		resolver bool
	}
	cases := []testCase{
		{name: "attached, plain handle"},
		{name: "attached, prepared handle", prepared: true},
		{name: "resolved, plain handle", resolver: true},
		{name: "resolved, prepared handle", prepared: true, resolver: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			d := migratedDB(t)
			g := openGormWith(t, d.conn.DSN, &gormdb.Config{PrepareStmt: tc.prepared})
			tx := beginGorm(ctx, t, g)

			var lineages session.Store
			callCtx := ctx
			if tc.resolver {
				lineages = lineageSessions(t, g, storefix.TestCipher(t), gormstore.WithTxResolver(resolving(tx)))
			} else {
				lineages = lineageSessions(t, g, storefix.TestCipher(t))
				callCtx = gormstore.WithTx(ctx, tx)
			}

			family := opID(1100)
			require.NoError(t, lineages.Create(callCtx, opSession("in-tx", family)))

			inTx := func(table string) int {
				var n int
				require.NoError(t, tx.Raw(fmt.Sprintf("SELECT count(*) FROM %s WHERE family_id = ?", table), family).Row().Scan(&n))
				return n
			}
			assert.Equal(t, 1, inTx(pgschema.RefreshTokenTable), "the write is in the lineage table")
			assert.Zero(t, inTx("sessions"), "and not in the sessions table")
			assert.Zero(t, heldIn(ctx, t, d, pgschema.RefreshTokenTable, family), "invisible before the caller commits")

			require.NoError(t, tx.Rollback().Error)
			assert.Zero(t, heldIn(ctx, t, d, pgschema.RefreshTokenTable, family), "gone with the rollback")
			assert.Zero(t, heldIn(ctx, t, d, "sessions", family))
		})
	}
}

// heldIn counts the rows of table in family, out of band.
func heldIn(ctx context.Context, t *testing.T, d database, table string, family id.ID) int {
	t.Helper()

	var n int
	// table is always one of this package's constants, never input.
	require.NoError(t, d.conn.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE family_id = $1", family).Scan(&n))

	return n
}
