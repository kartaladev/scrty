package storefix

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/sqlstore"
)

// BeginSQLStoreTx begins a database/sql transaction on raw and attaches it
// with sqlstore.WithTx, the way the database/sql stores take one. To a store
// of any other backend it is exactly what another backend's attachment is: a
// live transaction on the same database, in a context value it cannot see. A
// store that wrote in it would lose its write to the rollback it returns.
func BeginSQLStoreTx(t *testing.T, raw *sql.DB) (context.Context, func() error) {
	t.Helper()

	tx, err := raw.BeginTx(t.Context(), nil)
	require.NoError(t, err)

	return sqlstore.WithTx(t.Context(), tx), tx.Rollback
}
