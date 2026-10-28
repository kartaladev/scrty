// Package noalias imports each storage backend beside the driver it wraps,
// without an import alias.
package noalias

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/kartaladev/scrty/store/pgxstore"
)

// WithPgxTx binds a pgx transaction to ctx through the pgx backend.
func WithPgxTx(ctx context.Context, tx pgx.Tx) context.Context {
	return pgxstore.WithTx(ctx, tx)
}
