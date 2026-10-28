// Package noaliaspgx imports the pgx storage backend beside the driver it wraps,
// without an import alias.
package noaliaspgx

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/kartaladev/scrty/store/pgxstore"
)

// WithPgxTx binds a pgx transaction to ctx through the pgx backend.
func WithPgxTx(ctx context.Context, tx pgx.Tx) context.Context {
	return pgxstore.WithTx(ctx, tx)
}
