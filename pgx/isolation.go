package pgx

import (
	"context"
	"fmt"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/storeerr"
)

// ErrIsolationTooStrong is wrapped by the error an operation returns when it
// is run inside a caller's transaction whose isolation is stronger than READ
// COMMITTED, and its guarantee depends on READ COMMITTED. It is
// storeerr.ErrIsolationTooStrong under this package's name, so errors.Is
// matches either, and the error names the isolation it found. The operation
// writes nothing, and the caller's transaction stays usable. The operations
// that refuse are RecoveryCodeStore.ReplaceSet, AttemptStore.AddStreakFailure,
// OneTimeStore.InsertWithin and PasskeyCredentialStore.InsertWithin;
// every other operation joins a caller's transaction at any isolation. There
// is no option to relax it: a store cannot change a transaction's isolation
// once it has begun, so a consumer whose own work needs a stronger isolation
// runs these operations outside that transaction.
var ErrIsolationTooStrong = storeerr.ErrIsolationTooStrong

// beginReadCommitted begins a transaction of the store's own on its pool and
// sets it to READ COMMITTED as its first statement, whatever the database's
// or the role's default isolation is. A statement rather than
// pgx.TxOptions, so every backend's stores share one shape. When the
// statement fails, the transaction is rolled back and the error returned
// as the driver gave it.
func (c *config) beginReadCommitted(ctx context.Context) (pgxv5.Tx, error) {
	return beginReadCommitted(ctx, c.base)
}

// beginReadCommitted is config.beginReadCommitted on pool, for the limiter,
// which has no store config.
func beginReadCommitted(ctx context.Context, pool *pgxpool.Pool) (pgxv5.Tx, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, pgschema.SetReadCommitted); err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}

	return tx, nil
}

// readCommitted runs fn in a READ COMMITTED transaction of the store's own,
// begun by beginReadCommitted, and commits it when fn succeeds. It is rolled
// back on every other way out, a panic in fn included, even when ctx is done,
// so the transaction and its locks never outlive the call. fn's error is
// returned as it is; a failure to begin or commit as the driver gave it.
func (c *config) readCommitted(ctx context.Context, fn func(pgxv5.Tx) error) error {
	tx, err := c.beginReadCommitted(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// requireReadCommitted reads the isolation of q, a caller's transaction, and
// refuses one stronger than READ COMMITTED with an error wrapping
// ErrIsolationTooStrong and naming the isolation found. The read is a plain
// SELECT, so a refusal leaves the transaction usable. A failure to read is
// returned as the driver gave it.
func (c *config) requireReadCommitted(ctx context.Context, q DBTX) error {
	var level string
	if err := q.QueryRow(ctx, pgschema.CurrentIsolation).Scan(&level); err != nil {
		return err
	}
	if !pgschema.ReadCommittedOrWeaker(level) {
		return fmt.Errorf("%w: it runs at %s", ErrIsolationTooStrong, level)
	}

	return nil
}
