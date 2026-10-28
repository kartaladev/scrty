package gormstore

import (
	"context"
	"database/sql"
	"fmt"

	gormdb "gorm.io/gorm"

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

// beginReadCommitted begins a transaction of the store's own on db, a session
// on the store's *gorm.DB carrying the call's context, at READ COMMITTED,
// whatever the database's or the role's default isolation is. The isolation
// travels in the BEGIN itself (the driver sends BEGIN ISOLATION LEVEL READ
// COMMITTED), so setting it costs no round trip of its own. A failure to
// begin is returned as the driver gave it.
func beginReadCommitted(ctx context.Context, db *gormdb.DB) (*gormdb.DB, error) {
	tx := db.WithContext(ctx).Begin(readCommittedTx)
	if tx.Error != nil {
		return nil, tx.Error
	}

	return tx, nil
}

// readCommittedTx are the options every transaction a store begins for
// itself is begun with.
var readCommittedTx = &sql.TxOptions{Isolation: sql.LevelReadCommitted}

// readCommitted runs fn in a READ COMMITTED transaction of the store's own,
// begun on db by beginReadCommitted, and commits it when fn succeeds. It is
// rolled back on every other way out, a panic in fn included, so the
// transaction and its locks never outlive the call. fn's error is returned as
// it is; a failure to begin or commit as the driver gave it.
func readCommitted(ctx context.Context, db *gormdb.DB, fn func(*gormdb.DB) error) error {
	tx, err := beginReadCommitted(ctx, db)
	if err != nil {
		return err
	}
	defer func() { tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit().Error
}

// requireReadCommitted reads the isolation of q, a caller's transaction, and
// refuses one stronger than READ COMMITTED with an error wrapping
// ErrIsolationTooStrong and naming the isolation found. The read is a plain
// SELECT, so a refusal leaves the transaction usable. A failure to read is
// returned as the driver gave it.
func requireReadCommitted(ctx context.Context, q *gormdb.DB) error {
	var level string
	if err := savepointSession(ctx, q).Raw(pgschema.CurrentIsolation).Row().Scan(&level); err != nil {
		return err
	}
	if !pgschema.ReadCommittedOrWeaker(level) {
		return fmt.Errorf("%w: it runs at %s", ErrIsolationTooStrong, level)
	}

	return nil
}
