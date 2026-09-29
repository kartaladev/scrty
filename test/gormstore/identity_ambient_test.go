package gormstore_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/pkg/id"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// prepareAmbient creates, on db, the table WriteUnrelated writes (the caller's
// own work in the same transaction, outside every identity table) and one
// sentinel grant whose identifier an armed grantCollidingIDs hands out again.
// It returns that identifier. Both are dropped with the migrations at cleanup.
func prepareAmbient(t *testing.T, db *sql.DB) id.ID {
	t.Helper()

	ctx := t.Context()
	_, err := db.ExecContext(ctx, `CREATE TABLE identity_ambient_unrelated (key text PRIMARY KEY)`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS identity_ambient_unrelated`)
	})

	sentinel, err := seedIDs.NewID()
	require.NoError(t, err)
	owner, err := seedIDs.NewID()
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO assigned_roles
  (id, user_id, role_name, position, is_primary, super_role, created_at, updated_at)
VALUES ($1, $2, 'sentinel', 0, true, false, $3, $3)`, sentinel, owner, seedNow)
	require.NoError(t, err)

	return sentinel
}

// grantCollidingIDs is a consumer generator that mints from the default one
// until armed. Armed, it mints the next identifier (the user's) as usual and
// then hands out taken — the identifier of a grant already stored — for the
// user's first grant, so PostgreSQL itself rejects the grant insert with a
// primary-key violation after the user row is written, aborting the
// transaction it runs in exactly as an unexpected grant-write failure would.
type grantCollidingIDs struct {
	taken id.ID

	mu    sync.Mutex
	armed int // calls left until the collision; 0 is disarmed
}

func (g *grantCollidingIDs) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.armed = 2
}

func (g *grantCollidingIDs) NewID() (id.ID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.armed > 0 {
		g.armed--
		if g.armed == 0 {
			return g.taken, nil
		}
	}

	return seedIDs.NewID()
}

// consumerTxKey is where a consumer's own transaction manager keeps the
// current transaction, read by the consumer's resolver.
type consumerTxKey struct{}

// identityAmbient is the ambient-transaction harness over the identity store,
// one store per harness so a fault one case arms stays with it.
//
// With resolver false the store has no resolver and Begin attaches the
// transaction with gormstore.WithTx. With resolver true the store has a
// consumer WithTxResolver reading the consumer's own context key, and Begin
// attaches the transaction there only.
type identityAmbient struct {
	*identityFixture

	raw      *sql.DB
	ids      *grantCollidingIDs
	resolver bool
}

func newIdentityAmbient(t *testing.T, d database, taken id.ID, resolver bool) *identityAmbient {
	t.Helper()

	ids := &grantCollidingIDs{taken: taken}
	opts := []gormstore.Option{gormstore.WithIDGenerator(ids)}
	if resolver {
		opts = append(opts, gormstore.WithTxResolver(func(ctx context.Context) (*gormdb.DB, bool) {
			tx, ok := ctx.Value(consumerTxKey{}).(*gormdb.DB)
			return tx, ok
		}))
	}

	return &identityAmbient{
		identityFixture: newIdentityFixture(newIdentityStore(t, d.db, opts...), d.db),
		raw:             d.conn.DB,
		ids:             ids,
		resolver:        resolver,
	}
}

func (h *identityAmbient) Begin(ctx context.Context) (context.Context, func() error, func() error, error) {
	tx := h.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, nil, nil, tx.Error
	}

	txCtx := withSeedTx(ctx, tx)
	if h.resolver {
		txCtx = context.WithValue(txCtx, consumerTxKey{}, tx)
	} else {
		txCtx = gormstore.WithTx(txCtx, tx)
	}

	commit := func() error { return tx.Commit().Error }
	rollback := func() error { return tx.Rollback().Error }

	return txCtx, commit, rollback, nil
}

func (h *identityAmbient) WriteUnrelated(txCtx context.Context, key string) error {
	return h.q(txCtx).Exec(`INSERT INTO identity_ambient_unrelated (key) VALUES (?)`, key).Error
}

func (h *identityAmbient) UnrelatedStored(ctx context.Context, key string) (bool, error) {
	var n int
	err := h.raw.QueryRowContext(ctx, `SELECT count(*) FROM identity_ambient_unrelated WHERE key = $1`, key).Scan(&n)

	return n == 1, err
}

func (h *identityAmbient) FailGrantWrites() { h.ids.arm() }

var _ identitytest.AmbientHarness = (*identityAmbient)(nil)
