package pgxstore_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	pgxstore "github.com/kartaladev/scrty/pgx"
)

// subxacts is what a connection reports about the subtransactions of its
// open transaction, read after the caller has written, which assigns a
// transaction ID to its transaction and to every savepoint still open around
// the write.
type subxacts struct {
	// xidLocks counts the transaction-ID locks the backend holds: one for
	// the caller's transaction and one per savepoint still open. A released
	// or rolled-back subtransaction drops its own. It is readable on every
	// supported PostgreSQL major.
	xidLocks int
	// cached is the backend's subtransaction cache count, open and released
	// subtransactions with an ID alike; -1 before PostgreSQL 16, which has
	// no pg_stat_get_backend_subxact.
	cached     int
	overflowed bool
}

// readSubxacts writes through tx, so every savepoint still open is assigned a
// transaction ID, then reads the backend's subtransaction state on tx's own
// connection.
func readSubxacts(ctx context.Context, t *testing.T, tx pgx.Tx) subxacts {
	t.Helper()

	_, err := tx.Exec(ctx, `CREATE TEMP TABLE savepoint_probe (x int) ON COMMIT DROP`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO savepoint_probe VALUES (1)`)
	require.NoError(t, err)

	s := subxacts{cached: -1}
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks
WHERE pid = pg_backend_pid() AND locktype = 'transactionid' AND granted`).Scan(&s.xidLocks))

	var version int
	require.NoError(t, tx.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version))
	if version >= 160000 {
		require.NoError(t, tx.QueryRow(ctx, `SELECT s.subxact_count, s.subxact_overflowed
FROM pg_stat_get_backend_idset() b, LATERAL pg_stat_get_backend_subxact(b) s
WHERE pg_stat_get_backend_pid(b) = pg_backend_pid()`).Scan(&s.cached, &s.overflowed))
	}

	return s
}

// assertReleased asserts that no savepoint of the store is left open, given
// the number of the store's calls in the transaction that succeeded with a
// write: each of those leaves one released subtransaction in the cache, and
// nothing else may remain there.
func assertReleased(t *testing.T, s subxacts, writes int) {
	t.Helper()

	assert.Equal(t, 1, s.xidLocks, "transaction-ID locks beyond the caller's are savepoints left open")
	if s.cached >= 0 {
		assert.Equal(t, writes, s.cached, "subtransactions beyond the successful writes are savepoints left open")
		assert.False(t, s.overflowed, "the backend's subtransaction cache overflowed")
	}
}

// TestIdentityStore_RefusalsLeaveNoOpenSavepoint pins that a call failing
// inside a caller's transaction — a plain refusal included — closes the
// savepoint it opened: rolled back and released, not merely rolled back.
// A call a panic interrupts is held to the same. Each savepoint left open
// would nest the caller's later work one level deeper, and past 64 of them
// the backend's subtransaction cache overflows.
func TestIdentityStore_RefusalsLeaveNoOpenSavepoint(t *testing.T) {
	t.Parallel()

	db := migratedIdentity(t)

	type testCase struct {
		name string
		// calls makes the store's calls inside the caller's transaction tx,
		// and returns how many of them succeeded with a write.
		calls  func(t *testing.T, ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool) int
		assert func(t *testing.T, s subxacts, writes int)
	}

	cases := []testCase{
		{
			name: "refused provisions of an existing username",
			calls: func(t *testing.T, ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool) int {
				txCtx := pgxstore.WithTx(ctx, tx)
				s := newIdentityStore(t, pool)
				_, err := s.Provision(ctx, "savepoint-taken")
				require.NoError(t, err)

				for range 5 {
					_, err := s.Provision(txCtx, "savepoint-taken")
					require.ErrorIs(t, err, identity.ErrUserExists)
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "updates of an unknown user",
			calls: func(t *testing.T, ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool) int {
				txCtx := pgxstore.WithTx(ctx, tx)
				s := newIdentityStore(t, pool)
				for range 5 {
					_, err := s.Update(txCtx, "savepoint-nobody", identity.WithUserName("Nobody"))
					require.ErrorIs(t, err, identity.ErrUserNotFound)
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "retires failing on a colliding history entry",
			calls: func(t *testing.T, ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool) int {
				txCtx := pgxstore.WithTx(ctx, tx)
				// One identifier over and over: the second history entry
				// collides with the first on the primary key.
				taken, err := seedIDs.NewID()
				require.NoError(t, err)
				s := newIdentityStore(t, pool, pgxstore.WithIDGenerator(fixedIDs{taken}))
				user := newHistoryUser(t)
				require.NoError(t, s.RetirePassword(ctx, user, []byte("savepoint-old-hash"), 5))

				for range 5 {
					require.Error(t, s.RetirePassword(txCtx, user, []byte("savepoint-new-hash"), 5))
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "a refused provision followed by a successful one",
			calls: func(t *testing.T, ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool) int {
				txCtx := pgxstore.WithTx(ctx, tx)
				s := newIdentityStore(t, pool)
				_, err := s.Provision(ctx, "savepoint-first")
				require.NoError(t, err)

				_, err = s.Provision(txCtx, "savepoint-first")
				require.ErrorIs(t, err, identity.ErrUserExists)
				_, err = s.Provision(txCtx, "savepoint-second", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				return 1
			},
			assert: assertReleased,
		},
		{
			// The wrapper panics after the user insert has run, so the
			// interrupted call has written under its savepoint; the store's
			// cleanup must roll that savepoint back and release it before
			// the panic reaches the caller.
			name: "a provision a panicking transaction wrapper interrupts",
			calls: func(t *testing.T, ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool) int {
				s := newIdentityStore(t, pool, faultResolver())
				h := newFaultingTx(tx, exact(pgschema.InsertUser), false, func() { panic("handle exploded") })
				require.PanicsWithValue(t, "handle exploded", func() {
					_, _ = s.Provision(withFaultTx(ctx, h), "savepoint-panicking", identity.WithUserRoles("admin"))
				})

				return 0
			},
			assert: assertReleased,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			tx := beginTx(ctx, t, db.Pool)
			writes := tc.calls(t, ctx, tx, db.Pool)
			tc.assert(t, readSubxacts(ctx, t, tx), writes)
		})
	}
}
