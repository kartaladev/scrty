package sqlstore_test

import (
	"context"
	"database/sql"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
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
//
// pg_stat_get_backend_subxact reads a statistics snapshot that PostgreSQL
// keeps for the rest of the transaction once taken, so a reading taken
// earlier in the same transaction would be replayed here instead of the
// current state. It is therefore read last, once, after the write and the
// lock count, and nothing earlier in any caller's transaction may read it.
func readSubxacts(ctx context.Context, t *testing.T, tx *sql.Tx) subxacts {
	t.Helper()

	_, err := tx.ExecContext(ctx, `CREATE TEMP TABLE savepoint_probe (x int) ON COMMIT DROP`)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `INSERT INTO savepoint_probe VALUES (1)`)
	require.NoError(t, err)

	s := subxacts{cached: -1}
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks
WHERE pid = pg_backend_pid() AND locktype = 'transactionid' AND granted`).Scan(&s.xidLocks))

	var version int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version))
	if version >= 160000 {
		require.NoError(t, tx.QueryRowContext(ctx, `SELECT s.subxact_count, s.subxact_overflowed
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

// TestIdentityStore_RefusalsLeaveNoOpenSavepoint pins design decision 6 of
// the default-identity-store change: a call failing inside a caller's
// transaction — a plain refusal included, and a call a panic interrupts —
// closes the savepoint it opened: rolled back and released, not merely rolled
// back. Each savepoint left open would nest the caller's later work one level
// deeper, and past 64 of them the backend's subtransaction cache overflows,
// which slows snapshots for every session on the server.
//
// The caller's write readSubxacts makes assigns a transaction ID to every
// savepoint still open around it, so the backend's transaction-ID locks count
// the open savepoints on every supported PostgreSQL major, whether or not
// the refused calls themselves ever wrote.
func TestIdentityStore_RefusalsLeaveNoOpenSavepoint(t *testing.T) {
	t.Parallel()

	conn := migratedIdentityDB(t)

	type testCase struct {
		name string
		// calls makes the store's calls inside the caller's transaction tx,
		// and returns how many of them succeeded with a write.
		calls  func(t *testing.T, ctx context.Context, tx *sql.Tx, db *sql.DB) int
		assert func(t *testing.T, s subxacts, writes int)
	}

	cases := []testCase{
		{
			name: "refused provisions of an existing username",
			calls: func(t *testing.T, ctx context.Context, tx *sql.Tx, db *sql.DB) int {
				s := newIdentityStore(t, db)
				_, err := s.Provision(ctx, "savepoint-taken")
				require.NoError(t, err)

				for range 5 {
					_, err := s.Provision(sqlstore.WithTx(ctx, tx), "savepoint-taken")
					require.ErrorIs(t, err, identity.ErrUserExists)
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "updates of an unknown user",
			calls: func(t *testing.T, ctx context.Context, tx *sql.Tx, db *sql.DB) int {
				s := newIdentityStore(t, db)
				for i := range 5 {
					_, err := s.Update(sqlstore.WithTx(ctx, tx), "savepoint-nobody-"+strconv.Itoa(i),
						identity.WithUserName("Nobody"))
					require.ErrorIs(t, err, identity.ErrUserNotFound)
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			// The collider mints an already-stored user's identifier for
			// every fresh username, so InsertUser genuinely violates the
			// primary key, a database-level abort ON CONFLICT (username)
			// does not absorb. 70 exceeds PostgreSQL's 64-slot
			// subtransaction cache, so a missing release would overflow it,
			// not merely fill it.
			name: "provisions failing on a colliding identifier",
			calls: func(t *testing.T, ctx context.Context, tx *sql.Tx, db *sql.DB) int {
				existing, err := newIdentityStore(t, db).Provision(ctx, "savepoint-collide-base")
				require.NoError(t, err)
				taken := id.MustParse(string(existing.ID))
				collider := newIdentityStore(t, db,
					sqlstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return taken, nil })))

				for i := range 70 {
					_, err := collider.Provision(sqlstore.WithTx(ctx, tx), "savepoint-collide-"+strconv.Itoa(i))
					require.Error(t, err)
					require.NotErrorIs(t, err, identity.ErrUserExists,
						"a colliding identifier is a database failure, not the username decision")
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "a refused provision followed by a successful one",
			calls: func(t *testing.T, ctx context.Context, tx *sql.Tx, db *sql.DB) int {
				s := newIdentityStore(t, db)
				_, err := s.Provision(ctx, "savepoint-first")
				require.NoError(t, err)

				txCtx := sqlstore.WithTx(ctx, tx)
				_, err = s.Provision(txCtx, "savepoint-first")
				require.ErrorIs(t, err, identity.ErrUserExists)
				_, err = s.Provision(txCtx, "savepoint-second", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				return 1
			},
			assert: assertReleased,
		},
		{
			// The handle panics after the user insert has run, so the
			// interrupted call has written under its savepoint; the store's
			// cleanup must roll that savepoint back and release it before
			// the panic reaches the caller.
			name: "a provision a panicking handle interrupts",
			calls: func(t *testing.T, ctx context.Context, tx *sql.Tx, db *sql.DB) int {
				s := newIdentityStore(t, db, faultResolver())
				h := &faultingTx{Tx: tx, matches: exact(pgschema.InsertUser), hook: func() { panic("handle exploded") }}
				require.PanicsWithValue(t, "handle exploded", func() {
					_, _ = s.Provision(context.WithValue(ctx, faultTxKey{}, sqlstore.DBTX(h)),
						"savepoint-panicking", identity.WithUserRoles("admin"))
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
			tx, err := conn.DB.BeginTx(ctx, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = tx.Rollback() })

			writes := tc.calls(t, ctx, tx, conn.DB)
			tc.assert(t, readSubxacts(ctx, t, tx), writes)
		})
	}
}
