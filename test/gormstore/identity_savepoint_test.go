package gormstore_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
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
	// cached is the backend's subtransaction cache count, released
	// subtransactions with an ID and open ones alike; -1 before PostgreSQL
	// 16, which has no pg_stat_get_backend_subxact.
	cached     int
	overflowed bool
}

// readSubxacts writes through tx, so every savepoint still open is assigned a
// transaction ID, then reads the backend's subtransaction state on tx's own
// connection.
//
// pg_stat_get_backend_subxact is read once, as the last statement: reading
// it changes what it goes on to report for the rest of the session
// (observed against a live server), so no earlier reading may precede the
// one a case asserts on.
func readSubxacts(t *testing.T, tx *gormdb.DB) subxacts {
	t.Helper()

	require.NoError(t, tx.Exec(`CREATE TEMP TABLE savepoint_probe (x int) ON COMMIT DROP`).Error)
	require.NoError(t, tx.Exec(`INSERT INTO savepoint_probe VALUES (1)`).Error)

	s := subxacts{cached: -1}
	require.NoError(t, tx.Raw(`SELECT count(*) FROM pg_locks
WHERE pid = pg_backend_pid() AND locktype = 'transactionid' AND granted`).Row().Scan(&s.xidLocks))

	var version int
	require.NoError(t, tx.Raw(`SELECT current_setting('server_version_num')::int`).Row().Scan(&version))
	if version >= 160000 {
		require.NoError(t, tx.Raw(`SELECT s.subxact_count, s.subxact_overflowed
FROM pg_stat_get_backend_idset() b, LATERAL pg_stat_get_backend_subxact(b) s
WHERE pg_stat_get_backend_pid(b) = pg_backend_pid()`).Row().Scan(&s.cached, &s.overflowed))
	} else {
		t.Logf("server_version_num %d predates PostgreSQL 16: only the transaction-ID locks are checked", version)
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
// transaction — a plain refusal, a database-level abort, or a panic the
// caller recovers — closes the savepoint it opened: rolled back and
// released, not merely rolled back. Each savepoint left open would nest the
// caller's later work one level deeper, and past 64 of them the backend's
// subtransaction cache overflows, which slows snapshots for every session on
// the server.
//
// Each case runs in a transaction of its own, then makes one write in it:
// that write assigns a transaction ID to every savepoint still enclosing it,
// so each one left open shows as a transaction-ID lock of its own, on every
// supported PostgreSQL major.
func TestIdentityStore_RefusalsLeaveNoOpenSavepoint(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	type testCase struct {
		name string
		// calls makes the store's calls inside tx, the caller's
		// transaction, and returns how many of them succeeded with a write.
		calls  func(t *testing.T, ctx context.Context, tx *gormdb.DB) int
		assert func(t *testing.T, s subxacts, writes int)
	}

	cases := []testCase{
		{
			name: "refused provisions of an existing username",
			calls: func(t *testing.T, ctx context.Context, tx *gormdb.DB) int {
				s := newIdentityStore(t, d.db)
				_, err := s.Provision(ctx, "savepoint-taken")
				require.NoError(t, err)

				for range 5 {
					_, err := s.Provision(gormstore.WithTx(ctx, tx), "savepoint-taken")
					require.ErrorIs(t, err, identity.ErrUserExists)
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "updates of an unknown user",
			calls: func(t *testing.T, ctx context.Context, tx *gormdb.DB) int {
				s := newIdentityStore(t, d.db)
				for i := range 5 {
					_, err := s.Update(gormstore.WithTx(ctx, tx), "savepoint-missing-"+strconv.Itoa(i),
						identity.WithUserName("Nobody"))
					require.ErrorIs(t, err, identity.ErrUserNotFound)
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			// A reused identifier makes each insert violate the primary key
			// PostgreSQL was not told to ignore: a real, database-level
			// abort. 70 exceeds the backend's 64-slot subtransaction cache.
			name: "provisions whose identifier collides",
			calls: func(t *testing.T, ctx context.Context, tx *gormdb.DB) int {
				taken := storefix.NewID(t)
				s := newIdentityStore(t, d.db,
					gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) { return taken, nil })))
				_, err := s.Provision(ctx, "savepoint-collide-base")
				require.NoError(t, err)

				for i := range 70 {
					_, err := s.Provision(gormstore.WithTx(ctx, tx), "savepoint-collide-"+strconv.Itoa(i))
					require.Error(t, err)
					assert.NotErrorIs(t, err, identity.ErrUserExists,
						"a colliding identifier is a database failure, not the username decision")
				}

				return 0
			},
			assert: assertReleased,
		},
		{
			name: "a refused provision followed by a successful one",
			calls: func(t *testing.T, ctx context.Context, tx *gormdb.DB) int {
				s := newIdentityStore(t, d.db)
				_, err := s.Provision(ctx, "savepoint-first")
				require.NoError(t, err)

				_, err = s.Provision(gormstore.WithTx(ctx, tx), "savepoint-first")
				require.ErrorIs(t, err, identity.ErrUserExists)
				_, err = s.Provision(gormstore.WithTx(ctx, tx), "savepoint-second", identity.WithUserRoles("admin"))
				require.NoError(t, err)

				return 1
			},
			assert: assertReleased,
		},
		{
			// The panic interrupts the store mid-write; the caller recovers
			// it and carries on in its transaction, which must then hold no
			// savepoint of the store's.
			name: "a handle panicking under the savepoint, recovered by the caller",
			calls: func(t *testing.T, ctx context.Context, tx *gormdb.DB) int {
				s := newIdentityStore(t, d.db, faultResolver())
				_, err := s.Provision(context.WithValue(ctx, faultTxKey{}, tx), "savepoint-before-panic")
				require.NoError(t, err)

				h := &faultingPool{ConnPool: tx.Statement.ConnPool, matches: isUserInsert,
					hook: func() { panic("handle exploded") }}
				txCtx := context.WithValue(ctx, faultTxKey{}, overPool(ctx, tx, h))
				require.PanicsWithValue(t, "handle exploded", func() {
					_, _ = s.Provision(txCtx, "savepoint-panicking", identity.WithUserRoles("admin"))
				})
				require.True(t, h.fired, "the user insert was not matched")

				return 1
			},
			assert: assertReleased,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			tx := beginGorm(ctx, t, d.db)
			writes := tc.calls(t, ctx, tx)
			tc.assert(t, readSubxacts(t, tx), writes)
		})
	}
}
