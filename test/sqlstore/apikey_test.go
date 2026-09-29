package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newAPIKeyStore builds the API key store over db, failing t on a refusal.
func newAPIKeyStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.APIKeyStore {
	t.Helper()

	s, err := sqlstore.NewAPIKeyStore(db, opts...)
	require.NoError(t, err)

	return s
}

func TestAPIKeyStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunAPIKeyStoreSuite(t, func(t *testing.T) apikey.Store {
			return newAPIKeyStore(t, emptied(t, db, "api_keys"))
		})
	})
}

func TestNewAPIKeyStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.APIKeyStore, err error)
	}

	refused := refusedConfig[*sqlstore.APIKeyStore]
	accepted := storefix.AcceptedConfig[*sqlstore.APIKeyStore]

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{
			name:   "an id generator does not apply to keys, which carry their own",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "a clock does not apply to keys",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to keys, which hold nothing sealed",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewAPIKeyStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// TestAPIKeyStore_NilScopes pins the stored form of a key issued with no
// scopes: an empty JSON array, the ordered list the column holds, never null.
func TestAPIKeyStore_NilScopes(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	ctx := t.Context()
	key := storefix.APIKey(10, "svc-no-scopes")
	key.Scopes = nil
	require.NoError(t, newAPIKeyStore(t, db).Put(ctx, key))

	var scopes string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT scopes::text FROM api_keys WHERE id = $1`, key.ID.String()).Scan(&scopes))
	assert.Equal(t, "[]", scopes, "nil scopes are not stored as an empty array")
}

func TestAPIKeyStore_Resolver(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, db *sql.DB)
	}

	begin := func(t *testing.T, ctx context.Context) *sql.Tx {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback() })
		return tx
	}

	cases := []testCase{
		{
			name: "a resolver supplies the transaction: its rollback discards the insert",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				tx := begin(t, ctx)
				s := newAPIKeyStore(t, db,
					sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) { return tx, true }))

				require.NoError(t, s.Put(ctx, storefix.APIKey(1, "svc")))
				assert.False(t, storefix.ExistsCtx(ctx, t, db, storefix.KeyRowExists, storefix.APIKey(1, "").ID), "the insert ran outside the resolver's transaction")
				require.NoError(t, tx.Rollback())
				assert.False(t, storefix.ExistsCtx(ctx, t, db, storefix.KeyRowExists, storefix.APIKey(1, "").ID), "the insert survived the rollback")
			},
		},
		{
			name: "a resolver reporting none runs on the handle, even with a transaction attached",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				attached := begin(t, ctx)
				s := newAPIKeyStore(t, db,
					sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) { return nil, false }))

				require.NoError(t, s.Put(sqlstore.WithTx(ctx, attached), storefix.APIKey(2, "svc")))
				assert.True(t, storefix.ExistsCtx(ctx, t, db, storefix.KeyRowExists, storefix.APIKey(2, "").ID), "the insert is not visible at once")
				require.NoError(t, attached.Rollback())
				assert.True(t, storefix.ExistsCtx(ctx, t, db, storefix.KeyRowExists, storefix.APIKey(2, "").ID), "the insert ran in the attached transaction")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, t.Context(), db)
		})
	}
}
