package pgxstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
)

// newAPIKeyStore builds the API key store over pool, failing t on a refusal.
func newAPIKeyStore(t *testing.T, pool *pgxpool.Pool, opts ...pgxstore.Option) *pgxstore.APIKeyStore {
	t.Helper()

	s, err := pgxstore.NewAPIKeyStore(pool, opts...)
	require.NoError(t, err)

	return s
}

// apiKey is the key numbered n, issued to principal.
func apiKey(n int, principal identity.UserID) apikey.Key {
	digest := sha256.Sum256(fmt.Appendf(nil, "api-key-%d", n))

	return apikey.Key{
		ID:           id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", 0x300000+n)),
		Principal:    principal,
		Name:         fmt.Sprintf("key %d", n),
		Scopes:       []string{"read"},
		SecretDigest: digest[:],
		CreatedAt:    time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC),
	}
}

// keyRowExists selects whether the key $1 is committed.
const keyRowExists = `SELECT EXISTS (SELECT 1 FROM api_keys WHERE id = $1)`

// apiKeyPresent reports whether key n is committed, read out of band.
func apiKeyPresent(t *testing.T, raw *sql.DB, n int) bool {
	t.Helper()

	return exists(t, raw, keyRowExists, apiKey(n, "").ID.String())
}

func TestAPIKeyStore(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	t.Run("pgx", func(t *testing.T) {
		storetest.RunAPIKeyStoreSuite(t, func(t *testing.T) apikey.Store {
			return newAPIKeyStore(t, emptied(t, db, "api_keys"))
		})
	})
}

func TestNewAPIKeyStore(t *testing.T) {
	t.Parallel()

	pool := unreachablePool(t)

	type testCase struct {
		name   string
		pool   *pgxpool.Pool
		opts   []pgxstore.Option
		assert func(t *testing.T, s *pgxstore.APIKeyStore, err error)
	}

	refused := refusedConfig[*pgxstore.APIKeyStore]
	accepted := acceptedConfig[*pgxstore.APIKeyStore]

	cases := []testCase{
		{name: "a pool is all it needs", pool: pool, assert: accepted},
		{name: "a missing pool is refused", assert: refused("the pool is nil")},
		{
			name:   "an id generator does not apply to keys, which carry their own",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "a clock does not apply to keys",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithClock(time.Now)},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to keys, which hold nothing sealed",
			pool:   pool,
			opts:   []pgxstore.Option{pgxstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := pgxstore.NewAPIKeyStore(tc.pool, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestAPIKeyStore_Durable(t *testing.T) {
	t.Parallel()

	db := migrated(t)

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, db database)
	}

	present := func(ctx context.Context, t *testing.T, n int) bool {
		t.Helper()
		return existsCtx(ctx, t, db.DB, keyRowExists, apiKey(n, "").ID.String())
	}

	cases := []testCase{
		{
			name: "a resolver supplies the transaction: its rollback discards the insert",
			assert: func(t *testing.T, ctx context.Context, db database) {
				tx := beginTx(ctx, t, db.Pool)
				s := newAPIKeyStore(t, db.Pool,
					pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) { return tx, true }))

				require.NoError(t, s.Put(ctx, apiKey(1, "svc")))
				assert.False(t, present(ctx, t, 1), "the insert ran outside the resolver's transaction")
				require.NoError(t, tx.Rollback(ctx))
				assert.False(t, present(ctx, t, 1), "the insert survived the rollback")
			},
		},
		{
			name: "a resolver reporting none runs on the pool, even with a transaction attached",
			assert: func(t *testing.T, ctx context.Context, db database) {
				attached := beginTx(ctx, t, db.Pool)
				s := newAPIKeyStore(t, db.Pool,
					pgxstore.WithTxResolver(func(context.Context) (pgx.Tx, bool) { return nil, false }))

				require.NoError(t, s.Put(pgxstore.WithTx(ctx, attached), apiKey(2, "svc")))
				assert.True(t, present(ctx, t, 2), "the insert is not visible at once")
				require.NoError(t, attached.Rollback(ctx))
				assert.True(t, present(ctx, t, 2), "the insert ran in the attached transaction")
			},
		},
		{
			name: "a key whose revocation time is infinite is an error, never unrevoked",
			assert: func(t *testing.T, ctx context.Context, db database) {
				s := newAPIKeyStore(t, db.Pool)
				key := apiKey(3, "svc-infinite")
				require.NoError(t, s.Put(ctx, key))
				_, err := db.DB.ExecContext(ctx, `UPDATE api_keys SET revoked_at = 'infinity' WHERE id = $1`,
					key.ID.String())
				require.NoError(t, err)

				got, err := s.Get(ctx, key.ID)
				require.Error(t, err, "an infinite revocation time read as %v", got.RevokedAt)
				assert.NotErrorIs(t, err, apikey.ErrKeyNotFound)
				_, err = s.List(ctx, "svc-infinite")
				require.Error(t, err)
			},
		},
		{
			name: "a key holding text PostgreSQL cannot store is refused without echoing it",
			assert: func(t *testing.T, ctx context.Context, db database) {
				key := apiKey(4, "svc")
				key.Scopes = []string{"read", "bad\x00canary-3c9e"}
				err := newAPIKeyStore(t, db.Pool).Put(ctx, key)
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-3c9e")
				assert.False(t, present(ctx, t, 4), "nothing is written")
			},
		},
		{
			name: "a key issued with no scopes stores an empty JSON array, never null",
			assert: func(t *testing.T, ctx context.Context, db database) {
				key := apiKey(10, "svc-no-scopes")
				key.Scopes = nil
				require.NoError(t, newAPIKeyStore(t, db.Pool).Put(ctx, key))

				var scopes string
				require.NoError(t, db.DB.QueryRowContext(ctx,
					`SELECT scopes::text FROM api_keys WHERE id = $1`, key.ID.String()).Scan(&scopes))
				assert.Equal(t, "[]", scopes, "nil scopes are not stored as an empty array")
			},
		},
		{
			name: "a revocation under a cancelled context fails with the cancellation, never as not found",
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, db database) {
				err := newAPIKeyStore(t, db.Pool).Revoke(ctx, apiKey(5, "").ID, time.Now())
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, apikey.ErrKeyNotFound)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx, db)
		})
	}
}
