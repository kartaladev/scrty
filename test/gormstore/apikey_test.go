package gormstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/apikey"
	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/test/storetest"
)

// newAPIKeyStore builds the API key store over db, failing t on a refusal.
func newAPIKeyStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.APIKeyStore {
	t.Helper()

	s, err := gormstore.NewAPIKeyStore(db, opts...)
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

	return exists(t, raw, keyRowExists, apiKey(n, "").ID)
}

func TestAPIKeyStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunAPIKeyStoreSuite(t, func(t *testing.T) apikey.Store {
			return newAPIKeyStore(t, emptied(t, d, "api_keys"))
		})
	})
}

func TestNewAPIKeyStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.APIKeyStore, err error)
	}

	refused := refusedConfig[*gormstore.APIKeyStore]
	accepted := acceptedConfig[*gormstore.APIKeyStore]

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{
			name:   "an id generator does not apply to keys, which carry their own",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "a clock does not apply to keys",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithClock(time.Now)},
			assert: refused("WithClock does not apply to this store"),
		},
		{
			name:   "re-sealing does not apply to keys, which hold nothing sealed",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithResealOnRead(false)},
			assert: refused("WithResealOnRead does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewAPIKeyStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// TestAPIKeyStore_NilScopes pins the stored form of a key issued with no
// scopes: an empty JSON array, the ordered list the column holds, never null.
func TestAPIKeyStore_NilScopes(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	ctx := t.Context()
	key := apiKey(10, "svc-no-scopes")
	key.Scopes = nil
	require.NoError(t, newAPIKeyStore(t, d.db).Put(ctx, key))

	var scopes string
	require.NoError(t, d.conn.DB.QueryRowContext(ctx,
		`SELECT scopes::text FROM api_keys WHERE id = $1`, key.ID.String()).Scan(&scopes))
	assert.Equal(t, "[]", scopes, "nil scopes are not stored as an empty array")
}

func TestAPIKeyStore_Resolver(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}

	cases := []testCase{
		{
			name: "a resolver supplies the transaction: its rollback discards the insert",
			assert: func(t *testing.T, ctx context.Context, d database) {
				tx := beginGorm(ctx, t, d.db)
				s := newAPIKeyStore(t, d.db, gormstore.WithTxResolver(resolving(tx)))

				require.NoError(t, s.Put(ctx, apiKey(1, "svc")))
				assert.False(t, existsCtx(ctx, t, d.conn.DB, keyRowExists, apiKey(1, "").ID),
					"the insert ran outside the resolver's transaction")
				require.NoError(t, tx.Rollback().Error)
				assert.False(t, existsCtx(ctx, t, d.conn.DB, keyRowExists, apiKey(1, "").ID), "the insert survived the rollback")
			},
		},
		{
			name: "a resolver reporting none runs on the handle, even with a transaction attached",
			assert: func(t *testing.T, ctx context.Context, d database) {
				attached := beginGorm(ctx, t, d.db)
				s := newAPIKeyStore(t, d.db, gormstore.WithTxResolver(noTransaction))

				require.NoError(t, s.Put(gormstore.WithTx(ctx, attached), apiKey(2, "svc")))
				assert.True(t, existsCtx(ctx, t, d.conn.DB, keyRowExists, apiKey(2, "").ID), "the insert is not visible at once")
				require.NoError(t, attached.Rollback().Error)
				assert.True(t, existsCtx(ctx, t, d.conn.DB, keyRowExists, apiKey(2, "").ID),
					"the insert ran in the attached transaction")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, t.Context(), d)
		})
	}
}

// noTransaction is a resolver that never reports a transaction, so a store
// built with it writes through its own handle whatever the context carries.
func noTransaction(context.Context) (*gormdb.DB, bool) { return nil, false }
