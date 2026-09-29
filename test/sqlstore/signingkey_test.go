package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newSigningKeyStore builds the signing-key store over db, failing t on a
// refusal.
func newSigningKeyStore(t *testing.T, db *sql.DB, c seal.Cipher, opts ...sqlstore.Option) signingkey.KeyStore {
	t.Helper()

	s, err := sqlstore.NewSigningKeyStore(db, c, opts...)
	require.NoError(t, err)

	return s
}

func TestSigningKeyStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	c := storefix.TestCipher(t)

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunSigningKeyStoreSuite(t, func(t *testing.T) signingkey.KeyStore {
			return newSigningKeyStore(t, emptied(t, db, "signing_keys"), c)
		})
	})
}

func TestSigningKeyStore_SealedColumns(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)
	c := storefix.TestCipher(t)
	h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) signingkey.KeyStore {
		return newSigningKeyStore(t, db, c, opts...)
	})

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, storefix.SealedSigningKeys(conn.DB,
			func(t *testing.T, db *sql.DB, c seal.Cipher) signingkey.KeyStore {
				return newSigningKeyStore(t, db, c)
			}))
	})
}

func TestNewSigningKeyStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		db     *sql.DB
		cipher seal.Cipher
		opts   []sqlstore.Option
		assert func(t *testing.T, s signingkey.KeyStore, err error)
	}

	refused := refusedConfig[signingkey.KeyStore]
	accepted := storefix.AcceptedConfig[signingkey.KeyStore]

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name:   "it honours re-sealing on read turned off",
			db:     db,
			cipher: c,
			opts:   []sqlstore.Option{sqlstore.WithResealOnRead(false)},
			assert: accepted,
		},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{name: "a missing handle is refused", cipher: c, assert: refused("the database handle is nil")},
		{
			name:   "a clock does not apply to signing keys",
			db:     db,
			cipher: c,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewSigningKeyStore(tc.db, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestSigningKeyStore_Sealed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys)
	}

	// storedUnderK1 stores kid through a store sealing under k1 alone, and
	// returns its sealed column.
	storedUnderK1 := func(t *testing.T, ctx context.Context, db *sql.DB, keys storefix.Keys, kid string) []byte {
		t.Helper()
		require.NoError(t, newSigningKeyStore(t, db, keys.UnderK1(t)).Store(ctx, storefix.SigningKey(kid, []byte("PKCS8-"+kid))))
		return storefix.PrivateColumn(ctx, t, db, kid)
	}

	cases := []testCase{
		{
			name: "the private key column does not hold the key, and the store reads it back",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				s := newSigningKeyStore(t, conn.DB, keys.Rotated(t))
				require.NoError(t, s.Store(ctx, storefix.SigningKey("kid-1", []byte("PKCS8-SENTINEL"))))

				assert.NotContains(t, string(storefix.PrivateColumn(ctx, t, conn.DB, "kid-1")), "PKCS8-SENTINEL")
				recs, err := s.LoadAll(ctx)
				require.NoError(t, err)
				require.Len(t, recs, 1)
				assert.Equal(t, []byte("PKCS8-SENTINEL"), recs[0].Private)
			},
		},
		{
			name: "one unreadable key of three fails the whole load and returns no keys",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				s := newSigningKeyStore(t, conn.DB, keys.Rotated(t))
				for _, kid := range []string{"kid-a", "kid-b", "kid-c"} {
					require.NoError(t, s.Store(ctx, storefix.SigningKey(kid, []byte("PKCS8-"+kid))))
				}
				// Flip the last byte of one key's tag.
				_, err := conn.DB.ExecContext(ctx, `UPDATE signing_keys
SET private_key = overlay(private_key placing
  decode(lpad(to_hex(get_byte(private_key, length(private_key) - 1) # 1), 2, '0'), 'hex')
  from length(private_key))
WHERE kid = 'kid-b'`)
				require.NoError(t, err)

				recs, err := s.LoadAll(ctx)
				require.ErrorIs(t, err, seal.ErrDecryptionFailed)
				assert.Nil(t, recs)
			},
		},
		{
			name: "a read outside a transaction re-seals a key under the active key",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				before := storedUnderK1(t, ctx, conn.DB, keys, "kid-reseal")

				_, err := newSigningKeyStore(t, conn.DB, keys.Rotated(t)).LoadAll(ctx)
				require.NoError(t, err)

				assert.NotEqual(t, before, storefix.PrivateColumn(ctx, t, conn.DB, "kid-reseal"), "the read did not re-seal")
			},
		},
		{
			name: "a read inside a transaction attached with WithTx rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				before := storedUnderK1(t, ctx, conn.DB, keys, "kid-in-tx")

				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback() })
				recs, err := newSigningKeyStore(t, conn.DB, keys.Rotated(t)).LoadAll(sqlstore.WithTx(ctx, tx))
				require.NoError(t, err)
				require.Len(t, recs, 1)
				require.NoError(t, tx.Commit())

				assert.Equal(t, before, storefix.PrivateColumn(ctx, t, conn.DB, "kid-in-tx"), "the read inside a transaction re-sealed")
			},
		},
		{
			name: "a read inside a transaction a resolver reports rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				before := storedUnderK1(t, ctx, conn.DB, keys, "kid-resolved")

				tx, err := conn.DB.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback() })
				s := newSigningKeyStore(t, conn.DB, keys.Rotated(t),
					sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) { return tx, true }))
				_, err = s.LoadAll(ctx)
				require.NoError(t, err)
				require.NoError(t, tx.Commit())

				assert.Equal(t, before, storefix.PrivateColumn(ctx, t, conn.DB, "kid-resolved"),
					"the read inside a transaction re-sealed")
			},
		},
		{
			name: "with re-sealing turned off a read rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				before := storedUnderK1(t, ctx, conn.DB, keys, "kid-off")

				_, err := newSigningKeyStore(t, conn.DB, keys.Rotated(t), sqlstore.WithResealOnRead(false)).LoadAll(ctx)
				require.NoError(t, err)

				assert.Equal(t, before, storefix.PrivateColumn(ctx, t, conn.DB, "kid-off"), "the read re-sealed")
			},
		},
		{
			name: "a re-seal does not replace material a concurrent store wrote under the same kid",
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				storedUnderK1(t, ctx, conn.DB, keys, "kid-race")

				gated := storefix.NewGatedCipher(keys.Rotated(t))
				reader := newSigningKeyStore(t, conn.DB, gated)
				type load struct {
					recs []signingkey.Record
					err  error
				}
				done := make(chan load, 1)
				go func() {
					recs, err := reader.LoadAll(ctx)
					done <- load{recs, err}
				}()

				<-gated.Opening()
				writer := newSigningKeyStore(t, conn.DB, keys.Rotated(t))
				require.NoError(t, writer.Store(ctx, storefix.SigningKey("kid-race", []byte("PKCS8-NEW"))))
				gated.Release()
				got := <-done
				require.NoError(t, got.err)
				require.Len(t, got.recs, 1)
				require.Equal(t, []byte("PKCS8-kid-race"), got.recs[0].Private, "the gated read opened the old material")

				recs, err := writer.LoadAll(ctx)
				require.NoError(t, err)
				require.Len(t, recs, 1)
				assert.Equal(t, []byte("PKCS8-NEW"), recs[0].Private, "the re-seal overwrote the concurrent store")
			},
		},
		{
			name: "a load under a cancelled context fails with the cancellation",
			ctx:  storefix.Cancelled,
			assert: func(t *testing.T, ctx context.Context, conn test.PostgresConn, keys storefix.Keys) {
				recs, err := newSigningKeyStore(t, conn.DB, keys.Rotated(t)).LoadAll(ctx)
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, recs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Each case has a database of its own: LoadAll reads the whole
			// table, so one case's keys would be another's.
			conn := migratedDB(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx, conn, storefix.NewKeys(t))
		})
	}
}
