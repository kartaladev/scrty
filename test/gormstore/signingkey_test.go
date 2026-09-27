package gormstore_test

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/test/storetest"
)

// newSigningKeyStore builds the signing-key store over db, failing t on a
// refusal.
func newSigningKeyStore(t *testing.T, db *gormdb.DB, c seal.Cipher, opts ...gormstore.Option) signingkey.KeyStore {
	t.Helper()

	s, err := gormstore.NewSigningKeyStore(db, c, opts...)
	require.NoError(t, err)

	return s
}

// keyCreated is when every key here was generated; kids break the tie.
var keyCreated = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// signingKey is a record for kid holding private material private.
func signingKey(kid string, private []byte) signingkey.Record {
	return signingkey.Record{
		Kid:       kid,
		Alg:       "ES256",
		Private:   private,
		PublicJWK: []byte(`{"kty":"EC","kid":"` + kid + `"}`),
		CreatedAt: keyCreated,
	}
}

// privateColumn is kid's private_key column as stored.
func privateColumn(ctx context.Context, t *testing.T, db *sql.DB, kid string) []byte {
	t.Helper()

	var b []byte
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT private_key FROM signing_keys WHERE kid = $1`, kid).Scan(&b))

	return b
}

// sealedSigningKeys is the sealed-column suite's view of the signing-key
// store, built by newWith over a cipher on db.
func sealedSigningKeys(
	db *gormdb.DB, newWith func(t *testing.T, db *gormdb.DB, c seal.Cipher) signingkey.KeyStore,
) storetest.Sealed[signingkey.KeyStore] {
	return storetest.Sealed[signingkey.KeyStore]{
		Encoding: storetest.SealedBytes,
		Rotation: storetest.ResealOnRead,
		NewWithKeyring: func(t *testing.T, kr seal.Keyring) signingkey.KeyStore {
			c, err := seal.NewAEADCipher(kr)
			require.NoError(t, err)
			return newWith(t, db, c)
		},
		Put: func(ctx context.Context, s signingkey.KeyStore, owner string, secret []byte) error {
			return s.Store(ctx, signingKey(owner, secret))
		},
		Get: func(ctx context.Context, s signingkey.KeyStore, owner string) ([]byte, bool, error) {
			recs, err := s.LoadAll(ctx)
			if err != nil {
				return nil, false, err
			}
			i := slices.IndexFunc(recs, func(r signingkey.Record) bool { return r.Kid == owner })
			if i < 0 {
				return nil, false, nil
			}
			return recs[i].Private, true, nil
		},
		RawColumn: func(t *testing.T, raw *sql.DB, owner string) []byte {
			return privateColumn(t.Context(), t, raw, owner)
		},
		CopySealed: func(t *testing.T, raw *sql.DB, from, to string) {
			_, err := raw.ExecContext(t.Context(), `UPDATE signing_keys
SET private_key = (SELECT private_key FROM signing_keys WHERE kid = $1) WHERE kid = $2`, from, to)
			require.NoError(t, err)
		},
	}
}

func TestSigningKeyStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := testCipher(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSigningKeyStoreSuite(t, func(t *testing.T) signingkey.KeyStore {
			return newSigningKeyStore(t, emptied(t, d, "signing_keys"), c)
		})
	})
}

func TestSigningKeyStore_SealedColumns(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := testCipher(t)
	h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) signingkey.KeyStore {
		return newSigningKeyStore(t, db, c, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunSealedColumns(t, h, sealedSigningKeys(d.db,
			func(t *testing.T, db *gormdb.DB, c seal.Cipher) signingkey.KeyStore {
				return newSigningKeyStore(t, db, c)
			}))
	})
}

func TestNewSigningKeyStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := testCipher(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		cipher seal.Cipher
		opts   []gormstore.Option
		assert func(t *testing.T, s signingkey.KeyStore, err error)
	}

	refused := refusedConfig[signingkey.KeyStore]
	accepted := acceptedConfig[signingkey.KeyStore]

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name:   "it honours an id generator and re-sealing turned off",
			db:     db,
			cipher: c,
			opts: []gormstore.Option{
				gormstore.WithIDGenerator(id.NewV7Generator()),
				gormstore.WithResealOnRead(false),
			},
			assert: accepted,
		},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{name: "a typed nil cipher is refused", db: db, cipher: (*gatedCipher)(nil), assert: refused("the cipher is nil")},
		{name: "a missing handle is refused", cipher: c, assert: refused("the database handle is nil")},
		{
			name:   "a clock does not apply to signing keys",
			db:     db,
			cipher: c,
			opts:   []gormstore.Option{gormstore.WithClock(time.Now)},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewSigningKeyStore(tc.db, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestSigningKeyStore_Sealed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, d database, keys testKeys)
	}

	// storedUnderK1 stores kid through a store sealing under k1 alone, and
	// returns its sealed column.
	storedUnderK1 := func(t *testing.T, ctx context.Context, d database, keys testKeys, kid string) []byte {
		t.Helper()
		require.NoError(t, newSigningKeyStore(t, d.db, keys.underK1(t)).Store(ctx, signingKey(kid, []byte("PKCS8-"+kid))))
		return privateColumn(ctx, t, d.conn.DB, kid)
	}

	cases := []testCase{
		{
			name: "the private key column does not hold the key, and the store reads it back",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newSigningKeyStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.Store(ctx, signingKey("kid-1", []byte("PKCS8-SENTINEL"))))

				assert.NotContains(t, string(privateColumn(ctx, t, d.conn.DB, "kid-1")), "PKCS8-SENTINEL")
				recs, err := s.LoadAll(ctx)
				require.NoError(t, err)
				require.Len(t, recs, 1)
				assert.Equal(t, []byte("PKCS8-SENTINEL"), recs[0].Private)
			},
		},
		{
			name: "one unreadable key of three fails the whole load and returns no keys",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newSigningKeyStore(t, d.db, keys.rotated(t))
				for _, kid := range []string{"kid-a", "kid-b", "kid-c"} {
					require.NoError(t, s.Store(ctx, signingKey(kid, []byte("PKCS8-"+kid))))
				}
				// Flip the last byte of one key's tag.
				_, err := d.conn.DB.ExecContext(ctx, `UPDATE signing_keys
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
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				before := storedUnderK1(t, ctx, d, keys, "kid-reseal")

				_, err := newSigningKeyStore(t, d.db, keys.rotated(t)).LoadAll(ctx)
				require.NoError(t, err)

				assert.NotEqual(t, before, privateColumn(ctx, t, d.conn.DB, "kid-reseal"), "the read did not re-seal")
				recs, err := newSigningKeyStore(t, d.db, keys.onlyK2(t)).LoadAll(ctx)
				require.NoError(t, err, "the re-sealed key does not open under the active key alone")
				require.Len(t, recs, 1)
				assert.Equal(t, []byte("PKCS8-kid-reseal"), recs[0].Private)
			},
		},
		{
			name: "a read inside a transaction attached with WithTx rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				before := storedUnderK1(t, ctx, d, keys, "kid-in-tx")

				tx := beginGorm(ctx, t, d.db)
				recs, err := newSigningKeyStore(t, d.db, keys.rotated(t)).LoadAll(gormstore.WithTx(ctx, tx))
				require.NoError(t, err)
				require.Len(t, recs, 1)
				require.NoError(t, tx.Commit().Error)

				assert.Equal(t, before, privateColumn(ctx, t, d.conn.DB, "kid-in-tx"), "the read inside a transaction re-sealed")
			},
		},
		{
			name: "a read inside a transaction a resolver reports rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				before := storedUnderK1(t, ctx, d, keys, "kid-resolved")

				tx := beginGorm(ctx, t, d.db)
				s := newSigningKeyStore(t, d.db, keys.rotated(t), gormstore.WithTxResolver(resolving(tx)))
				_, err := s.LoadAll(ctx)
				require.NoError(t, err)
				require.NoError(t, tx.Commit().Error)

				assert.Equal(t, before, privateColumn(ctx, t, d.conn.DB, "kid-resolved"),
					"the read inside a transaction re-sealed")
			},
		},
		{
			name: "with re-sealing turned off a read rewrites nothing",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				before := storedUnderK1(t, ctx, d, keys, "kid-off")

				_, err := newSigningKeyStore(t, d.db, keys.rotated(t), gormstore.WithResealOnRead(false)).LoadAll(ctx)
				require.NoError(t, err)

				assert.Equal(t, before, privateColumn(ctx, t, d.conn.DB, "kid-off"), "the read re-sealed")
			},
		},
		{
			name: "a store of a kid already stored replaces the key and keeps its row",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				s := newSigningKeyStore(t, d.db, keys.rotated(t))
				require.NoError(t, s.Store(ctx, signingKey("kid-replaced", []byte("PKCS8-OLD"))))
				var before string
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT id::text FROM signing_keys WHERE kid = 'kid-replaced'`).Scan(&before))

				replaced := signingKey("kid-replaced", []byte("PKCS8-NEW"))
				replaced.Alg = "EdDSA"
				require.NoError(t, s.Store(ctx, replaced))

				recs, err := s.LoadAll(ctx)
				require.NoError(t, err)
				require.Len(t, recs, 1)
				assert.Equal(t, []byte("PKCS8-NEW"), recs[0].Private)
				assert.Equal(t, signingkey.Alg("EdDSA"), recs[0].Alg)
				var after string
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT id::text FROM signing_keys WHERE kid = 'kid-replaced'`).Scan(&after))
				assert.Equal(t, before, after, "the replacement minted a new row")
			},
		},
		{
			name: "a kid PostgreSQL text cannot hold is refused without echoing it",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				err := newSigningKeyStore(t, d.db, keys.rotated(t)).
					Store(ctx, signingKey("kid\x00canary-5e1f", []byte("PKCS8")))
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "canary-5e1f")
				assert.False(t, existsCtx(ctx, t, d.conn.DB, `SELECT EXISTS (SELECT 1 FROM signing_keys)`), "nothing is written")
			},
		},
		{
			name: "a re-seal does not replace material a concurrent store wrote under the same kid",
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				storedUnderK1(t, ctx, d, keys, "kid-race")

				gated := newGatedCipher(keys.rotated(t))
				reader := newSigningKeyStore(t, d.db, gated)
				type load struct {
					recs []signingkey.Record
					err  error
				}
				done := make(chan load, 1)
				go func() {
					recs, err := reader.LoadAll(ctx)
					done <- load{recs, err}
				}()

				<-gated.opening
				writer := newSigningKeyStore(t, d.db, keys.rotated(t))
				require.NoError(t, writer.Store(ctx, signingKey("kid-race", []byte("PKCS8-NEW"))))
				close(gated.release)
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
			ctx:  cancelled,
			assert: func(t *testing.T, ctx context.Context, d database, keys testKeys) {
				recs, err := newSigningKeyStore(t, d.db, keys.rotated(t)).LoadAll(ctx)
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
			d := migratedDB(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.assert(t, ctx, d, newTestKeys(t))
		})
	}
}

// identityCipher "seals" by returning its input: a store over it keeps the
// plaintext, which the sealed-column suite must catch.
type identityCipher struct{}

func (identityCipher) Seal(plaintext, _ []byte) ([]byte, error) { return slices.Clone(plaintext), nil }

func (identityCipher) Open(sealed, _ []byte) ([]byte, string, error) {
	return slices.Clone(sealed), "k2", nil
}

func (identityCipher) ActiveKeyID() (string, error) { return "k2", nil }
