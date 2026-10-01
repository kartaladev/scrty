package gormstore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newPasskeyCredentialStore builds the passkey credential store over db,
// failing t on a refusal.
func newPasskeyCredentialStore(
	t *testing.T, db *gormdb.DB, c seal.Cipher, opts ...gormstore.Option,
) *gormstore.PasskeyCredentialStore {
	t.Helper()

	s, err := gormstore.NewPasskeyCredentialStore(db, c, opts...)
	require.NoError(t, err)

	return s
}

// newPasskeyHandleStore builds the passkey handle store over db, failing t on
// a refusal.
func newPasskeyHandleStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.PasskeyHandleStore {
	t.Helper()

	s, err := gormstore.NewPasskeyHandleStore(db, opts...)
	require.NoError(t, err)

	return s
}

func TestPasskeyCredentialStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunPasskeyCredentialStoreSuite(t, func(t *testing.T) passkey.CredentialStore {
			return newPasskeyCredentialStore(t, emptied(t, d, "passkey_credentials"), c)
		})
	})
}

func TestPasskeyHandleStore(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunPasskeyHandleStoreSuite(t, func(t *testing.T) passkey.HandleStore {
			return newPasskeyHandleStore(t, emptied(t, d, "passkey_user_handles"))
		})
	})
}

// The races, the ambient-transaction suite and the sealed-column suite write
// records of their own, so they share one database.
func TestPasskeyCredentialStore_Durable(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)
	h := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.PasskeyCredentialStore {
		return newPasskeyCredentialStore(t, db, c, opts...)
	})
	sealedHarness := durableHarness(d, func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) passkey.CredentialStore {
		return newPasskeyCredentialStore(t, db, c, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.PasskeyCounterRace[*gormstore.PasskeyCredentialStore]())
		storetest.RunLinkInsertRace(t, h, storefix.PasskeyInsertRace[*gormstore.PasskeyCredentialStore]())
		storetest.RunAmbientTx(t, h, storefix.PasskeyCredentialAmbient[*gormstore.PasskeyCredentialStore]())
		storetest.RunSealedColumns(t, sealedHarness, storefix.SealedPasskeyCodes(d.db,
			func(t *testing.T, db *gormdb.DB, c seal.Cipher) passkey.CredentialStore {
				return newPasskeyCredentialStore(t, db, c)
			}))
		storefix.RunPasskeyCodeAtRest(t, d.conn.DB, newPasskeyCredentialStore(t, d.db, c))
		storefix.RunPasskeyCodeBinding(t, d.conn.DB, newPasskeyCredentialStore(t, d.db, c))
		storefix.RunPasskeyClearedCodeRow(t, d.conn.DB, newPasskeyCredentialStore(t, d.db, c))
	})
}

func TestPasskeyHandleStore_Durable(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.PasskeyHandleStore {
		return newPasskeyHandleStore(t, db, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.PasskeyHandleRace[*gormstore.PasskeyHandleStore]())
		storetest.RunAmbientTx(t, h, storefix.PasskeyHandleAmbient[*gormstore.PasskeyHandleStore]())
	})
}

// TestPasskeyCredentialStore_Rows checks what only the stored rows show, and
// the refusals of values the columns cannot carry.
func TestPasskeyCredentialStore_Rows(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore)
	}

	cases := []testCase{
		{
			name: "Insert rolled back with the caller",
			assert: func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore) {
				tx := beginGorm(ctx, t, d.db)

				cred := storefix.PasskeyCredential(storefix.NewID(t), "rows-rolled-back", "rows-rolled-back")
				require.NoError(t, s.Insert(gormstore.WithTx(ctx, tx), cred))
				require.NoError(t, tx.Rollback().Error)

				assert.False(t, storefix.Exists(t, d.conn.DB,
					`SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE id = $1)`, cred.ID),
					"the credential survived its caller's rollback")
			},
		},
		{
			name: "transports are stored one per line, and the counter as an unsigned 32-bit value",
			assert: func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore) {
				cred := storefix.PasskeyCredential(storefix.NewID(t), "rows-transports", "rows-transports")
				cred.SignCount = 1<<32 - 1
				require.NoError(t, s.Insert(ctx, cred))

				var (
					transports string
					count      int64
				)
				require.NoError(t, d.conn.DB.QueryRowContext(ctx,
					`SELECT transports, sign_count FROM passkey_credentials WHERE id = $1`, cred.ID).
					Scan(&transports, &count))
				assert.Equal(t, "internal\nhybrid", transports)
				assert.Equal(t, int64(1<<32-1), count)
			},
		},
		{
			name: "a transport holding a newline is refused, naming the field, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore) {
				cred := storefix.PasskeyCredential(storefix.NewID(t), "rows-newline", "rows-newline")
				cred.Transports = []string{"usb\nnfc"}

				err := s.Insert(ctx, cred)
				require.Error(t, err)
				storefix.AssertNamesOnly(t, err, "transports", "usb")
				_, err = s.FindByCredentialID(ctx, cred.CredentialID)
				require.ErrorIs(t, err, passkey.ErrNotFound)
			},
		},
		{
			name: "a user reference PostgreSQL text cannot hold is refused by insert and matches nothing",
			assert: func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore) {
				const user identity.UserID = "rows-\x00-nul"
				cred := storefix.PasskeyCredential(storefix.NewID(t), user, "rows-nul")

				err := s.Insert(ctx, cred)
				require.Error(t, err)
				storefix.AssertNamesOnly(t, err, "user", string(user))

				_, err = s.Find(ctx, user, cred.ID)
				require.ErrorIs(t, err, passkey.ErrNotFound)
				n, err := s.Count(ctx, user)
				require.NoError(t, err)
				assert.Zero(t, n)
				ok, err := s.Rename(ctx, user, cred.ID, "x")
				require.NoError(t, err)
				assert.False(t, ok)
				n, err = s.DeleteUser(ctx, user)
				require.NoError(t, err)
				assert.Zero(t, n)
			},
		},
		{
			name: "a zero library identifier is refused",
			assert: func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore) {
				err := s.Insert(ctx, storefix.PasskeyCredential(id.Nil, "rows-zero", "rows-zero"))
				require.Error(t, err)
				assert.NotErrorIs(t, err, passkey.ErrDuplicateCredential)
				assert.ErrorContains(t, err, "gorm: insert passkey credential")
			},
		},
		{
			name: "a stored emailed code that is not base64url fails the read, never read as no code",
			assert: func(t *testing.T, ctx context.Context, s *gormstore.PasskeyCredentialStore) {
				cred := storefix.PasskeyAwaitingCode(
					storefix.PasskeyCredential(storefix.NewID(t), "rows-corrupt", "rows-corrupt"), "123456")
				require.NoError(t, s.Insert(ctx, cred))
				_, err := d.conn.DB.ExecContext(ctx,
					`UPDATE passkey_credentials SET email_code = '***' WHERE id = $1`, cred.ID)
				require.NoError(t, err)

				got, err := s.FindByCredentialID(ctx, cred.CredentialID)
				require.Error(t, err)
				assert.NotErrorIs(t, err, passkey.ErrNotFound)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), newPasskeyCredentialStore(t, d.db, c))
		})
	}
}

func TestNewPasskeyCredentialStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		cipher seal.Cipher
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.PasskeyCredentialStore, err error)
	}

	refused := refusedConfig[*gormstore.PasskeyCredentialStore]
	accepted := storefix.AcceptedConfig[*gormstore.PasskeyCredentialStore]
	resolver := func(context.Context) (*gormdb.DB, bool) { return nil, false }

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name: "it honours a resolver", db: db, cipher: c,
			opts: []gormstore.Option{gormstore.WithTxResolver(resolver)}, assert: accepted,
		},
		{name: "a missing handle is refused", cipher: c, assert: refused("the database handle is nil")},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{
			name: "a nil option is refused", db: db, cipher: c,
			opts: []gormstore.Option{nil}, assert: refused("an option is nil"),
		},
		{
			name: "an id generator does not apply to credentials, which carry their own", db: db, cipher: c,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name: "a clock does not apply, since every time comes from the caller", db: db, cipher: c,
			opts:   []gormstore.Option{gormstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewPasskeyCredentialStore(tc.db, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestNewPasskeyHandleStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.PasskeyHandleStore, err error)
	}

	refused := refusedConfig[*gormstore.PasskeyHandleStore]
	accepted := storefix.AcceptedConfig[*gormstore.PasskeyHandleStore]
	resolver := func(context.Context) (*gormdb.DB, bool) { return nil, false }

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{
			name:   "it honours an id generator and a resolver",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(id.NewV7Generator()), gormstore.WithTxResolver(resolver)},
			assert: accepted,
		},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{name: "a nil option is refused", db: db, opts: []gormstore.Option{nil}, assert: refused("an option is nil")},
		{
			name:   "a nil id generator is refused",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(nil)},
			assert: refused("the id generator is nil"),
		},
		{
			name:   "a clock does not apply, since the store judges no time",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewPasskeyHandleStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// TestPasskeyHandleStore_Rows checks the configured row identifier and the
// refusal of a user reference the column cannot hold.
func TestPasskeyHandleStore_Rows(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	t.Run("rows carry the configured identifiers", func(t *testing.T) {
		t.Parallel()

		want := storefix.NewID(t)
		s := newPasskeyHandleStore(t, d.db, gormstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
			return want, nil
		})))
		_, err := s.Assign(t.Context(), "rows-handle-ids", storefix.PasskeyOffer("rows-handle-ids", 0))
		require.NoError(t, err)

		var got id.ID
		require.NoError(t, d.conn.DB.QueryRowContext(t.Context(),
			`SELECT id FROM passkey_user_handles WHERE user_id = $1`, "rows-handle-ids").Scan(&got))
		assert.Equal(t, want, got)
	})

	t.Run("a user reference PostgreSQL text cannot hold is refused, naming the field", func(t *testing.T) {
		t.Parallel()

		const user identity.UserID = "rows-\x00-handle"
		s := newPasskeyHandleStore(t, d.db)
		h, err := s.Assign(t.Context(), user, storefix.PasskeyOffer(string(user), 0))
		require.Error(t, err)
		assert.Nil(t, h)
		storefix.AssertNamesOnly(t, err, "user", string(user))
	})
}
