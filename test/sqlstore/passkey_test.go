package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newPasskeyCredentialStore builds the passkey credential store over db,
// failing t on a refusal.
func newPasskeyCredentialStore(
	t *testing.T, db *sql.DB, c seal.Cipher, opts ...sqlstore.Option,
) *sqlstore.PasskeyCredentialStore {
	t.Helper()

	s, err := sqlstore.NewPasskeyCredentialStore(db, c, opts...)
	require.NoError(t, err)

	return s
}

// newPasskeyHandleStore builds the passkey handle store over db, failing t on
// a refusal.
func newPasskeyHandleStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.PasskeyHandleStore {
	t.Helper()

	s, err := sqlstore.NewPasskeyHandleStore(db, opts...)
	require.NoError(t, err)

	return s
}

func TestPasskeyCredentialStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	c := storefix.TestCipher(t)

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunPasskeyCredentialStoreSuite(t, func(t *testing.T) passkey.CredentialStore {
			return newPasskeyCredentialStore(t, emptied(t, db, "passkey_credentials"), c)
		})
	})
}

func TestPasskeyHandleStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunPasskeyHandleStoreSuite(t, func(t *testing.T) passkey.HandleStore {
			return newPasskeyHandleStore(t, emptied(t, db, "passkey_user_handles"))
		})
	})
}

// The races, the ambient-transaction suite and the sealed-column suite write
// records of their own, so they share one database.
func TestPasskeyCredentialStore_Durable(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)
	c := storefix.TestCipher(t)
	h := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.PasskeyCredentialStore {
		return newPasskeyCredentialStore(t, db, c, opts...)
	})
	sealedHarness := durableHarness(conn, func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) passkey.CredentialStore {
		return newPasskeyCredentialStore(t, db, c, opts...)
	})

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.PasskeyCounterRace[*sqlstore.PasskeyCredentialStore]())
		storetest.RunLinkInsertRace(t, h, storefix.PasskeyInsertRace[*sqlstore.PasskeyCredentialStore]())
		storetest.RunAmbientTx(t, h, storefix.PasskeyCredentialAmbient[*sqlstore.PasskeyCredentialStore]())
		storetest.RunSealedColumns(t, sealedHarness, storefix.SealedPasskeyCodes(conn.DB,
			func(t *testing.T, db *sql.DB, c seal.Cipher) passkey.CredentialStore {
				return newPasskeyCredentialStore(t, db, c)
			}))
		storefix.RunPasskeyCodeAtRest(t, conn.DB, newPasskeyCredentialStore(t, conn.DB, c))
	})
}

func TestPasskeyHandleStore_Durable(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.PasskeyHandleStore {
		return newPasskeyHandleStore(t, db, opts...)
	})

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.PasskeyHandleRace[*sqlstore.PasskeyHandleStore]())
		storetest.RunAmbientTx(t, h, storefix.PasskeyHandleAmbient[*sqlstore.PasskeyHandleStore]())
	})
}

// TestPasskeyCredentialStore_Rows checks what only the stored rows show, and
// the refusals of values the columns cannot carry.
func TestPasskeyCredentialStore_Rows(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore)
	}

	cases := []testCase{
		{
			name: "Insert rolled back with the caller",
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore) {
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback() })

				cred := storefix.PasskeyCredential(storefix.NewID(t), "rows-rolled-back", "rows-rolled-back")
				require.NoError(t, s.Insert(sqlstore.WithTx(ctx, tx), cred))
				require.NoError(t, tx.Rollback())

				assert.False(t, storefix.Exists(t, db,
					`SELECT EXISTS (SELECT 1 FROM passkey_credentials WHERE id = $1)`, cred.ID),
					"the credential survived its caller's rollback")
			},
		},
		{
			name: "transports are stored one per line, and the counter as an unsigned 32-bit value",
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore) {
				cred := storefix.PasskeyCredential(storefix.NewID(t), "rows-transports", "rows-transports")
				cred.SignCount = 1<<32 - 1
				require.NoError(t, s.Insert(ctx, cred))

				var (
					transports string
					count      int64
				)
				require.NoError(t, db.QueryRowContext(ctx,
					`SELECT transports, sign_count FROM passkey_credentials WHERE id = $1`, cred.ID).
					Scan(&transports, &count))
				assert.Equal(t, "internal\nhybrid", transports)
				assert.Equal(t, int64(1<<32-1), count)
			},
		},
		{
			name: "a transport holding a newline is refused, naming the field, and nothing is written",
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore) {
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
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore) {
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
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore) {
				err := s.Insert(ctx, storefix.PasskeyCredential(id.Nil, "rows-zero", "rows-zero"))
				require.Error(t, err)
				assert.NotErrorIs(t, err, passkey.ErrDuplicateCredential)
				assert.ErrorContains(t, err, "sqlstore: insert passkey credential")
			},
		},
		{
			name: "a stored emailed code that is not base64url fails the read, never read as no code",
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.PasskeyCredentialStore) {
				cred := storefix.PasskeyAwaitingCode(
					storefix.PasskeyCredential(storefix.NewID(t), "rows-corrupt", "rows-corrupt"), "123456")
				require.NoError(t, s.Insert(ctx, cred))
				_, err := db.ExecContext(ctx,
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

			tc.assert(t, t.Context(), newPasskeyCredentialStore(t, db, c))
		})
	}
}

func TestNewPasskeyCredentialStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)
	c := storefix.TestCipher(t)

	type testCase struct {
		name   string
		db     *sql.DB
		cipher seal.Cipher
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.PasskeyCredentialStore, err error)
	}

	refused := refusedConfig[*sqlstore.PasskeyCredentialStore]
	accepted := storefix.AcceptedConfig[*sqlstore.PasskeyCredentialStore]
	resolver := func(context.Context) (sqlstore.DBTX, bool) { return nil, false }

	cases := []testCase{
		{name: "a handle and a cipher are all it needs", db: db, cipher: c, assert: accepted},
		{
			name: "it honours a resolver", db: db, cipher: c,
			opts: []sqlstore.Option{sqlstore.WithTxResolver(resolver)}, assert: accepted,
		},
		{name: "a missing handle is refused", cipher: c, assert: refused("the database handle is nil")},
		{name: "a missing cipher is refused", db: db, assert: refused("the cipher is nil")},
		{
			name: "a nil option is refused", db: db, cipher: c,
			opts: []sqlstore.Option{nil}, assert: refused("an option is nil"),
		},
		{
			name: "an id generator does not apply to credentials, which carry their own", db: db, cipher: c,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name: "a clock does not apply, since every time comes from the caller", db: db, cipher: c,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewPasskeyCredentialStore(tc.db, tc.cipher, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestNewPasskeyHandleStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.PasskeyHandleStore, err error)
	}

	refused := refusedConfig[*sqlstore.PasskeyHandleStore]
	accepted := storefix.AcceptedConfig[*sqlstore.PasskeyHandleStore]
	resolver := func(context.Context) (sqlstore.DBTX, bool) { return nil, false }

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{
			name:   "it honours an id generator and a resolver",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(id.NewV7Generator()), sqlstore.WithTxResolver(resolver)},
			assert: accepted,
		},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{name: "a nil option is refused", db: db, opts: []sqlstore.Option{nil}, assert: refused("an option is nil")},
		{
			name:   "a nil id generator is refused",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(nil)},
			assert: refused("the id generator is nil"),
		},
		{
			name:   "a clock does not apply, since the store judges no time",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewPasskeyHandleStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// TestPasskeyHandleStore_Rows checks the configured row identifier and the
// refusal of a user reference the column cannot hold.
func TestPasskeyHandleStore_Rows(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("rows carry the configured identifiers", func(t *testing.T) {
		t.Parallel()

		want := storefix.NewID(t)
		s := newPasskeyHandleStore(t, db, sqlstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
			return want, nil
		})))
		_, err := s.Assign(t.Context(), "rows-handle-ids", storefix.PasskeyOffer("rows-handle-ids", 0))
		require.NoError(t, err)

		var got id.ID
		require.NoError(t, db.QueryRowContext(t.Context(),
			`SELECT id FROM passkey_user_handles WHERE user_id = $1`, "rows-handle-ids").Scan(&got))
		assert.Equal(t, want, got)
	})

	t.Run("a user reference PostgreSQL text cannot hold is refused, naming the field", func(t *testing.T) {
		t.Parallel()

		const user identity.UserID = "rows-\x00-handle"
		s := newPasskeyHandleStore(t, db)
		h, err := s.Assign(t.Context(), user, storefix.PasskeyOffer(string(user), 0))
		require.Error(t, err)
		assert.Nil(t, h)
		storefix.AssertNamesOnly(t, err, "user", string(user))
	})
}
