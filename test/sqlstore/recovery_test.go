package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newRecoveryCodeStore builds the saved-code store over db, failing t on a
// refusal.
func newRecoveryCodeStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.RecoveryCodeStore {
	t.Helper()

	s, err := sqlstore.NewRecoveryCodeStore(db, opts...)
	require.NoError(t, err)

	return s
}

// newRecoveryRecordStore builds the recovery-record store over db, failing t
// on a refusal.
func newRecoveryRecordStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.RecoveryRecordStore {
	t.Helper()

	s, err := sqlstore.NewRecoveryRecordStore(db, opts...)
	require.NoError(t, err)

	return s
}

// recoveryHashes returns n distinct 32-byte hashes derived from label.
func recoveryHashes(label string, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256(fmt.Appendf(nil, "%s-%d", label, i))
		out[i] = h[:]
	}

	return out
}

// recoveryAt is the instant the driver-level cases stamp their writes with.
var recoveryAt = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// The saved-code store takes its times from the caller, so the suite's clock
// is not passed on.
func TestRecoveryCodeStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunRecoveryCodeStoreSuite(t, func(t *testing.T, _ clock.Clock) recovery.CodeStore {
			return newRecoveryCodeStore(t, emptied(t, db, "recovery_codes"))
		})
	})
}

func TestRecoveryRecordStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunRecoveryRecordStoreSuite(t, func(t *testing.T, _ clock.Clock) recovery.RecordStore {
			return newRecoveryRecordStore(t, emptied(t, db, "account_recoveries"))
		})
	})
}

// The race, the ambient-transaction suite and the replacement's transaction
// cases write records of their own users, so they share one database.
func TestRecoveryCodeStore_Durable(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.RecoveryCodeStore {
		return newRecoveryCodeStore(t, db, opts...)
	})

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.RecoverySpendRace[*sqlstore.RecoveryCodeStore]())
		storetest.RunAmbientTx(t, h, storefix.RecoveryCodeAmbient[*sqlstore.RecoveryCodeStore]())
		storetest.RunRecoveryCodeTx(t, h)
	})
}

func TestRecoveryRecordStore_Durable(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) *sqlstore.RecoveryRecordStore {
		return newRecoveryRecordStore(t, db, opts...)
	})

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.RecoveryRecordRace[*sqlstore.RecoveryRecordStore]())
		storetest.RunAmbientTx(t, h, storefix.RecoveryRecordAmbient[*sqlstore.RecoveryRecordStore]())
	})
}

// spentAt reads user's code hash's spent_at out of band.
func spentAt(ctx context.Context, t *testing.T, db *sql.DB, user identity.UserID, hash []byte) sql.NullTime {
	t.Helper()

	var at sql.NullTime
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT spent_at FROM recovery_codes WHERE user_id = $1 AND code_hash = $2`, string(user), hash).Scan(&at))

	return at
}

// TestRecoveryCodeStore_Rows checks what only the stored rows show: the first
// spending time kept, the configured row identifiers, and a replacement that
// fails part way leaving the previous set whole, inside and outside a caller's
// transaction.
func TestRecoveryCodeStore_Rows(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)
	db := conn.DB

	type testCase struct {
		name   string
		user   identity.UserID
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, ctx context.Context, user identity.UserID)
	}

	cases := []testCase{
		{
			name: "a code spent twice keeps its first spending time",
			user: "rows-user-spent-twice",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				s := newRecoveryCodeStore(t, db)
				hashes := recoveryHashes(string(user), 2)
				require.NoError(t, s.ReplaceSet(ctx, user, hashes, recoveryAt))

				first := recoveryAt.Add(time.Minute + 123456789*time.Nanosecond)
				ok, err := s.Spend(ctx, user, hashes[0], first)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = s.Spend(ctx, user, hashes[0], first.Add(time.Hour))
				require.NoError(t, err)
				assert.False(t, ok)

				at := spentAt(ctx, t, db, user, hashes[0])
				require.True(t, at.Valid)
				want := first.Truncate(time.Microsecond)
				assert.True(t, want.Equal(at.Time), "spent_at is %v, want the first spend at %v", at.Time, want)
				assert.False(t, spentAt(ctx, t, db, user, hashes[1]).Valid, "the other code must stay unspent")
			},
		},
		{
			name: "rows carry the configured identifiers and the replacement time",
			user: "rows-user-ids",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				want := storefix.NewID(t)
				s := newRecoveryCodeStore(t, db, sqlstore.WithIDGenerator(storefix.GeneratorFunc(func() (id.ID, error) {
					return want, nil
				})))
				require.NoError(t, s.ReplaceSet(ctx, user, recoveryHashes(string(user), 1), recoveryAt))

				var (
					got     id.ID
					created time.Time
				)
				require.NoError(t, db.QueryRowContext(ctx,
					`SELECT id, created_at FROM recovery_codes WHERE user_id = $1`, string(user)).Scan(&got, &created))
				assert.Equal(t, want, got)
				assert.True(t, recoveryAt.Equal(created), "created_at is %v, want %v", created, recoveryAt)
			},
		},
		{
			name: "a replacement failing part way leaves the previous set whole",
			user: "rows-user-fails-alone",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				old := recoveryHashes(string(user)+"-old", 3)
				require.NoError(t, newRecoveryCodeStore(t, db).ReplaceSet(ctx, user, old, recoveryAt))

				failing := newRecoveryCodeStore(t, db, sqlstore.WithIDGenerator(fixedIDs{storefix.NewID(t)}))
				require.Error(t, failing.ReplaceSet(ctx, user, recoveryHashes(string(user)+"-new", 2), recoveryAt))

				assertSet(ctx, t, newRecoveryCodeStore(t, db), user, old)
			},
		},
		{
			name: "inside a caller's transaction, a failed replacement undoes only its own statements",
			user: "rows-user-fails-in-tx",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				old := recoveryHashes(string(user)+"-old", 3)
				s := newRecoveryCodeStore(t, db)
				require.NoError(t, s.ReplaceSet(ctx, user, old, recoveryAt))

				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tx.Rollback() })
				txCtx := sqlstore.WithTx(ctx, tx)

				other := user + "-other"
				require.NoError(t, s.ReplaceSet(txCtx, other, recoveryHashes(string(other), 2), recoveryAt),
					"the caller's earlier write")

				failing := newRecoveryCodeStore(t, db, sqlstore.WithIDGenerator(fixedIDs{storefix.NewID(t)}))
				require.Error(t, failing.ReplaceSet(txCtx, user, recoveryHashes(string(user)+"-new", 2), recoveryAt))

				n, err := s.Remaining(txCtx, other)
				require.NoError(t, err, "the caller's transaction must stay usable after the failed replacement")
				assert.Equal(t, 2, n)
				require.NoError(t, tx.Commit())

				reader := newRecoveryCodeStore(t, db)
				assertSet(ctx, t, reader, user, old)
				n, err = reader.Remaining(ctx, other)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "the caller's earlier write must commit")
			},
		},
		{
			name: "a replacement under a cancelled context fails and leaves the previous set whole",
			user: "rows-user-cancelled",
			assert: func(t *testing.T, _ context.Context, user identity.UserID) {
				old := recoveryHashes(string(user)+"-old", 2)
				s := newRecoveryCodeStore(t, db)
				require.NoError(t, s.ReplaceSet(t.Context(), user, old, recoveryAt)) //nolint:contextcheck // deliberately a cancelled or fresh test context

				err := s.ReplaceSet(storefix.Cancelled(t.Context()), user, recoveryHashes(string(user)+"-new", 2), recoveryAt) //nolint:contextcheck // deliberately a cancelled or fresh test context
				require.ErrorIs(t, err, context.Canceled)

				assertSet(t.Context(), t, s, user, old) //nolint:contextcheck // deliberately a cancelled or fresh test context
			},
		},
		{
			name: "a user reference PostgreSQL text cannot hold is refused by a write and matches nothing",
			user: "rows-user-\x00-nul",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				s := newRecoveryCodeStore(t, db)
				hashes := recoveryHashes("nul", 1)

				err := s.ReplaceSet(ctx, user, hashes, recoveryAt)
				require.Error(t, err)
				storefix.AssertNamesOnly(t, err, "user", string(user))

				matched, err := s.Match(ctx, user, hashes[0])
				require.NoError(t, err)
				assert.False(t, matched)
				ok, err := s.Spend(ctx, user, hashes[0], recoveryAt)
				require.NoError(t, err)
				assert.False(t, ok)
				n, err := s.Remaining(ctx, user)
				require.NoError(t, err)
				assert.Zero(t, n)
				n, err = s.DeleteUser(ctx, user)
				require.NoError(t, err)
				assert.Zero(t, n)
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

			tc.assert(t, ctx, tc.user)
		})
	}
}

// assertSet requires user's set to be exactly want, every code unspent.
func assertSet(ctx context.Context, t *testing.T, s recovery.CodeStore, user identity.UserID, want [][]byte) {
	t.Helper()

	n, err := s.Remaining(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, len(want), n, "the previous set must be whole")
	for _, h := range want {
		matched, err := s.Match(ctx, user, h)
		require.NoError(t, err)
		assert.True(t, matched, "a code of the previous set must still match")
	}
}

// recoveryRow reads record rid's proven and reported columns out of band.
func recoveryRow(ctx context.Context, t *testing.T, db *sql.DB, rid id.ID) (proven, reported string) {
	t.Helper()

	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT proven, reported FROM account_recoveries WHERE id = $1`, rid).Scan(&proven, &reported))

	return proven, reported
}

// recoveryRecord is a pending record of user, completable at recoveryAt.
func recoveryRecord(t *testing.T, user identity.UserID) recovery.Record {
	return recovery.Record{
		ID:        storefix.NewID(t),
		User:      user,
		StartedAt: recoveryAt.Add(-time.Hour),
		NotBefore: recoveryAt,
	}
}

// TestRecoveryRecordStore_Rows checks the stored form of the authenticator
// lists, and the refusals of lists and rows that form cannot carry.
func TestRecoveryRecordStore_Rows(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

	type testCase struct {
		name   string
		record func(t *testing.T) recovery.Record
		assert func(t *testing.T, ctx context.Context, s *sqlstore.RecoveryRecordStore, r recovery.Record, err error)
	}

	cases := []testCase{
		{
			name: "the lists are stored as kind:id lines, in order",
			record: func(t *testing.T) recovery.Record {
				r := recoveryRecord(t, "rows-lists")
				r.Proven = []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}, {Kind: "password", ID: "p"}}
				r.Reported = []recovery.AuthenticatorRef{{Kind: "mfa", ID: "totp"}, {Kind: "passkey", ID: "cred:1"}}
				return r
			},
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.NoError(t, err)
				proven, reported := recoveryRow(ctx, t, db, r.ID)
				assert.Equal(t, "saved:code\npassword:p", proven)
				assert.Equal(t, "mfa:totp\npasskey:cred:1", reported)

				got, err := s.Find(ctx, r.ID)
				require.NoError(t, err)
				assert.Equal(t, r.Proven, got.Proven)
				assert.Equal(t, r.Reported, got.Reported)
			},
		},
		{
			name:   "empty lists are stored as empty text and read back as none",
			record: func(t *testing.T) recovery.Record { return recoveryRecord(t, "rows-empty") },
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.NoError(t, err)
				proven, reported := recoveryRow(ctx, t, db, r.ID)
				assert.Empty(t, proven)
				assert.Empty(t, reported)

				got, err := s.Find(ctx, r.ID)
				require.NoError(t, err)
				assert.Empty(t, got.Proven)
				assert.Empty(t, got.Reported)
			},
		},
		{
			name: "a reference holding a newline is refused and nothing is written",
			record: func(t *testing.T) recovery.Record {
				r := recoveryRecord(t, "rows-newline")
				r.Reported = []recovery.AuthenticatorRef{{Kind: "mfa", ID: "totp\nmfa:email"}}
				return r
			},
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.Error(t, err)
				storefix.AssertNamesOnly(t, err, "reported", "totp")
				_, err = s.Find(ctx, r.ID)
				require.ErrorIs(t, err, recovery.ErrRecordNotFound)
			},
		},
		{
			name: "a reference whose kind holds a colon is refused and nothing is written",
			record: func(t *testing.T) recovery.Record {
				r := recoveryRecord(t, "rows-colon")
				r.Proven = []recovery.AuthenticatorRef{{Kind: "sa:ved", ID: "code"}}
				return r
			},
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.Error(t, err)
				storefix.AssertNamesOnly(t, err, "proven", "sa:ved")
				_, err = s.Find(ctx, r.ID)
				require.ErrorIs(t, err, recovery.ErrRecordNotFound)
			},
		},
		{
			name: "a zero identifier is refused",
			record: func(t *testing.T) recovery.Record {
				r := recoveryRecord(t, "rows-zero")
				r.ID = id.Nil
				return r
			},
			assert: func(t *testing.T, _ context.Context, _ *sqlstore.RecoveryRecordStore, _ recovery.Record, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "sqlstore: insert recovery record")
			},
		},
		{
			name: "a stored list that is not kind:id lines fails the find, never read as another list",
			record: func(t *testing.T) recovery.Record {
				r := recoveryRecord(t, "rows-corrupt")
				r.Proven = []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}}
				return r
			},
			assert: func(t *testing.T, ctx context.Context, s *sqlstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.NoError(t, err)
				_, err = db.ExecContext(ctx, `UPDATE account_recoveries SET proven = 'no-colon' WHERE id = $1`, r.ID)
				require.NoError(t, err)

				got, err := s.Find(ctx, r.ID)
				require.Error(t, err)
				assert.NotErrorIs(t, err, recovery.ErrRecordNotFound)
				assert.ErrorContains(t, err, "sqlstore: find recovery record")
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			s := newRecoveryRecordStore(t, db)
			r := tc.record(t)
			tc.assert(t, ctx, s, r, s.Insert(ctx, r))
		})
	}
}

func TestNewRecoveryCodeStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.RecoveryCodeStore, err error)
	}

	refused := refusedConfig[*sqlstore.RecoveryCodeStore]
	accepted := storefix.AcceptedConfig[*sqlstore.RecoveryCodeStore]
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
			name:   "a nil resolver is refused",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithTxResolver(nil)},
			assert: refused("the transaction resolver is nil"),
		},
		{
			name:   "a clock does not apply, since every time comes from the caller",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewRecoveryCodeStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestNewRecoveryRecordStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.Option
		assert func(t *testing.T, s *sqlstore.RecoveryRecordStore, err error)
	}

	refused := refusedConfig[*sqlstore.RecoveryRecordStore]
	accepted := storefix.AcceptedConfig[*sqlstore.RecoveryRecordStore]
	resolver := func(context.Context) (sqlstore.DBTX, bool) { return nil, false }

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{name: "it honours a resolver", db: db, opts: []sqlstore.Option{sqlstore.WithTxResolver(resolver)}, assert: accepted},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{name: "a nil option is refused", db: db, opts: []sqlstore.Option{nil}, assert: refused("an option is nil")},
		{
			name:   "an id generator does not apply to records, which carry their own",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "a clock does not apply, since every time comes from the caller",
			db:     db,
			opts:   []sqlstore.Option{sqlstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := sqlstore.NewRecoveryRecordStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}
