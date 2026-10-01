package gormstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// newRecoveryCodeStore builds the saved-code store over db, failing t on a
// refusal.
func newRecoveryCodeStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.RecoveryCodeStore {
	t.Helper()

	s, err := gormstore.NewRecoveryCodeStore(db, opts...)
	require.NoError(t, err)

	return s
}

// newRecoveryRecordStore builds the recovery-record store over db, failing
// t on a refusal.
func newRecoveryRecordStore(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.RecoveryRecordStore {
	t.Helper()

	s, err := gormstore.NewRecoveryRecordStore(db, opts...)
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

	db := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunRecoveryCodeStoreSuite(t, func(t *testing.T, _ clock.Clock) recovery.CodeStore {
			return newRecoveryCodeStore(t, emptied(t, db, "recovery_codes"))
		})
	})
}

func TestRecoveryRecordStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t)

	t.Run("gorm", func(t *testing.T) {
		storetest.RunRecoveryRecordStoreSuite(t, func(t *testing.T, _ clock.Clock) recovery.RecordStore {
			return newRecoveryRecordStore(t, emptied(t, db, "account_recoveries"))
		})
	})
}

// The races, the ambient-transaction suite and the replacement's transaction
// cases write records of their own users, so they share one database.
func TestRecoveryCodeStore_Durable(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.RecoveryCodeStore {
		return newRecoveryCodeStore(t, db, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.RecoverySpendRace[*gormstore.RecoveryCodeStore]())
		storetest.RunAmbientTx(t, h, storefix.RecoveryCodeAmbient[*gormstore.RecoveryCodeStore]())
		storetest.RunRecoveryCodeTx(t, h)
	})
}

func TestRecoveryRecordStore_Durable(t *testing.T) {
	t.Parallel()

	h := durableHarness(migratedDB(t), func(t *testing.T, db *gormdb.DB, opts ...gormstore.Option) *gormstore.RecoveryRecordStore {
		return newRecoveryRecordStore(t, db, opts...)
	})

	t.Run("gorm", func(t *testing.T) {
		storetest.RunConsumeRace(t, h, storefix.RecoveryRecordRace[*gormstore.RecoveryRecordStore]())
		storetest.RunAmbientTx(t, h, storefix.RecoveryRecordAmbient[*gormstore.RecoveryRecordStore]())
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

// TestRecoveryCodeStore_Rows checks what only the stored rows show: the first
// spending time kept, the configured row identifiers, and a replacement that
// fails part way leaving the previous set whole, inside and outside a caller's
// transaction.
func TestRecoveryCodeStore_Rows(t *testing.T) {
	t.Parallel()

	db := migratedDB(t)

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
				s := newRecoveryCodeStore(t, db.db)
				hashes := recoveryHashes(string(user), 2)
				require.NoError(t, s.ReplaceSet(ctx, user, hashes, recoveryAt))

				first := recoveryAt.Add(time.Minute + 123456789*time.Nanosecond)
				ok, err := s.Spend(ctx, user, hashes[0], first)
				require.NoError(t, err)
				require.True(t, ok)

				ok, err = s.Spend(ctx, user, hashes[0], first.Add(time.Hour))
				require.NoError(t, err)
				assert.False(t, ok)

				at := spentAt(ctx, t, db.conn.DB, user, hashes[0])
				require.True(t, at.Valid)
				want := first.Truncate(time.Microsecond)
				assert.True(t, want.Equal(at.Time), "spent_at is %v, want the first spend at %v", at.Time, want)
				assert.False(t, spentAt(ctx, t, db.conn.DB, user, hashes[1]).Valid, "the other code must stay unspent")
			},
		},
		{
			name: "rows carry the configured identifiers and the replacement time",
			user: "rows-user-ids",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				want := storefix.NewID(t)
				s := newRecoveryCodeStore(t, db.db, gormstore.WithIDGenerator(fixedIDs{want}))
				require.NoError(t, s.ReplaceSet(ctx, user, recoveryHashes(string(user), 1), recoveryAt))

				var (
					got     id.ID
					created time.Time
				)
				require.NoError(t, db.conn.DB.QueryRowContext(ctx,
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
				require.NoError(t, newRecoveryCodeStore(t, db.db).ReplaceSet(ctx, user, old, recoveryAt))

				failing := newRecoveryCodeStore(t, db.db, gormstore.WithIDGenerator(fixedIDs{storefix.NewID(t)}))
				require.Error(t, failing.ReplaceSet(ctx, user, recoveryHashes(string(user)+"-new", 2), recoveryAt))

				assertSet(ctx, t, newRecoveryCodeStore(t, db.db), user, old)
			},
		},
		{
			name: "inside a caller's transaction, a failed replacement undoes only its own statements",
			user: "rows-user-fails-in-tx",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				old := recoveryHashes(string(user)+"-old", 3)
				s := newRecoveryCodeStore(t, db.db)
				require.NoError(t, s.ReplaceSet(ctx, user, old, recoveryAt))

				tx := beginGorm(ctx, t, db.db)
				txCtx := gormstore.WithTx(ctx, tx)

				other := user + "-other"
				require.NoError(t, s.ReplaceSet(txCtx, other, recoveryHashes(string(other), 2), recoveryAt),
					"the caller's earlier write")

				failing := newRecoveryCodeStore(t, db.db, gormstore.WithIDGenerator(fixedIDs{storefix.NewID(t)}))
				require.Error(t, failing.ReplaceSet(txCtx, user, recoveryHashes(string(user)+"-new", 2), recoveryAt))

				n, err := s.Remaining(txCtx, other)
				require.NoError(t, err, "the caller's transaction must stay usable after the failed replacement")
				assert.Equal(t, 2, n)
				require.NoError(t, tx.Commit().Error)

				reader := newRecoveryCodeStore(t, db.db)
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
				s := newRecoveryCodeStore(t, db.db)
				require.NoError(t, s.ReplaceSet(t.Context(), user, old, recoveryAt))

				err := s.ReplaceSet(storefix.Cancelled(t.Context()), user, recoveryHashes(string(user)+"-new", 2), recoveryAt)
				require.ErrorIs(t, err, context.Canceled)

				assertSet(t.Context(), t, s, user, old)
			},
		},
		{
			name: "a resolver reporting a nil transaction fails the replacement before any statement",
			user: "rows-user-nil-tx",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				s := newRecoveryCodeStore(t, db.db,
					gormstore.WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return nil, true }))

				err := s.ReplaceSet(ctx, user, recoveryHashes(string(user), 1), recoveryAt)
				require.ErrorIs(t, err, gormstore.ErrNilTransaction)
				assert.ErrorContains(t, err, "gorm: replace recovery codes")
			},
		},
		{
			name: "a user reference PostgreSQL text cannot hold is refused by a write and matches nothing",
			user: "rows-user-\x00-nul",
			assert: func(t *testing.T, ctx context.Context, user identity.UserID) {
				s := newRecoveryCodeStore(t, db.db)
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

	db := migratedDB(t)

	type testCase struct {
		name   string
		record func(t *testing.T) recovery.Record
		assert func(t *testing.T, ctx context.Context, s *gormstore.RecoveryRecordStore, r recovery.Record, err error)
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
			assert: func(t *testing.T, ctx context.Context, s *gormstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.NoError(t, err)
				proven, reported := recoveryRow(ctx, t, db.conn.DB, r.ID)
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
			assert: func(t *testing.T, ctx context.Context, s *gormstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.NoError(t, err)
				proven, reported := recoveryRow(ctx, t, db.conn.DB, r.ID)
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
			assert: func(t *testing.T, ctx context.Context, s *gormstore.RecoveryRecordStore, r recovery.Record, err error) {
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
			assert: func(t *testing.T, ctx context.Context, s *gormstore.RecoveryRecordStore, r recovery.Record, err error) {
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
			assert: func(t *testing.T, _ context.Context, _ *gormstore.RecoveryRecordStore, _ recovery.Record, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "gorm: insert recovery record")
			},
		},
		{
			name: "a stored list that is not kind:id lines fails the find, never read as another list",
			record: func(t *testing.T) recovery.Record {
				r := recoveryRecord(t, "rows-corrupt")
				r.Proven = []recovery.AuthenticatorRef{{Kind: "saved", ID: "code"}}
				return r
			},
			assert: func(t *testing.T, ctx context.Context, s *gormstore.RecoveryRecordStore, r recovery.Record, err error) {
				require.NoError(t, err)
				_, err = db.conn.DB.ExecContext(ctx, `UPDATE account_recoveries SET proven = 'no-colon' WHERE id = $1`, r.ID)
				require.NoError(t, err)

				got, err := s.Find(ctx, r.ID)
				require.Error(t, err)
				assert.NotErrorIs(t, err, recovery.ErrRecordNotFound)
				assert.ErrorContains(t, err, "gorm: find recovery record")
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			s := newRecoveryRecordStore(t, db.db)
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
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.RecoveryCodeStore, err error)
	}

	refused := refusedConfig[*gormstore.RecoveryCodeStore]
	accepted := storefix.AcceptedConfig[*gormstore.RecoveryCodeStore]
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
			name:   "a nil resolver is refused",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithTxResolver(nil)},
			assert: refused("the transaction resolver is nil"),
		},
		{
			name:   "a clock does not apply, since every time comes from the caller",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewRecoveryCodeStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func TestNewRecoveryRecordStore(t *testing.T) {
	t.Parallel()

	db := unreachableDB(t)

	type testCase struct {
		name   string
		db     *gormdb.DB
		opts   []gormstore.Option
		assert func(t *testing.T, s *gormstore.RecoveryRecordStore, err error)
	}

	refused := refusedConfig[*gormstore.RecoveryRecordStore]
	accepted := storefix.AcceptedConfig[*gormstore.RecoveryRecordStore]
	resolver := func(context.Context) (*gormdb.DB, bool) { return nil, false }

	cases := []testCase{
		{name: "a handle is all it needs", db: db, assert: accepted},
		{name: "it honours a resolver", db: db, opts: []gormstore.Option{gormstore.WithTxResolver(resolver)}, assert: accepted},
		{name: "a missing handle is refused", assert: refused("the database handle is nil")},
		{name: "a nil option is refused", db: db, opts: []gormstore.Option{nil}, assert: refused("an option is nil")},
		{
			name:   "an id generator does not apply to records, which carry their own",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithIDGenerator(id.NewV7Generator())},
			assert: refused("WithIDGenerator does not apply to this store"),
		},
		{
			name:   "a clock does not apply, since every time comes from the caller",
			db:     db,
			opts:   []gormstore.Option{gormstore.WithClock(clock.System())},
			assert: refused("WithClock does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := gormstore.NewRecoveryRecordStore(tc.db, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

// TestRecoveryStores_Statements pins the statements the recovery stores'
// single-statement operations send, a refused one included: exactly one
// conditional write or read, no SELECT before a write and no BEGIN of gorm's
// default transaction. A replacement is one BEGIN on the pool, its own
// statements then running on that transaction.
func TestRecoveryStores_Statements(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	pool := &recordingPool{db: d.conn.DB}
	recorded, err := gormdb.Open(postgres.New(postgres.Config{Conn: pool}), &gormdb.Config{DisableAutomaticPing: true})
	require.NoError(t, err)

	seedCodes, codes := newRecoveryCodeStore(t, d.db), newRecoveryCodeStore(t, recorded)
	seedRecords, records := newRecoveryRecordStore(t, d.db), newRecoveryRecordStore(t, recorded)
	const user identity.UserID = "stmt-recovery-user"
	hashes := recoveryHashes(string(user), 2)
	require.NoError(t, seedCodes.ReplaceSet(t.Context(), user, hashes, recoveryAt))
	pending := recoveryRecord(t, user)
	require.NoError(t, seedRecords.Insert(t.Context(), pending))

	const (
		spend    = `UPDATE "recovery_codes" SET "spent_at"=$1 WHERE user_id = $2 AND code_hash = $3 AND spent_at IS NULL`
		complete = `UPDATE "account_recoveries" SET "completed_at"=$1 WHERE id = $2 AND completed_at IS NULL AND cancelled_at IS NULL AND not_before <= $3`
	)

	type testCase struct {
		name   string
		run    func(ctx context.Context) error
		expect []string
	}

	errRefused := errors.New("refused")
	flag := func(ok bool, err error) error {
		if err == nil && !ok {
			return errRefused
		}
		return err
	}

	cases := []testCase{
		{
			name:   "spend",
			run:    func(ctx context.Context) error { return flag(codes.Spend(ctx, user, hashes[0], recoveryAt)) },
			expect: []string{spend},
		},
		{
			name: "spend of a spent code",
			run: func(ctx context.Context) error {
				if err := flag(codes.Spend(ctx, user, hashes[0], recoveryAt)); !errors.Is(err, errRefused) {
					return fmt.Errorf("want the refusal, got %v", err)
				}
				return nil
			},
			expect: []string{spend},
		},
		{
			name:   "replacement",
			run:    func(ctx context.Context) error { return codes.ReplaceSet(ctx, user+"-other", hashes, recoveryAt) },
			expect: []string{"BEGIN"},
		},
		{
			name: "completion before the completable instant",
			run: func(ctx context.Context) error {
				if err := flag(records.Complete(ctx, pending.ID, pending.NotBefore.Add(-time.Second))); !errors.Is(err, errRefused) {
					return fmt.Errorf("want the refusal, got %v", err)
				}
				return nil
			},
			expect: []string{complete},
		},
		{
			name:   "completion",
			run:    func(ctx context.Context) error { return flag(records.Complete(ctx, pending.ID, pending.NotBefore)) },
			expect: []string{complete},
		},
	}

	// The cases share one recording pool and one record, so they run one
	// after another, in order.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool.take()
			require.NoError(t, tc.run(t.Context()))
			assert.Equal(t, tc.expect, normalized(pool.take()))
		})
	}
}
