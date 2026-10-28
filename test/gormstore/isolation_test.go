package gormstore_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/storeerr"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// setRepeatableReadDefault makes REPEATABLE READ the default isolation of
// raw's database, as a consumer's database or role may. It applies to
// connections opened after it, so the caller opens its handles afterwards.
func setRepeatableReadDefault(t *testing.T, raw *sql.DB) {
	t.Helper()

	var stmt string
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT format('ALTER DATABASE %I SET default_transaction_isolation = %L', current_database(), 'repeatable read')`,
	).Scan(&stmt))
	_, err := raw.ExecContext(t.Context(), stmt)
	require.NoError(t, err)
}

// isolationFixture is the isolation suite's fixture over a database holding
// both migration sets, whose default isolation is REPEATABLE READ. The stores
// run on a *gorm.DB opened after the default changed. A gorm consumer's rate
// limiter is sqlstore's, on the *gorm.DB's own *sql.DB.
func isolationFixture(t *testing.T) storetest.IsolationFixture {
	t.Helper()

	d := migratedIdentityDB(t)
	setRepeatableReadDefault(t, d.conn.DB)
	db := openGorm(t, d.conn.DSN)
	sqlDB, err := db.DB()
	require.NoError(t, err)

	return storetest.IsolationFixture{
		Streaks: func(t *testing.T) policy.FailureStreakStore {
			s, err := gormstore.NewAttemptStore(db)
			require.NoError(t, err)
			return s
		},
		RecoveryCodes: func(t *testing.T) recovery.CodeStore {
			s, err := gormstore.NewRecoveryCodeStore(db)
			require.NoError(t, err)
			return s
		},
		Identities: func(t *testing.T) identity.UserProvisioner { return newIdentityStore(t, db) },
		OneTime:    func(t *testing.T) onetime.Store { return newOneTimeStore(t, db) },
		Passkeys: func(t *testing.T) passkey.CredentialStore {
			return newPasskeyCredentialStore(t, db, storefix.TestCipher(t))
		},
		Limiter: func(t *testing.T) ratelimit.Limiter {
			l, err := sqlstore.NewLimiter(sqlDB, "isolation", 400, time.Hour,
				sqlstore.WithLimiterOperationTimeout(5*time.Second))
			require.NoError(t, err)
			return l
		},
		Begin: func(t *testing.T, isolation storetest.Isolation) storetest.CallerTx {
			level := sql.LevelReadCommitted
			if isolation == storetest.RepeatableRead {
				level = sql.LevelRepeatableRead
			}
			tx := db.WithContext(t.Context()).Begin(&sql.TxOptions{Isolation: level})
			require.NoError(t, tx.Error)
			t.Cleanup(func() { tx.Rollback() })

			return storetest.CallerTx{
				Ctx:      gormstore.WithTx(t.Context(), tx),
				Probe:    func() error { return tx.Exec("SELECT 1").Error },
				Commit:   func() error { return tx.Commit().Error },
				Rollback: func() error { return tx.Rollback().Error },
			}
		},
		Raw:              d.conn.DB,
		IsolationRefused: gormstore.ErrIsolationTooStrong,
		PoolSize:         poolSize,
	}
}

func TestIsolation_RepeatableReadDefault(t *testing.T) {
	t.Parallel()

	f := isolationFixture(t)
	t.Run("gorm", func(t *testing.T) { storetest.RunIsolationSuite(t, f) })
}

func TestSessionDelete_SettlesUnderConcurrentCreates(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)
	t.Run("gorm", func(t *testing.T) {
		storetest.RunSessionDeleteSettles(t, func(t *testing.T) session.Store {
			return newSessionStore(t, d.db, c)
		})
	})
}

// TestInsertWithin_RefusesCallerRepeatableReadTx: a bounded one-time insert
// inside a caller's REPEATABLE READ transaction is refused with this backend's
// isolation error, writes nothing, and leaves the transaction usable. Under
// that snapshot the count would predate the subject's lock, so a silent
// insert could over-issue.
func TestInsertWithin_RefusesCallerRepeatableReadTx(t *testing.T) {
	t.Parallel()

	f := isolationFixture(t)
	s := f.OneTime(t)
	tok := storefix.RaceToken(1)

	tx := f.Begin(t, storetest.RepeatableRead)
	stored, err := s.InsertWithin(tx.Ctx, tok, tok.IssuedAt.Add(-time.Hour), 5)

	require.ErrorIs(t, err, gormstore.ErrIsolationTooStrong)
	require.ErrorIs(t, err, storeerr.ErrIsolationTooStrong)
	assert.Contains(t, err.Error(), "repeatable read")
	assert.False(t, stored)
	require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
	require.NoError(t, tx.Commit())
	_, err = s.FindByID(t.Context(), tok.ID)
	require.ErrorIs(t, err, onetime.ErrTokenNotFound, "the refused bounded insert stored its record")
}
