package sqlstore_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/sqlstore"
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
// run on a handle opened after the default changed; the helper's own handle,
// opened before, is the out-of-band view.
func isolationFixture(t *testing.T) storetest.IsolationFixture {
	t.Helper()

	conn := migratedIdentityDB(t)
	setRepeatableReadDefault(t, conn.DB)
	db := openReplica(t, conn.DSN)

	return storetest.IsolationFixture{
		Streaks: func(t *testing.T) policy.FailureStreakStore {
			s, err := sqlstore.NewAttemptStore(db)
			require.NoError(t, err)
			return s
		},
		RecoveryCodes: func(t *testing.T) recovery.CodeStore {
			s, err := sqlstore.NewRecoveryCodeStore(db)
			require.NoError(t, err)
			return s
		},
		Identities: func(t *testing.T) identity.UserProvisioner { return newIdentityStore(t, db) },
		OneTime:    func(t *testing.T) onetime.Store { return newOneTimeStore(t, db) },
		Passkeys: func(t *testing.T) passkey.CredentialStore {
			return newPasskeyCredentialStore(t, db, storefix.TestCipher(t))
		},
		Limiter: func(t *testing.T) ratelimit.Limiter {
			l, err := sqlstore.NewLimiter(db, "isolation", 400, time.Hour,
				sqlstore.WithLimiterOperationTimeout(5*time.Second))
			require.NoError(t, err)
			return l
		},
		Begin: func(t *testing.T, isolation storetest.Isolation) storetest.CallerTx {
			level := sql.LevelReadCommitted
			if isolation == storetest.RepeatableRead {
				level = sql.LevelRepeatableRead
			}
			tx, err := db.BeginTx(t.Context(), &sql.TxOptions{Isolation: level})
			require.NoError(t, err)
			t.Cleanup(func() { _ = tx.Rollback() })

			return storetest.CallerTx{
				Ctx: sqlstore.WithTx(t.Context(), tx),
				Probe: func() error {
					_, err := tx.ExecContext(t.Context(), "SELECT 1")
					return err
				},
				Commit:   tx.Commit,
				Rollback: tx.Rollback,
			}
		},
		Raw:              conn.DB,
		IsolationRefused: sqlstore.ErrIsolationTooStrong,
		PoolSize:         poolSize,
	}
}

func TestIsolation_RepeatableReadDefault(t *testing.T) {
	t.Parallel()

	f := isolationFixture(t)
	t.Run("sqlstore", func(t *testing.T) { storetest.RunIsolationSuite(t, f) })
}

func TestSessionDelete_SettlesUnderConcurrentCreates(t *testing.T) {
	t.Parallel()

	conn := migratedDB(t)
	c := storefix.TestCipher(t)
	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunSessionDeleteSettles(t, func(t *testing.T) session.Store {
			return newSessionStore(t, conn.DB, c)
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

	require.ErrorIs(t, err, sqlstore.ErrIsolationTooStrong)
	require.ErrorIs(t, err, storeerr.ErrIsolationTooStrong)
	assert.Contains(t, err.Error(), "repeatable read")
	assert.False(t, stored)
	require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
	require.NoError(t, tx.Commit())
	_, err = s.FindByID(t.Context(), tok.ID)
	require.ErrorIs(t, err, onetime.ErrTokenNotFound, "the refused bounded insert stored its record")
}
