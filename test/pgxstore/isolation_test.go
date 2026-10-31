package pgxstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
	"github.com/kartaladev/scrty/token/onetime"
)

// setRepeatableReadDefault makes REPEATABLE READ the default isolation of
// raw's database, as a consumer's database or role may. It applies to
// connections opened after it, so the caller opens its handles afterwards.
func setRepeatableReadDefault(t *testing.T, raw *sql.DB) {
	t.Helper()

	var name string
	require.NoError(t, raw.QueryRowContext(t.Context(), "SELECT current_database()").Scan(&name))
	_, err := raw.ExecContext(t.Context(),
		"ALTER DATABASE "+pgx.Identifier{name}.Sanitize()+" SET default_transaction_isolation = 'repeatable read'")
	require.NoError(t, err)
}

// callerTxKey is the context key the fixture's Begin also attaches the
// caller's transaction under, for the broken stores of the isolation
// self-check, which cannot read pgx's own attachment.
type callerTxKey struct{}

// isolationFixture is the isolation suite's fixture over a database holding
// both migration sets, whose default isolation is REPEATABLE READ, and the
// pool its stores run on.
func isolationFixture(t *testing.T) (storetest.IsolationFixture, *pgxpool.Pool) {
	t.Helper()

	db := migratedIdentity(t)
	setRepeatableReadDefault(t, db.DB)
	pool := openPool(t, db.DSN)

	return storetest.IsolationFixture{
		Streaks: func(t *testing.T) lockout.FailureStreakStore {
			s, err := pgxstore.NewAttemptStore(pool)
			require.NoError(t, err)
			return s
		},
		RecoveryCodes: func(t *testing.T) recovery.CodeStore {
			s, err := pgxstore.NewRecoveryCodeStore(pool)
			require.NoError(t, err)
			return s
		},
		Identities: func(t *testing.T) identity.UserProvisioner { return newIdentityStore(t, pool) },
		OneTime:    func(t *testing.T) onetime.Store { return newOneTimeStore(t, pool) },
		Passkeys: func(t *testing.T) passkey.CredentialStore {
			return newPasskeyCredentialStore(t, pool, storefix.TestCipher(t))
		},
		Limiter: func(t *testing.T) ratelimit.Limiter {
			l, err := pgxstore.NewLimiter(pool, "isolation", 400, time.Hour,
				pgxstore.WithLimiterOperationTimeout(5*time.Second))
			require.NoError(t, err)
			return l
		},
		Begin: func(t *testing.T, isolation storetest.Isolation) storetest.CallerTx {
			level := pgx.ReadCommitted
			if isolation == storetest.RepeatableRead {
				level = pgx.RepeatableRead
			}
			tx, err := pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: level})
			require.NoError(t, err)
			end := context.WithoutCancel(t.Context())
			t.Cleanup(func() { _ = tx.Rollback(end) })

			return storetest.CallerTx{
				Ctx: context.WithValue(pgxstore.WithTx(t.Context(), tx), callerTxKey{}, tx),
				Probe: func() error {
					_, err := tx.Exec(t.Context(), "SELECT 1")
					return err
				},
				Commit:   func() error { return tx.Commit(end) },
				Rollback: func() error { return tx.Rollback(end) },
			}
		},
		Raw:              db.DB,
		IsolationRefused: pgxstore.ErrIsolationTooStrong,
		PoolSize:         poolSize,
	}, pool
}

func TestIsolation_RepeatableReadDefault(t *testing.T) {
	t.Parallel()

	f, _ := isolationFixture(t)
	t.Run("pgx", func(t *testing.T) { storetest.RunIsolationSuite(t, f) })
}

func TestSessionDelete_SettlesUnderConcurrentCreates(t *testing.T) {
	t.Parallel()

	db := migrated(t)
	c := storefix.TestCipher(t)
	t.Run("pgx", func(t *testing.T) {
		storetest.RunSessionDeleteSettles(t, func(t *testing.T) session.Store {
			return newSessionStore(t, db.Pool, c)
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

	f, _ := isolationFixture(t)
	s := f.OneTime(t)
	tok := storefix.RaceToken(1)

	tx := f.Begin(t, storetest.RepeatableRead)
	stored, err := s.InsertWithin(tx.Ctx, tok, tok.IssuedAt.Add(-time.Hour), 5)

	require.ErrorIs(t, err, pgxstore.ErrIsolationTooStrong)
	require.ErrorIs(t, err, store.ErrIsolationTooStrong)
	assert.Contains(t, err.Error(), "repeatable read")
	assert.False(t, stored)
	require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
	require.NoError(t, tx.Commit())
	_, err = s.FindByID(t.Context(), tok.ID)
	require.ErrorIs(t, err, onetime.ErrTokenNotFound, "the refused bounded insert stored its record")
}
