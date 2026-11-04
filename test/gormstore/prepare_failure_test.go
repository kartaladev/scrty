package gormstore_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/store/gormstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// cancelled is ctx, already cancelled: the first statement a handle that prepares its
// statements prepares fails on it.
func cancelled(ctx context.Context) context.Context {
	c, cancel := context.WithCancel(ctx)
	cancel()

	return c
}

// cancelAfter makes db cancel the context its next statement started with prefix ran under,
// once that statement has run. The statement itself succeeds; the one after it is the first
// to find the context dead, which is how a statement that follows a write can fail to prepare.
func cancelAfter(db *gormdb.DB, cancel context.CancelFunc, prefix string) {
	_ = db.Callback().Raw().After("gorm:raw").Register("test:cancel_after", func(tx *gormdb.DB) {
		if strings.HasPrefix(tx.Statement.SQL.String(), prefix) {
			cancel()
		}
	})
}

// abortedTx is a caller's transaction a failed statement has aborted: every statement after
// it, a prepare included, is refused by the server.
func abortedTx(ctx context.Context, t *testing.T, db *gormdb.DB) context.Context {
	t.Helper()

	tx := beginGorm(ctx, t, db)
	require.Error(t, tx.Exec("SELECT 1/0").Error)

	return gormstore.WithTx(ctx, tx)
}

// TestGormStore_StatementThatCannotPrepareIsAnError runs, on a handle that prepares every
// statement, each store call that reads a single row, with the statement made to fail at its
// prepare. gorm's prepared QueryRowContext hands back an empty row then, and scanning it
// panics: the call must instead return an ordinary error, as it does on a plain handle.
func TestGormStore_StatementThatCannotPrepareIsAnError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// call runs the store call under test and returns its error. It may replace what the
		// handle does through setup before the first statement.
		call   func(ctx context.Context, t *testing.T, d database) error
		assert func(t *testing.T, err error)
	}

	failedWith := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
	}
	at := time.Date(2030, 2, 1, 9, 0, 0, 0, time.UTC)
	someUser := identity.UserID("u-1")

	cases := []testCase{
		{
			name: "provider store row scan, table gone",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := d.conn.DB.ExecContext(ctx, "DROP TABLE "+pgschema.PendingRequestTable)
				require.NoError(t, err)
				_, err = newPendingStore(t, d.db).Load(ctx, []byte{1})

				return err
			},
			assert: failedWith,
		},
		{
			name: "provider store row scan, caller's transaction aborted",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := newClientStore(t, d.db).Client(abortedTx(ctx, t, d.db), "c-1")

				return err
			},
			assert: failedWith,
		},
		{
			name: "grants end, the held-set read cannot prepare",
			call: func(ctx context.Context, t *testing.T, d database) error {
				s := newGrantStore(t, d.db)
				require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))
				_, err := d.conn.DB.ExecContext(ctx, "DROP TABLE "+pgschema.GrantTable)
				require.NoError(t, err)
				_, err = s.EndSignIns(ctx, oidcprovider.SignInSelector{User: someUser}, at)

				return err
			},
			assert: failedWith,
		},
		{
			name: "session mark-presented refusal read",
			call: func(ctx context.Context, t *testing.T, d database) error {
				c, cancel := context.WithCancel(ctx)
				defer cancel()
				cancelAfter(d.db, cancel, "UPDATE sessions")

				return newSessionStore(t, d.db, storefix.TestCipher(t)).MarkPresented(c, "absent", at)
			},
			assert: failedWith,
		},
		{
			name: "session successor-presented read",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := newSessionStore(t, d.db, storefix.TestCipher(t)).SuccessorPresented(cancelled(ctx), "x")

				return err
			},
			assert: failedWith,
		},
		{
			name: "lineage successor-presented read",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := lineageSessions(t, d.db, storefix.TestCipher(t)).SuccessorPresented(cancelled(ctx), "x")

				return err
			},
			assert: failedWith,
		},
		{
			name: "login streak read",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := newAttemptStore(t, d.db).FailureStreak(cancelled(ctx), "alice", at)

				return err
			},
			assert: failedWith,
		},
		{
			name: "login streak add on the pool, table gone",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := d.conn.DB.ExecContext(ctx, "DROP TABLE login_failure_streaks")
				require.NoError(t, err)
				_, _, err = newAttemptStore(t, d.db).AddStreakFailure(ctx, "alice", at, at.Add(-time.Hour), 3)

				return err
			},
			assert: failedWith,
		},
		{
			name: "isolation check in a caller's transaction aborted",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, _, err := newAttemptStore(t, d.db).AddStreakFailure(abortedTx(ctx, t, d.db), "alice", at, at.Add(-time.Hour), 3)

				return err
			},
			assert: failedWith,
		},
		{
			name: "enrolment verification charge",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, _, err := newEnrolmentStore(t, d.db, storefix.TestCipher(t)).
					ChargeVerifyAttempt(cancelled(ctx), someUser, at, 3, time.Minute)

				return err
			},
			assert: failedWith,
		},
		{
			name: "passkey handle assignment read-back",
			call: func(ctx context.Context, t *testing.T, d database) error {
				c, cancel := context.WithCancel(ctx)
				defer cancel()
				cancelAfter(d.db, cancel, "INSERT")
				_, err := newPasskeyHandleStore(t, d.db).Assign(c, someUser, make([]byte, 64))

				return err
			},
			assert: failedWith,
		},
		{
			name: "passkey handle lookup",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, _, err := newPasskeyHandleStore(t, d.db).UserFor(cancelled(ctx), make([]byte, 64))

				return err
			},
			assert: failedWith,
		},
		{
			name: "passkey credential returning statement",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, _, err := newPasskeyCredentialStore(t, d.db, storefix.TestCipher(t)).
					ClearReason(cancelled(ctx), someUser, opID(1), passkey.PendingSavedCodes)

				return err
			},
			assert: failedWith,
		},
		{
			name: "recovery code match",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, err := newRecoveryCodeStore(t, d.db).Match(cancelled(ctx), someUser, make([]byte, 32))

				return err
			},
			assert: failedWith,
		},
		{
			name: "recovery record latest completion",
			call: func(ctx context.Context, t *testing.T, d database) error {
				_, _, err := newRecoveryRecordStore(t, d.db).LatestCompletion(cancelled(ctx), someUser)

				return err
			},
			assert: failedWith,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := migratedPrepared(t)
			var err error
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				err = tc.call(t.Context(), t, d)
			}()
			require.Nil(t, panicked, "a failed statement must be an error, never a panic")
			tc.assert(t, err)
		})
	}
}
