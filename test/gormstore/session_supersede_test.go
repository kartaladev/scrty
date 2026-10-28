package gormstore_test

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// supersedeAt is the instant the supersession cases run at.
var supersedeAt = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// supersessionOf is the supersession of old by a new session named
// successorID in old's family, observing observed, at supersedeAt.
func supersessionOf(old *session.Session, successorID string, observed []byte) session.Supersession {
	successor := storefix.DurableSession(successorID, supersedeAt)
	successor.UserID = old.UserID
	successor.FamilyID = old.FamilyID
	successor.FamilyCreatedAt = old.FamilyCreatedAt

	return session.Supersession{
		Old:               old.ID,
		ObservedSuccessor: observed,
		AcceptUntil:       supersedeAt.Add(30 * time.Second),
		RetainUntil:       supersedeAt.Add(time.Hour),
		Successor:         successor,
		Now:               supersedeAt,
	}
}

// successorIsNull reports whether the stored successor_digest of session sid
// is SQL NULL, and whether the row exists.
func successorIsNull(ctx context.Context, t *testing.T, db *sql.DB, sid string) (isNull, found bool) {
	t.Helper()

	err := db.QueryRowContext(ctx,
		`SELECT successor_digest IS NULL FROM sessions WHERE id_digest = $1`, storefix.Digest(sid)).Scan(&isNull)
	if err == sql.ErrNoRows {
		return false, false
	}
	require.NoError(t, err)

	return isNull, true
}

func TestSessionStore_SupersedeObservingNoSuccessor(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	db := d.conn.DB
	store := newSessionStore(t, d.db, storefix.TestCipher(t))

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, sid string)
	}

	cases := []testCase{
		{
			name: "a live record's successor digest is NULL, and a supersession observing none succeeds",
			assert: func(t *testing.T, ctx context.Context, sid string) {
				old := storefix.DurableSession(sid, supersedeAt)
				require.NoError(t, store.Create(ctx, old))
				isNull, _ := successorIsNull(ctx, t, db, sid)
				assert.True(t, isNull, "a live record's successor_digest is not SQL NULL")

				require.NoError(t, store.Supersede(ctx, supersessionOf(old, sid+"-next", nil)))

				isNull, _ = successorIsNull(ctx, t, db, sid)
				assert.False(t, isNull, "the superseded record records its successor")
				isNull, found := successorIsNull(ctx, t, db, sid+"-next")
				require.True(t, found)
				assert.True(t, isNull, "the successor, live, has a NULL successor_digest")
			},
		},
		{
			name: "an empty observation reads as none",
			assert: func(t *testing.T, ctx context.Context, sid string) {
				old := storefix.DurableSession(sid, supersedeAt)
				require.NoError(t, store.Create(ctx, old))

				require.NoError(t, store.Supersede(ctx, supersessionOf(old, sid+"-next", []byte{})))
			},
		},
		{
			name: "a supersession observing none is refused on a record already superseded",
			assert: func(t *testing.T, ctx context.Context, sid string) {
				old := storefix.DurableSession(sid, supersedeAt)
				require.NoError(t, store.Create(ctx, old))
				require.NoError(t, store.Supersede(ctx, supersessionOf(old, sid+"-next", nil)))

				for _, observed := range [][]byte{nil, {}} {
					err := store.Supersede(ctx, supersessionOf(old, sid+"-late", observed))
					require.ErrorIs(t, err, session.ErrRenewalConflict)
				}
				_, found := successorIsNull(ctx, t, db, sid+"-late")
				assert.False(t, found, "a refused supersession wrote its successor")
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, t.Context(), "sess-nosucc-"+strconv.Itoa(i))
		})
	}
}

// slowSuccessorInserts installs, until the test ends, a trigger that sleeps
// for a minute before every insert into sessions for user, and for no other
// user. The trigger and function names are constants, never built from input.
func slowSuccessorInserts(ctx context.Context, t *testing.T, db *sql.DB, user string) {
	t.Helper()

	const name = "slow_session_insert"
	_, err := db.ExecContext(ctx, `CREATE FUNCTION `+name+`() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.user_id = '`+user+`' THEN
    PERFORM pg_sleep(600);
  END IF;
  RETURN NEW;
END $$`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `CREATE TRIGGER `+name+` BEFORE INSERT ON sessions
FOR EACH ROW EXECUTE FUNCTION `+name+`()`)
	require.NoError(t, err)

	t.Cleanup(func() {
		cctx := context.WithoutCancel(ctx)
		_, _ = db.ExecContext(cctx, `DROP TRIGGER IF EXISTS `+name+` ON sessions`)
		_, _ = db.ExecContext(cctx, `DROP FUNCTION IF EXISTS `+name+`()`)
	})
}

func TestSessionStore_SupersedeCancelledMidTransaction(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	db := d.conn.DB
	store := newSessionStore(t, d.db, storefix.TestCipher(t))

	ctx := t.Context()
	const sid = "sess-cancel-a"
	old := storefix.DurableSession(sid, supersedeAt)
	require.NoError(t, store.Create(ctx, old))
	slowSuccessorInserts(ctx, t, db, string(old.UserID))

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.Supersede(cancelCtx, supersessionOf(old, sid+"-next", nil)) }()

	// The first statement has run, and the successor's insert sleeps in the
	// trigger: the transaction is open, holding the old row's lock.
	require.Eventually(t, func() bool {
		var n int
		err := db.QueryRowContext(ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'PgSleep' AND datname = current_database()`).Scan(&n)
		return err == nil && n == 1
	}, 2*time.Minute, 20*time.Millisecond, "the supersession never reached the successor's insert")
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(30 * time.Second):
		t.Fatal("a cancelled supersession did not return")
	}

	// Nothing was written: the old record is as it was, with no successor.
	var live bool
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT superseded_at IS NULL AND successor_digest IS NULL AND accept_until IS NULL FROM sessions WHERE id_digest = $1`,
		storefix.Digest(sid)).Scan(&live))
	assert.True(t, live, "the old record was changed")
	_, found := successorIsNull(ctx, t, db, sid+"-next")
	assert.False(t, found, "the successor was written")

	// The transaction ended: none is left open holding the old row's lock.
	require.Eventually(t, func() bool {
		var n int
		err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND state LIKE 'idle in transaction%'`).Scan(&n)
		return err == nil && n == 0
	}, 10*time.Second, 20*time.Millisecond, "a transaction was left open")

	// The same pool still works: a read, and a supersession once the trigger is gone.
	opCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	_, err := store.Load(opCtx, sid)
	require.NoError(t, err)
	_, err = db.ExecContext(opCtx, `DROP TRIGGER slow_session_insert ON sessions`)
	require.NoError(t, err)
	require.NoError(t, store.Supersede(opCtx, supersessionOf(old, sid+"-next", nil)))
}
