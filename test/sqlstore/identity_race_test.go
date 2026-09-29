package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/sqlstore"
)

// These tests force the two interleavings the identity store's writes must
// survive, instead of hoping a burst of goroutines happens to hit them: one
// transaction is held open after its write, the other is started and
// confirmed, through pg_stat_activity, to be waiting on a lock the first
// holds, and only then is the first committed.
//
// Each scenario returns what it saw go wrong, nil when nothing did, rather
// than failing the test itself. That lets the same scenario run against the
// real store, where it must report nothing, and against a deliberately broken
// variant built here from outside the store, where it must report the defect
// the scenario exists to catch. The variant rows prove the scenarios bite.

// lockWaitDeadline bounds how long a scenario waits for the second
// transaction to show up as blocked, and for it to finish once released.
const lockWaitDeadline = 20 * time.Second

// provisioner is what a scenario drives: a user provisioner that can also
// load a user, so a variant with a preceding read can be expressed.
type provisioner interface {
	identity.UserProvisioner
	LoadByUsername(ctx context.Context, username string) (*identity.Details, error)
}

// binding returns the provisioner, and the context to call it with, that runs
// its writes inside tx, a transaction of db the scenario holds open.
type binding func(t *testing.T, db *sql.DB, tx *sql.Tx) (provisioner, context.Context)

// realStore binds the unmodified store to tx through sqlstore.WithTx.
func realStore(t *testing.T, db *sql.DB, tx *sql.Tx) (provisioner, context.Context) {
	return newIdentityStore(t, db), sqlstore.WithTx(t.Context(), tx)
}

// precedingReadStore binds the check-then-insert variant to tx: see
// precedingRead.
func precedingReadStore(t *testing.T, db *sql.DB, tx *sql.Tx) (provisioner, context.Context) {
	return precedingRead{newIdentityStore(t, db)}, sqlstore.WithTx(t.Context(), tx)
}

// unlockedStore binds the store to tx through a consumer resolver whose handle
// sends the user lock without FOR UPDATE: see unlockedTx.
func unlockedStore(t *testing.T, db *sql.DB, tx *sql.Tx) (provisioner, context.Context) {
	require.True(t, strings.HasSuffix(pgschema.LockUserByUsername, " FOR UPDATE"),
		"the lock statement no longer ends in FOR UPDATE; the unlocked variant would equal the store")

	h := unlockedTx{Tx: tx}
	s := newIdentityStore(t, db, sqlstore.WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) {
		return h, true
	}))

	return s, t.Context()
}

// precedingRead is the store behind a check-then-insert wrapper: it reads the
// username first, refuses when the read finds it, and otherwise provisions,
// trusting its read so far that a collision on the insert is taken for this
// caller's own earlier write and answered with the stored record. The read
// sees nothing another transaction has not yet committed, so it decides
// nothing under a race.
type precedingRead struct {
	*sqlstore.IdentityStore
}

func (p precedingRead) Provision(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	_, err := p.LoadByUsername(ctx, username)
	if err == nil {
		return nil, identity.ErrUserExists
	}
	if !errors.Is(err, identity.ErrUserNotFound) {
		return nil, err
	}

	d, err := p.IdentityStore.Provision(ctx, username, opts...)
	if errors.Is(err, identity.ErrUserExists) {
		return p.LoadByUsername(ctx, username)
	}

	return d, err
}

// unlockedTx is a caller's transaction that sends the store's user lock as a
// plain read, so an update reads and plans against a row another transaction
// is still changing.
type unlockedTx struct {
	*sql.Tx
}

func (u unlockedTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if query == pgschema.LockUserByUsername {
		query = strings.TrimSuffix(query, " FOR UPDATE")
	}

	return u.Tx.QueryRowContext(ctx, query, args...)
}

// outcome is what a provisioner call returned.
type outcome struct {
	d   *identity.Details
	err error
}

// backendPID is the PostgreSQL backend serving tx.
func backendPID(t *testing.T, tx *sql.Tx) int {
	t.Helper()

	var pid int
	require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid))

	return pid
}

// awaitBlockedBy polls pg_stat_activity until some backend is waiting on a
// lock that holder holds, and reports an error when none is within
// lockWaitDeadline, or when done delivers first: the other call finished
// without ever waiting. A delivered outcome is put back for the caller.
func awaitBlockedBy(ctx context.Context, db *sql.DB, holder int, done chan outcome) error {
	const query = `SELECT count(*) FROM pg_stat_activity
WHERE wait_event_type = 'Lock' AND $1 = ANY(pg_blocking_pids(pid))`

	deadline := time.NewTimer(lockWaitDeadline)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()

	for {
		var n int
		if err := db.QueryRowContext(ctx, query, holder).Scan(&n); err != nil {
			return fmt.Errorf("reading pg_stat_activity: %w", err)
		}
		if n > 0 {
			return nil
		}

		select {
		case o := <-done:
			done <- o
			return errors.New("the second call finished without waiting on the first transaction's lock")
		case <-deadline.C:
			return errors.New("the second call never waited on the first transaction's lock")
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// begin opens a transaction on db that is rolled back at cleanup unless it
// was committed first.
func begin(t *testing.T, db *sql.DB) *sql.Tx {
	t.Helper()

	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })

	return tx
}

// holdThenRelease runs first inside a transaction A it holds open, starts
// second inside a transaction B of its own, waits until B is confirmed
// blocked on a lock A holds, commits A, and returns B's outcome once B's call
// returns; B is then committed when its call succeeded and rolled back
// otherwise. A failure to confirm the wait is returned as a violation beside
// the outcome.
func holdThenRelease(
	t *testing.T, db *sql.DB, bind binding,
	first, second func(p provisioner, ctx context.Context) (*identity.Details, error),
) (outcome, error) {
	t.Helper()

	txA := begin(t, db)
	pA, ctxA := bind(t, db, txA)
	_, err := first(pA, ctxA)
	require.NoError(t, err, "the held transaction's own call")
	holder := backendPID(t, txA)

	txB := begin(t, db)
	pB, ctxB := bind(t, db, txB)
	done := make(chan outcome, 1)
	go func() {
		d, err := second(pB, ctxB)
		done <- outcome{d, err}
	}()

	waitErr := awaitBlockedBy(t.Context(), db, holder, done)
	require.NoError(t, txA.Commit())

	var got outcome
	select {
	case got = <-done:
	case <-time.After(lockWaitDeadline):
		t.Fatal("the second call did not return after the first transaction committed")
	}

	if got.err == nil {
		require.NoError(t, txB.Commit())
	} else {
		require.NoError(t, txB.Rollback())
	}

	return got, waitErr
}

// insertAtomicity provisions username in a held transaction A, then again in
// B, which must block on the unique index until A commits and then report
// that the user exists. It returns every way the outcome departs from that.
func insertAtomicity(t *testing.T, db *sql.DB, bind binding, username string) error {
	t.Helper()

	got, waitErr := holdThenRelease(t, db, bind,
		func(p provisioner, ctx context.Context) (*identity.Details, error) {
			return p.Provision(ctx, username, identity.WithUserName("first"), identity.WithUserRoles("admin"))
		},
		func(p provisioner, ctx context.Context) (*identity.Details, error) {
			return p.Provision(ctx, username, identity.WithUserName("second"), identity.WithUserRoles("root"))
		})

	violations := []error{waitErr}
	if !errors.Is(got.err, identity.ErrUserExists) {
		// The error is printed for the report, never matched, and a nil one
		// must print as <nil>, so it goes in as text rather than wrapped.
		violations = append(violations, fmt.Errorf(
			"the blocked provision returned a record: %t, error %s; want the user-already-exists error",
			got.d != nil, fmt.Sprint(got.err)))
	}
	if n := userRowCount(t.Context(), t, db, username); n != 1 {
		violations = append(violations, fmt.Errorf("%d users stored under the name, want 1", n))
	}

	stored, err := newIdentityStore(t, db).LoadByUsername(t.Context(), username)
	require.NoError(t, err)
	if stored.Name != "first" || len(stored.Roles) != 1 || stored.Roles[0].Name != "admin" {
		violations = append(violations, errors.New("the stored user is not the one the first provision created"))
	}

	return errors.Join(violations...)
}

// revokeRacesReassert seeds username holding admin as a super role, then
// updates it to viewer in a held transaction A, and to admin in B, which must
// block on the user's row lock until A commits and then apply on top of A's
// result: the user ends holding exactly admin, and since A had revoked it, as
// a new grant with no super role. It returns every way the outcome departs
// from that.
func revokeRacesReassert(t *testing.T, db *sql.DB, bind binding, username string) error {
	t.Helper()

	seeded, err := newIdentityStore(t, db).Provision(t.Context(), username, identity.WithUserRoles("admin"))
	require.NoError(t, err)
	require.Len(t, seeded.Roles, 1)
	revoked := seeded.Roles[0].ID
	// A super role is written by the consumer's tooling, never by the store.
	_, err = db.ExecContext(t.Context(), `UPDATE assigned_roles SET super_role = true WHERE id = $1`, revoked)
	require.NoError(t, err)

	got, waitErr := holdThenRelease(t, db, bind,
		func(p provisioner, ctx context.Context) (*identity.Details, error) {
			return p.Update(ctx, username, identity.WithUserRoles("viewer"))
		},
		func(p provisioner, ctx context.Context) (*identity.Details, error) {
			return p.Update(ctx, username, identity.WithUserRoles("admin"))
		})

	violations := []error{waitErr}
	if got.err != nil {
		violations = append(violations, fmt.Errorf("the blocked update failed: %w", got.err))
	}

	final, err := newIdentityStore(t, db).LoadByUsername(t.Context(), username)
	require.NoError(t, err)

	names := make([]string, 0, len(final.Roles))
	for _, g := range final.Roles {
		names = append(names, g.Name)
	}
	if len(final.Roles) != 1 || final.Roles[0].Name != "admin" {
		violations = append(violations, fmt.Errorf("final grants %v, want exactly [admin]", names))
	} else {
		g := final.Roles[0]
		if g.ID == revoked {
			violations = append(violations, errors.New("the revoked admin grant came back with its old identifier"))
		}
		if g.SuperRole {
			violations = append(violations, errors.New("the revoked admin grant's super role came back"))
		}
	}

	return errors.Join(violations...)
}

// otherUserDeadline bounds how long an update of a user nobody holds may
// take while another user's update is held open. It shares lockWaitDeadline's
// bound so a loaded host cannot flake this on the side that must not block.
const otherUserDeadline = lockWaitDeadline

// heldUpdate updates holder's roles in a transaction A it holds open, then
// updates target's roles in a transaction B of its own while A is still open.
// It reports whether B was ever seen, through pg_stat_activity, waiting on a
// lock A holds, and whether B's call returned within otherUserDeadline; then
// commits A, and returns B's outcome once it arrives, B committed when its
// call succeeded and rolled back otherwise.
func heldUpdate(t *testing.T, db *sql.DB, holder, target string) (waited, finished bool, got outcome) {
	t.Helper()

	s := newIdentityStore(t, db)
	txA := begin(t, db)
	_, err := s.Update(sqlstore.WithTx(t.Context(), txA), holder, identity.WithUserRoles("held"))
	require.NoError(t, err, "the held transaction's own update")
	pidA := backendPID(t, txA)

	txB := begin(t, db)
	done := make(chan outcome, 1)
	go func() {
		d, err := s.Update(sqlstore.WithTx(t.Context(), txB), target, identity.WithUserRoles("other"))
		done <- outcome{d, err}
	}()

	const blockedByA = `SELECT count(*) FROM pg_stat_activity
WHERE wait_event_type = 'Lock' AND $1 = ANY(pg_blocking_pids(pid))`

	deadline := time.NewTimer(otherUserDeadline)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()

watch:
	for {
		var n int
		require.NoError(t, db.QueryRowContext(t.Context(), blockedByA, pidA).Scan(&n))
		if n > 0 {
			waited = true
			break
		}

		select {
		case got = <-done:
			finished = true
			break watch
		case <-deadline.C:
			break watch
		case <-tick.C:
		}
	}

	require.NoError(t, txA.Commit())
	if !finished {
		select {
		case got = <-done:
		case <-time.After(lockWaitDeadline):
			t.Fatal("the second update did not return after the first transaction committed")
		}
	}

	if got.err == nil {
		require.NoError(t, txB.Commit())
	} else {
		require.NoError(t, txB.Rollback())
	}

	return waited, finished, got
}

// TestIdentityRace pins that the identity store's collision check is its
// insert and that concurrent updates of one user serialise on its row lock,
// with each interleaving forced rather than left to chance.
func TestIdentityRace(t *testing.T) {
	t.Parallel()

	db := migratedIdentityDB(t).DB

	t.Run("forced interleavings", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name     string
			username string
			scenario func(t *testing.T, db *sql.DB, bind binding, username string) error
			bind     binding
			assert   func(t *testing.T, violation error)
		}

		cases := []testCase{
			{
				name:     "a provision blocked on the unique index reports the user exists",
				username: "race-insert-store",
				scenario: insertAtomicity,
				bind:     realStore,
				assert: func(t *testing.T, violation error) {
					require.NoError(t, violation)
				},
			},
			{
				name:     "an update blocked on the row lock applies on top of the one before it",
				username: "race-update-store",
				scenario: revokeRacesReassert,
				bind:     realStore,
				assert: func(t *testing.T, violation error) {
					require.NoError(t, violation)
				},
			},
			{
				name:     "insert atomicity catches a preceding read",
				username: "race-insert-preceding-read",
				scenario: insertAtomicity,
				bind:     precedingReadStore,
				assert: func(t *testing.T, violation error) {
					require.ErrorContains(t, violation,
						"the blocked provision returned a record: true, error <nil>; want the user-already-exists error")
				},
			},
			{
				name:     "update serialisation catches a missing row lock",
				username: "race-update-unlocked",
				scenario: revokeRacesReassert,
				bind:     unlockedStore,
				assert: func(t *testing.T, violation error) {
					require.ErrorContains(t, violation, "the revoked admin grant came back with its old identifier")
					require.ErrorContains(t, violation, "the revoked admin grant's super role came back")
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				tc.assert(t, tc.scenario(t, db, tc.bind, tc.username))
			})
		}
	})

	t.Run("an update held open blocks only its own user", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name   string
			holder string
			// same targets the holder's own user when true.
			same   bool
			assert func(t *testing.T, waited, finished bool, got outcome)
		}

		cases := []testCase{
			{
				name:   "an update of another user completes while the first is held",
				holder: "race-held-other-a",
				assert: func(t *testing.T, waited, finished bool, got outcome) {
					assert.False(t, waited, "the other user's update waited on the held transaction's lock")
					assert.True(t, finished, "the other user's update did not finish within %v", otherUserDeadline)
					require.NoError(t, got.err)
					require.Len(t, got.d.Roles, 1)
					assert.Equal(t, "other", got.d.Roles[0].Name)
				},
			},
			{
				name:   "control: an update of the same user waits on the held one",
				holder: "race-held-same",
				same:   true,
				assert: func(t *testing.T, waited, finished bool, got outcome) {
					assert.True(t, waited, "the same user's update never waited on the held transaction's lock")
					assert.False(t, finished, "the same user's update finished while the first was held")
					require.NoError(t, got.err, "once released, the update applies")
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				s := newIdentityStore(t, db)
				target := tc.holder
				if !tc.same {
					target = tc.holder + "-target"
				}
				_, err := s.Provision(t.Context(), tc.holder)
				require.NoError(t, err)
				if !tc.same {
					_, err = s.Provision(t.Context(), target)
					require.NoError(t, err)
				}

				waited, finished, got := heldUpdate(t, db, tc.holder, target)
				tc.assert(t, waited, finished, got)
			})
		}
	})

	t.Run("eight concurrent provisions of one name create one user", func(t *testing.T) {
		t.Parallel()

		const (
			racers   = 8
			username = "race-double-submit"
		)
		s := newIdentityStore(t, db)

		start := make(chan struct{})
		results := make([]outcome, racers)
		var wg sync.WaitGroup
		for i := range racers {
			wg.Go(func() {
				<-start
				d, err := s.Provision(t.Context(), username, identity.WithUserRoles("admin"))
				results[i] = outcome{d, err}
			})
		}
		close(start)
		wg.Wait()

		var created, exists int
		for i, r := range results {
			switch {
			case r.err == nil:
				created++
				require.NotNil(t, r.d, "racer %d", i)
				assert.Equal(t, username, r.d.Username, "racer %d", i)
				assert.NotEmpty(t, r.d.ID, "racer %d", i)
			case errors.Is(r.err, identity.ErrUserExists):
				exists++
				assert.Nil(t, r.d, "racer %d", i)
			default:
				t.Errorf("racer %d failed with neither success nor the user-already-exists error: %v", i, r.err)
			}
		}
		assert.Equal(t, 1, created, "successful provisions")
		assert.Equal(t, racers-1, exists, "user-already-exists refusals")
		assert.Equal(t, 1, userRowCount(t.Context(), t, db, username))
	})
}
