package gormstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
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
// its writes inside tx, a transaction of d the scenario holds open.
type binding func(t *testing.T, d database, tx *gormdb.DB) (provisioner, context.Context)

// realStore binds the unmodified store to tx through gormstore.WithTx.
func realStore(t *testing.T, d database, tx *gormdb.DB) (provisioner, context.Context) {
	return newIdentityStore(t, d.db), gormstore.WithTx(t.Context(), tx)
}

// precedingReadStore binds the check-then-insert variant to tx: see
// precedingRead.
func precedingReadStore(t *testing.T, d database, tx *gormdb.DB) (provisioner, context.Context) {
	return precedingRead{newIdentityStore(t, d.db)}, gormstore.WithTx(t.Context(), tx)
}

// unlockedStore binds the store to tx through a consumer resolver whose
// handle runs on unlockedPool, which sends the store's user lock without FOR
// UPDATE. gorm builds that lock from clause.Locking, so there is no shared
// statement text to swap: the variant strips the clause from whatever
// statement reaches the connection, and the case fails if none carried it,
// since the variant would then equal the store.
func unlockedStore(t *testing.T, d database, tx *gormdb.DB) (provisioner, context.Context) {
	pool := &unlockedPool{ConnPool: tx.Statement.ConnPool}
	t.Cleanup(func() {
		assert.Positive(t, pool.stripped.Load(),
			"no statement carried FOR UPDATE; the unlocked variant equals the store")
	})

	h := overPool(t.Context(), tx, pool)
	s := newIdentityStore(t, d.db, gormstore.WithTxResolver(func(context.Context) (*gormdb.DB, bool) {
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
	*gormstore.IdentityStore
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

// lockSuffix is how gorm's PostgreSQL dialect ends a statement carrying
// clause.Locking{Strength: "UPDATE"}.
const lockSuffix = " FOR UPDATE"

// unlockedPool is a caller's transaction that sends the store's user lock as
// a plain read, so an update reads and plans against a row another
// transaction is still changing. It counts the statements it stripped.
type unlockedPool struct {
	gormdb.ConnPool

	stripped atomic.Int64
}

func (u *unlockedPool) unlock(query string) string {
	if strings.HasSuffix(query, lockSuffix) {
		u.stripped.Add(1)
		return strings.TrimSuffix(query, lockSuffix)
	}

	return query
}

func (u *unlockedPool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return u.ConnPool.QueryContext(ctx, u.unlock(query), args...)
}

func (u *unlockedPool) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return u.ConnPool.QueryRowContext(ctx, u.unlock(query), args...)
}

// outcome is what a provisioner call returned.
type outcome struct {
	d   *identity.Details
	err error
}

// backendPID is the PostgreSQL backend serving tx.
func backendPID(t *testing.T, tx *gormdb.DB) int {
	t.Helper()

	var pid int
	require.NoError(t, tx.Raw(`SELECT pg_backend_pid()`).Scan(&pid).Error)
	require.NotZero(t, pid)

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

// holdThenRelease runs first inside a transaction A it holds open, starts
// second inside a transaction B of its own, waits until B is confirmed
// blocked on a lock A holds, commits A, and returns B's outcome once B's call
// returns; B is then committed when its call succeeded and rolled back
// otherwise. A failure to confirm the wait is returned as a violation beside
// the outcome.
func holdThenRelease(
	t *testing.T, d database, bind binding,
	first, second func(p provisioner, ctx context.Context) (*identity.Details, error),
) (outcome, error) {
	t.Helper()

	txA := beginGorm(t.Context(), t, d.db)
	pA, ctxA := bind(t, d, txA)
	_, err := first(pA, ctxA)
	require.NoError(t, err, "the held transaction's own call")
	holder := backendPID(t, txA)

	txB := beginGorm(t.Context(), t, d.db)
	pB, ctxB := bind(t, d, txB)
	done := make(chan outcome, 1)
	go func() {
		got, err := second(pB, ctxB)
		done <- outcome{got, err}
	}()

	waitErr := awaitBlockedBy(t.Context(), d.conn.DB, holder, done)
	require.NoError(t, txA.Commit().Error)

	var got outcome
	select {
	case got = <-done:
	case <-time.After(lockWaitDeadline):
		t.Fatal("the second call did not return after the first transaction committed")
	}

	if got.err == nil {
		require.NoError(t, txB.Commit().Error)
	} else {
		require.NoError(t, txB.Rollback().Error)
	}

	return got, waitErr
}

// insertAtomicity provisions username in a held transaction A, then again in
// B, which must block on the unique index until A commits and then report
// that the user exists. It returns every way the outcome departs from that.
func insertAtomicity(t *testing.T, d database, bind binding, username string) error {
	t.Helper()

	got, waitErr := holdThenRelease(t, d, bind,
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
	if n := userRowCount(t.Context(), t, d.conn.DB, username); n != 1 {
		violations = append(violations, fmt.Errorf("%d users stored under the name, want 1", n))
	}

	stored, err := newIdentityStore(t, d.db).LoadByUsername(t.Context(), username)
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
func revokeRacesReassert(t *testing.T, d database, bind binding, username string) error {
	t.Helper()

	seeded, err := newIdentityStore(t, d.db).Provision(t.Context(), username, identity.WithUserRoles("admin"))
	require.NoError(t, err)
	require.Len(t, seeded.Roles, 1)
	revoked := seeded.Roles[0].ID
	// A super role is written by the consumer's tooling, never by the store.
	_, err = d.conn.DB.ExecContext(t.Context(), `UPDATE assigned_roles SET super_role = true WHERE id = $1`, revoked)
	require.NoError(t, err)

	got, waitErr := holdThenRelease(t, d, bind,
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

	final, err := newIdentityStore(t, d.db).LoadByUsername(t.Context(), username)
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

// updateWaits seeds first and second, updates first in a held transaction A,
// then updates second outside any transaction of the caller's, and reports
// whether that call waited on a lock A holds: nil when it did, an error when
// it finished without waiting. A is rolled back once the answer is in, and
// the second call must then return without error.
func updateWaits(t *testing.T, d database, first, second string) error {
	t.Helper()

	s := newIdentityStore(t, d.db)
	for _, username := range []string{first, second} {
		if _, err := s.Provision(t.Context(), username); err != nil && !errors.Is(err, identity.ErrUserExists) {
			require.NoError(t, err)
		}
	}

	txA := beginGorm(t.Context(), t, d.db)
	_, err := s.Update(gormstore.WithTx(t.Context(), txA), first, identity.WithUserName("held"))
	require.NoError(t, err, "the held transaction's own update")
	holder := backendPID(t, txA)

	done := make(chan outcome, 1)
	go func() {
		got, err := s.Update(t.Context(), second, identity.WithUserName("independent"))
		done <- outcome{got, err}
	}()

	waitErr := awaitBlockedBy(t.Context(), d.conn.DB, holder, done)
	require.NoError(t, txA.Rollback().Error)

	select {
	case got := <-done:
		require.NoError(t, got.err, "the second update")
	case <-time.After(lockWaitDeadline):
		t.Fatal("the second update did not return after the held transaction ended")
	}

	return waitErr
}

// TestIdentityRace pins that the identity store's collision check is its
// insert and that concurrent updates of one user serialise on its row lock,
// with each interleaving forced rather than left to chance.
func TestIdentityRace(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	t.Run("forced interleavings", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name     string
			username string
			scenario func(t *testing.T, d database, bind binding, username string) error
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

				tc.assert(t, tc.scenario(t, d, tc.bind, tc.username))
			})
		}
	})

	t.Run("updates wait only on the user they lock", func(t *testing.T) {
		t.Parallel()

		type testCase struct {
			name          string
			first, second string
			assert        func(t *testing.T, waited error)
		}

		cases := []testCase{
			{
				name:   "an update of another user does not wait on the held one",
				first:  "race-independent-held",
				second: "race-independent-other",
				assert: func(t *testing.T, waited error) {
					require.ErrorContains(t, waited, "finished without waiting",
						"an update of a different user waited on the held transaction")
				},
			},
			{
				name:   "an update of the same user waits on the held one",
				first:  "race-independent-same",
				second: "race-independent-same",
				assert: func(t *testing.T, waited error) {
					require.NoError(t, waited, "the control update did not wait on the user's row lock")
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				tc.assert(t, updateWaits(t, d, tc.first, tc.second))
			})
		}
	})

	t.Run("eight concurrent provisions of one name create one user", func(t *testing.T) {
		t.Parallel()

		const (
			racers   = 8
			username = "race-double-submit"
		)
		s := newIdentityStore(t, d.db)

		start := make(chan struct{})
		results := make([]outcome, racers)
		var wg sync.WaitGroup
		for i := range racers {
			wg.Go(func() {
				<-start
				got, err := s.Provision(t.Context(), username, identity.WithUserRoles("admin"))
				results[i] = outcome{got, err}
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
		assert.Equal(t, 1, userRowCount(t.Context(), t, d.conn.DB, username))
	})
}
