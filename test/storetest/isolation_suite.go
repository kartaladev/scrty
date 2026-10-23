package storetest

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
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/storeerr"
)

// Isolation names a transaction isolation level, spelled as PostgreSQL's
// transaction_isolation setting reports it.
type Isolation string

// The isolation levels the isolation suite begins caller transactions at.
const (
	ReadCommitted  Isolation = "read committed"
	RepeatableRead Isolation = "repeatable read"
)

// CallerTx is a transaction the caller owns, begun by
// IsolationFixture.Begin.
type CallerTx struct {
	// Ctx carries the transaction, attached the way the backend under test
	// attaches one.
	Ctx context.Context
	// Probe runs a trivial statement in the transaction, and fails when the
	// transaction is no longer usable.
	Probe func() error
	// Commit commits the transaction.
	Commit func() error
	// Rollback rolls the transaction back.
	Rollback func() error
}

// IsolationFixture is what RunIsolationSuite needs: stores on one database
// whose default transaction isolation is REPEATABLE READ (set, for example,
// with ALTER DATABASE ... SET default_transaction_isolation), a way to begin a
// transaction the caller owns on that database, and the backend's refusal of
// a caller's stronger transaction. Every field is required, and a suite given
// a fixture with one missing fails at once, naming it.
type IsolationFixture struct {
	// Streaks returns a failure-streak store on the database.
	Streaks func(t *testing.T) policy.FailureStreakStore
	// RecoveryCodes returns a saved-code store on the database.
	RecoveryCodes func(t *testing.T) recovery.CodeStore
	// Identities returns an identity store on the database, which holds the
	// identity tables too.
	Identities func(t *testing.T) identity.UserProvisioner
	// Limiter returns a rate limiter on the database whose limit is well
	// above the failures the suite records.
	Limiter func(t *testing.T) ratelimit.Limiter
	// Begin begins a caller-owned transaction on the database at isolation,
	// and rolls it back at cleanup unless the case ended it.
	Begin func(t *testing.T, isolation Isolation) CallerTx
	// Raw reaches the database out of band.
	Raw *sql.DB
	// IsolationRefused is the error, matched with errors.Is, that an
	// operation needing READ COMMITTED returns inside a caller's stronger
	// transaction.
	IsolationRefused error
	// PoolSize is how many connections each store can hold open at once.
	PoolSize int
}

// isolationRacers is how many callers each race of the isolation suite
// releases at once.
const isolationRacers = 16

// missing names the fields of f that are missing, in declaration order.
func (f IsolationFixture) missing() []string {
	return missingInputs(
		input{"IsolationFixture.Streaks", f.Streaks != nil},
		input{"IsolationFixture.RecoveryCodes", f.RecoveryCodes != nil},
		input{"IsolationFixture.Identities", f.Identities != nil},
		input{"IsolationFixture.Limiter", f.Limiter != nil},
		input{"IsolationFixture.Begin", f.Begin != nil},
		input{"IsolationFixture.Raw", f.Raw != nil},
		input{"IsolationFixture.IsolationRefused", f.IsolationRefused != nil},
		input{"IsolationFixture.PoolSize", f.PoolSize > 0},
	)
}

// RunIsolationSuite holds a durable store's outcomes on a database whose
// default isolation is REPEATABLE READ to what they are at READ COMMITTED:
// failure streaks count every concurrent failure, overlapping saved-code
// replacements leave only the later set, concurrent provisions of one
// username give one user, concurrent updates of one user all succeed, and
// concurrent limiter records report no failure. Inside a caller's REPEATABLE
// READ transaction, the operations that need READ COMMITTED refuse with an
// error naming the level and leave the transaction usable.
//
// A store that begins its own transactions, or runs a statement outside one,
// at the database default fails the streak and the replacement cases.
func RunIsolationSuite(t *testing.T, f IsolationFixture) {
	t.Helper()

	failMissing(t, f.missing())
	requirePool(t, f.PoolSize, isolationRacers+1)

	runDurableCases(t, []durableCase{
		{"concurrent failures of one username all count", func(t *testing.T) {
			s := f.Streaks(t)
			at := suiteStart
			since := at.Add(-time.Hour)
			_, _, err := s.AddStreakFailure(t.Context(), "iso-streak", at, since, 1000)
			require.NoError(t, err)

			errs := raceAll(t.Context(), isolationRacers, func(ctx context.Context, _ int) error {
				_, _, err := s.AddStreakFailure(ctx, "iso-streak", at, since, 1000)
				return err
			})

			assertNoErrors(t, errs, "a concurrent streak failure")
			got, err := s.FailureStreak(t.Context(), "iso-streak", since)
			require.NoError(t, err)
			assert.Equal(t, 1+isolationRacers, got.Failures, "concurrent failures were not all counted")
		}},
		{"of two overlapping saved-code replacements, only the later set remains", func(t *testing.T) {
			s := f.RecoveryCodes(t)
			user := identity.UserID("iso-codes")

			// The earlier replacement runs in a caller's READ COMMITTED
			// transaction, so it holds the user's serialisation until that
			// commits, and the later one, in a transaction of the store's
			// own, waits for it.
			earlier := f.Begin(t, ReadCommitted)
			require.NoError(t, s.ReplaceSet(earlier.Ctx, user, codeSet("a"), suiteStart))

			later := make(chan error, 1)
			go func() { later <- s.ReplaceSet(t.Context(), user, codeSet("b"), suiteStart) }()
			awaitAdvisoryWaiter(t, f.Raw)
			require.NoError(t, earlier.Commit())
			require.NoError(t, <-later)

			n, err := s.Remaining(t.Context(), user)
			require.NoError(t, err)
			assert.Equal(t, 10, n, "the overlapping replacements did not leave exactly one set")
			for _, code := range codeSet("a") {
				ok, err := s.Match(t.Context(), user, code)
				require.NoError(t, err)
				assert.False(t, ok, "a code of the earlier set %q still matches", code)
			}
		}},
		{"concurrent provisions of one username create one user", func(t *testing.T) {
			s := f.Identities(t)

			errs := raceAll(t.Context(), 8, func(ctx context.Context, _ int) error {
				_, err := s.Provision(ctx, "iso-provision")
				return err
			})

			won, exists := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					won++
				case errors.Is(err, identity.ErrUserExists):
					exists++
				default:
					t.Errorf("a concurrent provision failed: %v", err)
				}
			}
			assert.Equal(t, 1, won, "provisions that succeeded")
			assert.Equal(t, 7, exists, "provisions refused as existing")
		}},
		{"concurrent updates of one user all succeed", func(t *testing.T) {
			s := f.Identities(t)
			_, err := s.Provision(t.Context(), "iso-update")
			require.NoError(t, err)

			errs := raceAll(t.Context(), 8, func(ctx context.Context, i int) error {
				_, err := s.Update(ctx, "iso-update", identity.WithUserName(fmt.Sprintf("name-%d", i)))
				return err
			})

			assertNoErrors(t, errs, "a concurrent update")
		}},
		{"concurrent limiter records report no failure", func(t *testing.T) {
			l := f.Limiter(t)
			require.NoError(t, l.RecordFailure(t.Context(), "iso-limiter"))

			errs := raceAll(t.Context(), isolationRacers, func(ctx context.Context, _ int) error {
				return l.RecordFailure(ctx, "iso-limiter")
			})

			assertNoErrors(t, errs, "a concurrent limiter record")
		}},
		{"a caller's repeatable-read transaction refuses a saved-code replacement", func(t *testing.T) {
			s := f.RecoveryCodes(t)
			user := identity.UserID("iso-codes-refused")
			require.NoError(t, s.ReplaceSet(t.Context(), user, codeSet("kept"), suiteStart))

			tx := f.Begin(t, RepeatableRead)
			err := s.ReplaceSet(tx.Ctx, user, codeSet("refused"), suiteStart)

			assertIsolationRefused(t, f, err)
			require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
			require.NoError(t, tx.Commit())
			ok, err := s.Match(t.Context(), user, codeSet("kept")[0])
			require.NoError(t, err)
			assert.True(t, ok, "the refused replacement changed the stored set")
		}},
		{"a caller's repeatable-read transaction refuses a streak failure", func(t *testing.T) {
			s := f.Streaks(t)
			since := suiteStart.Add(-time.Hour)

			tx := f.Begin(t, RepeatableRead)
			_, _, err := s.AddStreakFailure(tx.Ctx, "iso-streak-refused", suiteStart, since, 1000)

			assertIsolationRefused(t, f, err)
			require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
			require.NoError(t, tx.Commit())
			got, err := s.FailureStreak(t.Context(), "iso-streak-refused", since)
			require.NoError(t, err)
			assert.Zero(t, got.Failures, "the refused failure was counted")
		}},
		{"a caller's read-committed transaction is joined", func(t *testing.T) {
			codes, streaks := f.RecoveryCodes(t), f.Streaks(t)
			user := identity.UserID("iso-codes-joined")
			since := suiteStart.Add(-time.Hour)

			tx := f.Begin(t, ReadCommitted)
			require.NoError(t, codes.ReplaceSet(tx.Ctx, user, codeSet("joined"), suiteStart))
			_, _, err := streaks.AddStreakFailure(tx.Ctx, "iso-streak-joined", suiteStart, since, 1000)
			require.NoError(t, err)
			require.NoError(t, tx.Rollback())

			n, err := codes.Remaining(t.Context(), user)
			require.NoError(t, err)
			assert.Zero(t, n, "the replacement did not run in the caller's transaction")
			got, err := streaks.FailureStreak(t.Context(), "iso-streak-joined", since)
			require.NoError(t, err)
			assert.Zero(t, got.Failures, "the streak failure did not run in the caller's transaction")
		}},
	})
}

// codeSet returns ten distinct saved-code hashes tagged with tag.
func codeSet(tag string) [][]byte {
	out := make([][]byte, 10)
	for i := range out {
		out[i] = fmt.Appendf(nil, "iso-%s-%d", tag, i)
	}
	return out
}

// raceAll releases n callers of fn at once, and returns each one's error by
// its index.
func raceAll(ctx context.Context, n int, fn func(ctx context.Context, i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = fn(ctx, i)
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// assertNoErrors fails t once for every error in errs, naming what failed.
func assertNoErrors(t *testing.T, errs []error, what string) {
	t.Helper()

	for _, err := range errs {
		assert.NoError(t, err, "%s failed", what)
	}
}

// assertIsolationRefused requires err to be the backend's refusal of a
// caller's stronger transaction, naming the level it found. The refusal
// matches both the backend's own name for it and storeerr's, so a consumer
// matches it whichever backend runs.
func assertIsolationRefused(t *testing.T, f IsolationFixture, err error) {
	t.Helper()

	require.ErrorIs(t, err, f.IsolationRefused, "the operation ran in the caller's REPEATABLE READ transaction")
	require.ErrorIs(t, err, storeerr.ErrIsolationTooStrong, "the backend's refusal is not storeerr's")
	assert.Contains(t, strings.ToLower(err.Error()), string(RepeatableRead), "the refusal does not name the level")
}

// awaitAdvisoryWaiter waits until one session of raw's database waits on an
// advisory lock: the later replacement queued behind the earlier one.
func awaitAdvisoryWaiter(t *testing.T, raw *sql.DB) {
	t.Helper()

	require.Eventually(t, func() bool {
		var waiting int
		err := raw.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_locks
WHERE locktype = 'advisory' AND NOT granted
  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 10*time.Millisecond, "the later replacement never waited on the earlier one")
}
