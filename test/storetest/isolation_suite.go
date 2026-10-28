package storetest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/store"
	"github.com/kartaladev/scrty/token/onetime"
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
	Streaks func(t *testing.T) lockout.FailureStreakStore
	// RecoveryCodes returns a saved-code store on the database.
	RecoveryCodes func(t *testing.T) recovery.CodeStore
	// Identities returns an identity store on the database, which holds the
	// identity tables too.
	Identities func(t *testing.T) identity.UserProvisioner
	// Limiter returns a rate limiter on the database whose limit is well
	// above the failures the suite records.
	Limiter func(t *testing.T) ratelimit.Limiter
	// OneTime returns a one-time token store on the database.
	OneTime func(t *testing.T) onetime.Store
	// Passkeys returns a passkey credential store on the database.
	Passkeys func(t *testing.T) passkey.CredentialStore
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
		input{"IsolationFixture.OneTime", f.OneTime != nil},
		input{"IsolationFixture.Passkeys", f.Passkeys != nil},
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
// concurrent limiter records report no failure, and concurrent bounded
// one-time inserts for one subject, and bounded passkey inserts for one user,
// store no more than their limit. Inside a
// caller's REPEATABLE READ transaction, the operations that need READ
// COMMITTED refuse with an error naming the level and leave the transaction
// usable. Inside a caller's READ COMMITTED transaction, a bounded insert holds
// its subject until the caller's transaction ends, and only its subject.
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
		{"concurrent bounded inserts of one subject store no more than the limit", func(t *testing.T) {
			s := f.OneTime(t)

			stored := make([]bool, isolationRacers)
			errs := raceAll(t.Context(), isolationRacers, func(ctx context.Context, i int) error {
				var err error
				stored[i], err = s.InsertWithin(ctx, isolationToken(i, "iso-bounded"), suiteStart, isolationLimit)
				return err
			})

			assertNoErrors(t, errs, "a concurrent bounded insert")
			won := 0
			for _, ok := range stored {
				if ok {
					won++
				}
			}
			assert.Equal(t, isolationLimit, won, "bounded inserts reported stored")
			n, err := s.CountRecentBySubject(t.Context(), isolationPurpose, "iso-bounded", suiteStart)
			require.NoError(t, err)
			assert.Equal(t, isolationLimit, n, "records stored")
		}},
		{"a caller's repeatable-read transaction refuses a bounded insert", func(t *testing.T) {
			s := f.OneTime(t)

			tx := f.Begin(t, RepeatableRead)
			stored, err := s.InsertWithin(tx.Ctx, isolationToken(100, "iso-bounded-refused"), suiteStart, isolationLimit)

			assertIsolationRefused(t, f, err)
			assert.False(t, stored)
			require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
			require.NoError(t, tx.Commit())
			n, err := s.CountRecentBySubject(t.Context(), isolationPurpose, "iso-bounded-refused", suiteStart)
			require.NoError(t, err)
			assert.Zero(t, n, "the refused bounded insert stored a record")
		}},
		{"concurrent bounded passkey inserts of one user store no more than the limit", func(t *testing.T) {
			s := f.Passkeys(t)
			user := identity.UserID("iso-passkeys")

			stored := make([]bool, isolationRacers)
			errs := raceAll(t.Context(), isolationRacers, func(ctx context.Context, i int) error {
				var err error
				stored[i], err = s.InsertWithin(ctx, isolationCredential(i, user), isolationLimit)
				return err
			})

			assertNoErrors(t, errs, "a concurrent bounded passkey insert")
			won := 0
			for _, ok := range stored {
				if ok {
					won++
				}
			}
			assert.Equal(t, isolationLimit, won, "bounded passkey inserts reported stored")
			n, err := s.Count(t.Context(), user)
			require.NoError(t, err)
			assert.Equal(t, isolationLimit, n, "passkeys stored")
		}},
		{"a caller's repeatable-read transaction refuses a bounded passkey insert", func(t *testing.T) {
			s := f.Passkeys(t)
			user := identity.UserID("iso-passkeys-refused")

			tx := f.Begin(t, RepeatableRead)
			stored, err := s.InsertWithin(tx.Ctx, isolationCredential(100, user), isolationLimit)

			assertIsolationRefused(t, f, err)
			assert.False(t, stored)
			require.NoError(t, tx.Probe(), "the caller's transaction is not usable after the refusal")
			require.NoError(t, tx.Commit())
			n, err := s.Count(t.Context(), user)
			require.NoError(t, err)
			assert.Zero(t, n, "the refused bounded passkey insert stored a credential")
		}},
		{"a caller's read-committed transaction holds only its subject's bounded inserts until it ends", func(t *testing.T) {
			s := f.OneTime(t)

			tx := f.Begin(t, ReadCommitted)
			stored, err := s.InsertWithin(tx.Ctx, isolationToken(200, "iso-bounded-held"), suiteStart, 1)
			require.NoError(t, err)
			require.True(t, stored, "the caller's bounded insert under its limit must be stored")

			// Another subject is not held: it decides while the caller's
			// transaction is still open.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			stored, err = s.InsertWithin(ctx, isolationToken(201, "iso-bounded-other"), suiteStart, 1)
			require.NoError(t, err, "a bounded insert of another subject waited on the caller's transaction")
			assert.True(t, stored)

			// The same subject is held, and once the caller commits it counts
			// the caller's record and is refused.
			type outcome struct {
				stored bool
				err    error
			}
			later := make(chan outcome, 1)
			go func() {
				ok, err := s.InsertWithin(t.Context(), isolationToken(202, "iso-bounded-held"), suiteStart, 1)
				later <- outcome{ok, err}
			}()
			awaitAdvisoryWaiter(t, f.Raw)
			require.NoError(t, tx.Commit())
			got := <-later
			require.NoError(t, got.err)
			assert.False(t, got.stored, "the held bounded insert did not count the caller's committed record")
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
// matches both the backend's own name for it and store's, so a consumer
// matches it whichever backend runs.
func assertIsolationRefused(t *testing.T, f IsolationFixture, err error) {
	t.Helper()

	require.ErrorIs(t, err, f.IsolationRefused, "the operation ran in the caller's REPEATABLE READ transaction")
	require.ErrorIs(t, err, store.ErrIsolationTooStrong, "the backend's refusal is not store's")
	assert.Contains(t, strings.ToLower(err.Error()), string(RepeatableRead), "the refusal does not name the level")
}

// awaitAdvisoryWaiter waits until one session of raw's database waits on an
// advisory lock: the later caller queued behind the earlier one.
func awaitAdvisoryWaiter(t *testing.T, raw *sql.DB) {
	t.Helper()

	require.Eventually(t, func() bool {
		var waiting int
		err := raw.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_locks
WHERE locktype = 'advisory' AND NOT granted
  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 10*time.Millisecond, "the later caller never waited on the earlier one's advisory lock")
}

// The one-time records the isolation suite inserts: their purpose, and the
// limit its bounded inserts are held to, well below isolationRacers.
const (
	isolationPurpose = "iso-purpose"
	isolationLimit   = 5
)

// isolationToken returns the isolation suite's n-th one-time record, for
// subject, issued at suiteStart. Each n is one identifier, so callers number
// their records apart.
func isolationToken(n int, subject string) onetime.Token {
	h := sha256.Sum256([]byte(subject))
	return onetime.Token{
		ID:         suiteID(5000 + n),
		Purpose:    isolationPurpose,
		Subject:    subject,
		SecretHash: h[:],
		IssuedAt:   suiteStart,
		ExpiresAt:  suiteStart.Add(oneTimeTTL),
	}
}

// isolationCredential returns the isolation suite's n-th passkey credential,
// of user. Each n is one library identifier and one credential ID, so callers
// number their credentials apart.
func isolationCredential(n int, user identity.UserID) *passkey.Credential {
	return passkeyCredential(6000+n, user, fmt.Sprintf("iso-credential-%d", n))
}
