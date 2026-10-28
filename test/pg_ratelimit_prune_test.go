package test

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// pgPruneEnv is what a prune case drives: a database of the case's own, so
// one case's prune never counts another's rows, a factory over it in
// application-clock mode, the clock, and a builder of further factories over
// the same database and clock, as other replicas would build.
type pgPruneEnv struct {
	conn       PostgresConn
	clock      *clockwork.FakeClock
	factory    pgFactory
	newFactory func() pgFactory
	ns         func(name string) string
}

// limiter builds a limiter of f, failing the case on error.
func (e pgPruneEnv) limiter(t *testing.T, f pgFactory, ns string, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	l, err := f.NewLimiter(ns, limit, window)
	require.NoError(t, err)
	return l
}

// lockWaiters counts the sessions of the case's database waiting on a lock.
func (e pgPruneEnv) lockWaiters(t *testing.T) int {
	t.Helper()

	var n int
	require.NoError(t, e.conn.DB.QueryRowContext(t.Context(),
		`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`).Scan(&n))
	return n
}

// rows counts the bucket rows of ns.
func (e pgPruneEnv) rows(t *testing.T, ns string) int {
	t.Helper()

	var n int
	require.NoError(t, e.conn.DB.QueryRowContext(t.Context(),
		`SELECT count(*) FROM rate_limit_buckets WHERE namespace = $1`, ns).Scan(&n))
	return n
}

// runPGPrune pins the prune through ratelimit.ExpiryTask(factory): the
// longest window a key was recorded with protects it, an idle key is removed
// and counted, a row another session holds is skipped without waiting, one
// run covers every namespace, a prune racing an uncommitted record on an idle
// key never deletes the count that record commits, and records and prunes
// running together raise no error.
func runPGPrune(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name   string
		assert func(t *testing.T, e pgPruneEnv)
	}

	cases := []testCase{
		{
			name: "longest recorded window protects a key",
			assert: func(t *testing.T, e pgPruneEnv) {
				ns := e.ns("api-key")
				long := e.limiter(t, e.factory, ns, 2, 15*time.Minute)
				// The 1-minute instance is another replica's: one factory
				// refuses a namespace with a second policy.
				short := e.limiter(t, e.newFactory(), ns, 2, time.Minute)

				require.NoError(t, long.RecordFailure(t.Context(), "k"))
				e.clock.Advance(30 * time.Second)
				require.NoError(t, short.RecordFailure(t.Context(), "k"))
				e.clock.Advance(10 * time.Minute)

				removed, err := ratelimit.ExpiryTask(e.factory).Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 0, removed, "the prune removed a key a 15-minute instance still counts")
				exceeded, err := long.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded, "the 15-minute instance no longer counts both failures")
			},
		},
		{
			name: "idle key is removed and counted",
			assert: func(t *testing.T, e pgPruneEnv) {
				ns := e.ns("api-key")
				l := e.limiter(t, e.factory, ns, 1, time.Minute)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				e.clock.Advance(90 * time.Second)

				removed, err := ratelimit.ExpiryTask(e.factory).Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Zero(t, e.rows(t, ns), "the idle key's row is still there")
			},
		},
		{
			name: "row another session holds is skipped without waiting",
			assert: func(t *testing.T, e pgPruneEnv) {
				ns := e.ns("api-key")
				l := e.limiter(t, e.factory, ns, 1, time.Minute)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				e.clock.Advance(90 * time.Second)

				holder, err := e.conn.DB.BeginTx(t.Context(), nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = holder.Rollback() })
				var one int
				require.NoError(t, holder.QueryRowContext(t.Context(),
					`SELECT 1 FROM rate_limit_buckets WHERE namespace = $1 AND key = $2 FOR UPDATE`, ns, "k").Scan(&one))

				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				start := time.Now()
				removed, err := ratelimit.ExpiryTask(e.factory).Run(ctx)
				elapsed := time.Since(start)
				t.Logf("prune with a held row returned after %s", elapsed)
				// Checked before the error: a prune that waits ends with ctx's.
				assert.Less(t, elapsed, 500*time.Millisecond, "the prune waited on the held row")
				require.NoError(t, err)
				assert.Equal(t, 0, removed)
				assert.Equal(t, 1, e.rows(t, ns), "the held row was removed")
			},
		},
		{
			name: "one run covers every namespace",
			assert: func(t *testing.T, e pgPruneEnv) {
				var namespaces []string
				for _, name := range []string{"api-key", "magic-link", "totp"} {
					ns := e.ns(name)
					namespaces = append(namespaces, ns)
					require.NoError(t, e.limiter(t, e.factory, ns, 1, time.Minute).RecordFailure(t.Context(), "k"))
				}
				e.clock.Advance(90 * time.Second)

				removed, err := ratelimit.ExpiryTask(e.factory).Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
				for _, ns := range namespaces {
					assert.Zero(t, e.rows(t, ns), "namespace %s kept its idle key", ns)
				}
			},
		},
		{
			// The interleaving that loses a count: a record holds the idle
			// key's row, uncommitted, while the prune runs. Under READ
			// COMMITTED the prune's snapshot shows the idle version, so the
			// key is a victim; FOR UPDATE SKIP LOCKED then finds the row
			// locked and skips it, without waiting. A prune with no row lock
			// instead waits in its DELETE, and once the record commits
			// rechecks only its join to the victims, so it deletes the live
			// version. The commit is held until the prune has either returned
			// or is seen waiting on a lock, so the prune's snapshot predates
			// the commit either way.
			name: "prune against an uncommitted record on an idle key keeps the key",
			assert: func(t *testing.T, e pgPruneEnv) {
				const limit = 2
				ns := e.ns("api-key")
				l := e.limiter(t, e.factory, ns, limit, time.Minute)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				e.clock.Advance(2 * time.Minute)

				// Another session records limit failures and does not
				// commit yet: the key is live in its version only.
				rec, err := e.conn.DB.BeginTx(t.Context(), nil)
				require.NoError(t, err)
				t.Cleanup(func() { _ = rec.Rollback() })
				now := e.clock.Now().UTC().Truncate(time.Microsecond)
				for range limit {
					_, err := rec.ExecContext(t.Context(), pgStatement(t, pgRecordName),
						ns, pgStoredKey("k"), limit, time.Minute.Microseconds(), now, "5000ms")
					require.NoError(t, err)
				}

				type result struct {
					removed int
					err     error
				}
				done := make(chan result, 1)
				go func() {
					n, err := ratelimit.ExpiryTask(e.factory).Run(t.Context())
					done <- result{removed: n, err: err}
				}()

				var (
					res      result
					finished bool
				)
				deadline := time.After(5 * time.Second)
			wait:
				for {
					select {
					case res = <-done:
						finished = true
						break wait
					case <-deadline:
						t.Error("the prune neither returned nor waited on the record's row")
						break wait
					case <-time.After(20 * time.Millisecond):
						if e.lockWaiters(t) > 0 {
							t.Log("the prune is waiting on the record's row")
							break wait
						}
					}
				}
				require.NoError(t, rec.Commit())
				if !finished {
					select {
					case res = <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("the prune did not return after the record committed")
					}
				}

				require.NoError(t, res.err)
				assert.Equal(t, 0, res.removed, "the prune deleted a key a committed record had made live")
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded, "the %d failures the record committed no longer count", limit)
			},
		},
		{
			// Contention only: many records and prunes at once raise no
			// error (no deadlock, no lock wait given up) and the key ends
			// exceeded. It does not reliably reach the interleaving that
			// loses a count; the case above pins that.
			name: "records and prunes running together raise no error",
			assert: func(t *testing.T, e pgPruneEnv) {
				const racers = 50
				ns := e.ns("api-key")
				l := e.limiter(t, e.factory, ns, racers, time.Minute)
				// The key goes idle first, so every prune below may take
				// it, until a record makes it live again.
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				e.clock.Advance(2 * time.Minute)

				var (
					wg      sync.WaitGroup
					mu      sync.Mutex
					errs    []error
					removed int
				)
				fail := func(err error) {
					mu.Lock()
					defer mu.Unlock()
					errs = append(errs, err)
				}
				release := make(chan struct{})
				for range racers {
					wg.Go(func() {
						<-release
						if err := l.RecordFailure(t.Context(), "k"); err != nil {
							fail(fmt.Errorf("record: %w", err))
						}
					})
				}
				wg.Go(func() {
					<-release
					task := ratelimit.ExpiryTask(e.factory)
					for range 20 {
						n, err := task.Run(t.Context())
						if err != nil {
							fail(fmt.Errorf("prune: %w", err))
						}
						mu.Lock()
						removed += n
						mu.Unlock()
					}
				})
				close(release)
				wg.Wait()

				t.Logf("the prunes removed %d rows while the records ran", removed)
				assert.Empty(t, errs)
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded, "a prune lost some of the %d failures recorded on the live key", racers)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := migratedLimiterDB(t)
			clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
			o := pgFaultOptions{clock: clk}
			newFactory := func() pgFactory { return b.factory(t, conn, o) }
			tc.assert(t, pgPruneEnv{
				conn:       conn,
				clock:      clk,
				factory:    newFactory(),
				newFactory: newFactory,
				ns:         func(name string) string { return pgScopedNamespace(t, name) },
			})
		})
	}
}

func TestPGLimiter_Prune(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGPrune)
}

// pgPruneByCheckingWindow is a prune that measures idleness by one instance's
// window, $3, rather than by the longest window recorded for each key. $2 is
// the batch size.
var pgPruneByCheckingWindow = pgStatementEdit{
	name: "prune-by-checking-window",
	stmt: pgPruneName,
	old:  "b.longest_window_us * interval",
	new:  "$3::bigint * interval",
}

// pgPruneWithoutRowLock is a prune that takes no row lock on its victims, so
// its DELETE waits on a row a record holds and, under READ COMMITTED, deletes
// the version that record committed: the DELETE rechecks only its join to the
// victims, not their idleness.
var pgPruneWithoutRowLock = pgStatementEdit{
	name: "prune-without-row-lock",
	stmt: pgPruneName,
	old:  "\n  FOR UPDATE OF b SKIP LOCKED",
	new:  "",
}

// pgPruneWithoutSkipLocked is a prune that locks its victims but waits for a
// row another session holds, rather than skipping it.
var pgPruneWithoutSkipLocked = pgStatementEdit{
	name: "prune-without-skip-locked",
	stmt: pgPruneName,
	old:  " SKIP LOCKED",
	new:  "",
}

// pgStatementPruneFactory is a factory whose prune runs a statement of the
// test's own, once, with the fake clock's time as $1 and extra after it. One
// statement is enough for the prune cases, none of which has 1,000 rows, the
// batch size the variants pass as $2.
type pgStatementPruneFactory struct {
	pgFactory // the real factory, for NewLimiter and Verify

	db    *sql.DB
	clk   *clockwork.FakeClock
	stmt  string
	extra []any
}

func (f *pgStatementPruneFactory) Prune(ctx context.Context) (int, error) {
	args := append([]any{f.clk.Now().UTC().Truncate(time.Microsecond)}, f.extra...)
	res, err := f.db.ExecContext(ctx, f.stmt, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// pgBrokenPruneBackend is the sqlstore backend, named as a broken variant,
// whose factory prunes with edit's statement and extra.
func pgBrokenPruneBackend(edit pgStatementEdit, extra ...any) pgFaultBackend {
	b := sqlstoreFaultBackend
	b.name = pgFaultBrokenBackend
	b.factory = func(t *testing.T, conn PostgresConn, o pgFaultOptions) pgFactory {
		t.Helper()
		clk, ok := o.clock.(*clockwork.FakeClock)
		require.True(t, ok, "the prune cases run on a fake clock")
		return &pgStatementPruneFactory{
			pgFactory: sqlstoreFaultBackend.factory(t, conn, o),
			db:        pgFaultDB(t, conn, pgFaultOptions{}),
			clk:       clk,
			stmt:      edit.apply(t),
			extra:     extra,
		}
	}
	return b
}

var pgPruneBroken = pgFaultVariants(runPGPrune,
	pgFaultVariant{
		name:      pgPruneByCheckingWindow.name,
		backend:   pgBrokenPruneBackend(pgPruneByCheckingWindow, 1000, time.Minute.Microseconds()),
		failsCase: "longest recorded window protects a key",
		failsWith: "the prune removed a key a 15-minute instance still counts",
	},
	pgFaultVariant{
		name:      pgPruneWithoutRowLock.name,
		backend:   pgBrokenPruneBackend(pgPruneWithoutRowLock, 1000),
		failsCase: "prune against an uncommitted record on an idle key keeps the key",
		failsWith: "the prune deleted a key a committed record had made live",
	},
	pgFaultVariant{
		name:      pgPruneWithoutSkipLocked.name,
		backend:   pgBrokenPruneBackend(pgPruneWithoutSkipLocked, 1000),
		failsCase: "row another session holds is skipped without waiting",
		failsWith: "the prune waited on the held row",
	},
)

// TestPGLimiter_PruneBroken is the child half of
// TestPGLimiter_PruneCatchesBrokenVariants. Without a variant named it skips.
func TestPGLimiter_PruneBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_PruneCatchesBrokenVariants", pgPruneBroken)
}

func TestPGLimiter_PruneCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_PruneBroken", pgPruneBroken)
}

// pruneFactoryOptions are what a prune test's factory differs by. The zero
// value is the production defaults: the 250ms operation timeout, the database
// clock and prune batches of 1,000 keys, over conn's handle or a pool of the
// factory's own.
type pruneFactoryOptions struct {
	// clock, when set, is the factory's clock, and the test timeout replaces
	// the default operation timeout, as the other builders give it.
	clock clock.Clock
	// batch, when set, is the prune batch size.
	batch int
	// timeout, when set, replaces the operation timeout.
	timeout time.Duration
	// pool, when set, is the pool a pgx factory runs on, so that two
	// factories can share one.
	pool *pgxpool.Pool
}

// pruneFactory builds b's factory over conn, configured by o, with a
// discarded log.
func pruneFactory(t *testing.T, b pgBackend, conn PostgresConn, o pruneFactoryOptions) pgFactory {
	t.Helper()

	discard := slog.New(slog.DiscardHandler)
	switch b.name {
	case sqlstoreBackend.name:
		opts := []sqlstore.LimiterOption{sqlstore.WithLimiterLogger(discard)}
		if o.clock != nil {
			opts = pgLimiterOptions(o.clock)
		}
		if o.batch != 0 {
			opts = append(opts, sqlstore.WithLimiterPruneBatchSize(o.batch))
		}
		if o.timeout != 0 {
			opts = append(opts, sqlstore.WithLimiterOperationTimeout(o.timeout))
		}
		f, err := sqlstore.NewLimiterFactory(conn.DB, opts...)
		require.NoError(t, err)
		return f
	case pgxBackend.name:
		opts := []pgxstore.LimiterOption{pgxstore.WithLimiterLogger(discard)}
		if o.clock != nil {
			opts = pgxLimiterOptions(o.clock)
		}
		if o.batch != 0 {
			opts = append(opts, pgxstore.WithLimiterPruneBatchSize(o.batch))
		}
		if o.timeout != 0 {
			opts = append(opts, pgxstore.WithLimiterOperationTimeout(o.timeout))
		}
		pool := o.pool
		if pool == nil {
			pool = pgxTestPool(t, conn.DSN)
		}
		f, err := pgxstore.NewLimiterFactory(pool, opts...)
		require.NoError(t, err)
		return f
	}
	t.Fatalf("no prune factory for backend %q", b.name)
	return nil
}

// pruneRecordConns is how many connections the records of
// runPGPruneUnderRecords run on: the harness handle's open limit.
const pruneRecordConns = 32

// prunePool is the handle b's records run on, sized to pruneRecordConns and
// keeping every connection it opens, with a count of its open connections.
type prunePool struct {
	pool *pgxpool.Pool // the pgx backend's; nil for sqlstore
	open func() int
}

// newPrunePool sizes b's handle over conn to pruneRecordConns connections,
// all kept open once opened: conn's handle for sqlstore, whose default of two
// idle connections would close the rest after each burst and make records
// dial again, or a pool of its own for pgx.
func newPrunePool(t *testing.T, b pgBackend, conn PostgresConn) prunePool {
	t.Helper()

	if b.name == pgxBackend.name {
		cfg, err := pgxpool.ParseConfig(conn.DSN)
		require.NoError(t, err)
		cfg.MaxConns = pruneRecordConns
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		return prunePool{pool: pool, open: func() int { return int(pool.Stat().TotalConns()) }}
	}
	conn.DB.SetMaxOpenConns(pruneRecordConns)
	conn.DB.SetMaxIdleConns(pruneRecordConns)
	return prunePool{open: func() int { return conn.DB.Stats().OpenConnections }}
}

// warmPrunePool runs bursts of records until p holds pruneRecordConns open
// connections, so that a later record does not dial. It records through warm,
// a factory over p with the test timeout, on keys of a namespace of its own: a
// connection slow to open must not fail the warm-up, nor trip the breaker of
// the limiter under test.
func warmPrunePool(t *testing.T, p prunePool, warm pgFactory) {
	t.Helper()

	l, err := warm.NewLimiter(pgScopedNamespace(t, "warm-up"), 5, time.Minute)
	require.NoError(t, err)
	// A burst opens a connection per record only while the records overlap,
	// so it repeats until every connection is open. What ends the loop is the
	// count alone: the seed, the migrations or a factory's construction may
	// have opened some of the connections, and a burst whose records did not
	// all overlap ran no record on some. A record may therefore still prepare
	// its statement on first use of a connection, a round trip on an open
	// connection, not a dial.
	for round := 0; p.open() < pruneRecordConns; round++ {
		require.Less(t, round, 20, "the warm-up opened %d of %d connections", p.open(), pruneRecordConns)
		var wg sync.WaitGroup
		for i := range pruneRecordConns {
			wg.Go(func() {
				assert.NoError(t, l.RecordFailure(t.Context(), fmt.Sprintf("warm-%d-%d", round, i)))
			})
		}
		wg.Wait()
	}
}

// pruneRecord is one record runPGPruneUnderRecords made during the prune.
type pruneRecord struct {
	key   string
	start time.Duration // since the prune began
	wait  time.Duration
	err   error
}

// pruneFailures describes failed, the records that errored or outlasted the
// timeout: the first to start, distinctly, and how many of the rest timed out
// or were refused at once, as an open breaker refuses them.
func pruneFailures(failed []pruneRecord, timeout time.Duration) string {
	if len(failed) == 0 {
		return "none"
	}
	slices.SortFunc(failed, func(a, b pruneRecord) int { return cmp.Compare(a.start, b.start) })
	first := failed[0]
	var timedOut, refused int
	for _, r := range failed[1:] {
		if r.wait >= timeout {
			timedOut++
		} else {
			refused++
		}
	}
	return fmt.Sprintf("first: key %s, started %s into the prune, waited %s, error %v; "+
		"then %d more timed out and %d were refused at once (the breaker)",
		first.key, first.start, first.wait, first.err, timedOut, refused)
}

// pruneLockWaits is what sampleLockWaits saw of the records' waits on locks
// the prune held. Every time in it is the server's: each sample reads the
// server's clock with the waits it lists.
type pruneLockWaits struct {
	// longest is the longest such wait any sample saw still under way: a
	// lower bound, from the lock's waitstart to the last sample that saw it,
	// or the record's lock timeout for a wait given up while its prune
	// transaction was open (see abandoned).
	longest time.Duration
	// bound is the longest a wait can have lasted: from its waitstart to the
	// first sample that no longer saw it, or to the last sample for one still
	// under way then. A wait given up at the lock timeout whose batch
	// committed before the next sample is seen at most just short of the
	// timeout, so longest misses it; bound does not, being the timeout or
	// more for every wait that reached it.
	bound time.Duration
	// waits counts the distinct waits seen.
	waits int
	// abandoned counts the waits that ended while the prune transaction they
	// waited on was still open. That transaction still held the lock, so the
	// record was not granted it: the server gave up the wait at the record's
	// lock_timeout, its operation timeout, and the wait lasted that long. A
	// record's client giving up does not end a server-side wait: pgx's
	// default context handling closes the connection rather than send a
	// cancel request, and a backend waiting on a lock does not notice its
	// client is gone.
	abandoned int
	// gap is the longest time between two consecutive successful samples,
	// from the one taken before the prune started to the one taken after
	// every record returned. A wait shorter than gap can fall between two
	// samples unseen; a wait at least as long as the timeout cannot while gap
	// is shorter than it.
	gap time.Duration
	// pruneSeen counts the samples that found a prune transaction open, and
	// recordSeen those that found a record session with the record statement
	// current: running it, or idle in its transaction before the commit.
	// Both match pg_stat_activity's query text exactly, as the wait query
	// does, so a positive count shows the match finds the statements the
	// adapters send. A record runs in a READ COMMITTED
	// transaction of its own, so once it commits its session shows the
	// COMMIT, not the record: only a sample taken while the record is still
	// in flight can see it, as only such a sample can see its wait.
	pruneSeen, recordSeen int
	// samples and failed count the samples taken and those whose query
	// failed; firstErr is the first such failure.
	samples, failed int
	firstErr        error
}

// pruneLockWaitsQuery lists the record sessions of the current database
// waiting on a lock the prune holds: $1 is the record statement and $2 the
// prune's, as pg_stat_activity shows them. The prune locks its victims FOR
// UPDATE SKIP LOCKED, which marks each row with its transaction id and never
// waits, so it keeps no heavyweight tuple lock a record could queue on: a
// record that finds a victim locked waits for the prune transaction's id,
// with the prune session among its pg_blocking_pids. A record queued on a
// row's tuple lock waits on the record ahead of it on that row, not on the
// prune; the records here take distinct keys. The first column is the
// server's clock at the sample, on every row, and a sample with no wait has
// one row with only it; each wait row then has the waiter's pid, the time its
// wait began, and the blocking prune transaction's pid and start, which
// identify it.
const pruneLockWaitsQuery = `
SELECT n.at, w.pid, w.waitstart, w.blocker_pid, w.blocker_start
FROM (SELECT clock_timestamp() AS at) AS n
LEFT JOIN LATERAL (
  SELECT a.pid, l.waitstart, p.pid AS blocker_pid, p.xact_start AS blocker_start
  FROM pg_stat_activity a
  JOIN pg_locks l ON l.pid = a.pid AND NOT l.granted AND l.waitstart IS NOT NULL
    AND l.locktype = 'transactionid'
  JOIN LATERAL (
    SELECT s.pid, s.xact_start FROM unnest(pg_blocking_pids(a.pid)) AS bp(pid)
    JOIN pg_stat_activity s ON s.pid = bp.pid
    WHERE s.query = $2 AND s.xact_start IS NOT NULL
    LIMIT 1) AS p ON true
  WHERE a.datname = current_database() AND a.wait_event_type = 'Lock' AND a.query = $1) AS w ON true`

// pruneOpenTxQuery lists the open transactions of prune sessions: $1 is the
// prune statement.
const pruneOpenTxQuery = `
SELECT pid, xact_start FROM pg_stat_activity
WHERE datname = current_database() AND query = $1 AND xact_start IS NOT NULL`

// pruneRecordSessionsQuery counts the sessions of the current database whose
// current statement is $1, the record statement: running it, as a session
// waiting on a lock is, or idle in its transaction after it. An idle session
// shows its last statement, the COMMIT of a record's transaction, so it is
// left out.
const pruneRecordSessionsQuery = `
SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND query = $1
  AND state IN ('active', 'idle in transaction')`

// pruneSampleEvery is how often sampleLockWaits samples.
const pruneSampleEvery = 10 * time.Millisecond

// pruneTx identifies a prune transaction: its session and its start, in
// microseconds since the epoch, the precision the server keeps.
type pruneTx struct {
	pid   int
	start int64
}

// requireTrackedInFull fails t unless the server's track_activity_query_size
// keeps every byte of each of stmts: pg_stat_activity truncates a longer
// statement, and the sampler's exact match would then never find it, seeing
// no wait at all.
func requireTrackedInFull(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()

	// The setting counts the terminating NUL, so a statement keeps all of
	// its bytes only when it is shorter than the setting.
	var size int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT setting::int FROM pg_settings WHERE name = 'track_activity_query_size'`).Scan(&size))
	for _, stmt := range stmts {
		require.Less(t, len(stmt), size,
			"pg_stat_activity truncates a statement to track_activity_query_size, so the sampler would never match it: %.60q", stmt)
	}
}

// sampleLockWaits polls, every pruneSampleEvery on a connection of its own,
// the waits of conn's record sessions on locks the prune holds, until stop
// closes, and then sends what it saw. It takes its first sample before it
// returns, so it covers everything started after the call. lockTimeout is the
// records' lock timeout, the length of a wait the server gave up. It reads
// the server's own record of each wait, and the server's clock, so a stalled
// test process does not lengthen a wait it reports: the client's clock counts
// the stall, the server's lock wait counts only the prune.
func sampleLockWaits(t *testing.T, conn PostgresConn, lockTimeout time.Duration, stop <-chan struct{}) <-chan pruneLockWaits {
	t.Helper()

	recordStmt, pruneStmt := pgStatement(t, pgRecordName), pgStatement(t, pgPruneName)
	db, err := sql.Open("pgx", conn.DSN)
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.PingContext(t.Context()))
	requireTrackedInFull(t, db, recordStmt, pruneStmt)

	type wait struct {
		since   time.Time
		blocker pruneTx
	}
	var (
		got     pruneLockWaits
		lastAt  time.Time
		waiting = map[int]wait{} // by the record session's pid
	)
	fail := func(err error) {
		got.failed++
		if got.firstErr == nil {
			got.firstErr = err
		}
	}
	// ended closes w, a wait no longer seen at at.
	ended := func(w wait, at time.Time, open map[pruneTx]bool) {
		bound := at.Sub(w.since)
		if open[w.blocker] {
			got.abandoned++
			got.longest = max(got.longest, lockTimeout)
			bound = max(bound, lockTimeout)
		}
		got.bound = max(got.bound, bound)
	}
	sample := func() {
		got.samples++
		rows, err := db.QueryContext(t.Context(), pruneLockWaitsQuery, recordStmt, pruneStmt)
		if err != nil {
			fail(err)
			return
		}
		var at time.Time
		now := map[int]wait{}
		for rows.Next() {
			var (
				pid, blockerPID  sql.NullInt64
				since, blockerAt sql.NullTime
			)
			if err := rows.Scan(&at, &pid, &since, &blockerPID, &blockerAt); err != nil {
				fail(err)
				_ = rows.Close()
				return
			}
			if pid.Valid {
				now[int(pid.Int64)] = wait{
					since:   since.Time,
					blocker: pruneTx{pid: int(blockerPID.Int64), start: blockerAt.Time.UnixMicro()},
				}
			}
		}
		if err := rows.Err(); err != nil {
			fail(err)
			return
		}
		// Read after the waits: a prune transaction open now was open when
		// they were read, so a wait that had ended by then ended while it
		// still held the lock.
		open := map[pruneTx]bool{}
		txs, err := db.QueryContext(t.Context(), pruneOpenTxQuery, pruneStmt)
		if err != nil {
			fail(err)
			return
		}
		for txs.Next() {
			var (
				pid   int
				start time.Time
			)
			if err := txs.Scan(&pid, &start); err != nil {
				fail(err)
				_ = txs.Close()
				return
			}
			open[pruneTx{pid: pid, start: start.UnixMicro()}] = true
		}
		if err := txs.Err(); err != nil {
			fail(err)
			return
		}
		var recording int
		if err := db.QueryRowContext(t.Context(), pruneRecordSessionsQuery, recordStmt).Scan(&recording); err != nil {
			fail(err)
			return
		}
		if recording > 0 {
			got.recordSeen++
		}

		if len(open) > 0 {
			got.pruneSeen++
		}
		if !lastAt.IsZero() {
			got.gap = max(got.gap, at.Sub(lastAt))
		}
		lastAt = at
		for pid, w := range now {
			// Compared by microsecond, as pruneTx is: == on time.Time also
			// compares the Location, which two scans need not share.
			if prev, ok := waiting[pid]; !ok || prev.blocker != w.blocker ||
				prev.since.UnixMicro() != w.since.UnixMicro() {
				if ok {
					ended(prev, at, open)
				}
				got.waits++
			}
			got.longest = max(got.longest, at.Sub(w.since))
			waiting[pid] = w
		}
		for pid, w := range waiting {
			if _, still := now[pid]; !still {
				ended(w, at, open)
				delete(waiting, pid)
			}
		}
	}
	// last takes the final sample and closes the waits still under way at it.
	last := func() {
		sample()
		for _, w := range waiting {
			got.bound = max(got.bound, lastAt.Sub(w.since))
		}
	}

	sample()
	out := make(chan pruneLockWaits, 1)
	go func() {
		for {
			select {
			case <-stop:
				last()
				out <- got
				return
			case <-time.After(pruneSampleEvery):
				sample()
			}
		}
	}()
	return out
}

// runPGPruneUnderRecords pins that a prune over a million idle keys holds no
// record on a key it is removing for as long as the record's 250ms operation
// timeout, and keeps every key recorded while it runs: records arrive about
// every 3ms on keys the prune is removing, with the production timeout and
// breaker. Their connections are open before the prune starts, so a wait is a
// wait on the prune, not on dialling.
//
// What it asserts is the server's lock wait, not the client's: the longest
// any record's wait on a lock the prune held can have lasted, from its start
// to the first sample that no longer saw it, a wait the server gave up at the
// record's lock timeout counting as that long. It also asserts that no record
// was refused a lock (SQLSTATE 55P03), that the samples left no gap a full
// wait could hide in, and that enough records reached the database for the
// waits to be exercised at all. The client's clock counts
// every stall of a busy host, which is not the prune's doing; the server's
// lock wait counts only the prune. A prune that held its victims' locks for
// its whole run would hold records for seconds, and each would end at its
// lock timeout. Records that failed or outlasted the timeout by the client's
// clock are logged, the first one named, so a failure stays diagnosable.
func runPGPruneUnderRecords(t *testing.T, b pgBackend) {
	t.Helper()

	const timeout = unavailable.DefaultTimeout // the factories' default

	conn := migratedLimiterDB(t)
	ns := pgScopedNamespace(t, "victims")
	_, err := conn.DB.ExecContext(t.Context(), `
INSERT INTO rate_limit_buckets (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, 'k' || g, ARRAY[now() - interval '1 hour'], now() - interval '1 hour', 60000000
FROM generate_series(1, 1000000) AS g`, ns)
	require.NoError(t, err)

	p := newPrunePool(t, b, conn)
	warmPrunePool(t, p, pruneFactory(t, b, conn, pruneFactoryOptions{pool: p.pool, timeout: pgTestTimeout}))

	// The production defaults, the timeout and the breaker: the test timeout
	// would let a record wait on the prune past 250ms unnoticed.
	f := pruneFactory(t, b, conn, pruneFactoryOptions{pool: p.pool})
	l, err := f.NewLimiter(ns, 5, time.Minute)
	require.NoError(t, err)
	warmed := p.open()

	// The sampler runs from before the prune starts until every record has
	// returned, and its result is read only after it has stopped.
	stopSampling := make(chan struct{})
	lockWaits := sampleLockWaits(t, conn, timeout, stopSampling)
	done := make(chan struct{})
	var (
		removed  int
		pruneErr error
		pruneDur time.Duration
	)
	begin := time.Now()
	go func() {
		defer close(done)
		removed, pruneErr = f.Prune(t.Context())
		pruneDur = time.Since(begin)
	}()

	var (
		mu        sync.Mutex
		recorded  []string
		slow      []pruneRecord
		attempted int
		refused   int // records the server refused a lock: SQLSTATE 55P03
		worst     time.Duration
	)
	var wg sync.WaitGroup
	tick := time.NewTicker(3 * time.Millisecond) // about 300 records a second
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-done:
			wg.Wait()
			close(stopSampling)
			waits := <-lockWaits
			t.Logf("the prune removed %d keys in %s; %d records, %d succeeded, on %d warmed connections",
				removed, pruneDur, attempted, len(recorded), warmed)
			t.Logf("server: %d record waits on the prune's locks, longest seen %s, at most %s, %d given up while the prune held the lock; %d records refused a lock (55P03)",
				waits.waits, waits.longest, waits.bound, waits.abandoned, refused)
			t.Logf("sampler: %d samples, %d failed (first error %v), longest gap %s; prune transaction seen in %d, a record in flight in %d",
				waits.samples, waits.failed, waits.firstErr, waits.gap, waits.pruneSeen, waits.recordSeen)
			t.Logf("client: worst record wait %s; %d records failed or waited past %s: %s",
				worst, len(slow), timeout, pruneFailures(slow, timeout))

			require.NoError(t, pruneErr)
			assert.Positive(t, removed)
			assert.GreaterOrEqual(t, len(recorded), pruneMinRecorded,
				"only %d of %d records reached the database and succeeded, so the waits below were barely exercised",
				len(recorded), attempted)
			require.Less(t, waits.failed, waits.samples, "no lock-wait sample succeeded")
			assert.Positive(t, waits.pruneSeen, "no sample matched the prune's statement in pg_stat_activity")
			assert.Positive(t, waits.recordSeen, "no sample found a session running the record statement in pg_stat_activity")
			assert.Less(t, waits.gap, timeout, "the samples left a gap a wait as long as the timeout could fall in unseen")
			assert.Less(t, waits.bound, timeout, "a record waited on a lock the prune held for as long as its timeout")
			assert.Zero(t, refused, "the server refused records a lock (SQLSTATE 55P03): a wait reached the timeout")
			assert.Empty(t, pgMissingKeys(t, conn, ns, recorded), "the prune removed keys recorded during the run")
			return
		case <-tick.C:
			key := fmt.Sprintf("k%d", 1+(i*7919)%1000000) // spread over the victims
			wg.Go(func() {
				start := time.Now()
				err := l.RecordFailure(t.Context(), key)
				d := time.Since(start)
				mu.Lock()
				defer mu.Unlock()
				worst = max(worst, d)
				attempted++
				if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == pgLockNotAvailable {
					refused++
				}
				if err != nil || d > timeout {
					slow = append(slow, pruneRecord{key: key, start: start.Sub(begin), wait: d, err: err})
				}
				if err == nil {
					recorded = append(recorded, key)
				}
			})
		}
	}
}

// pgLockNotAvailable is the SQLSTATE of a lock wait the server gave up at
// lock_timeout. A record's error keeps the server's error in its chain: the
// adapters wrap it with %w and the unavailable decorator keeps it as its
// fault's cause. A record whose client gave up first returns its context's
// error instead, so a count of zero is a complement to the sampler's bound,
// not a proof on its own.
const pgLockNotAvailable = "55P03"

// pruneMinRecorded is how many records runPGPruneUnderRecords requires to
// have reached the database and succeeded during the prune. A refused record
// never reaches a lock, so without a floor a limiter whose breaker refused
// every record would pass with no wait to measure. Records arrive about 300 a
// second over a prune of about 3 seconds, some 900 in all; 100 still leaves
// room for the breaker to open twice, a second of refusals each, on a host
// stall that is not the prune's doing, and a success is the backend's own,
// since the default refuse mode answers an unavailable backend with an error.
const pruneMinRecorded = 100

// pgMissingKeys returns those of keys that have no bucket row in ns.
func pgMissingKeys(t *testing.T, conn PostgresConn, ns string, keys []string) []string {
	t.Helper()

	rows, err := conn.DB.QueryContext(t.Context(), `
SELECT k FROM unnest($2::text[]) AS k
EXCEPT SELECT key FROM rate_limit_buckets WHERE namespace = $1`, ns, keys)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var missing []string
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		missing = append(missing, k)
	}
	require.NoError(t, rows.Err())
	return missing
}

// isolatedEnv names the environment variable that, when non-empty, lets
// TestPGLimiter_PruneUnderRecords run. make test-isolated sets it.
const isolatedEnv = "SCRTY_TEST_ISOLATED"

// TestPGLimiter_PruneUnderRecords runs only in its own invocation (make
// test-isolated), its backends one after the other, so that the load of the
// other packages' tests is not taken for a wait on the prune.
func TestPGLimiter_PruneUnderRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a million rows")
	}
	if os.Getenv(isolatedEnv) == "" {
		t.Skipf("runs alone: set %s=1, or run make test-isolated", isolatedEnv)
	}

	for _, b := range []pgBackend{sqlstoreBackend, pgxBackend} {
		t.Run(b.name, func(t *testing.T) { runPGPruneUnderRecords(t, b) })
	}
}

// pgFailThirdDelete installs a trigger that lets two bucket deletes through
// and fails every later one with a distinctive message, which it returns.
func pgFailThirdDelete(t *testing.T, conn PostgresConn) string {
	t.Helper()

	const marker = "scrty-distinctive-7f3a"
	_, err := conn.DB.ExecContext(t.Context(), `
CREATE SEQUENCE prune_deletes;
CREATE FUNCTION fail_third_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF nextval('prune_deletes') > 2 THEN RAISE EXCEPTION '`+marker+`'; END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER fail_third_delete BEFORE DELETE ON rate_limit_buckets
  FOR EACH ROW EXECUTE FUNCTION fail_third_delete();`)
	require.NoError(t, err)
	return marker
}

// runPGFactoryPruneBatches pins the factory's batched prune over 5 idle keys
// with a batch of 2: every key is removed and counted, and a batch that fails
// after one has committed leaves that batch's keys removed and counted, with
// an error that repeats none of the server's text.
func runPGFactoryPruneBatches(t *testing.T, b pgBackend) {
	t.Helper()

	type testCase struct {
		name string
		// batch is the prune batch size; 0 means 2.
		batch int
		// before runs on the case's database after the keys go idle and
		// before the prune, when set; its result reaches assert.
		before func(t *testing.T, conn PostgresConn) string
		assert func(t *testing.T, removed, left int, err error, before string)
	}

	cases := []testCase{
		{
			name: "batch of 2 removes all 5 idle keys",
			assert: func(t *testing.T, removed, left int, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, 5, removed)
				assert.Zero(t, left, "idle keys are left")
			},
		},
		{
			name:  "batch above the largest 32-bit integer removes all 5 idle keys",
			batch: math.MaxInt32 + 1,
			assert: func(t *testing.T, removed, left int, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, 5, removed)
				assert.Zero(t, left, "idle keys are left")
			},
		},
		{
			name:   "failed batch after a committed one returns its count and no server text",
			before: pgFailThirdDelete,
			assert: func(t *testing.T, removed, left int, err error, marker string) {
				assert.Equal(t, 2, removed, "the committed batch's count was not returned")
				require.Error(t, err)
				assert.NotContains(t, err.Error(), marker, "the error repeats the server's text")
				assert.Equal(t, 3, left, "the committed batch was not kept, or the failed batch was not rolled back")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := migratedLimiterDB(t)
			clk := clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
			f := pruneFactory(t, b, conn, pruneFactoryOptions{clock: clk, batch: cmp.Or(tc.batch, 2)})
			ns := pgScopedNamespace(t, "batches")
			l, err := f.NewLimiter(ns, 1, time.Minute)
			require.NoError(t, err)
			for i := range 5 {
				require.NoError(t, l.RecordFailure(t.Context(), fmt.Sprintf("idle-%d", i)))
			}
			clk.Advance(time.Minute)
			var before string
			if tc.before != nil {
				before = tc.before(t, conn)
			}

			removed, err := f.Prune(t.Context())
			var left int
			require.NoError(t, conn.DB.QueryRowContext(t.Context(),
				`SELECT count(*) FROM rate_limit_buckets WHERE namespace = $1`, ns).Scan(&left))
			tc.assert(t, removed, left, err, before)
		})
	}
}

func TestPGLimiter_FactoryPruneBatches(t *testing.T) {
	t.Parallel()

	for _, b := range []pgBackend{sqlstoreBackend, pgxBackend} {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			runPGFactoryPruneBatches(t, b)
		})
	}
}
