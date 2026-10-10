package test

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
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
// clock and prune batches of 1,000 keys.
type pruneFactoryOptions struct {
	// clock, when set, is the factory's clock, and the test timeout replaces
	// the default operation timeout, as the other builders give it.
	clock clock.Clock
	// batch, when set, is the prune batch size.
	batch int
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
		f, err := pgxstore.NewLimiterFactory(pgxTestPool(t, conn.DSN), opts...)
		require.NoError(t, err)
		return f
	}
	t.Fatalf("no prune factory for backend %q", b.name)
	return nil
}

// runPGPruneUnderRecords pins that a prune over a million idle keys holds no
// record past its 250ms operation timeout, and keeps every key recorded while
// it runs: records arrive about every 3ms on keys the prune is removing.
func runPGPruneUnderRecords(t *testing.T, b pgBackend) {
	t.Helper()

	conn := migratedLimiterDB(t)
	ns := pgScopedNamespace(t, "victims")
	_, err := conn.DB.ExecContext(t.Context(), `
INSERT INTO rate_limit_buckets (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, 'k' || g, ARRAY[now() - interval '1 hour'], now() - interval '1 hour', 60000000
FROM generate_series(1, 1000000) AS g`, ns)
	require.NoError(t, err)

	// The production defaults: the test timeout would hide a record waiting
	// on the prune.
	f := pruneFactory(t, b, conn, pruneFactoryOptions{})
	l, err := f.NewLimiter(ns, 5, time.Minute)
	require.NoError(t, err)

	done := make(chan struct{})
	var (
		removed  int
		pruneErr error
		pruneDur time.Duration
	)
	go func() {
		defer close(done)
		start := time.Now()
		removed, pruneErr = f.Prune(t.Context())
		pruneDur = time.Since(start)
	}()

	var (
		mu       sync.Mutex
		recorded []string
		slow     []time.Duration
		worst    time.Duration
	)
	var wg sync.WaitGroup
	tick := time.NewTicker(3 * time.Millisecond) // about 300 records a second
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-done:
			wg.Wait()
			t.Logf("the prune removed %d keys in %s; %d records, worst wait %s, %d over 250ms",
				removed, pruneDur, len(recorded)+len(slow), worst, len(slow))
			require.NoError(t, pruneErr)
			assert.Positive(t, removed)
			assert.Zero(t, len(slow), "records waited on the prune past their timeout")
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
				if err != nil || d > 250*time.Millisecond {
					slow = append(slow, d)
					return
				}
				recorded = append(recorded, key)
			})
		}
	}
}

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

// TestPGLimiter_PruneUnderRecords runs alone, its backends one after the
// other, so that no other test's load is taken for a wait on the prune.
func TestPGLimiter_PruneUnderRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a million rows")
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
