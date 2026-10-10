package test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// pgFaultOptions are the settings a fault, clock, transaction or prune test
// builds a PostgreSQL limiter with. A zero field keeps the integration tests'
// setting: pgTestTimeout, refuse mode, the default probe interval and the
// database's clock.
type pgFaultOptions struct {
	clock   clock.Clock // nil: the database's clock
	timeout time.Duration
	mode    ratelimit.UnavailableMode
	probe   time.Duration
	// dialer, when set, watches and gates every connection the limiter's
	// handle dials.
	dialer *pgDialer
}

// pgDialer watches the dials of a test's handle: it counts them, so a test
// sees whether a call reached the network at all, and refuses them once
// refuse is set, so a driver cannot open the connection a cancel request
// needs.
type pgDialer struct {
	count  atomic.Int64
	refuse atomic.Bool
}

func (o pgFaultOptions) operationTimeout() time.Duration {
	if o.timeout == 0 {
		return pgTestTimeout
	}
	return o.timeout
}

func (o pgFaultOptions) sqlstoreOptions() []sqlstore.LimiterOption {
	opts := []sqlstore.LimiterOption{
		sqlstore.WithLimiterOperationTimeout(o.operationTimeout()),
		sqlstore.WithLimiterLogger(slog.New(slog.DiscardHandler)),
		sqlstore.WithLimiterOnUnavailable(o.mode),
	}
	if o.probe != 0 {
		opts = append(opts, sqlstore.WithLimiterProbeInterval(o.probe))
	}
	if o.clock != nil {
		opts = append(opts, sqlstore.WithLimiterClock(o.clock))
	}
	return opts
}

func (o pgFaultOptions) pgxOptions() []pgxstore.LimiterOption {
	opts := []pgxstore.LimiterOption{
		pgxstore.WithLimiterOperationTimeout(o.operationTimeout()),
		pgxstore.WithLimiterLogger(slog.New(slog.DiscardHandler)),
		pgxstore.WithLimiterOnUnavailable(o.mode),
	}
	if o.probe != 0 {
		opts = append(opts, pgxstore.WithLimiterProbeInterval(o.probe))
	}
	if o.clock != nil {
		opts = append(opts, pgxstore.WithLimiterClock(o.clock))
	}
	return opts
}

// pgFaultDialFunc dials conn's server, through dialer when it is set. On an
// own server it asks the container for the host port on every
// dial, because Docker maps a restarted container to a new one.
func pgFaultDialFunc(conn PostgresConn, dialer *pgDialer) pgconn.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if dialer != nil {
			dialer.count.Add(1)
			if dialer.refuse.Load() {
				return nil, errors.New("the test refuses this dial")
			}
		}
		if conn.ctr != nil {
			endpoint, err := conn.ctr.PortEndpoint(ctx, postgresPort, "")
			if err != nil {
				return nil, err
			}
			addr = endpoint
		}
		d := net.Dialer{Timeout: postgresDialTimeout}
		return d.DialContext(ctx, network, addr)
	}
}

// pgFaultDB opens a database/sql handle of its own on conn's database, dialing
// through pgFaultDialFunc, closed at cleanup.
func pgFaultDB(t *testing.T, conn PostgresConn, dialer *pgDialer) *sql.DB {
	t.Helper()

	cfg, err := pgx.ParseConfig(conn.DSN)
	require.NoError(t, err)
	cfg.DialFunc = pgFaultDialFunc(conn, dialer)
	db := sql.OpenDB(stdlib.GetConnector(*cfg))
	db.SetMaxOpenConns(16)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// pgFaultPool opens a pgx pool of its own on conn's database, dialing through
// pgFaultDialFunc, closed at cleanup.
func pgFaultPool(t *testing.T, conn PostgresConn, dialer *pgDialer) *pgxpool.Pool {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(conn.DSN)
	require.NoError(t, err)
	cfg.ConnConfig.DialFunc = pgFaultDialFunc(conn, dialer)
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// pgFaultBackend is one PostgreSQL limiter backend as the fault, clock,
// transaction and prune tests build it: every limiter and factory over a
// handle of its own on conn's database.
type pgFaultBackend struct {
	name    string
	limiter func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter
	factory func(t *testing.T, conn PostgresConn, o pgFaultOptions) pgFactory
	// ambient begins a caller's transaction and returns what the
	// ambient-transaction test drives through it (pg_ratelimit_ambient_test.go).
	ambient func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, resolved bool) pgAmbient
}

// sqlstoreFaultLimiter builds the sqlstore limiter over a handle of its own.
func sqlstoreFaultLimiter(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
	t.Helper()
	l, err := sqlstore.NewLimiter(pgFaultDB(t, conn, o.dialer), ns, limit, window, o.sqlstoreOptions()...)
	require.NoError(t, err)
	return l
}

// pgxFaultLimiter builds the pgx limiter over a pool of its own.
func pgxFaultLimiter(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
	t.Helper()
	l, err := pgxstore.NewLimiter(pgFaultPool(t, conn, o.dialer), ns, limit, window, o.pgxOptions()...)
	require.NoError(t, err)
	return l
}

var sqlstoreFaultBackend = pgFaultBackend{
	name:    "sqlstore",
	limiter: sqlstoreFaultLimiter,
	factory: func(t *testing.T, conn PostgresConn, o pgFaultOptions) pgFactory {
		t.Helper()
		f, err := sqlstore.NewLimiterFactory(pgFaultDB(t, conn, o.dialer), o.sqlstoreOptions()...)
		require.NoError(t, err)
		return f
	},
	ambient: sqlstoreAmbient,
}

var pgxFaultBackend = pgFaultBackend{
	name:    "pgx",
	limiter: pgxFaultLimiter,
	factory: func(t *testing.T, conn PostgresConn, o pgFaultOptions) pgFactory {
		t.Helper()
		f, err := pgxstore.NewLimiterFactory(pgFaultPool(t, conn, o.dialer), o.pgxOptions()...)
		require.NoError(t, err)
		return f
	},
	ambient: pgxAmbient,
}

// pgFaultBackends are the backends every test of this kind loops over.
var pgFaultBackends = []pgFaultBackend{sqlstoreFaultBackend, pgxFaultBackend}

// runPGFaultBackends runs run once per backend, each as a parallel subtest
// named for it.
func runPGFaultBackends(t *testing.T, run func(t *testing.T, b pgFaultBackend)) {
	t.Helper()

	for _, b := range pgFaultBackends {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			run(t, b)
		})
	}
}

// pgRecordStatement is the limiter's record statement, restated: the test
// module cannot import the core module's internal package that holds it. The
// broken variants below run it, or a copy carrying one defect, in place of the
// limiter's own record.
const pgRecordStatement = `WITH t AS (SELECT coalesce($5::timestamptz, clock_timestamp()) AS now)
INSERT INTO rate_limit_buckets AS b (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, $2, ARRAY[t.now], t.now, $4::bigint
FROM t CROSS JOIN (SELECT set_config('lock_timeout', $6::text, true)) AS lt
ON CONFLICT (namespace, key) DO UPDATE SET
  stamps = (SELECT array_agg(n.s ORDER BY n.s) FROM
            (SELECT s FROM unnest(b.stamps || EXCLUDED.stamps) AS u(s) ORDER BY s DESC LIMIT $3::int) AS n),
  newest_at = GREATEST(b.newest_at, EXCLUDED.newest_at),
  longest_window_us = GREATEST(b.longest_window_us, EXCLUDED.longest_window_us)`

// pgExecer runs one statement, on a pool, a handle or a transaction.
type pgExecer func(ctx context.Context, query string, args ...any) error

func dbExecer(db interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}) pgExecer {
	return func(ctx context.Context, query string, args ...any) error {
		_, err := db.ExecContext(ctx, query, args...)
		return err
	}
}

// pgStatementLimiter is a PostgreSQL limiter whose record runs a statement of
// the test's own through exec, carrying one defect, with no unavailable
// handling around it; its check is the real limiter's. Like the real record it
// ignores the caller's cancellation and is bounded by its operation timeout.
type pgStatementLimiter struct {
	ratelimit.Limiter // the real limiter, for Exceeded

	exec        pgExecer
	record      string
	ns          string
	limit       int
	windowUS    int64
	clk         clock.Clock // nil: the database's clock
	timeout     time.Duration
	lockTimeout string
}

func (l *pgStatementLimiter) RecordFailure(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.timeout)
	defer cancel()

	var now any
	if l.clk != nil {
		now = l.clk.Now().UTC().Truncate(time.Microsecond)
	}
	return l.exec(ctx, l.record, l.ns, pgStoredKey(key), l.limit, l.windowUS, now, l.lockTimeout)
}

// newPGStatementLimiter builds the sqlstore limiter over conn with o, its
// record replaced by record run through exec (its own handle when nil), with
// lock_timeout set to lockTimeout.
func newPGStatementLimiter(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration,
	o pgFaultOptions, exec pgExecer, record, lockTimeout string,
) *pgStatementLimiter {
	t.Helper()

	if exec == nil {
		exec = dbExecer(pgFaultDB(t, conn, o.dialer))
	}
	return &pgStatementLimiter{
		Limiter:     sqlstoreFaultLimiter(t, conn, ns, limit, window, o),
		exec:        exec,
		record:      record,
		ns:          ns,
		limit:       limit,
		windowUS:    window.Microseconds(),
		clk:         o.clock,
		timeout:     o.operationTimeout(),
		lockTimeout: lockTimeout,
	}
}

// pgFaultBrokenVar names the environment variable that selects the broken
// variant a child test of this file's guards runs.
const pgFaultBrokenVar = "PG_RATELIMIT_FAULT_BROKEN"

// pgFaultBrokenBackend is the subtest name every broken variant runs under,
// which the guards read the failed cases beneath.
const pgFaultBrokenBackend = "broken"

// pgFaultVariant is a backend carrying one defect, and the case of the run
// that must catch it.
type pgFaultVariant struct {
	name      string
	backend   pgFaultBackend
	failsCase string
	failsWith string
}

// pgFaultVariants turns variants into the broken variants of run: each runs
// run against its backend, under the subtest pgFaultBrokenBackend.
func pgFaultVariants(run func(t *testing.T, b pgFaultBackend), variants ...pgFaultVariant) []storefix.BrokenVariant {
	out := make([]storefix.BrokenVariant, 0, len(variants))
	for _, v := range variants {
		out = append(out, storefix.BrokenVariant{
			Name: v.name,
			Run: func(t *testing.T) {
				t.Run(pgFaultBrokenBackend, func(t *testing.T) { run(t, v.backend) })
			},
			FailsCase: v.failsCase,
			FailsWith: v.failsWith,
		})
	}
	return out
}

// catchPGFaultVariants checks that child, run once per variant in a process
// of its own, fails each at the case guarding its defect.
func catchPGFaultVariants(t *testing.T, child string, variants []storefix.BrokenVariant) {
	t.Helper()

	// The children each want PostgreSQL: start the one server they share.
	EnsureTestPostgresServer(t)
	storefix.CatchBrokenVariants(t, pgFaultBrokenVar, child, pgFaultBrokenBackend, variants)
}

// brokenLimiterBackend is sqlstoreFaultBackend, named as a broken variant,
// with its limiter replaced by limiter.
func brokenLimiterBackend(
	limiter func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter,
) pgFaultBackend {
	b := sqlstoreFaultBackend
	b.name = pgFaultBrokenBackend
	b.limiter = limiter
	return b
}

// pgSQLState is the SQLSTATE of the PostgreSQL error in err's chain, or "".
func pgSQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// heldRowTimeout is the operation timeout of the held-row test, and
// heldRowBound how long its record may take at most.
const (
	heldRowTimeout = 250 * time.Millisecond
	heldRowBound   = 750 * time.Millisecond
)

// runPGHeldRow pins that a record gives up on a row another session holds
// within its operation timeout, and that the server stops waiting for the row
// too, by the record's own lock timeout.
//
// The record's lock timeout equals its operation timeout, so the client's
// deadline ends the call first, a few milliseconds ahead of the server: the
// error is the deadline's, and SQLSTATE 55P03 never reaches the caller. What
// the lock timeout adds is on the server. A driver's cancel request needs a
// new connection, so once the record is under way the test refuses every
// further dial of the limiter's handle: only the lock timeout can then end
// the server's wait, and without it the session would wait on the row for as
// long as the holder keeps it.
func runPGHeldRow(t *testing.T, b pgFaultBackend) {
	t.Helper()

	t.Run("record gives up on a held row within its timeout", func(t *testing.T) {
		conn := migratedLimiterDB(t)
		ns := pgScopedNamespace(t, "held")
		dialer := &pgDialer{}
		l := b.limiter(t, conn, ns, 3, time.Minute, pgFaultOptions{timeout: heldRowTimeout, dialer: dialer})
		// The first record creates the row and leaves a pooled connection,
		// so the timed record waits on the row rather than on a dial.
		require.NoError(t, l.RecordFailure(t.Context(), "k"))

		holder, err := conn.DB.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = holder.Rollback() })
		var one int
		require.NoError(t, holder.QueryRowContext(t.Context(),
			`SELECT 1 FROM rate_limit_buckets WHERE namespace = $1 AND key = $2 FOR UPDATE`, ns, "k").Scan(&one))

		dialer.refuse.Store(true)
		start := time.Now()
		err = l.RecordFailure(t.Context(), "k")
		elapsed := time.Since(start)
		t.Logf("record against the held row returned after %s: %v (SQLSTATE %q)", elapsed, err, pgSQLState(err))

		require.Error(t, err, "the record succeeded through a held row")
		assert.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
		assert.Less(t, elapsed, heldRowBound, "the record waited past its timeout")

		// The condition runs on a goroutine of its own, so it reports a
		// failed query as "not yet" rather than failing the test there.
		assert.Eventually(t, func() bool {
			var waiting int
			err := conn.DB.QueryRowContext(t.Context(),
				`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`).Scan(&waiting)
			return err == nil && waiting == 0
		}, time.Second, 20*time.Millisecond, "the server still has a session waiting on the held row")
	})
}

func TestPGLimiter_HeldRow(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGHeldRow)
}

// pgHeldRowBroken is a limiter whose record turns the lock timeout off: it
// ends only by the client's own deadline.
var pgHeldRowBroken = pgFaultVariants(runPGHeldRow, pgFaultVariant{
	name: "lock-timeout-off",
	backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
		t.Helper()
		return newPGStatementLimiter(t, conn, ns, limit, window, o, nil, pgRecordStatement, "0")
	}),
	failsCase: "record gives up on a held row within its timeout",
	failsWith: "the server still has a session waiting on the held row",
})

// TestPGLimiter_HeldRowBroken is the child half of
// TestPGLimiter_HeldRowCatchesBrokenVariants. Without a variant named it
// skips.
func TestPGLimiter_HeldRowBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_HeldRowCatchesBrokenVariants", pgHeldRowBroken)
}

func TestPGLimiter_HeldRowCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_HeldRowBroken", pgHeldRowBroken)
}

// Settings of the outage tests. The operation timeout is long, so that a call
// which waited it out and one the breaker answered at once cannot be confused
// under -race; the probe interval is short, so that a case can wait it out.
const (
	pgOutageTimeout = 2 * time.Second
	pgOutageProbe   = 200 * time.Millisecond
	pgOutageLimit   = 3
	pgOutageSource  = "203.0.113.7"
)

// pgOutage is what an outage case drives: an own server, the dialer every
// limiter it builds dials through, and the builder.
type pgOutage struct {
	conn   PostgresConn
	dialer *pgDialer
	// build returns a limiter over the server for namespace "api-key" with
	// the outage settings and mode.
	build func(mode ratelimit.UnavailableMode) ratelimit.Limiter
}

// runPGUnavailable pins what the limiter does while its server is stopped, in
// each unavailable mode, and that the breaker answers without calling the
// server until the probe interval has passed. Each case starts a server of its
// own.
func runPGUnavailable(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name   string
		assert func(t *testing.T, e pgOutage)
	}

	cases := []testCase{
		{
			name: "refuse while stopped: exceeded, as the backend unavailable",
			assert: func(t *testing.T, e pgOutage) {
				l := e.build(ratelimit.UnavailableRefuse)
				e.conn.Stop(t)

				exceeded, err := l.Exceeded(t.Context(), pgOutageSource)
				assert.True(t, exceeded, "refuse mode admitted a source while the server was stopped")
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
			},
		},
		{
			name: "fall back while stopped: local failures exceed the source on this instance",
			assert: func(t *testing.T, e pgOutage) {
				l := e.build(ratelimit.UnavailableFallBackToLocal)
				e.conn.Stop(t)

				for range pgOutageLimit {
					require.NoError(t, l.RecordFailure(t.Context(), pgOutageSource), "a failure was not counted locally")
				}
				exceeded, err := l.Exceeded(t.Context(), pgOutageSource)
				require.NoError(t, err)
				assert.True(t, exceeded, "three local failures do not exceed a limit of three")

				exceeded, err = l.Exceeded(t.Context(), "198.51.100.1")
				require.NoError(t, err)
				assert.False(t, exceeded, "a source with no local failure was refused")
			},
		},
		{
			name: "allow while stopped: not exceeded, and no error",
			assert: func(t *testing.T, e pgOutage) {
				l := e.build(ratelimit.UnavailableAllow)
				e.conn.Stop(t)

				for range pgOutageLimit + 2 {
					require.NoError(t, l.RecordFailure(t.Context(), pgOutageSource))
				}
				exceeded, err := l.Exceeded(t.Context(), pgOutageSource)
				require.NoError(t, err)
				assert.False(t, exceeded, "allow mode refused during the outage")
			},
		},
		{
			name: "breaker refuses without calling the server, and a probe reaches it once restarted",
			assert: func(t *testing.T, e pgOutage) {
				l := e.build(ratelimit.UnavailableRefuse)
				e.conn.Stop(t)

				start := time.Now()
				exceeded, err := l.Exceeded(t.Context(), pgOutageSource)
				t.Logf("first check against the stopped server returned after %s", time.Since(start))
				assert.True(t, exceeded)
				assert.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)

				dials := e.dialer.count.Load()
				var slowest time.Duration
				for i := range 10 {
					start := time.Now()
					exceeded, err := l.Exceeded(t.Context(), pgOutageSource)
					elapsed := time.Since(start)
					slowest = max(slowest, elapsed)
					assert.Less(t, elapsed, 50*time.Millisecond, "check %d waited for the server", i)
					assert.True(t, exceeded)
					assert.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				}
				t.Logf("slowest of the ten checks inside the probe interval: %s", slowest)
				assert.Equal(t, dials, e.dialer.count.Load(), "a check inside the probe interval called the server")

				e.conn.Start(t)
				time.Sleep(pgOutageProbe + 100*time.Millisecond)
				// A source with no failure: refuse mode would answer true,
				// so false with no error is the server's answer.
				exceeded, err = l.Exceeded(t.Context(), "198.51.100.1")
				require.NoError(t, err, "the check after the probe interval did not reach the restarted server")
				assert.False(t, exceeded)
				assert.Greater(t, e.dialer.count.Load(), dials, "the check after the probe interval did not dial the server")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := migratedLimiterDB(t, WithTestPostgresOwnServer())
			dialer := &pgDialer{}
			tc.assert(t, pgOutage{
				conn:   conn,
				dialer: dialer,
				build: func(mode ratelimit.UnavailableMode) ratelimit.Limiter {
					l := b.limiter(t, conn, "api-key", pgOutageLimit, time.Minute, pgFaultOptions{
						timeout: pgOutageTimeout,
						mode:    mode,
						probe:   pgOutageProbe,
						dialer:  dialer,
					})
					// Reached once while the server runs, so a case starts
					// from a closed breaker and a pooled connection.
					exceeded, err := l.Exceeded(t.Context(), pgOutageSource)
					require.NoError(t, err)
					require.False(t, exceeded)
					return l
				},
			})
		})
	}
}

func TestPGLimiter_Unavailable(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGUnavailable)
}

// pgCheckStatement is the limiter's check statement, restated as
// pgRecordStatement is.
const pgCheckStatement = `WITH t AS (SELECT coalesce($4::timestamptz, clock_timestamp()) AS now)
SELECT count(*) FROM rate_limit_buckets b CROSS JOIN t
CROSS JOIN LATERAL unnest(b.stamps) AS u(stamp)
WHERE b.namespace = $1 AND b.key = $2
  AND u.stamp > t.now - $3::bigint * interval '1 microsecond'`

// pgRawLimiter runs the limiter's statements with the operation timeout and
// nothing around them: no breaker, no unavailable mode, no hold. It is the
// backend the real limiters wrap, restated.
type pgRawLimiter struct {
	db          *sql.DB
	ns          string
	limit       int
	windowUS    int64
	timeout     time.Duration
	lockTimeout string
}

func (l *pgRawLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	var n int
	if err := l.db.QueryRowContext(ctx, pgCheckStatement, l.ns, pgStoredKey(key), l.windowUS, nil).Scan(&n); err != nil {
		return true, err
	}
	return n >= l.limit, nil
}

func (l *pgRawLimiter) RecordFailure(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.timeout)
	defer cancel()

	_, err := l.db.ExecContext(ctx, pgRecordStatement, l.ns, pgStoredKey(key), l.limit, l.windowUS, nil, l.lockTimeout)
	return err
}

var pgUnavailableBroken = pgFaultVariants(runPGUnavailable, pgFaultVariant{
	name: "no-breaker",
	backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
		t.Helper()
		return &pgRawLimiter{
			db:          pgFaultDB(t, conn, o.dialer),
			ns:          ns,
			limit:       limit,
			windowUS:    window.Microseconds(),
			timeout:     o.operationTimeout(),
			lockTimeout: "5000ms",
		}
	}),
	failsCase: "breaker refuses without calling the server, and a probe reaches it once restarted",
	failsWith: "a check inside the probe interval called the server",
})

// TestPGLimiter_UnavailableBroken is the child half of
// TestPGLimiter_UnavailableCatchesBrokenVariants. Without a variant named it
// skips.
func TestPGLimiter_UnavailableBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_UnavailableCatchesBrokenVariants", pgUnavailableBroken)
}

func TestPGLimiter_UnavailableCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_UnavailableBroken", pgUnavailableBroken)
}
