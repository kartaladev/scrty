package test

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/store/sqlstore"
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
	// tracer, when set, sees every statement the limiter's handle runs, with
	// its arguments.
	tracer pgx.QueryTracer
	// handles, when set, collects a ping of every handle built, so a test can
	// warm the handles before a call whose timeout must not cover a dial.
	handles *pgHandles
}

// pgHandles collects the pings of the handles a test's limiter was built
// over.
type pgHandles struct {
	mu    sync.Mutex
	pings []func(ctx context.Context) error
}

func (h *pgHandles) add(ping func(ctx context.Context) error) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pings = append(h.pings, ping)
}

// warm pings every collected handle, leaving a pooled connection on each, so
// a later call starts without dialing. It is a readiness check: on a loaded
// host a dial, and on an own server the container lookup inside it, can
// outlast a limiter's short timeout, so each ping has pgTestTimeout and is
// retried until postgresReadyTimeout has passed. The dial is then spent here,
// not on the call a test times or on the limiter's breaker.
func (h *pgHandles) warm(t *testing.T) {
	t.Helper()

	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotEmpty(t, h.pings, "no handle was built to warm")
	for _, ping := range h.pings {
		require.NoError(t, pingUntilReady(t, ping), "warming a limiter's handle")
	}
}

// pingUntilReady runs ping, each time with pgTestTimeout, until it succeeds,
// postgresReadyTimeout has passed or the test has ended, and returns its last
// error.
func pingUntilReady(t *testing.T, ping func(ctx context.Context) error) error {
	t.Helper()

	deadline := time.Now().Add(postgresReadyTimeout)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), pgTestTimeout)
		err := ping(ctx)
		cancel()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-t.Context().Done():
			return err
		case <-time.After(50 * time.Millisecond):
		}
	}
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
// through pgFaultDialFunc with o's dialer and tracing with o's tracer, closed
// at cleanup.
func pgFaultDB(t *testing.T, conn PostgresConn, o pgFaultOptions) *sql.DB {
	t.Helper()

	cfg, err := pgx.ParseConfig(conn.DSN)
	require.NoError(t, err)
	cfg.DialFunc = pgFaultDialFunc(conn, o.dialer)
	if o.tracer != nil {
		cfg.Tracer = o.tracer
	}
	db := sql.OpenDB(stdlib.GetConnector(*cfg))
	db.SetMaxOpenConns(16)
	t.Cleanup(func() { _ = db.Close() })
	o.handles.add(db.PingContext)
	return db
}

// pgFaultPool opens a pgx pool of its own on conn's database, as pgFaultDB
// opens a handle, closed at cleanup.
func pgFaultPool(t *testing.T, conn PostgresConn, o pgFaultOptions) *pgxpool.Pool {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(conn.DSN)
	require.NoError(t, err)
	cfg.ConnConfig.DialFunc = pgFaultDialFunc(conn, o.dialer)
	if o.tracer != nil {
		cfg.ConnConfig.Tracer = o.tracer
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	o.handles.add(pool.Ping)
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
	l, err := sqlstore.NewLimiter(pgFaultDB(t, conn, o), ns, limit, window, o.sqlstoreOptions()...)
	require.NoError(t, err)
	return l
}

// pgxFaultLimiter builds the pgx limiter over a pool of its own.
func pgxFaultLimiter(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
	t.Helper()
	l, err := pgxstore.NewLimiter(pgFaultPool(t, conn, o), ns, limit, window, o.pgxOptions()...)
	require.NoError(t, err)
	return l
}

var sqlstoreFaultBackend = pgFaultBackend{
	name:    "sqlstore",
	limiter: sqlstoreFaultLimiter,
	factory: func(t *testing.T, conn PostgresConn, o pgFaultOptions) pgFactory {
		t.Helper()
		f, err := sqlstore.NewLimiterFactory(pgFaultDB(t, conn, o), o.sqlstoreOptions()...)
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
		f, err := pgxstore.NewLimiterFactory(pgFaultPool(t, conn, o), o.pgxOptions()...)
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

// pgSchemaSource is the core module's file declaring the limiter's
// statements. The test module cannot import that internal package, so it
// reads the statements from the source instead of restating them: a broken
// variant runs the real statement, or the real statement with one edit, and
// cannot drift from what the limiters run.
const pgSchemaSource = "../internal/pgschema/ratelimit.go"

// The names of the statements in pgSchemaSource the tests run.
const (
	pgRecordName = "LimiterRecord"
	pgCheckName  = "LimiterCheck"
	pgPruneName  = "LimiterPrune"
	pgChargeName = "LimiterCharge"
	pgRefundName = "LimiterRefund"
)

// pgSchemaStatements parses pgSchemaSource once and returns its string
// constants by name.
var pgSchemaStatements = sync.OnceValues(func() (map[string]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), pgSchemaSource, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, err
				}
				out[name.Name] = v
			}
		}
	}
	return out, nil
})

// pgStatement is the statement named name, as pgSchemaSource declares it.
func pgStatement(t *testing.T, name string) string {
	t.Helper()

	statements, err := pgSchemaStatements()
	require.NoError(t, err, "parsing %s", pgSchemaSource)
	stmt, ok := statements[name]
	require.True(t, ok, "%s declares no string constant %s", pgSchemaSource, name)
	return stmt
}

// pgStatementEdit is the one defect a broken variant carries in a real
// statement: old, which occurs exactly once in it, replaced by new.
type pgStatementEdit struct {
	name     string // the variant's name
	stmt     string // the statement's constant name in pgSchemaSource
	old, new string
}

// apply returns the edited statement, failing the test when old does not
// occur exactly once, so an edit the real statement has outgrown fails
// rather than leaving the statement unchanged.
func (e pgStatementEdit) apply(t *testing.T) string {
	t.Helper()

	stmt := pgStatement(t, e.stmt)
	require.Equal(t, 1, strings.Count(stmt, e.old),
		"variant %s: %s no longer contains, exactly once, the text it edits: %q", e.name, e.stmt, e.old)
	edited := strings.Replace(stmt, e.old, e.new, 1)
	require.NotEqual(t, stmt, edited, "variant %s: the edit left %s unchanged", e.name, e.stmt)
	return edited
}

// pgStatementEdits are every edit a broken variant of these tests makes; the
// drift guard below applies each.
var pgStatementEdits = []pgStatementEdit{pgRecordReadingTimeTwice, pgPruneByCheckingWindow, pgPruneWithoutRowLock, pgPruneWithoutSkipLocked}

// TestPGLimiter_StatementEditsApply is the drift guard of the broken
// variants: each edit still finds, exactly once, the text it replaces in the
// real statement, and changes it. A statement reworded in pgschema fails here
// by name, rather than leaving a variant that carries no defect.
func TestPGLimiter_StatementEditsApply(t *testing.T) {
	t.Parallel()

	for _, e := range pgStatementEdits {
		t.Run(e.name, func(t *testing.T) {
			t.Parallel()
			e.apply(t)
		})
	}
	for _, name := range []string{pgRecordName, pgCheckName, pgPruneName, pgChargeName, pgRefundName} {
		assert.NotEmpty(t, pgStatement(t, name))
	}
}

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
		exec = dbExecer(pgFaultDB(t, conn, o))
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
// heldRowBound how long its call may take at most.
//
// The timeout is two seconds, not the 250ms default, because the test
// proves nothing unless the statement reaches the server and waits on the
// row, which the test requires it to be seen doing. Before it does, the
// call has round trips to make (BEGIN, and the prepare on a connection's
// first use), and on a loaded server those can outlast 250ms: the client
// then gives up before the statement is sent, and no session ever waits.
// The bound stays three times the timeout, so a call that waits past its
// timeout still fails it.
const (
	heldRowTimeout = 2 * time.Second
	heldRowBound   = 3 * heldRowTimeout
)

// heldRowDropWait is how long the held-row test waits to see the session
// wait on the row, and then for the server to drop it. A loaded server can
// start the wait late and run the lock timeout late. Without a lock timeout
// the session waits as long as the holder holds the row, until the test
// ends, so no wait this test could choose lets that variant pass.
const heldRowDropWait = 10 * time.Second

// logPGActivity logs the sessions of the test database, as the server
// reports them, so a failure shows what the server was still doing.
func logPGActivity(t *testing.T, db *sql.DB) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), pgTestTimeout)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT pid, state, wait_event_type, wait_event, query
FROM pg_stat_activity WHERE datname = current_database()`)
	if err != nil {
		t.Logf("reading pg_stat_activity: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var pid int
		var state, waitType, waitEvent, query sql.NullString
		if err := rows.Scan(&pid, &state, &waitType, &waitEvent, &query); err != nil {
			t.Logf("scanning pg_stat_activity: %v", err)
			return
		}
		t.Logf("pg_stat_activity: pid=%d state=%q wait_event_type=%q wait_event=%q query=%q",
			pid, state.String, waitType.String, waitEvent.String, query.String)
	}
	if err := rows.Err(); err != nil {
		t.Logf("reading pg_stat_activity: %v", err)
	}
}

// pgRowQuerier runs a one-row query, on a handle or one connection of it.
type pgRowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// pgRowWaiter is the session of q's database blocked by the session holder,
// or 0 when none is. It reads the lock manager (pg_blocking_pids), not the
// wait event a session reports, which a blocked session can briefly show as
// something else.
func pgRowWaiter(ctx context.Context, q pgRowQuerier, holder int) (int, error) {
	var pid int
	err := q.QueryRowContext(ctx, `SELECT coalesce(min(pid), 0) FROM pg_stat_activity
WHERE datname = current_database() AND $1::int = ANY(pg_blocking_pids(pid))`, holder).Scan(&pid)
	return pid, err
}

// pgStillBlocked reports whether the session pid is still blocked by the
// session holder.
func pgStillBlocked(ctx context.Context, q pgRowQuerier, pid, holder int) (bool, error) {
	var blocked bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
WHERE pid = $1 AND $2::int = ANY(pg_blocking_pids(pid)))`, pid, holder).Scan(&blocked)
	return blocked, err
}

// heldRowWaiter is what watchHeldRowWait found: the first session seen
// blocked by the holder, and when it was seen.
type heldRowWaiter struct {
	mu   sync.Mutex
	pid  int
	seen time.Time
}

func (w *heldRowWaiter) found() (pid int, seen time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pid, w.seen
}

// watchHeldRowWait polls q every few milliseconds, until a session blocked
// by the session holder is found, stop is called or the test ends, and
// records the first such session in w. q is a connection of the sampler's
// own, opened before the call it watches, so no sample waits on a dial or
// on a pool. stop returns once the sampler has.
func watchHeldRowWait(t *testing.T, q pgRowQuerier, holder int, w *heldRowWaiter) (stop func()) {
	t.Helper()

	quit, ended := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ended)
		for {
			if pid, err := pgRowWaiter(t.Context(), q, holder); err == nil && pid != 0 {
				w.mu.Lock()
				w.pid, w.seen = pid, time.Now()
				w.mu.Unlock()
				return
			}
			select {
			case <-quit:
				return
			case <-t.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	var once sync.Once
	stop = func() { once.Do(func() { close(quit); <-ended }) }
	t.Cleanup(stop)
	return stop
}

// runPGHeldRow pins that a record, a charge and a refund each give up on a
// row another session holds within the operation timeout, and that the server
// stops waiting for the row too, by the statement's own lock timeout.
//
// The lock timeout equals the operation timeout, so the client's deadline ends
// the call first, a few milliseconds ahead of the server: the error is the
// deadline's, and SQLSTATE 55P03 never reaches the caller. What the lock
// timeout adds is on the server. A driver's cancel request needs a new
// connection, so once the call is under way the test refuses every further
// dial of the limiter's handle: only the lock timeout can then end the
// server's wait, and without it the session would wait on the row for as long
// as the holder keeps it.
func runPGHeldRow(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name string
		// call runs the statement under test against the held row; stamp is
		// the stamp the row holds.
		call func(t *testing.T, l ratelimit.Limiter, stamp time.Time) error
	}

	cases := []testCase{
		{
			name: "record gives up on a held row within its timeout",
			call: func(t *testing.T, l ratelimit.Limiter, _ time.Time) error {
				return l.RecordFailure(t.Context(), "k")
			},
		},
		{
			name: "charge gives up on a held row within its timeout",
			call: func(t *testing.T, l ratelimit.Limiter, _ time.Time) error {
				r, exceeded, err := l.Charge(t.Context(), "k")
				assert.True(t, exceeded, "a charge that could not be decided reported the key below its limit")
				assert.Zero(t, r)
				return err
			},
		},
		{
			name: "refund gives up on a held row within its timeout",
			call: func(t *testing.T, l ratelimit.Limiter, stamp time.Time) error {
				return l.Refund(t.Context(), ratelimit.NewReceipt("k", stamp))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := migratedLimiterDB(t)
			ns := pgScopedNamespace(t, "held")
			dialer := &pgDialer{}
			handles := &pgHandles{}
			l := b.limiter(t, conn, ns, 3, time.Minute, pgFaultOptions{timeout: heldRowTimeout, dialer: dialer, handles: handles})
			// The row is created out of band, and the limiter's handles are
			// warmed with the generous test timeout: the timed call then
			// waits on the row rather than on a dial. A setup record through
			// the limiter itself would run under heldRowTimeout, dial
			// included, and a slow dial would open the breaker before the
			// case began.
			_, err := conn.DB.ExecContext(t.Context(), pgStatement(t, pgRecordName),
				ns, pgStoredKey("k"), 3, time.Minute.Microseconds(), nil, "5000ms")
			require.NoError(t, err)
			handles.warm(t)

			holder, err := conn.DB.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = holder.Rollback() })
			var stamp time.Time
			require.NoError(t, holder.QueryRowContext(t.Context(),
				`SELECT stamps[1] FROM rate_limit_buckets WHERE namespace = $1 AND key = $2 FOR UPDATE`, ns, "k").Scan(&stamp))
			var holderPID int
			require.NoError(t, holder.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&holderPID))

			// The drop checked below shows the lock timeout at work only
			// once a session has been seen blocked by the holder. On a
			// loaded server the statement can begin its wait after the
			// call has returned, and a check made before then finds no
			// session waiting and passes with nothing shown, the variant
			// included. The sampler runs from before the call, because a
			// wait the lock timeout ends on time is over a moment after
			// the call.
			probe, err := conn.DB.Conn(t.Context())
			require.NoError(t, err)
			t.Cleanup(func() { _ = probe.Close() })
			pid, err := pgRowWaiter(t.Context(), probe, holderPID)
			require.NoError(t, err)
			require.Zero(t, pid, "a session waits on the row before the call")
			var waiter heldRowWaiter
			stopSampling := watchHeldRowWait(t, probe, holderPID, &waiter)

			dialer.refuse.Store(true)
			start := time.Now()
			err = tc.call(t, l, stamp)
			elapsed := time.Since(start)
			t.Logf("the call against the held row returned after %s: %v (SQLSTATE %q)", elapsed, err, pgSQLState(err))

			require.Error(t, err, "the call succeeded through a held row")
			assert.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
			assert.Less(t, elapsed, heldRowBound, "the call waited past its timeout")

			seen := assert.Eventually(t, func() bool { pid, _ := waiter.found(); return pid != 0 },
				heldRowDropWait, 10*time.Millisecond,
				"no session was seen waiting on the held row, so nothing shows the lock timeout ending a wait")
			stopSampling()
			if !seen {
				logPGActivity(t, conn.DB)
				t.FailNow()
			}
			pid, seenAt := waiter.found()
			t.Logf("session %d was first seen blocked by the holder %s after the call began", pid, seenAt.Sub(start))
			// The condition runs on a goroutine of its own, so it reports a
			// failed query as "not yet" rather than failing the test there.
			dropped := assert.Eventually(t, func() bool {
				blocked, err := pgStillBlocked(t.Context(), probe, pid, holderPID)
				return err == nil && !blocked
			}, heldRowDropWait, 20*time.Millisecond, "the server still has a session waiting on the held row")
			// The wait must have ended on the waiter's side: a holder that
			// let go of the row would end it too, with no lock timeout.
			var stillHeld int
			assert.NoError(t, holder.QueryRowContext(t.Context(), `SELECT 1`).Scan(&stillHeld),
				"the holder's transaction ended, so the row was let go rather than given up on")
			if !dropped {
				logPGActivity(t, conn.DB)
			}
		})
	}
}

// TestPGLimiter_HeldRow runs beside the rest of the suite. Its timing is
// made to hold on a loaded host rather than moved to make test-isolated:
// what it proves is a bound relative to its own timeout and a server-side
// wait that ends, and heldRowTimeout and heldRowDropWait say how each
// tolerates the load without letting the variant pass.
func TestPGLimiter_HeldRow(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGHeldRow)
}

// pgHeldRowBroken is a limiter whose record turns the lock timeout off: it
// ends only by the client's own deadline.
//
// The variant's record also runs without the unavailable decorator around
// it: the decorator lives in the core module's internal package, which this
// module cannot import, so a record of the test's own cannot be wrapped in
// it. Its own operation timeout stands in for the decorator's. That leaves
// the case's first assertions (an error, within the bound) passing, and the
// guard still pins the intended case and message: the server-side wait the
// lock timeout ends.
var pgHeldRowBroken = pgFaultVariants(runPGHeldRow, pgFaultVariant{
	name: "lock-timeout-off",
	backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
		t.Helper()
		return newPGStatementLimiter(t, conn, ns, limit, window, o, nil, pgStatement(t, pgRecordName), "0")
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

// Settings of the outage tests.
//
// The operation timeout is long, so that a call which waited it out and one
// the breaker answered at once cannot be confused under -race. It is not
// what the tests time: a call against the stopped server fails at once, as
// the dial is refused, so the timeout bounds only the calls made while the
// server runs. Those are the warm-up and the probe after the restart, which
// dials the restarted container through a Docker lookup and must not be cut
// off by a loaded host.
//
// pgOutageAtOnce is how long a check the open breaker answers may take. It
// does no I/O, so the bound only has to tell it from a check that waited out
// the timeout, with room for a loaded host. That the check did not call the
// server is the dial count's to prove, not the bound's.
//
// The probe interval is measured on the case's fake clock where a case waits
// it out (see the breaker case), so its length costs no time.
const (
	pgOutageTimeout = 10 * time.Second
	pgOutageAtOnce  = 500 * time.Millisecond
	pgOutageProbe   = 200 * time.Millisecond
	pgOutageLimit   = 3
	pgOutageSource  = "203.0.113.7"
)

// pgOutage is what an outage case drives: an own server, the dialer every
// limiter it builds dials through, the clock, and the builder.
type pgOutage struct {
	conn   PostgresConn
	dialer *pgDialer
	// clock is the limiters' clock in a case that sets fakeClock, and nil,
	// the system and database clocks, in every other.
	clock *clockwork.FakeClock
	// build returns a limiter over the server for namespace "api-key" with
	// the outage settings and mode, its handle warmed and its breaker closed.
	build func(mode ratelimit.UnavailableMode) ratelimit.Limiter
}

// runPGUnavailable pins what the limiter does while its server is stopped, in
// each unavailable mode, and that the breaker answers without calling the
// server until the probe interval has passed. Each case starts a server of its
// own.
func runPGUnavailable(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name string
		// fakeClock gives the case's limiters a fake clock, e.clock.
		fakeClock bool
		assert    func(t *testing.T, e pgOutage)
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
				l := e.build(ratelimit.UnavailableFallbackToLocal)
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
			name: "refuse while stopped: a charge is refused as the backend unavailable",
			assert: func(t *testing.T, e pgOutage) {
				c := e.build(ratelimit.UnavailableRefuse)
				e.conn.Stop(t)

				r, exceeded, err := c.Charge(t.Context(), pgOutageSource)
				assert.True(t, exceeded, "refuse mode accepted a charge while the server was stopped")
				assert.Zero(t, r)
				require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
			},
		},
		{
			name: "fall back while stopped: charges count locally, stop at the limit, and a refund returns one",
			assert: func(t *testing.T, e pgOutage) {
				c := e.build(ratelimit.UnavailableFallbackToLocal)
				e.conn.Stop(t)

				var first ratelimit.Receipt
				for i := range pgOutageLimit {
					r, exceeded, err := c.Charge(t.Context(), pgOutageSource)
					require.NoError(t, err, "charge %d was not counted locally", i+1)
					require.False(t, exceeded, "charge %d of a limit of three was refused", i+1)
					if i == 0 {
						first = r
					}
				}
				_, exceeded, err := c.Charge(t.Context(), pgOutageSource)
				require.NoError(t, err)
				assert.True(t, exceeded, "a fourth local charge passed a limit of three")

				require.NoError(t, c.Refund(t.Context(), first))
				_, exceeded, err = c.Charge(t.Context(), pgOutageSource)
				require.NoError(t, err)
				assert.False(t, exceeded, "the refund did not return a local charge's allowance")
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
			// The breaker measures its probe interval on a fake clock. On the
			// system clock a loaded host could run the ten checks below past
			// the interval, and the check that then probed would dial the
			// stopped server: the failure the no-breaker variant is caught
			// by, with no defect behind it. Moving the clock past the
			// interval after the restart still proves that the configured
			// interval, not the default, is the one the breaker keeps.
			name:      "breaker refuses without calling the server, and a probe reaches it once restarted",
			fakeClock: true,
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
					assert.Less(t, elapsed, pgOutageAtOnce, "check %d waited for the server", i)
					assert.True(t, exceeded)
					assert.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				}
				t.Logf("slowest of the ten checks inside the probe interval: %s", slowest)
				assert.Equal(t, dials, e.dialer.count.Load(), "a check inside the probe interval called the server")

				e.conn.Start(t)
				e.clock.Advance(pgOutageProbe)
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

			conn := migratedLimiterDB(t, WithTestPostgresRestartable())
			dialer := &pgDialer{}
			var clk *clockwork.FakeClock
			o := pgFaultOptions{timeout: pgOutageTimeout, probe: pgOutageProbe, dialer: dialer}
			if tc.fakeClock {
				clk = clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
				o.clock = clk
			}
			tc.assert(t, pgOutage{
				conn:   conn,
				dialer: dialer,
				clock:  clk,
				build: func(mode ratelimit.UnavailableMode) ratelimit.Limiter {
					handles := &pgHandles{}
					o := o
					o.mode, o.handles = mode, handles
					l := b.limiter(t, conn, "api-key", pgOutageLimit, time.Minute, o)
					// The handle is dialed first, by a readiness check with
					// retries, so the warm-up below runs on a pooled
					// connection. The warm-up is one call under the
					// operation timeout, and a failure of it would open the
					// breaker. A dial to a freshly started container asks
					// Docker for its port, and on a loaded host that alone
					// can outlast the timeout.
					handles.warm(t)
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

// TestPGLimiter_Unavailable runs beside the rest of the suite rather than in
// make test-isolated: its limiters are warmed by a readiness check before
// their first call, the operation timeout bounds only calls to a running
// server, the breaker case keeps its probe interval on a fake clock, and its
// one wall-clock bound, pgOutageAtOnce, leaves a loaded host room.
func TestPGLimiter_Unavailable(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGUnavailable)
}

// pgRawLimiter runs the limiter's statements with the operation timeout and
// nothing around them: no breaker, no unavailable mode, no hold. It is the
// backend the real limiters wrap, restated.
type pgRawLimiter struct {
	db          *sql.DB
	check       string
	record      string
	charge      string
	refund      string
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
	if err := l.db.QueryRowContext(ctx, l.check, l.ns, pgStoredKey(key), l.windowUS, nil).Scan(&n); err != nil {
		return true, err
	}
	return n >= l.limit, nil
}

func (l *pgRawLimiter) RecordFailure(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.timeout)
	defer cancel()

	_, err := l.db.ExecContext(ctx, l.record, l.ns, pgStoredKey(key), l.limit, l.windowUS, nil, l.lockTimeout)
	return err
}

func (l *pgRawLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()

	var (
		recorded bool
		stamp    time.Time
	)
	err := l.db.QueryRowContext(ctx, l.charge, l.ns, pgStoredKey(key), l.limit, l.windowUS, nil, l.lockTimeout).
		Scan(&recorded, &stamp)
	if err != nil || !recorded {
		return ratelimit.Receipt{}, true, err
	}
	return ratelimit.NewReceipt(key, stamp), false, nil
}

func (l *pgRawLimiter) Refund(ctx context.Context, r ratelimit.Receipt) error {
	if r.Stamp().IsZero() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), l.timeout)
	defer cancel()

	_, err := l.db.ExecContext(ctx, l.refund, l.ns, pgStoredKey(r.Key()), r.Stamp(), l.windowUS, nil, l.lockTimeout)
	return err
}

// pgUnavailableBroken is a limiter with no breaker. Like the held-row variant
// it bypasses the unavailable decorator altogether, which the test module
// cannot import, and so also lacks the unavailable modes and the hold; the
// cases pinning those may fail too. The guard still requires the breaker's
// case to fail with the breaker's message, which no other missing behaviour
// produces.
var pgUnavailableBroken = pgFaultVariants(runPGUnavailable, pgFaultVariant{
	name: "no-breaker",
	backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
		t.Helper()
		return &pgRawLimiter{
			db:          pgFaultDB(t, conn, o),
			check:       pgStatement(t, pgCheckName),
			record:      pgStatement(t, pgRecordName),
			charge:      pgStatement(t, pgChargeName),
			refund:      pgStatement(t, pgRefundName),
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
