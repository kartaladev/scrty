package test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/migrate"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/ratelimittest"
)

// pgTestTimeout is the operation timeout the integration tests give the
// PostgreSQL limiters. The default 250ms is a production bound; under the race
// detector and a busy Docker host a healthy call can take longer, and a call
// cut off would be taken for an outage the test did not stage.
const pgTestTimeout = 5 * time.Second

// pgLimiterBuilder builds one backend's PostgreSQL limiter over the database
// db reaches, which dsn names too, so a backend that opens its own pool (pgx)
// can. A nil clk means the database's clock.
type pgLimiterBuilder func(t *testing.T, db *sql.DB, dsn, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter

// pgFactory is what every backend's PostgreSQL limiter factory provides.
type pgFactory interface {
	ratelimit.LimiterFactory
	ratelimit.Pruner
	ratelimit.Verifier
}

// pgFactoryBuilder builds one backend's PostgreSQL limiter factory, as
// pgLimiterBuilder builds its limiter.
type pgFactoryBuilder func(t *testing.T, db *sql.DB, dsn string, clk clock.Clock) pgFactory

// pgBackend is one PostgreSQL limiter backend under test. Each backend's test
// functions run the shared runners below with its own pgBackend; the second
// backend adds a pgBackend and its own Test functions.
type pgBackend struct {
	name    string
	limiter pgLimiterBuilder
	// allow builds a limiter in ratelimit.UnavailableAllow mode.
	allow   pgLimiterBuilder
	factory pgFactoryBuilder
}

// pgLimiterOptions are the options every sqlstore limiter in these tests
// takes: the test timeout, a discarded log and, when clk is set, that clock.
func pgLimiterOptions(clk clock.Clock) []sqlstore.LimiterOption {
	opts := []sqlstore.LimiterOption{
		sqlstore.WithLimiterOperationTimeout(pgTestTimeout),
		sqlstore.WithLimiterLogger(slog.New(slog.DiscardHandler)),
	}
	if clk != nil {
		opts = append(opts, sqlstore.WithLimiterClock(clk))
	}
	return opts
}

// sqlstoreBackend is the database/sql limiter.
var sqlstoreBackend = pgBackend{
	name: "sqlstore",
	limiter: func(t *testing.T, db *sql.DB, _, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter {
		t.Helper()
		l, err := sqlstore.NewLimiter(db, ns, limit, window, pgLimiterOptions(clk)...)
		require.NoError(t, err)
		return l
	},
	allow: func(t *testing.T, db *sql.DB, _, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter {
		t.Helper()
		opts := append(pgLimiterOptions(clk), sqlstore.WithLimiterOnUnavailable(ratelimit.UnavailableAllow))
		l, err := sqlstore.NewLimiter(db, ns, limit, window, opts...)
		require.NoError(t, err)
		return l
	},
	factory: func(t *testing.T, db *sql.DB, _ string, clk clock.Clock) pgFactory {
		t.Helper()
		f, err := sqlstore.NewLimiterFactory(db, pgLimiterOptions(clk)...)
		require.NoError(t, err)
		return f
	},
}

// pgxLimiterOptions are the options every pgx limiter in these tests takes,
// the counterpart of pgLimiterOptions.
func pgxLimiterOptions(clk clock.Clock) []pgxstore.LimiterOption {
	opts := []pgxstore.LimiterOption{
		pgxstore.WithLimiterOperationTimeout(pgTestTimeout),
		pgxstore.WithLimiterLogger(slog.New(slog.DiscardHandler)),
	}
	if clk != nil {
		opts = append(opts, pgxstore.WithLimiterClock(clk))
	}
	return opts
}

// pgxTestPool opens a pool of its own on dsn, closed at cleanup. The pgx
// limiter takes a *pgxpool.Pool, so it cannot borrow the *sql.DB the harness
// passes.
func pgxTestPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()

	pool, err := pgxpool.New(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// pgxBackend is the native pgx limiter.
var pgxBackend = pgBackend{
	name: "pgx",
	limiter: func(t *testing.T, _ *sql.DB, dsn, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter {
		t.Helper()
		l, err := pgxstore.NewLimiter(pgxTestPool(t, dsn), ns, limit, window, pgxLimiterOptions(clk)...)
		require.NoError(t, err)
		return l
	},
	allow: func(t *testing.T, _ *sql.DB, dsn, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter {
		t.Helper()
		opts := append(pgxLimiterOptions(clk), pgxstore.WithLimiterOnUnavailable(ratelimit.UnavailableAllow))
		l, err := pgxstore.NewLimiter(pgxTestPool(t, dsn), ns, limit, window, opts...)
		require.NoError(t, err)
		return l
	},
	factory: func(t *testing.T, _ *sql.DB, dsn string, clk clock.Clock) pgFactory {
		t.Helper()
		f, err := pgxstore.NewLimiterFactory(pgxTestPool(t, dsn), pgxLimiterOptions(clk)...)
		require.NoError(t, err)
		return f
	},
}

// migratedLimiterDB returns a database of the test's own with the
// security-state set applied.
func migratedLimiterDB(t *testing.T, opts ...TestOption) PostgresConn {
	t.Helper()

	set := migrate.SecurityState()
	return RunTestPostgres(t, append([]TestOption{WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable)}, opts...)...)
}

// pgHarness adapts a PostgreSQL limiter to the conformance suite in
// application-clock mode, over one database.
//
// Every namespace a subtest asks for is prefixed with a digest of the
// subtest's name and a hyphen (a colon is refused), so a limiter that ignored
// its namespace would count two namespaces together and the suite would catch
// it. New deletes only the rows of its own namespace, so a namespace the suite
// builds again starts empty while the subtest's other namespaces keep their
// counts. SecondInstance builds a limiter of the second builder over the same
// database and namespace, as another process would; it shares nothing with
// the first instance but the table.
type pgHarness struct {
	db            *sql.DB
	dsn           string
	first, second pgLimiterBuilder
	clock         *clockwork.FakeClock
}

func newPGHarness(db *sql.DB, dsn string, first, second pgLimiterBuilder) *pgHarness {
	return &pgHarness{
		db:     db,
		dsn:    dsn,
		first:  first,
		second: second,
		// Whole seconds, so the clock reads on whole microseconds however
		// the suite advances it.
		clock: clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0)),
	}
}

// pgScopedNamespace is namespace within t's scope: a digest of the subtest's
// name, a hyphen, and the namespace. It stays within the 64-byte maximum for
// every namespace the suite asks for.
func pgScopedNamespace(t *testing.T, namespace string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(t.Name()))
	return hex.EncodeToString(sum[:8]) + "-" + namespace
}

func (h *pgHarness) newLimiter(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	ns := pgScopedNamespace(t, namespace)
	_, err := h.db.ExecContext(t.Context(), `DELETE FROM rate_limit_buckets WHERE namespace = $1`, ns)
	require.NoError(t, err)
	return h.first(t, h.db, h.dsn, ns, limit, window, h.clock)
}

func (h *pgHarness) secondInstance(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter {
	t.Helper()

	return h.second(t, h.db, h.dsn, pgScopedNamespace(t, namespace), limit, window, h.clock)
}

func (h *pgHarness) harness() ratelimittest.Harness {
	return ratelimittest.Harness{
		New:            h.newLimiter,
		Advance:        h.clock.Advance,
		SecondInstance: h.secondInstance,
	}
}

// runPGConformance runs the shared-limiter conformance suite against first,
// with second as the other replica.
func runPGConformance(t *testing.T, first, second pgBackend) {
	t.Helper()

	conn := migratedLimiterDB(t)
	h := newPGHarness(conn.DB, conn.DSN, first.limiter, second.limiter).harness()
	require.NotNil(t, h.SecondInstance, "the cross-instance scenarios would be skipped")
	ratelimittest.Run(t, h)
}

func TestSQLStoreLimiter_Conformance(t *testing.T) {
	t.Parallel()

	runPGConformance(t, sqlstoreBackend, sqlstoreBackend)
}

// runPGKeys pins the stored form of keys: a key of 512 bytes is stored as
// given and one of 513 as a digest, without the two sharing a bucket; a key
// spelled like a digest is itself digested; and a limit of 128, the maximum,
// is reached.
func runPGKeys(t *testing.T, b pgBackend) {
	t.Helper()

	long := strings.Repeat("k", 513)
	sum := sha256.Sum256([]byte(long))
	digestSpelled := "sha256:" + hex.EncodeToString(sum[:])

	type testCase struct {
		name     string
		limit    int
		recorded string
		checked  string
		assert   func(t *testing.T, exceeded bool, err error)
	}

	exceeded := func(t *testing.T, got bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, got)
	}
	notExceeded := func(t *testing.T, got bool, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.False(t, got)
	}

	cases := []testCase{
		{name: "513-byte key counts its own failures", limit: 3, recorded: long, checked: long, assert: exceeded},
		{name: "512-byte prefix of a 513-byte key is apart", limit: 3, recorded: long, checked: long[:512], assert: notExceeded},
		{name: "512-byte key counts its own failures", limit: 3, recorded: long[:512], checked: long[:512], assert: exceeded},
		{name: "513-byte key apart from its 512-byte prefix", limit: 3, recorded: long[:512], checked: long, assert: notExceeded},
		{name: "key spelled as a digest is apart from the long key", limit: 3, recorded: long, checked: digestSpelled, assert: notExceeded},
		{name: "limit at the maximum is reached", limit: 128, recorded: "k", checked: "k", assert: exceeded},
	}

	conn := migratedLimiterDB(t)
	clk := clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := b.limiter(t, conn.DB, conn.DSN, pgScopedNamespace(t, "keys"), tc.limit, time.Minute, clk)
			for range tc.limit {
				require.NoError(t, l.RecordFailure(t.Context(), tc.recorded))
			}
			got, err := l.Exceeded(t.Context(), tc.checked)
			tc.assert(t, got, err)
		})
	}
}

func TestSQLStoreLimiter_Keys(t *testing.T) {
	t.Parallel()

	runPGKeys(t, sqlstoreBackend)
}

// runPGPoisonKey pins that a key PostgreSQL's text type cannot hold, one with
// a NUL byte or invalid UTF-8, is stored as a digest: it is recorded and
// counted like any key, and it neither reads as an outage nor trips the
// breaker for the other keys of the namespace, in refuse mode (an innocent
// key is checked without error) or in allow mode (a key at its limit stays
// exceeded).
func runPGPoisonKey(t *testing.T, b pgBackend) {
	t.Helper()

	type testCase struct {
		name   string
		poison string
		assert func(t *testing.T, b pgBackend, conn PostgresConn, clk clock.Clock, poison string)
	}
	cases := []testCase{
		{
			name: "NUL byte, refuse mode", poison: "user\x00",
			assert: assertPoisonRefuse,
		},
		{
			name: "invalid UTF-8, refuse mode", poison: "user\xff",
			assert: assertPoisonRefuse,
		},
		{
			name: "NUL byte, allow mode", poison: "user\x00",
			assert: assertPoisonAllow,
		},
		{
			name: "invalid UTF-8, allow mode", poison: "user\xff",
			assert: assertPoisonAllow,
		},
	}

	conn := migratedLimiterDB(t)
	clk := clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, b, conn, clk, tc.poison)
		})
	}
}

const pgPoisonLimit = 3

func assertPoisonRefuse(t *testing.T, b pgBackend, conn PostgresConn, clk clock.Clock, poison string) {
	t.Helper()

	l := b.limiter(t, conn.DB, conn.DSN, pgScopedNamespace(t, "poison"), pgPoisonLimit, time.Minute, clk)
	for range pgPoisonLimit {
		require.NoError(t, l.RecordFailure(t.Context(), poison))
	}
	got, err := l.Exceeded(t.Context(), poison)
	require.NoError(t, err)
	assert.True(t, got, "the poison key does not count its own failures")

	got, err = l.Exceeded(t.Context(), "innocent")
	require.NoError(t, err, "the poison key opened the breaker for the namespace")
	assert.False(t, got)
}

func assertPoisonAllow(t *testing.T, b pgBackend, conn PostgresConn, clk clock.Clock, poison string) {
	t.Helper()

	l := b.allow(t, conn.DB, conn.DSN, pgScopedNamespace(t, "poison"), pgPoisonLimit, time.Minute, clk)
	for range pgPoisonLimit {
		require.NoError(t, l.RecordFailure(t.Context(), "victim"))
	}
	got, err := l.Exceeded(t.Context(), "victim")
	require.NoError(t, err)
	require.True(t, got, "the victim is not at its limit")

	require.NoError(t, l.RecordFailure(t.Context(), poison))
	_, err = l.Exceeded(t.Context(), poison)
	require.NoError(t, err)

	got, err = l.Exceeded(t.Context(), "victim")
	require.NoError(t, err)
	assert.True(t, got, "the poison key lifted the victim's limit")
}

func TestSQLStoreLimiter_PoisonKey(t *testing.T) {
	t.Parallel()

	runPGPoisonKey(t, sqlstoreBackend)
}

func TestPgxLimiter_PoisonKey(t *testing.T) {
	t.Parallel()

	runPGPoisonKey(t, pgxBackend)
}

// runPGClockBehindNewest pins a record whose application clock reads behind
// the key's newest stamp: newest_at keeps the newest, and the stamps stay
// ascending.
func runPGClockBehindNewest(t *testing.T, b pgBackend) {
	t.Helper()

	conn := migratedLimiterDB(t)
	at := time.Unix(1_700_000_000, 0).UTC()
	clk := clockwork.NewFakeClockAt(at)
	ns := pgScopedNamespace(t, "behind")
	l := b.limiter(t, conn.DB, conn.DSN, ns, 3, time.Minute, clk)

	require.NoError(t, l.RecordFailure(t.Context(), "k"))
	clk.Advance(-10 * time.Second)
	require.NoError(t, l.RecordFailure(t.Context(), "k"))

	var (
		newest        time.Time
		first, second time.Time
		n             int
		ascending     bool
	)
	require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT newest_at, stamps[1], stamps[2], cardinality(stamps),
  stamps = ARRAY(SELECT s FROM unnest(stamps) AS u(s) ORDER BY s)
FROM rate_limit_buckets WHERE namespace = $1 AND key = $2`, ns, "k").Scan(&newest, &first, &second, &n, &ascending))

	assert.True(t, newest.Equal(at), "newest_at moved back to %s", newest)
	assert.Equal(t, 2, n)
	assert.True(t, ascending, "stamps out of order")
	assert.True(t, first.Equal(at.Add(-10*time.Second)), "first stamp %s", first)
	assert.True(t, second.Equal(at), "second stamp %s", second)
}

func TestSQLStoreLimiter_ClockBehindNewest(t *testing.T) {
	t.Parallel()

	runPGClockBehindNewest(t, sqlstoreBackend)
}

// pgBrokenVar names the environment variable that selects the one broken
// PostgreSQL limiter the child test runs.
const pgBrokenVar = "PG_RATELIMIT_BROKEN"

// brokenRecordLimiter is a PostgreSQL limiter whose record runs a statement of
// the test's own, carrying one defect; its check is the real limiter's. The
// ended-context rules are kept, so only the defect can fail the suite.
type brokenRecordLimiter struct {
	ratelimit.Limiter // the real limiter, for Exceeded

	db       *sql.DB
	ns       string
	limit    int
	windowUS int64
	clk      clock.Clock
	record   string
}

// pgStoredKey is the form the limiter stores key in: as given, except that a
// key longer than 512 bytes, one that itself starts with "sha256:", or one
// that is not valid UTF-8 or contains a NUL byte, is stored as "sha256:" and
// the hex digest of the key. The test module cannot
// import the core module's internal package that holds the mapping, so the
// documented contract is restated here; the key tests pin both sides of it.
func pgStoredKey(key string) string {
	if len(key) <= 512 && !strings.HasPrefix(key, "sha256:") && utf8.ValidString(key) && !strings.ContainsRune(key, 0) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (l *brokenRecordLimiter) RecordFailure(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgTestTimeout)
	defer cancel()
	_, err := l.db.ExecContext(ctx, l.record, l.ns, pgStoredKey(key), l.limit, l.windowUS,
		l.clk.Now().UTC().Truncate(time.Microsecond), "5000ms")
	return err
}

// pgRecordTrimmingByTime is a record that first drops the stamps older than
// its own window: a shorter-window replica would delete failures that a
// longer-window replica still counts.
const pgRecordTrimmingByTime = `WITH t AS (SELECT coalesce($5::timestamptz, clock_timestamp()) AS now)
INSERT INTO rate_limit_buckets AS b (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, $2, ARRAY[t.now], t.now, $4::bigint
FROM t CROSS JOIN (SELECT set_config('lock_timeout', $6::text, true)) AS lt
ON CONFLICT (namespace, key) DO UPDATE SET
  stamps = (SELECT array_agg(n.s ORDER BY n.s) FROM
            (SELECT s FROM unnest(b.stamps || EXCLUDED.stamps) AS u(s)
             WHERE s > EXCLUDED.newest_at - $4::bigint * interval '1 microsecond'
             ORDER BY s DESC LIMIT $3::int) AS n),
  newest_at = GREATEST(b.newest_at, EXCLUDED.newest_at),
  longest_window_us = GREATEST(b.longest_window_us, EXCLUDED.longest_window_us)`

// brokenRecordBuilder builds the sqlstore limiter with its record replaced by
// record.
func brokenRecordBuilder(record string) pgLimiterBuilder {
	return func(t *testing.T, db *sql.DB, dsn, ns string, limit int, window time.Duration, clk clock.Clock) ratelimit.Limiter {
		t.Helper()
		return &brokenRecordLimiter{
			Limiter:  sqlstoreBackend.limiter(t, db, dsn, ns, limit, window, clk),
			db:       db,
			ns:       ns,
			limit:    limit,
			windowUS: window.Microseconds(),
			clk:      clk,
			record:   record,
		}
	}
}

func pgBrokenVariant(name, record, failsCase string) storefix.BrokenVariant {
	return storefix.BrokenVariant{
		Name: name,
		Run: func(t *testing.T) {
			conn := migratedLimiterDB(t)
			build := brokenRecordBuilder(record)
			t.Run("sqlstore", func(t *testing.T) {
				ratelimittest.Run(t, newPGHarness(conn.DB, conn.DSN, build, build).harness())
			})
		},
		FailsCase: failsCase,
	}
}

// pgBrokenVariants are the defects the conformance run of the PostgreSQL
// limiters must catch, each at the case that guards it.
var pgBrokenVariants = []storefix.BrokenVariant{
	pgBrokenVariant("trimming-by-time", pgRecordTrimmingByTime, "shorter-window instance does not disarm a longer one"),
}

// TestSQLStoreLimiter_ConformanceBroken runs the broken variant named by the
// environment, and is the child half of
// TestSQLStoreLimiter_ConformanceCatchesBrokenVariants. Without a variant
// named it skips.
func TestSQLStoreLimiter_ConformanceBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgBrokenVar, "TestSQLStoreLimiter_ConformanceCatchesBrokenVariants", pgBrokenVariants)
}

// TestSQLStoreLimiter_ConformanceCatchesBrokenVariants checks that the
// conformance run fails against each broken variant, at the case guarding its
// defect. Each variant runs in its own process, because a failing suite
// reports through its own *testing.T and would fail this test with it.
func TestSQLStoreLimiter_ConformanceCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	// The children each want PostgreSQL: start the one server they share.
	EnsureTestPostgresServer(t)
	storefix.CatchBrokenVariants(t, pgBrokenVar, "TestSQLStoreLimiter_ConformanceBroken", "sqlstore", pgBrokenVariants)
}

// runPGFactory pins that limiters a factory builds for one namespace and
// policy share its buckets, and that the same namespace with another policy is
// refused, naming both.
func runPGFactory(t *testing.T, b pgBackend) {
	t.Helper()

	type testCase struct {
		name   string
		assert func(t *testing.T, f pgFactory, ns string)
	}

	cases := []testCase{
		{
			name: "same namespace and policy shares the buckets",
			assert: func(t *testing.T, f pgFactory, ns string) {
				first, err := f.NewLimiter(ns, 2, time.Minute)
				require.NoError(t, err)
				second, err := f.NewLimiter(ns, 2, time.Minute)
				require.NoError(t, err)

				require.NoError(t, first.RecordFailure(t.Context(), "k"))
				require.NoError(t, second.RecordFailure(t.Context(), "k"))
				for _, l := range []ratelimit.Limiter{first, second} {
					got, err := l.Exceeded(t.Context(), "k")
					require.NoError(t, err)
					assert.True(t, got, "a limiter does not count the other's failure")
				}
			},
		},
		{
			name: "same namespace with another policy is refused",
			assert: func(t *testing.T, f pgFactory, ns string) {
				_, err := f.NewLimiter(ns, 2, time.Minute)
				require.NoError(t, err)
				l, err := f.NewLimiter(ns, 5, time.Hour)
				require.ErrorIs(t, err, ratelimit.ErrConfig)
				assert.Contains(t, err.Error(), "2 per 1m0s")
				assert.Contains(t, err.Error(), "5 per 1h0m0s")
				assert.Nil(t, l)
			},
		},
	}

	conn := migratedLimiterDB(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := b.factory(t, conn.DB, conn.DSN, clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0)))
			tc.assert(t, f, pgScopedNamespace(t, "api-key"))
		})
	}
}

func TestSQLStoreLimiter_Factory(t *testing.T) {
	t.Parallel()

	runPGFactory(t, sqlstoreBackend)
}

// runPGFactoryPrune pins the factory's prune across namespaces: an idle key of
// each of two namespaces is removed and counted, and a live key is kept and
// still counts.
func runPGFactoryPrune(t *testing.T, b pgBackend) {
	t.Helper()

	conn := migratedLimiterDB(t)
	clk := clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
	f := b.factory(t, conn.DB, conn.DSN, clk)
	nsA, nsB := pgScopedNamespace(t, "a"), pgScopedNamespace(t, "b")
	a, err := f.NewLimiter(nsA, 1, time.Minute)
	require.NoError(t, err)
	bl, err := f.NewLimiter(nsB, 1, time.Minute)
	require.NoError(t, err)

	require.NoError(t, a.RecordFailure(t.Context(), "idle"))
	require.NoError(t, bl.RecordFailure(t.Context(), "idle"))
	clk.Advance(time.Minute)
	require.NoError(t, a.RecordFailure(t.Context(), "live"))

	removed, err := f.Prune(t.Context())
	require.NoError(t, err)
	assert.Equal(t, 2, removed)

	var keys []string
	rows, err := conn.DB.QueryContext(t.Context(),
		`SELECT namespace || '/' || key FROM rate_limit_buckets WHERE namespace IN ($1, $2) ORDER BY 1`, nsA, nsB)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		keys = append(keys, k)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{nsA + "/live"}, keys)

	got, err := a.Exceeded(t.Context(), "live")
	require.NoError(t, err)
	assert.True(t, got, "the prune freed a live key's quota")
}

func TestSQLStoreLimiter_FactoryPrune(t *testing.T) {
	t.Parallel()

	runPGFactoryPrune(t, sqlstoreBackend)
}

// pgVerifyTarget is the database a Verify case checks: a handle and its DSN,
// and the handle of the server's own user on the same database, for reading
// what the check left behind.
type pgVerifyTarget struct {
	db    *sql.DB
	dsn   string
	admin *sql.DB
}

// pgRoleTarget creates a login role on conn's server that holds only
// privileges (a GRANT list) on the bucket table, and returns a handle
// connected as it. The role is dropped at cleanup, before the database is.
func pgRoleTarget(t *testing.T, conn PostgresConn, privileges string) pgVerifyTarget {
	t.Helper()

	sum := sha256.Sum256([]byte(t.Name()))
	role := "scrty_ro_" + hex.EncodeToString(sum[:6])
	ctx := t.Context()
	_, err := conn.DB.ExecContext(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'readonly'`)
	require.NoError(t, err)
	_, err = conn.DB.ExecContext(ctx, `GRANT `+privileges+` ON rate_limit_buckets TO `+role)
	require.NoError(t, err)

	u, err := url.Parse(conn.DSN)
	require.NoError(t, err)
	u.User = url.UserPassword(role, "readonly")
	db, err := sql.Open("pgx", u.String())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := conn.DB.ExecContext(ctx, `REVOKE ALL ON rate_limit_buckets FROM `+role)
		assert.NoError(t, err)
		_, err = conn.DB.ExecContext(ctx, `DROP ROLE `+role)
		assert.NoError(t, err)
	})
	return pgVerifyTarget{db: db, dsn: u.String(), admin: conn.DB}
}

// runPGVerify pins Verify on both the factory and a limiter it builds: each
// refusal is a configuration error naming its cause, and a supported primary
// passes and keeps no probe row.
func runPGVerify(t *testing.T, b pgBackend) {
	t.Helper()

	type testCase struct {
		name   string
		target func(t *testing.T) pgVerifyTarget
		ctx    func(ctx context.Context) context.Context // nil means identity
		// prunes also runs the factory's Prune, which must succeed.
		prunes bool
		assert func(t *testing.T, target pgVerifyTarget, err error)
	}

	refused := func(want ...string) func(t *testing.T, _ pgVerifyTarget, err error) {
		return func(t *testing.T, _ pgVerifyTarget, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
		}
	}
	// notConfig is a failure of the call, not of the wiring: it does not wrap
	// ratelimit.ErrConfig, so a caller can retry instead of refusing to start.
	notConfig := func(extra func(t *testing.T, err error)) func(t *testing.T, _ pgVerifyTarget, err error) {
		return func(t *testing.T, _ pgVerifyTarget, err error) {
			t.Helper()
			require.Error(t, err)
			assert.NotErrorIs(t, err, ratelimit.ErrConfig)
			if extra != nil {
				extra(t, err)
			}
		}
	}
	plain := func(conn PostgresConn) pgVerifyTarget {
		return pgVerifyTarget{db: conn.DB, dsn: conn.DSN, admin: conn.DB}
	}

	cases := []testCase{
		{
			name: "standby",
			target: func(t *testing.T) pgVerifyTarget {
				set := migrate.SecurityState()
				sb := RunTestPostgresStandby(t, WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
				return pgVerifyTarget{db: sb.Standby.DB, dsn: sb.Standby.DSN, admin: sb.Primary.DB}
			},
			assert: refused("standby"),
		},
		{
			name:   "no migrations applied",
			target: func(t *testing.T) pgVerifyTarget { return plain(RunTestPostgres(t)) },
			assert: refused("security-state migration set"),
		},
		{
			name: "table only in a schema outside search_path",
			target: func(t *testing.T) pgVerifyTarget {
				conn := RunTestPostgres(t)
				_, err := conn.DB.ExecContext(t.Context(), `CREATE SCHEMA other;
CREATE TABLE other.rate_limit_buckets (
  namespace text NOT NULL, key text NOT NULL, stamps timestamptz[] NOT NULL,
  newest_at timestamptz NOT NULL, longest_window_us bigint NOT NULL,
  PRIMARY KEY (namespace, key))`)
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := conn.DB.ExecContext(context.Background(), `DROP SCHEMA other CASCADE`)
					assert.NoError(t, err)
				})
				return plain(conn)
			},
			assert: refused("security-state migration set"),
		},
		{
			name: "unlogged table",
			target: func(t *testing.T) pgVerifyTarget {
				conn := migratedLimiterDB(t)
				_, err := conn.DB.ExecContext(t.Context(), `ALTER TABLE rate_limit_buckets SET UNLOGGED`)
				require.NoError(t, err)
				return plain(conn)
			},
			assert: refused("unlogged"),
		},
		{
			name:   "role that may only read the table",
			target: func(t *testing.T) pgVerifyTarget { return pgRoleTarget(t, migratedLimiterDB(t), "SELECT") },
			assert: refused("record statement"),
		},
		{
			name: "role holding exactly the documented privileges",
			target: func(t *testing.T) pgVerifyTarget {
				return pgRoleTarget(t, migratedLimiterDB(t), "SELECT, INSERT, UPDATE, DELETE")
			},
			prunes: true,
			assert: func(t *testing.T, _ pgVerifyTarget, err error) { require.NoError(t, err) },
		},
		{
			name:   "ended context",
			target: func(t *testing.T) pgVerifyTarget { return plain(migratedLimiterDB(t)) },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: notConfig(func(t *testing.T, err error) { assert.ErrorIs(t, err, context.Canceled) }),
		},
		{
			name: "unreachable server",
			target: func(t *testing.T) pgVerifyTarget {
				set := migrate.SecurityState()
				conn := RunTestPostgres(t, WithTestPostgresOwnServer(),
					WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
				conn.Stop(t)
				return plain(conn)
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				_ = cancel // released with the test's context
				return cctx
			},
			assert: notConfig(nil),
		},
		{
			name:   "migrated primary",
			target: func(t *testing.T) pgVerifyTarget { return plain(migratedLimiterDB(t)) },
			assert: func(t *testing.T, target pgVerifyTarget, err error) {
				require.NoError(t, err)
				var n int
				require.NoError(t, target.admin.QueryRowContext(t.Context(),
					`SELECT count(*) FROM rate_limit_buckets WHERE namespace = ''`).Scan(&n))
				assert.Zero(t, n, "Verify left its probe row behind")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := tc.target(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			for _, clk := range []clock.Clock{nil, clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))} {
				f := b.factory(t, target.db, target.dsn, clk)
				tc.assert(t, target, f.Verify(ctx))
				if tc.prunes {
					_, err := f.Prune(ctx)
					require.NoError(t, err, "a role with the documented privileges cannot prune")
				}

				l, err := f.NewLimiter("api-key", 3, time.Minute)
				require.NoError(t, err)
				v, ok := l.(ratelimit.Verifier)
				require.True(t, ok, "the limiter does not implement ratelimit.Verifier")
				tc.assert(t, target, v.Verify(ctx))
			}
		})
	}
}

func TestSQLStoreLimiter_Verify(t *testing.T) {
	t.Parallel()

	runPGVerify(t, sqlstoreBackend)
}

// TestPgxLimiter_Conformance runs the suite against the pgx limiter with the
// sqlstore limiter as the other replica, which also pins that the two backends
// share one table: failures recorded through one are counted by the other.
func TestPgxLimiter_Conformance(t *testing.T) {
	t.Parallel()

	runPGConformance(t, pgxBackend, sqlstoreBackend)
}

func TestPgxLimiter_Keys(t *testing.T) {
	t.Parallel()

	runPGKeys(t, pgxBackend)
}

func TestPgxLimiter_ClockBehindNewest(t *testing.T) {
	t.Parallel()

	runPGClockBehindNewest(t, pgxBackend)
}

func TestPgxLimiter_Factory(t *testing.T) {
	t.Parallel()

	runPGFactory(t, pgxBackend)
}

func TestPgxLimiter_FactoryPrune(t *testing.T) {
	t.Parallel()

	runPGFactoryPrune(t, pgxBackend)
}

func TestPgxLimiter_Verify(t *testing.T) {
	t.Parallel()

	runPGVerify(t, pgxBackend)
}

// TestSQLStoreLimiter_GormConsumer pins that an application on gorm gets a
// shared limiter by handing the *sql.DB under its gorm handle to the factory:
// two limiters built over it for one namespace, as two replicas would, count
// together.
func TestSQLStoreLimiter_GormConsumer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// secondNamespace is the namespace the second replica counts in.
		secondNamespace string
		assert          func(t *testing.T, first, second ratelimit.Limiter)
	}

	cases := []testCase{
		{
			name:            "replicas of one namespace count together",
			secondNamespace: "api-key",
			assert: func(t *testing.T, first, second ratelimit.Limiter) {
				for _, l := range []ratelimit.Limiter{first, second} {
					got, err := l.Exceeded(t.Context(), "k")
					require.NoError(t, err)
					assert.True(t, got, "two failures on one replica and one on the other did not reach the limit of 3")
				}
			},
		},
		{
			name:            "another namespace counts apart",
			secondNamespace: "magic-link",
			assert: func(t *testing.T, first, second ratelimit.Limiter) {
				for _, l := range []ratelimit.Limiter{first, second} {
					got, err := l.Exceeded(t.Context(), "k")
					require.NoError(t, err)
					assert.False(t, got, "a failure in another namespace was counted")
				}
			},
		},
	}

	conn := migratedLimiterDB(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Each replica is a gorm handle of its own over the database.
			replica := func(namespace string) ratelimit.Limiter {
				gdb, err := gormdb.Open(postgres.Open(conn.DSN), &gormdb.Config{DisableAutomaticPing: true})
				require.NoError(t, err)
				sqlDB, err := gdb.DB()
				require.NoError(t, err)
				t.Cleanup(func() { _ = sqlDB.Close() })

				f, err := sqlstore.NewLimiterFactory(sqlDB, pgLimiterOptions(nil)...)
				require.NoError(t, err)
				require.NoError(t, f.Verify(t.Context()))
				l, err := f.NewLimiter(pgScopedNamespace(t, namespace), 3, time.Minute)
				require.NoError(t, err)
				return l
			}
			first, second := replica("api-key"), replica(tc.secondNamespace)

			require.NoError(t, first.RecordFailure(t.Context(), "k"))
			require.NoError(t, first.RecordFailure(t.Context(), "k"))
			require.NoError(t, second.RecordFailure(t.Context(), "k"))
			tc.assert(t, first, second)
		})
	}
}
