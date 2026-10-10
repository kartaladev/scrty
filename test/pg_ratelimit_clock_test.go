package test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// pgArgsTracer records the SQL and arguments of every statement a handle
// runs, so a test sees what a limiter passed as its now parameter.
type pgArgsTracer struct {
	mu    sync.Mutex
	calls []pgTracedCall
}

type pgTracedCall struct {
	sql  string
	args []any
}

var _ pgx.QueryTracer = (*pgArgsTracer)(nil)

func (r *pgArgsTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, pgTracedCall{sql: data.SQL, args: pgStatementArgs(data.Args)})
	return ctx
}

// pgStatementArgs drops the query options a driver passes ahead of a
// statement's arguments, as pgx's database/sql adapter passes the result
// formats of a query, and copies the rest.
func pgStatementArgs(args []any) []any {
	for len(args) > 0 {
		switch args[0].(type) {
		case pgx.QueryResultFormats, pgx.QueryResultFormatsByOID, pgx.QueryExecMode, pgx.QueryRewriter:
			args = args[1:]
			continue
		}
		break
	}
	return append([]any(nil), args...)
}

func (*pgArgsTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// args returns the arguments of every traced run of stmt, in order.
func (r *pgArgsTracer) args(stmt string) [][]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [][]any
	for _, c := range r.calls {
		if c.sql == stmt {
			out = append(out, c.args)
		}
	}
	return out
}

// pgClockEnv is what a database-clock case drives: the database, the case's
// namespace, the limiter, and the tracer on every handle the limiter was
// built over.
type pgClockEnv struct {
	conn   PostgresConn
	ns     string
	l      ratelimit.Limiter
	tracer *pgArgsTracer
}

// runPGDatabaseClock pins the default time source, the database's
// clock_timestamp(), with no application clock configured: the record and the
// check pass no time of their own, a failure stops counting one window after
// it was recorded, in real time, and each record reads the time once, so the
// newest stamp it writes and newest_at agree to the microsecond.
func runPGDatabaseClock(t *testing.T, b pgFaultBackend) {
	t.Helper()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, e pgClockEnv)
	}

	cases := []testCase{
		{
			// The now parameter is NULL, which the statements read as
			// clock_timestamp(). Behaviour alone cannot tell the database's
			// clock from the host's here, since the container shares the
			// host's: the arguments can.
			name:   "with no clock configured the statements pass no time",
			limit:  1,
			window: time.Minute,
			assert: func(t *testing.T, e pgClockEnv) {
				require.NoError(t, e.l.RecordFailure(t.Context(), "k"))
				_, err := e.l.Exceeded(t.Context(), "k")
				require.NoError(t, err)

				records := e.tracer.args(pgStatement(t, pgRecordName))
				require.NotEmpty(t, records, "no record statement was traced")
				for _, args := range records {
					require.Len(t, args, 6)
					assert.Nil(t, args[4], "the record passed an application time with no clock configured")
				}
				checks := e.tracer.args(pgStatement(t, pgCheckName))
				require.NotEmpty(t, checks, "no check statement was traced")
				for _, args := range checks {
					require.Len(t, args, 4)
					assert.Nil(t, args[3], "the check passed an application time with no clock configured")
				}
			},
		},
		{
			name:   "a failure stops counting one window later",
			limit:  1,
			window: 2 * time.Second,
			assert: func(t *testing.T, e pgClockEnv) {
				l := e.l
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded, "the failure just recorded does not count")

				time.Sleep(2100 * time.Millisecond)
				exceeded, err = l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.False(t, exceeded, "the failure still counts a window after it was recorded")
			},
		},
		{
			name:   "each record leaves newest_at at its newest stamp",
			limit:  20,
			window: time.Minute,
			assert: func(t *testing.T, e pgClockEnv) {
				l, conn, ns := e.l, e.conn, e.ns
				// More records than the limit: the reads of the broken
				// variant fall in one microsecond often enough that twenty
				// records could all agree by chance, and a full row keeps
				// its newest stamp last as well.
				for i := range 60 {
					require.NoError(t, l.RecordFailure(t.Context(), "k"))
					var equal bool
					require.NoError(t, conn.DB.QueryRowContext(t.Context(),
						`SELECT newest_at = stamps[array_upper(stamps, 1)] FROM rate_limit_buckets WHERE namespace = $1 AND key = $2`,
						ns, "k").Scan(&equal))
					assert.True(t, equal, "record %d: newest_at differs from the newest stamp", i)
				}
			},
		},
	}

	conn := migratedLimiterDB(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ns := pgScopedNamespace(t, "clock")
			tracer := &pgArgsTracer{}
			l := b.limiter(t, conn, ns, tc.limit, tc.window, pgFaultOptions{tracer: tracer})
			tc.assert(t, pgClockEnv{conn: conn, ns: ns, l: l, tracer: tracer})
		})
	}
}

func TestPGLimiter_DatabaseClock(t *testing.T) {
	t.Parallel()

	runPGFaultBackends(t, runPGDatabaseClock)
}

// pgRecordReadingTimeTwice is a record that reads clock_timestamp() once for
// the stamp and again for newest_at, so the two differ by however long lay
// between the reads.
var pgRecordReadingTimeTwice = pgStatementEdit{
	name: "time-read-twice",
	stmt: pgRecordName,
	old:  "ARRAY[t.now], t.now,",
	new:  "ARRAY[coalesce($5::timestamptz, clock_timestamp())], coalesce($5::timestamptz, clock_timestamp()),",
}

var pgDatabaseClockBroken = pgFaultVariants(runPGDatabaseClock,
	pgFaultVariant{
		name: "clock-frozen-at-construction",
		backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
			t.Helper()
			o.clock = clockwork.NewFakeClockAt(time.Now())
			return sqlstoreFaultLimiter(t, conn, ns, limit, window, o)
		}),
		failsCase: "a failure stops counting one window later",
		failsWith: "the failure still counts a window after it was recorded",
	},
	pgFaultVariant{
		name: "time-read-twice",
		backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
			t.Helper()
			return newPGStatementLimiter(t, conn, ns, limit, window, o, nil, pgRecordReadingTimeTwice.apply(t), "5000ms")
		}),
		failsCase: "each record leaves newest_at at its newest stamp",
		failsWith: "newest_at differs from the newest stamp",
	},
	pgFaultVariant{
		// The host's clock where none is configured: limiterNow returning
		// time.Now() for a nil clock. Every behavioural case passes it.
		name: "host-clock-by-default",
		backend: brokenLimiterBackend(func(t *testing.T, conn PostgresConn, ns string, limit int, window time.Duration, o pgFaultOptions) ratelimit.Limiter {
			t.Helper()
			o.clock = clock.System()
			return newPGStatementLimiter(t, conn, ns, limit, window, o, nil, pgStatement(t, pgRecordName), "5000ms")
		}),
		failsCase: "with no clock configured the statements pass no time",
		failsWith: "the record passed an application time with no clock configured",
	},
)

// TestPGLimiter_DatabaseClockBroken is the child half of
// TestPGLimiter_DatabaseClockCatchesBrokenVariants. Without a variant named it
// skips.
func TestPGLimiter_DatabaseClockBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_DatabaseClockCatchesBrokenVariants", pgDatabaseClockBroken)
}

func TestPGLimiter_DatabaseClockCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_DatabaseClockBroken", pgDatabaseClockBroken)
}
