package test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
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
// run covers every namespace, and a prune racing records on an idle key never
// loses a live count.
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
				require.NoError(t, err)
				assert.Less(t, elapsed, 500*time.Millisecond, "the prune waited on the held row")
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
			name: "prune racing records on an idle key never loses a live count",
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
// window, $2, rather than by the longest window recorded for each key.
const pgPruneByCheckingWindow = `WITH t AS (SELECT coalesce($1::timestamptz, clock_timestamp()) AS now),
victims AS (
  SELECT b.namespace, b.key FROM rate_limit_buckets b CROSS JOIN t
  WHERE b.newest_at + $2::bigint * interval '1 microsecond' <= t.now
  FOR UPDATE OF b SKIP LOCKED)
DELETE FROM rate_limit_buckets d USING victims v
WHERE d.namespace = v.namespace AND d.key = v.key`

// pgWindowPruneFactory is a factory whose prune runs pgPruneByCheckingWindow
// with the window of the instance checking, one minute.
type pgWindowPruneFactory struct {
	pgFactory // the real factory, for NewLimiter and Verify

	db  *sql.DB
	clk *clockwork.FakeClock
}

func (f *pgWindowPruneFactory) Prune(ctx context.Context) (int, error) {
	res, err := f.db.ExecContext(ctx, pgPruneByCheckingWindow,
		f.clk.Now().UTC().Truncate(time.Microsecond), time.Minute.Microseconds())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

var pgPruneBroken = pgFaultVariants(runPGPrune, pgFaultVariant{
	name: "prune-by-checking-window",
	backend: func() pgFaultBackend {
		b := sqlstoreFaultBackend
		b.name = pgFaultBrokenBackend
		b.factory = func(t *testing.T, conn PostgresConn, o pgFaultOptions) pgFactory {
			t.Helper()
			clk, ok := o.clock.(*clockwork.FakeClock)
			require.True(t, ok, "the prune cases run on a fake clock")
			return &pgWindowPruneFactory{
				pgFactory: sqlstoreFaultBackend.factory(t, conn, o),
				db:        pgFaultDB(t, conn, nil),
				clk:       clk,
			}
		}
		return b
	}(),
	failsCase: "longest recorded window protects a key",
	failsWith: "the prune removed a key a 15-minute instance still counts",
})

// TestPGLimiter_PruneBroken is the child half of
// TestPGLimiter_PruneCatchesBrokenVariants. Without a variant named it skips.
func TestPGLimiter_PruneBroken(t *testing.T) {
	storefix.RunBrokenChild(t, pgFaultBrokenVar, "TestPGLimiter_PruneCatchesBrokenVariants", pgPruneBroken)
}

func TestPGLimiter_PruneCatchesBrokenVariants(t *testing.T) {
	t.Parallel()

	catchPGFaultVariants(t, "TestPGLimiter_PruneBroken", pgPruneBroken)
}
