package test

// The PostgreSQL limiter benchmark. It measures, for both backends, how the
// table's storage parameters, the load shape and the pool arrangement change
// latency, the share of HOT updates, table size, prune time and the cost to a
// login path that shares the pool. Narrow the sweep with -bench, for example
//
//	go test -run '^$' -bench 'PostgresLimiter/ff=70/av=default/load=hot' .
//
// Case names read ff=<fillfactor>/av=<default|low>/load=<hot|distinct|checkheavy>
// /pool=<own|shared>/backend=<sqlstore|pgx>. The server is the tuned test
// server (fsync off, data on tmpfs), so WAL cost and disk latency are
// understated; relative differences between cases are the finding, not the
// absolute numbers.
//
// Under -benchtime=Nx every case runs exactly N operations; the distinct load
// tops its key count up to benchDistinctKeys with unmeasured records first.

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/migrate"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
)

const (
	benchNamespace    = "bench"
	benchHotKeys      = 100
	benchRecorders    = 32
	benchDistinctKeys = 100_000
	benchLimit        = 10
	benchWindow       = 15 * time.Minute
	benchPoolConns    = 32

	benchLoginRate    = 300 // simulated logins per second
	benchLoginWorkers = 8
	benchLoginUsers   = 1000

	benchPruneReps = 3 // prune repetitions per size; -benchtime does not apply
)

// percentile is the nearest-rank percentile p (0..100) of sorted, which must
// be in ascending order. It is 0 for no samples.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

func TestBenchPercentile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		samples []int64
		p       float64
		assert  func(t *testing.T, got int64)
	}

	hundred := make([]int64, 100)
	for i := range hundred {
		hundred[i] = int64(i + 1)
	}

	cases := []testCase{
		{name: "no samples", p: 99, assert: func(t *testing.T, got int64) { assert.Zero(t, got) }},
		{name: "one sample", samples: []int64{7}, p: 99, assert: func(t *testing.T, got int64) { assert.EqualValues(t, 7, got) }},
		{name: "median of 100", samples: hundred, p: 50, assert: func(t *testing.T, got int64) { assert.EqualValues(t, 50, got) }},
		{name: "p99 of 100", samples: hundred, p: 99, assert: func(t *testing.T, got int64) { assert.EqualValues(t, 99, got) }},
		{name: "p100 is the max", samples: hundred, p: 100, assert: func(t *testing.T, got int64) { assert.EqualValues(t, 100, got) }},
		{name: "p0 clamps to the min", samples: hundred, p: 0, assert: func(t *testing.T, got int64) { assert.EqualValues(t, 1, got) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, percentile(tc.samples, tc.p))
		})
	}
}

// benchSamples is a mutex-guarded sink the workers merge their local latency
// slices into once, so recording an operation never contends.
type benchSamples struct {
	mu   sync.Mutex
	data []int64
}

func (s *benchSamples) merge(local []int64) {
	if len(local) == 0 {
		return
	}
	s.mu.Lock()
	s.data = append(s.data, local...)
	s.mu.Unlock()
}

// report adds the p50 and p99 of the samples, in nanoseconds, as prefix-p50-ns
// and prefix-p99-ns. It adds nothing for an empty sink.
func (s *benchSamples) report(b *testing.B, prefix string) {
	b.Helper()
	if len(s.data) == 0 {
		return
	}
	slices.Sort(s.data)
	b.ReportMetric(float64(percentile(s.data, 50)), prefix+"-p50-ns")
	b.ReportMetric(float64(percentile(s.data, 99)), prefix+"-p99-ns")
}

// benchPool is one backend's connection pool, with the limiter built on it and
// the login statements that share it.
type benchPool struct {
	limiter func(ns string) (ratelimit.Limiter, error)
	login   func(ctx context.Context, user string) error
	close   func()
}

type benchBackend struct {
	name string
	open func(b *testing.B, conn PostgresConn) benchPool
}

var benchBackends = []benchBackend{
	{name: "sqlstore", open: func(b *testing.B, conn PostgresConn) benchPool {
		return benchPool{
			limiter: func(ns string) (ratelimit.Limiter, error) {
				return sqlstore.NewLimiter(conn.DB, ns, benchLimit, benchWindow,
					sqlstore.WithLimiterOperationTimeout(pgTestTimeout),
					sqlstore.WithLimiterLogger(slog.New(slog.DiscardHandler)))
			},
			login: func(ctx context.Context, user string) error {
				var n int
				if err := conn.DB.QueryRowContext(ctx,
					`SELECT count(*) FROM login_attempts WHERE username = $1 AND attempted_at > now() - interval '15 minutes'`,
					user).Scan(&n); err != nil {
					return err
				}
				_, err := conn.DB.ExecContext(ctx,
					`INSERT INTO login_attempts (id, username, attempted_at) VALUES (gen_random_uuid(), $1, now())`, user)
				return err
			},
			close: func() {},
		}
	}},
	{name: "pgx", open: func(b *testing.B, conn PostgresConn) benchPool {
		cfg, err := pgxpool.ParseConfig(conn.DSN)
		require.NoError(b, err)
		cfg.MaxConns = benchPoolConns
		pool, err := pgxpool.NewWithConfig(b.Context(), cfg)
		require.NoError(b, err)
		return benchPool{
			limiter: func(ns string) (ratelimit.Limiter, error) {
				return pgxstore.NewLimiter(pool, ns, benchLimit, benchWindow,
					pgxstore.WithLimiterOperationTimeout(pgTestTimeout),
					pgxstore.WithLimiterLogger(slog.New(slog.DiscardHandler)))
			},
			login: func(ctx context.Context, user string) error {
				var n int
				if err := pool.QueryRow(ctx,
					`SELECT count(*) FROM login_attempts WHERE username = $1 AND attempted_at > now() - interval '15 minutes'`,
					user).Scan(&n); err != nil {
					return err
				}
				_, err := pool.Exec(ctx,
					`INSERT INTO login_attempts (id, username, attempted_at) VALUES (gen_random_uuid(), $1, now())`, user)
				return err
			},
			close: pool.Close,
		}
	}},
}

// provisionBenchPostgres starts an own server with the security-state set
// applied. RunTestPostgres takes a *testing.T, so this repeats its steps for a
// *testing.B with the same helpers.
func provisionBenchPostgres(b *testing.B) PostgresConn {
	b.Helper()

	set := migrate.SecurityState()
	cfg := &testConfig{}
	for _, opt := range []TestOption{
		WithTestPostgresOwnServer(),
		WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable),
	} {
		opt(cfg)
	}
	requireHealthyProvider(b)

	ctr, err := startPostgresContainerWith(b.Context(), resolvePostgresImage(cfg), false)
	require.NoError(b, err, "failed to start PostgreSQL test container")
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), postgresTerminateTimeout)
		defer cancel()
		if err := ctr.Terminate(ctx); err != nil {
			b.Errorf("failed to terminate PostgreSQL container: %s", err)
		}
	})
	srv, err := newOwnPostgresServer(b.Context(), resolvePostgresImage(cfg), ctr)
	require.NoError(b, err)
	b.Cleanup(func() { _ = srv.admin.Close() })

	return postgresProvision(b, srv, cfg)
}

type benchCase struct {
	ff      int
	av      string // "default" or "low"
	load    string // "hot", "distinct" or "checkheavy"
	shared  bool
	backend benchBackend
}

func (c benchCase) name() string {
	pool := "own"
	if c.shared {
		pool = "shared"
	}
	return fmt.Sprintf("ff=%d/av=%s/load=%s/pool=%s/backend=%s", c.ff, c.av, c.load, pool, c.backend.name)
}

// benchConfigure sets the table's storage parameters for a case and leaves it
// empty and compacted.
func benchConfigure(b *testing.B, db *sql.DB, c benchCase) {
	b.Helper()
	ctx := b.Context()

	exec := func(q string) {
		b.Helper()
		_, err := db.ExecContext(ctx, q)
		require.NoError(b, err, q)
	}
	exec(fmt.Sprintf(`ALTER TABLE rate_limit_buckets SET (fillfactor = %d)`, c.ff))
	if c.av == "low" {
		exec(`ALTER TABLE rate_limit_buckets SET (autovacuum_vacuum_scale_factor = 0.01, autovacuum_vacuum_insert_scale_factor = 0.01)`)
	} else {
		exec(`ALTER TABLE rate_limit_buckets RESET (autovacuum_vacuum_scale_factor, autovacuum_vacuum_insert_scale_factor)`)
	}
	exec(`TRUNCATE rate_limit_buckets, login_attempts`)
	exec(`VACUUM FULL rate_limit_buckets`)
	exec(`VACUUM FULL login_attempts`)
}

// tupleCounters reads the table's cumulative update counters after letting
// every backend's pending statistics flush.
func tupleCounters(b *testing.B, db *sql.DB) (upd, hot int64) {
	b.Helper()

	// A backend flushes its pending statistics when it exits, and an idle one
	// only after up to ten seconds, so close the idle connections first. The
	// caller closes the limiter's own pool before reading.
	db.SetMaxIdleConns(0)
	db.SetMaxIdleConns(2)
	time.Sleep(500 * time.Millisecond)
	conn, err := db.Conn(b.Context())
	require.NoError(b, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(b.Context(), `SELECT pg_stat_force_next_flush()`)
	require.NoError(b, err)
	require.NoError(b, conn.QueryRowContext(b.Context(),
		`SELECT coalesce(max(n_tup_upd), 0), coalesce(max(n_tup_hot_upd), 0) FROM pg_stat_user_tables WHERE relname = 'rate_limit_buckets'`,
	).Scan(&upd, &hot))
	return upd, hot
}

// benchErrors counts failed operations and logs the first.
type benchErrors struct {
	n     atomic.Int64
	first sync.Once
}

func (e *benchErrors) note(b *testing.B, err error) {
	e.n.Add(1)
	e.first.Do(func() { b.Logf("first operation error: %v", err) })
}

// loginLoad is the simulated login path: logins arrive at a fixed rate, each
// a select and an insert, and its latency counts from the arrival, so a queue
// behind a starved pool shows.
type loginLoad struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
	lat    benchSamples
	errs   atomic.Int64
	drops  atomic.Int64
}

func startLoginLoad(parent context.Context, p benchPool) *loginLoad {
	ctx, cancel := context.WithCancel(parent)
	l := &loginLoad{cancel: cancel}
	arrivals := make(chan time.Time, 1024)

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer close(arrivals)
		tick := time.NewTicker(time.Second / benchLoginRate)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case at := <-tick.C:
				select {
				case arrivals <- at:
				default:
					l.drops.Add(1)
				}
			}
		}
	}()
	for w := range benchLoginWorkers {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			rng := rand.New(rand.NewPCG(uint64(w), 7))
			var local []int64
			for at := range arrivals {
				user := "login-user-" + strconv.Itoa(rng.IntN(benchLoginUsers))
				if err := p.login(context.Background(), user); err != nil {
					l.errs.Add(1)
					continue
				}
				local = append(local, time.Since(at).Nanoseconds())
			}
			l.lat.merge(local)
		}()
	}
	return l
}

func (l *loginLoad) stop(b *testing.B) {
	b.Helper()
	l.cancel()
	l.wg.Wait()
	l.lat.report(b, "login")
	b.ReportMetric(float64(l.errs.Load()), "login-errors")
	b.ReportMetric(float64(l.drops.Load()), "login-dropped")
}

func runBenchCase(b *testing.B, conn PostgresConn, c benchCase) {
	benchConfigure(b, conn.DB, c)
	pool := c.backend.open(b, conn)
	defer pool.close()

	lim, err := pool.limiter(benchNamespace)
	require.NoError(b, err)

	var errs benchErrors
	hotKey := func(i int) string { return "hot-" + strconv.Itoa(i%benchHotKeys) }
	var distinct atomic.Int64
	distinctKey := func() string { return "key-" + strconv.FormatInt(distinct.Add(1), 10) }

	// Warm the connections, then, for the distinct load, fill the keys b.N
	// does not cover, unmeasured.
	if c.load == "distinct" {
		if fill := benchDistinctKeys - b.N; fill > 0 {
			var next atomic.Int64
			var wg sync.WaitGroup
			for range benchRecorders {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for next.Add(1) <= int64(fill) {
						if err := lim.RecordFailure(context.Background(), distinctKey()); err != nil {
							errs.note(b, err)
						}
					}
				}()
			}
			wg.Wait()
		}
	}
	updBefore, hotBefore := tupleCounters(b, conn.DB)

	var login *loginLoad
	if c.shared {
		login = startLoginLoad(b.Context(), pool)
	}

	var checks, records benchSamples
	var workers atomic.Uint64
	b.SetParallelism(max(1, (benchRecorders+runtime.GOMAXPROCS(0)-1)/runtime.GOMAXPROCS(0)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		id := workers.Add(1)
		rng := rand.New(rand.NewPCG(id, 1))
		lc := make([]int64, 0, 4096)
		lr := make([]int64, 0, 4096)
		n := int(id) * 7
		ctx := context.Background()
		for pb.Next() {
			n++
			var (
				err    error
				isRead bool
			)
			start := time.Now()
			switch c.load {
			case "hot":
				err = lim.RecordFailure(ctx, hotKey(n))
			case "distinct":
				err = lim.RecordFailure(ctx, distinctKey())
			default: // checkheavy
				if rng.IntN(100) < 95 {
					isRead = true
					_, err = lim.Exceeded(ctx, hotKey(rng.IntN(benchHotKeys)))
				} else {
					err = lim.RecordFailure(ctx, hotKey(rng.IntN(benchHotKeys)))
				}
			}
			d := time.Since(start).Nanoseconds()
			switch {
			case err != nil:
				errs.note(b, err)
			case isRead:
				lc = append(lc, d)
			default:
				lr = append(lr, d)
			}
		}
		checks.merge(lc)
		records.merge(lr)
	})
	b.StopTimer()

	if login != nil {
		login.stop(b)
	}
	checks.report(b, "check")
	records.report(b, "record")
	b.ReportMetric(float64(errs.n.Load()), "errors")

	pool.close() // ends the pool's sessions, which flushes their statistics
	updAfter, hotAfter := tupleCounters(b, conn.DB)
	if upd := updAfter - updBefore; upd > 0 {
		b.ReportMetric(float64(hotAfter-hotBefore)/float64(upd), "hot-ratio")
	} else {
		b.ReportMetric(-1, "hot-ratio") // no updates happened: not applicable
	}
	var size int64
	require.NoError(b, conn.DB.QueryRowContext(b.Context(),
		`SELECT pg_total_relation_size('rate_limit_buckets')`).Scan(&size))
	b.ReportMetric(float64(size), "table-bytes")
}

func BenchmarkPostgresLimiter(b *testing.B) {
	if testing.Short() {
		b.Skip("the PostgreSQL limiter benchmark starts a server and is long")
	}
	conn := provisionBenchPostgres(b)

	for _, ff := range []int{100, 90, 70, 50} {
		for _, av := range []string{"default", "low"} {
			for _, load := range []string{"hot", "distinct", "checkheavy"} {
				for _, shared := range []bool{false, true} {
					for _, be := range benchBackends {
						c := benchCase{ff: ff, av: av, load: load, shared: shared, backend: be}
						b.Run(c.name(), func(b *testing.B) { runBenchCase(b, conn, c) })
					}
				}
			}
		}
	}
}

// BenchmarkPostgresLimiterLoginBaseline is the login load alone on a pool,
// the comparison for the login-p99-ns of the shared-pool cases.
func BenchmarkPostgresLimiterLoginBaseline(b *testing.B) {
	if testing.Short() {
		b.Skip("the PostgreSQL limiter benchmark starts a server and is long")
	}
	conn := provisionBenchPostgres(b)

	for _, be := range benchBackends {
		b.Run("backend="+be.name, func(b *testing.B) {
			benchConfigure(b, conn.DB, benchCase{ff: 70, av: "default"})
			pool := be.open(b, conn)
			defer pool.close()

			login := startLoginLoad(b.Context(), pool)
			b.ResetTimer()
			time.Sleep(time.Duration(b.N) * time.Second / benchLoginRate)
			b.StopTimer()
			login.stop(b)
		})
	}
}

// BenchmarkPostgresLimiterPrune times one factory Prune over idle rows. The
// refill between repetitions is not timed. -benchtime does not apply: each
// size runs benchPruneReps times and reports the mean as ns/op.
func BenchmarkPostgresLimiterPrune(b *testing.B) {
	if testing.Short() {
		b.Skip("the PostgreSQL limiter benchmark starts a server and is long")
	}
	conn := provisionBenchPostgres(b)

	for _, rows := range []int{100_000, 1_000_000} {
		for _, be := range []struct {
			name  string
			prune func(b *testing.B) (func(context.Context) (int, error), func())
		}{
			{"sqlstore", func(b *testing.B) (func(context.Context) (int, error), func()) {
				f, err := sqlstore.NewLimiterFactory(conn.DB, sqlstore.WithLimiterLogger(slog.New(slog.DiscardHandler)))
				require.NoError(b, err)
				return f.Prune, func() {}
			}},
			{"pgx", func(b *testing.B) (func(context.Context) (int, error), func()) {
				pool, err := pgxpool.New(b.Context(), conn.DSN)
				require.NoError(b, err)
				f, err := pgxstore.NewLimiterFactory(pool, pgxstore.WithLimiterLogger(slog.New(slog.DiscardHandler)))
				require.NoError(b, err)
				return f.Prune, pool.Close
			}},
		} {
			b.Run(fmt.Sprintf("rows=%d/backend=%s", rows, be.name), func(b *testing.B) {
				prune, closePool := be.prune(b)
				defer closePool()

				var total time.Duration
				var errCount, wrong int64
				for range benchPruneReps {
					for _, q := range []string{`TRUNCATE rate_limit_buckets`, fmt.Sprintf(
						`INSERT INTO rate_limit_buckets (namespace, key, stamps, newest_at, longest_window_us)
						 SELECT 'bench', 'k' || g, ARRAY[now() - interval '1 hour']::timestamptz[], now() - interval '1 hour', 1000000
						 FROM generate_series(1, %d) g`, rows), `VACUUM ANALYZE rate_limit_buckets`} {
						_, err := conn.DB.ExecContext(b.Context(), q)
						require.NoError(b, err, q)
					}
					start := time.Now()
					removed, err := prune(b.Context())
					total += time.Since(start)
					if err != nil {
						errCount++
						b.Logf("prune error: %v", err)
					} else if removed != rows {
						wrong++
					}
				}
				b.ReportMetric(float64(rows), "rows")
				b.ReportMetric(float64(total.Nanoseconds())/benchPruneReps, "ns/op")
				b.ReportMetric(float64(errCount), "errors")
				b.ReportMetric(float64(wrong), "wrong-removed")
			})
		}
	}
}
