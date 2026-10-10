package test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kartaladev/scrty/migrate"
	"github.com/kartaladev/scrty/pkg/id"
)

func TestRunTestPostgres(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, a, b PostgresConn)
	}

	cases := []testCase{
		{
			name: "isolated databases",
			assert: func(t *testing.T, a, b PostgresConn) {
				ctx := t.Context()
				for _, c := range []PostgresConn{a, b} {
					_, err := c.DB.ExecContext(ctx, `CREATE TABLE probe (id uuid PRIMARY KEY, val text)`)
					require.NoError(t, err)
				}

				// Both sides write under the same key: isolation must come
				// from the databases being different, not from the keys
				// being different.
				key := id.MustParse("0192f000-0000-7000-8000-000000000001")
				_, err := a.DB.ExecContext(ctx, `INSERT INTO probe VALUES ($1, $2)`, key, "a")
				require.NoError(t, err)
				_, err = b.DB.ExecContext(ctx, `INSERT INTO probe VALUES ($1, $2)`, key, "b")
				require.NoError(t, err)

				for _, side := range []struct {
					conn PostgresConn
					want string
				}{{a, "a"}, {b, "b"}} {
					var n int
					require.NoError(t, side.conn.DB.QueryRowContext(ctx, `SELECT count(*) FROM probe`).Scan(&n))
					assert.Equal(t, 1, n, "a row written through the other helper database is visible here")

					var val string
					require.NoError(t, side.conn.DB.QueryRowContext(ctx,
						`SELECT val FROM probe WHERE id = $1`, key).Scan(&val))
					assert.Equal(t, side.want, val, "this database sees the other side's row instead of its own")
				}
			},
		},
		{
			name: "native uuid round trip",
			assert: func(t *testing.T, a, _ PostgresConn) {
				ctx := t.Context()
				want, err := id.NewV7Generator().NewID()
				require.NoError(t, err)

				_, err = a.DB.ExecContext(ctx, `CREATE TABLE rt (id uuid PRIMARY KEY)`)
				require.NoError(t, err)
				_, err = a.DB.ExecContext(ctx, `INSERT INTO rt VALUES ($1)`, want)
				require.NoError(t, err)

				var got id.ID
				require.NoError(t, a.DB.QueryRowContext(ctx, `SELECT id FROM rt`).Scan(&got))
				assert.Equal(t, want, got)
			},
		},
		{
			name: "DSN reaches the same database",
			assert: func(t *testing.T, a, _ PostgresConn) {
				ctx := t.Context()
				_, err := a.DB.ExecContext(ctx, `CREATE TABLE seen (n int)`)
				require.NoError(t, err)

				other, err := sql.Open("pgx", a.DSN)
				require.NoError(t, err)
				t.Cleanup(func() { _ = other.Close() })

				var n int
				require.NoError(t, other.QueryRowContext(ctx, `SELECT count(*) FROM seen`).Scan(&n))
				assert.Zero(t, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, RunTestPostgres(t), RunTestPostgres(t))
		})
	}
}

// errUnhealthyProvider stands in for whatever error a real Docker provider
// health check would return, to simulate an unhealthy provider without
// touching Docker.
var errUnhealthyProvider = errors.New("simulated: docker is not healthy")

// recordingTB stands in for testing.TB while postgresSetUp or
// requireHealthyProvider run, so what they report is observed by the real
// test instead of ending it. Its Fatalf and Skipf stop only the goroutine
// that calls them, the way testing.T's do (runtime.Goexit, not a panic), so a
// caller must run the call under runRecorded and inspect the results
// afterward.
type recordingTB struct {
	ctx      context.Context
	cleanups []func()
	errs     []string
	skips    []string
}

func (r *recordingTB) Helper()                      {}
func (r *recordingTB) Cleanup(f func())             { r.cleanups = append(r.cleanups, f) }
func (r *recordingTB) Context() context.Context     { return r.ctx }
func (r *recordingTB) Errorf(f string, args ...any) { r.errs = append(r.errs, fmt.Sprintf(f, args...)) }

func (r *recordingTB) Fatalf(f string, args ...any) {
	r.Errorf(f, args...)
	runtime.Goexit()
}

func (r *recordingTB) Skipf(f string, args ...any) {
	r.skips = append(r.skips, fmt.Sprintf(f, args...))
	runtime.Goexit()
}

// runCleanups runs the registered cleanups last first, as the testing
// package does.
func (r *recordingTB) runCleanups() {
	r.runLastCleanups(len(r.cleanups))
}

// runLastCleanups runs the n cleanups registered last, last first, and
// forgets them, so a test can observe the state between two cleanups.
func (r *recordingTB) runLastCleanups(n int) {
	for range n {
		last := len(r.cleanups) - 1
		f := r.cleanups[last]
		r.cleanups = r.cleanups[:last]
		f()
	}
}

// runRecorded runs f on its own goroutine and waits for it to finish. f is
// expected to call into a recordingTB, whose Fatalf and Skipf end only that
// goroutine (runtime.Goexit): running f directly, on the calling test's own
// goroutine, would let such a call end the real test early instead of
// recording it.
func runRecorded(f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	<-done
}

func TestPostgresTeardown(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// Either dir (+ versionTable, defaulting to "goose_probe") for a
		// single migration set, or sets for several — sets wins when given.
		dir                string
		versionTable       string
		sets               []postgresMigrations
		finalizers         []string
		leftoverTableCheck bool
		before             func(t *testing.T, db *sql.DB) // runs between set-up and teardown
		assert             func(t *testing.T, db *sql.DB, errs []string)
	}

	cases := []testCase{
		{
			name: "clean rollback reports nothing",
			dir:  "testdata/migrations/good",
			assert: func(t *testing.T, db *sql.DB, errs []string) {
				assert.Empty(t, errs)

				var n int
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename = 'probe_a'`).Scan(&n))
				assert.Zero(t, n, "the set was not rolled back")
			},
		},
		{
			name: "rollback error fails the test",
			dir:  "testdata/migrations/good",
			before: func(t *testing.T, db *sql.DB) {
				// The set's Down drops probe_a without IF EXISTS, so dropping
				// it first makes the rollback fail.
				_, err := db.ExecContext(t.Context(), `DROP TABLE probe_a`)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0], "roll back migrations")
				assert.Contains(t, errs[0], "testdata/migrations/good")
			},
		},
		{
			name:               "forgotten table in a rollback is named",
			dir:                "testdata/migrations/forgets_table",
			leftoverTableCheck: true,
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0], "tables left behind")
				assert.Contains(t, errs[0], "probe_b")
				assert.NotContains(t, errs[0], "probe_a")
			},
		},
		{
			// A finalize script cleans up the table the rollback forgot, so the
			// check passes only if it runs after the scripts, not before them.
			name:               "leftover check runs after the finalize scripts",
			dir:                "testdata/migrations/forgets_table",
			finalizers:         []string{`DROP TABLE probe_b`},
			leftoverTableCheck: true,
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				assert.Empty(t, errs)
			},
		},
		{
			// The registered version table is not named "goose_probe" here,
			// so a check that still exempted it by a "goose%" name pattern
			// would report nothing wrong for the wrong reason; a check that
			// exempted nothing would instead report the version table
			// itself as leftover. Only exempting exactly the registered name
			// passes this case.
			name:               "leftover check exempts exactly the registered version table",
			dir:                "testdata/migrations/good",
			versionTable:       "auth_schema_versions",
			leftoverTableCheck: true,
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				assert.Empty(t, errs)
			},
		},
		{
			// The table left behind here is named like a goose version
			// table but is not one of the sets' registered version tables,
			// so a name-pattern exemption would silently miss it.
			name:               "leftover check names a table shaped like a goose version table",
			dir:                "testdata/migrations/goose_like_leftover",
			leftoverTableCheck: true,
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0], "goose_like_but_real")
			},
		},
		{
			// dep_child references dep_parent, so rolling back dep_parent
			// before dep_child fails with a foreign key violation. Only
			// rolling back the second-registered set (dep_child) first
			// succeeds.
			name: "reverse rollback across sets",
			sets: []postgresMigrations{
				{fsys: os.DirFS("."), dir: "testdata/migrations/dep_parent", versionTable: "goose_dep_parent"},
				{fsys: os.DirFS("."), dir: "testdata/migrations/dep_child", versionTable: "goose_dep_child"},
			},
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				assert.Empty(t, errs, "the dependent set must roll back before the set it depends on")
			},
		},
		{
			name: "finalize scripts run after rollback in declared order",
			dir:  "testdata/migrations/good",
			finalizers: []string{
				// Fails unless the rollback already dropped probe_a.
				`DO $$ BEGIN
					IF to_regclass('probe_a') IS NOT NULL THEN RAISE EXCEPTION 'ran before rollback'; END IF;
				END $$;
				CREATE TABLE finalize_log (seq serial, script int);
				INSERT INTO finalize_log (script) VALUES (1)`,
				// Fails unless the first script already ran.
				`INSERT INTO finalize_log (script) VALUES (2)`,
			},
			assert: func(t *testing.T, db *sql.DB, errs []string) {
				require.Empty(t, errs)

				rows, err := db.QueryContext(t.Context(), `SELECT script FROM finalize_log ORDER BY seq`)
				require.NoError(t, err)
				defer func() { _ = rows.Close() }()

				var order []int
				for rows.Next() {
					var n int
					require.NoError(t, rows.Scan(&n))
					order = append(order, n)
				}
				require.NoError(t, rows.Err())
				assert.Equal(t, []int{1, 2}, order)
			},
		},
		{
			// Up fails partway (the fixture's only statement is invalid
			// SQL). postgresSetUp must record that as a failure of the
			// recorder it was given, not panic or otherwise abort the test
			// binary — proven by this case reaching its assertion at all.
			name: "a migration that fails Up is recorded as a failure, not a panic",
			dir:  "testdata/migrations/broken_up",
			assert: func(t *testing.T, _ *sql.DB, errs []string) {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0], "apply migrations")
				assert.Contains(t, errs[0], "testdata/migrations/broken_up")
			},
		},
	}

	// Each case runs twice, with the same assertions: once applying the sets
	// directly to an empty database (postgresSetUp), and once the way
	// RunTestPostgres does, on a clone of the sets' template
	// (postgresProvision). The second proves the teardown is as strong on a
	// clone as on a database the sets were applied to.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sets := tc.sets
			if sets == nil {
				versionTable := tc.versionTable
				if versionTable == "" {
					versionTable = "goose_probe"
				}
				sets = []postgresMigrations{{fsys: os.DirFS("."), dir: tc.dir, versionTable: versionTable}}
			}
			newCfg := func() *testConfig {
				return &testConfig{
					migrations:         sets,
					finalizers:         tc.finalizers,
					leftoverTableCheck: tc.leftoverTableCheck,
				}
			}

			t.Run("applied", func(t *testing.T) {
				t.Parallel()

				conn := RunTestPostgres(t)
				rec := &recordingTB{ctx: t.Context()}
				runRecorded(func() { postgresSetUp(rec, conn.DB, newCfg()) })
				if tc.before != nil {
					tc.before(t, conn.DB)
				}

				rec.runCleanups()
				tc.assert(t, conn.DB, rec.errs)
			})

			t.Run("cloned", func(t *testing.T) {
				t.Parallel()

				srv := sharedTestPostgresServer(t)
				rec := &recordingTB{ctx: t.Context()}
				var conn PostgresConn
				runRecorded(func() { conn = postgresProvision(rec, srv, newCfg()) })
				// Undone even when an assertion below stops the test.
				t.Cleanup(rec.runCleanups)

				fp, err := postgresFingerprint(sets)
				require.NoError(t, err)
				tpl := postgresTemplatePrefix + fp
				if conn.DB == nil {
					// The sets never applied: no template of them may remain.
					var n int
					require.NoError(t, srv.admin.QueryRowContext(t.Context(),
						`SELECT count(*) FROM pg_database WHERE datname = $1`, tpl).Scan(&n))
					assert.Zero(t, n, "a template whose sets failed to apply remains")
					tc.assert(t, nil, rec.errs)
					return
				}
				var isTemplate, allowConn bool
				require.NoError(t, srv.admin.QueryRowContext(t.Context(),
					`SELECT datistemplate, datallowconn FROM pg_database WHERE datname = $1`, tpl).Scan(&isTemplate, &allowConn),
					"the call's database was not cloned from a template of its sets")
				assert.True(t, isTemplate)
				assert.False(t, allowConn)

				if tc.before != nil {
					tc.before(t, conn.DB)
				}
				// Only the migration teardown, the cleanup registered last:
				// the database is still open and still there.
				rec.runLastCleanups(1)
				tc.assert(t, conn.DB, rec.errs)

				var name string
				require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&name))
				reported := len(rec.errs)
				rec.runCleanups()
				assert.Len(t, rec.errs, reported, "closing or dropping the call's database failed: %v", rec.errs)
				var n int
				require.NoError(t, srv.admin.QueryRowContext(t.Context(),
					`SELECT count(*) FROM pg_database WHERE datname = $1`, name).Scan(&n))
				assert.Zero(t, n, "the call's database %s outlived its teardown", name)
			})
		})
	}
}

// sharedTestPostgresServer returns the server RunTestPostgres shares in this
// process for the default image.
func sharedTestPostgresServer(t *testing.T) *postgresServer {
	t.Helper()
	requireHealthyProvider(t)

	srv, err := defaultPostgresRegistry.server(resolvePostgresImage(&testConfig{}))
	require.NoError(t, err)
	return srv
}

// A set that cannot be applied is a wiring mistake, so it stops the test at
// set-up, before the database is used; these cases need no database.
func TestPostgresSetUpRejectsMigrationWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		set    postgresMigrations
		assert func(t *testing.T, errs []string)
	}

	cases := []testCase{
		{
			name: "nil file system",
			set:  postgresMigrations{dir: "testdata/migrations/good", versionTable: "goose_probe"},
			assert: func(t *testing.T, errs []string) {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0], "no file system")
			},
		},
		{
			name: "empty version table",
			set:  postgresMigrations{fsys: os.DirFS("."), dir: "testdata/migrations/good"},
			assert: func(t *testing.T, errs []string) {
				require.Len(t, errs, 1)
				assert.Contains(t, errs[0], "no version table")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &recordingTB{ctx: t.Context()}
			runRecorded(func() {
				postgresSetUp(rec, nil, &testConfig{migrations: []postgresMigrations{tc.set}})
			})
			tc.assert(t, rec.errs)
		})
	}
}

// Not parallel: each case sets the process environment.
func TestRequireHealthyProviderNoSilentSkipInCI(t *testing.T) {
	type testCase struct {
		name   string
		ci     string // "" means unset
		assert func(t *testing.T, rec *recordingTB)
	}

	cases := []testCase{
		{
			name: "unhealthy provider skips locally",
			assert: func(t *testing.T, rec *recordingTB) {
				assert.Empty(t, rec.errs)
				require.Len(t, rec.skips, 1)
				assert.Contains(t, rec.skips[0], "Docker")
			},
		},
		{
			name: "unhealthy provider fails the test when CI is set",
			ci:   "true",
			assert: func(t *testing.T, rec *recordingTB) {
				assert.Empty(t, rec.skips)
				require.Len(t, rec.errs, 1)
				assert.Contains(t, rec.errs[0], "CI is set")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(ciEnv, tc.ci)

			restore := postgresProviderHealth
			postgresProviderHealth = func() error { return errUnhealthyProvider }
			t.Cleanup(func() { postgresProviderHealth = restore })

			rec := &recordingTB{ctx: t.Context()}
			runRecorded(func() { requireHealthyProvider(rec) })

			tc.assert(t, rec)
		})
	}
}

// Not parallel: each case sets the process environment.
func TestRunTestPostgresImage(t *testing.T) {
	type testCase struct {
		name   string
		env    string // "" means unset
		opts   []TestOption
		assert func(t *testing.T, version string)
	}

	const postgres15 = "postgres:15.19-alpine"

	cases := []testCase{
		{
			name: "default is PostgreSQL 18",
			assert: func(t *testing.T, version string) {
				assert.True(t, strings.HasPrefix(version, "18."), "server version %s", version)
			},
		},
		{
			name: "environment selects the image",
			env:  postgres15,
			assert: func(t *testing.T, version string) {
				assert.True(t, strings.HasPrefix(version, "15."), "server version %s", version)
			},
		},
		{
			name: "option overrides the environment",
			env:  postgres15,
			opts: []TestOption{WithTestPostgresImage(postgresImage)},
			assert: func(t *testing.T, version string) {
				assert.True(t, strings.HasPrefix(version, "18."), "server version %s", version)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(PostgresImageEnv, tc.env)

			conn := RunTestPostgres(t, tc.opts...)

			var version string
			require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SHOW server_version`).Scan(&version))
			tc.assert(t, version)
		})
	}
}

// terminateForTest removes a container a test started for itself. It detaches
// from t.Context(), which is already cancelled when cleanup runs, and allows a
// budget above Docker's own 10-second stop grace period.
func terminateForTest(t *testing.T, ctr *postgres.PostgresContainer) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), postgresTerminateTimeout)
	defer cancel()
	if err := ctr.Terminate(ctx); err != nil {
		t.Errorf("failed to terminate PostgreSQL container: %s", err)
	}
}

func TestPostgresServerSharing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(t *testing.T, r *postgresRegistry) []*postgresServer
		assert func(t *testing.T, starts int64, got []*postgresServer)
	}

	cases := []testCase{
		{
			name: "many calls for one image share one server",
			act: func(t *testing.T, r *postgresRegistry) []*postgresServer {
				var out []*postgresServer
				for range 5 {
					s, err := r.server(postgresImage)
					require.NoError(t, err)
					out = append(out, s)
				}
				return out
			},
			assert: func(t *testing.T, starts int64, got []*postgresServer) {
				assert.EqualValues(t, 1, starts)
				for _, s := range got[1:] {
					assert.Same(t, got[0], s)
				}
			},
		},
		{
			name: "a different image gets a server of its own",
			act: func(t *testing.T, r *postgresRegistry) []*postgresServer {
				a, err := r.server("postgres:18.6-alpine")
				require.NoError(t, err)
				b, err := r.server("postgres:15.19-alpine")
				require.NoError(t, err)
				return []*postgresServer{a, b}
			},
			assert: func(t *testing.T, starts int64, got []*postgresServer) {
				assert.EqualValues(t, 2, starts)
				assert.NotSame(t, got[0], got[1])
				var v15 string
				require.NoError(t, got[1].admin.QueryRowContext(t.Context(), `SHOW server_version`).Scan(&v15))
				assert.True(t, strings.HasPrefix(v15, "15."), v15)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireHealthyProvider(t)

			var starts atomic.Int64
			r := &postgresRegistry{start: func(ctx context.Context, image string) (*postgres.PostgresContainer, error) {
				starts.Add(1)
				ctr, err := startPostgresContainer(ctx, image)
				if ctr != nil {
					// The cleanup outlives the start's context, so it must not use it.
					t.Cleanup(func() { terminateForTest(t, ctr) }) //nolint:contextcheck // runs after the start's context is gone
				}
				return ctr, err
			}}

			got := tc.act(t, r)
			tc.assert(t, starts.Load(), got)
		})
	}
}

func TestPostgresServerStartFailureIsRemembered(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(r *postgresRegistry) []error
		assert func(t *testing.T, starts int64, errs []error)
	}

	boomA := errors.New("docker said no to A")
	boomB := errors.New("docker said no to B")
	images := []string{"postgres:18.6-alpine", "postgres:15.19-alpine"}
	failures := map[string]error{images[0]: boomA, images[1]: boomB}

	cases := []testCase{
		{
			name: "sequential calls do not retry",
			act: func(r *postgresRegistry) []error {
				var errs []error
				for range 40 {
					_, err := r.server(images[0])
					errs = append(errs, err)
				}
				return errs
			},
			assert: func(t *testing.T, starts int64, errs []error) {
				assert.EqualValues(t, 1, starts, "a failed start must not be retried")
				for _, err := range errs {
					require.ErrorIs(t, err, boomA)
				}
			},
		},
		{
			name: "concurrent first calls start each image once",
			act: func(r *postgresRegistry) []error {
				const callers = 64
				errs := make([]error, callers)
				var wg sync.WaitGroup
				for i := range callers {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, errs[i] = r.server(images[i%len(images)])
					}()
				}
				wg.Wait()
				return errs
			},
			assert: func(t *testing.T, starts int64, errs []error) {
				assert.EqualValues(t, 2, starts, "concurrent first calls must share one start per image")
				for i, err := range errs {
					require.ErrorIs(t, err, failures[images[i%len(images)]], "call %d got another image's error", i)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var starts atomic.Int64
			r := &postgresRegistry{start: func(_ context.Context, image string) (*postgres.PostgresContainer, error) {
				starts.Add(1)
				// Slow enough that concurrent callers all arrive mid-start.
				time.Sleep(50 * time.Millisecond)
				return nil, failures[image]
			}}

			errs := tc.act(r)
			tc.assert(t, starts.Load(), errs)
		})
	}
}

func TestRunTestPostgresOwnServer(t *testing.T) {
	// Not parallel: it asserts on the state of containers it starts itself.
	shared := RunTestPostgres(t)

	var ownDSN string
	t.Run("own server", func(t *testing.T) {
		own := RunTestPostgres(t, WithTestPostgresOwnServer())
		ownDSN = own.DSN

		require.NoError(t, own.DB.PingContext(t.Context()))
		sharedURL, err := url.Parse(shared.DSN)
		require.NoError(t, err)
		ownURL, err := url.Parse(own.DSN)
		require.NoError(t, err)
		assert.NotEqual(t, sharedURL.Host, ownURL.Host, "an own server must not be the shared one")
	})

	require.NotEmpty(t, ownDSN)
	// Aim at the server's own database, which exists for as long as the
	// server does, so a failure means the server is gone and not that a
	// cloned database was dropped.
	u, err := url.Parse(ownDSN)
	require.NoError(t, err)
	u.Path = "/" + postgresDatabase
	u.RawPath = ""
	serverDSN := u.String()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", serverDSN)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	err = db.PingContext(ctx)
	require.Error(t, err, "the own server must be terminated with its test")
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		assert.NotEqual(t, "3D000", pgErr.Code, "the server answered: only a database is missing, not the server")
	}
}

func TestPostgresConfigError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []TestOption
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "no options is valid",
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "an image is valid",
			opts: []TestOption{WithTestPostgresImage(postgresImage)},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "an empty image is a wiring mistake",
			opts: []TestOption{WithTestPostgresImage("")},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WithTestPostgresImage")
				assert.Contains(t, err.Error(), "empty")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &testConfig{}
			for _, opt := range tc.opts {
				opt(cfg)
			}
			tc.assert(t, cfg.postgresConfigError())
		})
	}
}

func TestEnsureConfigError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []TestOption
		assert func(t *testing.T, err error)
	}

	refused := func(option string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.Error(t, err)
			assert.Contains(t, err.Error(), option)
			assert.Contains(t, err.Error(), "only selects the image")
		}
	}

	cases := []testCase{
		{
			name:   "no options is valid",
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name:   "an image is valid",
			opts:   []TestOption{WithTestPostgresImage(postgresImage)},
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			name:   "an own server is refused",
			opts:   []TestOption{WithTestPostgresOwnServer()},
			assert: refused("WithTestPostgresOwnServer"),
		},
		{
			name:   "a migration set is refused",
			opts:   []TestOption{WithTestPostgresMigrations(probeSet("ensure_probe"), ".", "ensure_versions")},
			assert: refused("WithTestPostgresMigrations"),
		},
		{
			name:   "a finalize script is refused",
			opts:   []TestOption{WithTestPostgresFinalizeScripts("SELECT 1")},
			assert: refused("WithTestPostgresFinalizeScripts"),
		},
		{
			name:   "a leftover table check is refused",
			opts:   []TestOption{WithTestPostgresLeftoverTableCheck()},
			assert: refused("WithTestPostgresLeftoverTableCheck"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &testConfig{}
			for _, opt := range tc.opts {
				opt(cfg)
			}
			tc.assert(t, cfg.ensureConfigError())
		})
	}
}

func TestRunTestPostgresIsolation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "two calls in one test see nothing of each other",
			assert: func(t *testing.T) {
				a := RunTestPostgres(t)
				b := RunTestPostgres(t)
				_, err := a.DB.ExecContext(t.Context(), `CREATE TABLE probe (v int); INSERT INTO probe VALUES (1)`)
				require.NoError(t, err)

				var n int
				require.NoError(t, b.DB.QueryRowContext(t.Context(),
					`SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename = 'probe'`).Scan(&n))
				assert.Zero(t, n, "a table created through one call's database is visible through another's")
				assert.NotEqual(t, a.DSN, b.DSN)
			},
		},
		{
			name: "no sets gives an empty database",
			assert: func(t *testing.T) {
				conn := RunTestPostgres(t)
				var tables []string
				rows, err := conn.DB.QueryContext(t.Context(),
					`SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
				require.NoError(t, err)
				defer func() { _ = rows.Close() }()
				for rows.Next() {
					var name string
					require.NoError(t, rows.Scan(&name))
					tables = append(tables, name)
				}
				require.NoError(t, rows.Err())
				assert.Empty(t, tables, "a call that names no migration set got tables")
			},
		},
		{
			name: "DSN names the call's database",
			assert: func(t *testing.T) {
				conn := RunTestPostgres(t)
				var viaDB string
				require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&viaDB))

				other, err := sql.Open("pgx", conn.DSN)
				require.NoError(t, err)
				t.Cleanup(func() { _ = other.Close() })
				var viaDSN string
				require.NoError(t, other.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&viaDSN))

				assert.Equal(t, viaDB, viaDSN, "DSN reaches another database than DB")
				assert.NotEqual(t, postgresDatabase, viaDSN, "the call got the server's own database")
				assert.True(t, strings.HasPrefix(viaDSN, "t_"), "the call's database %q is not a generated clone", viaDSN)
			},
		},
		{
			name: "fifty parallel calls get fifty databases",
			assert: func(t *testing.T) {
				var mu sync.Mutex
				seen := map[string]bool{}
				t.Run("calls", func(t *testing.T) {
					for i := range 50 {
						t.Run(strconv.Itoa(i), func(t *testing.T) {
							t.Parallel()
							conn := RunTestPostgres(t)
							var name string
							require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&name))
							mu.Lock()
							defer mu.Unlock()
							assert.False(t, seen[name], "database %s handed out twice", name)
							seen[name] = true
						})
					}
				})
				assert.Len(t, seen, 50)
			},
		},
		{
			name: "one call truncating a table leaves another call's rows",
			assert: func(t *testing.T) {
				set := migrate.SecurityState()
				security := WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable)
				sessionID := id.MustParse("0192f000-0000-7000-8000-0000000000aa")

				inserter := RunTestPostgres(t, security)
				truncater := RunTestPostgres(t, security)

				now := time.Now().UTC()
				_, err := inserter.DB.ExecContext(t.Context(), `INSERT INTO sessions
					(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
					VALUES ($1, $2, 'u', $3, $3, $4, $4)`,
					sessionID, []byte("digest"), now, now.Add(time.Hour))
				require.NoError(t, err)

				_, err = truncater.DB.ExecContext(t.Context(), `TRUNCATE sessions`)
				require.NoError(t, err)

				var n int
				require.NoError(t, inserter.DB.QueryRowContext(t.Context(),
					`SELECT count(*) FROM sessions WHERE id = $1`, sessionID).Scan(&n))
				assert.Equal(t, 1, n, "another call's TRUNCATE removed this call's session")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

func TestRunTestPostgresDropsTheDatabase(t *testing.T) {
	t.Parallel()
	requireHealthyProvider(t)

	srv, err := defaultPostgresRegistry.server(resolvePostgresImage(&testConfig{image: postgresImage}))
	require.NoError(t, err)

	var name string
	t.Run("call", func(t *testing.T) {
		conn := RunTestPostgres(t, WithTestPostgresImage(postgresImage))
		require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&name))
	})
	require.NotEmpty(t, name)

	var n int
	require.NoError(t, srv.admin.QueryRowContext(t.Context(),
		`SELECT count(*) FROM pg_database WHERE datname = $1`, name).Scan(&n))
	assert.Zero(t, n, "the call's database %s outlived its test", name)
}

func TestPostgresCloneDSN(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		adminDSN string
		database string
		assert   func(t *testing.T, dsn string, err error)
	}

	dsnOf := func(database string) string {
		u := url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword(postgresUsername, postgresPassword),
			Host:     "localhost:55432",
			Path:     "/" + database,
			RawQuery: "sslmode=disable",
		}
		return u.String()
	}

	cases := []testCase{
		{
			name:     "swaps the database and keeps the rest",
			adminDSN: dsnOf(postgresDatabase),
			database: "t_0123456789abcdef",
			assert: func(t *testing.T, dsn string, err error) {
				require.NoError(t, err)
				assert.Equal(t, dsnOf("t_0123456789abcdef"), dsn)
			},
		},
		{
			name:     "an unparsable admin DSN is an error",
			adminDSN: "postgres://scrty:scrty@localhost:bad port/scrty",
			database: "t_0123456789abcdef",
			assert: func(t *testing.T, _ string, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &postgresServer{adminDSN: tc.adminDSN}
			dsn, err := s.dsnFor(tc.database)
			tc.assert(t, dsn, err)
		})
	}
}

func TestPostgresTemplate(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	identity := migrate.Identity()
	securitySet := postgresMigrations{fsys: set.FS(), dir: set.Dir, versionTable: set.VersionTable}
	identitySet := postgresMigrations{fsys: identity.FS(), dir: identity.Dir, versionTable: identity.VersionTable}
	security := WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable)
	ident := WithTestPostgresMigrations(identity.FS(), identity.Dir, identity.VersionTable)

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "same sets give the schema and version rows of a fresh application",
			assert: func(t *testing.T) {
				cloned := RunTestPostgres(t, security, ident)
				fresh := RunTestPostgres(t)
				require.NoError(t, postgresApply(t.Context(), fresh.DB, []postgresMigrations{securitySet, identitySet}))

				want := schemaOf(t, fresh.DB, set.VersionTable, identity.VersionTable)
				require.NotEmpty(t, want)
				assert.Equal(t, want, schemaOf(t, cloned.DB, set.VersionTable, identity.VersionTable))
			},
		},
		{
			name: "order gives different templates",
			assert: func(t *testing.T) {
				a, err := postgresFingerprint([]postgresMigrations{securitySet, identitySet})
				require.NoError(t, err)
				b, err := postgresFingerprint([]postgresMigrations{identitySet, securitySet})
				require.NoError(t, err)
				assert.NotEqual(t, a, b)
			},
		},
		{
			name: "same lists give the same template",
			assert: func(t *testing.T) {
				a, err := postgresFingerprint([]postgresMigrations{securitySet, identitySet})
				require.NoError(t, err)
				b, err := postgresFingerprint([]postgresMigrations{
					{fsys: set.FS(), dir: set.Dir, versionTable: set.VersionTable},
					{fsys: identity.FS(), dir: identity.Dir, versionTable: identity.VersionTable},
				})
				require.NoError(t, err)
				assert.Equal(t, a, b)
				assert.Regexp(t, `^[0-9a-f]{16}$`, a)
			},
		},
		{
			name: "same directory, different files, different templates",
			assert: func(t *testing.T) {
				one := fstest.MapFS{"m/00001_a.sql": {Data: []byte("-- +goose Up\nCREATE TABLE a (v int);\n-- +goose Down\nDROP TABLE a;\n")}}
				two := fstest.MapFS{"m/00001_a.sql": {Data: []byte("-- +goose Up\nCREATE TABLE b (v int);\n-- +goose Down\nDROP TABLE b;\n")}}
				a, err := postgresFingerprint([]postgresMigrations{{fsys: one, dir: "m", versionTable: "v"}})
				require.NoError(t, err)
				b, err := postgresFingerprint([]postgresMigrations{{fsys: two, dir: "m", versionTable: "v"}})
				require.NoError(t, err)
				assert.NotEqual(t, a, b)
			},
		},
		{
			name: "another version table gives another template",
			assert: func(t *testing.T) {
				a, err := postgresFingerprint([]postgresMigrations{identitySet})
				require.NoError(t, err)
				b, err := postgresFingerprint([]postgresMigrations{{fsys: identity.FS(), dir: identity.Dir, versionTable: "app_identity_versions"}})
				require.NoError(t, err)
				assert.NotEqual(t, a, b)
			},
		},
		{
			name: "a set that cannot be applied is refused before any database is touched",
			assert: func(t *testing.T) {
				_, err := postgresFingerprint([]postgresMigrations{{dir: "testdata/migrations/good", versionTable: "goose_probe"}})
				require.ErrorContains(t, err, "no file system")
				_, err = postgresFingerprint([]postgresMigrations{{fsys: os.DirFS("."), dir: "testdata/migrations/good"}})
				require.ErrorContains(t, err, "no version table")
			},
		},
		{
			name: "parallel first calls apply the set once and get distinct databases",
			assert: func(t *testing.T) {
				srv := newTestPostgresServer(t) // a cold server of its own
				sets := []postgresMigrations{{fsys: probeSet("m_probe"), dir: "m", versionTable: "v"}}

				const callers = 8
				names := make([]string, callers)
				var wg sync.WaitGroup
				for i := range callers {
					wg.Go(func() {
						tpl, err := srv.template(t.Context(), sets)
						if !assert.NoError(t, err) {
							return
						}
						names[i], err = srv.clone(t.Context(), tpl)
						assert.NoError(t, err)
					})
				}
				wg.Wait()

				assert.EqualValues(t, 1, srv.applies.Load(), "the set's migrations must run once on a server")
				distinct := map[string]bool{}
				for _, name := range names {
					require.NotEmpty(t, name)
					distinct[name] = true
				}
				assert.Len(t, distinct, callers)
			},
		},
		{
			// Every build holds one admin connection for its advisory lock.
			// More parallel first builds than the admin pool has connections
			// must all finish: a build that needed a second admin connection
			// while holding the first would wait forever once every
			// connection was held by a build.
			name: "more parallel first builds than admin connections do not deadlock",
			assert: func(t *testing.T) {
				srv := newTestPostgresServer(t)
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()

				const builds = postgresAdminMaxOpenConns + 4
				var wg sync.WaitGroup
				for i := range builds {
					wg.Go(func() {
						sets := []postgresMigrations{{fsys: probeSet(fmt.Sprintf("p%d", i)), dir: "m", versionTable: "v"}}
						tpl, err := srv.template(ctx, sets)
						if !assert.NoError(t, err, "build %d", i) {
							return
						}
						_, err = srv.clone(ctx, tpl)
						assert.NoError(t, err, "clone %d", i)
					})
				}
				wg.Wait()
				assert.EqualValues(t, builds, srv.applies.Load())
			},
		},
		{
			// Two postgresServer values over one container stand in for two
			// processes sharing a server: their in-process maps are separate,
			// so only the advisory lock and the template check on PostgreSQL
			// keep them from building the same template twice.
			name: "two processes sharing a server build a template once",
			assert: func(t *testing.T) {
				first := newTestPostgresServer(t)
				for round := range 5 {
					second, err := newPostgresServer(t.Context(), first.image, first.ctr)
					require.NoError(t, err)
					t.Cleanup(func() { _ = second.admin.Close() })
					sets := []postgresMigrations{{fsys: probeSet(fmt.Sprintf("x%d", round)), dir: "m", versionTable: "v"}}

					before := first.applies.Load()
					var wg sync.WaitGroup
					for _, srv := range []*postgresServer{first, second} {
						wg.Go(func() {
							tpl, err := srv.template(t.Context(), sets)
							if !assert.NoError(t, err, "round %d", round) {
								return
							}
							_, err = srv.clone(t.Context(), tpl)
							assert.NoError(t, err, "round %d", round)
						})
					}
					wg.Wait()
					// first counts every round, so compare this round's share.
					assert.EqualValues(t, 1, first.applies.Load()-before+second.applies.Load(),
						"round %d: the set was applied more than once across the two servers", round)
				}
			},
		},
		{
			// The two sets each create t if it is missing, with another
			// column, so whichever runs first decides t's shape.
			name: "order matters: each order gives the schema of applying that order",
			assert: func(t *testing.T) {
				setFor := func(column string) fstest.MapFS {
					return fstest.MapFS{"m/00001_t.sql": {Data: fmt.Appendf(nil,
						"-- +goose Up\nCREATE TABLE IF NOT EXISTS t (%s int);\n\n-- +goose Down\nDROP TABLE IF EXISTS t;\n", column)}}
				}
				a := postgresMigrations{fsys: setFor("a"), dir: "m", versionTable: "va"}
				b := postgresMigrations{fsys: setFor("b"), dir: "m", versionTable: "vb"}
				option := func(m postgresMigrations) TestOption {
					return WithTestPostgresMigrations(m.fsys, m.dir, m.versionTable)
				}

				var schemas [][]string
				for _, order := range [][]postgresMigrations{{a, b}, {b, a}} {
					cloned := RunTestPostgres(t, option(order[0]), option(order[1]))
					fresh := RunTestPostgres(t)
					require.NoError(t, postgresApply(t.Context(), fresh.DB, order))

					want := schemaOf(t, fresh.DB, "va", "vb")
					require.NotEmpty(t, want)
					assert.Equal(t, want, schemaOf(t, cloned.DB, "va", "vb"),
						"a call naming %s then %s did not get the schema of that order", order[0].versionTable, order[1].versionTable)
					schemas = append(schemas, want)
				}
				require.Len(t, schemas, 2)
				assert.NotEqual(t, schemas[0], schemas[1], "the two orders must differ, or the case proves nothing")
			},
		},
		{
			name: "a failing set is never handed out half applied",
			assert: func(t *testing.T) {
				srv := sharedTestPostgresServer(t)
				sets := []postgresMigrations{{fsys: os.DirFS("testdata/migrations"), dir: "fails_partway", versionTable: "goose_fails"}}
				fp, err := postgresFingerprint(sets)
				require.NoError(t, err)

				for range 2 {
					_, err := srv.template(t.Context(), sets)
					require.ErrorContains(t, err, "apply migrations fails_partway")

					var n int
					require.NoError(t, srv.admin.QueryRowContext(t.Context(),
						`SELECT count(*) FROM pg_database WHERE datname = $1`, postgresTemplatePrefix+fp).Scan(&n))
					assert.Zero(t, n, "a half-built template remains")
				}
			},
		},
		{
			name: "a half-built leftover is rebuilt",
			assert: func(t *testing.T) {
				srv := newTestPostgresServer(t)
				sets := []postgresMigrations{securitySet}
				fp, err := postgresFingerprint(sets)
				require.NoError(t, err)
				// What a process killed mid-build leaves: the database, not
				// marked as a template, with only part of the sets applied.
				_, err = srv.admin.ExecContext(t.Context(), "CREATE DATABASE "+pgx.Identifier{postgresTemplatePrefix + fp}.Sanitize())
				require.NoError(t, err)

				tpl, err := srv.template(t.Context(), sets)
				require.NoError(t, err)
				name, err := srv.clone(t.Context(), tpl)
				require.NoError(t, err)

				db := openFor(t, srv, name)
				assert.True(t, regclassExists(t, db, "sessions"), "the clone of a rebuilt template has no sessions table")
				assert.EqualValues(t, 1, srv.applies.Load())
			},
		},
		{
			name: "a built template refuses connections",
			assert: func(t *testing.T) {
				srv := sharedTestPostgresServer(t)
				tpl, err := srv.template(t.Context(), []postgresMigrations{securitySet})
				require.NoError(t, err)

				dsn, err := srv.dsnFor(tpl)
				require.NoError(t, err)
				db, err := sql.Open("pgx", dsn)
				require.NoError(t, err)
				defer func() { _ = db.Close() }()
				assert.ErrorContains(t, db.PingContext(t.Context()), "not currently accepting connections")
			},
		},
		{
			name: "parallel tests truncating one table do not disturb each other",
			assert: func(t *testing.T) {
				for i := range 2 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						conn := RunTestPostgres(t, security)
						if i == 0 {
							_, err := conn.DB.ExecContext(t.Context(), `TRUNCATE sessions`)
							require.NoError(t, err)
							return
						}
						insertProbeSession(t, conn.DB)
						var n int
						require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM sessions`).Scan(&n))
						assert.Equal(t, 1, n)
					})
				}
			},
		},
		{
			// D2's concurrent-clone check, repeated on a migrated template.
			name: "fifty parallel calls clone one migrated template",
			assert: func(t *testing.T) {
				var mu sync.Mutex
				seen := map[string]bool{}
				t.Run("calls", func(t *testing.T) {
					for i := range 50 {
						t.Run(strconv.Itoa(i), func(t *testing.T) {
							t.Parallel()
							conn := RunTestPostgres(t, security)
							var name string
							require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&name))
							assert.True(t, regclassExists(t, conn.DB, "sessions"))
							mu.Lock()
							defer mu.Unlock()
							assert.False(t, seen[name], "database %s handed out twice", name)
							seen[name] = true
						})
					}
				})
				assert.Len(t, seen, 50)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

// probeSet returns a one-migration set at directory "m" that creates and
// drops table. A distinct table gives a distinct set, and so a distinct
// template.
func probeSet(table string) fstest.MapFS {
	return fstest.MapFS{"m/00001_probe.sql": {Data: fmt.Appendf(nil,
		"-- +goose Up\nCREATE TABLE %[1]s (v int);\n\n-- +goose Down\nDROP TABLE %[1]s;\n", table)}}
}

// newTestPostgresServer starts a server of the test's own, outside every
// registry RunTestPostgres uses, so nothing else builds templates on it. It
// is terminated when the test ends.
func newTestPostgresServer(t *testing.T) *postgresServer {
	t.Helper()
	requireHealthyProvider(t)

	r := &postgresRegistry{start: func(ctx context.Context, image string) (*postgres.PostgresContainer, error) {
		ctr, err := startPostgresContainer(ctx, image)
		if ctr != nil {
			// The cleanup outlives the start's context, so it must not use it.
			t.Cleanup(func() { terminateForTest(t, ctr) }) //nolint:contextcheck // runs after the start's context is gone
		}
		return ctr, err
	}}
	srv, err := r.server(resolvePostgresImage(&testConfig{}))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.admin.Close() })
	return srv
}

// openFor opens a handle on database name of srv, closed when the test ends.
func openFor(t *testing.T, srv *postgresServer, name string) *sql.DB {
	t.Helper()

	dsn, err := srv.dsnFor(name)
	require.NoError(t, err)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// insertProbeSession inserts one valid row into the security-state sessions
// table.
func insertProbeSession(t *testing.T, db *sql.DB) {
	t.Helper()

	now := time.Now().UTC()
	_, err := db.ExecContext(t.Context(), `INSERT INTO sessions
		(id, id_digest, user_id, created_at, last_accessed_at, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, 'u', $3, $3, $4, $4)`,
		id.MustParse("0192f000-0000-7000-8000-0000000000bb"), []byte("digest"), now, now.Add(time.Hour))
	require.NoError(t, err)
}

// schemaOf describes db's current schema as a sorted list of lines: its
// tables, columns, indexes, constraints and triggers, and the rows of each of
// versionTables.
func schemaOf(t *testing.T, db *sql.DB, versionTables ...string) []string {
	t.Helper()

	queries := []string{
		`SELECT 'table ' || tablename FROM pg_tables WHERE schemaname = current_schema()`,
		`SELECT format('column %s.%s %s %s %s', table_name, column_name, data_type, is_nullable, coalesce(column_default, ''))
			FROM information_schema.columns WHERE table_schema = current_schema()`,
		`SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = current_schema()`,
		`SELECT format('constraint %s %s %s', conrelid::regclass, conname, pg_get_constraintdef(oid))
			FROM pg_constraint WHERE connamespace = current_schema()::regnamespace`,
		`SELECT 'trigger ' || pg_get_triggerdef(tg.oid) FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid
			WHERE NOT tg.tgisinternal AND c.relnamespace = current_schema()::regnamespace`,
	}
	var out []string
	for _, q := range queries {
		out = append(out, queryStrings(t, db, q)...)
	}
	for _, vt := range versionTables {
		out = append(out, queryStrings(t, db,
			`SELECT format('version %s %s %s', $1::text, version_id, is_applied) FROM `+pgx.Identifier{vt}.Sanitize(), vt)...)
	}
	slices.Sort(out)
	return out
}

// Not parallel: each case sets the process environment. Only the first case
// needs a server that answers; it takes the one RunTestPostgres already shares,
// so this test starts no container. The others only need a DSN string.
func TestPostgresServerInherits(t *testing.T) {
	// unreachableDSN names an address nothing listens on.
	const unreachableDSN = "postgres://scrty:scrty@127.0.0.1:1/scrty?sslmode=disable" //nolint:gosec // G101: a placeholder DSN for a server that does not exist

	type testCase struct {
		name string
		// live makes the parent a running server rather than unreachableDSN.
		live   bool
		env    func(parentDSN, image string) string
		assert func(t *testing.T, parentDSN string, got *postgresServer, err error, starts int64)
	}

	errStart := errors.New("start refused")

	cases := []testCase{
		{
			name: "an inherited server is used and nothing is started",
			live: true,
			env: func(parentDSN, image string) string {
				return fmt.Sprintf(`{%q:%q}`, image, parentDSN)
			},
			assert: func(t *testing.T, parentDSN string, got *postgresServer, err error, starts int64) {
				require.NoError(t, err)
				t.Cleanup(func() {
					if got.admin != nil {
						_ = got.admin.Close()
					}
				})
				assert.Equal(t, parentDSN, got.adminDSN)
				assert.Nil(t, got.ctr, "an inherited server has no container handle, so it is never terminated")
				assert.Zero(t, starts)
				require.NoError(t, got.admin.PingContext(t.Context()))
			},
		},
		{
			name: "an image the variable does not name is started",
			env: func(parentDSN, _ string) string {
				return fmt.Sprintf(`{"postgres:other":%q}`, parentDSN)
			},
			assert: func(t *testing.T, _ string, _ *postgresServer, err error, starts int64) {
				require.ErrorIs(t, err, errStart)
				assert.EqualValues(t, 1, starts)
			},
		},
		{
			name: "an unset variable starts the server",
			env:  func(string, string) string { return "" },
			assert: func(t *testing.T, _ string, _ *postgresServer, err error, starts int64) {
				require.ErrorIs(t, err, errStart)
				assert.EqualValues(t, 1, starts)
			},
		},
		{
			name: "a malformed variable is an error that names it, and starts nothing",
			env:  func(string, string) string { return `{"postgres` },
			assert: func(t *testing.T, _ string, _ *postgresServer, err error, starts int64) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), postgresServersEnv)
				assert.Zero(t, starts)
			},
		},
		{
			name: "an inherited server that cannot be reached is an error, and starts nothing",
			env: func(_, image string) string {
				return fmt.Sprintf(`{%q:%q}`, image, unreachableDSN)
			},
			assert: func(t *testing.T, _ string, _ *postgresServer, err error, starts int64) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), postgresServersEnv)
				assert.Zero(t, starts)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parentDSN := unreachableDSN
			if tc.live {
				parentDSN = sharedTestPostgresServer(t).adminDSN
			}
			image := resolvePostgresImage(&testConfig{})
			t.Setenv(postgresServersEnv, tc.env(parentDSN, image))

			var starts atomic.Int64
			r := &postgresRegistry{shareEnv: true, start: func(context.Context, string) (*postgres.PostgresContainer, error) {
				starts.Add(1)
				return nil, errStart
			}}
			got, err := r.server(image)
			tc.assert(t, parentDSN, got, err, starts.Load())
		})
	}
}

// Not parallel: each case sets the process environment. Every case's start
// returns the container RunTestPostgres already shares, so this test starts no
// container of its own; the registry under test only wraps it and publishes
// its DSN.
func TestPostgresServerPublishes(t *testing.T) {
	type testCase struct {
		name   string
		env    string // the variable before the start; "" means unset
		shared bool
		assert func(t *testing.T, srv *postgresServer, image string, published map[string]string)
	}

	cases := []testCase{
		{
			name:   "a started server is published under its image",
			shared: true,
			assert: func(t *testing.T, srv *postgresServer, image string, published map[string]string) {
				assert.Equal(t, map[string]string{image: srv.adminDSN}, published)
			},
		},
		{
			name:   "servers already published are kept",
			env:    `{"postgres:other":"postgres://other"}`,
			shared: true,
			assert: func(t *testing.T, srv *postgresServer, image string, published map[string]string) {
				assert.Equal(t, map[string]string{"postgres:other": "postgres://other", image: srv.adminDSN}, published)
			},
		},
		{
			name: "a registry that does not share leaves the environment alone",
			env:  `{"postgres:other":"postgres://other"}`,
			assert: func(t *testing.T, _ *postgresServer, _ string, published map[string]string) {
				assert.Equal(t, map[string]string{"postgres:other": "postgres://other"}, published)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctr := sharedTestPostgresServer(t).ctr
			if ctr == nil {
				t.Skip("the shared server was inherited from a parent process: no container to wrap")
			}
			t.Setenv(postgresServersEnv, tc.env)

			r := &postgresRegistry{shareEnv: tc.shared, start: func(context.Context, string) (*postgres.PostgresContainer, error) {
				return ctr, nil
			}}
			image := resolvePostgresImage(&testConfig{})
			srv, err := r.server(image)
			require.NoError(t, err)
			t.Cleanup(func() { _ = srv.admin.Close() })

			published := map[string]string{}
			if raw := os.Getenv(postgresServersEnv); raw != "" {
				require.NoError(t, json.Unmarshal([]byte(raw), &published))
			}
			tc.assert(t, srv, image, published)
		})
	}
}

// Not parallel: it sets the process environment.
func TestEnsureTestPostgresServer(t *testing.T) {
	requireHealthyProvider(t)

	image := resolvePostgresImage(&testConfig{})
	srv, err := defaultPostgresRegistry.server(image)
	require.NoError(t, err)

	// Wiped after the server started: Ensure publishes it again.
	t.Setenv(postgresServersEnv, "")
	EnsureTestPostgresServer(t)

	var published map[string]string
	require.NoError(t, json.Unmarshal([]byte(os.Getenv(postgresServersEnv)), &published))
	assert.Equal(t, srv.adminDSN, published[image])

	again, err := defaultPostgresRegistry.server(image)
	require.NoError(t, err)
	assert.Same(t, srv, again, "Ensure shares the server RunTestPostgres uses")
}

const childProbeEnv = "SCRTY_TEST_CHILD_PROBE"

// TestPostgresChildReusesParentServer re-executes this test binary: the child
// half starts no container and reports the database it was given.
func TestPostgresChildReusesParentServer(t *testing.T) {
	if os.Getenv(childProbeEnv) != "" {
		before := postgresContainerStarts.Load()
		conn := RunTestPostgres(t)
		var db string
		require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&db))
		fmt.Printf("child-starts=%d\nchild-db=%s\n", postgresContainerStarts.Load()-before, db)
		return
	}
	t.Parallel()

	EnsureTestPostgresServer(t)
	parent := RunTestPostgres(t)
	var parentDB string
	require.NoError(t, parent.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&parentDB))

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestPostgresChildReusesParentServer$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childProbeEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	assert.Contains(t, string(out), "child-starts=0", "the child started a server of its own:\n%s", out)
	assert.Contains(t, string(out), "child-db=", "the child reported no database:\n%s", out)
	assert.NotContains(t, string(out), "child-db="+parentDB+"\n", "the child was handed the parent's database")
}

// postgresDataDirectory returns the data directory srv runs on, as the server
// reports it, so the answer holds for every image whatever its PGDATA.
func postgresDataDirectory(t *testing.T, srv *postgresServer) string {
	t.Helper()

	var dir string
	require.NoError(t, srv.admin.QueryRowContext(t.Context(), `SHOW data_directory`).Scan(&dir))
	return dir
}

func TestPostgresServerTuning(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		server func(t *testing.T) *postgresServer
		assert func(t *testing.T, srv *postgresServer)
	}

	// assertTuned checks the settings every server gets, whichever kind a test asked for.
	assertTuned := func(t *testing.T, srv *postgresServer) {
		t.Helper()

		for setting, want := range map[string]string{
			"fsync":              "off",
			"synchronous_commit": "off",
			"full_page_writes":   "off",
			"max_connections":    strconv.Itoa(postgresMaxConnections),
		} {
			var got string
			require.NoError(t, srv.admin.QueryRowContext(t.Context(), "SHOW "+setting).Scan(&got))
			assert.Equal(t, want, got, setting)
		}

		// A server another process started has no container to look into; its
		// parent's own run checks the mount.
		if srv.ctr == nil {
			return
		}
		dir := postgresDataDirectory(t, srv)
		code, out, err := srv.ctr.Exec(t.Context(), []string{"stat", "-f", "-c", "%T", dir}, tcexec.Multiplexed())
		require.NoError(t, err)
		b, err := io.ReadAll(out)
		require.NoError(t, err)
		require.Zero(t, code, string(b))
		assert.Equal(t, "tmpfs", strings.TrimSpace(string(b)), "the data directory %s is not on a tmpfs", dir)
	}

	cases := []testCase{
		{
			name:   "the shared server",
			server: sharedTestPostgresServer,
			assert: assertTuned,
		},
		{
			name:   "an own server",
			server: newTestPostgresServer,
			assert: assertTuned,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.server(t))
		})
	}
}

// Server tuning must not change what a test can observe: PostgreSQL still
// refuses a write skew under SERIALIZABLE, whatever the WAL settings.
func TestPostgresServerKeepsSerializableConflicts(t *testing.T) {
	t.Parallel()

	conn := RunTestPostgres(t)
	ctx := t.Context()
	_, err := conn.DB.ExecContext(ctx, `CREATE TABLE doctors (name text PRIMARY KEY, on_call bool NOT NULL);
		INSERT INTO doctors VALUES ('a', true), ('b', true)`)
	require.NoError(t, err)

	opts := &sql.TxOptions{Isolation: sql.LevelSerializable}
	t1, err := conn.DB.BeginTx(ctx, opts)
	require.NoError(t, err)
	t2, err := conn.DB.BeginTx(ctx, opts)
	require.NoError(t, err)
	var n int
	require.NoError(t, t1.QueryRowContext(ctx, `SELECT count(*) FROM doctors WHERE on_call`).Scan(&n))
	require.NoError(t, t2.QueryRowContext(ctx, `SELECT count(*) FROM doctors WHERE on_call`).Scan(&n))
	_, err = t1.ExecContext(ctx, `UPDATE doctors SET on_call = false WHERE name = 'a'`)
	require.NoError(t, err)
	_, err = t2.ExecContext(ctx, `UPDATE doctors SET on_call = false WHERE name = 'b'`)
	require.NoError(t, err)
	require.NoError(t, t1.Commit())

	err = t2.Commit()
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "write skew must be refused under SERIALIZABLE")
	assert.Equal(t, "40001", pgErr.Code)
}

func TestRunTestPostgres_StopStart(t *testing.T) {
	t.Parallel()

	conn := RunTestPostgres(t, WithTestPostgresOwnServer())
	ctx := t.Context()
	_, err := conn.DB.ExecContext(ctx, `CREATE TABLE restart_probe (v int); INSERT INTO restart_probe VALUES (7)`)
	require.NoError(t, err)

	conn.Stop(t)
	stopped, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.Error(t, conn.DB.PingContext(stopped), "the server answers after Stop")

	conn.Start(t)
	var v int
	require.NoError(t, conn.DB.QueryRowContext(ctx, `SELECT v FROM restart_probe`).Scan(&v),
		"DB must reach the restarted server, and the data must survive the restart")
	assert.Equal(t, 7, v)
}

func TestRunTestPostgres_Refusals(t *testing.T) {
	t.Parallel()

	// Stop and Start end the test with t.Fatal on a shared server, which a
	// test cannot observe on its own *testing.T, so the check behind them is
	// exercised directly, as TestRunTestRedis_Refusals does.
	_, err := PostgresConn{}.own()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WithTestPostgresOwnServer")
}

func TestRunTestPostgresStandby(t *testing.T) {
	t.Parallel()

	s := RunTestPostgresStandby(t)
	ctx := t.Context()

	var inRecovery bool
	require.NoError(t, s.Standby.DB.QueryRowContext(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery))
	assert.True(t, inRecovery, "the standby is not in recovery")
	require.NoError(t, s.Primary.DB.QueryRowContext(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery))
	assert.False(t, inRecovery, "the primary is in recovery")

	_, err := s.Primary.DB.ExecContext(ctx, `CREATE TABLE standby_probe (v int); INSERT INTO standby_probe VALUES (1)`)
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var v int
		assert.NoError(c, s.Standby.DB.QueryRowContext(ctx, `SELECT v FROM standby_probe`).Scan(&v))
	}, 30*time.Second, 200*time.Millisecond)

	// A standby refuses writes.
	_, err = s.Standby.DB.ExecContext(ctx, `INSERT INTO standby_probe VALUES (2)`)
	require.Error(t, err)

	// Both are own servers, so each can be stopped and restarted.
	s.Standby.Stop(t)
	s.Standby.Start(t)
}

func TestRunTestPostgresStandby_Migrations(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{"m/00001_t.sql": {Data: []byte("-- +goose Up\nCREATE TABLE standby_migrated (v int);\n-- +goose Down\nDROP TABLE standby_migrated;\n")}}
	s := RunTestPostgresStandby(t, WithTestPostgresMigrations(fsys, "m", "standby_mig_version"))
	ctx := t.Context()
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var n int
		assert.NoError(c, s.Standby.DB.QueryRowContext(ctx, `SELECT count(*) FROM standby_migrated`).Scan(&n))
	}, 30*time.Second, 200*time.Millisecond, "the primary's migration never reached the standby")
}

// A test that leaves its own server stopped must still clean up: terminating
// the container removes the database, so neither the drop nor the migration
// rollback may run against a server that is down.
func TestRunTestPostgres_StopLeftStopped(t *testing.T) {
	t.Parallel()

	conn := RunTestPostgres(t, WithTestPostgresOwnServer())
	conn.Stop(t)
}
