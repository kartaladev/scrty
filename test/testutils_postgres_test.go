package test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
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

			conn := RunTestPostgres(t)
			rec := &recordingTB{ctx: t.Context()}
			cfg := &testConfig{
				migrations:         sets,
				finalizers:         tc.finalizers,
				leftoverTableCheck: tc.leftoverTableCheck,
			}
			runRecorded(func() { postgresSetUp(rec, conn.DB, cfg) })
			if tc.before != nil {
				tc.before(t, conn.DB)
			}

			rec.runCleanups()
			tc.assert(t, conn.DB, rec.errs)
		})
	}
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
