# PostgreSQL Limiter Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every code-writing step to a subagent (`.claude/rules/subagent-delegation.md`); the main session runs the verification commands itself.

**Goal:** Make the PostgreSQL rate limiter serve the default HTTP chain (cap 400), bound its prune so no record waits on it, refuse databases it cannot serve, and keep one copy of the logic both adapters share.

**Architecture:** The limiter keeps one row per (namespace, key) with a `timestamptz[]`. The cap rises to 400 behind a `toast_tuple_target = 8160` storage parameter. The driver-agnostic code moves out of `sqlstore` and `pgx` into a new `internal/pglimiter` package. It runs statements through a two-method `Runner` interface that each adapter implements over its handle. The prune becomes a loop of `FOR UPDATE SKIP LOCKED` batches, each its own transaction.

**Tech Stack:** Go 1.27 workspace; PostgreSQL 15 and 18; `database/sql` over pgx stdlib (`sqlstore`), native `pgxpool` (`pgx`); testcontainers-go through the `test` module's `RunTestPostgres`; testify; clockwork.

**Spec:** `openspec/changes/postgres-limiter-hardening/specs/rate-limiting/spec.md`, with `design.md` (decisions 1–10) and `tasks.md`. Read all three before starting a task.

## Global Constraints

- Test-first for every task: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), then implement (`.claude/rules/golang-tdd.md`).
- Table tests use the `table-test` skill's form: an `assert` closure per case, `t.Context()`, no `want`/`wantErr` fields.
- Mocks come from the `use-mockgen` skill; PostgreSQL comes from `RunTestPostgres` (`use-testcontainers`). No hand-rolled database fakes. The `pglimiter` unit tests' fake `Runner` is a two-method test double over no database, and that is allowed.
- Never cite, copy or mention the legacy reference in code, comments or commits (`.claude/rules/legacy-reference.md`).
- A defect claim needs a failing test (`.claude/rules/defect-claims.md`).
- No public signature changes. New public API is limited to `WithLimiterPruneBatchSize(n int) LimiterOption` in `sqlstore` and `pgx`, and `WithTestPostgresRestartable() TestOption` in `test`.
- `LimiterOption` stays `func(*limiterConfig)` in each adapter. No exported identifier names an `internal/...` type.
- Error prefixes stay `sqlstore:` and `pgx:`. Every configuration error wraps `ratelimit.ErrConfig`.
- No limiter error repeats PostgreSQL's message text. Use `internal/diag.Wrap(err, text, kinds...)`, which keeps the cause in `Unwrap` and so keeps `errors.Is(err, context.Canceled)` working.
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.
- Verification commands, run from the repository root unless stated:
  - core module: `go test -count=1 ./internal/... ./sqlstore/...`
  - pgx module: `(cd pgx && go test -count=1 ./...)`
  - test module: `(cd test && go test -count=1 -run '<Name>' ./...)`
  - always: `go vet ./...` in each touched module, and `gofmt -l .` printing nothing.

## Review Focus

These are inputs no task's happy path exercises. Each has its test placed in the task that owns the code.

1. **A limit of exactly 400 with a 512-byte key.** This is the widest row the cap allows. It must record and count without a `row is too big` error. Test in Task 1 (step 1.2b).
2. **A prune with a batch size larger than the table.** One batch removes everything, the loop stops after one statement, and the count is exact. Test in Task 5 (the `pglimiter` unit table, case "short first batch stops").
3. **A prune on an empty table.** It returns `0, nil` after one statement, with no error and no second batch. Same table, case "empty table".
4. **`Verify` on a UTF8 database whose bucket table is temporary.** The encoding check must not mask the persistence check. Test in Task 4 (step 4.2).
5. **A factory built with a nil option among valid ones, and the new batch-size option.** Nil is still skipped, and the batch size still applies. Test in Task 5 (step 5.2, case "nil option ignored").

---

### Task 1: The limit maximum rises to 400 (tasks 1.1–1.4)

**Model:** Sonnet. The plan gives the constant, the migration line and the tests.

**Files:**
- Create: `test/pg_ratelimit_chain_test.go` (package `test_test`)
- Modify: `internal/pgschema/ratelimit.go:20-22` (`LimiterMaxLimit`), `:51-58` (record godoc)
- Modify: `migrate/securitystate/20260926000000_security_state.sql` (the `CREATE TABLE rate_limit_buckets` statement)
- Modify: `sqlstore/limiter_test.go:75-76, :317`, `pgx/limiter_test.go:90-91, :333`
- Modify: godoc in `sqlstore/limiter.go`, `sqlstore/limiter_factory.go`, `pgx/limiter.go`, `pgx/limiter_factory.go`
- Modify: `test/pg_ratelimit_test.go` (one case in an existing runner, for 400 failures and the 512-byte key)

**Interfaces:**
- Consumes: `httpsec.New`, `httpsec.WithRateLimiterFactory`, `httpsec.EnableFormLogin`, `sqlstore.NewLimiterFactory`, `pgxstore.NewLimiterFactory`, `test.RunTestPostgres`, `test.WithTestPostgresMigrations`, `migrate.SecurityState()`.
- Produces: `pgschema.LimiterMaxLimit == 400`.

- [ ] **Step 1.1a: Write the failing chain test**

`test/pg_ratelimit_chain_test.go`. A capturing factory wraps the real one and records each limiter it builds:

```go
package test_test

import (
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/migrate"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
)

// capturingFactory records each limiter a factory builds, with the limit it
// was asked for, so a test can drive the limiter a chain built.
type capturingFactory struct {
	ratelimit.LimiterFactory

	mu    sync.Mutex
	built map[string]capturedLimiter
}

type capturedLimiter struct {
	limit   int
	limiter ratelimit.Limiter
}

func (f *capturingFactory) NewLimiter(ns string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	l, err := f.LimiterFactory.NewLimiter(ns, limit, window)
	if err == nil {
		f.mu.Lock()
		f.built[ns] = capturedLimiter{limit: limit, limiter: l}
		f.mu.Unlock()
	}
	return l, err
}

// TestPGLimiter_DefaultChainBuilds pins that the default chain, password
// login and its default IPv6 aggregate included, builds over either
// PostgreSQL factory, and that the aggregate counts to its full limit.
func TestPGLimiter_DefaultChainBuilds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		factory func(t *testing.T, conn test.PostgresConn) ratelimit.LimiterFactory
		assert  func(t *testing.T, f *capturingFactory, err error)
	}

	countsTo200 := func(t *testing.T, f *capturingFactory, err error) {
		t.Helper()
		require.NoError(t, err)
		var agg *capturedLimiter
		for ns, c := range f.built {
			if c.limit == 200 {
				c := c
				agg = &c
				t.Logf("aggregate namespace %q", ns)
			}
		}
		require.NotNil(t, agg, "the chain built no limiter with a limit of 200")
		for range 199 {
			require.NoError(t, agg.limiter.RecordFailure(t.Context(), "2001:db8::/64"))
		}
		got, err := agg.limiter.Exceeded(t.Context(), "2001:db8::/64")
		require.NoError(t, err)
		assert.False(t, got, "exceeded after 199 of 200")
		require.NoError(t, agg.limiter.RecordFailure(t.Context(), "2001:db8::/64"))
		got, err = agg.limiter.Exceeded(t.Context(), "2001:db8::/64")
		require.NoError(t, err)
		assert.True(t, got, "not exceeded at 200 of 200")
	}

	cases := []testCase{
		{
			name: "sqlstore",
			factory: func(t *testing.T, conn test.PostgresConn) ratelimit.LimiterFactory {
				f, err := sqlstore.NewLimiterFactory(conn.DB)
				require.NoError(t, err)
				return f
			},
			assert: countsTo200,
		},
		{
			name: "pgx",
			factory: func(t *testing.T, conn test.PostgresConn) ratelimit.LimiterFactory {
				pool, err := pgxpool.New(t.Context(), conn.DSN)
				require.NoError(t, err)
				t.Cleanup(pool.Close)
				f, err := pgxstore.NewLimiterFactory(pool)
				require.NoError(t, err)
				return f
			},
			assert: countsTo200,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := migrate.SecurityState()
			conn := test.RunTestPostgres(t, test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable))
			f := &capturingFactory{LimiterFactory: tc.factory(t, conn), built: map[string]capturedLimiter{}}

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)
			_, err = httpsec.New(
				httpsec.WithRateLimiterFactory(f),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: refusingAuthenticator{},
					Sessions:      sessions,
					Tokens:        fixedTokens{},
					Attempts:      policy.NewMemoryAttemptStore(),
				}),
			)
			tc.assert(t, f, err)
		})
	}
}
```

`refusingAuthenticator` and `fixedTokens` already exist in `test/httpsec_login_redis_test.go`, in the same package.

- [ ] **Step 1.1b: Run and see it fail**

Run: `(cd test && go test -count=1 -run 'TestPGLimiter_DefaultChainBuilds' ./...)`
Expected: FAIL in both subtests at `require.NoError`, with `ratelimit: invalid configuration: a limit of 200 is above 128`.

- [ ] **Step 1.2a: Move the adapters' boundary cases**

In `sqlstore/limiter_test.go` and `pgx/limiter_test.go`:
- `{name: "limit 129", ... limit: 129, ... assert: refused("128")}` becomes `{name: "limit 401", ... limit: 401, ... assert: refused("400")}`.
- `{name: "limit 128 accepted", ... limit: 128, ...}` becomes `{name: "limit 400 accepted", ... limit: 400, ...}`.
- The factory row `{name: "limit 129", ask: request{"api-key", 129, time.Minute}, assert: refused("128")}` becomes `{name: "limit 401", ask: request{"api-key", 401, time.Minute}, assert: refused("400")}`.

- [ ] **Step 1.2b: Add the widest-row case to the test module**

In `test/pg_ratelimit_test.go`, add `TestPGLimiter_WidestRow` (package `test`), run over both backends with `for _, b := range []pgBackend{sqlstoreBackend, pgxBackend}`. For each backend, use `migratedLimiterDB(t)` and a limit of 400 with a one-hour window. Record 400 failures for a 512-byte key, `strings.Repeat("k", 512)`, then assert `Exceeded` is true. Then read the row and assert that it is stored in-line and was not TOASTed:

```go
var stamps int
require.NoError(t, conn.DB.QueryRowContext(t.Context(),
	`SELECT cardinality(stamps) FROM rate_limit_buckets WHERE namespace = $1`, ns).Scan(&stamps))
assert.Equal(t, 400, stamps)
var opts string
require.NoError(t, conn.DB.QueryRowContext(t.Context(),
	`SELECT array_to_string(coalesce(reloptions, '{}'), ',') FROM pg_class WHERE oid = 'rate_limit_buckets'::regclass`).Scan(&opts))
assert.Contains(t, opts, "toast_tuple_target=8160")
```

- [ ] **Step 1.2c: Run and see them fail**

Run: `go test -count=1 -run 'TestNewLimiter|TestLimiterFactory' ./sqlstore/ && (cd pgx && go test -count=1 -run 'TestNewLimiter|TestLimiterFactory' ./...) && (cd test && go test -count=1 -run 'TestPGLimiter_WidestRow' ./...)`
Expected:
- "limit 400 accepted" fails with an error naming 128.
- "limit 401" fails because the error names 128, not 400.
- `TestPGLimiter_WidestRow` fails at construction (limit above 128).

(Use `go test -list . ./sqlstore/` to find the exact names of the test functions holding those tables, and run them.)

- [ ] **Step 1.3: Implement**

`internal/pgschema/ratelimit.go`:

```go
	// LimiterMaxLimit is the largest limit a limiter may be built with. A
	// bucket keeps at most that many stamps, which bounds the row's size: at
	// 400 stamps and the longest key a row is under 4 kB, so it stays in-line
	// (the table's toast_tuple_target) and an update stays HOT.
	LimiterMaxLimit = 400
```

In the migration, add the storage parameter to the bucket table's `WITH (...)` list, next to `fillfactor = 70` and the autovacuum settings:

```sql
  -- Keeps a bucket's stamp array in-line up to a full page, so a row of up
  -- to 400 stamps is never moved to TOAST and an update stays HOT. Without
  -- it, rows above about 2 kB are TOASTed: slower, never wrong.
  toast_tuple_target = 8160,
```

(Read the statement first. If the table has no `WITH (...)` list but separate `ALTER TABLE ... SET (...)` statements, add the parameter to that `SET` list instead.)

Run steps 1.1b and 1.2c again. Expected: PASS.

- [ ] **Step 1.4: Godoc**

- `sqlstore/limiter.go` and `pgx/limiter.go`, the `NewLimiter` "Maximums" paragraph:

```go
// Maximums: a limit of at most 400 and a namespace of at most 64 bytes,
// counted in bytes, not characters. They keep the widest row under 4 kB, which
// the migration's storage parameter (toast_tuple_target) keeps in-line, so a
// record never rewrites an out-of-line array. They have no override; a flow
// needing a larger limit belongs on the Redis limiter.
```

- In the `NewLimiter` error list, "a limit below 1 or above 128" becomes "a limit below 1 or above 400".
- In `LimiterFactory.NewLimiter`'s godoc, "a limit above 128" becomes "a limit above 400".
- `internal/pgschema/ratelimit.go`, record statement godoc:

```go
	// A new key gets one row holding the stamp. An existing key keeps at most
	// $3 stamps, the new one included: the newest $3 of its stored stamps and
	// the new one, ascending, so a clock behind the stored newest stamp still
	// leaves them ordered; newest_at and longest_window_us only grow
	// (GREATEST).
```

Run: `grep -rn '128' sqlstore/limiter*.go pgx/limiter*.go internal/pgschema/ratelimit.go`. Expected: no line about the maximum. Then `go vet ./... && (cd pgx && go vet ./...) && gofmt -l .`. Expected: clean.

- [ ] **Step 1.5: Commit**

```bash
git add internal/pgschema/ratelimit.go migrate/securitystate/ sqlstore/limiter* pgx/limiter* test/pg_ratelimit_chain_test.go test/pg_ratelimit_test.go
git commit -m "fix(ratelimit): the PostgreSQL limiter holds 400 stamps, so the default chain builds"
```

---

### Task 2: Own test servers on tmpfs unless restartable (tasks 2.1–2.3)

**Model:** Sonnet. A test-helper option with a stated contract. It runs in parallel with Task 1: it owns only `test/testutils*.go`, `test/testutils_postgres_test.go`, and the `WithTestPostgresOwnServer()` call sites listed below.

**Files:**
- Modify: `test/testutils.go` (`testConfig`, `PostgresConn`, `own()`, `Stop`, `Start`, `startTestPostgres`, new `WithTestPostgresRestartable`)
- Modify: `test/testutils_pgstandby.go` (the primary is restartable; the standby's `PostgresConn` is marked restartable)
- Modify: `test/testutils_postgres_test.go` (new tests; `TestRunTestPostgres_StopStart`, `TestRunTestPostgres_StopLeftStopped` and the `own()` case at line 1803 add the option)
- Modify: `test/pg_ratelimit_fault_test.go:716`, `test/pg_ratelimit_test.go:804` (add the option)
- Modify: `test/pg_ratelimit_bench_test.go:255-262` (comment only: the benchmark keeps data on disk on purpose)

**Interfaces:**
- Produces: `func WithTestPostgresRestartable() TestOption`. It implies an own server, so `WithTestPostgresOwnServer()` beside it is redundant but harmless.

- [ ] **Step 2.1a: Write the failing tests**

In `test/testutils_postgres_test.go` (package `test`):

```go
// TestRunTestPostgres_OwnServerStorage pins where an own server keeps its
// data: tmpfs by default, disk when it must survive Stop and Start.
func TestRunTestPostgres_OwnServerStorage(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []TestOption
		assert func(t *testing.T, conn PostgresConn, mount string)
	}

	cases := []testCase{
		{
			name: "own server on tmpfs",
			opts: []TestOption{WithTestPostgresOwnServer()},
			assert: func(t *testing.T, _ PostgresConn, mount string) {
				assert.Contains(t, mount, "tmpfs")
			},
		},
		{
			name: "restartable server on disk",
			opts: []TestOption{WithTestPostgresRestartable()},
			assert: func(t *testing.T, conn PostgresConn, mount string) {
				assert.NotContains(t, mount, "tmpfs")
				conn.Stop(t)
				conn.Start(t)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := RunTestPostgres(t, tc.opts...)
			code, r, err := conn.ctr.Exec(t.Context(), []string{"sh", "-c", "grep ' " + postgresDataDir + " ' /proc/mounts || true"})
			require.NoError(t, err)
			require.Equal(t, 0, code)
			out, err := io.ReadAll(r)
			require.NoError(t, err)
			tc.assert(t, conn, string(out))
		})
	}
}

func TestRunTestPostgres_StopRefusesNonRestartable(t *testing.T) {
	t.Parallel()

	_, err := PostgresConn{ctr: &postgres.PostgresContainer{}}.own()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WithTestPostgresRestartable")
}
```

(`postgresDataDir` is `/var/lib/postgresql/data`, and `postgresTmpfs` mounts tmpfs on exactly that path, so the grep finds it.)

- [ ] **Step 2.1b: Run and see them fail**

Run: `(cd test && go test -count=1 -run 'TestRunTestPostgres_OwnServerStorage|TestRunTestPostgres_StopRefusesNonRestartable' ./...)`
Expected:
- "own server on tmpfs" fails, because the mount line has no `tmpfs`.
- The refusal test fails, because `own()` returns no error for a non-nil container.
- `WithTestPostgresRestartable` must exist first as an empty stub (`func(c *testConfig) {}`) so that this is not a compile error.

- [ ] **Step 2.2: Implement**

In `test/testutils.go`:

```go
// in testConfig
	restartable        bool

// in PostgresConn, next to ctr
	restartable bool // the data is on disk, so Stop and Start keep it

// WithTestPostgresRestartable gives this call an own server, as
// WithTestPostgresOwnServer does, whose data lives on the container's disk
// rather than tmpfs, so it survives Stop and Start. Only a test that stops or
// restarts its server needs it; Stop and Start refuse a server built without
// it, whose tmpfs data a restart would lose.
func WithTestPostgresRestartable() TestOption {
	return func(c *testConfig) { c.ownServer, c.restartable = true, true }
}

func (c PostgresConn) own() (*postgres.PostgresContainer, error) {
	switch {
	case c.ctr == nil:
		return nil, errors.New("Stop and Start need WithTestPostgresRestartable: this is a shared server other tests are using")
	case !c.restartable:
		return nil, errors.New("Stop and Start need WithTestPostgresRestartable: this own server keeps its data on tmpfs, which a restart loses")
	}
	return c.ctr, nil
}
```

- `startTestPostgres(t, image, extra...)` becomes `startTestPostgres(t, image, onDisk bool, extra...)`. It calls `startPostgresContainerWith(t.Context(), image, !onDisk, extra...)`.
- `RunTestPostgres` passes `cfg.restartable` and sets `restartable: cfg.restartable` where it builds the `PostgresConn` (around `testutils.go:716`; follow how `ctr` gets there).
- Update the `startPostgresContainerWith` comment: an own server keeps its data in memory unless it is restartable.
- Update `Stop`'s doc: "It fails the test on a shared server, and on an own server built without WithTestPostgresRestartable."

Run step 2.1b again. Expected: PASS.

- [ ] **Step 2.3: Pass the option where a server is stopped**

- `test/testutils_pgstandby.go`:
  - The primary's `startTestPostgres(t, image, true, ...)`.
  - The standby's `PostgresConn{DB: db, DSN: dsn, ctr: sbCtr, restartable: true}`. Its container never had tmpfs.
  - The doc comment of `RunTestPostgresStandby` changes from `RunTestPostgres(t, WithTestPostgresOwnServer(), opts...)` to `RunTestPostgres(t, WithTestPostgresRestartable(), opts...)`.
- `test/pg_ratelimit_fault_test.go:716`: `migratedLimiterDB(t, WithTestPostgresRestartable())`.
- `test/pg_ratelimit_test.go:804`: `WithTestPostgresRestartable()` in place of `WithTestPostgresOwnServer()`.
- `test/testutils_postgres_test.go`: in `TestRunTestPostgres_StopStart` (around line 1780) and `TestRunTestPostgres_StopLeftStopped` (around 1854), use `WithTestPostgresRestartable()`. In the `own()` test at line 1803, update the expected text to name `WithTestPostgresRestartable`.
- `test/pg_ratelimit_bench_test.go`, above line 262: `// The benchmark keeps the data on disk, as a real server does: tmpfs would flatter WAL and checkpoint cost.`

Then `grep -n 'WithTestPostgresOwnServer()' test/*.go`. Every remaining caller must be one that never calls `Stop` or `Start`.

Run: `(cd test && go test -count=1 -run 'TestRunTestPostgres|TestPGLimiter_Unavailable|TestSQLStoreLimiter_Verify|TestPgxLimiter_Verify|Standby' ./...)`
Expected: PASS.

- [ ] **Step 2.4: Commit**

```bash
git add test/testutils.go test/testutils_pgstandby.go test/testutils_postgres_test.go test/pg_ratelimit_fault_test.go test/pg_ratelimit_test.go test/pg_ratelimit_bench_test.go
git commit -m "test: own PostgreSQL servers run on tmpfs unless built restartable"
```

---

### Task 3: One shared limiter core (tasks 3.1–3.5)

**Model:** Opus. This refactor must keep behaviour while extracting shared code, across `internal/unavailable`, `sqlstore` and `pgx`, so the reviewer is Opus too. It runs after Task 1 lands, because both edit `sqlstore/limiter*.go` and `pgx/limiter*.go`.

**Files:**
- Create: `internal/pglimiter/doc.go`, `config.go`, `facts.go`, `registry.go`, `runner.go`, and `*_test.go` beside each
- Modify: `internal/unavailable/wrap.go` (`validate` split; new `ValidateConfig`), `internal/unavailable/modes_test.go` or a new `validate_test.go`
- Modify: `sqlstore/limiter.go`, `limiter_options.go`, `limiter_factory.go`, `limiter_verify.go`
- Modify: `pgx/limiter.go`, `limiter_options.go`, `limiter_factory.go`, `limiter_verify.go`

**Interfaces:**
- Consumes: `unavailable.Config`, `unavailable.DefaultConfig`, `unavailable.Wrap`, `pgschema.*`, `diag.Wrap`.
- Produces, in `internal/unavailable`:

```go
// ValidateConfig checks cfg as Wrap does, without a backend, namespace or
// policy: a known mode, a positive timeout and probe interval, a clock and a
// logger. It is what a backend's factory checks its options with.
func ValidateConfig(cfg Config) error
```

- Produces, in `internal/pglimiter`:

```go
// Row is one result row; *sql.Row and pgx.Row both satisfy it.
type Row interface{ Scan(dest ...any) error }

// Runner runs the limiter's statements over one adapter's handle.
type Runner interface {
	Exec(ctx context.Context, sql string, args ...any) (rowsAffected int64, err error)
	QueryRow(ctx context.Context, sql string, args ...any) Row
}

// Config is what the adapters' limiter options describe.
type Config struct {
	Clock          clock.Clock // nil: the database's clock
	ClockSet       bool
	Unavailable    unavailable.Config
	PruneBatchSize int // Task 5; zero until then is never read
}

func DefaultConfig() Config               // Unavailable: unavailable.DefaultConfig()
func (c Config) Validate() error          // lock-timeout ceiling, nil clock, then unavailable.ValidateConfig
func ValidatePolicy(namespace string, limit int, window time.Duration) error
func LockTimeout(d time.Duration) string  // "%dms", at least 1
func Now(clk clock.Clock) any             // nil, or clk.Now().UTC().Truncate(time.Microsecond)

// Backend is the ratelimit.Limiter the decorator wraps.
func NewBackend(r Runner, prefix, namespace string, limit int, window time.Duration, cfg Config) ratelimit.Limiter

// Verify runs the server-facts check and the probe, as the adapters' Verify did.
func Verify(ctx context.Context, r Runner, prefix string, cfg Config) error

type Policy struct{ Limit int; Window time.Duration }
func (p Policy) String() string           // "%d per %s"
type Registry struct{ /* mu, built map[string]Policy */ }
func NewRegistry() *Registry
// Claim builds through build, under the registry's lock, unless namespace
// already holds a different policy, and records the policy only when build succeeds.
func (r *Registry) Claim(namespace string, p Policy, build func() (ratelimit.Limiter, error)) (ratelimit.Limiter, error)
```

`prefix` is `"sqlstore"` or `"pgx"`. Every error text the adapters produce today keeps its exact wording, with `prefix` in place of the literal.

- [ ] **Step 3.1: Baseline**

Run, and save the output to the scratchpad:

```bash
go test -count=1 -run 'Limiter' ./sqlstore/ ./internal/unavailable/ > $SCRATCH/baseline-core.txt
(cd pgx && go test -count=1 -run 'Limiter' ./...) > $SCRATCH/baseline-pgx.txt
(cd test && go test -count=1 -run 'Limiter|PGLimiter' ./...) > $SCRATCH/baseline-test.txt
go doc -all ./sqlstore | sed -n '/^type Limiter /,$p' > $SCRATCH/api-sqlstore.txt
(cd pgx && go doc -all . ) > $SCRATCH/api-pgx.txt
```

Expected: all `ok`.

- [ ] **Step 3.2: Red — `unavailable.ValidateConfig`**

Add `func ValidateConfig(cfg Config) error { return nil }` as a stub, and a table test, `TestValidateConfig`, with these cases:

| case | cfg | assert |
|---|---|---|
| default | `DefaultConfig()` | `NoError` |
| unknown mode | `Mode = 99` | `ErrorIs ErrConfig`, contains `unknown unavailable mode 99` |
| zero timeout | `Timeout = 0` | contains `bounds nothing` |
| zero probe | `ProbeInterval = 0` | contains `probe interval` |
| nil clock | `Clock = nil` | contains `the clock is nil` |
| nil logger | `Logger = nil` | contains `the logger is nil` |

Run: `go test -count=1 -run TestValidateConfig ./internal/unavailable/`
Expected: FAIL on every refusal case (stub returns nil); default passes.

- [ ] **Step 3.3: Implement `ValidateConfig`**

Move the mode, timeout, probe, clock and logger cases out of `validate` into `ValidateConfig`. `validate` checks the backend, namespace, limit and window, then returns `ValidateConfig(cfg)`. The order of the checks stays as it is today.

Run: `go test -count=1 ./internal/unavailable/`. Expected: PASS.

- [ ] **Step 3.4: Red, then green — `internal/pglimiter`**

Write the tests first, against stubs that return zero values:
- `config_test.go`: `TestValidatePolicy`. Cases: empty namespace, colon, NUL, invalid UTF-8, 65 bytes, limit 0, limit 401, window 999ns, and a valid policy. Each refusal asserts `ErrorIs(err, ratelimit.ErrConfig)` and the message text the adapters use today (copy from `sqlstore/limiter.go` `validateLimiter`).
- `TestConfigValidate`. Cases: timeout `(pgschema.LimiterMaxLockTimeoutMS+1) * time.Millisecond`, `ClockSet` with a nil clock, nil logger (via `ValidateConfig`), and the default.
- `TestLockTimeout`. Cases: 0 → `"1ms"`, 250ms → `"250ms"`, 1500µs → `"1ms"`.
- `facts_test.go`: `TestFactsCheck`, a table over `Facts{InRecovery, Version, TableExists, Logged}` with today's four refusals and messages.
- `registry_test.go`: `TestRegistryClaim`. Cases: same policy twice builds twice; a different policy is refused naming both policies; a failed build does not claim the namespace.
- `runner_test.go`: `TestVerify` and `TestBackend`, over a hand-written `fakeRunner` with scripted results (`exec []execResult`, `rows []rowResult`). The cases:
  - `Verify` refuses facts before probing (assert the runner saw one query).
  - A 42501 on record maps to a configuration error naming "record".
  - Any other error has fixed text and does not contain the fake error's text.
  - The backend's `Exceeded` compares the count with the limit.
  - A record error is wrapped with `prefix + ": rate-limit record: "`.

Run: `go test -count=1 ./internal/pglimiter/`. Expected: FAIL on the stubs' zero values; record the output.

Implement by moving the code from `sqlstore/limiter.go` (`validateLimiter`, `lockTimeout`, `limiterNow`, `limiterBackend`), `sqlstore/limiter_verify.go` (`limiterServerFacts`, `verify`, `probe`, `probeError`, the `sqlStater` interface, `sqlStateInsufficientPrivilege`) and `sqlstore/limiter_factory.go` (`limiterPolicy`, the `built` map logic). Then replace `"sqlstore"` with `prefix`.

Run: `go test -count=1 ./internal/pglimiter/`. Expected: PASS.

- [ ] **Step 3.5: Move the adapters onto the core**

Each adapter keeps:
- its exported API and godoc, unchanged;
- a nil-handle check with its own message (`the database handle is nil` / `the pool is nil`);
- a runner over its handle.

```go
// sqlstore
type limiterRunner struct{ db *sql.DB }

func (r limiterRunner) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r limiterRunner) QueryRow(ctx context.Context, q string, args ...any) pglimiter.Row {
	return r.db.QueryRowContext(ctx, q, args...)
}

// pgx
type limiterRunner struct{ pool *pgxpool.Pool }

func (r limiterRunner) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	tag, err := r.pool.Exec(ctx, q, args...)
	return tag.RowsAffected(), err
}

func (r limiterRunner) QueryRow(ctx context.Context, q string, args ...any) pglimiter.Row {
	return r.pool.QueryRow(ctx, q, args...)
}
```

- `limiterConfig` becomes `struct{ core pglimiter.Config }`.
- The options write `c.core.Clock`, `c.core.Unavailable.Timeout`, and so on.
- `newLimiterConfig` starts from `pglimiter.DefaultConfig()`.

`NewLimiter`:

```go
	cfg := newLimiterConfig(opts)
	if nilcheck.IsNil(db) {
		return nil, fmt.Errorf("%w: the database handle is nil", ratelimit.ErrConfig)
	}
	if err := pglimiter.ValidatePolicy(namespace, limit, window); err != nil {
		return nil, err
	}
	if err := cfg.core.Validate(); err != nil {
		return nil, err
	}
	window = window.Truncate(time.Microsecond)
	r := limiterRunner{db: db}
	wrapped, err := unavailable.Wrap(pglimiter.NewBackend(r, "sqlstore", namespace, limit, window, cfg.core),
		namespace, limit, window, cfg.core.Unavailable)
```

`NewLimiterFactory` drops `limiterFactoryProbeNamespace` and the discarded limiter (decision 6):

```go
	opts = slices.Clone(opts)
	if nilcheck.IsNil(db) {
		return nil, fmt.Errorf("%w: the database handle is nil", ratelimit.ErrConfig)
	}
	cfg := newLimiterConfig(opts)
	if err := cfg.core.Validate(); err != nil {
		return nil, err
	}
```

- `LimiterFactory.NewLimiter` calls `f.registry.Claim(namespace, pglimiter.Policy{Limit: limit, Window: window.Truncate(time.Microsecond)}, func() (ratelimit.Limiter, error) { return NewLimiter(f.db, namespace, limit, window, f.opts...) })`.
- `Verify` calls `pglimiter.Verify(ctx, limiterRunner{db}, "sqlstore", cfg.core)`.
- `Prune` stays in the adapter for now. Task 5 moves it.

Do the same in `pgx` with `"pgx"`.

Run:
- `go test -count=1 -run 'Limiter' ./sqlstore/ ./internal/...`, `(cd pgx && go test -count=1 ./...)` and `(cd test && go test -count=1 -run 'Limiter|PGLimiter' ./...)`. Expected: the same tests pass as in the 3.1 baselines (`diff <(grep -E '^(ok|FAIL|---)' ...)`).
- `go doc -all ./sqlstore` and the pgx equivalent, diffed against the saved API files. Expected: no difference in exported identifiers or godoc.
- Then `go vet` and `gofmt -l`.

- [ ] **Step 3.6: Commit**

```bash
git add internal/unavailable internal/pglimiter sqlstore/limiter* pgx/limiter*
git commit -m "refactor(ratelimit): one PostgreSQL limiter core under both adapters"
```

---

### Task 4: `Verify` refuses what the limiter cannot serve (tasks 4.1–4.3)

**Model:** Sonnet. Two checks the design states exactly, added to the core Task 3 built. It runs after Task 3.

**Files:**
- Modify: `internal/pgschema/ratelimit.go` (`LimiterServerFacts`)
- Modify: `internal/pglimiter/facts.go`, `facts_test.go`, `runner.go` (the scan)
- Modify: `test/pg_ratelimit_test.go` (`runPGVerify` gains cases), godoc in both factories and limiters

**Interfaces:**
- Consumes: `pglimiter.Facts`, `pglimiter.Verify` from Task 3.
- Produces: `Facts` gains `Persistence string` (`"p"`, `"u"`, `"t"`, or `""` when there is no table) in place of `Logged bool`, and `Encoding string`.

- [ ] **Step 4.1a: Red — encodings in the test module**

Add a helper in `test/pg_ratelimit_test.go`:

```go
// pgEncodedDatabase creates a database with encoding enc on conn's server,
// dropped at cleanup, and returns a handle to it and its DSN. It carries no
// migration; Verify must refuse it on the encoding before it looks for the
// table.
func pgEncodedDatabase(t *testing.T, conn PostgresConn, enc string) (*sql.DB, string) {
	t.Helper()

	sum := sha256.Sum256([]byte(t.Name()))
	name := "scrty_enc_" + hex.EncodeToString(sum[:6])
	_, err := conn.DB.ExecContext(t.Context(),
		`CREATE DATABASE `+name+` ENCODING '`+enc+`' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0`) //nolint:gosec // fixed identifiers
	require.NoError(t, err)

	u, err := url.Parse(conn.DSN)
	require.NoError(t, err)
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := conn.DB.ExecContext(ctx, `DROP DATABASE `+name+` WITH (FORCE)`)
		assert.NoError(t, err)
	})
	return db, u.String()
}
```

Add cases to `runPGVerify`'s table, one each for `LATIN1`, `SQL_ASCII` and `EUC_JP`. Each target is `pgVerifyTarget{db: db, dsn: dsn, admin: conn.DB}` from `pgEncodedDatabase(t, migratedLimiterDB(t), enc)`. The assert is: `ErrorIs(err, ratelimit.ErrConfig)`, `Contains(err.Error(), enc)`, `Contains(err.Error(), "UTF8")`. Follow the table's existing assert shape, which covers both factory and limiter.

Run: `(cd test && go test -count=1 -run 'TestSQLStoreLimiter_Verify|TestPgxLimiter_Verify' ./...)`
Expected: the three new cases FAIL. The error names the missing table (`does not resolve through the connection's search_path`), not the encoding.

- [ ] **Step 4.2: Red — temporary table, and the UTF-8 temporary combination (Review Focus 4)**

Add a target builder that creates the temporary table on every connection of a one-connection handle:

```go
// pgTempTableTarget returns handles on conn's database whose every
// connection has a temporary rate_limit_buckets shadowing the migration's.
func pgTempTableTarget(t *testing.T, conn PostgresConn) pgVerifyTarget {
	t.Helper()

	cfg, err := pgx.ParseConfig(conn.DSN)
	require.NoError(t, err)
	db := stdlib.OpenDB(*cfg, stdlib.OptionAfterConnect(func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `CREATE TEMP TABLE rate_limit_buckets (LIKE public.rate_limit_buckets INCLUDING ALL)`)
		return err
	}))
	t.Cleanup(func() { _ = db.Close() })
	return pgVerifyTarget{db: db, dsn: conn.DSN, admin: conn.DB}
}
```

The pgx backend builds its own pool from `dsn`. For this case, the pgx backend's `factory` builder needs a pool with the same `AfterConnect`. Add an optional `afterConnect func(ctx context.Context, c *pgx.Conn) error` field to `pgVerifyTarget`. When it is set, the pgx verify builder uses `pgxpool.ParseConfig` and sets `AfterConnect` (read `runPGVerify` first, and plumb it the way `dsn` is plumbed).

The assert: `ErrorIs ErrConfig`, `Contains "temporary"`, `NotContains "SET LOGGED"`.

Run: same command as 4.1a. Expected: FAIL. The message says `unlogged ... SET LOGGED`.

- [ ] **Step 4.3: Implement**

`LimiterServerFacts`:

```go
	// LimiterServerFacts reports, in one row, whether the server is a standby
	// (in_recovery), its server_version_num, its server_encoding, and the
	// relpersistence of the bucket table that resolves through search_path:
	// 'p' permanent, 'u' unlogged, 't' temporary, or '' when none resolves.
	LimiterServerFacts = `SELECT pg_is_in_recovery(),
  current_setting('server_version_num')::int,
  current_setting('server_encoding'),
  coalesce((SELECT c.relpersistence::text FROM pg_class c
            WHERE c.oid = to_regclass('rate_limit_buckets')), '')`
```

`Facts.Check()` order: standby, version, **encoding**, table missing (`Persistence == ""`), **temporary** (`"t"`), unlogged (`"u"`).

```go
	case f.Encoding != "UTF8":
		return fmt.Errorf("%w: the database's server encoding is %s; the limiter needs UTF8, "+
			"the encoding every key and namespace is stored in", ratelimit.ErrConfig, f.Encoding)
	case f.Persistence == "t":
		return fmt.Errorf("%w: the table %s resolves to a temporary table, which shadows the migration's "+
			"and lasts only for its session; drop it", ratelimit.ErrConfig, pgschema.LimiterTable)
```

Extend `TestFactsCheck` with cases for `LATIN1`, `SQL_ASCII` and `"t"`, written and seen failing before the switch changes.

Godoc:
- In both factories' `Verify` list, add after the version bullet: `//   - a database whose server encoding is not UTF8, SQL_ASCII included: keys and namespaces are stored as UTF-8;`.
- After the unlogged bullet, add: `//   - a temporary table of that name, which shadows the migration's;`.
- In both `LimiterFactory` type docs, add a sentence after the primary-only paragraph: `The database must be UTF8; Verify refuses any other encoding.`

Run: `go test -count=1 ./internal/pglimiter/`, then `(cd test && go test -count=1 -run 'Verify' ./...)`. Expected: PASS, including the existing cases.

- [ ] **Step 4.4: Commit**

```bash
git add internal/pgschema/ratelimit.go internal/pglimiter sqlstore/limiter* pgx/limiter* test/pg_ratelimit_test.go
git commit -m "fix(ratelimit): Verify refuses non-UTF8 databases and names a temporary table"
```

---

### Task 5: The prune bounds itself in batches (tasks 5.1–5.5)

**Model:** Opus. The batch loop, its race guarantees and the record-wait test are ordering under concurrency, and a wrong prune would pass a naive test while still being wrong. It runs after Task 4, because it shares `internal/pglimiter` and `internal/pgschema/ratelimit.go`.

**Files:**
- Modify: `internal/pgschema/ratelimit.go` (`LimiterPrune`, new `LimiterClock`)
- Create: `internal/pglimiter/prune.go`, `prune_test.go`
- Modify: `internal/pglimiter/config.go` (`PruneBatchSize`, `DefaultPruneBatchSize`)
- Modify: `sqlstore/limiter_options.go`, `limiter_factory.go`; `pgx/limiter_options.go`, `limiter_factory.go`; option tests in `sqlstore/limiter_test.go`, `pgx/limiter_test.go`
- Modify: `test/pg_ratelimit_prune_test.go` (new cases, re-pointed broken variants)

**Interfaces:**
- Consumes: `pglimiter.Runner`, `pglimiter.Config`, `diag.Wrap`.
- Produces:

```go
// internal/pglimiter
const DefaultPruneBatchSize = 1000
func Prune(ctx context.Context, r Runner, prefix string, cfg Config) (int, error)

// sqlstore and pgx
// WithLimiterPruneBatchSize sets how many keys one prune batch removes, each
// batch its own transaction. Default: 1,000 ...
func WithLimiterPruneBatchSize(n int) LimiterOption
```

- [ ] **Step 5.1a: Red — records during a large prune**

In `test/pg_ratelimit_prune_test.go`, add `TestPGLimiter_PruneUnderRecords` (package `test`). Run it over both backends with the database clock (`b.factory(t, conn.DB, conn.DSN, nil)`), so the records stamp real time:

```go
func runPGPruneUnderRecords(t *testing.T, b pgBackend) {
	t.Helper()

	conn := migratedLimiterDB(t)
	ns := pgScopedNamespace(t, "victims")
	_, err := conn.DB.ExecContext(t.Context(), `
INSERT INTO rate_limit_buckets (namespace, key, stamps, newest_at, longest_window_us)
SELECT $1, 'k' || g, ARRAY[now() - interval '1 hour'], now() - interval '1 hour', 60000000
FROM generate_series(1, 1000000) AS g`, ns)
	require.NoError(t, err)

	f := pruneFactory250ms(t, b, conn) // the default 250ms operation timeout; pgTestTimeout is 5s
	l, err := f.NewLimiter(ns, 5, time.Minute)
	require.NoError(t, err)

	done := make(chan struct{})
	var removed int
	var pruneErr error
	go func() {
		defer close(done)
		removed, pruneErr = f.Prune(t.Context())
	}()

	var (
		mu       sync.Mutex
		recorded []string
		slow     []time.Duration
	)
	var wg sync.WaitGroup
	tick := time.NewTicker(3 * time.Millisecond) // about 300 records a second
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-done:
			wg.Wait()
			require.NoError(t, pruneErr)
			assert.Positive(t, removed)
			assert.Empty(t, slow, "records waited on the prune past their timeout")
			for _, k := range recorded {
				var n int
				require.NoError(t, conn.DB.QueryRowContext(t.Context(),
					`SELECT count(*) FROM rate_limit_buckets WHERE namespace = $1 AND key = $2`, ns, k).Scan(&n))
				assert.Equal(t, 1, n, "the prune removed key %s, recorded during the run", k)
			}
			return
		case <-tick.C:
			key := fmt.Sprintf("k%d", 1+(i*7919)%1000000) // spread over the victims
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				err := l.RecordFailure(t.Context(), key)
				d := time.Since(start)
				mu.Lock()
				defer mu.Unlock()
				if err != nil || d > 250*time.Millisecond {
					slow = append(slow, d)
					return
				}
				recorded = append(recorded, key)
			}()
		}
	}
}
```

`pgTestTimeout` is 5s, so `b.factory` cannot be used here. Add `pruneFactory250ms(t, b, conn) pgFactory`, which switches on `b.name`: it builds `sqlstore.NewLimiterFactory(conn.DB, sqlstore.WithLimiterLogger(discard))`, or `pgxstore.NewLimiterFactory(pgxTestPool(t, conn.DSN), pgxstore.WithLimiterLogger(discard))`, so the default 250ms operation timeout and the database clock apply. Gate the test with `if testing.Short() { t.Skip("seeds a million rows") }`.

Run: `(cd test && go test -count=1 -run 'TestPGLimiter_PruneUnderRecords' ./...)`
Expected: FAIL with `records waited on the prune past their timeout`, because `slow` is not empty under today's single statement.

- [ ] **Step 5.1b: Red — Review Focus 2 and 3, in the core**

In `internal/pglimiter/prune_test.go`, against a stub `Prune` that returns `0, nil`. A `fakeRunner` scripts `Exec` results, and its `QueryRow` returns a fixed `time.Time` for `LimiterClock`:

| case | batch | exec results | assert |
|---|---|---|---|
| empty table | 1000 | `0` | `0, nil`; one Exec |
| short first batch stops | 1000 | `400` | `400, nil`; one Exec |
| full batches then short | 2 | `2, 2, 1` | `5, nil`; three Execs; each Exec's args are `(sameTime, 2)` |
| application clock | 2 | `1` | the clock's time, truncated to µs, is `$1`; no QueryRow |
| database clock read once | 2 | `2, 0` | one QueryRow, and both Execs carry its time |

- [ ] **Step 5.2: Red — the batch-size option (Review Focus 5)**

In `sqlstore/limiter_test.go` and `pgx/limiter_test.go`, add to the factory-construction table:
- `{name: "prune batch 0", opts: []LimiterOption{WithLimiterPruneBatchSize(0)}, assert: refused("batch")}`
- `{name: "prune batch -1", ...}`
- `{name: "nil option ignored", opts: []LimiterOption{nil, WithLimiterPruneBatchSize(2)}, assert: accepted}`

In `test/pg_ratelimit_test.go`, add to `runPGFactoryPrune` (or as a sibling runner) a case that builds the factory with a batch size of 2, records 5 idle keys, advances the clock past the window and prunes. Assert `5, nil` and no rows left.

The option must exist as a no-op stub, `func WithLimiterPruneBatchSize(n int) LimiterOption { return func(*limiterConfig) {} }`, so that the red step is not a compile error.

Run: the adapters' option tests and `(cd test && go test -count=1 -run 'FactoryPrune' ./...)`
Expected:
- "prune batch 0" and "-1" FAIL (accepted).
- The batch-size-2 prune passes vacuously today, because the single statement removes all 5. That is recorded and expected: 5.4's loop must keep it green, and 5.1b pins the batching itself.

- [ ] **Step 5.3: Red — partial count, withheld text, cancellation**

Test module, in `test/pg_ratelimit_prune_test.go`:

```go
// pgFailThirdDelete installs a trigger that lets two bucket deletes through
// and fails every later one with a distinctive message.
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
```

The case: a factory with a fake clock and a batch size of 2, 5 idle keys, `pgFailThirdDelete`, then `Prune`. Assert:
- `removed == 2`;
- `require.Error`;
- `NotContains(err.Error(), marker)`;
- the bucket rows for the namespace number 3.

Core, in `internal/pglimiter/prune_test.go`, more rows for the table:

| case | exec results | assert |
|---|---|---|
| cancelled during first batch | `2` (the fake cancels `ctx` inside Exec), batch 2 | `2`, `ErrorIs(err, context.Canceled)`; one Exec |
| failed second batch | `2`, then `errors.New("server says secret-xyz")` | `2`, `Error`, `NotContains "secret-xyz"`, `ErrorIs` the fake error |
| clock read fails | QueryRow error `"secret-abc"` | `0`, `NotContains "secret-abc"` |

Run: `go test -count=1 -run TestPrune ./internal/pglimiter/` and `(cd test && go test -count=1 -run 'Prune' ./...)`
Expected:
- The core cases FAIL against the stub.
- The trigger case FAILS. Today's single statement aborts entirely, so `removed == 0`, five rows remain, and the error text contains the marker (`%w`).

- [ ] **Step 5.4: Implement**

`internal/pgschema/ratelimit.go`:

```go
	// LimiterClock reads the database clock once, for a prune's whole run.
	LimiterClock = `SELECT clock_timestamp()`

	// LimiterPrune deletes one batch of idle keys: those whose newest stamp is
	// at least the longest window ever recorded for them older than $1, at
	// most $2 of them. It locks each victim (FOR UPDATE), and the lock rechecks
	// idleness on a row a record updated after the statement's snapshot, so a
	// key recorded during the prune is kept. Rows another transaction holds
	// are skipped (SKIP LOCKED), never waited for. Rows affected is the count
	// removed. Run it in a loop until a batch removes fewer than $2, each batch
	// its own transaction, so no record waits on more than one batch.
	LimiterPrune = `WITH v AS (
  SELECT b.namespace, b.key FROM rate_limit_buckets b
  WHERE b.newest_at + b.longest_window_us * interval '1 microsecond' <= $1::timestamptz
  LIMIT $2::int
  FOR UPDATE OF b SKIP LOCKED)
DELETE FROM rate_limit_buckets d USING v
WHERE d.namespace = v.namespace AND d.key = v.key`
```

`internal/pglimiter/prune.go`:

```go
// Prune deletes idle keys in batches of cfg.PruneBatchSize, each its own
// statement and so its own transaction, and returns how many keys the batches
// that committed removed. The time is read once, before the first batch: the
// configured clock, or the database's. It stops on a short batch, on an ended
// ctx, or on the first failed batch; the count it returns with an error is a
// lower bound, every key of it removed. No error repeats the server's text.
func Prune(ctx context.Context, r Runner, prefix string, cfg Config) (int, error) {
	now := Now(cfg.Clock)
	if now == nil {
		var t time.Time
		if err := r.QueryRow(ctx, pgschema.LimiterClock).Scan(&t); err != nil {
			return 0, diag.Wrap(err, prefix+": rate-limit prune: the database clock could not be read")
		}
		now = t
	}

	total := 0
	for {
		n, err := r.Exec(ctx, pgschema.LimiterPrune, now, cfg.PruneBatchSize)
		if err != nil {
			return total, diag.Wrap(err, prefix+": rate-limit prune: a batch could not be deleted")
		}
		total += int(n)
		if n < int64(cfg.PruneBatchSize) {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("%s: rate-limit prune: stopped after %d keys: %w", prefix, total, err)
		}
	}
}
```

`Config`:
- `DefaultConfig` sets `PruneBatchSize: DefaultPruneBatchSize`.
- `Validate` adds: `case c.PruneBatchSize < 1: return fmt.Errorf("%w: a prune batch of %d keys removes nothing", ratelimit.ErrConfig, c.PruneBatchSize)`.

Adapters:

```go
// WithLimiterPruneBatchSize sets how many keys one batch of the factory's
// prune removes. Each batch is its own transaction, and holds its victims'
// row locks only until it commits, so a record on a key being pruned waits at
// most one batch. Default: 1,000, which ran in 18-29ms over a million idle
// keys; batches of 5,000 or more ran over 100ms, near the default operation
// timeout. A size below 1 fails construction with ratelimit.ErrConfig.
func WithLimiterPruneBatchSize(n int) LimiterOption {
	return func(c *limiterConfig) { c.core.PruneBatchSize = n }
}

func (f *LimiterFactory) Prune(ctx context.Context) (int, error) {
	return pglimiter.Prune(ctx, limiterRunner{f.db}, "sqlstore", f.cfg.core)
}
```

The factory keeps `cfg limiterConfig` in place of its `clock` field.

Prune godoc, in both factories:
- Replace "It is one statement ... A database failure is an error wrapping the driver's, with nothing deleted." with the batched behaviour:

```go
// It runs in batches (WithLimiterPruneBatchSize), each its own transaction,
// so a record on a key being pruned waits at most one batch. Rows another
// session holds, such as a record in flight, are skipped rather than waited
// for, and kept until a later prune. It applies no operation timeout of its
// own, and is bounded by ctx, which an expiry.Runner bounds with its run
// timeout; ctx is checked between batches.
//
// Run it through ratelimit.ExpiryTask(f). On a failure or an ended ctx, it
// returns the keys the committed batches removed, a lower bound, with an
// error that repeats none of the server's text.
```

- In the `LimiterFactory` type doc, the "Run the prune task every ten minutes" paragraph keeps the ten minutes. Remove any sentence saying a large backlog can open the breaker, if one exists (`grep -n breaker sqlstore/limiter_factory.go pgx/limiter_factory.go`).

Run:
- `go test -count=1 ./internal/pglimiter/ ./sqlstore/`
- `(cd pgx && go test -count=1 ./...)`
- `(cd test && go test -count=1 -run 'Prune|PruneUnderRecords|FactoryPrune' ./...)`

Expected: PASS, 5.1a included, with `slow` empty.

- [ ] **Step 5.5: Re-point the broken variants**

The variants edit `LimiterPrune`'s text, and `pgStatementPruneFactory` passes `$1` (time) plus `extra`. With the new statement:
- `pgPruneWithoutRowLock`: `old: "\n  FOR UPDATE OF b SKIP LOCKED"`, unchanged text, and still present exactly once. Its factory passes `extra = []any{1000}` for `$2`.
- `pgPruneByCheckingWindow`: `$2` is now the batch size. Edit `old: "b.longest_window_us * interval"`, `new: "$3::bigint * interval"`, with `extra = []any{1000, time.Minute.Microseconds()}`.
- Add `pgPruneWithoutSkipLocked`: `old: " SKIP LOCKED"`, `new: ""`, `extra = []any{1000}`. Catch it with `failsCase: "row another session holds is skipped without waiting"` and the `failsWith` that case's assertion prints (read the case at line 112 for its message).

`pgStatementPruneFactory.Prune` runs one statement, which is enough for these cases, since each has fewer than 1,000 rows.

Run: `(cd test && go test -count=1 -run 'TestPGLimiter_PruneCatchesBrokenVariants|TestPGLimiter_Prune$' ./...)`
Expected: PASS. Every variant is caught by its named case.

- [ ] **Step 5.6: Commit**

```bash
git add internal/pgschema/ratelimit.go internal/pglimiter sqlstore/limiter* pgx/limiter* test/pg_ratelimit_prune_test.go test/pg_ratelimit_test.go
git commit -m "fix(ratelimit): the PostgreSQL prune deletes in batches, so no record waits on it"
```

---

### Task 6: Factory godoc states the conflict check's reach (task 6.1)

**Model:** Sonnet, for godoc and an example. It can run in parallel with Task 4, since it touches only the `LimiterFactory` type doc paragraph and the example files. If Task 4 is editing the same type doc, sequence it after Task 4 instead. The safe default is to run it after Task 5.

**Files:**
- Modify: `sqlstore/limiter_factory.go`, `pgx/limiter_factory.go`, `redis/limiter*.go` (the factory type doc)
- Modify: `sqlstore/example_limiter_test.go`, `pgx/example_limiter_test.go`, `redis/example_test.go` (whichever shows two factories)

- [ ] **Step 6.1a: Red**

This is documentation, so there is no behaviour test. The red step is the example's `// Output:`. If the example prints the namespaces it builds, change it first so it prints them, and run `go test -run Example` to see the new output fail. Then make the two factories' namespaces visibly disjoint (`"api-key"` and `"magic-link"`, not one namespace twice).

- [ ] **Step 6.1b: Implement**

Replace "The factory cannot see other processes, so every replica must still configure a namespace the same way." in each of the three packages with:

```go
// The check covers this factory only. It cannot see another factory in the
// same process, over the same handle or not, nor another process, so no two
// factories or replicas may build one namespace with different policies.
```

Run: `go test -count=1 -run Example ./sqlstore/ && (cd pgx && go test -count=1 -run Example ./...) && (cd redis && go test -count=1 -run Example ./...)`, `go vet`, and `go doc ./sqlstore LimiterFactory | grep -n 'covers this factory'`.
Expected: PASS, and the new sentence is shown.

- [ ] **Step 6.2: Commit**

```bash
git add sqlstore/limiter_factory.go pgx/limiter_factory.go redis/ <example files>
git commit -m "docs(ratelimit): state the reach of the factories' policy-conflict check"
```

---

### Task 7: Integration (tasks 7.1–7.3)

Run by the main session, not delegated.

- [ ] **Step 7.1: Full gate**

```bash
for m in . pgx redis gorm sweep fibersec ginsec passkey/webauthn test; do (cd $m && go test -count=1 ./... && go vet ./...) || echo "FAIL $m"; done
gofmt -l .
make lint
```

Expected: no `FAIL`, no `gofmt` output, and lint clean.

- [ ] **Step 7.2: Benchmarks**

```bash
(cd test && go test -run '^$' -bench 'BenchmarkPostgresLimiter$|BenchmarkPostgresLimiterPrune' -count=6 ./...) | tee $SCRATCH/bench-18.txt
(cd test && SCRTY_TEST_POSTGRES_IMAGE=postgres:15 go test -run '^$' -bench 'BenchmarkPostgresLimiter$|BenchmarkPostgresLimiterPrune' -count=6 ./...) | tee $SCRATCH/bench-15.txt
```

Compare with `design.md` decision 2's figures. A record at the default limits must not regress. If the prune's total run time drifts from the measured 2.7–2.8s at 10⁶ rows, record the drift in `design.md`.

- [ ] **Step 7.3: Whole-branch review**

Dispatch an Opus reviewer, which edits nothing, against `specs/rate-limiting/spec.md` (every requirement and scenario) and `design.md` decisions 1–10. Each defect it claims needs a failing test or an `UNREPRODUCED` label. Fold the findings back through a fresh dispatch.
