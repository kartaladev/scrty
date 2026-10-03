# Testcontainers Optimize Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session does not write Go code: each code task below is one implementer dispatch, followed by verification and a fresh reviewer (`.claude/rules/subagent-delegation.md`). Tasks 1.1, 4.1, 4.2 and 4.3 are the main session's own work: measurement, a skill document, the gate. The main session commits.

**Goal:** Cut the `test` module's wall time by sharing one PostgreSQL server per test process and image, and handing each `RunTestPostgres` call a database cloned from a migrated template, with every test and per-call check exactly as strong as today.

**Architecture:**
- A process-wide registry maps a resolved image to a lazily started server.
- A template database per ordered migration list is built once per server, under an in-process lock and a server advisory lock.
- Each call clones the template (or `template1` when no set is named), registers today's teardown on the clone (rollback, finalize scripts, leftover check), then drops it.
- Child test processes inherit their parent's servers through an environment variable.

**Tech Stack:** Go 1.27, testcontainers-go v0.44 (`modules/postgres`), pgx v5 stdlib driver, goose v3 providers, testify. PostgreSQL 15.19 and 18.6 alpine images.

**Spec:**
- `openspec/changes/testcontainers-optimize/proposal.md`
- `openspec/changes/testcontainers-optimize/design.md`, decisions D1–D9
- `openspec/changes/testcontainers-optimize/specs/test-provisioning/spec.md`
- `openspec/changes/testcontainers-optimize/tasks.md`; every task below names its task number.

## Global Constraints

- **Test-first for every code task.** Write the failing test, run it focused, and confirm it fails for the intended reason. A compile error is not a red step: land the API shape with a stub first (`.claude/rules/golang-tdd.md`).
- **Table tests** use the `assert` closure form and `t.Context()`, never `context.Background()` in a test body (`.claude/skills/table-test`).
- **Containers** come only from the `test` module's helpers (`.claude/skills/use-testcontainers`).
- **Defect claims** made during the work need a failing test or an `UNREPRODUCED` label (`.claude/rules/defect-claims.md`).
- **No caller of `RunTestPostgres` changes.** Its signature, its options and `PostgresConn{DB, DSN}` stay as they are. The only caller edits are one `test.EnsureTestPostgresServer(t)` line in `test/sqlstore/broken_test.go`, `test/pgxstore/broken_test.go`, `test/gormstore/broken_test.go` and `test/crossbackend/naming_test.go`.
- **No test is removed, skipped or weakened.** The `go test -json` count of passed tests and subtests must equal the baseline from task 1.1.
- **Every default has an override** (`library-design.md`): sharing by default, `WithTestPostgresOwnServer()` to opt out. Godoc names the default each option replaces.
- **No new module dependency.** `golang.org/x/sync` is only indirect in `test/go.mod`, so the in-process build lock is a mutex map, not `singleflight`.
- **Identifiers in SQL** are quoted with `pgx.Identifier{name}.Sanitize()`, and values are bound. Database names are generated (`tpl_<hex>`, `t_<hex>`) and never come from a caller.
- **No git command that discards work** is run by any agent (`checkout --`, `restore`, `reset --hard`, `stash`, `clean`).
- **The legacy snapshot** is never read for this change, and never cited.
- **The gate per module:** `go build ./... && go vet ./... && gofmt -l .` (empty), `golangci-lint run ./...` (0 issues), and `go test -race ./...`.

## Review Focus

1. **The image changes mid-process.** `TestRunTestPostgresImage` sets `SCRTY_TEST_POSTGRES_IMAGE` after the default-image server already exists. The call must get a server running the new image, never the cached default. Servers are keyed by the resolved image (task 2.1, case "a different image gets a server of its own").
2. **Two migration sets with the same directory and version table but different files.** For example, two `fstest.MapFS` values both at `migrations`. They must get different templates: the fingerprint hashes contents, not names (task 2.3, case "same directory, different files, different templates").
3. **A stray connection to a template.** No one can connect to a built template, so no clone can ever fail with "being accessed by other users" (task 2.3, case "a built template refuses connections").
4. **A half-built template left by a killed process.** A database named like the template but not marked `datistemplate` is dropped and rebuilt, never cloned (task 2.3, case "a half-built leftover is rebuilt").
5. **Many parallel calls.** Fifty parallel calls on one server get fifty distinct database names, and none fails on a concurrent clone (task 2.2, case "fifty parallel calls get fifty databases").

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `test/testutils.go` | `RunTestPostgres` composition, `EnsureTestPostgresServer`, `WithTestPostgresOwnServer`, godoc | 2.1–2.4, 3.1 |
| `test/testutils_pgserver.go` (new) | `postgresRegistry`, `postgresServer`, container start (shared and own), child-process publication, tuning | 2.1, 3.1, 3.2 |
| `test/testutils_pgtemplate.go` (new) | fingerprint, template build, clone and drop, `postgresApply`, `postgresRegisterTeardown` | 2.2, 2.3 |
| `test/testutils_postgres_test.go` | helper tests: sharing, failures, isolation, templates, teardown, children, tuning | 2.1–3.2 |
| `test/sqlstore/broken_test.go`, `test/pgxstore/broken_test.go`, `test/gormstore/broken_test.go`, `test/crossbackend/naming_test.go` | one `test.EnsureTestPostgresServer(t)` before spawning | 3.1 |
| `.claude/skills/use-testcontainers/SKILL.md` | practice 6 and examples | 4.1 |
| `openspec/changes/testcontainers-optimize/design.md` | D6, D7 and D8 measurements | 1.1, 3.2, 4.2 |

The new files keep `testutils.go` from growing past one responsibility. They are in package `test` and are not `_test.go` files, matching where `RunTestPostgres` lives today.

---

### Task 1.1: Baseline (main session)

**Files:** `openspec/changes/testcontainers-optimize/design.md` (D8 "Before").

- [ ] **Step 1: Local timings and counts**

```bash
cd test
go test -race -count=1 -json ./... > /tmp/before.json
jq -r 'select(.Action=="pass" and .Test==null) | "\(.Package) \(.Elapsed)"' /tmp/before.json
jq -r 'select(.Action=="pass" and .Test!=null)' /tmp/before.json | jq -s length
jq -r 'select(.Action=="output") | .Output' /tmp/before.json | grep -c 'Creating container for image postgres'
```

- [ ] **Step 2: CI timings.** `gh run view 36997890510 --log` on both jobs, taking the `ok … <seconds>` lines of `github.com/kartaladev/scrty/test…`.
- [ ] **Step 3: Record** the per-package seconds (local, CI 15, CI 18), the passed count and the container count under D8 "Before". Commit: `docs(openspec): testcontainers-optimize baseline`.

---

### Task 2.1: The per-process server registry and the own-server option

**Files:**
- Create: `test/testutils_pgserver.go`
- Modify: `test/testutils.go` (`testConfig` gains `ownServer bool`; `RunTestPostgres` resolves the image and calls the registry; `startTestPostgres` becomes the own-server path over the shared start function)
- Test: `test/testutils_postgres_test.go`

**Interfaces:**
- Produces:
  - `type postgresServer struct { image string; adminDSN string; admin *sql.DB; ctr *postgres.PostgresContainer /* nil when inherited */; tmplMu sync.Mutex; tmplLocks map[string]*sync.Mutex; tmplBuilt map[string]bool; applies atomic.Int64 /* sets applied to templates, read by tests */ }`
  - `type postgresRegistry struct { start func(ctx context.Context, image string) (*postgres.PostgresContainer, error); mu sync.Mutex; entries map[string]*postgresEntry }`, where `type postgresEntry struct { once sync.Once; srv *postgresServer; err error }`
  - `func (r *postgresRegistry) server(image string) (*postgresServer, error)`
  - `var defaultPostgresRegistry = &postgresRegistry{start: startPostgresContainer}`
  - `func startPostgresContainer(ctx context.Context, image string) (*postgres.PostgresContainer, error)`: today's options, wait strategy and port retry, without `t`.
  - `var postgresContainerStarts atomic.Int64`, incremented by `startPostgresContainer` on each container it creates.
  - `func WithTestPostgresOwnServer() TestOption`
  - `func resolvePostgresImage(cfg *testConfig) string`

- [ ] **Step 1: Land the shapes with stubs.** Add the types above with `server` returning `nil, errors.New("not implemented")`, the option setting `cfg.ownServer = true`, and `resolvePostgresImage` returning today's resolution. Run `go build ./...` in `test`.

- [ ] **Step 2: Write the failing tests** in `test/testutils_postgres_test.go`:

```go
func TestPostgresServerSharing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(t *testing.T, r *postgresRegistry) []*postgresServer
		assert func(t *testing.T, starts int64, got []*postgresServer, err error)
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
			assert: func(t *testing.T, starts int64, got []*postgresServer, _ error) {
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
			assert: func(t *testing.T, starts int64, got []*postgresServer, _ error) {
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
					t.Cleanup(func() { terminateForTest(t, ctr) })
				}
				return ctr, err
			}}
			got := tc.act(t, r)
			tc.assert(t, starts.Load(), got, nil)
		})
	}
}

func TestPostgresServerStartFailureIsRemembered(t *testing.T) {
	t.Parallel()

	var starts atomic.Int64
	boom := errors.New("docker said no")
	r := &postgresRegistry{start: func(context.Context, string) (*postgres.PostgresContainer, error) {
		starts.Add(1)
		return nil, boom
	}}
	for range 40 {
		_, err := r.server(postgresImage)
		require.ErrorIs(t, err, boom)
	}
	assert.EqualValues(t, 1, starts.Load(), "a failed start must not be retried")
}

func TestRunTestPostgresOwnServer(t *testing.T) {
	t.Parallel()

	before := postgresContainerStarts.Load()
	conn := RunTestPostgres(t, WithTestPostgresOwnServer())
	require.NoError(t, conn.DB.PingContext(t.Context()))
	assert.Greater(t, postgresContainerStarts.Load(), before, "an own server starts a container for this call")
}
```

`terminateForTest(t, ctr)` is a small helper in the test file: it terminates with a 60-second background context and `t.Errorf` on failure, as `startTestPostgres`'s cleanup does today.

- [ ] **Step 3: Run them and see them fail**

Run: `cd test && go test -race -count=1 -run 'TestPostgresServerSharing|TestPostgresServerStartFailureIsRemembered|TestRunTestPostgresOwnServer' .`
Expected: FAIL with `not implemented` from `server`. The own-server case fails until `RunTestPostgres` reads `ownServer`.

- [ ] **Step 4: Implement**
  - **`startPostgresContainer(ctx, image)`.** Move today's `postgres.Run` options, the readiness wait and the unpublished-port retry here. Return the container or the error. Terminate every failed attempt itself with a 60-second background context, so nothing leaks. Increment `postgresContainerStarts` per created container.
  - **`(*postgresRegistry).server(image)`:**

```go
func (r *postgresRegistry) server(image string) (*postgresServer, error) {
	r.mu.Lock()
	if r.entries == nil {
		r.entries = map[string]*postgresEntry{}
	}
	e, ok := r.entries[image]
	if !ok {
		e = &postgresEntry{}
		r.entries[image] = e
	}
	r.mu.Unlock()

	e.once.Do(func() {
		// Not a test's context: the server outlives the call that started it.
		ctx, cancel := context.WithTimeout(context.Background(), postgresStartAttempts*(postgresReadyTimeout+postgresPortTimeout))
		defer cancel()
		ctr, err := r.start(ctx, image)
		if err != nil {
			e.err = fmt.Errorf("start PostgreSQL %s: %w", image, err)
			return
		}
		e.srv, e.err = newPostgresServer(ctx, image, ctr)
	})
	return e.srv, e.err
}
```

  - **`newPostgresServer`** reads `ctr.ConnectionString(ctx, "sslmode=disable")` as `adminDSN` (database `scrty`, used only for admin statements), and opens `admin` with `sql.Open("pgx", adminDSN)` and `SetMaxOpenConns(8)`.
  - **Teardown.** A shared server is never terminated by a test. Ryuk removes it at process exit (D1).
  - **`RunTestPostgres`** keeps `requireHealthyProvider(t)` first.
    - With `cfg.ownServer`, it builds a one-off `postgresServer` from `startPostgresContainer`, and registers `terminateForTest`-style cleanup on `t` (today's 60-second terminate).
    - Otherwise it calls `defaultPostgresRegistry.server(resolvePostgresImage(cfg))`. An error goes to `t.Fatalf("%v", err)`.
    - Until task 2.2 lands, the call returns the server's own database: `DB` opened on `adminDSN` with 32 connections, then `postgresSetUp` as today. Calls share a database until then, so the whole-module suite is red between tasks 2.1 and 2.2: `TestRunTestPostgres/isolated_databases` and the store packages fail on colliding migrations and rollbacks. Group 2 is verified as a whole only after task 2.2, and commits after task 2.3.

- [ ] **Step 5: Run green**

Run: `cd test && go test -race -count=1 -run 'TestPostgresServerSharing|TestPostgresServerStartFailureIsRemembered|TestRunTestPostgresOwnServer|TestRequireHealthyProvider' .`
Expected: PASS for the new tests. `TestRunTestPostgres/isolated_databases` fails until task 2.2.

- [ ] **Step 6: Do not commit yet.** The group commits after task 2.3, because shared databases between 2.1 and 2.2 break isolation. Dispatches 2.1 → 2.2 → 2.3 run in order in one lane.

---

### Task 2.2: A cloned database per call

**Files:**
- Create: `test/testutils_pgtemplate.go`
- Modify: `test/testutils.go` (`RunTestPostgres` clones)
- Test: `test/testutils_postgres_test.go`

**Interfaces:**
- Consumes: `postgresServer` (2.1).
- Produces:
  - `func (s *postgresServer) clone(ctx context.Context, template string) (name string, err error)`; an empty `template` means `template1`.
  - `func (s *postgresServer) drop(ctx context.Context, name string) error`, which runs `DROP DATABASE … WITH (FORCE)`.
  - `func (s *postgresServer) dsnFor(name string) (string, error)`, which swaps the database path of `adminDSN`.

- [ ] **Step 1: Write the failing tests**

```go
func TestRunTestPostgresIsolation(t *testing.T) {
	t.Parallel()

	t.Run("two calls in one test see nothing of each other", func(t *testing.T) {
		t.Parallel()
		a := RunTestPostgres(t)
		b := RunTestPostgres(t)
		_, err := a.DB.ExecContext(t.Context(), `CREATE TABLE probe (v int); INSERT INTO probe VALUES (1)`)
		require.NoError(t, err)
		var n int
		require.NoError(t, b.DB.QueryRowContext(t.Context(),
			`SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename = 'probe'`).Scan(&n))
		assert.Zero(t, n)
		assert.NotEqual(t, a.DSN, b.DSN)
	})

	t.Run("no sets gives an empty database", func(t *testing.T) {
		t.Parallel()
		conn := RunTestPostgres(t)
		var n int
		require.NoError(t, conn.DB.QueryRowContext(t.Context(),
			`SELECT count(*) FROM pg_tables WHERE schemaname = current_schema()`).Scan(&n))
		assert.Zero(t, n)
	})

	t.Run("fifty parallel calls get fifty databases", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		seen := map[string]bool{}
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
}

func TestRunTestPostgresDropsTheDatabase(t *testing.T) {
	t.Parallel()

	var name string
	srv, err := defaultPostgresRegistry.server(resolvePostgresImage(&testConfig{image: postgresImage}))
	require.NoError(t, err)
	t.Run("call", func(t *testing.T) {
		conn := RunTestPostgres(t)
		require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&name))
	})
	var n int
	require.NoError(t, srv.admin.QueryRowContext(t.Context(),
		`SELECT count(*) FROM pg_database WHERE datname = $1`, name).Scan(&n))
	assert.Zero(t, n, "the call's database outlived its test")
}
```

The parallel-truncate scenario of "Every PostgreSQL call gets a database of its own" is covered by the migrated case in task 2.3. It needs the security-state set.

- [ ] **Step 2: Run them and see them fail**

Run: `cd test && go test -race -count=1 -run 'TestRunTestPostgresIsolation|TestRunTestPostgresDropsTheDatabase' .`
Expected: FAIL. With 2.1's interim, the second call already sees `probe`, the DSNs are equal, and `seen` reports `scrty` twice.

- [ ] **Step 3: Implement** in `test/testutils_pgtemplate.go`:

```go
func (s *postgresServer) clone(ctx context.Context, template string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := "t_" + hex.EncodeToString(b[:])
	if template == "" {
		template = "template1"
	}
	_, err := s.admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+
		" TEMPLATE "+pgx.Identifier{template}.Sanitize())
	if err != nil {
		return "", fmt.Errorf("create database from %s: %w", template, err)
	}
	return name, nil
}

func (s *postgresServer) drop(ctx context.Context, name string) error {
	_, err := s.admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	return err
}

func (s *postgresServer) dsnFor(name string) (string, error) {
	u, err := url.Parse(s.adminDSN)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}
```

- **`RunTestPostgres`.** After getting the server: `name := s.clone(ctx, "")` (2.3 supplies a template). Register the drop cleanup first, so it runs last: a background context of `postgresTeardownBudget`, and `t.Errorf` on error. Then open `DB` on `dsnFor(name)` with 32 connections, registering its close. Then `postgresSetUp(t, db, cfg)` as today, which 2.3 replaces. Return `PostgresConn{DB: db, DSN: dsn}`.
- **Concurrent clones.** If "fifty parallel calls" fails with SQLSTATE `55006` ("source database … is being accessed by other users"), the D2 unverified claim is false for this case. Serialize `clone` per template with a mutex from `tmplLocks`, and record the observation in the dispatch report as REPRODUCED, with the failing output.

- [ ] **Step 4: Run green**

Run: `cd test && go test -race -count=1 -run 'TestRunTestPostgres' .` then `go test -race -count=1 .`
Expected: PASS. The root package's migration tests still apply their own sets on empty clones.

---

> **Note (2026-10-03).** Task 2.2 also sets a provisional `postgresMaxConnections = 1000` through `testcontainers.WithCmdArgs`. With one shared server per process, the default of 100 failed the store packages with SQLSTATE 53300. Task 3.2 still measures the peak and replaces the value, and its other settings are appended to the same `WithCmdArgs`.

### Task 2.3: Templates per migration list

**Files:**
- Modify: `test/testutils_pgtemplate.go`, `test/testutils.go` (`postgresSetUp` split)
- Test: `test/testutils_postgres_test.go` (new `TestPostgresTemplate`; `TestPostgresTeardown` adapted)

**Interfaces:**
- Consumes: `clone`, `drop`, `dsnFor` (2.2).
- Produces:
  - `func postgresFingerprint(migrations []postgresMigrations) (string, error)`: 16 hex characters of SHA-256 over each set's `dir`, `versionTable`, and every file's path and contents under `dir`, in order.
  - `func (s *postgresServer) template(ctx context.Context, migrations []postgresMigrations) (string, error)`: `""` when `migrations` is empty.
  - `func postgresApply(ctx context.Context, db *sql.DB, migrations []postgresMigrations) error`: applies in order; the error names the set (`apply migrations <dir>: …`).
  - `func postgresRegisterTeardown(tb cleanupTB, db *sql.DB, cfg *testConfig, sets []postgresAppliedSet)`: today's cleanup body, a reverse `DownTo(0)` then finalizers then the leftover check, within `postgresTeardownBudget`.
  - `type postgresAppliedSet struct { dir string; provider *goose.Provider }`
  - `postgresSetUp(tb, db, cfg)` keeps its signature and behaviour for `TestPostgresTeardown`. It builds the providers, registers the teardown over the sets reached so far, and applies with `Fatalf` on error, exactly as today.

- [ ] **Step 1: Write the failing tests**

```go
func TestPostgresTemplate(t *testing.T) {
	t.Parallel()

	set := migrate.SecurityState()
	identity := migrate.Identity()
	security := WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable)
	ident := WithTestPostgresMigrations(identity.FS(), identity.Dir, identity.VersionTable)

	type testCase struct {
		name   string
		run    func(t *testing.T)
	}
	cases := []testCase{
		{name: "same sets give the schema of a fresh application", run: func(t *testing.T) {
			cloned := RunTestPostgres(t, security, ident)
			fresh := RunTestPostgres(t, WithTestPostgresOwnServer())
			require.NoError(t, postgresApply(t.Context(), fresh.DB, []postgresMigrations{
				{fsys: set.FS(), dir: set.Dir, versionTable: set.VersionTable},
				{fsys: identity.FS(), dir: identity.Dir, versionTable: identity.VersionTable},
			}))
			assert.Equal(t, schemaOf(t, fresh.DB), schemaOf(t, cloned.DB))
		}},
		{name: "order gives different templates", run: func(t *testing.T) {
			a, err := postgresFingerprint([]postgresMigrations{{set.FS(), set.Dir, set.VersionTable}, {identity.FS(), identity.Dir, identity.VersionTable}})
			require.NoError(t, err)
			b, err := postgresFingerprint([]postgresMigrations{{identity.FS(), identity.Dir, identity.VersionTable}, {set.FS(), set.Dir, set.VersionTable}})
			require.NoError(t, err)
			assert.NotEqual(t, a, b)
		}},
		{name: "same directory, different files, different templates", run: func(t *testing.T) {
			one := fstest.MapFS{"m/00001_a.sql": {Data: []byte("-- +goose Up\nCREATE TABLE a (v int);\n-- +goose Down\nDROP TABLE a;\n")}}
			two := fstest.MapFS{"m/00001_a.sql": {Data: []byte("-- +goose Up\nCREATE TABLE b (v int);\n-- +goose Down\nDROP TABLE b;\n")}}
			a, err := postgresFingerprint([]postgresMigrations{{one, "m", "v"}})
			require.NoError(t, err)
			b, err := postgresFingerprint([]postgresMigrations{{two, "m", "v"}})
			require.NoError(t, err)
			assert.NotEqual(t, a, b)
		}},
		{name: "parallel first calls apply the set once and get distinct databases", run: func(t *testing.T) {
			srv := newTestPostgresServer(t) // own registry, own container: a cold server
			fsys := countingSet(t)
			var names sync.Map
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tpl, err := srv.template(t.Context(), []postgresMigrations{{fsys, "m", "v"}})
					assert.NoError(t, err)
					name, err := srv.clone(t.Context(), tpl)
					assert.NoError(t, err)
					names.Store(name, true)
				}()
			}
			wg.Wait()
			assert.EqualValues(t, 1, srv.applies.Load(), "the set's migrations must run once on a server")
			n := 0
			names.Range(func(any, any) bool { n++; return true })
			assert.Equal(t, 8, n)
		}},
		{name: "a failing set is never handed out half applied", run: func(t *testing.T) {
			srv := newTestPostgresServer(t)
			sub := os.DirFS("testdata/migrations")
			for range 2 {
				_, err := srv.template(t.Context(), []postgresMigrations{{sub, "fails_partway", "goose_fails"}})
				require.ErrorContains(t, err, "apply migrations fails_partway")
			}
			var n int
			require.NoError(t, srv.admin.QueryRowContext(t.Context(),
				`SELECT count(*) FROM pg_database WHERE datname LIKE 'tpl\_%'`).Scan(&n))
			assert.Zero(t, n, "no half-built template may remain")
		}},
		{name: "a half-built leftover is rebuilt", run: func(t *testing.T) {
			srv := newTestPostgresServer(t)
			ms := []postgresMigrations{{set.FS(), set.Dir, set.VersionTable}}
			fp, err := postgresFingerprint(ms)
			require.NoError(t, err)
			_, err = srv.admin.ExecContext(t.Context(), "CREATE DATABASE "+pgx.Identifier{"tpl_" + fp}.Sanitize())
			require.NoError(t, err)
			tpl, err := srv.template(t.Context(), ms)
			require.NoError(t, err)
			name, err := srv.clone(t.Context(), tpl)
			require.NoError(t, err)
			db := openFor(t, srv, name)
			var n int
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT count(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename = 'sessions'`).Scan(&n))
			assert.Equal(t, 1, n)
		}},
		{name: "a built template refuses connections", run: func(t *testing.T) {
			srv := newTestPostgresServer(t)
			tpl, err := srv.template(t.Context(), []postgresMigrations{{set.FS(), set.Dir, set.VersionTable}})
			require.NoError(t, err)
			dsn, err := srv.dsnFor(tpl)
			require.NoError(t, err)
			db, err := sql.Open("pgx", dsn)
			require.NoError(t, err)
			defer db.Close()
			assert.ErrorContains(t, db.PingContext(t.Context()), "not currently accepting connections")
		}},
		{name: "parallel tests truncating one table do not disturb each other", run: func(t *testing.T) {
			for i := range 2 {
				t.Run(strconv.Itoa(i), func(t *testing.T) {
					t.Parallel()
					conn := RunTestPostgres(t, security)
					if i == 0 {
						_, err := conn.DB.ExecContext(t.Context(), `TRUNCATE sessions`)
						require.NoError(t, err)
						return
					}
					_, err := conn.DB.ExecContext(t.Context(), insertProbeSession)
					require.NoError(t, err)
					var n int
					require.NoError(t, conn.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM sessions`).Scan(&n))
					assert.Equal(t, 1, n)
				})
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}
```

Helpers in the test file:
- **`schemaOf(t, db)`** returns a sorted string of `pg_tables`, `information_schema.columns` (table, column, type, nullability, default), the index definitions from `pg_indexes`, and each version table's `version_id` rows, all for `current_schema()`.
- **`newTestPostgresServer(t)`** is a `postgresRegistry` with its own `start`, which terminates the container at the end of the test.
- **`openFor(t, srv, name)`** opens and closes a `*sql.DB` on a clone.
- **`insertProbeSession`** is the minimal valid `INSERT INTO sessions …` row. Copy its column list from `migrate/securitystate`'s sessions table when writing it.
- **`countingSet(t)`** returns a `fstest.MapFS` with one SQL migration at `m/00001_probe.sql` that creates and drops `m_probe`, and an `applies(srv)` reading `srv.applies.Load()`. `srv.applies` is an `atomic.Int64` field of `postgresServer`, which `applyTo` increments once per set it applies. It counts per server, so parallel tests on other servers cannot disturb the count.

- [ ] **Step 2: Run them and see them fail**

Run: `cd test && go test -race -count=1 -run 'TestPostgresTemplate' .`
Expected: FAIL, with `template` not implemented, `postgresFingerprint` undefined at first, so land them as stubs returning `"", errors.New("not implemented")` before running.

- [ ] **Step 3: Implement**

```go
func postgresFingerprint(migrations []postgresMigrations) (string, error) {
	h := sha256.New()
	for _, m := range migrations {
		fmt.Fprintf(h, "set\x00%s\x00%s\x00", m.dir, m.versionTable)
		err := fs.WalkDir(m.fsys, m.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(m.fsys, p)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "file\x00%s\x00%d\x00", p, len(b))
			h.Write(b)
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("fingerprint migrations %s: %w", m.dir, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func (s *postgresServer) template(ctx context.Context, migrations []postgresMigrations) (string, error) {
	if len(migrations) == 0 {
		return "", nil
	}
	fp, err := postgresFingerprint(migrations)
	if err != nil {
		return "", err
	}
	name := "tpl_" + fp

	s.tmplMu.Lock()
	if s.tmplBuilt[name] {
		s.tmplMu.Unlock()
		return name, nil
	}
	lock, ok := s.tmplLocks[name]
	if !ok {
		lock = &sync.Mutex{}
		s.tmplLocks[name] = lock
	}
	s.tmplMu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	s.tmplMu.Lock()
	built := s.tmplBuilt[name]
	s.tmplMu.Unlock()
	if built {
		return name, nil
	}

	if err := s.buildTemplate(ctx, name, fp, migrations); err != nil {
		return "", err
	}
	s.tmplMu.Lock()
	s.tmplBuilt[name] = true
	s.tmplMu.Unlock()
	return name, nil
}

func (s *postgresServer) buildTemplate(ctx context.Context, name, fp string, migrations []postgresMigrations) error {
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	key, _ := strconv.ParseUint(fp, 16, 64)
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, int64(key)); err != nil {
		return fmt.Errorf("lock template %s: %w", name, err)
	}
	// A background context: the unlock must run even when ctx is done.
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, int64(key)) //nolint:errcheck // released with the session anyway

	var isTemplate sql.NullBool
	switch err := conn.QueryRowContext(ctx, `SELECT datistemplate FROM pg_database WHERE datname = $1`, name).Scan(&isTemplate); {
	case err == nil && isTemplate.Bool:
		return nil // built by another process of this binary
	case err == nil:
		if _, err := conn.ExecContext(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			return fmt.Errorf("drop half-built template %s: %w", name, err)
		}
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	if _, err := conn.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		return fmt.Errorf("create template %s: %w", name, err)
	}
	if err := s.applyTo(ctx, name, migrations); err != nil {
		_, _ = conn.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		return err
	}
	_, err = conn.ExecContext(ctx, "ALTER DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false")
	return err
}
```

- **`applyTo`** opens a `*sql.DB` on `dsnFor(name)`, calls `postgresApply`, and closes the DB before returning, so no session holds the template.
- **`postgresApply`** is today's validation and `Up` loop, returning errors instead of `Fatalf`: `migrations %s: no file system`, `migrations %s: no version table`, `open migrations %s`, `load migrations %s`, `apply migrations %s: %w`. `applyTo` adds the number of sets it applied to `s.applies`.
- **`RunTestPostgres` after this task:**

```go
srv := … // 2.1
tpl, err := srv.template(t.Context(), cfg.migrations)
if err != nil {
	t.Fatalf("%v", err)
}
name, err := srv.clone(t.Context(), tpl)
require.NoError(t, err, "failed to create the test database")
t.Cleanup(func() { /* drop, as 2.2 */ })
db := … // open on dsnFor(name), 32 conns, close registered
sets, err := postgresProviders(db, cfg.migrations) // goose providers over the clone, no Up
require.NoError(t, err)
postgresRegisterTeardown(t, db, cfg, sets)
return PostgresConn{DB: db, DSN: dsn}
```

- **`postgresSetUp(tb, db, cfg)`** stays for `TestPostgresTeardown`: providers, then `postgresRegisterTeardown` over a slice that grows as each `Up` succeeds (today's partial-failure rollback), then the `Up` loop with `Fatalf`. Do **not** change `TestPostgresTeardown`'s cases or assertions. It must pass unchanged, which shows the extracted teardown is today's teardown.
- **Per-call teardown order** (cleanups run last-registered-first): the teardown runs, then `DB` closes, then the database is dropped.

- [ ] **Step 4: Run green, then the whole module**

Run: `cd test && go test -race -count=1 -run 'TestPostgresTemplate|TestPostgresTeardown|TestRunTestPostgres' .` then `go test -race -count=1 -timeout 30m ./...`
Expected: PASS, every package.

- [ ] **Step 5: Commit (main session, after review)** `test: share a PostgreSQL server per process and clone a database per call`

---

### Task 2.4: Godoc

**Files:** `test/testutils.go`, `test/testutils_pgserver.go`, `test/testutils_pgtemplate.go`

- [ ] **Step 1:** Rewrite `RunTestPostgres`'s godoc:
  - one server per test process and image, started on first use, removed by testcontainers' reaper when the process exits;
  - each call's own database, cloned from a template per ordered migration list or from `template1`;
  - the teardown checks on that database, then its drop;
  - `WithTestPostgresOwnServer` for a server of one's own;
  - the Ryuk-disabled limit (D1, risks).
- [ ] **Step 2:** Add godoc to `WithTestPostgresOwnServer`, naming the default it replaces ("a server shared by every call in the process"). Update `PostgresConn.DSN`'s comment, which now names the call's own database.
- [ ] **Step 3:** Run `go doc -all github.com/kartaladev/scrty/test RunTestPostgres` and `golangci-lint run ./...` in `test`. Expected: the text as above, and 0 issues.

---

### Task 3.1: Child processes reuse their parent's servers

**Files:**
- Modify: `test/testutils_pgserver.go` (publication and inheritance), `test/testutils.go` (`EnsureTestPostgresServer`)
- Modify: `test/sqlstore/broken_test.go:278`, `test/pgxstore/broken_test.go:280`, `test/gormstore/broken_test.go` (the `CatchBrokenVariants` call), `test/crossbackend/naming_test.go:91`. One line each, before spawning.
- Test: `test/testutils_postgres_test.go`

**Interfaces:**
- Produces:
  - `func EnsureTestPostgresServer(t *testing.T, opts ...TestOption)`: `requireHealthyProvider(t)`, then `defaultPostgresRegistry.server(resolvePostgresImage(cfg))`, with `t.Fatalf` on error.
  - `const postgresServersEnv = "SCRTY_TEST_POSTGRES_SERVERS"` (unexported): a JSON `map[string]string` from image to admin DSN.
  - In `(*postgresRegistry).server`, before `r.start`: if `postgresServersEnv` names the image, connect with `newPostgresServer(ctx, image, nil)` from that DSN and start nothing. After a successful start: read the map, add the image, and `os.Setenv`, under a package mutex.

- [ ] **Step 1: Write the failing test.** The test re-executes its own binary, as `storefix` does:

```go
const childProbeEnv = "SCRTY_TEST_CHILD_PROBE"

func TestPostgresChildReusesParentServer(t *testing.T) {
	if os.Getenv(childProbeEnv) != "" {
		before := postgresContainerStarts.Load()
		conn := RunTestPostgres(t)
		require.NoError(t, conn.DB.PingContext(t.Context()))
		fmt.Printf("child-starts=%d\n", postgresContainerStarts.Load()-before)
		return
	}
	t.Parallel()

	EnsureTestPostgresServer(t)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPostgresChildReusesParentServer$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), childProbeEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "child-starts=0", "the child started a server of its own:\n%s", out)
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cd test && go test -race -count=1 -run 'TestPostgresChildReusesParentServer' .`
Expected: FAIL with `child-starts=1`.

- [ ] **Step 3: Implement** publication and inheritance as in Interfaces, and `EnsureTestPostgresServer` with godoc. The godoc says to call it before spawning child processes that call `RunTestPostgres`, and that the default image resolution applies. Add the one-line calls in the four parents. Do **not** change `storefix`.

- [ ] **Step 4: Run green**

Run: `cd test && go test -race -count=1 -run 'TestPostgresChildReusesParentServer' . && go test -race -count=1 -timeout 30m ./sqlstore/ ./pgxstore/ ./gormstore/ ./crossbackend/ ./storetest/`
Expected: PASS. `storetest`'s in-memory broken variants still pass with no server involved.

- [ ] **Step 5: Commit (main session, after review)** `test: child test processes reuse their parent's PostgreSQL servers`

---

### Task 3.2: Tune the server

**Files:** `test/testutils_pgserver.go` (`startPostgresContainer` options), `test/testutils_postgres_test.go`, and design.md D6 (main session records the measurement).

- [ ] **Step 1: Measure the peak connection count (dispatch reports, main session records).** On the shared server, sample `SELECT count(*) FROM pg_stat_activity` every 250 ms during a full `go test -race -count=1 ./...` in `test`. Do this locally and in one CI run, through a temporary `SCRTY_TEST_POSTGRES_PEAK` log line that is removed before review. Report both peaks.
- [ ] **Step 2: Write the failing tests**

```go
func TestPostgresServerTuning(t *testing.T) {
	t.Parallel()

	conn := RunTestPostgres(t)
	for setting, want := range map[string]string{
		"fsync":              "off",
		"synchronous_commit": "off",
		"full_page_writes":   "off",
		"max_connections":    strconv.Itoa(postgresMaxConnections),
	} {
		var got string
		require.NoError(t, conn.DB.QueryRowContext(t.Context(), "SHOW "+setting).Scan(&got))
		assert.Equal(t, want, got, setting)
	}

	srv, err := defaultPostgresRegistry.server(resolvePostgresImage(&testConfig{image: postgresImage}))
	require.NoError(t, err)
	if srv.ctr != nil { // an inherited server has no handle in a child
		code, out, err := srv.ctr.Exec(t.Context(), []string{"sh", "-c", `stat -f -c %T "$PGDATA"`})
		require.NoError(t, err)
		require.Zero(t, code)
		b, _ := io.ReadAll(out)
		assert.Contains(t, string(b), "tmpfs")
	}
}

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
```

- [ ] **Step 3: Run them and see `TestPostgresServerTuning` fail**

Run: `cd test && go test -race -count=1 -run 'TestPostgresServerTuning|TestPostgresServerKeepsSerializableConflicts' .`
Expected:
- `TestPostgresServerTuning` FAILs on `synchronous_commit`, `full_page_writes`, `max_connections` and the tmpfs check. Check `fsync` in the output too: testcontainers' postgres module may already set `fsync=off` (unverified; read `go doc github.com/testcontainers/testcontainers-go/modules/postgres` and report).
- `TestPostgresServerKeepsSerializableConflicts` PASSes already. It is the guard that the tuning must keep passing, not a red step.

- [ ] **Step 4: Implement.**
  - Define `const postgresMaxConnections` as the larger measured peak from step 1 times 2, rounded up to the next 100, and never below 200.
  - Pass `testcontainers.WithCmdArgs("-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off", "-c", "max_connections="+strconv.Itoa(postgresMaxConnections))`, or the module's equivalent; check `go doc` for whether the module's default `Cmd` must be replaced rather than appended to.
  - Add `testcontainers.WithTmpfs(map[string]string{"/var/lib/postgresql": "rw"})`, which covers PGDATA on both the 15 and 18 images. Confirm by the tmpfs assertion under both images.
  - Own servers go through the same `startPostgresContainer`, so they are tuned too.

- [ ] **Step 5: Run green under both images**

Run: `cd test && go test -race -count=1 -timeout 30m ./... && SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine go test -race -count=1 -timeout 30m ./...`
Expected: PASS, including the race, ambient-transaction and lock-wait suites, unchanged.

- [ ] **Step 6: Commit (main session, after review, with D6 updated)** `test: tune the shared PostgreSQL server for tests`

---

### Task 4.1: The testcontainers skill (main session)

**Files:** `.claude/skills/use-testcontainers/SKILL.md`

- [ ] **Step 1:** Replace practice 6. The new text is "One server per test process, one database per call", and says:
  - `RunTestPostgres` shares a server per process and image, and clones a database per call from a template per migration list;
  - `WithTestPostgresOwnServer()` is for a test that must change server settings or stop the server;
  - a parent that spawns child test processes calls `EnsureTestPostgresServer` first;
  - why not a testify suite: no isolation between its tests, and no parallel table tests;
  - Keycloak and Mailpit stay per call while each has one caller.
- [ ] **Step 2:** Update the "Adding support for a new service" text. A new service's helper may start one container per call, and it adopts the registry pattern once a second caller makes sharing worthwhile.
- [ ] **Step 3:** Verify with `grep -n "One container per test" .claude/skills/use-testcontainers/SKILL.md`, which must find nothing, and by reading the result against D1, D2, D5 and D9.

---

### Task 4.2: Measure after, and the Keycloak budget (main session)

- [ ] **Step 1:** Repeat task 1.1's commands. Record the per-package seconds, the passed count (it must equal the baseline) and the container count under D8 "After".
- [ ] **Step 2:** Push and let CI run three times; re-run the workflow for the second and third runs.
  - For each job, read the Keycloak start from the `RunTestKeycloak` log: the container-created time to the "started in" line. Add `t.Logf` of the elapsed readiness time in `RunTestKeycloak` through a dispatch if the log does not show it.
  - If every reading is under 90 seconds, a Haiku dispatch sets `keycloakStartupTimeout = 3 * time.Minute` and rewrites its comment, the exact diff given. Otherwise keep five minutes.
  - Record the readings and the outcome in D7.
- [ ] **Step 3:** After a local run, `docker ps --filter label=org.testcontainers=true -q` must print nothing within 30 seconds of exit. That checks "Provisioned containers do not outlive the test run".

---

### Task 4.3: Final gate and whole-branch review (main session)

- [ ] **Step 1:** For every module in `go.work`, run `go build ./... && go vet ./... && gofmt -l . && golangci-lint run ./... && go test -race -count=1 ./...`. Expected: clean, with 0 issues and green.
- [ ] **Step 2:** Run `openspec validate testcontainers-optimize --strict`. Expected: valid.
- [ ] **Step 3:** One whole-branch review, by a fresh Opus reviewer, against every requirement and scenario in `specs/test-provisioning/spec.md` and decisions D1–D9. It maps each requirement to code and to the test that pins it, and labels each defect claim REPRODUCED or UNREPRODUCED.

---

## Dispatch plan (for the main session)

- **One lane: 2.1 → 2.2 → 2.3**, sequential, all in `test/testutils*.go`.
  - Dispatch on **Opus**: shared mutable state across goroutines and processes, an advisory lock, and conditional rebuilds, where "a mistake would pass the tests and still be wrong".
  - The reviewer is Opus.
- **2.4 on Sonnet**: godoc whose content this plan states. It can run alongside 3.1 only if 3.1 does not touch the same doc comments; otherwise it runs after 3.1.
- **3.1 on Sonnet**: the mechanism is fixed above and the test is given. The reviewer is Opus, because cross-process sharing is on Opus's list.
- **3.2 on Sonnet**, with an Opus reviewer: the settings are stated, but the measurement and the "no observable change" guard need judgement.
- Nothing in groups 2 and 3 runs in parallel. They share `test/testutils_pgserver.go`, and each builds on the previous one's API.

## Self-review

- **Spec coverage:**

| Requirement | Task |
|---|---|
| own database | 2.2, 2.3 (parallel truncate) |
| fresh-application schema | 2.3 |
| per-call teardown | 2.3 (`TestPostgresTeardown` unchanged, and the drop in 2.2) |
| share per image | 2.1 |
| child processes | 3.1 |
| failing set never half applied | 2.3 |
| concurrent first calls once | 2.3 |
| tuning invisible | 3.2 |
| containers do not outlive the run | 4.2 step 3 |
| runtime unavailable, failed start remembered | 2.1 (plus the existing `requireHealthyProvider` tests) |

- **Placeholders:** none. The connection peak in 3.2 is a measured value, with the formula given.
- **Type consistency:** `postgresServer`, `postgresRegistry.server`, `clone`, `drop`, `dsnFor`, `template`, `postgresFingerprint`, `postgresApply`, `postgresRegisterTeardown`, `postgresAppliedSet`, `EnsureTestPostgresServer`, `WithTestPostgresOwnServer`, `postgresContainerStarts`, `postgresServer.applies` and `postgresMaxConnections` are used as defined.
- **Review focus:** each of the five items is pinned in its owning task's tests.
