# Durable Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Durable PostgreSQL stores for every security-state contract on `database/sql`, `pgx` and `gorm`, an embedded goose-format migration set, AES-256-GCM sealing of the three long-lived secrets, and shared conformance suites that prove backend parity, atomic single use, transaction participation and sealing.

**Architecture:** Core gains `migrate` (embedded SQL), `seal` (cipher, keyring, envelope, sealing wrappers), `internal/pgschema` (SQL shared by `sqlstore` and `pgx`) and `sqlstore` (`database/sql` adapters). The nested modules `pgx` and `gorm` hold their backend's adapters. Everything that needs PostgreSQL, goose or testcontainers lives in the `test` module: `RunTestPostgres` in `test/testutils.go`, the `storetest` suites, and every adapter's integration run. Every refusal is one conditional write; sealed stores can only be built with a cipher.

**Tech Stack:** Go 1.27, PostgreSQL 15 and 18, `database/sql` + `github.com/jackc/pgx/v5/stdlib`, `github.com/jackc/pgx/v5` (`pgxpool`), `gorm.io/gorm` + `gorm.io/driver/postgres`, `github.com/pressly/goose/v3` (test module only), `testcontainers-go` + `modules/postgres`, testify, `crypto/aes` + `crypto/cipher`.

**Spec:** `openspec/changes/durable-persistence/` — `proposal.md`, `design.md` (decisions 1–12 are cited below as D1…D12), `specs/{security-state-stores,schema-migrations,store-conformance,secrets-at-rest}/spec.md`, and `tasks.md`, whose numbers (`1.1` … `9.4`) head every task below.

## Global Constraints

- Core module: no new dependency. It must never require pgx, gorm, goose, testcontainers or the `test` module, not even indirectly through a `_test.go` import (`layout_guard_test.go`, `TestConsumerModuleGraph`).
- No scrty module imports `github.com/kartaladev/scrty/test`, test files included. Every test that needs PostgreSQL lives in `./test`.
- Go 1.27 minimum in every new `go.mod`; each nested module requires `github.com/kartaladev/scrty v0.0.0` with `replace github.com/kartaladev/scrty => ../`.
- Tables are unqualified. Primary keys are `uuid`. User references are `text`, compared byte for byte, never trimmed, folded or parsed. No foreign keys, no joins with identity tables.
- Guard columns (`consumed_at`, `completed_at`, `confirmed_at`, `revoked_at`) are nullable with no default.
- Absent federation/handoff strings are `text NOT NULL DEFAULT ''`, and `''` arguments never match (`$n <> ''` guards).
- Times are stored UTC at microsecond precision (`timestamptz`), and compared with `time.Time.Equal`.
- Every refusal is zero rows affected from one conditional statement, never a read followed by a write, never a failed statement.
- Error text never contains stored values, secrets or user references. Backend errors are wrapped with the operation name (`"sqlstore: consume one-time token: %w"`) and never mapped to a refusal or to absence.
- Constructors return `(store, error)`, reject a nil handle, a nil option value, and (for sealed stores) a nil cipher, and never touch the database.
- Session identifiers are never stored: `id_digest = sha256(identifier)` is the lookup key.
- AAD strings are stored format: `scrty/signingkey:private:` + kid, `scrty/mfa:secret:` + user reference, `scrty/session:external-id-token:` + session identifier (already in `session/encrypted.go:44`).
- Migration files never contain goose's no-transaction annotation text, not even in a comment.
- Test-first on every task (`golang-tdd.md`): red step seen and read, for the intended reason; table tests in the `assert`-closure form with `t.Context()` (`table-test`); PostgreSQL only through `RunTestPostgres` (`use-testcontainers`); no mocks of the database.
- Never copy or cite the predecessor (`legacy-reference.md`). Defect claims need a failing test (`defect-claims.md`).
- Implementers never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.

## Review Focus

1. **A cancelled context mid-operation** must return a wrapped `context.Canceled`, never a refusal (`ErrTokenNotFound`, `ErrHandoffNotFound`, "not enrolled"). Pinned in 6.2 (consume) and 6.5 (MFA `Get`), with a `ctx` modifier case in each table.
2. **Session `Data` with non-ASCII keys and values, an empty map, and a nil map** must round-trip (nil and empty both load as an empty map, never an error). Pinned in 5.2 (portable suite), so every backend inherits it.
3. **A user reference containing a NUL byte or invalid UTF-8** cannot be stored in PostgreSQL `text`. The store must return an error that does not echo the value, never truncate it. Pinned in 6.3 (login attempts, `RecordFailure`) and inherited by 7.2 and 8.2 through the shared test table.
4. **Two keyring keys with the same bytes under different ids**, and **an envelope whose key-id length byte exceeds the remaining length**, must be a configuration error and `ErrDecryptionFailed` respectively, never a panic. Pinned in 3.1 and 3.2.
5. **A consume or complete called with a zero `id.ID` or an empty handle/token id** is refused like an unknown record, with no statement error. Pinned in 5.2 (one-time) and 6.7 (flows, handoffs).

---

## File Structure

```
go.work                                   + ./pgx ./gorm
layout_guard_test.go                      (unchanged lists already forbid pgx/gorm; 1.1 adds goose + postgres module)
migrate/
  migrate.go                              SecurityState() Set; Set{FS() fs.FS; Dir; VersionTable}
  securitystate/20260926000000_security_state.sql
seal/
  doc.go, errors.go                       ErrDecryptionFailed, ErrUnknownKeyID, ErrInvalidConfiguration
  keyring.go                              Keyring, NewKeyring, WithEncryptionKey, WithRetiredEncryptionKey
  aead.go, envelope.go                    NewAEADCipher, envelope encode/decode
  aad.go                                  AADSigningKeyPrefix, AADMFASecretPrefix
  session.go                              SessionCipher
  signingkey.go                           NewSigningKeyStore wrapper, SigningKeyResealer, WithResealOnRead
  mfa.go                                  NewEnrolmentStore wrapper, EnrolmentResealer
internal/pgschema/
  sessions.go onetime.go attempts.go signingkeys.go mfa.go apikeys.go oidc.go   SQL constants
sqlstore/
  doc.go tx.go options.go savepoint.go errors.go
  session.go onetime.go attempts.go signingkey.go mfa.go apikey.go oidc_link.go oidc_flow.go oidc_handoff.go
pgx/   go.mod doc.go tx.go options.go + the same nine store files
gorm/  go.mod doc.go tx.go options.go models.go + the same nine store files
test/
  testutils.go                            + RunTestPostgres, PostgresConn, WithTestPostgres* options
  testutils_postgres_test.go              helper tests
  migrate_securitystate_test.go           group 2
  example_migrate_test.go                 ExampleApplySecurityStateMigrations
  storetest/
    harness.go race.go ambient.go sealed.go
    session_suite.go onetime_suite.go attempts_suite.go signingkey_suite.go mfa_suite.go apikey_suite.go
    memory_test.go broken_test.go         in-memory runs and broken-variant guards
  sqlstore/  (package sqlstore_test)      runs for core adapters
  pgxstore/  (package pgxstore_test)      runs for pgx adapters
  gormstore/ (package gormstore_test)     runs for gorm adapters
  crossbackend/                           group 9
.github/workflows/ci.yml                  + SCRTY_TEST_POSTGRES_IMAGE matrix
```

## Dispatch Plan (for the main session)

Lanes and their sequential dispatches. Different lanes run in parallel only where noted.

| Dispatch | Tasks | Model | Why |
|---|---|---|---|
| A | 1.1–1.5 | Opus | module graph plus a helper whose cleanup must fail tests, several modules touched |
| B (parallel with A after 1.1 lands) | 3.1–3.3 | Opus | security-critical crypto and envelope parsing |
| C (after A) | 2.1–2.5 | Sonnet | schema from a stated table model, tests stated here |
| D (after B) | 3.4–3.5 | Opus | fail-closed and re-seal ordering |
| E (after A, C) | 4.1–4.2 | Opus | transaction and savepoint semantics other lanes compile against |
| F (after A; parallel with D, E) | 5.1–5.4 | Sonnet | portable suites against stated contracts |
| G (after F) | 5.5–5.6 | Opus | barrier race engine and ambient-transaction suite |
| H1 (after D, E, G) | 6.1–6.4 | Opus | sealed stores, digest keys, conditional writes |
| H2 | 6.5–6.8 | Opus | MFA races, OIDC atomicity, ambient transaction |
| I1, I2 (after H2; parallel with J) | 7.1–7.2, 7.3–7.4 | Opus | backend semantics differ (pgx.Tx nesting, error types) |
| J1, J2 (after H2; parallel with I) | 8.1–8.2, 8.3–8.4 | Opus | gorm savepoints and RowsAffected pitfalls |
| K | 9.1–9.3 | Sonnet | tests over finished adapters |
| — | 9.4 | main session + reviewer | final gate |

File ownership: A owns `go.work`, every `go.mod`, `layout_guard_test.go`, `test/testutils.go`, CI. C owns `migrate/`, `test/migrate_*`. B and D own `seal/`. E owns `sqlstore/{tx,options,savepoint,errors}.go` and `internal/pgschema/`. F and G own `test/storetest/`. H owns the `sqlstore` store files, `internal/pgschema` store SQL, and `test/sqlstore/`. I owns `pgx/` and `test/pgxstore/`. J owns `gorm/` and `test/gormstore/`. K owns `test/crossbackend/`.

---

### Task 1.1: Nested modules and the dependency guard

**Files:**
- Create: `pgx/go.mod`, `pgx/doc.go`, `gorm/go.mod`, `gorm/doc.go`
- Modify: `go.work`, `test/go.mod`, `layout_guard_test.go:integrationModules`
- Test: `layout_guard_test.go` (existing `TestLayout*`, `TestConsumerModuleGraph`)

**Interfaces:**
- Produces: module paths `github.com/kartaladev/scrty/pgx` (package `pgx`, imports `github.com/jackc/pgx/v5` as `pgxv5`) and `github.com/kartaladev/scrty/gorm` (package `gorm`, imports `gorm.io/gorm` as `gormdb`).

- [ ] **Step 1: Write the failing guard change.** Add `"github.com/pressly/goose"` and `"github.com/testcontainers/testcontainers-go/modules/postgres"` to `integrationModules` in `layout_guard_test.go`, and add a temporary blank import of `github.com/pressly/goose/v3` in a new core file `migrate/zz_guard_probe.go` together with the matching `go get` in the core module.
- [ ] **Step 2: Run it and see red.** `go test -run 'TestLayout|TestConsumerModuleGraph' -count=1 ./` — expected: FAIL naming `github.com/pressly/goose/v3` as a forbidden core requirement. Delete the probe file and run `go mod tidy` in the core module.
- [ ] **Step 3: Create the modules.**

```
// pgx/go.mod
module github.com/kartaladev/scrty/pgx

go 1.27

require (
	github.com/kartaladev/scrty v0.0.0
	github.com/jackc/pgx/v5 v5.7.x   // latest v5 at implementation time
)

replace github.com/kartaladev/scrty => ../
```

```go
// pgx/doc.go
// Package pgx provides scrty's security-state stores over native pgx v5
// (pgxpool.Pool and pgx.Tx). Each store joins a transaction attached with
// WithTx, or one supplied by WithTxResolver, and otherwise runs on the pool.
package pgx
```

`gorm/go.mod` is the same shape with `gorm.io/gorm` and `gorm.io/driver/postgres`; `gorm/doc.go` says the same for `*gorm.DB`. Add both to `go.work` `use`. In `test/go.mod` require `github.com/kartaladev/scrty/pgx v0.0.0`, `github.com/kartaladev/scrty/gorm v0.0.0` (with `replace … => ../pgx`, `../gorm`), `github.com/pressly/goose/v3`, `github.com/testcontainers/testcontainers-go/modules/postgres v0.44.0` (match the existing testcontainers version), and `github.com/jackc/pgx/v5`.
- [ ] **Step 4: See green.** `go test -run 'TestLayout|TestConsumerModuleGraph' -count=1 ./` PASS; `go build ./...` in `.`, `./pgx`, `./gorm`, `./test` all succeed; `go work sync` leaves no diff in the core `go.mod`.
- [ ] **Step 5: Hand back** with the red output of Step 2.

### Task 1.2: `RunTestPostgres`

**Files:**
- Modify: `test/testutils.go`
- Test: `test/testutils_postgres_test.go`

**Interfaces:**
- Produces:

```go
type PostgresConn struct {
	DB  *sql.DB // pgx stdlib driver, closed at cleanup
	DSN string  // for pgxpool.New and gorm.Open
}
func RunTestPostgres(t *testing.T, opts ...TestOption) PostgresConn
func WithTestPostgresImage(ref string) TestOption
const defaultPostgresImage = "postgres:18.N-alpine" // exact current 18 minor, pinned
```

`testConfig` gains `postgresImage string`, `migrations []postgresMigrations`, `finalizers []string`. The image defaults to `$SCRTY_TEST_POSTGRES_IMAGE` when set (1.5), otherwise `defaultPostgresImage`.

- [ ] **Step 1: Write the failing tests.**

```go
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
					_, err := c.DB.ExecContext(ctx, `CREATE TABLE probe (id uuid PRIMARY KEY)`)
					require.NoError(t, err)
				}
				key := id.MustParse("0192f000-0000-7000-8000-000000000001")
				_, err := a.DB.ExecContext(ctx, `INSERT INTO probe VALUES ($1)`, key)
				require.NoError(t, err)
				var n int
				require.NoError(t, b.DB.QueryRowContext(ctx, `SELECT count(*) FROM probe`).Scan(&n))
				assert.Zero(t, n)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, RunTestPostgres(t), RunTestPostgres(t))
		})
	}
}
```

- [ ] **Step 2: Run** `go test -run TestRunTestPostgres -count=1 .` in `./test` — expected: FAIL, `undefined: RunTestPostgres` is a compile error, so first add a stub `func RunTestPostgres(t *testing.T, opts ...TestOption) PostgresConn { t.Helper(); t.Fatal("not implemented"); return PostgresConn{} }` and re-run: FAIL with `not implemented`. That is the red step.
- [ ] **Step 3: Implement.**

```go
func RunTestPostgres(t *testing.T, opts ...TestOption) PostgresConn {
	t.Helper()
	cfg := defaultTestConfig()
	for _, o := range opts {
		o(cfg)
	}
	ctx := t.Context()
	ctr, err := postgres.Run(ctx, cfg.postgresImage,
		postgres.WithDatabase("scrty"), postgres.WithUsername("scrty"), postgres.WithPassword("scrty"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	require.NoError(t, err, "start postgres test container")
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ctr.Terminate(cctx); err != nil {
			t.Errorf("terminate postgres container: %v", err)
		}
	})
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(32) // wide enough for the race suites' 8 racers × parallel records
	t.Cleanup(func() { _ = db.Close() }) // registered after Terminate, so it runs first
	postgresSetUp(t, db, cfg) // migrations and teardown, 1.3 and 1.4
	return PostgresConn{DB: db, DSN: dsn}
}
```

Import `_ "github.com/jackc/pgx/v5/stdlib"`.
- [ ] **Step 4: See green**, then run the skill's checks: a temporary `t.Fatal("force")` leaves `docker ps` empty; a back-to-back re-run passes.
- [ ] **Step 5: Hand back.**

### Task 1.3: Migrations and verified rollback at cleanup

**Files:** Modify `test/testutils.go`; Test `test/testutils_postgres_test.go`, fixtures `test/testdata/migrations/{good,forgets_table}/*.sql`.

**Interfaces:**
- Produces: `func WithTestPostgresMigrations(fsys fs.FS, dir, versionTable string) TestOption`; unexported `postgresSetUp(tb cleanupTB, db *sql.DB, cfg *testConfig)` where

```go
// cleanupTB is the subset of testing.TB the teardown uses, so its failure
// reporting can be tested with a recorder.
type cleanupTB interface {
	Helper()
	Cleanup(func())
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Context() context.Context
}
```

- [ ] **Step 1: Write the failing test** (internal test file, package `test`):

```go
type recordingTB struct {
	ctx      context.Context
	cleanups []func()
	errs     []string
}
func (r *recordingTB) Helper()                    {}
func (r *recordingTB) Cleanup(f func())           { r.cleanups = append(r.cleanups, f) }
func (r *recordingTB) Errorf(f string, a ...any)  { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *recordingTB) Fatalf(f string, a ...any)  { r.Errorf(f, a...); panic(errFatal) }
func (r *recordingTB) Context() context.Context   { return r.ctx }
func (r *recordingTB) runCleanups() {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
}

func TestPostgresTeardown(t *testing.T) {
	t.Parallel()
	type testCase struct {
		name   string
		dir    string
		break_ func(t *testing.T, db *sql.DB) // run before teardown
		assert func(t *testing.T, errs []string)
	}
	cases := []testCase{
		{name: "clean rollback reports nothing", dir: "testdata/migrations/good",
			assert: func(t *testing.T, errs []string) { assert.Empty(t, errs) }},
		{name: "rollback error fails the test", dir: "testdata/migrations/good",
			break_: func(t *testing.T, db *sql.DB) {
				// the good set's Down drops probe_a without IF EXISTS; locking it out makes Down fail
				_, err := db.ExecContext(t.Context(), `ALTER TABLE probe_a RENAME TO probe_gone; CREATE VIEW probe_a AS SELECT 1`)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, errs []string) {
				require.NotEmpty(t, errs)
				assert.Contains(t, errs[0], "roll back migrations")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := RunTestPostgres(t)
			rec := &recordingTB{ctx: t.Context()}
			postgresSetUp(rec, conn.DB, &testConfig{migrations: []postgresMigrations{{os.DirFS("."), tc.dir, "goose_probe"}}})
			if tc.break_ != nil {
				tc.break_(t, conn.DB)
			}
			rec.runCleanups()
			tc.assert(t, rec.errs)
		})
	}
}
```

Fixture `good/00001_probe.sql`: `-- +goose Up` / `CREATE TABLE probe_a (id uuid PRIMARY KEY);` / `-- +goose Down` / `DROP TABLE probe_a;`.
- [ ] **Step 2: Run** `go test -run TestPostgresTeardown -count=1 .` — red: `rollback error fails the test` fails with `errs` empty, because the stub teardown does nothing.
- [ ] **Step 3: Implement** `postgresSetUp`: for each set, `sub, _ := fs.Sub(fsys, dir)`, `store, _ := database.NewStore(database.DialectPostgres, versionTable)`, `p, _ := goose.NewProvider("", db, sub, goose.WithStore(store))` (check the exact goose v3 API in its godoc; the dialect argument is empty when a store is supplied), `p.Up(ctx)`, fatal on error. Register one `tb.Cleanup` that, with a fresh `context.WithTimeout(context.Background(), 30*time.Second)`, runs `p.DownTo(ctx, 0)` for each set in reverse order and calls `tb.Errorf("roll back migrations %s: %v", dir, err)` on error, then runs the finalizers (1.4).
- [ ] **Step 4: See green.**
- [ ] **Step 5: Hand back.**

### Task 1.4: Finalizer scripts and the leftover-table check

**Files:** Modify `test/testutils.go`; Test `test/testutils_postgres_test.go`; fixture `test/testdata/migrations/forgets_table/00001_two.sql` (Up creates `probe_a`, `probe_b`; Down drops only `probe_a`).

**Interfaces:**
- Produces: `func WithTestPostgresFinalizeScripts(sql ...string) TestOption`; `const LeftoverTablesScript` — a `DO $$ … RAISE EXCEPTION 'tables left behind: %', string_agg(...)` over `pg_tables WHERE schemaname = current_schema() AND tablename NOT LIKE 'goose%'`.

- [ ] **Step 1: Add a case** to `TestPostgresTeardown`: `dir: "testdata/migrations/forgets_table"`, finalizers `[]string{LeftoverTablesScript}`, assert `errs` has one entry containing `probe_b` and not `probe_a`. Add a case with two finalizers that each `INSERT INTO finalize_log` (created by the first) and assert order through a third out-of-band read before teardown ends (the recorder collects `RAISE NOTICE`-free proof by having the second script fail with `'second'` only if the first's row is missing).
- [ ] **Step 2: Run**, red: no finalizer runs, so no error names `probe_b`.
- [ ] **Step 3: Implement**: after rollback, run each script in declared order on the same 30-second context; `tb.Errorf("finalize script %d: %v", i, err)` on error. Document on `WithTestPostgresFinalizeScripts` that scripts run after rollback in declared order.
- [ ] **Step 4: See green.** **Step 5: Hand back.**

### Task 1.5: PostgreSQL 15 and 18 in CI

**Files:** Modify `.github/workflows/ci.yml`, `test/testutils.go` (env override from 1.2).

- [ ] **Step 1: Red.** Add a case to `TestRunTestPostgres`: with `t.Setenv("SCRTY_TEST_POSTGRES_IMAGE", "postgres:15.N-alpine")` (not parallel), `SHOW server_version` starts with `15.`. Run: FAIL, the version is 18.
- [ ] **Step 2: Implement** the env override in `defaultTestConfig`. Add to the CI job matrix `postgres: ["postgres:15.N-alpine", "postgres:18.N-alpine"]` and `env: SCRTY_TEST_POSTGRES_IMAGE: ${{ matrix.postgres }}`, with exact pinned minors.
- [ ] **Step 3: Verify**: the case passes; `actionlint .github/workflows/ci.yml` (or `python3 -c 'import yaml,sys;yaml.safe_load(open(sys.argv[1]))' .github/workflows/ci.yml`); `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.N-alpine make test` and `make test` pass.
- [ ] **Step 4: Hand back.**

---

### Task 2.1: The embedded set and its tables

**Files:**
- Create: `migrate/migrate.go`, `migrate/securitystate/20260926000000_security_state.sql`
- Test: `test/migrate_securitystate_test.go`

**Interfaces:**
- Produces:

```go
package migrate

// Set is an embedded migration set in goose's annotated SQL format.
type Set struct {
	fsys         fs.FS
	Dir          string // directory inside FS() holding the files
	VersionTable string // default version table name for this set
}
func (s Set) FS() fs.FS
// SecurityState returns the security-state set. Its default version table is
// goose_security_state; a consumer may use any other name.
func SecurityState() Set
const SecurityStateVersionTable = "goose_security_state"
```

- [ ] **Step 1: Write the failing tests.**

```go
func migrated(t *testing.T) *sql.DB {
	t.Helper()
	set := migrate.SecurityState()
	return test.RunTestPostgres(t,
		test.WithTestPostgresMigrations(set.FS(), set.Dir, set.VersionTable),
		test.WithTestPostgresFinalizeScripts(test.LeftoverTablesScript),
	).DB
}

var securityStateTables = []string{"sessions", "signing_keys", "login_attempts", "mfa_enrolments",
	"api_keys", "one_time_tokens", "oidc_links", "oidc_flows", "oidc_handoffs"}

func TestSecurityStateMigrations_Schema(t *testing.T) {
	t.Parallel()
	db := migrated(t)
	type testCase struct {
		name   string
		query  string
		assert func(t *testing.T, rows []string)
	}
	cases := []testCase{
		{name: "fresh database has the nine tables and the version table",
			query: `SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY 1`,
			assert: func(t *testing.T, rows []string) {
				assert.ElementsMatch(t, append(slices.Clone(securityStateTables), "goose_security_state"), rows)
			}},
		{name: "no identity tables",
			query: `SELECT tablename FROM pg_tables WHERE tablename IN ('users','roles','organizations','groups','privileges')`,
			assert: func(t *testing.T, rows []string) { assert.Empty(t, rows) }},
		{name: "every primary key is uuid",
			query: `SELECT c.table_name || '.' || c.column_name || ':' || c.data_type
			          FROM information_schema.table_constraints tc
			          JOIN information_schema.key_column_usage k USING (constraint_name, table_name)
			          JOIN information_schema.columns c ON c.table_name = k.table_name AND c.column_name = k.column_name
			         WHERE tc.constraint_type = 'PRIMARY KEY' AND c.table_name <> 'goose_security_state'`,
			assert: func(t *testing.T, rows []string) {
				require.Len(t, rows, 9)
				for _, r := range rows {
					assert.True(t, strings.HasSuffix(r, ":uuid"), r)
				}
			}},
		{name: "every user reference is text",
			query: `SELECT table_name || ':' || data_type FROM information_schema.columns
			         WHERE column_name = 'user_id' AND table_schema = current_schema()`,
			assert: func(t *testing.T, rows []string) {
				require.Len(t, rows, 5) // sessions, mfa_enrolments, api_keys, oidc_links, oidc_handoffs
				for _, r := range rows {
					assert.True(t, strings.HasSuffix(r, ":text"), r)
				}
			}},
		{name: "no foreign keys",
			query: `SELECT constraint_name FROM information_schema.table_constraints WHERE constraint_type = 'FOREIGN KEY'`,
			assert: func(t *testing.T, rows []string) { assert.Empty(t, rows) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, queryStrings(t, db, tc.query))
		})
	}
}
```

`queryStrings` scans one text column into `[]string`.
- [ ] **Step 2: Run** `go test -run TestSecurityStateMigrations_Schema -count=1 .` in `./test` with an empty `migrate` set containing only an Up/Down pair creating nothing: red on the table list.
- [ ] **Step 3: Write the migration** (every choice-recording comment kept):

```sql
-- +goose Up
-- Security state only: no identity tables, and no foreign keys to them.
-- User references are opaque consumer-owned text compared byte for byte.

-- +goose StatementBegin
CREATE TABLE sessions (
    id                  uuid PRIMARY KEY,
    -- SHA-256 of the session identifier. The identifier is a bearer credential
    -- and is never stored.
    id_digest           bytea NOT NULL UNIQUE,
    user_id             text NOT NULL,
    created_at          timestamptz NOT NULL,
    last_accessed_at    timestamptz NOT NULL,
    idle_expires_at     timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    first_factor        text NOT NULL DEFAULT '',
    mfa_state           smallint NOT NULL DEFAULT 0,
    mfa_satisfied_at    timestamptz NULL,
    password_change_pending boolean NOT NULL DEFAULT false,
    -- Absent federation values are '' rather than NULL so every adapter scans
    -- plain strings; deletions guard with <> '' so '' never matches.
    external_provider   text NOT NULL DEFAULT '',
    external_issuer     text NOT NULL DEFAULT '',
    external_session_id text NOT NULL DEFAULT '',
    -- base64url envelope, '' = none.
    external_id_token   text NOT NULL DEFAULT '',
    data                jsonb NOT NULL DEFAULT '{}'
);
-- +goose StatementEnd
-- Issuer leads: a provider session id is unique only within its issuer.
CREATE INDEX sessions_external_session ON sessions (external_issuer, external_session_id) WHERE external_session_id <> '';
CREATE INDEX sessions_user_issuer ON sessions (user_id, external_issuer) WHERE external_issuer <> '';
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (idle_expires_at, absolute_expires_at);

CREATE TABLE signing_keys (
    id          uuid PRIMARY KEY,
    kid         text NOT NULL UNIQUE,
    alg         text NOT NULL,
    private_key bytea NOT NULL, -- envelope over PKCS8 DER
    public_jwk  bytea NOT NULL, -- published, not sealed
    created_at  timestamptz NOT NULL
);

CREATE TABLE login_attempts (
    id           uuid PRIMARY KEY,
    username     text NOT NULL,
    attempted_at timestamptz NOT NULL
);
CREATE INDEX login_attempts_username ON login_attempts (username, attempted_at);
-- Deletion scans by time alone and cannot range-scan the composite index:
-- do not consolidate these two indexes.
CREATE INDEX login_attempts_time ON login_attempts (attempted_at);

CREATE TABLE mfa_enrolments (
    id           uuid PRIMARY KEY,
    user_id      text NOT NULL UNIQUE,
    secret       text NOT NULL, -- base64url envelope
    -- Nullable guard: NULL = pending. A NOT NULL default would make
    -- "IS NULL" unsatisfiable and break confirm-once.
    confirmed_at timestamptz NULL,
    last_step    bigint NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL
);

CREATE TABLE api_keys (
    id            uuid PRIMARY KEY,
    user_id       text NOT NULL,
    name          text NOT NULL,
    scopes        jsonb NOT NULL DEFAULT '[]',
    secret_digest bytea NOT NULL,
    expires_at    timestamptz NULL,
    revoked_at    timestamptz NULL, -- nullable guard, first revocation kept
    last_used_at  timestamptz NULL,
    created_at    timestamptz NOT NULL
);
CREATE INDEX api_keys_user ON api_keys (user_id);

CREATE TABLE one_time_tokens (
    id           uuid PRIMARY KEY,
    purpose      text NOT NULL,
    subject      text NOT NULL,
    secret_hash  bytea NOT NULL,
    binding_hash bytea NOT NULL,
    issued_at    timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    -- Nullable guard with no default: single use is "consumed_at IS NULL".
    consumed_at  timestamptz NULL
);
CREATE INDEX one_time_tokens_subject ON one_time_tokens (purpose, subject);
CREATE INDEX one_time_tokens_expiry ON one_time_tokens (purpose, expires_at);

CREATE TABLE oidc_links (
    id         uuid PRIMARY KEY,
    provider   text NOT NULL,
    issuer     text NOT NULL,
    subject    text NOT NULL,
    user_id    text NOT NULL,
    username   text NOT NULL DEFAULT '', -- operators only, never a lookup key
    email      text NOT NULL DEFAULT '', -- operators only, never a lookup key
    created_at timestamptz NOT NULL,
    UNIQUE (provider, issuer, subject)
);
CREATE INDEX oidc_links_user ON oidc_links (user_id);

CREATE TABLE oidc_flows (
    id           uuid PRIMARY KEY,
    handle       text NOT NULL UNIQUE,
    provider     text NOT NULL,
    state        text NOT NULL,
    nonce        text NOT NULL,
    verifier     text NOT NULL,
    next         text NOT NULL DEFAULT '', -- untrusted, stored verbatim
    expires_at   timestamptz NOT NULL,
    completed_at timestamptz NULL -- nullable guard with no default
);
CREATE INDEX oidc_flows_expiry ON oidc_flows (expires_at);

CREATE TABLE oidc_handoffs (
    id          uuid PRIMARY KEY,
    token_id    text NOT NULL UNIQUE,
    secret_hash bytea NOT NULL,
    user_id     text NOT NULL,
    provider    text NOT NULL DEFAULT '',
    issuer      text NOT NULL DEFAULT '',
    session_id  text NOT NULL DEFAULT '',
    id_token    text NOT NULL DEFAULT '',
    next        text NOT NULL DEFAULT '', -- untrusted, re-resolved at redemption
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL,
    consumed_at timestamptz NULL -- nullable guard with no default
);
CREATE INDEX oidc_handoffs_expiry ON oidc_handoffs (expires_at);

-- +goose Down
-- Reverse creation order; IF EXISTS so teardown completes after a test drops a table.
DROP TABLE IF EXISTS oidc_handoffs;
DROP TABLE IF EXISTS oidc_flows;
DROP TABLE IF EXISTS oidc_links;
DROP TABLE IF EXISTS one_time_tokens;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_enrolments;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS sessions;
```

Check the `session.Session` fields (`session/session.go:54`) and the `signingkey.Record`, `apikey.Key`, `onetime.Token`, `oidc.*` records before finalising the columns. Every field has a column. If one does not map, stop and report rather than inventing a column. `migrate.go`: `//go:embed securitystate/*.sql` into `var securityState embed.FS`; `SecurityState()` returns `Set{fsys: securityState, Dir: "securitystate", VersionTable: SecurityStateVersionTable}`.
- [ ] **Step 4: See green.** **Step 5: Hand back.**

### Task 2.2: Pinned schema choices

**Files:** Test `test/migrate_securitystate_test.go`; `migrate/migrate_test.go` (core, file scan only, no database).

- [ ] **Step 1: Write the failing tests.** Add rows to `TestSecurityStateMigrations_Schema`:
  - nullable guards: `SELECT table_name||'.'||column_name||':'||is_nullable||':'||coalesce(column_default,'') FROM information_schema.columns WHERE column_name IN ('consumed_at','completed_at','confirmed_at','revoked_at')` → exactly `one_time_tokens.consumed_at:YES:`, `oidc_handoffs.consumed_at:YES:`, `oidc_flows.completed_at:YES:`, `mfa_enrolments.confirmed_at:YES:`, `api_keys.revoked_at:YES:`;
  - indexes: `SELECT indexname||':'||indexdef FROM pg_indexes WHERE schemaname=current_schema()` contains `login_attempts (username, attempted_at)`, `login_attempts (attempted_at)`, `sessions (external_issuer, external_session_id) WHERE (external_session_id <> ''::text)`, `sessions (user_id, external_issuer) WHERE (external_issuer <> ''::text)`, and unique indexes on `sessions (id_digest)`, `signing_keys (kid)`, `mfa_enrolments (user_id)`, `oidc_handoffs (token_id)`, `oidc_flows (handle)`, `oidc_links (provider, issuer, subject)`.

  In core, `TestSecurityStateFilesAvoidNoTransactionAnnotation` walks `SecurityState().FS()` and fails when any file contains the string built as `"+goose " + "NO TRANSACTION"` (built by concatenation so this test file itself never contains the literal).
- [ ] **Step 2: See each test go red.** Temporarily edit the migration: give `consumed_at` `DEFAULT now()`, drop `login_attempts_time`, add `-- +goose NO TRANSACTION` in a comment. Run, see three failures naming those, then restore the file by editing it back (never `git checkout`).
- [ ] **Step 3: See green.** **Step 4: Hand back** with the three red outputs.

### Task 2.3: Version-table behaviour

**Files:** Test `test/migrate_securitystate_test.go`; fixture `test/testdata/migrations/identity_probe/00001_probe.sql`.

- [ ] **Step 1: Write** `TestSecurityStateMigrations_VersionTable` as a table over `{name, apply func(t, db), assert func(t, db)}`:
  - default: apply with `goose_security_state`; `SELECT count(*) FROM goose_security_state WHERE is_applied AND version_id > 0` = 1;
  - consumer table: apply with `auth_schema_versions`; that table has 1 applied version; `to_regclass('goose_security_state') IS NULL`;
  - independent: apply security state and `identity_probe` (version table `goose_identity_probe`), `DownTo(0)` the probe; all nine tables exist and `goose_security_state` still has 1 applied version.

  Each case uses a bare `RunTestPostgres(t)` and a local `provider(t, db, fsys, dir, table) *goose.Provider` helper in the test file, and registers `t.Cleanup` for the security-state `DownTo(0)`.
- [ ] **Step 2: Red:** first run with the helper pointing all cases at one fixed table name, and see `consumer table` fail. Then correct it.
- [ ] **Step 3: See green.** **Step 4: Hand back.**

### Task 2.4: Application and rollback

**Files:** Test `test/migrate_securitystate_test.go`; fixture `test/testdata/migrations/fails_partway/{00001_ok.sql,00002_fails.sql}` (00002 creates `half_a`, then `SELECT 1/0`).

- [ ] **Step 1: Write** `TestSecurityStateMigrations_Lifecycle`, table cases:
  - re-apply is a no-op: `Up` twice; the second returns no results; row counts of `goose_security_state` unchanged; `pg_class` relfilenode of `sessions` unchanged;
  - failing migration leaves nothing: `Up` on `fails_partway` returns an error; `to_regclass('half_a') IS NULL`; version 2 not recorded;
  - full rollback: `DownTo(0)`; no security-state table; `goose_security_state` records no applied version above 0;
  - table already dropped: `DROP TABLE oidc_links`, then `DownTo(0)` succeeds;
  - re-apply after rollback: `DownTo(0)`, `Up`, all nine tables exist;
  - each Down on its own: for every migration file, parse its `-- +goose Down` section with goose's parser (`sqlparser.ParseSQLMigration(r, sqlparser.DirectionDown, false)`), execute it against a freshly migrated database, and assert that the tables its Up created are gone and every other table remains. With one file, that is all nine gone and `goose_security_state` intact.
- [ ] **Step 2: Red:** first run the failing-migration case against a fixture that marks 00002 as running outside a transaction (fixture only, not the security-state set) and see `half_a` survive. That proves the assertion notices. Then restore the fixture.
- [ ] **Step 3: See green.** **Step 4: Hand back.**

### Task 2.5: The goose recipe as a compiled example

**Files:** Create `test/example_migrate_test.go`; Test `test/migrate_securitystate_test.go`.

- [ ] **Step 1: Write** `TestGooseDirect` (apply with `goose.NewProvider` and version table `app_security_versions`; every table, column and index from 2.1 and 2.2 exists, checked by reusing the 2.2 queries; then `DownTo(0)`, no security-state table remains) and:

```go
func ExampleApplySecurityStateMigrations() {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	set := migrate.SecurityState()
	fsys, err := fs.Sub(set.FS(), set.Dir)
	if err != nil {
		log.Fatal(err)
	}
	store, err := database.NewStore(database.DialectPostgres, set.VersionTable)
	if err != nil {
		log.Fatal(err)
	}
	provider, err := goose.NewProvider("", db, fsys, goose.WithStore(store))
	if err != nil {
		log.Fatal(err)
	}
	if _, err := provider.Up(context.Background()); err != nil {
		log.Fatal(err)
	}
}
```

(No `// Output:` line, so it compiles but never runs.)
- [ ] **Step 2: Red:** `TestGooseDirect` before the shared-query refactor fails on the missing helper; make it fail for a real reason by asserting an index name that is misspelt, see it, then fix it.
- [ ] **Step 3: Verify** `go test -run 'Example|TestGooseDirect' -count=1 .` and `go vet .` in `./test`. **Step 4: Hand back.**

---

### Task 3.1: Keyring

**Files:** Create `seal/doc.go`, `seal/errors.go`, `seal/keyring.go`; Test `seal/keyring_test.go`.

**Interfaces:**
- Produces:

```go
var (
	ErrInvalidConfiguration = errors.New("seal: invalid configuration")
	ErrDecryptionFailed     = errors.New("seal: decryption failed")
	ErrUnknownKeyID         = errors.New("seal: unknown key id")
)
type Keyring interface {
	Active() (id string, key []byte, err error)
	ByID(id string) ([]byte, error) // ErrUnknownKeyID
}
type KeyringOption func(*keyringConfig)
func NewKeyring(opts ...KeyringOption) (Keyring, error)
// WithEncryptionKey names the one active key, which seals and opens.
func WithEncryptionKey(id string, key []byte) KeyringOption
// WithRetiredEncryptionKey adds a key that only opens.
func WithRetiredEncryptionKey(id string, key []byte) KeyringOption
```

- [ ] **Step 1: Write the failing table test** `TestNewKeyring` with rows: no active key; two active keys; 16-byte active key; 33-byte retired key; empty id; duplicate id across active and retired; id `"bad/id"`; a 65-character id; **two ids with identical key bytes** (Review Focus 4: rejected, since a retired key equal to the active key hides a rotation that never happened); valid `k2` active plus `k1` retired, where `Active()` returns `k2` and `ByID("k1")` returns the key. Error rows assert `require.ErrorIs(t, err, seal.ErrInvalidConfiguration)` and that `err.Error()` contains no key bytes (hex or raw).
- [ ] **Step 2: Run** `go test -run TestNewKeyring -count=1 ./seal/`, red with a stub `NewKeyring` returning `nil, nil`.
- [ ] **Step 3: Implement**, validating the id with `^[A-Za-z0-9._-]{1,64}$`, copying key bytes defensively, and comparing keys with `subtle.ConstantTimeCompare`.
- [ ] **Step 4: See green.** **Step 5: Hand back.**

### Task 3.2: Envelope and AES-256-GCM cipher

**Files:** Create `seal/envelope.go`, `seal/aead.go`; Test `seal/aead_test.go`.

**Interfaces:**
- Produces:

```go
type Cipher interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) (plaintext []byte, keyID string, err error)
	ActiveKeyID() (string, error)
}
func NewAEADCipher(kr Keyring) Cipher
// envelope: magic "SCS1" | keyIDLen(1) | keyID | nonce(12) | ciphertext‖tag
```

- [ ] **Step 1: Write the failing table test** `TestAEADCipher`, every row an `assert func(t *testing.T, plaintext []byte, keyID string, err error)` over one `Open` call, with setup mutating a sealed value: round trip (returns plaintext, key id `k2`); wrong AAD → `ErrDecryptionFailed`; opened with another keyring holding a different key under id `k2` → `ErrDecryptionFailed`; tampered last byte → `ErrDecryptionFailed`; truncated to 10 bytes → `ErrDecryptionFailed`; missing magic → `ErrDecryptionFailed`; **key-id length byte 200 on a 30-byte value** → `ErrDecryptionFailed`, no panic (Review Focus 4); sealed under retired `k1` → plaintext, key id `k1`; key id `gone` → `ErrUnknownKeyID` and `!errors.Is(err, ErrDecryptionFailed)`. Separately, `TestAEADCipher_Randomised`: sealing the same plaintext twice gives different bytes.
- [ ] **Step 2: Run**, red on a stub.
- [ ] **Step 3: Implement** with `aes.NewCipher`, `cipher.NewGCM`, a 12-byte `crypto/rand` nonce, and the header parsed with explicit bounds checks before slicing.
- [ ] **Step 4: See green**, and run `go test -race ./seal/`. **Step 5: Hand back.**

### Task 3.3: AAD constants and `SessionCipher`

**Files:** Create `seal/aad.go`, `seal/session.go`; Test `seal/aad_test.go`, `seal/session_test.go`.

**Interfaces:**
- Produces:

```go
const (
	AADSigningKeyPrefix = "scrty/signingkey:private:"
	AADMFASecretPrefix  = "scrty/mfa:secret:"
)
func SigningKeyAAD(kid string) []byte
func MFASecretAAD(user identity.UserID) []byte
// SessionCipher adapts a Cipher to session.Cipher for session.NewEncryptedStore.
func SessionCipher(c Cipher) session.Cipher
```

- [ ] **Step 1: Write** `TestAADGolden` (table: `SigningKeyAAD("k-1")` = `[]byte("scrty/signingkey:private:k-1")`, `MFASecretAAD("Alice ")` = `[]byte("scrty/mfa:secret:Alice ")`) and `TestSessionCipher` (table over a `session.NewEncryptedStore(session.NewMemoryStore(), seal.SessionCipher(c))`: round trip keeps `ExternalIDToken`; the inner store's copy is not the plaintext; token moved to another session's record in the inner store → `session.ErrSessionUnreadable`; a nil `Cipher` passed to `SessionCipher` makes `NewEncryptedStore` return `session.ErrConfig`).
- [ ] **Step 2: Red:** a stub `SessionCipher` returning a pass-through makes "inner copy is not the plaintext" fail; change a golden constant and see `TestAADGolden` fail; restore.
- [ ] **Step 3: Implement.** `SessionCipher(nil)` returns a nil `session.Cipher` interface value, not a typed nil, so the constructor's nil check fires.
- [ ] **Step 4: See green.** **Step 5: Hand back.**

### Task 3.4: Signing-key sealing wrapper

**Files:** Create `seal/signingkey.go`, `seal/options.go`; Test `seal/signingkey_test.go`.

**Interfaces:**
- Consumes: `signingkey.KeyStore{Store(ctx, Record) error; LoadAll(ctx) ([]Record, error)}`.
- Produces:

```go
// SigningKeyResealer is implemented by durable stores: it replaces the stored
// private material for kid only if it still equals old, and writes nothing
// when a caller's transaction is ambient.
type SigningKeyResealer interface {
	ResealSigningKey(ctx context.Context, kid string, old, new []byte) error
}
type Option func(*options)
// WithResealOnRead turns re-sealing retired-key values on read on or off (default on).
func WithResealOnRead(on bool) Option
func NewSigningKeyStore(inner signingkey.KeyStore, r SigningKeyResealer, c Cipher, opts ...Option) (signingkey.KeyStore, error)
```

- [ ] **Step 1: Write** `TestSigningKeyStore`, table over `{name, setup, assert func(t, recs []signingkey.Record, err error, resealer *recordingResealer)}`, where the inner store is `signingkey.NewInMemoryKeyStore()` and `recordingResealer` records calls and can fail:
  - round trip: `Private` from `LoadAll` equals the original, and the inner record's `Private` does not contain it;
  - one of three keys unreadable (its inner `Private` tampered) → error, `recs == nil`;
  - sealed under retired `k1`, active `k2` → one reseal call with `old` = the inner bytes and `new` opening under `k2` with the kid's AAD;
  - reseal fails → `LoadAll` still succeeds;
  - `WithResealOnRead(false)` → no reseal call;
  - constructor: nil inner, nil cipher, nil resealer each → `ErrInvalidConfiguration`.
- [ ] **Step 2: Red** on a stub pass-through wrapper.
- [ ] **Step 3: Implement.** Seal a copy of the record on `Store`. `LoadAll` opens every record, fails the whole load on the first error (`fmt.Errorf("seal: open signing key: %w", err)` with no kid in the text), re-seals when `keyID != active`, and ignores the re-seal error.
- [ ] **Step 4: See green.** **Step 5: Hand back.**

### Task 3.5: MFA enrolment sealing wrapper

**Files:** Create `seal/mfa.go`; Test `seal/mfa_test.go`.

**Interfaces:**
- Consumes: `mfa.EnrolmentStore` (Get, PutPending, Confirm, AcceptStep, Delete).
- Produces:

```go
type EnrolmentResealer interface {
	ResealEnrolmentSecret(ctx context.Context, user identity.UserID, old, new []byte) error
}
func NewEnrolmentStore(inner mfa.EnrolmentStore, r EnrolmentResealer, c Cipher, opts ...Option) (mfa.EnrolmentStore, error)
```

The `Secret` passed to the inner store is the raw envelope. The durable store base64url-encodes it for its text column; the wrapper does not.
- [ ] **Step 1: Write** `TestEnrolmentStore` over `mfa.NewMemoryEnrolmentStore()`:
  - round trip;
  - unreadable secret → `Get` returns `(_, false, err)` with `err != nil`;
  - consumer cipher whose `Seal` fails → `PutPending` returns an error wrapping it, and the inner `Get` reports absent;
  - retired-key reseal called, with `WithResealOnRead(false)` not calling it;
  - `Confirm`, `AcceptStep` and `Delete` pass through (the inner memory store's result is returned unchanged);
  - constructor nil checks.
- [ ] **Step 2: Red** on a stub. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

---

### Task 4.1: `sqlstore` handle resolution and shared SQL package

**Files:** Create `sqlstore/doc.go`, `sqlstore/tx.go`, `sqlstore/options.go`, `sqlstore/errors.go`, `internal/pgschema/doc.go`; Test `sqlstore/tx_test.go` (core, no database: resolution is pure).

**Interfaces:**
- Produces:

```go
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
// WithTx attaches tx so every sqlstore store uses it for operations on ctx.
// Limit: an unexpected backend error on a single-statement write inside tx
// aborts tx, as PostgreSQL defines; refusals never do.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context
type TxResolver func(ctx context.Context) (DBTX, bool)
var ErrConfig = errors.New("sqlstore: invalid configuration")

type Option func(*config) // shared by every store
func WithTxResolver(r TxResolver) Option
func WithIDGenerator(g id.Generator) Option  // honoured by the five minting stores
func WithClock(now func() time.Time) Option  // honoured by session and flow stores

// internal: conn resolves resolver → context → base, and reports whether a
// caller's transaction is ambient.
func (c *config) conn(ctx context.Context) (q DBTX, tx *sql.Tx, ambient bool)
```

- [ ] **Step 1: Write** `TestConfigConn` (table: no resolver or context → base, `ambient=false`; context tx → that tx, `ambient=true`; resolver reports a tx → resolver wins over context; resolver reports false → base even with a context tx, since the resolver replaces the context lookup) using a fake `DBTX` identity type for the resolver case and `*sql.Tx` zero values compared by pointer for the context case. `TestNewConfig` table: `WithTxResolver(nil)`, `WithIDGenerator(nil)`, `WithClock(nil)` → `ErrConfig`.
- [ ] **Step 2: Red** on stubs. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 4.2: Savepoint containment and construction validation

**Files:** Create `sqlstore/savepoint.go`; Modify `sqlstore/options.go`; Test `test/sqlstore/savepoint_test.go`, `sqlstore/options_test.go`.

**Interfaces:**
- Produces:

```go
// inUnit runs fn in a savepoint when a caller's tx is ambient, otherwise in its own tx.
func (c *config) inUnit(ctx context.Context, fn func(q DBTX) error) error
// newConfig validates base and options; sealed stores also pass requireCipher.
func newConfig(base *sql.DB, opts []Option) (*config, error)
```

The savepoint name is `scrty_sp_<n>` from an `atomic.Uint64`. `inUnit` issues `SAVEPOINT`, then either `RELEASE SAVEPOINT` or `ROLLBACK TO SAVEPOINT` followed by `RELEASE`.
- [ ] **Step 1: Write** in core `TestNewConfig`: nil base → `ErrConfig`. **Containment is pending a decision:** under D3, every store operation is a single statement, and re-seal writes are skipped inside a caller's transaction. So no operation exists for `inUnit` to contain, and the scenario "Multi-statement failure is contained" has no code to exercise. The dispatch implements construction validation only, and does not add `inUnit`, until the main session records a decision in design.md and tasks.md (see the change's open item).
- [ ] **Step 2: Red** on `newConfig(nil, nil)` returning a config. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

---

### Task 5.1: Harnesses and required inputs

**Files:** Create `test/storetest/harness.go`; Test `test/storetest/harness_test.go`.

**Interfaces:**
- Produces:

```go
type Harness[S any] struct {
	New func(t *testing.T) S // an empty store, fresh state per call
}
type DurableHarness[S any] struct {
	Harness[S]
	Raw *sql.DB // same database, out of band
	// Begin starts a caller-owned tx and returns ctx carrying it (attached with the backend's WithTx).
	Begin func(t *testing.T) (ctx context.Context, commit, rollback func() error)
	// BeginResolved starts a tx and returns a store configured with a resolver
	// reporting it; ctx does not carry an attachment.
	BeginResolved func(t *testing.T) (s S, ctx context.Context, commit, rollback func() error)
	// BeginForeign attaches a tx of a different backend to ctx.
	BeginForeign func(t *testing.T) (ctx context.Context, rollback func() error)
	PoolSize int
}
// Require fails t immediately, naming every nil field or zero PoolSize.
func (h DurableHarness[S]) Require(t testing.TB)
func requirePool(t testing.TB, pool, racers int) // "pool of %d connections cannot exercise a race of %d racers"
```

- [ ] **Step 1: Write** `TestDurableHarnessRequire` (table: each field nil in turn → a recorder `testing.TB` gets `Fatalf` naming it, e.g. `"storetest: DurableHarness.Raw is required"`; a full harness → no failure) and `TestRequirePool` (pool 2, racers 8 → fatal message contains "cannot exercise"). Use the recorder from 1.3, copied into this package's test file.
- [ ] **Step 2: Red** on stubs that do nothing. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 5.2: Session and one-time token suites

**Files:** Create `test/storetest/session_suite.go`, `test/storetest/onetime_suite.go`, `test/storetest/memory_test.go`, `test/storetest/broken_test.go`.

**Interfaces:**
- Produces:

```go
func RunSessionStoreSuite(t *testing.T, newStore func(t *testing.T, now func() time.Time) session.Store)
func RunOneTimeStoreSuite(t *testing.T, newStore func(t *testing.T) onetime.Store) // reaper cases run when the store implements onetime.Reaper
```

The clock handed in is a `*fakeClock` the suite advances; the factory must build the store on it.
- [ ] **Step 1: Write the suites.** Each is one table per method group with exact assertions. Session cases:
  - `Create` then `Load` round-trips every field: `Data` with `{"tenant":"t-9","flags":"a,b","":"empty key","ключ":"值"}`, plus a nil map and an empty map, both loading as an empty map (Review Focus 2);
  - duplicate `Create` errors and leaves the original unchanged;
  - `Save` after `Delete` → `ErrSessionNotFound`, and `Load` → `ErrSessionNotFound`;
  - `Load` at the idle deadline → `ErrSessionExpired`, via the clock;
  - `CountActiveByUser` is exact;
  - `DeleteExpired` with 2 expired and 1 live → 2, and the live one loads;
  - `DeleteByExternalSession("", "sid-1")` → 0; `(issuerA, "")` → 0; issuers A and B share a sid, delete A → 1 and B remains;
  - `DeleteByUserAndExternalIssuer(u1, A)` with 2 A and 1 B → 2;
  - user reference `"Alice@Example.COM "` round-trips byte for byte.

  One-time cases:
  - `Insert` duplicate ID errors;
  - `FindByID` unknown → `ErrTokenNotFound`;
  - `Consume` at T1 then T2 → the second is `ErrTokenNotFound` and `ConsumedAt` equals T1;
  - `Consume` of `id.Nil` → `ErrTokenNotFound` (Review Focus 5);
  - `CountRecentBySubject` is exact at the `since` boundary (issued at `since` counts);
  - reaper: a zero `retainSince` → `ErrRetainSinceRequired`; with 2 expired and issued before, 1 expired and issued after, and 1 live → 2;
  - microsecond truncation: `IssuedAt` `…10:00:00.123456789Z` reads back `Equal` to `…10:00:00.123456Z` for durable stores, and to the input for memory stores. Assert `got.Equal(want) || got.Equal(want.Truncate(time.Microsecond))`.
- [ ] **Step 2: Red on broken variants.** In `broken_test.go`, `brokenSaveInserts` wraps the memory session store so `Save` re-creates a deleted session, and `brokenConsumeMovesTime` makes `Consume` overwrite `ConsumedAt`. Run each suite against its broken variant through a recorder `testing.T` substitute: since suites take `*testing.T`, run the broken suite in a subtest and assert failure with this pattern:

```go
func TestSuitesCatchBrokenStores(t *testing.T) {
	// Each suite must fail against its broken store. The inner run uses a
	// separate test binary invocation so its failure does not fail this test.
	if os.Getenv("STORETEST_BROKEN") != "" {
		switch os.Getenv("STORETEST_BROKEN") {
		case "session-save-inserts":
			storetest.RunSessionStoreSuite(t, newBrokenSaveInserts)
		case "onetime-consume-moves-time":
			storetest.RunOneTimeStoreSuite(t, newBrokenConsumeMovesTime)
		}
		return
	}
	for _, name := range []string{"session-save-inserts", "onetime-consume-moves-time"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSuitesCatchBrokenStores$", "-test.count=1")
			cmd.Env = append(os.Environ(), "STORETEST_BROKEN="+name)
			out, err := cmd.CombinedOutput()
			require.Error(t, err, "suite passed against a broken store:\n%s", out)
			assert.Contains(t, string(out), "--- FAIL")
		})
	}
}
```

  This re-exec guard is the pattern for every "suite must go red" check in this plan. Its failing inner output is the red evidence to report.
- [ ] **Step 3: Run against memory** in `memory_test.go`: `RunSessionStoreSuite(t, func(t, now) session.Store { return session.NewMemoryStore(session.WithMemoryStoreClock(now)) })` and `RunOneTimeStoreSuite(t, … onetime.NewMemoryStore(onetime.WithMemoryStoreClock(…)))`. If a memory store fails a case, stop and report: either the suite misreads the contract or the memory store has a defect, which needs a failing test and a decision (`defect-claims.md`).
- [ ] **Step 4: See green**: `go test -run 'TestMemory|TestSuitesCatchBrokenStores' -count=1 ./storetest/`. **Step 5: Hand back.**

### Task 5.3: Login-attempt and signing-key suites

**Files:** Create `test/storetest/attempts_suite.go`, `test/storetest/signingkey_suite.go`; Modify `memory_test.go`, `broken_test.go`.

**Interfaces:**
- Produces: `func RunAttemptStoreSuite(t *testing.T, newStore func(t *testing.T) policy.AttemptStore)`, where reaper cases run only when the store implements `policy.AttemptReaper` and report `t.Log("store does not implement AttemptReaper")` otherwise; `func RunSigningKeyStoreSuite(t *testing.T, newStore func(t *testing.T) signingkey.KeyStore)`.
- [ ] **Step 1: Write the cases.** Attempts:
  - `FailureCount` counts strictly after `since`, so an attempt at `since` is excluded;
  - `Reset` clears one user only;
  - user names differing only in case are distinct;
  - reaper: zero cutoff → `ErrRetainSinceRequired`; attempts before, at and after the cutoff → 1 deleted (strictly before).

  Signing keys:
  - `Store` twice with the same `Kid` → one record carrying the second's fields;
  - `LoadAll` is ordered oldest first by `CreatedAt`;
  - an empty store → empty slice, no error.
- [ ] **Step 2: Red** on broken variants `brokenCountInclusive` and `brokenLoadAllUnordered`, through the re-exec guard. **Step 3: Run against memory**, green. **Step 4: Hand back.**

### Task 5.4: MFA enrolment and API key suites

**Files:** Create `test/storetest/mfa_suite.go`, `test/storetest/apikey_suite.go`; Modify `memory_test.go`, `broken_test.go`.

**Interfaces:**
- Produces: `func RunEnrolmentStoreSuite(t *testing.T, newStore func(t *testing.T) mfa.EnrolmentStore)`; `func RunAPIKeyStoreSuite(t *testing.T, newStore func(t *testing.T) apikey.Store)`.
- [ ] **Step 1: Write the cases.** MFA:
  - `Get` absent → `(_, false, nil)`;
  - `PutPending` twice while pending → the second secret is kept and `LastStep` is 0;
  - `PutPending` after `Confirm` → `ErrAlreadyEnrolled`, and the original secret and `ConfirmedAt` are kept;
  - `Confirm(u, 1000, T)` → true; `Get` shows `ConfirmedAt` = T and `LastStep` = 1000; a second `Confirm` → false with T unchanged; `Confirm` with no enrolment → false;
  - `AcceptStep` on a pending enrolment → false; on a confirmed one: 1001 → true, 1001 → false, 1000 → false (`LastStep` stays 1001), 1002 → true;
  - `Delete` of an absent user → nil.

  API keys:
  - `Put` then `Get` equal on every field (`Scopes` order kept, `LastUsedAt` nil);
  - `Get` unknown → `ErrKeyNotFound`;
  - `Revoke` at T1 then T2 → `RevokedAt` = T1; `Revoke` unknown → `ErrKeyNotFound`;
  - `TouchLastUsed` sets it; unknown → `ErrKeyNotFound`;
  - `List(p)` returns only p's keys; `List` of an unknown principal → empty, no error.
- [ ] **Step 2: Red** on broken variants `brokenPutPendingOverwritesConfirmed` and `brokenRevokeMovesTime`. **Step 3: Run against memory**, green. **Step 4: Hand back.**

### Task 5.5: Race suites

**Files:** Create `test/storetest/race.go`; Test `test/storetest/race_test.go`.

**Interfaces:**
- Produces:

```go
type Race[S any] struct {
	Records int // default 50
	Racers  int // default 8
	// Seed creates record i and returns the key racers contend on.
	Seed func(ctx context.Context, t *testing.T, s S, i int) string
	// Attempt performs one racing call; won reports success, and a refusal is (false, nil).
	Attempt func(ctx context.Context, s S, key string) (won bool, err error)
}
func RunConsumeRace[S any](t *testing.T, h DurableHarness[S], r Race[S])
func RunLinkInsertRace[S any](t *testing.T, h DurableHarness[S], r Race[S])
func RunStepAcceptRace[S any](t *testing.T, h DurableHarness[S], r Race[S])
```

All three share one engine, `runRace`. It seeds records × racers goroutines that block on one `close(start)` barrier, requires `err == nil` for every attempt, and asserts exactly one `won` per key, printing the keys with 0 or more than 1 wins. It calls `h.Require(t)` and `requirePool(t, h.PoolSize, r.Racers)` first.
- [ ] **Step 1: Write** `TestRunRaceInputs` (re-exec guard: a harness with `PoolSize: 2`, racers 8 → the inner output contains "cannot exercise"; a nil `Seed` → names `Race.Seed`). The durable red runs are in 6.2, 6.5 and 6.7.
- [ ] **Step 2: Red** on a stub engine that returns early. **Step 3: Implement.** **Step 4: See green** with `-race`. **Step 5: Hand back.**

### Task 5.6: Ambient-transaction and sealed-column suites

**Files:** Create `test/storetest/ambient.go`, `test/storetest/sealed.go`; Test `test/storetest/ambient_test.go`.

**Interfaces:**
- Produces:

```go
type Ambient[S any] struct {
	Write   func(ctx context.Context, s S, i int) error    // write record i
	Present func(t *testing.T, raw *sql.DB, i int) bool   // out of band
	Refuse  func(ctx context.Context, s S) error           // a refusal; must return a refusal sentinel
}
func RunAmbientTx[S any](t *testing.T, h DurableHarness[S], a Ambient[S])
// cases: rollback discards; commit keeps; refusal then Write then commit keeps both writes;
// resolver honoured (BeginResolved, rollback, absent); foreign backend tx ignored
// (BeginForeign, Write, rollback, present).

type Sealed[S any] struct {
	NewWithKeyring func(t *testing.T, kr seal.Keyring) S
	Put            func(ctx context.Context, s S, owner string, secret []byte) error
	Get            func(ctx context.Context, s S, owner string) (secret []byte, present bool, err error)
	RawSealed      func(t *testing.T, raw *sql.DB, owner string) []byte // decoded envelope bytes
	CopySealed     func(t *testing.T, raw *sql.DB, from, to string)
	Stored         string // the raw column's value is also checked as stored text, before decoding
}
func RunSealedColumns[S any](t *testing.T, h DurableHarness[S], s Sealed[S])
// cases: plaintext "SENTINEL-SECRET" absent from raw text and decoded bytes; copy victim→attacker,
// Get(attacker) errors; keyring lacking k1 → error and present=false; reseal: sealed under k1,
// read via ring {active k2, retired k1}, then Get via ring {k2} returns the secret.
```

- [ ] **Step 1: Write** `TestAmbientInputs` and `TestSealedInputs` (re-exec guard: `Raw` nil → names `DurableHarness.Raw`, the spec's "Missing out-of-band access"; `Sealed.CopySealed` nil → names it).
- [ ] **Step 2: Red** on stubs. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

---

### Task 6.1: `sqlstore` session store

**Files:** Create `internal/pgschema/sessions.go`, `sqlstore/session.go`; Test `test/sqlstore/session_test.go`, `test/sqlstore/harness_test.go`.

**Interfaces:**
- Consumes: `seal.Cipher`, `seal.SessionCipher`, `session.NewEncryptedStore`, `sqlstore.Option`.
- Produces:

```go
// NewSessionStore returns a durable session store. Provider ID tokens are
// sealed with c; there is no unsealed variant.
func NewSessionStore(db *sql.DB, c seal.Cipher, opts ...Option) (session.Store, error)
```

SQL (`pgschema`), where every lookup takes `$1 = sha256(identifier)`:

```go
const SessionInsert = `INSERT INTO sessions (id, id_digest, user_id, created_at, last_accessed_at,
  idle_expires_at, absolute_expires_at, first_factor, mfa_state, mfa_satisfied_at,
  password_change_pending, external_provider, external_issuer, external_session_id,
  external_id_token, data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
  ON CONFLICT (id_digest) DO NOTHING`
const SessionUpdate = `UPDATE sessions SET user_id=$2, last_accessed_at=$3, idle_expires_at=$4,
  absolute_expires_at=$5, first_factor=$6, mfa_state=$7, mfa_satisfied_at=$8,
  password_change_pending=$9, external_provider=$10, external_issuer=$11,
  external_session_id=$12, external_id_token=$13, data=$14 WHERE id_digest=$1`
const SessionSelect = `SELECT user_id, created_at, … , data FROM sessions WHERE id_digest=$1`
const SessionDelete = `DELETE FROM sessions WHERE id_digest=$1`
const SessionDeleteByUser = `DELETE FROM sessions WHERE user_id=$1`
const SessionCountActive = `SELECT count(*) FROM sessions WHERE user_id=$1 AND idle_expires_at > $2 AND absolute_expires_at > $2`
const SessionDeleteExpired = `DELETE FROM sessions WHERE idle_expires_at <= $1 OR absolute_expires_at <= $1`
const SessionDeleteByExternal = `DELETE FROM sessions WHERE external_issuer=$1 AND external_session_id=$2 AND $1 <> '' AND $2 <> ''`
const SessionDeleteByUserIssuer = `DELETE FROM sessions WHERE user_id=$1 AND external_issuer=$2 AND $2 <> ''`
```

Expiry on `Load` is decided in Go with the store clock, using the same rule as `session.go:152`. `Load` of an expired row returns `ErrSessionExpired`, and zero rows returns `ErrSessionNotFound`. The id column is minted from the generator on `Create`. `Create` with zero rows affected returns `errors.New("sqlstore: create session: identifier already in use")`. `Data` goes through `json.Marshal` of `map[string]string`, and nil marshals as `{}`.
- [ ] **Step 1: Write the run** in `test/sqlstore/session_test.go`:

```go
func TestSessionStore(t *testing.T) {
	t.Parallel()
	storetest.RunSessionStoreSuite(t, func(t *testing.T, now func() time.Time) session.Store {
		s, err := sqlstore.NewSessionStore(migratedDB(t), testCipher(t), sqlstore.WithClock(now))
		require.NoError(t, err)
		return s
	})
}
```

  `harness_test.go` holds `migratedDB(t) *sql.DB` (RunTestPostgres plus the security-state set), `testCipher(t)` (keyring with active `k2` and retired `k1`), and `durableHarness[S](t, newWith func(db *sql.DB, opts ...sqlstore.Option) S) storetest.DurableHarness[S]`, which fills `Raw`, `Begin` (`db.BeginTx` + `sqlstore.WithTx`), `BeginResolved` (a store built with `WithTxResolver(func(context.Context) (sqlstore.DBTX, bool) { return tx, true })`), `BeginForeign` (a `pgxpool` tx attached with `pgx.WithTx`, from the pgx module, available once 7.1 lands; until then it `t.Fatal`s with "pgx backend not yet available", which keeps 6.8's foreign case red until 7.1) and `PoolSize: 32`. Then add the table `TestSessionStore_Durable` with the rows:
  - Session identifiers are never stored: out of band `SELECT row_to_json(s)::text FROM sessions s` does not contain `SESSION-SENTINEL`, and `Load("SESSION-SENTINEL")` works;
  - Session with unreadable ID token: tamper `external_id_token` out of band → `errors.Is(err, session.ErrSessionUnreadable)`;
  - Sessions are not rewritten on read: sealed under `k1`, `Load` with ring {k2, k1}, the raw column is unchanged; `Delete`, then `Load` → not found;
  - Cipher missing: `NewSessionStore(db, nil)` → `sqlstore.ErrConfig`;
  - Missing handle: `NewSessionStore(nil, c)` → `ErrConfig`;
  - Consumer cipher used: a counting `seal.Cipher` sees one `Seal` and one `Open`, both with AAD `"scrty/session:external-id-token:" + id`.
- [ ] **Step 2: Red:** a stub `NewSessionStore` that returns `ErrConfig` → the suite fails at construction; that is compile-clean and fails for a stated reason. Better red: implement `Save` as an upsert first and see the suite's "save after delete" case fail, then correct it. Report both outputs.
- [ ] **Step 3: Implement.** `NewSessionStore` validates, builds the unexported `sessionStore`, and returns `session.NewEncryptedStore(inner, seal.SessionCipher(c))`.
- [ ] **Step 4: See green** `go test -run 'TestSessionStore' -count=1 ./sqlstore/` in `./test`. **Step 5: Hand back.**

### Task 6.2: `sqlstore` one-time token store and reaper

**Files:** Create `internal/pgschema/onetime.go`, `sqlstore/onetime.go`; Test `test/sqlstore/onetime_test.go`.

**Interfaces:** `func NewOneTimeStore(db *sql.DB, opts ...Option) (interface{ onetime.Store; onetime.Reaper }, error)`, or a named exported type `*OneTimeStore` implementing both. Prefer the named type, as the in-memory default does.

SQL:

```sql
-- OneTimeConsume
UPDATE one_time_tokens SET consumed_at = $2 WHERE id = $1 AND consumed_at IS NULL
-- OneTimeDeleteExpiredBefore ($1 purpose, $2 now, $3 retainSince)
DELETE FROM one_time_tokens WHERE purpose = $1 AND expires_at <= $2 AND issued_at < $3
```

The reaper's "now" is the store clock (`WithClock`, default `time.Now`): the contract judges expiry at call time. Confirm against `onetime/memory.go` before implementing, and report if the memory store uses something else.
- [ ] **Step 1: Write**:
  - `RunOneTimeStoreSuite` over the store;
  - `RunConsumeRace` with `Seed` inserting token i and `Attempt` = `Consume` mapping `ErrTokenNotFound` → `(false, nil)`;
  - the broken guard `brokenReadThenWriteConsume` (`FindByID`, check `ConsumedAt.IsZero()`, then `UPDATE … WHERE id=$1` unconditionally), run through the re-exec guard and asserting the inner output contains "more than one successful";
  - `TestOneTimeStore_Failures` table:
    - Consumption fails: `db.Close()` first → the error is not `ErrTokenNotFound` and wraps `sql.ErrConnDone`;
    - a cancelled `ctx` → `errors.Is(err, context.Canceled)` and not `ErrTokenNotFound` (Review Focus 1);
    - Microsecond round trip.
- [ ] **Step 2: Red:** implement `Consume` read-then-write first (that is the broken variant's body). See the race suite fail, and keep that output. **Step 3: Implement** the conditional write. **Step 4: See green**, and see the guard still green (the inner run fails). **Step 5: Hand back.**

### Task 6.3: `sqlstore` login-attempt store

**Files:** Create `internal/pgschema/attempts.go`, `sqlstore/attempts.go`; Test `test/sqlstore/attempts_test.go`.

**Interfaces:** `func NewAttemptStore(db *sql.DB, opts ...Option) (*AttemptStore, error)` implementing `policy.AttemptStore` and `policy.AttemptReaper`.

SQL: `INSERT INTO login_attempts (id, username, attempted_at) VALUES ($1,$2,$3)`; `DELETE FROM login_attempts WHERE username=$1`; `SELECT count(*) FROM login_attempts WHERE username=$1 AND attempted_at > $2`; `DELETE FROM login_attempts WHERE attempted_at < $1` (zero cutoff refused before the statement).
- [ ] **Step 1: Write**: `RunAttemptStoreSuite`, and `TestAttemptStore_IDs` table:
  - Default generator: the stored id's version nibble is 7 (`SELECT id::text`, char 14 = `7`);
  - Consumer generator: a fixed generator returning `00000000-0000-4000-8000-000000000001` → that id is stored;
  - Generator failure: the generator errors → `errors.Is(err, genErr)` and `count(*) = 0`;
  - a user name `"a\x00b"` → an error whose text does not contain `a\x00b`, and no row (Review Focus 3).
- [ ] **Step 2: Red:** ignore `WithIDGenerator` at first (always v7). See the consumer-generator row fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 6.4: `sqlstore` signing-key store (sealed)

**Files:** Create `internal/pgschema/signingkeys.go`, `sqlstore/signingkey.go`; Test `test/sqlstore/signingkey_test.go`.

**Interfaces:** `func NewSigningKeyStore(db *sql.DB, c seal.Cipher, opts ...Option) (signingkey.KeyStore, error)`. It also accepts `WithResealOnRead(on bool) Option` in `sqlstore`, forwarding to `seal.WithResealOnRead`. The unexported inner store implements `seal.SigningKeyResealer`:

```sql
-- SigningKeyUpsert
INSERT INTO signing_keys (id, kid, alg, private_key, public_jwk, created_at) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (kid) DO UPDATE SET alg=EXCLUDED.alg, private_key=EXCLUDED.private_key,
  public_jwk=EXCLUDED.public_jwk, created_at=EXCLUDED.created_at
-- SigningKeyLoadAll
SELECT kid, alg, private_key, public_jwk, created_at FROM signing_keys ORDER BY created_at, kid
-- SigningKeyReseal
UPDATE signing_keys SET private_key = $3 WHERE kid = $1 AND private_key = $2
```

`ResealSigningKey` returns nil without executing when `conn(ctx)` reports `ambient`.
- [ ] **Step 1: Write**:
  - `RunSigningKeyStoreSuite`;
  - `RunSealedColumns` with owner = kid and `RawSealed` = `SELECT private_key`;
  - `TestSigningKeyStore_Sealed` table: Signing key column (`PKCS8-SENTINEL` absent from raw bytes); One signing key unreadable (tamper one of three → `LoadAll` returns an error and nil); a read inside `WithTx` does not rewrite a `k1` value;
  - the guard `identityCipher` (Seal/Open return input, key id `k2`) through the re-exec guard, expecting `RunSealedColumns` to fail.
- [ ] **Step 2: Red:** construct with `identityCipher` first, and see the sealed suite fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 6.5: `sqlstore` MFA enrolment store (sealed)

**Files:** Create `internal/pgschema/mfa.go`, `sqlstore/mfa.go`; Test `test/sqlstore/mfa_test.go`.

**Interfaces:** `func NewEnrolmentStore(db *sql.DB, c seal.Cipher, opts ...Option) (mfa.EnrolmentStore, error)`. The inner store implements `seal.EnrolmentResealer` and stores `base64.RawURLEncoding` of the envelope.

```sql
-- EnrolmentPutPending
INSERT INTO mfa_enrolments (id, user_id, secret, confirmed_at, last_step, created_at)
VALUES ($1, $2, $3, NULL, 0, $4)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, created_at = EXCLUDED.created_at, last_step = 0
WHERE mfa_enrolments.confirmed_at IS NULL
-- EnrolmentGet
SELECT secret, confirmed_at, last_step, created_at FROM mfa_enrolments WHERE user_id = $1
-- EnrolmentConfirm
UPDATE mfa_enrolments SET confirmed_at = $3, last_step = $2 WHERE user_id = $1 AND confirmed_at IS NULL
-- EnrolmentAcceptStep
UPDATE mfa_enrolments SET last_step = $2 WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_step < $2
-- EnrolmentDelete
DELETE FROM mfa_enrolments WHERE user_id = $1
-- EnrolmentReseal
UPDATE mfa_enrolments SET secret = $3 WHERE user_id = $1 AND secret = $2
```

`PutPending` with zero rows affected returns `mfa.ErrAlreadyEnrolled`. A base64 decode failure on `Get` is an error with `false`, never absence.
- [ ] **Step 1: Write**:
  - `RunEnrolmentStoreSuite`;
  - `RunStepAcceptRace` (seed: `PutPending` plus `Confirm` at step 1000; attempt: `AcceptStep(u, 1002)`);
  - `RunSealedColumns` (owner = user; `RawSealed` decodes `secret`; `CopySealed` = `UPDATE … SET secret = (SELECT secret … WHERE user_id=$1) WHERE user_id=$2`);
  - `TestEnrolmentStore_Durable` table:
    - Cipher missing;
    - Enrolment reassigned to another user (`UPDATE … SET user_id='victim' WHERE user_id='attacker'` after deleting victim's row → `Get(victim)` errors);
    - Value moved between tables (copy a sealed session token's base64 text into `secret` → error);
    - Tampered byte;
    - Re-sealed under the active key;
    - Concurrent re-enrolment is kept: pending sealed under `k1`, read with a `seal.Cipher` wrapper whose `Open` blocks on a channel while the test runs `PutPending(new)` through a second store, then releases; the final raw secret opens to the new secret;
    - Inside a caller's transaction (no rewrite);
    - Re-seal turned off;
    - Lookup fails (closed db → error, `present == false`);
    - a cancelled `ctx` on `Get` → `context.Canceled`, `present == false` (Review Focus 1);
  - the guard `missingAADCipher` (wraps AEAD but ignores the AAD) → `RunSealedColumns` fails at "copy victim→attacker".
- [ ] **Step 2: Red:** write `AcceptStep` as `SELECT last_step` then `UPDATE` first, and see `RunStepAcceptRace` fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 6.6: `sqlstore` API key store

**Files:** Create `internal/pgschema/apikeys.go`, `sqlstore/apikey.go`; Test `test/sqlstore/apikey_test.go`.

**Interfaces:** `func NewAPIKeyStore(db *sql.DB, opts ...Option) (*APIKeyStore, error)` implementing `apikey.Store`.

```sql
INSERT INTO api_keys (id, user_id, name, scopes, secret_digest, expires_at, revoked_at, last_used_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
SELECT user_id, name, scopes, secret_digest, expires_at, revoked_at, last_used_at, created_at FROM api_keys WHERE id=$1
UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1
UPDATE api_keys SET last_used_at = $2 WHERE id = $1
SELECT id, … FROM api_keys WHERE user_id = $1 ORDER BY created_at, id
```

Zero-value `time.Time` fields map to SQL `NULL` and back to zero, and `LastUsedAt` maps `*time.Time` ↔ `NULL`.
- [ ] **Step 1: Write**: `RunAPIKeyStoreSuite`; `RunAmbientTx` rows for Resolver supplies the transaction and Resolver reports no transaction (the latter as a direct test: the resolver returns `false`, `Put`, and `Raw` sees the row at once).
- [ ] **Step 2: Red:** ignore the resolver at first, and see "resolver honoured" fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 6.7: `sqlstore` OIDC link, flow and handoff stores

**Files:** Create `internal/pgschema/oidc.go`, `sqlstore/oidc_link.go`, `sqlstore/oidc_flow.go`, `sqlstore/oidc_handoff.go`; Test `test/sqlstore/oidc_test.go`.

**Interfaces:** `NewLinkStore(db, opts...) (*LinkStore, error)`, `NewFlowStore(db, opts...) (*FlowStore, error)` (honours `WithClock` and `WithIDGenerator`, and mints `handle` as `base64.RawURLEncoding` of 32 `crypto/rand` bytes), `NewHandoffStore(db, opts...) (*HandoffStore, error)`.

```sql
-- LinkInsert: zero rows → oidc.ErrLinkExists
INSERT INTO oidc_links (id, provider, issuer, subject, user_id, username, email, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (provider, issuer, subject) DO NOTHING
-- LinkDeleteByUser
DELETE FROM oidc_links WHERE user_id = $1 AND $1 <> ''
-- FlowComplete: zero rows → oidc.ErrInvalidState
UPDATE oidc_flows SET completed_at = $4
 WHERE handle = $1 AND provider = $2 AND state = $3 AND $3 <> '' AND completed_at IS NULL AND expires_at > $4
RETURNING provider, state, nonce, verifier, next, expires_at
-- FlowDeleteExpired / HandoffDeleteExpired ($1 before; zero refused with oidc.ErrRetainSinceRequired)
DELETE FROM oidc_flows WHERE expires_at < $1
-- HandoffConsume: zero rows → oidc.ErrHandoffNotFound
UPDATE oidc_handoffs SET consumed_at = $2 WHERE token_id = $1 AND consumed_at IS NULL
```

Check the "±1s tolerated" note on `FlowStore.Complete` (`oidc/ports.go:27`) against the flow suite before choosing `expires_at > $4`. The suite is the arbiter.
- [ ] **Step 1: Write**:
  - `oidctest.RunLinkStoreSuite`, `RunFlowStoreSuite` (the store built with `WithClock(now)`), `RunHandoffStoreSuite`;
  - `RunLinkInsertRace` (8 racers insert the same provider, issuer and subject for users `u-<racer>`; win = nil error, refusal = `ErrLinkExists`);
  - `RunConsumeRace` over handoffs;
  - `TestOIDCStores_Durable` table:
    - Refused insert does not overwrite;
    - Error text carries no submitted values (`err.Error()` contains neither subject nor user);
    - All of one user's links removed (reports 2);
    - Empty user reference (reports 0);
    - Wrong state and Wrong provider do not burn a flow;
    - Expired flow (clock advanced, not slept);
    - `Complete` with an empty handle → `ErrInvalidState` (Review Focus 5);
    - Handoff subject round trip (user reference `Alice@Example.com`, provider, issuer, session id and next equal);
    - Sequential second consumption keeps T1;
    - `Consume("")` → `ErrHandoffNotFound`;
  - the guard `upsertLinkInsert` (`ON CONFLICT … DO UPDATE SET user_id = EXCLUDED.user_id`, reporting success) → `RunLinkInsertRace` fails.
- [ ] **Step 2: Red:** write `Insert` as the upsert first and see both the race and "does not overwrite" fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 6.8: `sqlstore` ambient-transaction runs

**Files:** Test `test/sqlstore/ambient_test.go`.

- [ ] **Step 1: Write** `TestAmbientTx`, one subtest per store (session, one-time, attempts, signing keys, MFA, API keys, links, flows, handoffs), each calling `storetest.RunAmbientTx` with its `Write`, `Present` and `Refuse` (for example, one-time `Refuse` consumes an already-consumed token). Add `TestAmbientTx_Scenarios`:
  - Rolled back with the caller (session);
  - Committed with the caller (attempt + consume in one tx);
  - Refusal then commit (save S, refused consume, save T, commit, both present);
  - Consumer-owned identity: with only the security-state set applied, each store's create, read and delete work, and `to_regclass('users') IS NULL`.

  The guard `bypassingSessionStore` (built on `db` and ignoring `WithTx`) goes through the re-exec guard, and `RunAmbientTx` must fail. The foreign-backend case stays red until 7.1 (see 6.1). Report it as expected-red with its message.
- [ ] **Step 2: Red:** the bypassing variant's inner run fails. **Step 3: Fix** any store that fails `RunAmbientTx` for a real reason. **Step 4: See green** except the foreign case. **Step 5: Hand back.**

---

### Task 7.1: `pgx` handle resolution and validation

**Files:** Create `pgx/tx.go`, `pgx/options.go`, `pgx/errors.go`; Test `pgx/tx_test.go` (no database).

**Interfaces:**

```go
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgxv5.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgxv5.Row
}
func WithTx(ctx context.Context, tx pgxv5.Tx) context.Context
type TxResolver func(ctx context.Context) (pgxv5.Tx, bool)
func WithTxResolver(r TxResolver) Option
func WithIDGenerator(g id.Generator) Option
func WithClock(now func() time.Time) Option
func WithResealOnRead(on bool) Option
var ErrConfig = errors.New("pgx: invalid configuration")
```

The base handle is `*pgxpool.Pool`. `id.ID` values are passed as their `String()` (pgx does not use `driver.Valuer` for uuid by default), and scanned through `pgtype.UUID` then `id.ID(u.Bytes)`. Put this in two helpers, `uuidArg` and `scanID`, tested in `pgx/uuid_test.go`.
- [ ] **Step 1: Write** `TestConfigConn` (same table shape as 4.1, with the pgx types), `TestNewConfig` (nil pool, nil resolver, nil generator, nil clock → `ErrConfig`) and `TestUUIDHelpers` (round trip through `pgtype.UUID`). **Step 2: Red** on stubs. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 7.2: `pgx` session, one-time and login-attempt stores

**Files:** Create `pgx/session.go`, `pgx/onetime.go`, `pgx/attempts.go`; Test `test/pgxstore/{harness,session,onetime,attempts}_test.go`.

**Interfaces:** `NewSessionStore(pool *pgxpool.Pool, c seal.Cipher, opts ...Option) (session.Store, error)`, `NewOneTimeStore(pool, opts...) (*OneTimeStore, error)`, `NewAttemptStore(pool, opts...) (*AttemptStore, error)`. They reuse the `internal/pgschema` SQL verbatim. Zero rows affected is `tag.RowsAffected() == 0`, and not-found on `QueryRow` is `errors.Is(err, pgxv5.ErrNoRows)`. `Data` is sent as JSON bytes to `jsonb`.
- [ ] **Step 1: Write**: the harness builds a pool from `RunTestPostgres(t, …).DSN` with `pool_max_conns=32`, and `Begin` uses `pool.Begin` + `pgx.WithTx`. The runs are:
  - `RunSessionStoreSuite`, `RunOneTimeStoreSuite`, `RunAttemptStoreSuite`;
  - `RunConsumeRace`, with the read-then-write guard through the re-exec pattern;
  - `TestSessionStore_Durable`: identifier never stored, unreadable ID token, not rewritten on read, cipher missing, missing handle, consumer cipher used;
  - `TestOneTimeStore_Failures`: closed pool → not `ErrTokenNotFound`; cancelled `ctx` → `context.Canceled`; microsecond round trip;
  - `TestAttemptStore_IDs`: default and consumer generator, generator failure, NUL user name.
- [ ] **Step 2: Red:** run before implementing the stores, with constructors returning `ErrConfig`, so construction fails with the stated error. Then implement `Consume` read-then-write and see the race fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 7.3: `pgx` signing-key, MFA and API key stores

**Files:** Create `pgx/signingkey.go`, `pgx/mfa.go`, `pgx/apikey.go`; Test `test/pgxstore/{signingkey,mfa,apikey}_test.go`.

**Interfaces:** `NewSigningKeyStore(pool, c, opts...)`, `NewEnrolmentStore(pool, c, opts...)`, `NewAPIKeyStore(pool, opts...)`. The re-seal ports write nothing when `conn(ctx)` reports an ambient tx.
- [ ] **Step 1: Write**:
  - `RunSigningKeyStoreSuite`, `RunEnrolmentStoreSuite`, `RunAPIKeyStoreSuite`;
  - `RunSealedColumns` for signing keys and MFA, with the `identityCipher` and `missingAADCipher` guards;
  - `RunStepAcceptRace`;
  - `TestSigningKeyStore_Sealed`: the column read out of band has no plaintext; one unreadable key of three fails the whole load; no re-seal inside a caller tx;
  - `TestEnrolmentStore_Durable`: cipher missing, reassigned user, value moved between tables, tampered byte, re-sealed under the active key, concurrent re-enrolment kept (blocking-`Open` cipher), no re-seal inside a caller tx, re-seal turned off, lookup fails, cancelled `ctx`;
  - `TestAPIKeyStore_Resolver`: resolver supplies the transaction; resolver reports none.
- [ ] **Step 2: Red:** first write `AcceptStep` as read-then-write, and see `RunStepAcceptRace` fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 7.4: `pgx` OIDC stores and ambient runs

**Files:** Create `pgx/oidc_link.go`, `pgx/oidc_flow.go`, `pgx/oidc_handoff.go`; Test `test/pgxstore/{oidc,ambient}_test.go`; Modify `test/sqlstore/harness_test.go` (`BeginForeign` now attaches a pgx tx).

- [ ] **Step 1: Write**:
  - the three `oidctest` suites, `RunLinkInsertRace` and `RunConsumeRace` over handoffs;
  - `TestOIDCStores_Durable`, with the same rows as 6.7: refused insert does not overwrite; error text has no submitted values; one user's links removed; empty user reference; wrong state; wrong provider; expired flow; empty handle; handoff round trip; second consumption; `Consume("")`;
  - `TestAmbientTx`, one subtest per pgx store, with `BeginForeign` attaching a `sqlstore.WithTx` tx;
  - the scenarios Rolled back, Committed, Refusal then commit and Consumer-owned identity;
  - the guards: an upsert-link variant and a store bypassing the transaction.
- [ ] **Step 2: Red:** the sqlstore foreign case from 6.8 is still red. Wire `BeginForeign` and see it pass. For the pgx stores, write `Insert` as an upsert first and see the race fail. **Step 3: Implement.** **Step 4: See green** in `./test/sqlstore` and `./test/pgxstore`. **Step 5: Hand back.**

---

### Task 8.1: `gorm` handle resolution, containment and validation

**Files:** Create `gorm/tx.go`, `gorm/options.go`, `gorm/errors.go`, `gorm/models.go`; Test `gorm/tx_test.go`.

**Interfaces:**

```go
func WithTx(ctx context.Context, tx *gormdb.DB) context.Context
type TxResolver func(ctx context.Context) (*gormdb.DB, bool)
func WithTxResolver(r TxResolver) Option
func WithIDGenerator(g id.Generator) Option
func WithClock(now func() time.Time) Option
func WithResealOnRead(on bool) Option
var ErrConfig = errors.New("gorm: invalid configuration")
// models: one struct per table with explicit `gorm:"column:…;type:…"` tags and
// TableName() methods; no AutoMigrate anywhere; id.ID columns use a
// gorm-compatible type implementing sql.Scanner/driver.Valuer (id.ID already does).
```

Every operation calls `db.WithContext(ctx)` on the resolved handle. Refusals read `result.RowsAffected`, and not-found is `errors.Is(err, gormdb.ErrRecordNotFound)`, or `RowsAffected == 0` with `Find`. The logger is set to `logger.Discard` on the store's session, because gorm's default logger prints SQL with bound values, which would put secrets and user references in logs.
- [ ] **Step 1: Write** `TestConfigConn`, `TestNewConfig` (nil db, nil resolver → `ErrConfig`) and `TestModelsTableNames` (each model's `TableName()` matches the migration). **Step 2: Red** on stubs. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 8.2: `gorm` session, one-time and login-attempt stores

**Files:** Create `gorm/session.go`, `gorm/onetime.go`, `gorm/attempts.go`; Test `test/gormstore/{harness,session,onetime,attempts}_test.go`.

Conditional writes in gorm:

```go
// consume
res := q.Model(&oneTimeToken{}).Where("id = ? AND consumed_at IS NULL", tokenID).Update("consumed_at", at.UTC())
// create session: insert-only
res := q.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id_digest"}}, DoNothing: true}).Create(&row)
// save session: update-only; Select("*") so zero values (false, 0, "") are written
res := q.Model(&sessionRow{}).Where("id_digest = ?", digest).Select("*").Omit("id", "id_digest", "created_at").Updates(&row)
```

Pin gorm's zero-value trap: without `Select`, `Updates` skips `false`/`0`/`""`, so clearing `PasswordChangePending` would silently not persist. The session suite must include a case that saves `PasswordChangePending` true, then false, and loads false. Add that case to 5.2's suite if absent. It is a suite addition, not new scope, since the contract already requires `Save` to persist every field.
- [ ] **Step 1: Write**: the harness opens `gorm.Open(postgres.Open(dsn))` and sets the pool to 32 through `DB()`; `Begin` uses `db.Begin()` + `gorm.WithTx`. The runs:
  - `RunSessionStoreSuite`, `RunOneTimeStoreSuite`, `RunAttemptStoreSuite`;
  - `RunConsumeRace` with its read-then-write guard;
  - `TestSessionStore_Durable`: identifier never stored, unreadable ID token, not rewritten on read, cipher missing, missing handle, consumer cipher used;
  - `TestOneTimeStore_Failures`: closed db → not `ErrTokenNotFound`; cancelled `ctx`; microsecond round trip;
  - `TestAttemptStore_IDs`: default and consumer generator, generator failure, NUL user name.
- [ ] **Step 2: Red:** write `Save` with `Updates(&row)` without `Select("*")` first, and see the `PasswordChangePending` case fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 8.3: `gorm` signing-key, MFA and API key stores

**Files:** Create `gorm/signingkey.go`, `gorm/mfa.go`, `gorm/apikey.go`; Test `test/gormstore/{signingkey,mfa,apikey}_test.go`.

`PutPending` uses `clause.OnConflict{Columns: user_id, DoUpdates: clause.AssignmentColumns([...]), Where: clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "mfa_enrolments.confirmed_at IS NULL"}}}}`, with `RowsAffected == 0` → `ErrAlreadyEnrolled`. `Scopes` uses a `jsonb` column through a `serializer:json` tag.
- [ ] **Step 1: Write**:
  - `RunSigningKeyStoreSuite`, `RunEnrolmentStoreSuite`, `RunAPIKeyStoreSuite`;
  - `RunSealedColumns` for signing keys and MFA, with the `identityCipher` and `missingAADCipher` guards;
  - `RunStepAcceptRace`;
  - `TestSigningKeyStore_Sealed`: no plaintext in the raw column; one unreadable key fails the whole load; no re-seal inside a caller tx;
  - `TestEnrolmentStore_Durable`: cipher missing, reassigned user, moved value, tampered byte, re-sealed under the active key, concurrent re-enrolment kept, no re-seal inside a caller tx, re-seal off, lookup fails, cancelled `ctx`;
  - `TestAPIKeyStore_Resolver`: resolver supplies the transaction; resolver reports none.
- [ ] **Step 2: Red:** omit the `Where` on the conflict clause first, and see "confirmed not replaced" fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 8.4: `gorm` OIDC stores and ambient runs

**Files:** Create `gorm/oidc_link.go`, `gorm/oidc_flow.go`, `gorm/oidc_handoff.go`; Test `test/gormstore/{oidc,ambient}_test.go`.

`FlowStore.Complete` uses `q.Raw(<the FlowComplete SQL with ? placeholders>, …).Scan(&row)` and checks `RowsAffected`, so the `RETURNING` stays one statement.
- [ ] **Step 1: Write**:
  - the three `oidctest` suites, `RunLinkInsertRace` and `RunConsumeRace` over handoffs;
  - `TestOIDCStores_Durable`, with the same rows as 6.7: refused insert does not overwrite; error text has no submitted values; one user's links removed; empty user reference; wrong state; wrong provider; expired flow; empty handle; handoff round trip; second consumption; `Consume("")`;
  - `TestAmbientTx` per gorm store, with `BeginForeign` attaching a `sqlstore` tx;
  - the scenarios Rolled back, Committed, Refusal then commit and Consumer-owned identity;
  - the guards: upsert-link, and a store bypassing the transaction.
- [ ] **Step 2: Red:** write the link `Insert` with `clause.OnConflict{UpdateAll: true}` first, and see the race fail. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

---

### Task 9.1: Cross-backend guarantees

**Files:** Create `test/crossbackend/crossbackend_test.go`.

- [ ] **Step 1: Write** `TestCrossBackend`, one migrated database and three backends over it, as a table over `{name, run func(t, b backends)}`:
  - Backends share one schema: for each ordered pair (writer, reader), `Put` an API key through the writer and `Get` it through the reader, with every field equal;
  - Transaction attached for another backend: attach a `sqlstore` tx, save a session through the pgx store, roll back, and the session exists;
  - State survives a process restart: save through one store instance, drop it and close its pool, open a new pool and store, load;
  - Another replica sees a consumption: two independent pools, consume on the first, the second is refused.
- [ ] **Step 2: Red:** point the reader at a second `RunTestPostgres` database first, and see "share one schema" fail with not-found. **Step 3: Restore.** **Step 4: See green.** **Step 5: Hand back.**

### Task 9.2: Populated-database migration rule

**Files:** Create `test/crossbackend/populated_test.go`, fixture `test/testdata/migrations/populated/99990101000000_add_not_null.sql`.

- [ ] **Step 1: Write**: apply the security-state set, seed one row in each of the nine tables through the `sqlstore` stores, then apply a second set, from the fixture dir with its own version table, that runs `ALTER TABLE <each> ADD COLUMN probe_flag boolean NOT NULL DEFAULT false`. Every seeded row then reads back through each backend's store without error. Its Down drops the columns.
- [ ] **Step 2: Red:** remove `DEFAULT false` from the fixture, and see the apply fail on populated tables. **Step 3: Restore.** **Step 4: See green.** **Step 5: Hand back.**

### Task 9.3: Suite failures name the case and the backend

**Files:** Modify `test/storetest/harness.go` (every suite wraps its cases in `t.Run(backendName+"/"+caseName)`, where the backend name comes from a new `Harness.Name string` field); Test `test/storetest/broken_test.go`.

This adds `Name` to `Harness`. Every run from 5.2 onward sets it (`"memory"`, `"sqlstore"`, `"pgx"`, `"gorm"`), and a missing `Name` fails like any other required input. Because this touches every run, do it at the end of dispatch G if possible. The task stays numbered 9.3 because its scenario is verified here.
- [ ] **Step 1: Write** a re-exec guard over the handoff suite with `zeroConsumedAt`, a variant returning `ConsumedAt` as the zero value. The inner output must contain `--- FAIL: …/zeroConsumedAt/` and the case name `consume records the time`.
- [ ] **Step 2: Red:** before the naming change the output lacks the backend segment. **Step 3: Implement.** **Step 4: See green.** **Step 5: Hand back.**

### Task 9.4: Whole-branch review and final gate

- [ ] **Step 1:** The main session dispatches a fresh reviewer (edits nothing) against every requirement and scenario in the four delta specs, and against D1–D12. Each finding is `REPRODUCED` with a failing test, or `UNREPRODUCED` with a reason.
- [ ] **Step 2:** Findings go back to fresh dispatches of the owning lane.
- [ ] **Step 3:** The main session runs `make check` (every workspace module), `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.N-alpine make test`, and `gofmt -l .` (empty), then reads the output.
- [ ] **Step 4:** The main session ticks the tasks in `tasks.md` and commits.

---

## Self-Review Notes

- **Coverage.** Every scenario in the four delta specs maps to a named test row above. The only scenario whose code is not certain to exist is "Multi-statement failure is contained" (security-state-stores). No store operation in D3 needs more than one statement, so 4.2 carries an explicit stop-and-report point instead of inventing a multi-statement operation to contain.
- **Placeholders knowingly left.** Pinned image minors (`15.N`, `18.N`) and the latest pgx/gorm versions are resolved at implementation time with `docker manifest inspect` and `go list -m -versions`. Pinning a guessed version would be worse.
- **Type consistency.** Every backend exports `NewSessionStore`, `NewOneTimeStore`, `NewAttemptStore`, `NewSigningKeyStore`, `NewEnrolmentStore`, `NewAPIKeyStore`, `NewLinkStore`, `NewFlowStore`, `NewHandoffStore`, `WithTx`, `WithTxResolver`, `WithIDGenerator`, `WithClock`, `WithResealOnRead` and `ErrConfig`, in its own package. `seal` exports `NewSigningKeyStore` and `NewEnrolmentStore` as the wrappers; the adapters call them.
