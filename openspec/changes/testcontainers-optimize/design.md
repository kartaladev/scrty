# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **`RunTestPostgres(t, opts...) PostgresConn`** in `test/testutils.go`:
  - It starts one container per call, with database, user and password all `scrty`.
  - It waits for the second "ready to accept connections" log line and a mapped port, within 70 seconds, retrying up to three times when Docker binds no host port.
  - `postgresSetUp` applies each migration set with goose `Up`. It registers a teardown that rolls each set back to zero in reverse order, runs the finalize scripts, and runs the leftover-table check when requested, within one 30-second budget.
  - `PostgresConn` exposes only `DB` (pgx stdlib, 32 open connections) and `DSN`. No caller sees the container.
- **Callers.**
  - The store packages (`sqlstore`, `pgxstore`, `gormstore`) call through `migratedDB`, `migrated` or `migratedIdentityDB`, using one of two migration lists: security-state alone, or security-state then identity. Each top-level test owns a database and shares it among its subtests.
  - The root package reaches the helper from the HTTP conformance scenarios: three adapters, scenarios run in parallel.
  - The root package's own migration tests (`migrate_*_test.go`, `testutils_postgres_test.go`) ask for an empty database and drive goose themselves, with custom version tables.
  - `TestRunTestPostgresImage` sets `SCRTY_TEST_POSTGRES_IMAGE` and checks for PostgreSQL 15 and then 18.
- **What tests rely on.**
  - No test stops, reconfigures or inspects the server.
  - No test creates roles, tablespaces or databases, or uses `LISTEN`/`NOTIFY` or the database name.
  - Many tests rely on the database being theirs alone: whole-table `TRUNCATE`s, triggers and constraints added in committed DDL, and `pg_stat_activity` filtered by `current_database()`. Advisory locks are database-scoped.
- **Child processes.** `storefix.CatchBrokenVariants` and `crossbackend/naming_test.go` re-execute the test binary once per broken variant, in parallel, with `cmd.Env = append(os.Environ(), …)`. Each child calls the helper.
- **CI.** `make check` runs `go test -race -count=1 ./...` per module on `ubuntu-latest`, which has 4 vCPU and 16 GB for a public repository. `-p` and `-parallel` are at their defaults. Each package is its own process, and the packages of the `test` module run at the same time on one Docker host.
- **The established design** started containers per test, as scrty does today. It had no shared servers or template databases, so nothing here departs from it.

## Goals / Non-Goals

**Goals:**
- Cut the `test` module's wall time by removing almost all PostgreSQL container starts.
- Keep every test, assertion and per-call check exactly as strong as today: same tests, same count, same teardown checks, `-race` kept.
- No caller changes.

**Non-Goals:**
- **Sharing one server across package processes**, through a CI service container or reuse by name. The user chose per process on 2026-10-02 (see D1).
- **Sharing Keycloak or Mailpit.** Each has a single caller (D7).
- **Changing `-p`, `-parallel` or `-race`** in `make check`.
- **Transaction-rollback isolation** (D2 alternatives).

## Decisions

### D1. One PostgreSQL server per test process and image

- **What.** A process-wide registry maps a resolved image to a server. The first call for an image starts it, and later calls wait on that start and reuse the server.
  - The image resolves as today: the `WithTestPostgresImage` option, then `SCRTY_TEST_POSTGRES_IMAGE`, then the pinned default. `TestRunTestPostgresImage` therefore still gets a PostgreSQL 15 server and a PostgreSQL 18 server.
- **Start.** The server starts with a context that does not belong to the first caller's test. A test that ends must not cancel a server others use. The 70-second readiness budget and the host-port retry are kept.
- **A failed start** is remembered per image. Every later call in the process fails with the same reason at once, and no new start is attempted. This avoids fifty sequential 70-second timeouts when Docker is broken. The `CI` rule is unchanged: with no healthy runtime the call fails in CI and skips elsewhere.
- **Teardown.** testcontainers' reaper (Ryuk) removes the container when the process exits, since no test owns a shared server's lifetime.
  - Alternative rejected: a `TestMain` in every package to terminate it. That is boilerplate in eight packages, and a consumer calling the helper would need it too.
- **Default and override.**
  - Default: a shared server.
  - `WithTestPostgresOwnServer()`, a new option, gives that call a container of its own, terminated when its test ends, as today. It is for a test that must change server settings or stop the server. No current test needs it.
- **Alternative rejected: one server for the whole run.** It needs provisioning outside `go test`, through the Makefile or a CI service container, or testcontainers' experimental reuse-by-name. Plain `go test ./...` would then behave differently from `make check`. The user chose per process.

### D2. A database per call, cloned from a template per migration list

- **Fingerprint.** A call's migration list is fingerprinted as the ordered list of its sets. Each set contributes its version table, its directory, and a SHA-256 over the names and contents of every file in that directory.
  - Two calls with the same list share a template. A changed file, or a different order, gives a different one.
- **Template.**
  - Named `tpl_<fingerprint prefix>` and built once per server: create it, apply the sets in order with goose, close every connection to it, then `ALTER DATABASE … WITH IS_TEMPLATE true ALLOW_CONNECTIONS false`.
  - Blocking connections means no stray session can hold it. A held template makes every clone fail with "source database … is being accessed by other users".
- **Clone.**
  - Each call gets `CREATE DATABASE t_<random> TEMPLATE tpl_…` with the default `WAL_LOG` strategy, which PostgreSQL documents as the efficient one for small templates. `FILE_COPY` forces two checkpoints per clone.
  - A call with no sets gets `CREATE DATABASE t_<random>` from `template1`, which is the database a fresh container gives today.
  - `PostgresConn.DSN` names the clone, and `DB` keeps its 32-connection limit.
- **Teardown (unchanged checks).** The call's teardown runs on the clone:
  1. roll back each set to zero in reverse order (the clone carries the template's version-table rows, so goose rolls back exactly what was applied);
  2. run the finalize scripts, then the leftover-table check;
  3. close `DB`, since steps 1 and 2 run through it;
  4. `DROP DATABASE … WITH (FORCE)` on the server's admin pool;
  5. for an own server only, close its admin pool and terminate the container.

  Failures fail the test as today. Steps 1 and 2 share today's 30-second budget. The drop has a budget of its own, as today's container termination does, so a slow rollback cannot leave the database behind.
  - Rolling every clone back is kept on purpose. It is what proves every set's down migrations on every call, and dropping it would weaken the gate.
- **Concurrent clones of one template: verified in task 2.2 (2026-10-03).** Fifty parallel calls, run ten times on each of `postgres:15.19-alpine` and `postgres:18.6-alpine` (500 clones per run, up to 8 at once on the admin pool), gave no `55006` "being accessed by other users" error and no other failure. Those clones were of `template1`. Task 2.3 repeated the check on the migrated security-state template: fifty parallel calls, ten times on each image (500 clones per image), with the same result. Clones are not serialised. The reasoning that motivated the check follows.
- **Originally unverified: concurrent clones of one template.** The PostgreSQL docs neither promise nor forbid concurrent clones of one template. The source takes a share lock on the source relations for a `WAL_LOG` copy, and pgtestdb and integresql both clone concurrently in practice.
  - Task 2.2's parallel-clone test is the red step.
  - If it shows conflicts, clones of one template are serialised in-process. They stay cheap, so this changes no requirement.
- **Alternatives rejected:**
  - **Transaction rollback per test** (Rails, Django `TestCase`). The stores begin and join their own transactions, the race suites need several connections that see each other's commits, and Django itself points such tests at `TransactionTestCase`.
  - **testcontainers' `Snapshot`/`Restore`.** It restores one named database in place, so it is serial by design and cannot give parallel tests separate databases.
  - **Truncating between tests on a shared database.** Tests add triggers and constraints and read whole tables, so leftover objects would leak between tests.

### D3. A template is built once, safely, even across processes

- **In-process.** One build per server and fingerprint, through a `singleflight`-style map. Parallel first calls wait for it.
- **Across processes.** Child processes reach the same server (D5), so the build also runs under `pg_advisory_lock(<fingerprint key>)`, held on a connection to the server's maintenance database. After taking the lock, the builder checks `pg_database`:
  - a template already marked `datistemplate` is used as is;
  - a database of that name that is not marked is a half-built leftover from a failed build, and is dropped and rebuilt;
  - otherwise the template is built.
- **Failure.** A failed build drops the half-built database and fails the call, naming the set. Nothing is cached, so the next call naming the same list tries again from empty. That follows the spec requirement "A migration set that fails is never handed out half applied".

### D4. Our own implementation, not pgtestdb

Both give each test a database cloned from a migrated template. They differ in who owns what.

| | Our own (chosen) | pgtestdb |
|---|---|---|
| **Server** | Started and owned by `RunTestPostgres` (D1), tuned for tests (D6). | Expects a server you already run; its README assumes a Compose or CI service shared by all packages. With testcontainers, we would still write D1 ourselves. |
| **Migrations** | Our goose sets, in order, each with its own version table, fingerprinted by content (D2). | A `Migrator` interface. A goose plugin exists, but several sets with separate version tables means writing our own `Migrator` that hashes them (unverified for its goose plugin). |
| **Per-test teardown** | Rollback of every set, finalize scripts, leftover-table check, then drop: today's gate, unchanged. | Drops a passing test's database and keeps a failing one. It has no rollback or leftover check; we would add them in `t.Cleanup` around it, and its drop would race our rollback. |
| **Connections** | pgx stdlib `DB` and a DSN, as `PostgresConn` exposes today. | `database/sql`; returns a `*sql.DB` and lets you build a DSN. Compatible. |
| **Cross-process build** | An advisory lock and a `datistemplate` marker (D3): about 40 lines, tested. | Already solved (advisory lock, `once.Map`, half-built recovery). This is its strongest point. |
| **Dependency** | None. | `github.com/peterldowns/pgtestdb`: MIT, 512 stars, last push 2026-08-07, no releases (tag v0.1.1, pre-1.0), no OSV advisories, as read on 2026-10-02 (figures drift). |
| **Size** | About 150 lines plus tests in `test/testutils.go`. | About 30 lines of wiring, plus a custom `Migrator` and the teardown we must keep. |

- **Why our own.** The parts pgtestdb solves are the template build and the cross-process lock: about 40 of our lines. The parts it does not solve are the server lifecycle, ordered multi-set fingerprints, and the per-call rollback and leftover checks. Those are most of the work, and they are what keeps the gate as strong as today. Adopting it would add a pre-1.0 dependency and still leave us writing the hard parts around it.
- **Revisit** if a second database engine or a cross-package shared server is ever wanted. That is pgtestdb's home ground.

### D5. Child test processes reuse their parent's servers

- **Publishing.** When a server starts, the registry adds it to an environment variable of the process, `SCRTY_TEST_POSTGRES_SERVERS`: a JSON map from image to maintenance DSN, set with `os.Setenv`.
- **Inheriting.** A child started with `append(os.Environ(), …)` inherits the variable. Its registry reads the variable before starting anything, so a child never starts a server for an image its parent already runs.
- **The parent starts first.** Children started before any server exists would each start one. So a parent that spawns PostgreSQL children calls `test.EnsureTestPostgresServer(t, opts...)` first: the PostgreSQL broken-variant parents (`sqlstore`, `pgxstore`, `gormstore`) and the cross-backend naming check.
  - The new exported function starts or reuses the shared server for the resolved image, publishes it, and fails or skips by the same `CI` rule as `RunTestPostgres`.
  - It honours only the image option. `WithTestPostgresOwnServer()` or a migration, finalize or leftover-check option passed to it fails the test as a configuration error, because Ensure provisions no database for them to act on (`library-design.md` rules 4 and 6). Those options belong on `RunTestPostgres`.
  - **Unreadable inheritance fails, never falls back.** A malformed `SCRTY_TEST_POSTGRES_SERVERS`, or an inherited server that does not answer within 30 seconds, fails the call with an error naming the variable, and starts nothing. Starting a server instead would hide a broken handover. An unset or empty variable means nothing is inherited.
  - `storefix.CatchBrokenVariants` is left unchanged, because its in-memory callers in `storetest` need no server and must keep running without Docker.
- **Databases stay the child's own.** A child still clones a database of its own, and drops it in its own teardown. Template builds are safe across the two processes (D3).
- **The variable is internal.** It is a contract between processes of one test binary, not consumer API, so it is unexported and documented in the helper's godoc.

### D6. The shared server is tuned for tests

- **Durability.** The server runs with `fsync=off`, `synchronous_commit=off` and `full_page_writes=off`, and its data directory is on a tmpfs.
  - PostgreSQL documents these as risking loss only on an operating-system crash, which a test container's lifetime makes irrelevant.
  - **Unverified:** that they leave isolation, locking and error behaviour untouched. The docs describe them as affecting only when WAL reaches disk. The spec requirement "Server tuning never changes what a test can observe" pins it with a serialization-conflict test, and the race, ambient-transaction and lock-wait suites run unchanged on the tuned server.
  - Unlogged tables are not used: they change behaviour.
- **Connections.** `max_connections` is sized for parallel tests, because each call's `DB` may open 32 connections, or 8 for the conformance pool. The children of one package share the parent's server.
  - Task 3.2 measures the peak connection count of a full local and CI run first, then sets the value with headroom and records the measurement here.
  - **Set provisionally in task 2.2 (2026-10-03).** From task 2.1 on, one server carries a whole package, and PostgreSQL's default of 100 connections failed the three store packages with SQLSTATE 53300 (`too many clients already`). `max_connections=1000` turned them green, so it is set as a provisional value. Task 3.2 replaces it with the measured value.
  - **Measured in task 3.2 (2026-10-04).** Client backends were sampled every few hundred milliseconds in each server of one local `go test -race -count=1 ./...` (PostgreSQL 18.6, about 3,270 samples, broken-variant children included). Peaks: `pgxstore` 301, `gormstore` 157, `sqlstore` 153, `crossbackend` 35, root package 19 per server. `max_connections` is the largest peak doubled and rounded up to the next hundred: **700**, about 2.3 times the sampled peak. Task 4.2 checks it against CI.
- **Data directory.** The tmpfs mount covers the image's data directory, which differs between the PostgreSQL 15 and 18 images (`PGDATA` moved in 18). Task 3.2 verifies the path on both.
  - **Found in task 3.2.** The 15 image sets `PGDATA=/var/lib/postgresql/data` with that path as its volume. The 18 image sets `/var/lib/postgresql/18/docker` with `/var/lib/postgresql` as its volume, and refuses to start when `/var/lib/postgresql/data` is a mount ("there appears to be PostgreSQL data in … (unused mount/volume)").
  - **So the helper pins `PGDATA=/var/lib/postgresql/data` on every image** and mounts a tmpfs on both `/var/lib/postgresql` and `/var/lib/postgresql/data`. Neither image then leaves an anonymous disk volume behind, and `SHOW data_directory` is the same on both.
  - Each mount is capped at 2 GB, so a runaway test fails with "no space left" rather than exhausting the Docker VM's memory. The largest data directory sampled was 520 MB (`sqlstore`).
  - `fsync=off` is already in the testcontainers module's default command. The helper sets it again, so the tuning does not depend on that default.
- **Own servers** (`WithTestPostgresOwnServer`) are tuned the same way, so a test's observations never depend on which kind it got.

### D7. Keycloak and Mailpit stay per call; the Keycloak budget is re-measured

- **Per call.** `RunTestKeycloak` and `RunTestSMTP` each have one caller.
  - Sharing Keycloak would also need per-test realms, because the back-channel logout URL is fixed per container at import.
  - Sharing Mailpit would need per-test mailbox clearing.
- **The Keycloak budget** went from three to five minutes in `1f76d35` because the PostgreSQL load starved its start-up build (augmentation). After this change, task 4.2 reads the Keycloak start time from three CI runs of each job.
  - If every run is ready within 90 seconds, the budget goes back to three minutes.
  - Otherwise it stays at five, and the measurement is recorded here.
- **Alternative rejected: a pre-built, optimized Keycloak image** (`kc.sh build`, then `start --optimized`), which Keycloak documents for the fastest start. The build step would run inside the test run, costing the same augmentation, unless we published our own image, which this change does not do. The stock image refused `start --optimized` when tried on 2026-10-02 because it had not been built.

### D8. Quality and speed are measured, not assumed

- **Before.** Task 1.1 records:
  - per-package wall times of the `test` module from one local run and from the CI jobs of `1f76d35`;
  - the test count: passed tests and subtests from `go test -json`.
- **Before (recorded 2026-10-03).**
  - Local: `go test -race -count=1 -json ./...` in `test` on 14 CPUs (Docker 29.8.0), 3 min 6 s wall time. CI: run 36997890510 of `1f76d35`, both jobs green.

    | Package | Local (s) | CI PG 15 (s) | CI PG 18 (s) | PostgreSQL containers (local) |
    |---|---|---|---|---|
    | `test` | 183.6 | 316.7 | 409.4 | 98 |
    | `test/sqlstore` | 148.0 | 247.8 | 326.8 | 59 |
    | `test/pgxstore` | 149.7 | 264.5 | 338.5 | 60 |
    | `test/gormstore` | 148.5 | 297.1 | 374.1 | 67 |
    | `test/crossbackend` | 33.7 | 45.7 | 54.2 | 16 |
    | `test/storetest` | 8.9 | 9.7 | 11.9 | 0 |
    | `test/oidc` | 6.9 | 12.4 | 10.3 | 0 |
    | `test/identity` | 4.6 | 5.3 | 4.9 | 0 |
    | `test/ratelimittest` | 3.8 | — | — | 0 |
    | `test/internal/storefix` | 3.3 | 1.1 | 1.1 | 0 |

  - Test count (local `go test -json`): **4439 passed** tests and subtests, 0 failed, 18 skipped. `test/httpsecconformance` has no tests.
  - Containers are counted from the "Creating container for image postgres" lines in each package's output, child processes included: **300** in all.
  - `test/ratelimittest` is not in the `1f76d35` CI run; it was added after it.
- **After.** The same measurements, recorded in this section.
- **Acceptance:**
  - the same test count;
  - every test passing under `-race`;
  - the helper's own tests covering every new requirement;
  - the store packages' CI wall time at least halved. If a target is missed, the cause is measured and recorded before anything else changes.

### D9. The project's testcontainers convention changes with it

- **The skill.** `.claude/skills/use-testcontainers/SKILL.md` practice 6 ("One container per test, by default", with a testify suite as the way to share) becomes "one server per process, one database per call", together with:
  - when a test needs `WithTestPostgresOwnServer`;
  - why testify suites are not the sharing mechanism: they give no isolation between their tests, and they do not combine with the parallel table tests the `table-test` skill requires.
- **Godoc.** The godoc of `RunTestPostgres`, which says "Every call starts its own container", is rewritten to match.

## Risks / Trade-offs

- **[One server failing takes down every PostgreSQL test in the process, not one.]** → The failure is remembered and reported once, with its reason, to every call (D1). A healthy Docker host is already a precondition today.
- **[Ryuk disabled (`TESTCONTAINERS_RYUK_DISABLED=true`) leaks shared servers until removed by hand.]** → This is documented in the helper's godoc and the skill. Containers carry testcontainers' labels, so `docker rm` by label clears them. scrty's CI does not disable Ryuk.
- **[A template held by a stray connection makes every clone fail.]** → Templates disallow connections once built (D2).
- **[Connection exhaustion under parallel tests and child processes.]** → `max_connections` is sized from a measurement (D6).
- **[A parent whose server is not started before its children are spawned.]** → `storefix` starts it first (D5). The helper's tests check that children start no container.
- **[Memory on tmpfs.]** → Clones are dropped at the end of each call. A migrated clone is a few megabytes, and the runner has 16 GB.
- **[A debugging session loses the failed test's database]**, because it is dropped as today's container is terminated. → No change from today.

## Migration Plan

Code order, each step leaving `make check` green:

1. Record the baseline (D8).
2. Add the registry, templates and clones behind the unchanged `RunTestPostgres` signature, with the helper's own tests.
3. Make child processes reuse their parent's server.
4. Tune the server.
5. Update the skill and godoc.
6. Re-measure, including the Keycloak budget, and record the results.

No production code and no consumer API change. **Rollback:** revert the commits. Callers are unchanged, so a revert is clean.

## References

### Researched (accessed 2026-10-02)

**D1, D5: sharing per process, child processes, CI resources**
- [`cmd/go` documentation](https://pkg.go.dev/cmd/go): one test binary per package; `-p` runs them in parallel (default GOMAXPROCS); `-parallel` limits `t.Parallel` within one binary.
- [testcontainers-go: creating a container](https://golang.testcontainers.org/features/creating_container/): reuse-by-name is experimental, and the examples terminate per test.
- [testcontainers-go: garbage collector (Ryuk)](https://golang.testcontainers.org/features/garbage_collector/): Ryuk removes labelled containers after the process ends; disabling it is for CI with its own cleanup.
- [testcontainers-go releases](https://github.com/testcontainers/testcontainers-go): latest v0.44.0 (2026-08-07), read through the GitHub API on 2026-10-02 (drifts).
- [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners): `ubuntu-latest` has 4 vCPU and 16 GB for public repositories.

**D2, D3: template databases and their safety**
- [PostgreSQL 18: CREATE DATABASE](https://www.postgresql.org/docs/18/sql-createdatabase.html): `TEMPLATE`, `STRATEGY` (`WAL_LOG` default and efficient for small templates; `FILE_COPY` checkpoints), `IS_TEMPLATE`, `ALLOW_CONNECTIONS`, no other sessions on the template.
- [PostgreSQL 15: CREATE DATABASE](https://www.postgresql.org/docs/15/sql-createdatabase.html): the same on the oldest supported major.
- [PostgreSQL 18: template databases](https://www.postgresql.org/docs/18/manage-ag-templatedbs.html): `datistemplate` and `datallowconn`.
- [PostgreSQL 18: DROP DATABASE](https://www.postgresql.org/docs/18/sql-dropdatabase.html): `WITH (FORCE)` and its limits.
- [PostgreSQL `dbcommands.c` (REL_18_STABLE)](https://raw.githubusercontent.com/postgres/postgres/REL_18_STABLE/src/backend/commands/dbcommands.c): the "source database … is being accessed by other users" error, and the share lock taken during a `WAL_LOG` copy.
- [testcontainers-go postgres module](https://golang.testcontainers.org/modules/postgres/) and [its source](https://raw.githubusercontent.com/testcontainers/testcontainers-go/main/modules/postgres/postgres.go): `Snapshot`/`Restore` recreate one named database in place, so they are serial.
- [Django testing overview](https://docs.djangoproject.com/en/5.2/topics/testing/overview/): `TestCase` rolls back per test, and `TransactionTestCase` exists for code that manages transactions.
- [Rails testing guide](https://guides.rubyonrails.org/testing.html): transactional tests, and a database per parallel worker.

**D4: our own implementation vs pgtestdb**
- [pgtestdb README](https://raw.githubusercontent.com/peterldowns/pgtestdb/main/README.md) and [`testdb.go`](https://raw.githubusercontent.com/peterldowns/pgtestdb/main/testdb.go): template per migrator hash, advisory lock and `once.Map`, `datistemplate` marker, half-built recovery, drop on pass and keep on failure, external server.
- GitHub API for [pgtestdb](https://github.com/peterldowns/pgtestdb): MIT, 512 stars, 0 open issues, last push 2026-08-07, no releases (tag v0.1.1), read 2026-10-02 (drifts).
- [integresql README](https://raw.githubusercontent.com/allaboutapps/integresql/master/README.md): a separate REST server with template pools; last push 2024-01-30 through the GitHub API, read 2026-10-02 (drifts).
- [OSV query API](https://api.osv.dev/v1/query): no advisories for pgtestdb, integresql or integresql-client-go, queried 2026-10-02.

**D6: server tuning and connections**
- [PostgreSQL 18: non-durable settings](https://www.postgresql.org/docs/18/non-durability.html): `fsync`, `synchronous_commit`, `full_page_writes`, and the operating-system-crash caveat.
- [PostgreSQL 18: connection settings](https://www.postgresql.org/docs/18/runtime-config-connection.html): `max_connections` defaults to 100, with 3 reserved for superusers.

**D7: Keycloak**
- [Keycloak: running in a container](https://www.keycloak.org/server/containers): build at image time for the best start-up, and skipping it "significantly increases startup time".
- [Keycloak: configuring Keycloak](https://www.keycloak.org/server/configuration): build options vs runtime options, and `start --optimized`.
- [Keycloak: import and export](https://www.keycloak.org/server/importExport): `--import-realm` at start-up.

**D8, D9**
- Reasoned from scrty's own settled specs (`module-layout`, `store-conformance`), the project's `use-testcontainers` and `table-test` conventions, and the established design.
