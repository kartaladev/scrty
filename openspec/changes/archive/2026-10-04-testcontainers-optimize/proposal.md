# Proposal

## Why

`RunTestPostgres` starts a new PostgreSQL container for every call, and a CI job of the `test` module makes about 300 calls:
- 95 in the root package;
- about 55 in each of the three store packages;
- 34 in the child processes that check broken store variants;
- 15 in `crossbackend`.

On a four-CPU runner that load stretched the store packages to between 200 and 370 seconds each. It also starved the one Keycloak container: Keycloak's start-up build took 100 seconds, and `TestKeycloak` failed every run of the PostgreSQL 18 job until its start-up budget was raised from three to five minutes. Every one of those tests needs a database of its own, but none needs a server of its own. Each pays for a server start only because the helper offers nothing smaller.

## What Changes

- **One PostgreSQL server per test process and image.** `RunTestPostgres` starts it lazily on first use and every later call in the process reuses it. A call that asks for another image gets a server for that image.
- **A database per call, cloned from a template.**
  - Each distinct, ordered list of migration sets is applied once, to a template database.
  - Every call gets a fresh database cloned from that template, so no two calls see each other's rows, tables, triggers or locks.
  - A call with no migration set gets an empty database, as today.
- **Per-call checks are unchanged.** The rollback of each applied set, the finalize scripts and the leftover-table check still run at the end of every call, on that call's own database. The database is then dropped.
- **Child test processes reuse their parent's servers.** The processes that run broken store variants inherit the servers instead of starting their own.
- **The shared server is tuned for tests.** Durability settings that matter only after an operating-system crash are off, the data directory is in memory, and the connection limit is sized for parallel tests.
- **The signature of `RunTestPostgres`, its options and `PostgresConn` do not change**, so no caller of it changes.
- **The Keycloak start-up budget is re-measured.** Once the PostgreSQL load is gone, the budget goes back to three minutes if CI shows the headroom, and stays at five minutes otherwise, with the measurement recorded.
- **The `use-testcontainers` skill's default changes** from "one container per test" to "one server per process, one database per test", and the skill describes when a test needs a server of its own.
- **Keycloak and SMTP stay one container per call.** Each has a single caller, so sharing gains nothing.

## Capabilities

### New Capabilities

- `test-provisioning`: how the test module's helpers provision container-backed resources for tests:
  - each call's isolation;
  - server sharing by process and image;
  - the migration-set template and the per-call checks;
  - reuse by child processes;
  - start-up budgets.

### Modified Capabilities

None. `module-layout` and `store-conformance` keep their requirements. The helpers stay in the test module, and the suites still take harnesses rather than containers.

## Impact

- **Code:**
  - `test/testutils.go`: `RunTestPostgres`, `postgresSetUp` and the Keycloak budget. The server registry is in the new `test/testutils_pgserver.go`, and the template builder in the new `test/testutils_pgtemplate.go`;
  - a new exported `test.EnsureTestPostgresServer`, called by the PostgreSQL broken-variant parents and the cross-backend naming check before they spawn child processes;
  - `test/testutils_postgres_test.go`: the helper's own tests.
- **Tests:** no caller of `RunTestPostgres` changes. The four parent tests that spawn PostgreSQL child processes each gain one `EnsureTestPostgresServer` call. Every existing test must pass unchanged, and the number of tests run must not fall.
- **CI:** `make check` is unchanged. Wall time of the `test` module is measured before and after.
- **Docs:** `.claude/skills/use-testcontainers/SKILL.md` and the godoc of `RunTestPostgres`.
- **No new dependency.** No production module changes.
