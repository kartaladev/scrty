---
name: use-testcontainers
description: Provision heavy external resources (PostgreSQL, MinIO, SNS, Redis, Kafka, etc.) in Go tests using testcontainers-go, never via mocks, in-memory fakes, Docker Compose, or shared dev databases. When a service already has a helper, call it directly — do not spin up your own container or write a parallel helper. When adding support for a service with no helper yet, expose it through a single `RunTestX(t *testing.T, opts ...TestOption) <conn>` helper in the owning module's `testutils.go`. Use whenever a Go test needs a database, object store, queue, cache, or any external service whose behavior is hard to fake faithfully. Overrides the integration-test scaffolding guidance in `cc-skills-golang:golang-testing`; when the two conflict, prefer this one.
---

# Testing with Testcontainers

This repo provisions every resource-heavy dependency (databases, object stores, message brokers, caches) through [`testcontainers-go`](https://github.com/testcontainers/testcontainers-go). No mocks, no `sqlmock`, no `miniredis`, no shared dev instance.

When this skill conflicts with `cc-skills-golang:golang-testing` (which leans on in-memory fakes for speed), this skill wins for these resource categories. Faithful integration tests catch the things mocks hide — schema drift, real isolation behavior, codec bugs, IAM-style permission mismatches, container-startup timing assumptions — and those are exactly the bugs that survive into production.

## Why testcontainers, not the alternatives

- **Mocks / `sqlmock`** lie about query parsing, transaction isolation, and driver-level error shapes. A test passing against `sqlmock` while the real query fails on Postgres is the canonical case of this skill existing.
- **In-memory fakes (`miniredis`, embedded MinIO clones)** diverge from real server behavior in subtle ways — eviction policies, ETag formats, multipart semantics. They're fine for narrow unit tests of business logic, never for integration tests of the adapter that talks to the real service.
- **Shared dev databases / Docker Compose stacks** create cross-test pollution, force serialized CI runs, and break when two developers run tests in parallel. Testcontainers gives each test (or test suite) its own isolated container that is torn down on exit.
- **Skipping the test entirely** until "we have a real environment" is technical debt that accrues silently. If the service is hard to fake, that is exactly the reason to use a container.

## Use existing helpers — do not reinvent

For a service that already has a helper in this workspace, **call that helper**. Do not spin up your own container, do not copy-paste startup code into your test file, do not introduce a parallel helper with the same purpose. Duplicated startup paths drift, hide bugs, and double CI time.

Before writing any container startup code, check the owning module for a `testutils.go` exposing a `RunTestX` helper. If one exists, call it and extend it through its functional options (migrations, init scripts, bucket pre-creation) rather than handling those inline. If you find a need the helper truly cannot express, add a new option to the helper itself; that keeps every future caller benefiting from the same fix. If no helper exists for the service, see *Adding support for a new service* below.

**Anti-pattern to avoid** — a per-test helper that re-implements an existing `RunTestX`:

```go
// DO NOT: re-implement in a test file what the module's RunTestX helper already
// does. New tests must not follow this shape; existing instances should be
// migrated when touched.
func ConnectionString(t *testing.T) string {
    container, err := postgres.Run(ctx, "postgres:16.10-alpine", /* ... */)
    // ...
}
```

The correct shape for the consumer is one line:

```go
db := store.RunTestDatabase(t,
    store.WithInitScripts("testdata/schema.sql"),
)
```

(That is illustrative — substitute whichever module owns the service and the helper it actually exposes.)

## Adding support for a new service

The rest of this section applies **only when you are adding a service that does not yet have a helper** (Postgres, MinIO, SNS, Redis, Kafka, etc.). Once added, every downstream test must use the helper, not roll its own container.

Every new service exposes **one helper** in the owning module's `testutils.go`, with this shape:

```go
// In <module>/testutils.go
func RunTestX(t *testing.T, opts ...TestOption) <ReturnType> {
    t.Helper()

    cfg := &testConfig{ /* defaults: pinned image, sensible startup, etc. */ }
    for _, opt := range opts {
        opt(cfg)
    }

    ctx := t.Context()

    container, err := x.Run(ctx, cfg.image,
        // service-specific options
        testcontainers.WithWaitStrategy(
            wait.ForLog("ready").WithStartupTimeout(20*time.Second),
        ),
    )
    require.NoError(t, err, "failed to start <service> test container")

    t.Cleanup(func() {
        cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := container.Terminate(cleanupCtx); err != nil {
            t.Fatalf("failed to terminate <service> container: %s", err)
        }
    })

    // build the client/connection the caller actually wants
    return /* *sql.DB, *minio.Client, *sns.Client, etc. */
}
```

The return type is the **highest-level client a consumer would want**, not a raw container handle. For Postgres that means the database handle the module's code actually uses (e.g. `*sql.DB` or `*pgxpool.Pool`). For MinIO it would be a configured `*minio.Client`. For SNS, an `*sns.Client` already pointed at the LocalStack endpoint. Callers should not need to know about `testcontainers.Container` at all.

**Why this exact shape:**

- `t.Helper()` keeps failure lines pointing at the test, not the helper.
- Functional options (`TestOption`) let consumers extend setup (init scripts, migrations, bucket pre-creation) without forking the helper.
- `t.Cleanup` ties container lifetime to the test, so a test failure or panic still terminates the container.
- Termination uses a **fresh `context.Background()` with a timeout**, not `t.Context()`. `t.Context()` is already canceled by the time cleanup runs, and `Terminate` would no-op or fail.
- One helper per service means new modules don't reinvent wait strategies, image pinning, or cleanup discipline — and code review of "are containers being terminated" stays cheap.

## Required practices

1. **Pin the image tag to a specific version.** `postgres:16.10-alpine`, `minio/minio:RELEASE.2024-09-13T20-26-02Z`, etc. Never `:latest`. Pinned images keep CI reproducible and stop a remote image update from changing test behavior overnight.

2. **Always declare a wait strategy.** A container being *started* is not the same as a service being *ready*. Use `wait.ForLog`, `wait.ForListeningPort`, `wait.ForHTTP`, or a combination, sized for the slowest reasonable startup. For Postgres specifically, wait for `"database system is ready to accept connections"` with `WithOccurrence(2)` — the log appears once during init and once after restart, and only the second one means the database is truly ready.

3. **Register `t.Cleanup` for `container.Terminate` immediately after a successful start.** Before any other setup that could fail. Otherwise a failed migration or init script will leak the container.

4. **Use `t.Context()` for the start/setup context, and `context.Background()` with a timeout for cleanup.** Document this in the helper if it isn't obvious — every new service helper rediscovers the "t.Context is dead during cleanup" trap.

5. **Don't gate testcontainer tests behind build tags.** This repo keeps integration and unit tests in the same `go test ./...` run. The trade-off is accepted: slower local runs in exchange for never having "integration tests broken for two weeks because nobody ran them with the right tag."

6. **One container per test, by default.** If a service is genuinely slow to start and shared state is acceptable (read-only fixtures, generated UUIDs preventing collisions), promote the helper to a `testify/suite` `SetupSuite` so the container is shared across the suite's tests. This is the same boundary referenced in the [`table-test`](../table-test/SKILL.md) skill.

## Helper file layout

```
<module>/
├── testutils.go              // RunTestX helpers, exported for downstream tests
├── testutils_test.go         // exercise the helper itself (optional but encouraged)
└── <feature>/<feature>_test.go  // consumes RunTestX from the parent module
```

- The helper lives in the **producer module** (the one that owns the integration), not in a shared `internal/testutils` package. A Postgres helper belongs in the module that owns the Postgres adapter, not in `internal/testing/`. This keeps each module self-contained — a downstream consumer doesn't import a sprawling test-utility module just to spin up Postgres.
- Filename is **`testutils.go`** (no `_test.go` suffix) so the helper is reachable from `_test.go` files in *other* packages. The file may itself import test-only dependencies like `github.com/testcontainers/testcontainers-go` — that's fine in this repo because the test container modules are direct deps, not test-only deps.
- Functional options live in the same file as `RunTestX`; option types are unexported (`testConfig`) with exported `With*` constructors, following the template above.

### scrty: helpers and the tests that use them live in the `test` module

In this repository, the "producer module" rule above is replaced by one rule that applies to every module:

- Shared helpers (`RunTestPostgres`, `RunTestRedis`, …) and conformance suites live in `github.com/kartaladev/scrty/test`.
- No other scrty module imports that module, **not even from a `_test.go` file**. A test-only import still becomes a `go.mod` requirement, so the helpers' drivers and testcontainers would appear in every consumer's `go list -m all`. This is reproducible: a core `_test.go` importing a helper module that uses pgx adds `github.com/jackc/pgx/v5 // indirect` to the core `go.mod`, and pgx then shows up in a core-only consumer's module graph.
- Integration tests and conformance-suite runs that need those helpers live **inside** the `test` module, which imports the modules under test: core's `database/sql` adapters, core's in-memory defaults, and the `pgx` and `gorm` adapters.
- Consumers may import the `test` module freely from their own tests, to run the conformance suites against their own implementations.
- The layout guard (`layout_test.go` at the repository root) enforces this: it fails on any import of the test module from any file, and on any `go.mod` requirement on it.

## When *not* to use a container

These cases are out of scope and a real unit-test mock or fake is appropriate:

- The code under test only touches a single small struct method that happens to live on a repository — extract the logic, test it without the database.
- The test is exercising the *caller* of a service interface and the interface is small. Generate a [`mockgen`](../use-mockgen/SKILL.md) mock instead.
- The dependency is a remote SaaS with no container image (e.g., a third-party billing API). Mock the client interface; do not invent a fake container.

## Verification

After adding or modifying a testcontainer-backed test, confirm each of the following before considering the work done:

1. `go test -race ./...` from the module root passes. Race detector matters because container startup, cleanup, and the goroutines that drive them are all genuinely concurrent.
2. A deliberately-failing test (e.g., add a `t.Fatal("force")` temporarily) still terminates its container — check `docker ps` after the run is empty. Proves `t.Cleanup` is wired correctly.
3. Re-running the test back-to-back works without manual `docker rm`. Proves nothing leaks state between runs.
4. The helper is reachable from a `_test.go` in a *sibling* package (not just the module's own internal tests). Proves the file naming is right.
5. CI run time for the affected module hasn't regressed by more than the cost of one container start. If it has, the helper is being called per-case rather than per-suite — promote to `testify/suite`.
