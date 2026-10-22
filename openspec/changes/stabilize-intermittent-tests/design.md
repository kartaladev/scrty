# Design

## Context

See `proposal.md` (Why) for the two failures. What the code shows today, read on 2026-10-22:

- **The history scenarios share one database.** `TestIdentityStore_HistoryScenarios` (`test/pgxstore/identity_history_test.go`) calls `migratedIdentity(t)` once and runs its cases as parallel subtests against that one database.
  - Two cases, "a retire whose prune fails" outside and inside a caller's transaction, call `refuseHistoryDeletes`. It runs `CREATE FUNCTION` and `CREATE TRIGGER … BEFORE DELETE ON password_history`, and drops both in `t.Cleanup`.
  - The other cases run `RetirePassword` concurrently. Each `RetirePassword` is one transaction (or a savepoint inside the caller's) running `NewestHistory`, `InsertHistory`, then `PruneHistory` against `password_history` (`pgx/identity_history.go`).
  - The `sqlstore` and `gorm` packages have twins of the same test (`test/sqlstore/identity_history_test.go`, `test/gormstore/identity_history_test.go`). Only `pgxstore` has been seen failing.
- **PostgreSQL's lock modes.** `CREATE TRIGGER` takes `SHARE ROW EXCLUSIVE` on the table. `INSERT` and `DELETE` take `ROW EXCLUSIVE`. The two conflict in both directions, and `SHARE ROW EXCLUSIVE` is self-exclusive. The lock `DROP TRIGGER` takes is not stated on its reference page; `ACCESS EXCLUSIVE` is commonly assumed, which is **unverified** here.

  A trigger's DDL in one subtest can therefore wait on, and be waited on by, another subtest's open `RetirePassword` transaction. That is the leading hypothesis for the cycle. It is a hypothesis, not a finding.
- **The Redis fault cases share a warm-up.** In `TestRedisLimiter_Fault` (`test/redis_fault_test.go`), `cutOff` first calls `l.Exceeded` with `require.NoError`, "so the check below waits on a read rather than on a dial". Only then does it hang the server.
  - The control case builds a new client with `ContextTimeoutEnabled = false`, and a limiter on it with `WithOperationTimeout(hungTimeout)`, where `hungTimeout` is 250 ms.
  - The failure (`:182`, from `:244`) is that warm-up returning `ratelimit: backend unavailable` before the server is hung.
  - The leading hypothesis is that the first call on a fresh client (dial, handshake, first command) exceeded 250 ms on a host starved by `make check`. That too is unverified.
- **The gate's shape.** It was settled in `testcontainers-optimize`: `make check` runs `go test -race -count=1 ./...` per module. The `test` module's packages run at the same time on one Docker host (4 vCPU in CI), with `-p` and `-parallel` at their defaults. The one test that cannot hold under that load, `TestPGLimiter_PruneUnderRecords`, skips there and runs alone in `test-isolated`.

## Goals / Non-Goals

**Goals:**
- Each failure reproduced on demand and classified with evidence, before anything is changed.
- Each fixed at its cause, with the shared pattern fixed wherever it recurs.
- The full gate green repeatedly, as the acceptance test.

**Non-Goals:**
- A general sweep for other load-sensitive tests. Any found along the way are listed in this design's findings and proposed as their own change, not fixed here.
- Changing `make check`'s concurrency, or retrying failed tests automatically (no `-failfast`/rerun wrappers, no `t.Skip` on a timing failure).

## Decisions

### 1. Reproduce before deciding, and capture the database's own account of the deadlock

The first task for each failure is a reproduction that fails on demand. Rerunning `make check` until it happens is not one.

- **Deadlock.**
  - Run the history scenarios repeatedly under load: high `-count`, `-parallel` raised for the package, and the `sqlstore`/`gormstore`/`pgxstore` packages together. Do this on PostgreSQL 18 and 15.
  - Capture the deadlock's `DETAIL`: the processes, the lock each waits for, and which process holds it. PostgreSQL sends this with the error, and pgx exposes it as `*pgconn.PgError` `Detail` (**unverified**: the first reproduction confirms where the text arrives).
  - Turn on `log_lock_waits` for the reproduction run, so the waits leading up to the cycle are in the server log.
  - The statements in the cycle decide the classification:
    - **Test defect:** the cycle involves the fixture's trigger DDL.
    - **Product defect:** two `RetirePassword` transactions deadlock with no DDL involved. A store operation that can deadlock with itself under concurrent use is a product defect, whatever the test does.
- **Redis.**
  - Reproduce with the host loaded the way `make check` loads it: the `test` module's packages running together. Then try a targeted variant, the control case alone with CPU contention (`GOMAXPROCS=1` or a busy-loop neighbour).
  - Record which call fails (the warm-up `Exceeded`, the hung check, or the build) and how long it took.
  - **Test defect:** the warm-up ran under the 250 ms budget meant for the hung check.
  - **Product defect:** a healthy server is answered `backend unavailable` while the call is well inside its operation timeout, for example a breaker opened by an earlier case's state leaking into a new limiter.
- **Alternative rejected:** fixing on the leading hypotheses straight away. A fix that happens to make the failure rarer would pass review and the gate while the cause stayed. `defect-claims.md` asks for a failing test, and this is that test.

### 2. A test defect is fixed in the test's isolation or budget, never by hiding the failure

**Deadlock (if the fixture is the cause).** The cases that install a schema-wide trigger must not share a database with concurrently running cases. In order of preference:
1. give those cases a database of their own (`migratedIdentity` per case, as `test-provisioning`'s "Every PostgreSQL call gets a database of its own" already allows);
2. run them sequentially, outside the parallel group;
3. refuse deletes by a means that takes no table lock against other sessions.

The `sqlstore` and `gorm` twins get the same fix, since they share the pattern even though they have not been seen failing.

**Redis (if the warm-up's budget is the cause).** The warm-up proves only that a pooled connection exists. Run it on a limiter or call without the 250 ms hung-check budget: either a separate limiter on the same client for the warm-up, or a warm-up through the client itself (`PING`). Keep `hungTimeout` for the measured call only. Every case using `cutOff` benefits. The hung-check assertions (the cut-off happens within `hungTimeout + hungMargin`, and the control is not cut off) are not loosened.

- **Alternative rejected: moving either test to `test-isolated`.** That is reserved for a test that measures something load itself distorts, as the prune measurement does. It is used here only if decision 1's evidence shows neither fix can hold, and the design records why.
- **Alternative rejected: raising timeouts across the board.** It weakens the cut-off assertions, which are the point of the fault test.

### 3. A product defect goes through the spec first

If decision 1 classifies either failure as a product defect, implementation stops, and the main session updates the change:
- removes `skip_specs`;
- adds a delta to `default-identity-store` or `rate-limiting`, with the scenario the reproduction shows;
- updates `tasks.md` and `plans.md`.

Only then is the fix written test-first, with the reproduction as its red step. A product fix keeps the established design unless that design is the defect. In that case the departure is recorded here, as `legacy-reference.md` requires.

### 4. Acceptance is the gate, repeated

- **Each fixed test:** green 200 times under the reproduction's load, where before the fix it failed in that same setup.
- **The whole gate:** five consecutive `make check` runs green on PostgreSQL 18, and the `test` module green on PostgreSQL 15.
- **Unrelated failures:** a failure elsewhere during those runs is recorded with its output and proposed separately. It does not count against this change, and is never silently rerun away.

## Risks / Trade-offs

- **The failure will not reproduce on demand** → widen the load (packages together, `-cpu 1,2`, a CPU-bound neighbour). If it still will not reproduce after a bounded effort (about an hour of runs, recorded), record the attempt and its runs, keep the claim `UNREPRODUCED`, and apply only a change justified independently by decision 2. For the fixture, that is isolation, which is correct regardless. Then add the evidence-gathering hook (logging the deadlock `DETAIL` on failure) so the next occurrence carries its own cause.
- **Per-case databases slow the history tests** → the cost is one migrated database per isolated case, which the shared-server helper keeps small. Only the trigger-installing cases need it.
- **A product deadlock in `RetirePassword` would change a store's transaction shape** → that is decision 3's spec-first path, run on all three drivers on PostgreSQL 15 and 18.

## Migration Plan

None. These are test changes, and any product change goes through decision 3.

## References

**Primary documentation:**
- [PostgreSQL: Explicit Locking, table-level locks](https://www.postgresql.org/docs/current/explicit-locking.html), accessed 2026-10-22: `CREATE TRIGGER` takes `SHARE ROW EXCLUSIVE`; `INSERT`, `UPDATE`, `DELETE` take `ROW EXCLUSIVE`; the two conflict in both directions; deadlocks are detected and one transaction aborted, and which one "should not be relied upon" (Context, decision 1).
- [PostgreSQL: DROP TRIGGER](https://www.postgresql.org/docs/current/sql-droptrigger.html), accessed 2026-10-22: does not state the lock it takes, so the Context labels that unverified.
- [PostgreSQL: Error Reporting and Logging, `log_lock_waits`](https://www.postgresql.org/docs/current/runtime-config-logging.html), accessed 2026-10-22: logs a wait longer than `deadlock_timeout`; off by default (decision 1).

Decisions 2 to 4 are reasoned from scrty's own settled specs (`test-provisioning`, `store-conformance`), the archived `testcontainers-optimize` design, and the project rules (`defect-claims.md`, `golang-tdd.md`).
