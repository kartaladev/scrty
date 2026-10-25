# Design

## Context

See `proposal.md` (Why) for the two failures. What the code shows today, read on 2026-10-22:

- **The history scenarios share one database.** `TestIdentityStore_HistoryScenarios` (`test/pgxstore/identity_history_test.go`) calls `migratedIdentity(t)` once and runs its cases as parallel subtests against that one database.
  - Two cases, "a retire whose prune fails" outside and inside a caller's transaction, call `refuseHistoryDeletes`. It runs `CREATE FUNCTION` and `CREATE TRIGGER … BEFORE DELETE ON password_history`, and drops both in `t.Cleanup`.
  - The other cases run `RetirePassword` concurrently. Each `RetirePassword` is one transaction (or a savepoint inside the caller's) running `NewestHistory`, `InsertHistory`, then `PruneHistory` against `password_history` (`pgx/identity_history.go`).
  - A third case, "an unavailable table fails every call", issues stronger DDL in the same database. Four times, it opens a transaction, runs `ALTER TABLE password_history RENAME TO password_history_gone` (which takes `ACCESS EXCLUSIVE`), makes one store call that fails with 42P01, and rolls back. Each time, that transaction holds the strongest table lock there is while the other cases run.
  - The `sqlstore` and `gorm` packages have twins of the same test (`test/sqlstore/identity_history_test.go`, `test/gormstore/identity_history_test.go`). Both have the trigger cases and the rename case. The gorm twin's rename goes through `withGoneTable` in `test/gormstore/identity_test.go`. Only `pgxstore` has been seen failing.
- **PostgreSQL's lock modes.** `CREATE TRIGGER` takes `SHARE ROW EXCLUSIVE` on the table. `INSERT` and `DELETE` take `ROW EXCLUSIVE`. The two conflict in both directions, and `SHARE ROW EXCLUSIVE` is self-exclusive. The lock `DROP TRIGGER` takes is not stated on its reference page. Task 1.1 observed it: `ACCESS SHARE`, then an upgrade to `ACCESS EXCLUSIVE` (see Findings).

  A test's DDL in one subtest can therefore wait on, and be waited on by, another subtest's open `RetirePassword` transaction. The DDL is a trigger's `CREATE` or `DROP`, or the rename. That is the leading hypothesis for the cycle. It is a hypothesis, not a finding. Reading the statements does not show a complete cycle. A single lock upgrade inside one `RetirePassword` (`ACCESS SHARE` from `NewestHistory`, then `ROW EXCLUSIVE`) with DDL queued between is a case PostgreSQL's lock queue normally grants early rather than deadlocks on. A real cycle needs two sessions each holding a lock the other waits for, and only the server's deadlock report can name them.
- **The Redis fault cases share a warm-up.** In `TestRedisLimiter_Fault` (`test/redis_fault_test.go`), `cutOff` first calls `l.Exceeded` with `require.NoError`, "so the check below waits on a read rather than on a dial". Only then does it hang the server.
  - The control case builds a new client with `ContextTimeoutEnabled = false`, and a limiter on it with `WithOperationTimeout(hungTimeout)`, where `hungTimeout` is 250 ms.
  - The failure (`:182`, from `:244`) is that warm-up returning `ratelimit: backend unavailable` before the server is hung.
  - The leading hypothesis was that the first call on a fresh client (dial, handshake, first command) exceeded 250 ms on a host starved by `make check`. Task 3.1 reproduced it (see Findings).
  - The code seemed to show why only the control case would be exposed: every other `cutOff` case warms up a limiter over `e.conn.Client`, which the helpers have already used, so its pool was expected to hold a connection. Task 3.1 refuted this. `e.conn.Client`'s pool is empty at the warm-up too, and the hung-server case fails the same way (see Findings).
  - The control's premise is that, with `ContextTimeoutEnabled = false`, go-redis does not cut a read at the context's deadline. Something did cut the warm-up at that deadline. That fits go-redis still bounding the dial and the pool wait by the context whatever that option says. Task 3.1 confirmed this for go-redis v9.22.0, from its source and from the timing (see Findings).
- **What `main` changed since this change was proposed** (`77bd795..31512e3`, read on 2026-10-25):
  - None of the files above changed: the three history tests, the history store code in all three drivers, `internal/pgschema/identity.go`, the Redis fault test and its helpers, the `redis` module, and the `Makefile`.
  - Store-owned transactions now begin with an explicit `READ COMMITTED`, and a caller's transaction is checked to run no stronger (`pre-release-hardening`). The server already defaulted to `READ COMMITTED`, so `RetirePassword` takes the same table locks as before. A `40P01` comes from lock order, not isolation, so this neither explains nor removes the deadlock.
  - The `test` module grew by about 5,000 lines, including new parallel isolation suites on all three drivers. The gate loads the shared host more than when either failure was seen.
- **Earlier sightings and neighbouring hypotheses.**
  - The Redis control case failed its warm-up once before, on 2026-10-04, in about ten full local runs during `testcontainers-optimize`. It passed alone, and that design recorded it `UNREPRODUCED`.
  - The `first-party-sessions` design records a separate `UNREPRODUCED` hypothesis: user-wide session deletes lock rows in scan order, so they could deadlock with a re-rotation. That involves different tables and statements. If this change's reproduction runs catch it, it goes in the findings as an unrelated failure, under decision 4.
- **The gate's shape.** It was settled in `testcontainers-optimize`: `make check` runs `go test -race -count=1 ./...` per module. The `test` module's packages run at the same time on one Docker host (4 vCPU in CI), with `-p` and `-parallel` at their defaults. The one test that cannot hold under that load, `TestPGLimiter_PruneUnderRecords`, skips there and runs alone in `test-isolated`.

## Goals / Non-Goals

**Goals:**
- Each failure reproduced on demand and classified with evidence, before anything is changed.
- Each fixed at its cause, with the shared pattern fixed wherever it recurs.
- The full gate green repeatedly, as the acceptance test.

**Non-Goals:**
- A general sweep for other load-sensitive tests. Any found along the way are listed in this design's findings and proposed as their own change, not fixed here. The exception is a fault on the code path this change already fixes, found while verifying the fix: the twins' silent cleanup and the `hang` probe's budget (decision 2). Those are fixed here, because leaving them would leave the fixed test able to hide its failure or fail its own verification.
- Changing `make check`'s concurrency, or retrying failed tests automatically (no `-failfast`/rerun wrappers, no `t.Skip` on a timing failure).

## Decisions

### 1. Reproduce before deciding, and capture the database's own account of the deadlock

The first task for each failure is a reproduction that fails on demand. Rerunning `make check` until it happens is not one.

- **Deadlock.**
  - Run the history scenarios repeatedly under load: high `-count`, `-parallel` raised for the package, and the `sqlstore`/`gormstore`/`pgxstore` packages together. Do this on PostgreSQL 18 and 15.
  - Capture the deadlock's `DETAIL`: the processes, the lock each waits for, and which process holds it. PostgreSQL sends this with the error, and pgx exposes it as `*pgconn.PgError` `Detail`. Task 1.1 found the client gets the cycle without the statements, and only the server log names them (see Findings).
  - Turn on `log_lock_waits` for the reproduction run, so the waits leading up to the cycle are in the server log.
  - The statements in the cycle decide the classification:
    - **Test defect:** the cycle involves DDL the test issues: a trigger's `CREATE` or `DROP`, or the rename in "an unavailable table fails every call". The rule names every test-issued DDL, not only the trigger, so a cycle through the rename is not misfiled.
    - **Product defect:** two `RetirePassword` transactions deadlock with no DDL involved. A store operation that can deadlock with itself under concurrent use is a product defect, whatever the test does.
- **Redis.**
  - Reproduce with the host loaded the way `make check` loads it: the `test` module's packages running together. Then try a targeted variant, the control case alone with CPU contention (`GOMAXPROCS=1` or a busy-loop neighbour).
  - Record which call fails (the warm-up `Exceeded`, the hung check, or the build) and how long it took, and whether the client's pool had a connection before the call.
  - **Test defect:** the warm-up ran under the 250 ms budget meant for the hung check.
  - **Product defect:** a healthy server is answered `backend unavailable` while the call is well inside its operation timeout, for example a breaker opened by an earlier case's state leaking into a new limiter.
- **Alternative rejected:** fixing on the leading hypotheses straight away. A fix that happens to make the failure rarer would pass review and the gate while the cause stayed. `defect-claims.md` asks for a failing test, and this is that test.

### 2. A test defect is fixed in the test's isolation or budget, never by hiding the failure

**Deadlock (if test-issued DDL is the cause).** Every case that issues DDL on `password_history` must not share a database with concurrently running cases. That is the two cases that install the delete-refusing trigger, and the rename case "an unavailable table fails every call". The isolated set is all three, whichever one the captured cycle names. Isolating only the one the report names would leave the others able to form the next cycle, and would make the failure rarer rather than gone, which is the outcome decision 1 exists to rule out. In order of preference:
1. give each of those cases a database of its own (`migratedIdentity` per case, as `test-provisioning`'s "Every PostgreSQL call gets a database of its own" already allows);
2. run them sequentially, outside the parallel group;
3. refuse deletes by a means that takes no table lock against other sessions. This covers only the trigger cases; the rename needs 1 or 2.

The `sqlstore` and `gorm` twins get the same fix, since they share the pattern even though they have not been seen failing.

The twins' trigger cleanup also stops discarding its errors, and checks them the way the `pgx` case does. A discarded cleanup error is why the twins' deadlocks went unseen (see Findings). With the isolation in place, a cleanup failure has no expected cause, so one that happens must fail the test rather than leave a trigger behind.

**Redis (if the warm-up's budget is the cause).** The warm-up proves only that a pooled connection exists, and that the limiter's first-call work is done. It runs on a second limiter over the same client, built without the 250 ms hung-check budget, so it fills the pool the hung check will draw from without spending that budget. Keep `hungTimeout` for the measured call only. Every case using `cutOff` benefits. The hung-check assertions (the cut-off happens within `hungTimeout + hungMargin`, and the control is not cut off) are not loosened.

The `hang` helper's probe, which waits for the server to stop answering once `DEBUG SLEEP` is sent, is a setup step too. Its wait is sized for setup rather than for an idle host: long enough for a starved scheduler to start the sleep, and short enough that the remaining sleep (`hungFor`, 5 s) still covers the measured call, including the control's wait of more than a second. That wait is not an assertion about the limiter, so lengthening it loosens nothing the test exists to check.

- **Alternative rejected: a bare `PING` for the warm-up**, which decision 2 first preferred. The limiter's first call on a server also loads its script (`RunRO`). A `PING` leaves that undone, so the work would fall into the measured call and change what it measures. A warm-up `Exceeded` on a second limiter over the same client, built without `WithOperationTimeout(hungTimeout)`, fills the pool and loads the script.

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
  - For the deadlock, per-case databases remove the contention the reproduction depends on, so the 200 green runs are guaranteed by construction. The evidence that counts is the captured cycle: it names test-issued DDL, and the fix removes every test-issued DDL from the shared database. The findings say so, so a reviewer reads the green runs as confirmation, not as luck.
- **The whole gate:** five consecutive `make check` runs green on PostgreSQL 18, and the `test` module green on PostgreSQL 15.
- **Unrelated failures:** a failure elsewhere during those runs is recorded with its output and proposed separately. It does not count against this change, and is never silently rerun away.

## Findings

### History deadlock (tasks 1.1, 1.2): REPRODUCED, test defect

- **Reproduction**, run on 2026-10-24/25 against PostgreSQL 18.6 and 15.19 servers started with `log_lock_waits=on` and `deadlock_timeout=1s`, reached through `SCRTY_TEST_POSTGRES_SERVERS`. The three packages shared one server rather than one each, which does not change a deadlock, since deadlocks are per database.
  - `go test -race -count=50 -parallel 16 -run TestIdentityStore_HistoryScenarios ./pgxstore/ ./sqlstore/ ./gormstore/` on the unmodified tree, PostgreSQL 18: 415 s, `pgxstore` red, 3 deadlocks in the server log (1 pgx, 2 `sqlstore`). The same on PostgreSQL 15: 195 s, green, 2 deadlocks (`sqlstore`, gorm).
  - The same command against a copy instrumented to log the client error, PostgreSQL 18: 4 `pgxstore` subtests red, 12 deadlocks spread evenly over the three drivers.
  - The `sqlstore` and gorm twins alone, under load (`-cpu 1,2 -count=100` beside 12 busy loops): 4 deadlocks on 18 and 2 on 15, both runs green. Under light load: none.
  - All three DDL-issuing cases removed (both trigger cases and the rename case), light load and the same heavy load, both versions: no deadlock and no lock wait.
- **The failing lines** (`test/pgxstore/identity_history_test.go`, case "a retire whose prune fails, outside a caller's transaction, keeps no new entry"; line numbers as before the fix, now `:415` and `:417`): `:404`, the `assert.NoError` on `DROP TRIGGER` in `refuseHistoryDeletes`' `t.Cleanup`, with `ERROR: deadlock detected (SQLSTATE 40P01)`. Then `:406` on `DROP FUNCTION`, `cannot drop function … because other objects depend on it (SQLSTATE 2BP01)`, since the trigger is still there. No `RetirePassword` call fails.
- **The cycle, in PostgreSQL's words** (PostgreSQL 18):
  ```
  Process 981 waits for AccessExclusiveLock on relation 16793 of database 17133; blocked by process 983.
  Process 983 waits for AccessExclusiveLock on relation 16793 of database 17133; blocked by process 981.
  Process 981: DROP TRIGGER refuse_history_delete_… ON password_history
  Process 983: DROP TRIGGER refuse_history_delete_… ON password_history
  ```
  Every deadlock captured in every run has this shape: the cleanups of the two trigger cases ("…prune fails, outside…" and "…inside…"), each dropping its own trigger on the shared `password_history`. The twins' cycles are the same with `DROP TRIGGER IF EXISTS`. No cycle contains `RetirePassword`, `CREATE TRIGGER` or the rename; those produced lock waits of one to three seconds and nothing more.
- **The lock `DROP TRIGGER` takes** is now observed rather than assumed, on both versions: it holds `ACCESS SHARE` on the table, then waits to upgrade to `ACCESS EXCLUSIVE` (seen in `pg_locks` on a blocked drop). Two drops on one table each hold the lock the other's upgrade waits for. A probe with no DML at all, four sessions each creating and dropping a trigger on one table 300 times, deadlocks the same way.
- **Where the detail arrives:** both, with different content. The client's `*pgconn.PgError` carries `Code 40P01` and a `Detail` with the "Process … waits for … blocked by …" lines, but no statements; its `Hint` points to the server log. Only the server log names the statements.
- **Why only `pgxstore` was ever seen failing:** the twins deadlock just as often, but their cleanup discards the error of `DROP TRIGGER IF EXISTS` and of the following `DROP FUNCTION IF EXISTS`. The trigger and function are left in the database until the database is dropped, and the test stays green.
- **Classification: test defect.** The cycle is test-issued DDL only, and removing the DDL-issuing cases removes every deadlock and every lock wait, so nothing points to a product defect in `RetirePassword`. Decision 2's fix applies unchanged to all three drivers. Per decision 4, once the two trigger cases each have a database of their own, no two `DROP TRIGGER`s can share a table, so the 200 green runs task 2.1 asks for are certain by construction. The evidence is the cycle above, and the green runs confirm it. The rename case is in no cycle, and is isolated anyway, for the reason decision 2 gives.
- **The twins' cleanup (task 2.2)**: in a scratch copy with the twins' trigger cases back on the shared database, under the 1.1 load, the old cleanup ran green with a deadlock in the server log (PostgreSQL 18). The checked cleanup ran red on PostgreSQL 15, with `ERROR: deadlock detected (SQLSTATE 40P01)` reported from the cleanup in both twins. The same run on 18 had no deadlock, so it was not counted as red. On the tree, 200 runs passed on 18 and 15 with no deadlock in either server log. No single version showed both halves of the red step, the old cleanup green with a deadlock and the checked one red. Each half was seen on one version, and the reproduction is intermittent on both.
- **The `pgx` 200-run check, logged**: task 2.1's 200 runs were reported without the count in their logs. They were rerun at `2b45bbf` with `-race -count=200 -parallel 16 -run TestIdentityStore_HistoryScenarios ./pgxstore/` and passed on 18 (54 s) and 15 (51 s). Because the `pgx` cleanup checks its errors, a deadlock there fails the run.
- **The same pattern outside this change**: `test/sqlstore/session_supersede_test.go:136` and `test/gormstore/session_supersede_test.go:137` drop a trigger on `sessions` with the error discarded. No failure has been seen there, and whether their trigger cases share a database with concurrent DDL has not been checked. Under the non-goals, it is listed here and proposed as its own change.
- **Unrelated failure seen**: in the first PostgreSQL 18 run, `pgxstore` and `sqlstore` each failed once at teardown: `testutils.go:938: roll back migrations securitystate: partial migration error (…20261021000000): timeout: context deadline exceeded`. The 30 s teardown budget ran out at the end of the slowest run, with no lock wait over one second outside `password_history`. It did not recur. It is `UNREPRODUCED`, and is proposed as its own change only if it recurs in task 5.1's gate runs (decision 4).

### Redis fault failure (tasks 3.1, 3.2): REPRODUCED, test defect

- **Reproduction**, run on 2026-10-25 against an instrumented copy outside the tree. The instrumentation logs, for each step in `cutOff`, the duration, the error, `errors.Is(err, context.DeadlineExceeded)` and the client's `PoolStats()`.
  - Under `make check`-like load (a loop of `go test -race -count=1 ./...` in `test`, plus a concurrent PostgreSQL stress run on the same Docker host): `-test.count=10 -test.run 'TestRedisLimiter_Fault/(control:_a_client|a_hung)'`, four complete iterations, all red. 24 of 79 warm-ups failed: 9 of 39 in the control case and 15 of 40 in "a hung server is cut off at the operation timeout, and the breaker opens".
  - Under CPU contention alone (`GOMAXPROCS=1` and 14 busy-loop neighbours, `-test.count=10`): 4 of 10 failed in each of the two cases.
- **The failing call is always the warm-up `Exceeded`**, never the hung check or the build. It returns `ratelimit: backend unavailable` at the warm-up's `require.NoError` (`:182` in the tree), with `deadlineExceeded=true`, after 250.6 to 737 ms, most at 251 to 254 ms, which is `hungTimeout` itself. The pool was empty before every failing warm-up (`TotalConns 0, IdleConns 0`), on the control's fresh client and on `e.conn.Client` alike. Whenever the warm-up passed, the hung check behaved as specified: cut off at about 250 ms with `ErrBackendUnavailable` in the hung case, and not cut off (4.6 to 5 s, no error) in the control.
- **go-redis v9.22.0 bounds connection acquisition by the caller's context whatever `ContextTimeoutEnabled` says.** That option only switches the read and write deadlines to a background context (`redis.go:1469`). `withConn` gets the connection with the caller's context (`redis.go:1073`, `:511`). The pool's turn wait returns `ctx.Err()` (`internal/pool/pool.go:1164-1170`, `:1228`), and the dial is capped by the context's deadline (`internal/pool/pool.go:721-724`, `:740`). This settles the Context's unverified point. It is not a defect: the control's premise concerns reads, and the hung check reads on an established connection.
- **Classification: test defect.** The warm-up spends the 250 ms budget meant for the hung check on dialling a connection, and fails whenever a starved host makes the dial or handshake slower than that. The server was healthy, the deadline was the test's own, and no state leaked between limiters. Decision 2's Redis fix applies unchanged, and it must cover every `cutOff` case, not only the control, which is what task 4.1 already says.
- **After the warm-up fix (task 4.1)**: the 3.1 load no longer reproduced the failure on this host, so the red step used a harsher one: `GOMAXPROCS=1`, 40 busy loops, and 4 concurrent copies of the test binary, each run as `-test.count=10 -test.run 'TestRedisLimiter_Fault/(control:_a_client|a_hung)'`. Before the fix, 3 of the 4 copies failed at the warm-up (`:182`). After it, 4 copies at `-test.count=50` (200 runs) showed no warm-up failure. One run failed in a different setup step: the `hang` probe's `require.Eventually` (`:76`, "the server kept answering"), whose 1 s budget ran out before `DEBUG SLEEP` took hold. That is the same fault as the warm-up's, a setup step bounded by a budget sized for an idle host, on a path every `cutOff` case takes. It is fixed here under decision 2. It was seen once, so it is `UNREPRODUCED` as a separate defect, and the fix rests on the reading of the code.
- **After the probe fix**: under the same harsher load, 4 copies at `-test.count=50` (200 runs) passed with no failure in any step. The task 4.2 review notes that the warm-up limiter keeps the suite's `faultTimeout` (2 s). It is outside the 250 ms hung-check budget, not unbounded, so a dial slower than 2 s would still fail it. That is eight times the old margin, and the review judged it non-blocking. A `-count=5` run of the whole `TestRedisLimiter_Fault` after the probe fix passed.
- **A remaining setup budget, `UNREPRODUCED`**: the whole-change review notes that the probe's own `ReadTimeout` (20 ms) is sized for an idle host too. On a starved host, a `PING` to a server still answering could time out, so the probe would report the sleep begun before it has, and the measured call would find a live server. That has not been seen: 400 runs under the harsher load and 6 gate runs passed. It is listed here and proposed as its own change if it is ever seen, under the non-goals.
- **Unrelated failures seen in the load runs**, both under the extra load of a concurrent PostgreSQL stress run, so not counted against the gate and not yet proposed: `TestKeycloak` failed to start its container (`context deadline exceeded` after 315 s), and `TestPGLimiter_HeldRow/pgx/record gives up on a held row within its timeout` failed once (14 s, not investigated). Both are `UNREPRODUCED` as defects. If either recurs in task 5.1's gate runs, it is recorded there with its output and proposed as its own change (decision 4).

### Gate (task 5.1)

Run on 2026-10-25 at `2b45bbf`, with no other load on the host: five consecutive `make check` runs on PostgreSQL 18 (exit 0 each, 287 to 332 s, 56 packages `ok`, no `FAIL`), then `(cd test && SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine go test -race -count=1 ./...)` (exit 0, 203 s, no `FAIL`). None of the unrelated failures seen during the reproduction runs (`TestKeycloak`'s container start, `TestPGLimiter_HeldRow`, the migration rollback's teardown timeout) recurred, so none is proposed as its own change. They stay `UNREPRODUCED`. The `session_supersede_test.go` cleanup pattern listed under the history findings is still proposed separately, since it is a gap rather than a failure.

## Risks / Trade-offs

- **The failure will not reproduce on demand** → widen the load (packages together, `-cpu 1,2`, a CPU-bound neighbour). If it still will not reproduce after a bounded effort (about an hour of runs, recorded), record the attempt and its runs, keep the claim `UNREPRODUCED`, and apply only a change justified independently by decision 2. For the fixture, that is isolation, which is correct regardless. Then add the evidence-gathering hook (logging the deadlock `DETAIL` on failure) so the next occurrence carries its own cause.
- **Per-case databases slow the history tests** → the cost is one migrated database per isolated case, which the shared-server helper keeps small. Only the three DDL-issuing cases need it, in each of the three drivers.
- **A product deadlock in `RetirePassword` would change a store's transaction shape** → that is decision 3's spec-first path, run on all three drivers on PostgreSQL 15 and 18.

## Migration Plan

None. These are test changes, and any product change goes through decision 3.

## References

**Primary documentation:**
- [PostgreSQL: Explicit Locking, table-level locks](https://www.postgresql.org/docs/current/explicit-locking.html), accessed 2026-10-22: `CREATE TRIGGER` takes `SHARE ROW EXCLUSIVE`; `INSERT`, `UPDATE`, `DELETE` take `ROW EXCLUSIVE`; the two conflict in both directions; deadlocks are detected and one transaction aborted, and which one "should not be relied upon" (Context, decision 1).
- [PostgreSQL: DROP TRIGGER](https://www.postgresql.org/docs/current/sql-droptrigger.html), accessed 2026-10-22: does not state the lock it takes. Task 1.1 observed it in `pg_locks` instead (Findings).
- [PostgreSQL: Error Reporting and Logging, `log_lock_waits`](https://www.postgresql.org/docs/current/runtime-config-logging.html), accessed 2026-10-22: logs a wait longer than `deadlock_timeout`; off by default (decision 1).

Decisions 2 to 4 are reasoned from scrty's own settled specs (`test-provisioning`, `store-conformance`), the archived `testcontainers-optimize` design, and the project rules (`defect-claims.md`, `golang-tdd.md`).

The Context's earlier sightings and the review of `main` come from scrty's own history (read on 2026-10-25): the archived `testcontainers-optimize` design (the 2026-10-04 Redis sighting), the archived `first-party-sessions` design (the session-delete lock-order hypothesis), and `git diff 77bd795..31512e3` over the files the Context names. 

**Researched:**
- [go-redis v9.22.0 source](https://github.com/redis/go-redis/tree/v9.22.0), read from the Go module cache on 2026-10-25 (tag confirmed on the repository the same day): `ContextTimeoutEnabled` only selects the context for read and write deadlines (`redis.go:1469`). Connection acquisition and the dial use the caller's context (`redis.go:1073`, `:511`; `internal/pool/pool.go:721-724`, `:740`, `:1164-1170`, `:1228`). This supports the Redis findings and decision 2's warm-up.
