# Minimize Test Containers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session does not write Go code: each code dispatch below goes to one implementer, followed by the main session's verification and a fresh reviewer (`.claude/rules/subagent-delegation.md`). Tasks 1.1, 1.2, 5.6 and 6.x are the main session's own work: measurement, OpenSpec and skill documents, the gate. The main session commits.

**Goal:** Remove the `test` module's servers of a test's own that exist only to stage an outage or carry a fixed configuration. Every test and assertion is kept, and one real outage per backend stays.

**Architecture:**
- **The proxy.** An in-process TCP proxy (`outageProxy`), standard library only, sits in front of a shared server's mapped address. Its stop, hang and start modes stage outages for one call only.
- **The PostgreSQL and Redis helpers.** Each gains an option that routes a call through such a proxy. `Stop`, `Start` and a new `Hang` act on the proxy. The proxy is started again before the call's teardown.
- **The Redis registry.** It is keyed by image and start-up flags, so calls with identical flags share a server, each on its own logical database.

**Tech Stack:** Go 1.27, `net`, testcontainers-go v0.44 (`modules/postgres`, `modules/redis`), pgx v5 stdlib, go-redis v9, testify, goleak.

**Spec:**
- `openspec/changes/minimize-test-containers/proposal.md`
- `openspec/changes/minimize-test-containers/design.md`, decisions D1–D7
- `openspec/changes/minimize-test-containers/specs/test-provisioning/spec.md`
- `openspec/changes/minimize-test-containers/tasks.md`; every task below names its task number.

## Global Constraints

- **Precondition:** no dispatch starts before task 1.1 is done. `stabilize-intermittent-tests` must have classified `TestRedisLimiter_Fault` and landed its fix.
- **Test-first for every code task.** Write the failing test, run it focused, and confirm it fails for the intended reason. A compile error is not a red step: land the API shape with a stub that does nothing first (`.claude/rules/golang-tdd.md`). For a rewritten existing test, the red step is breaking what it guards temporarily, as tasks.md's preamble says.
- **Table tests** use the `assert` closure form, a `ctx` modifier where context matters, and `t.Context()` (`.claude/skills/table-test`).
- **Containers** come only from the `test` module's helpers (`.claude/skills/use-testcontainers`). The proxy itself is tested with no container.
- **No new dependency.** The proxy uses only the standard library (D1).
- **Defaults unchanged:** with no new option, every helper behaves exactly as today. The one exception is D5's `WithTestRedisServerArgs` without `WithTestRedisOwnContainer`, which used to be refused.
- **Refusals fail at the call, before any container starts** (`library-design.md` rule 6). Each error message names the options involved.
- **Defect claims** follow `.claude/rules/defect-claims.md`: a reviewer's claim needs a failing test or the label `UNREPRODUCED`.
- **Agents never run** `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.
- **Verification commands** run from `test/`: `go test -race -count=1 -run '<pattern>' .`, `go vet ./...`, `gofmt -l .`.

## Review Focus

1. **A proxy closed while a copy is blocked**, in hang or mid-transfer: no goroutine may outlive `Close`. Pinned in task 2.1's leak test.
2. **Stop during a large transfer:** the client's read ends with an error, never a hang or truncated success. Pinned in task 2.1.
3. **Mode changes in every order, from several goroutines:** hang then start without stop, stop while hung, start twice. No race and no deadlock under `-race`. Pinned in tasks 2.2 and 2.3.
4. **A late answer after hang:** a request that timed out while hung must not have its answer delivered to the next request on the same client or pool once started. Pinned in task 3.1 (pgx) and task 4.2 (go-redis).
5. **A test that fails mid-outage** (`t.Fatal` while hung): teardown still restores the proxy and removes the database. Pinned in task 3.2.

---

## Dispatch map

| Dispatch | Tasks | Owns (writes) | Model | Why that model | Runs |
|---|---|---|---|---|---|
| A: proxy | 2.1–2.3 | `test/testutils_outage.go`, `test/testutils_outage_test.go` | Opus | Concurrency: connection tracking, pausing and resuming copies, closing under races | first |
| B: PostgreSQL option | 3.1–3.5 | `test/testutils.go` (PostgreSQL sections, `testConfig`), `test/testutils_pgserver.go`, `test/testutils_postgres_test.go` | Opus | Teardown ordering, and an interface the move dispatches compile against | after A |
| C: Redis option and registry | 4.1–4.4 | `test/testutils.go` (Redis sections), `test/redis_testutils_test.go` | Sonnet | Extends the existing registry and option pattern; the proxy is already built and reviewed | after B (same file) |
| D: spike | 5.1 | nothing in the tree; scratch only | Opus | Interpreting driver errors decides which cases stay real; a wrong reading passes every test | after C |
| E: PostgreSQL moves | 5.2, 5.3 | `test/pg_ratelimit_fault_test.go`, `test/pg_ratelimit_test.go` | Sonnet | Applies a decided pattern, with D's list of cases that stay real | after D, parallel with F and G |
| F: Redis fault move | 5.4 | `test/redis_fault_test.go` | Opus | The hung-server cases and their timing are the flake's history; their outcome is timing-sensitive | after D, parallel with E and G |
| G: Redis verify move | 5.5 | `test/redis_verify_test.go` | Sonnet | Option swap plus ACL users scoped to the call | after D, parallel with E and F |

B and C both write `test/testutils.go`, so they run in order and never at once. E, F and G write disjoint files. F only reads `logRecorder` from `redis_verify_test.go`, and G must keep its signature unchanged. After each dispatch, the main session runs the verification commands and then a fresh reviewer on the same model checks the diff against the requirements it covers.

---

### Task 1.1: Precondition (main session)

- [ ] **Step 1:** Read `stabilize-intermittent-tests`'s design for the `TestRedisLimiter_Fault` classification, and confirm its fix is on the branch with `git log --oneline -- test/redis_fault_test.go`.
- [ ] **Step 2:** Add its finding to design.md under Risks, stating whether the hung-server control case may move to the proxy.
- [ ] **Step 3:** Commit: `docs(openspec): record the fault-test finding minimize-test-containers builds on`.

### Task 1.2: Baseline (main session)

- [ ] **Step 1:** Stop every unrelated container on the Docker host, and confirm with `docker ps` that the list is empty.
- [ ] **Step 2:** In `test/`, run `go test -race -count=1 -json ./... > before.json` while `docker events --filter type=container --filter event=start --format '{{.Actor.Attributes.image}}'` records starts. Then run each of `.`, `./sqlstore`, `./pgxstore`, `./gormstore` and `./crossbackend` alone the same way.
- [ ] **Step 3:** Attribute the root package's own servers to tests. Run `go test -race -count=1 -v -run '<Test>' .` for each test named in design.md's Context, and count the starts each run makes.
- [ ] **Step 4:** Record in design.md D6 under "Before":
  - starts by package and image;
  - wall times in the full run and alone;
  - passed and skipped counts from `before.json`;
  - the per-test attribution.
- [ ] **Step 5:** Commit: `docs(openspec): record the container baseline`.

---

### Task 2.1: Proxy stop and start (dispatch A)

**Files:**
- Create: `test/testutils_outage.go`
- Test: `test/testutils_outage_test.go`

**Interfaces:**
- Produces:
  - `type outageProxy struct` (unexported)
  - `func newOutageProxy(upstream string) (*outageProxy, error)`: listens on `127.0.0.1:0` and forwards each accepted connection to `upstream`
  - `func (p *outageProxy) Addr() string`: `host:port`, the same for the proxy's whole life
  - `func (p *outageProxy) Stop() error`
  - `func (p *outageProxy) Start() error`
  - `func (p *outageProxy) Close() error`: stops for good and waits for every goroutine it started

- [ ] **Step 1:** Write `TestOutageProxy_StopStart`, a table over a loopback echo server started in the test. Cases, each an `assert` closure:
  - **"stop closes open connections":** after `Stop`, a read on a connection opened before returns a non-nil error within 1 s.
  - **"stop refuses new connections":** after `Stop`, `net.DialTimeout("tcp", p.Addr(), time.Second)` fails.
  - **"start reopens the same address":** after `Stop` then `Start`, a new dial to the same `Addr()` echoes `"ping"`.
  - **"stop and start are idempotent":** `Stop` twice and `Start` twice each return nil, and echo works at the end.
  - **"stop mid-transfer ends the read":** the echo server streams 1 MiB slowly. `Stop` after the first 64 KiB makes the client's `io.ReadAll` return an error within 1 s (Review Focus 2).
- [ ] **Step 2:** Write `TestOutageProxy_CloseLeavesNoGoroutine`. Start with `defer goleak.VerifyNone(t, goleak.IgnoreCurrent())`, open two connections, `Stop`, `Start`, open one more, then `Close` (Review Focus 1).
- [ ] **Step 3:** Land the stub: `Stop`, `Start` and `Close` return nil and do nothing. Run `go test -race -count=1 -run 'TestOutageProxy' .`. Expected: FAIL in "stop closes open connections" (the read succeeds) and in the leak test, not a compile error.
- [ ] **Step 4:** Implement. Track every live client/upstream pair. `Stop` closes the listener and every pair. `Start` calls `net.Listen("tcp", p.addr)` on the remembered address and returns its error unchanged.
- [ ] **Step 5:** Run the same command. Expected: PASS.

### Task 2.2: Proxy hang (dispatch A)

**Interfaces:**
- Produces: `func (p *outageProxy) Hang() error`, which keeps connections and the listener open and forwards nothing until `Start`.

- [ ] **Step 1:** Add `TestOutageProxy_Hang`, a table:
  - **"connections stay open":** after `Hang`, a write by the client succeeds and a read with a 250 ms deadline fails with `os.ErrDeadlineExceeded`, not `io.EOF`.
  - **"new connections are accepted":** a dial after `Hang` succeeds.
  - **"held bytes are delivered after start":** write `"ping"` while hung, then `Start`; the read returns `"ping"` within 1 s.
  - **"stop while hung closes everything":** `Hang` then `Stop` makes reads on open connections fail with a non-deadline error.
  - **"hang then start without stop":** echo works after `Start` (Review Focus 3).
- [ ] **Step 2:** Stub `Hang` as returning nil. Run `go test -race -count=1 -run 'TestOutageProxy_Hang' .`. Expected: FAIL in "connections stay open", because the read gets the echo.
- [ ] **Step 3:** Implement. Copies wait on a gate that `Hang` closes and `Start` opens. Bytes read while gated are held and written after the gate opens.
- [ ] **Step 4:** Run `go test -race -count=1 -run 'TestOutageProxy' .`. Expected: PASS.

### Task 2.3: Port taken, and parallel mode changes (dispatch A)

- [ ] **Step 1:** Add the case **"start fails when the port is taken"** to `TestOutageProxy_StopStart`: `Stop`, then `net.Listen` on `p.Addr()` in the test, then `Start` returns an error containing `p.Addr()`.
- [ ] **Step 2:** Add `TestOutageProxy_ParallelModes`. Eight parallel proxies each run 50 rounds of `Stop`/`Start` with a dial-and-echo after each `Start`. One more proxy has two goroutines calling `Hang`, `Start` and `Stop` in random order for 200 ms, then a final `Start` and echo (Review Focus 3).
- [ ] **Step 3:** Run `go test -race -count=1 -run 'TestOutageProxy' .`. Expected: FAIL on the port case if `Start`'s error does not name the address. Otherwise this is behaviour already in place: show the test can fail by making `Start` ignore its listen error, then restore it.
- [ ] **Step 4:** Implement what failed. Run `go test -race -count=5 -run 'TestOutageProxy' .`. Expected: PASS all 5.
- [ ] **Step 5:** Run `go vet ./...` and `gofmt -l .`. Expected: no output. The main session commits: `test: an in-process proxy that stops, hangs and restarts one call's connections`.

---

### Task 3.1: The PostgreSQL option (dispatch B)

**Files:**
- Modify: `test/testutils.go` (`testConfig`; `PostgresConn` and its methods; `RunTestPostgres`)
- Modify: `test/testutils_pgserver.go` (`postgresProvision` builds the DSN through the proxy)
- Test: `test/testutils_postgres_test.go`

**Interfaces:**
- Consumes: `newOutageProxy`, `Addr`, `Stop`, `Hang`, `Start` and `Close` from task 2.1.
- Produces:
  - `func WithTestPostgresOutageProxy() TestOption`, which sets `testConfig.outageProxy bool`
  - `PostgresConn.proxy *outageProxy`
  - `func (c PostgresConn) Hang(t *testing.T)`
  - `Stop` and `Start` act on `c.proxy` when it is set, else on the own server as today

- [ ] **Step 1:** Write `TestRunTestPostgresOutageProxy`, a table. Each case calls `RunTestPostgres(t, WithTestPostgresOutageProxy())`:
  - **"many outage-capable calls, one server":** ten parallel calls, plus one direct call, all report the same `pg_postmaster_start_time()` and `system_identifier` from `pg_control_system()`, and ten distinct `current_database()`.
  - **"stopped":** after `conn.Stop(t)`, `conn.DB.PingContext` fails, while a direct call's `DB` pings.
  - **"started again":** insert a row, `Stop`, `Start`, open `sql.Open("pgx", conn.DSN)` and read the row.
  - **"a request while hung":** after `Hang`, a `SELECT 1` with a 250 ms context fails with `context.DeadlineExceeded`, and a direct call's `SELECT 1` succeeds.
  - **"answers resume":** `Hang`, run `SELECT 42` in a goroutine with no deadline, `Start`; it returns 42 within 2 s.
  - **"no late answer after hang":** `Hang`, a `SELECT 1` with a 250 ms deadline fails, `Start`; the next `SELECT 2` on `conn.DB` returns 2 (Review Focus 4).
- [ ] **Step 2:** Land `WithTestPostgresOutageProxy` as a no-op and `Hang` as a no-op. Run `go test -race -count=1 -run 'TestRunTestPostgresOutageProxy' .`. Expected: FAIL in "stopped", which says Stop needs `WithTestPostgresRestartable`.
- [ ] **Step 3:** Implement. On the option, `postgresProvision` builds the call's clone on the shared server as usual, starts a proxy in front of the server's mapped address, and points `DSN` and `DB` at `proxy.Addr()`.
- [ ] **Step 4:** Run the same command. Expected: PASS.

### Task 3.2: Teardown after an outage (dispatch B)

- [ ] **Step 1:** Add `TestRunTestPostgresOutageTeardown`, a table. Each case applies the security-state set and leaves the proxy in one state: `"stopped"` or `"hung"`. Each runs in a subtest whose cleanup the parent observes, and asserts:
  - the subtest passes;
  - afterwards, the clone's name is absent from `pg_database` on the server's admin pool.

  The case `"hung, then t.Fatal"` (Review Focus 5) runs in a re-executed child test process, as the helper's existing child-process tests do, because a failing subtest would fail its parent. The parent asserts:
  - the child failed only with its own message;
  - the child's clone is absent from `pg_database`.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestRunTestPostgresOutageTeardown' .`. Expected: FAIL, because the rollback cannot reach a stopped proxy.
- [ ] **Step 3:** Implement. Register `proxy.Start` as a cleanup after the per-call teardown is registered, so it runs first. Register `proxy.Close` before the teardown, so it runs last.
- [ ] **Step 4:** Run the same command. Expected: PASS.

### Task 3.3: Refused combinations (dispatch B)

- [ ] **Step 1:** Add to the PostgreSQL refusals table, in the `TestRunTestRedis_Refusals` style, checking `testConfig.postgresConfigError` and `PostgresConn.Hang`'s precondition:
  - `{outageProxy, ownServer}`: error contains `WithTestPostgresOutageProxy` and `WithTestPostgresOwnServer`.
  - `{outageProxy, restartable}`: error contains `WithTestPostgresOutageProxy` and `WithTestPostgresRestartable`.
  - `Hang` on a direct shared connection: error contains `WithTestPostgresOutageProxy`.
  - `Stop` on a direct shared connection: error contains `shared`, as today.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestRunTestPostgres.*Refus' .`. Expected: FAIL on the three new cases.
- [ ] **Step 3:** Implement the checks in `postgresConfigError`, and a `proxied()` precondition beside `own()`.
- [ ] **Step 4:** Run the same command. Expected: PASS.

### Task 3.4: Child processes (dispatch B)

- [ ] **Step 1:** Extend `TestEnsureTestPostgresServer`'s child-process case. The child calls `RunTestPostgres(t, WithTestPostgresOutageProxy())`, stops and starts it, and prints `child-starts=<n>` from the registry's start counter. The parent asserts `child-starts=0` and that the child passed.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestEnsureTestPostgresServer' .`. Expected: PASS if inheritance already works through the option. If so, show the test can fail by making the child build its proxy against a newly started server, then restore it.
- [ ] **Step 3:** Confirm that "A real outage is still available" is pinned by `TestRunTestPostgres_OwnServerStorage` or the restartable test at `testutils_postgres_test.go:1825`, by naming the assertion that a stopped restartable server's container is stopped. If none asserts it, add that case, red first.

### Task 3.5: PostgreSQL godoc (dispatch B)

- [ ] **Step 1:** Write the godoc of `WithTestPostgresOutageProxy`, `PostgresConn.Stop`, `Start` and `Hang`, and amend `RunTestPostgres`'s. It must cover:
  - the default, a direct connection;
  - what stop, hang and start do (design.md D2);
  - that the shared server is never touched;
  - the teardown guarantee;
  - the refused combinations;
  - for an own server, unchanged behaviour.
- [ ] **Step 2:** Run `go doc . WithTestPostgresOutageProxy`, `go doc . PostgresConn.Hang`, `go vet ./...` and `gofmt -l .`. Expected: the docs print, with no vet or fmt output.
- [ ] **Step 3:** Run `go test -race -count=1 -run 'TestRunTestPostgres|TestEnsureTestPostgresServer|TestPostgres' .`. Expected: PASS. The main session commits: `test: PostgreSQL calls can stage an outage through a proxy on the shared server`.

---

### Task 4.1: Pin a database of its own per Redis call (dispatch C)

**Files:**
- Modify: `test/testutils.go` (Redis sections only)
- Test: `test/redis_testutils_test.go`

- [ ] **Step 1:** Locate the existing tests for "Two parallel calls" and "Every database in use". `TestRunTestRedis` and `TestRunTestRedis_FlushesAtCleanup` are candidates. Add what is missing:
  - **"two parallel calls":** two parallel calls `SET k` to `"a"` and `"b"`, and each `GET k` returns its own value.
  - **"every database in use":** with `redisDatabases` calls holding databases, a further call in a child `t.Run` fails, and its message names the image.
- [ ] **Step 2:** The red step, for behaviour that already exists. Temporarily hand every call database 0, and watch "two parallel calls" fail. Temporarily make the full-pool case wait instead of fail, and watch "every database in use" fail by timeout. Restore both.
- [ ] **Step 3:** Run `go test -race -count=1 -run 'TestRunTestRedis' .`. Expected: PASS.

### Task 4.2: The Redis outage option (dispatch C)

**Interfaces:**
- Consumes: the `outageProxy` API from task 2.1, and `testConfig.outageProxy` and the refusal style from tasks 3.1 and 3.3. Redis gets its own `func (c RedisConn) proxied() (*outageProxy, error)` beside `RedisConn.own()`.
- Produces:
  - `func WithTestRedisOutageProxy() TestOption`, which sets the same `testConfig.outageProxy`
  - `RedisConn.proxy *outageProxy`
  - `func (c RedisConn) Hang(t *testing.T)`
  - `Stop` and `Start` act on the proxy when it is set

- [ ] **Step 1:** Write `TestRunTestRedisOutageProxy`, a table mirroring task 3.1's cases on go-redis:
  - **"one server":** the same `run_id` from `INFO server` as a direct call, on a different database.
  - **"stopped":** `PING` fails while a direct call's succeeds.
  - **"started again":** a key written before `Stop` reads back after `Start`.
  - **"a request while hung":** `PING` under a 250 ms context fails with `context.DeadlineExceeded`.
  - **"answers resume".**
  - **"no late answer after hang":** after a timed-out `GET a` while hung and then `Start`, `GET b` returns b's value (Review Focus 4).
  - **"teardown after stop":** the database is flushed and handed out again.
- [ ] **Step 2:** Add refusals: `{outageProxy, ownContainer}` names both options, and `Hang` on a direct connection names `WithTestRedisOutageProxy`.
- [ ] **Step 3:** Land no-op stubs. Run `go test -race -count=1 -run 'TestRunTestRedisOutageProxy|TestRunTestRedis_Refusals' .`. Expected: FAIL in "stopped" and in the new refusals.
- [ ] **Step 4:** Implement. The client's `Addr` is `proxy.Addr()`, keeping `ContextTimeoutEnabled: true`. `proxy.Start` is registered so it runs before the flush, and `proxy.Close` so it runs after it.
- [ ] **Step 5:** Run the same command. Expected: PASS.

### Task 4.3: Servers shared by image and flags (dispatch C)

**Interfaces:**
- Produces: `redisServers` keyed by `redisServerKey{image string; args string}`, where `args` is the flags joined by `"\x00"` in the given order.
- `sharedTestRedis(t *testing.T, image string, args []string) *redisShared`, replacing the one-argument form.

- [ ] **Step 1:** Write `TestRunTestRedisSharedByFlags`, a table:
  - **"same flags, one server":** three parallel calls with `WithTestRedisServerArgs("--maxmemory-policy", "allkeys-lru")` report the same `run_id`, three distinct databases, and `CONFIG GET maxmemory-policy` = `allkeys-lru`.
  - **"other flags, other server":** `allkeys-lru` and `noeviction` calls report different `run_id`s, each its own policy.
  - **"own server on request":** flags plus `WithTestRedisOwnContainer()` report a `run_id` no other call shares.
  - **"stop on a flag-shared server is refused":** the error contains `shared`.
- [ ] **Step 2:** Update the refusal case "server args on a shared server" in `TestRunTestRedis_Refusals`: it now expects no error (D5's recorded behaviour change).
- [ ] **Step 3:** Run `go test -race -count=1 -run 'TestRunTestRedisSharedByFlags|TestRunTestRedis_Refusals' .`. Expected: FAIL, because `redisConfigError` refuses flags without an own container.
- [ ] **Step 4:** Implement. Drop the refusal, key the registry, and start a flagged shared server with the flags appended to its command.
- [ ] **Step 5:** Run `go test -race -count=1 -run 'TestRunTestRedis' .`. Expected: PASS.

### Task 4.4: Redis godoc (dispatch C)

- [ ] **Step 1:** Rewrite the godoc of `RunTestRedis`, `WithTestRedisOutageProxy`, `WithTestRedisServerArgs` (no longer needs an own container), `WithTestRedisOwnContainer` and `RedisConn.Stop`, `Start` and `Hang`. It must cover:
  - the defaults;
  - sharing by image and flags;
  - that a test sending `CONFIG SET`, or otherwise changing the server, needs `WithTestRedisOwnContainer()` (D5).
- [ ] **Step 2:** Run `go doc . WithTestRedisServerArgs`, `go vet ./...` and `gofmt -l .`. Expected: the docs print, with no vet or fmt output.
- [ ] **Step 3:** Run `go test -race -count=1 -run 'TestRunTestRedis|TestOutageProxy|TestRunTestPostgres' .`. Expected: PASS. The main session commits: `test: Redis calls can stage an outage through a proxy, and share servers by flags`.

---

### Task 5.1: Driver spike (dispatch D, then the main session)

- [ ] **Step 1 (agent):** In a scratch copy of `test/` (`cp -R`) outside the tree, switch each outage case to the proxy one at a time, leaving its assertions unchanged:
  - `TestPGLimiter_Unavailable`, both backends;
  - "unreachable server" in `TestSQLStoreLimiter_Verify` and `TestPgxLimiter_Verify`;
  - every case of `TestRedisLimiter_Fault`.

  Run each both ways, 5 times, with `-race`.
- [ ] **Step 2 (agent):** For each case, report a table row:
  - the driver error text and its type, with `%T` of the unwrapped error, real and proxied;
  - the `57P01` SQLSTATE where present;
  - the limiter's outcome, real and proxied;
  - pass or fail counts in each mode.
- [ ] **Step 3 (main session):** Record the table in design.md D4, with the list of cases that stay real. Commit: `docs(openspec): record how the drivers see a proxied outage`.

### Task 5.2 and 5.3: PostgreSQL moves (dispatch E)

**Files:** Modify `test/pg_ratelimit_fault_test.go` and `test/pg_ratelimit_test.go`.

- [ ] **Step 1:** In `TestPGLimiter_Unavailable`, give each case the connection in the form 5.1 decided:
  - `migratedLimiterDB(t, WithTestPostgresOutageProxy())` for the moved cases;
  - `WithTestPostgresRestartable()` for the one real case per backend, "breaker refuses without calling the server, and a probe reaches it once restarted", and for any case 5.1 kept.

  The broken-variant child uses the proxy in every case.
- [ ] **Step 2:** In `runPGVerify`'s "unreachable server" case, use `RunTestPostgres(t, WithTestPostgresOutageProxy(), WithTestPostgresMigrations(...))` with `conn.Stop(t)`, unless 5.1 kept it real.
- [ ] **Step 3:** The red step. Temporarily make `outageProxy.Stop` return nil without stopping anything. Run `go test -race -count=1 -run 'TestPGLimiter_Unavailable|TestSQLStoreLimiter_Verify|TestPgxLimiter_Verify' .`. Expected: every moved case FAILS. Restore `Stop`.
- [ ] **Step 4:** Run the same command, and also `TestPGLimiter_UnavailableCatchesBrokenVariants`. Expected: PASS, and the guard still reports `no-breaker` failing its case.
- [ ] **Step 5:** Report the PostgreSQL starts for that run, counted with `docker events`.

### Task 5.4: Redis fault move (dispatch F)

**Files:** Modify `test/redis_fault_test.go`.

- [ ] **Step 1:** Change the cases' setup:
  - stopped cases call `RunTestRedis(t, WithTestRedisOutageProxy())` and use `conn.Stop` and `Start`;
  - hung cases replace `hang` (`DEBUG SLEEP`) with `conn.Hang` and a `time.AfterFunc(hungFor, ...)` that calls `conn.Start`;
  - one real stop-then-start case keeps `WithTestRedisOwnContainer()`;
  - the control case moves only if task 1.1's recorded finding allows it.

  Remove `hang` if nothing uses it.
- [ ] **Step 2:** The red step. Temporarily make `Stop` and `Hang` no-ops. Run `go test -race -count=1 -run 'TestRedisLimiter_Fault' .`. Expected: every moved case FAILS. Restore them.
- [ ] **Step 3:** Run `go test -race -count=20 -run 'TestRedisLimiter_Fault' .`. Expected: PASS all 20.
- [ ] **Step 4:** Report the Redis starts for one run, counted with `docker events`.

### Task 5.5: Redis verify move (dispatch G)

**Files:** Modify `test/redis_verify_test.go`. Keep the `logRecorder` signature unchanged, because F reads it.

- [ ] **Step 1:** Drop `WithTestRedisOwnContainer()` from flagged cases that neither stop nor reconfigure the server, keeping `WithTestRedisServerArgs`. Cases with no flags and no ACL use the default shared server.
- [ ] **Step 2:** Change `aclClient` to create its ACL user named `scrty-` plus a sanitized `t.Name()` and 8 random hex characters, and to `ACL DELUSER` it in `t.Cleanup`. ACL cases then run on the shared server.
- [ ] **Step 3:** The red step. Temporarily widen the ACL user's rules to `+@all`. Run `go test -race -count=1 -run 'TestRedisVerify' .`. Expected: the ACL cases FAIL. Restore the rules.
- [ ] **Step 4:** Run the same command. Expected: PASS. Report the Redis starts for the table, counted with `docker events`; at most 5 servers of a test's own.

After E, F and G have each passed verification and review, the main session commits each lane separately: `test: move the PostgreSQL outage cases onto the proxy`, `test: move the Redis fault cases onto the proxy`, `test: share configured Redis servers in the verify table`.

### Task 5.6: The skill (main session)

- [ ] **Step 1:** Revise `.claude/skills/use-testcontainers/SKILL.md` with D7's three rules. Check each against the godoc landed in 3.5 and 4.4.
- [ ] **Step 2:** Commit: `docs(skills): reach for the outage proxy before a server of one's own`.

---

### Task 6.1: After measurement (main session)

- [ ] **Step 1:** Repeat task 1.2, steps 1–3, on the same host, into `after.json`.
- [ ] **Step 2:** Record "After" in design.md D6, then check the acceptance list:
  - passed count ≥ before;
  - 0 failed;
  - root-package starts down by at least 20;
  - the store-package gap recorded, with its cause measured if it has not closed.
- [ ] **Step 3:** Commit: `docs(openspec): record the container counts after the change`.

### Task 6.2: The gate (main session)

- [ ] **Step 1:** Run `make check` three times in a row. Expected: green each time.
- [ ] **Step 2:** Push, read one CI run of each job, and record its URL, container counts and wall times in design.md D6.
- [ ] **Step 3:** Run the whole-branch review (Opus) against every requirement in `specs/test-provisioning/spec.md`. Do this before archive, as tasks.md's follow-up says.
