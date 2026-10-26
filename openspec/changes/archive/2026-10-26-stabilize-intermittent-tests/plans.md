# Stabilize Intermittent Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every code-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself. Progress is tracked in `tasks.md`; the step checkboxes here are not ticked.

**Goal:** Make two intermittent `make check` failures reproducible, classify each as a test defect or a product defect with evidence, fix each at its cause, and show the gate holds.

**Architecture:** Two independent lanes (history deadlock, Redis fault), each running reproduce → classify → fix → review, then one gate. A product-defect classification stops its lane until the main session amends the change (design decision 3).

**Tech Stack:**
- Go 1.27 workspace (`test` module);
- PostgreSQL 15 and 18 via `RunTestPostgres`;
- Redis via the `test` module's helpers;
- pgx v5, `database/sql`, gorm;
- testify.

**Spec:** `openspec/changes/stabilize-intermittent-tests/`: `proposal.md` and `design.md` (decisions 1–4). There are no spec deltas (`skip_specs: true`). Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **Reproduce first.** No test or product file changes before its lane's classification task (1.2, 3.2) is recorded in `design.md` by the main session.
- **Reproduction harnesses stay out of the tree.** Stress scripts and logs live in the session scratchpad. Only the fix, and any evidence hook the design's risk rule calls for, enters the tree.
- **Defect claims** (`.claude/rules/defect-claims.md`):
  - Every claim is reported `REPRODUCED` (test, command, failing lines) or `UNREPRODUCED` (runs attempted, load used, duration).
  - A reproduction counts only if it fails for the claimed reason. A container start-up timeout or a port clash is not the deadlock.
- **Assertions stay.** `hungTimeout = 250ms`, `hungMargin = 200ms` and every cut-off assertion in `test/redis_fault_test.go` are unchanged. So is every assertion in the history scenarios.
- **Gate settings stay.** `make check`'s `-p`, `-parallel` and `-race` are not changed. No retry wrapper, and no `t.Skip` on a timing failure. `test-isolated` is used only if the design records that the test cannot hold in the shared run.
- **Agents** never edit `openspec/`. They never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. They never commit.
- **PostgreSQL versions:** 18 with `SCRTY_TEST_POSTGRES_IMAGE` unset, and 15 with `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`.

## Review Focus

1. **A fix that only makes the failure rarer.**
   - Expected: the lane's reproduction fails before the fix and passes 200 times after it, under the same load.
   - Test: the "Verify" step of 2.1 and 4.1 reruns the exact reproduction command from 1.1 / 3.1.
2. **The same fixture pattern in a driver that was never seen failing.**
   - Expected: when the cause is test-issued DDL, the `sqlstore` and `gormstore` history twins isolate the same three cases (the two trigger cases and the rename case "an unavailable table fails every call").
   - Expected, too: a twin's cleanup failure fails the test instead of being discarded, so a deadlock cannot hide again.
   - Test: added to 1.2 (run the reproduction on the twins), 2.1 (fix all three) and 2.2 (the shared-database scratch copy goes red once the cleanup checks its errors).
3. **Every `cutOff` case exposed to the same setup budgets** ("a hung server is cut off at the operation timeout…" as well as the control; the findings show both fail at the warm-up, and the `hang` probe's 1 s wait failed once).
   - Expected: both are fixed by the same warm-up and probe changes, and their assertions still pass.
   - Test: added to 4.1 (200 runs of both cases under the harsher load, and `-count=5` over the whole `TestRedisLimiter_Fault`).
4. **A deadlock between two `RetirePassword` calls with no DDL involved.**
   - Expected: this is classified as a product defect, and the lane stops for the spec-first path.
   - Test: added to 1.2 (a variant of the reproduction with all three DDL-issuing cases removed: both trigger cases and the rename case).
5. **An unrelated failure during the gate runs.**
   - Expected: it is recorded with its output and proposed separately, never rerun away.
   - Test: 5.1's recording rule.

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1a (parallel) | H1 | 1.1, then reports for 1.2 | nothing in the tree; scratchpad harness only | Opus: reproducing and reading a lock cycle is concurrency judgement |
| 1b (parallel) | R1 | 3.1, then reports for 3.2 | nothing in the tree; scratchpad harness only | Sonnet: a timing measurement with a stated hypothesis |
| main | — | 1.2, 3.2 (record findings in `design.md`) | `openspec/` | — |
| 2a (after 1.2, test defect) | H2 | 2.1 | `test/pgxstore/identity_history_test.go`, `test/sqlstore/identity_history_test.go`, `test/gormstore/identity_history_test.go`; `test/gormstore/identity_test.go` only if a per-case `database` helper belongs beside `withGoneTable` | Sonnet: isolation per a recorded cause |
| 2b (after 3.2, test defect) | R2 | 4.1 (warm-up) | `test/redis_fault_test.go`, `test/redis_testutils_test.go` | Sonnet: a warm-up moved out of a stated budget |
| 3a (after 2.1, parallel with 3b) | H3 | 2.2 | `test/sqlstore/identity_history_test.go`, `test/gormstore/identity_history_test.go` | Sonnet: two cleanups made to check errors as a sibling already does |
| 3b (after R2, parallel with 3a) | R3 | 4.1 (`hang` probe) | `test/redis_fault_test.go` | Sonnet: a setup wait resized per a recorded finding |
| after each lane's fixes | reviewer | 2.3, 4.2 | read-only | Sonnet for a test fix; Opus if a product fix |
| last | main | 5.1, 5.2 | — | Opus whole-change reviewer |

H1 and R1 run in parallel, because they write nothing to the tree. H2 and R2 run in parallel too, since their files are disjoint. Neither lane waits on the other.

---

### Task 1.1: Reproduce the history deadlock (dispatch H1)

**Files:** none in the tree. The harness goes in the scratchpad.

- [ ] **Step 1:** Run the existing test under load, and write down the exact command before running it. A starting point:
  ```sh
  cd test && go test -race -count=50 -parallel 16 -run 'TestIdentityStore_HistoryScenarios' ./pgxstore/ ./sqlstore/ ./gormstore/
  ```
  If it does not fail, widen the load: add `-cpu 1,2`, run alongside the rest of `./...`, or add a CPU-bound neighbour process. Do this on PostgreSQL 18, then on 15.
- [ ] **Step 2:** Collect the evidence for the deadlock:
  - Enable `log_lock_waits` and capture the server log. Use the `RunTestPostgres` options the helper offers, or `ALTER SYSTEM` plus a reload on the helper's server.
  - On a failure, capture the `*pgconn.PgError` `Detail`, so the deadlock is described in PostgreSQL's own words.
  - Confirm whether the detail arrives in the client error, in the server log, or in both.
- [ ] **Step 3:** Report:
  - the command and load used;
  - runs and failures, per version;
  - the failing lines;
  - the full deadlock detail, naming each process, the lock it waits for, the lock it holds, and its statement;
  - which subtest each process belongs to, and whether any statement in the cycle is test-issued DDL (`CREATE TRIGGER`, `DROP TRIGGER`, or `ALTER TABLE password_history RENAME`).

  If there are no failures within about an hour of runs, report `UNREPRODUCED` with the runs attempted.

### Task 1.2: Classify (main session, with H1's report)

- [ ] **Step 1:** Ask H1 (or a follow-up dispatch) to rerun the reproduction in two more configurations:
  - with all three DDL-issuing cases removed, in a scratch copy: the two "a retire whose prune fails…" cases and "an unavailable table fails every call" (Review Focus 4). A deadlock that persists without them is a product defect;
  - on the `sqlstore` and `gormstore` twins on their own (Review Focus 2).
- [ ] **Step 2:** Record a findings entry in `design.md`: the statements and locks in the cycle, the drivers affected, and the classification. Test-issued DDL anywhere in the cycle (a trigger's `CREATE` or `DROP`, or the rename) makes it a test defect (design decision 1). A product defect stops here, and the change is amended under design decision 3.

### Task 2.1: Isolate the DDL-issuing cases (dispatch H2, test defect only)

**Files:** the three `identity_history_test.go` files. Also `test/gormstore/identity_test.go`, only if a per-case `database` helper belongs beside `withGoneTable`.

- [ ] **Step 1 (red):** H1's reproduction command, run as is, fails. Use the failing run recorded in 1.1 as the red step.
- [ ] **Step 2:** In each of the three drivers, move all three DDL-issuing cases onto a database of their own: the two "a retire whose prune fails…" cases and "an unavailable table fails every call". Do this whichever of them the 1.2 cycle names (design decision 2). Each case calls `migratedIdentity(t)` (or the driver's equivalent) itself, as `test-provisioning` allows, and the other cases keep the shared database. If a case needs the shared database, run it sequentially outside the parallel group, and say why. Leave the assertions, `refuseHistoryDeletes` / `refuseHistoryDelete` and `withGoneTable` unchanged.
- [ ] **Step 3:** Verify:
  - the reproduction command passes 200 times on 18 and on 15. With no test DDL left in the shared database, this is certain by construction. The evidence is 1.2's cycle, and the findings say so (design decision 4);
  - `(cd test && go test -count=1 ./sqlstore/... ./pgxstore/... ./gormstore/...)` passes on both;
  - `go vet ./...` and `golangci-lint run` in `test` are clean.
- [ ] **Step 4:** The main session commits: `test(stores): give the history cases that issue DDL a database of their own`.

### Task 2.2: The twins' trigger cleanup checks its errors (dispatch H3)

**Files:** `test/sqlstore/identity_history_test.go` (`refuseHistoryDeletes`, the `t.Cleanup` at about `:423`) and `test/gormstore/identity_history_test.go` (`refuseHistoryDelete`, the `t.Cleanup` at about `:410`).

- [ ] **Step 1 (red harness):** In a scratch export, put the twins' two trigger cases back on the shared database (`ownDB: false`), and change each twin's cleanup to check its errors (Step 3's change). Run 1.1's loaded reproduction (`-race -count=100 -cpu 1,2 -parallel 16 -run TestIdentityStore_HistoryScenarios ./sqlstore/ ./gormstore/` beside 12 busy loops, against the `log_lock_waits` server). Expected: red, with `40P01` reported from the cleanup, where the same scratch copy without the cleanup change was green with deadlocks in its server log (H1's T18L/T15L). This shows the check surfaces the failure the old cleanup hid.
- [ ] **Step 2:** If Step 1 stays green with no deadlock in its server log, the harness has not exercised the check. Widen the load and say so; do not count it as red.
- [ ] **Step 3:** In the tree, replace each `_, _ = db.ExecContext(…DROP TRIGGER IF EXISTS…)` and `…DROP FUNCTION IF EXISTS…` with a call whose error is checked by `assert.NoError(t, err)`, in the shape of `test/pgxstore/identity_history_test.go`'s `refuseHistoryDeletes` cleanup. Keep `IF EXISTS` only if a case body can already have dropped the trigger. Read the case bodies and say which you chose.
- [ ] **Step 4:** Verify:
  - 1.1's reproduction (`-count=200`) on the tree passes on 18 and 15, with no `deadlock detected` in either server log;
  - `(cd test && go test -count=1 ./sqlstore/... ./gormstore/...)` passes on both;
  - `go vet ./...`, `gofmt -l .` and `golangci-lint run` in `test` are clean.
- [ ] **Step 5:** The main session commits: `test(stores): fail the history twins' trigger cleanup on error`.

### Task 2.3: Review (fresh reviewer, Sonnet)

- [ ] Check the diff of 2.1 and 2.2 against design decision 2 and the 1.2 findings. Confirm:
  - the assertions are unchanged;
  - in all three drivers, the isolation covers both trigger cases and the rename case, with no DDL left on the shared database;
  - neither twin's cleanup discards an error.

### Task 3.1: Reproduce the Redis fault failure (dispatch R1)

**Files:** none in the tree. The harness goes in the scratchpad.

- [ ] **Step 1:** Load the host as `make check` does, then run the case. A starting point:
  ```sh
  cd test && go test -race -count=1 ./... &
  go test -race -count=20 -run 'TestRedisLimiter_Fault/control' .
  ```
  Then run the case alone under CPU contention (`GOMAXPROCS=1`, or a busy-loop neighbour).
- [ ] **Step 2:** Instrument a scratch copy, not the tree. Log the duration and the result of each call in `cutOff`: the warm-up `Exceeded`, `hang`, and the hung check. Before the warm-up, log the client's `PoolStats()` (`TotalConns`, `IdleConns`), so a dial inside the budget is visible. Also log the limiter's breaker state if it is observable.
- [ ] **Step 3:** Report:
  - the command and load used;
  - runs and failures;
  - which call failed, how long it took, and the pool state before it. A warm-up failing at about 250 ms on an empty pool is a dial cut by the context (design Context);
  - whether the other `cutOff` case fails the same way (Review Focus 3). The design expected not; the findings show it does, because its pool is empty too.

  If there are no failures after a bounded effort, report `UNREPRODUCED`.

### Task 3.2: Classify (main session, with R1's report)

- [ ] Record a findings entry in `design.md` naming the failing call, its timing, the pool state, whether the other `cutOff` cases were exposed, and the classification. A product defect stops here, and the change is amended under design decision 3.

### Task 4.1: Warm up outside the hung-check budget (dispatch R2, test defect only)

**Files:** `test/redis_fault_test.go`, and `test/redis_testutils_test.go` if a helper belongs there.

- [ ] **Step 1 (red), dispatch R2:** under the harsher load (`GOMAXPROCS=1`, 40 busy loops, 4 concurrent copies of the pre-fix binary, each `-test.count=10 -test.run 'TestRedisLimiter_Fault/(control:_a_client|a_hung)'`), 3 of 4 copies failed at the warm-up (`:182`, `ratelimit: backend unavailable`).
- [ ] **Step 2, dispatch R2:** `cutOff(t, e, warm, l)` runs the warm-up `Exceeded` on `warm`, a limiter over the same client as `l` built without `WithOperationTimeout(hungTimeout)`. That is `e.build()` in the hung case and `e.buildOn(hidden)` in the control. It fills the pool and loads the script (design decision 2). The measured call stays on `l`.
- [ ] **Step 3 (red), dispatch R3:** the run recorded in the findings is the red step for the probe: one of 200 runs failed at `:76` (`require.Eventually`, "the server kept answering") under the harsher load.
- [ ] **Step 4, dispatch R3:** in `hang` (`test/redis_fault_test.go`), raise the probe's `require.Eventually` wait from `time.Second` to `hungFor / 2`, and keep the 10 ms tick. That leaves at least 2.5 s of the 5 s sleep for the measured call, which covers the control's `assert.Greater(t, elapsed, time.Second, …)`. Say in the comment that the wait is setup-sized and why the remaining sleep still covers the check. Leave `hungFor`, `hungTimeout`, `hungMargin` and every assertion unchanged.
- [ ] **Step 5:** Verify, with the R2 and R3 changes together:
  - under the same harsher load, 4 copies at `-test.count=50` (200 runs) pass with no failure in any step;
  - `(cd test && go test -race -count=5 -run 'TestRedisLimiter_Fault' .)` passes;
  - `go vet ./...`, `gofmt -l .` and `golangci-lint run` in `test` are clean.
- [ ] **Step 6:** The main session commits: `test(ratelimit): keep the fault cases' setup outside the hung-check budget`.

### Task 4.2: Review (fresh reviewer, Sonnet)

- [ ] Check the diff against design decision 2 and the 3.2 findings. Confirm:
  - the measured call still runs under `hungTimeout`;
  - the control case still shows the client ignoring deadlines;
  - the probe's longer wait still leaves the sleep covering the measured call.

### Task 5.1: Gate (main session)

- [ ] Run `make check` five times in a row on 18, and `(cd test && go test -race -count=1 ./...)` once on 15. Keep each output in the scratchpad. All six must be green. Any unrelated failure is recorded in `design.md` and proposed as its own change.

### Task 5.2: Close (main session)

- [ ] Run `openspec validate stabilize-intermittent-tests --strict`. Then dispatch a fresh Opus reviewer that edits nothing, over the change's commits, against design decisions 1–4 and the recorded findings. Both must be clean.
