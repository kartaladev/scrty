# Stabilize Intermittent Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every code-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself.

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
- **The legacy reference** is not read for this change; it concerns test fixtures, not a predecessor behaviour.
- **PostgreSQL versions:** 18 with `SCRTY_TEST_POSTGRES_IMAGE` unset, and 15 with `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`.

## Review Focus

1. **A fix that only makes the failure rarer.**
   - Expected: the lane's reproduction fails before the fix and passes 200 times after it, under the same load.
   - Test: the "Verify" step of 2.1 and 4.1 reruns the exact reproduction command from 1.1 / 3.1.
2. **The same fixture pattern in a driver that was never seen failing.**
   - Expected: the `sqlstore` and `gormstore` history twins are isolated the same way when the cause is the fixture.
   - Test: added to 1.2 (run the reproduction on the twins) and 2.1 (fix all three).
3. **Another `cutOff` case exposed to the same warm-up budget** ("a hung server is cut off at the operation timeout…").
   - Expected: it is fixed by the same warm-up change, and its assertions still pass.
   - Test: added to 4.1 (`-count=5` over the whole `TestRedisLimiter_Fault`).
4. **A deadlock between two `RetirePassword` calls with no DDL involved.**
   - Expected: this is classified as a product defect, and the lane stops for the spec-first path.
   - Test: added to 1.2 (a variant of the reproduction with the trigger cases removed).
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
| 2a (after 1.2, test defect) | H2 | 2.1 | `test/pgxstore/identity_history_test.go`, `test/sqlstore/identity_history_test.go`, `test/gormstore/identity_history_test.go` | Sonnet: isolation per a recorded cause |
| 2b (after 3.2, test defect) | R2 | 4.1 | `test/redis_fault_test.go`, `test/redis_testutils_test.go` | Sonnet: a warm-up moved out of a stated budget |
| after each fix | reviewer | 2.2, 4.2 | read-only | Sonnet for a test fix; Opus if a product fix |
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
  - the full deadlock detail, naming each process, the lock it waits for, the lock it holds, and its statement.

  If there are no failures within about an hour of runs, report `UNREPRODUCED` with the runs attempted.

### Task 1.2: Classify (main session, with H1's report)

- [ ] **Step 1:** Ask H1 (or a follow-up dispatch) to rerun the reproduction in two more configurations:
  - with the two trigger-installing cases removed, in a scratch copy (Review Focus 4);
  - on the `sqlstore` and `gormstore` twins on their own (Review Focus 2).
- [ ] **Step 2:** Record a findings entry in `design.md`: the statements and locks in the cycle, the drivers affected, and the classification. A product defect stops here, and the change is amended under design decision 3.

### Task 2.1: Isolate the trigger cases (dispatch H2, test defect only)

**Files:** the three `identity_history_test.go` files.

- [ ] **Step 1 (red):** H1's reproduction command, run as is, fails. Use the failing run recorded in 1.1 as the red step.
- [ ] **Step 2:** Move the two "a retire whose prune fails…" cases onto a database of their own: call `migratedIdentity(t)` inside the case, as `test-provisioning` allows. If the fixture needs the shared database, run them sequentially outside the parallel group, and say why. Leave the assertions and the `refuseHistoryDeletes` behaviour unchanged.
- [ ] **Step 3:** Verify:
  - the reproduction command passes 200 times on 18 and on 15;
  - `(cd test && go test -count=1 ./sqlstore/... ./pgxstore/... ./gormstore/...)` passes on both;
  - `go vet ./...` and `golangci-lint run` in `test` are clean.
- [ ] **Step 4:** The main session commits: `test(stores): isolate the history cases that install a trigger`.

### Task 2.2: Review (fresh reviewer, Sonnet)

- [ ] Check the diff against design decision 2 and the 1.2 findings. Confirm the assertions are unchanged, and that the isolation covers every case that installs DDL.

### Task 3.1: Reproduce the Redis fault failure (dispatch R1)

**Files:** none in the tree. The harness goes in the scratchpad.

- [ ] **Step 1:** Load the host as `make check` does, then run the case. A starting point:
  ```sh
  cd test && go test -race -count=1 ./... &
  go test -race -count=20 -run 'TestRedisLimiter_Fault/control' .
  ```
  Then run the case alone under CPU contention (`GOMAXPROCS=1`, or a busy-loop neighbour).
- [ ] **Step 2:** Instrument a scratch copy, not the tree. Log the duration and the result of each call in `cutOff`: the warm-up `Exceeded`, `hang`, and the hung check. Also log the limiter's breaker state if it is observable.
- [ ] **Step 3:** Report:
  - the command and load used;
  - runs and failures;
  - which call failed, and how long it took;
  - whether the other `cutOff` case fails the same way (Review Focus 3).

  If there are no failures after a bounded effort, report `UNREPRODUCED`.

### Task 3.2: Classify (main session, with R1's report)

- [ ] Record a findings entry in `design.md` naming the failing call, its timing, and the classification. A product defect stops here, and the change is amended under design decision 3.

### Task 4.1: Warm up outside the hung-check budget (dispatch R2, test defect only)

**Files:** `test/redis_fault_test.go`, and `test/redis_testutils_test.go` if a helper belongs there.

- [ ] **Step 1 (red):** use the failing run recorded in 3.1 as the red step.
- [ ] **Step 2:** In `cutOff`, establish the pooled connection without the 250 ms budget, either with `e.conn.Client.Ping(ctx)` on the limiter's client, or with an `Exceeded` call on a limiter built without `WithOperationTimeout(hungTimeout)` over the same client. The measured call stays on the `hungTimeout` limiter. The control case's client (`ContextTimeoutEnabled = false`) is warmed the same way. Leave `hungTimeout`, `hungMargin` and every assertion unchanged.
- [ ] **Step 3:** Verify:
  - the reproduction passes 200 times under the same load;
  - `(cd test && go test -race -count=5 -run 'TestRedisLimiter_Fault' .)` passes;
  - `go vet` and `golangci-lint run` in `test` are clean.
- [ ] **Step 4:** The main session commits: `test(ratelimit): warm the fault cases' connection outside the hung-check budget`.

### Task 4.2: Review (fresh reviewer, Sonnet)

- [ ] Check the diff against design decision 2 and the 3.2 findings. Confirm the measured call still runs under `hungTimeout`, and that the control case still shows the client ignoring deadlines.

### Task 5.1: Gate (main session)

- [ ] Run `make check` five times in a row on 18, and `(cd test && go test -race -count=1 ./...)` once on 15. Keep each output in the scratchpad. All six must be green. Any unrelated failure is recorded in `design.md` and proposed as its own change.

### Task 5.2: Close (main session)

- [ ] Run `openspec validate stabilize-intermittent-tests --strict`. Then dispatch a fresh Opus reviewer that edits nothing, over the change's commits, against design decisions 1–4 and the recorded findings. Both must be clean.
