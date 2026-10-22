# Tasks

Every fix is test-first. The red step is the reproduction from group 1 or 3, seen failing for the intended reason. A compile error is not a red step, and a failure that comes from a missing fixture or a misconfigured environment is not one either. Each claim is recorded `REPRODUCED` (with the test, the command and the failing lines) or `UNREPRODUCED` (with the runs attempted), as `defect-claims.md` requires. PostgreSQL runs use `SCRTY_TEST_POSTGRES_IMAGE` unset (18) and `=postgres:15.19-alpine` (15).

## 1. Reproduce and classify the history deadlock (design: decision 1)

- [ ] 1.1 Build an on-demand reproduction of the `deadlock detected` in `TestIdentityStore_HistoryScenarios` (`test/pgxstore`). Run it on PostgreSQL 18 and 15 under load: raised `-count` and `-parallel`, with the `sqlstore`, `gormstore` and `pgxstore` packages running together, and `log_lock_waits` on. Capture the deadlock's `DETAIL` (each process, the lock it waits for, and who holds it) and confirm where pgx surfaces it. Verify: the reproduction fails at least once in a bounded run, and the captured detail names the statements in the cycle. If it does not fail within about an hour of recorded runs, record the attempt as `UNREPRODUCED` and continue at 2.1 under the design's risk rule.
- [ ] 1.2 Classify the cycle as a test defect (the fixture's trigger DDL is in it) or a product defect (two `RetirePassword` transactions, no DDL), and run the same reproduction against the `sqlstore` and `gormstore` twins. The main session records the evidence and the classification in `design.md`. Verify: `design.md` has a findings entry naming the statements, the locks and the driver(s) affected. If the classification is a product defect, stop here; the main session amends the change (design decision 3) before group 2.

## 2. Fix the history deadlock (design: decisions 2 and 3)

- [ ] 2.1 For a test defect: isolate the cases that install the delete-refusing trigger from the concurrently running cases, in `test/pgxstore`, `test/sqlstore` and `test/gormstore`. Use a database of their own per case, or sequential runs if the design records why. Keep every case's assertions unchanged. Verify: 1.1's reproduction passes 200 times under the same load on PostgreSQL 18 and 15, where it failed before the fix, and `(cd test && go test -count=1 ./sqlstore/... ./pgxstore/... ./gormstore/...)` passes on both.
- [ ] 2.2 Review: a fresh reviewer (Sonnet for a test-only fix, Opus for a product fix) checks the diff against the design's decisions and the findings recorded in 1.2. Verify: the review is clean, or its findings are folded and reviewed again.

## 3. Reproduce and classify the Redis fault failure (design: decision 1)

- [ ] 3.1 Build an on-demand reproduction of `TestRedisLimiter_Fault`, case "control: a client without ContextTimeoutEnabled is not cut off", failing with `ratelimit: backend unavailable`. Run it under `make check`-like load (the `test` module's packages together), then the case alone with CPU contention. Record which call fails (warm-up `Exceeded`, the hung check, or the build) and how long it took. Verify: the reproduction fails at least once in a bounded run, with the failing call and its duration logged. If it does not, record it `UNREPRODUCED` with the runs attempted, and continue at 4.1 under the design's risk rule.
- [ ] 3.2 Classify the failure as a test defect (the warm-up ran under the 250 ms hung-check budget) or a product defect (a healthy server answered `backend unavailable` well inside its operation timeout, or state leaking between limiters). Check whether the other cases that go through `cutOff` are exposed the same way. The main session records the evidence and the classification in `design.md`. Verify: `design.md` has a findings entry naming the failing call and its timing. If the classification is a product defect, stop here; the main session amends the change (design decision 3) before group 4.

## 4. Fix the Redis fault failure (design: decisions 2 and 3)

- [ ] 4.1 For a test defect: run the warm-up in `cutOff` (`test/redis_fault_test.go`) outside the 250 ms hung-check budget, either with a `PING` through the client or with a separate limiter on the same client. Keep `hungTimeout`, `hungMargin` and every cut-off assertion as they are. Verify: 3.1's reproduction passes 200 times under the same load where it failed before the fix, and `(cd test && go test -race -count=5 -run 'TestRedisLimiter_Fault' .)` passes.
- [ ] 4.2 Review: a fresh reviewer (Sonnet for a test-only fix, Opus for a product fix) checks the diff against the design and the findings recorded in 3.2. Verify: the review is clean, or its findings are folded and reviewed again.

## 5. Gate (design: decision 4)

- [ ] 5.1 Run `make check` five times in a row on PostgreSQL 18, and the `test` module once on PostgreSQL 15, keeping every output. Verify: all six are green. Record any unrelated failure in `design.md` with its output and propose it as its own change; never rerun it away silently.
- [ ] 5.2 Run `openspec validate stabilize-intermittent-tests --strict`, and a whole-change review by a fresh reviewer against the design's decisions and findings. Verify: both are clean.

## Workflow follow-up

- Archive the change once its review and gate are clean.
