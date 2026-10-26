# Proposal

## Why

Two tests failed intermittently in the full `make check` run while `first-party-sessions` group 10 was closing (2026-10-22). Both pass when run alone, and neither is in code that change touched, so they were left out of it:

- `test/pgxstore`, `TestIdentityStore_HistoryScenarios`, case "a retire whose prune fails, outside a caller's transaction, keeps no new entry": `ERROR: deadlock detected (SQLSTATE 40P01)`. Seen twice, once by a reviewer and once by the main session (one run in three).
- `test`, `TestRedisLimiter_Fault`, case "control: a client without ContextTimeoutEnabled is not cut off": `ratelimit: backend unavailable`, at `redis_fault_test.go:182` (called from `:244`). Seen once, in the second of three `make check` runs; the third was green. It had been seen once before, on 2026-10-04, in about ten full local runs during `testcontainers-optimize`, whose design recorded it `UNREPRODUCED` and out of scope. Two sightings three weeks apart make it a recurring failure, not a one-off.

Neither is fixed on `main` as of 2026-10-25. The 54 commits since this change was proposed, `pre-release-hardening` among them, leave every file named under Impact unchanged. They make the `test` module heavier, so `make check` loads the shared Docker host more than it did, and neither failure is less likely for it.

An intermittent gate is worse than a red one. Every later change pays for reruns, and a real regression in either area (identity history's transactions, or the shared limiter's fail-closed behaviour) can hide behind "it is the flaky one". Each failure is `UNREPRODUCED` today. The test code does not settle whether either is a test defect or a product defect, so this change finds out first, then fixes what it finds.

## What Changes

- **Reproduce each failure on demand**, with the evidence `defect-claims.md` requires:
  - the deadlock, with PostgreSQL's own deadlock report (the processes, locks and statements in the cycle) captured from the server log;
  - the Redis failure, with the step it fails at and the time it took.
- **Classify each** as a defect in the test or in the product, and record the evidence in `design.md`.
- **Fix each at its cause**:
  - A test defect is fixed in the test: its fixture, its isolation from parallel subtests, or its timing budget. Siblings sharing the same pattern are fixed too: the `sqlstore` and `gorm` history scenarios use the same delete-refusing trigger and the same table-renaming case, and every hung-server case goes through the same warm-up call.
  - A product defect is fixed test-first. Before any code changes, the change is amended with a spec delta for the affected capability (`default-identity-store` or `rate-limiting`).
- **Prove the gate holds**: repeated stress runs of each test under load comparable to `make check`, then repeated full `make check` runs, all green.
- **Not in scope**: changing `make check`'s `-p`, `-parallel` or `-race` settings. Those were settled in `testcontainers-optimize`. Moving a test to `test-isolated` is allowed only if the design shows the test cannot be made to hold under the shared run.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None at proposal time: fixing a test changes no specified behaviour, so the change opts out of specs (`skip_specs: true`). If reproduction shows a product defect, the change is updated to add a delta to `default-identity-store` (password history) or `rate-limiting` (shared limiter fail-closed behaviour) before the fix. The `skip_specs` marker is removed at the same time.

## Impact

- **Test code**: `test/pgxstore/identity_history_test.go` (and its `test/sqlstore` and `test/gormstore` twins, if they share the cause), and `test/redis_fault_test.go` with its helpers in `test/redis_testutils_test.go`.
- **Product code**: only if a product defect is shown. The candidates are `pgx/identity_history.go` (with its `sqlstore` and `gorm` twins), `internal/pgschema/identity.go`, and the `redis` limiter module.
- **No public API, dependency or migration change** is expected.
- **CI**: none, unless the design moves a test to `test-isolated`.
