# Serial Port-Error Rows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `go test -race -count=1 ./httpsec` runs in at most 300 s on the maintainer's machine and on a 4-CPU CI runner.

**Architecture:** three test-only fixes, each removing a reason rows still run serially or slowly.
- The three copied child launchers call the one parallel helper.
- Fixtures share one Argon2id hash of `e2ePassword`, derived once per process.
- The rehash rig upgrades to 20 MiB rather than 46 MiB.

**Tech Stack:** Go 1.27, `testing`, `sync.OnceValues`, `golang.org/x/crypto/argon2` through `authenticate/password`, testify.

**Spec:** `openspec/changes/serial-port-error-rows/design.md` (decisions 1–3, failure modes) and `proposal.md`. There are no spec deltas (`skip_specs: true`).

## Global Constraints

- Test code only, in package `httpsec`. No library, `Makefile`, CI or `go.mod` change.
- Every login in the touched fixtures still verifies a real Argon2id hash. No row switches to `MockEncoder`.
- The child budget (one minute), the child's arguments and row selection stay unchanged.
- `e2eEncoder`'s parameters stay as they are: 19456 KiB, 2 iterations, 1 thread.
- Package goal: at most 300 s locally and on CI. If it is missed, stop and report. Only the maintainer relaxes it.
- **Ordering.** The two dispatches share one package, so they run one after the other, never together. A half-edited file in one breaks compilation for the other, and concurrent package runs distort timings.
- **Git.** Never undo an edit with `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. Edit the file back. Agents do not commit and do not edit `openspec/`.
- **Binding rules:** `golang-tdd.md` (a compile error is not a red step), `defensive-coding.md`, `defect-claims.md`, `library-design.md` and `legacy-reference.md` (never read or cite `.claude/.legacy`). Load `/golang-how-to`, then `golang-testing`, `golang-concurrency` and the project's `table-test` skill.

## Review Focus

1. **A former copy's caller has a parent `t.Cleanup` or a slog swap on the top-level `t`.** Rows must still never overlap the sequential rows. This is pinned in Dispatch A, Step 2: the caller check reads each enclosing function's top and tail, not only its loop.
2. **`go test -run` selects a single child row of a former copy.** That one child should start and pass. Pinned in Dispatch A, Step 5.
3. **Two tests ask for `e2eHash` at once.** Both should get the same valid hash, and no race report. Pinned in Dispatch B, Step 4, by the full package run under `-race`, which runs many fixture users in parallel.
4. **A fixture whose user later changes password, or is rehashed.** It must not share the process hash. Pinned in Dispatch B, Step 1, as part of the fixture check, which names those cases.
5. **`-count=2`.** The once-derived hash is reused across counts without going stale. Pinned in Dispatch B, Step 4.

---

### Dispatch A: the copied launchers go through the shared helper (tasks 1.1–1.4)

**Model: Opus.** It is a refactor that must keep existing behaviour while removing copies, and it changes how rows are ordered under concurrency.

**Files** (owned):
- `httpsec/mfa_enrol_porterr_test.go`: the helper's excerpt length and godoc.
- `httpsec/throttle_porterr_test.go`, `httpsec/redemption_porterr_test.go` and `httpsec/oidc_backchannel_porterr_test.go`: the copies.

Must not touch: any other file.

**Interfaces:**
- Consumes: `limiterPortErrInChild(t *testing.T, envName, marker, row string)`.
- Produces: `throttlePortErrInChild(t *testing.T, row string)`, `redemptionPortErrInChild(t *testing.T, row string)` and `backchannelPortErrInChild(t *testing.T, row string)`, with unchanged signatures, each now one call to the helper with its own env var and marker constants.

- [ ] **Step 1 (1.1, red):** Run `go test -race -count=1 -json -run '^TestPortErrors_SourceThrottle$' ./httpsec`.
  - Expected: no `"Action":"pause"` on any row.
  - Report the wall time from the first and last event timestamps.
- [ ] **Step 2 (1.2):** Find every caller with gopls references: `generator_porterr_test.go:267`, `redemption_porterr_test.go:377` and `:639`, `throttle_porterr_test.go:241`, `oidc_backchannel_porterr_test.go:263`, or wherever they now sit. For each, report:
  - whether the helper is called once per subtest;
  - whether any ancestor calls `Setenv` or `Chdir`;
  - what the enclosing functions contain after their loops, including any `defer` and any `t.Cleanup` or `swapDefaultLogger` on the top-level `t`.

  Stop if a caller breaks the contract.
- [ ] **Step 3 (1.3, green):**
  - Replace each copy's body with `limiterPortErrInChild(t, <env const>, <marker const>, row)`.
  - Change the helper's excerpt from `min(len(lines), 8)` to `min(len(lines), 12)`, and add one godoc line saying it quotes the first 12 lines.
- [ ] **Step 4 (1.3, verify):**
  - Step 1's command now shows a `pause` on each child row.
  - `go test -race -count=1 -run '^(TestPortErrors_SourceThrottle|TestPortErrors_Redemption|TestPortErrors_OIDCRedemption|TestPortErrors_BackchannelLinkStore|TestPortErrors_TokenGenerator)$' ./httpsec` passes.
  - Report the wall times.
- [ ] **Step 5 (Review Focus 2):** `go test -race -count=1 -v -run "^TestPortErrors_SourceThrottle\$/^basic,_the_IPv6_aggregate_limiter's_check\$/^live\$/^self-cycle_through_Unwrap\(\)_\[\]error\$" ./httpsec` passes, and runs that row.
- [ ] **Step 6 (1.4):** In that `SourceThrottle` row's child path only:
  - (a) add `t.Fatal("induced")`. Expected: FAIL, with "the child failed:" and `induced`. Edit it back.
  - (b) print the marker with a wrong row. Expected: FAIL, with "the child printed no line". Edit it back.
  - Confirm with `git diff --stat` that only the four owned files differ, and in the intended places.
- [ ] **Step 7 (4.1 for this lane):** `make lint`, `make vet` and `gofmt -l httpsec` report nothing.
- [ ] **Step 8:** Report the diffs (they are small), the outputs of Steps 1, 4, 5 and 6, the caller verdicts from Step 2, and any open item.

### Dispatch B: one fixture hash, and the rehash target (tasks 2.1–3.2), after Dispatch A is verified

**Model: Sonnet.** A known pattern with signatures fixed here. The caller and fixture checks carry the judgement.

**Files** (owned):
- `httpsec/integration_test.go` (`e2eHash`);
- `httpsec/helpers_test.go` and `httpsec/passkey_login_test.go` (the fixtures);
- any other fixture file Step 1 clears, named in the report before it is edited;
- `httpsec/login_rehash_test.go`.

Must not touch: Dispatch A's four files.

**Interfaces:**
- Produces: `e2eHash(t *testing.T) string` in `httpsec/integration_test.go`. It is backed by a package-level `sync.OnceValues(func() (string, error))` that builds the encoder with `e2eEncoder`'s exact options and encodes `e2ePassword`. It calls `t.Helper()` and `require.NoError(t, err)`.

- [ ] **Step 1 (2.1 and 2.2):**
  - Run `go test -race -count=1 -cpuprofile <scratch>/cpu-before.out -run '^TestPortErrors_RecoveryCooldown$/^live$/^Unwrap_panicking_with_nil$' ./httpsec`, then `go tool pprof -top` on it. Expected: argon2 dominates. Report the row's elapsed time.
  - Then list, with gopls, every `e2eEncoder(t).Encode(e2ePassword)`. For each fixture, check its users for:
    - assertions on hash bytes or salt;
    - needing distinct hashes;
    - a password change or rehash on that fixture's stored hash;
    - a store that mutates the hash.

    Report each fixture as switched or kept, with the reason.
- [ ] **Step 2 (2.3, green):** Add `e2eHash`, and switch the cleared fixtures to it.
- [ ] **Step 3 (2.3, verify):**
  - Re-run Step 1's profile. Expected: a lower elapsed time and a lower argon2 share.
  - `go test -race -count=1 -run '^(TestPortErrors_RecoveryCooldown|TestPortErrors_PasswordlessUserLoader|TestPortErrors_TokenGenerator|TestRecovery.*|TestPasskeyLogin.*)$' ./httpsec` passes.
- [ ] **Step 4 (Review Focus 3, 5):** `go test -race -count=2 -run '^(TestRecovery.*|TestPasskeyLogin.*)$' ./httpsec` passes with no race report.
- [ ] **Step 5 (3.1, red):** Set `rehashNewMemory = 19 * 1024`.
  - Run `go test -race -count=1 -run '^(TestLogin_Rehash.*|TestPortErrors_RehashWrite)$' ./httpsec`. Expected: FAIL in the upgrade cases. Report which ones.
  - Then set `rehashNewMemory = 20 * 1024`.
- [ ] **Step 6 (3.2, green):**
  - The same command passes.
  - grep that no assertion ties `47104` to `rehashNewMemory`.
  - Report `TestPortErrors_RehashWrite`'s wall time, from event timestamps with `-json`, before and after.
- [ ] **Step 7 (4.1 for this lane):** `make lint`, `make vet` and `gofmt -l httpsec` report nothing.
- [ ] **Step 8:** Report the diffs, the fixture verdicts, every red and green output, the timings, and any open item.

### Main session: measurements, gates, CI and review (tasks 4.2–4.5)

- [ ] **4.2:** On an idle machine, `go test -race -count=1 -timeout 300s -json ./httpsec`.
  - Record in `design.md`'s Measurements: the package `Elapsed`, the count of rows with a `pause` action, and the time in rows that never paused.
  - Expected: at most 300 s.
- [ ] **4.3:** `make check` passes. Keep the log.
- [ ] **Commit:** `test(httpsec): run every port-error child row in parallel and hash fixtures once`, staging exact paths, plus the OpenSpec change.
- [ ] **4.4:** Push `test/serial-port-error-rows`, open a pull request, and run `gh workflow run ci.yml --ref test/serial-port-error-rows`.
  - Expected: both `test` legs report `httpsec` at no more than 300 s.
  - Record the figures and the run ID.
- [ ] **4.5:** A fresh **Opus** reviewer, matching Dispatch A, read-only, reviews `git diff main -- httpsec/` against decisions 1–3 and the failure-modes table. It enumerates how the change fails first, and labels findings `REPRODUCED` or `UNREPRODUCED`. Findings go to a fresh dispatch of the owning lane.
