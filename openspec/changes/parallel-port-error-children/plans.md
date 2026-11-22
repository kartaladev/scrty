# Parallel Port-Error Children Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `go test -race -count=1 ./httpsec` finishes in at most 300 s on the maintainer's machine and at most 400 s on a 4-CPU CI runner, because child-process port-error rows run concurrently.

**Architecture:**
- One test helper, `limiterPortErrInChild` in `httpsec/mfa_enrol_porterr_test.go`, marks its subtest parallel, and every child-process row already goes through it.
- The non-child rows that swap `slog.Default()` stay sequential in the parent's body. That body returns before any parallel subtest starts.
- No call site changes.

**Tech Stack:** Go 1.27, `testing` (`T.Parallel`, `-parallel`, `-timeout`), testify `require`/`assert`.

**Spec:** `openspec/changes/parallel-port-error-children/design.md` (decisions 1–3 and the failure-modes table) and `proposal.md`. The change has no spec deltas (`skip_specs: true`).

## Global Constraints

- Test code only. No library code, `Makefile`, CI workflow, `go.mod` or call-site change.
- Do not change the child's one-minute budget, its `-test.run`/`-test.count` arguments, or row selection (design non-goals).
- Do not change `make test`'s `-timeout`, `-p`, `-parallel` or `-race` (proposal, Not in scope).
- Package target: at most 300 s locally, at most 400 s on CI (re-baselined 2026-11-22, design Goals). Slowest child row: at most 20 s. If either line is crossed, stop and report; only the maintainer relaxes it (decision 3, design Goals).
- Never undo an edit with `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. Edit the file back.
- Binding rules for the implementer: `golang-tdd.md` (red, green, refactor; a compile error is not a red step), `defensive-coding.md`, `defect-claims.md`, `library-design.md`, and the read-only `legacy-reference.md`. Read `/golang-how-to`, then `golang-testing`, `golang-concurrency` and the project `table-test` skill.

## Review Focus

The conditions the tasks' main runs do not exercise, most likely first:
1. **A single row selected with `-run`.** For example, `go test -run 'TestPortErrors_RequestBody/passwordless_finish,_postedJSON/live/self-cycle' ./httpsec` still starts that one child and passes. Pinned in Task 1, Step 4.
2. **The override `-parallel 1`.** It restores serial order, and the package still passes (no timeout flag, since it is the slow path). Pinned in Task 1, Step 4.
3. **`-count=2`.** The concurrent rows run twice without colliding. Pinned in Task 1, Step 4, on one top-level test.
4. **A parallel row in a test that later gains a post-loop check.** Covered by the godoc contract (decision 2) and the reviewer in Task 3. No code site has it today.
5. **Memory pressure with `GOMAXPROCS` race children.** Measured as package time and row failures in Task 1, Step 4. Accepted in the design.

---

### Task 1: The helper runs its child row in parallel (tasks 1.1–1.4)

One implementer dispatch. **Model: Opus.** This is ordering under parallel subtests, where a wrong placement would still pass tests (`subagent-delegation.md`).

**Files:**
- Modify: `httpsec/mfa_enrol_porterr_test.go`, the function `limiterPortErrInChild` and its godoc.
- Temporarily modified in Step 5, then edited back: `httpsec/request_body_porterr_test.go`.
- Must not touch: every other file, and anything under `openspec/`.

**Interfaces:**
- Consumes: `limiterPortErrInChild(t *testing.T, envName, marker, row string)`, unchanged signature.
- Produces: the same signature. The behaviour change is that the subtest is parallel.

- [ ] **Step 1 (1.1, red):** Run `go test -race -count=1 -timeout 300s ./httpsec`.
  Expected: FAIL with `panic: test timed out after 5m0s`, and the running tests listed are `TestPortErrors_*` rows. Report the first 20 lines.
- [ ] **Step 2 (1.2, green):** In `limiterPortErrInChild`, add `t.Parallel()` as the statement right after `t.Helper()`. Extend the godoc with:
  - "call once per subtest";
  - "no `t.Setenv` or `t.Chdir` ancestor";
  - "a caller that must act after its rows finish wraps them in `t.Run("group", …)` and acts after that Run".
- [ ] **Step 3 (1.2, verify):** Run `go test -race -count=1 -timeout 300s -json ./httpsec > <scratch>/green.json`.
  - Expected: exit 0.
  - Report the package's `Elapsed`, and the largest `Elapsed` among the leaf subtests of the parent-process child rows, with its name.
  - Expected: package at most 300 s, slowest row at most 20 s. Otherwise stop and report.
- [ ] **Step 4 (Review Focus 1–3, 5):** Run each, and expect PASS:
  - `go test -race -count=1 -run 'TestPortErrors_RequestBody/passwordless_finish,_postedJSON/live/self-cycle' -v ./httpsec`. The output shows that one row ran.
  - `go test -race -count=1 -parallel 1 ./httpsec`. Report the elapsed time; it is expected to be about 600 s, and it runs without `-timeout`, so the default 10 m may kill it. If it does, report that as the evidence that `-parallel 1` restores the serial runtime.
  - `go test -race -count=2 -run '^TestPortErrors_RequestBody$' ./httpsec`.
- [ ] **Step 5 (1.3, the guard under concurrency):**
  - (a) In `TestPortErrors_RequestBody`, in the child path only (`childRow != ""`), make one named row call `t.Fatal("induced")`.
    - Run `go test -race -count=1 -run '^TestPortErrors_RequestBody$' ./httpsec`.
    - Expected: FAIL. That row's parent subtest reports "the child failed:" with `induced` in the quoted output, and other rows pass.
    - Edit it back.
  - (b) Make the same row print `bodyPortErrRan+"wrong"` instead of `bodyPortErrRan+row`. Run the same command.
    - Expected: FAIL with "the child printed no line".
    - Edit it back.
  - (c) Re-run Step 3's command. Expected: PASS.
- [ ] **Step 6 (1.4):** Run `make lint`, `make vet` and `gofmt -l httpsec`. Expected: no findings, no files.
- [ ] **Step 7 (report):** Report:
  - the file changed;
  - the red output from Step 1;
  - the figures from Steps 3 and 4;
  - the failing outputs from Steps 5a and 5b;
  - the final results of Step 6;
  - anything not finished.

  Do not commit. The main session commits.

### Task 2: Gates, measurements and CI (tasks 2.1–2.3; main session)

**Files:** `openspec/changes/parallel-port-error-children/design.md` (Measurements), written by the main session only.

- [ ] **Step 1 (2.1):** Add `## Measurements` to `design.md` with:
  - the red and green figures from Task 1, Steps 1 and 3;
  - the slowest child row;
  - `sysctl -n hw.ncpu`;
  - the date, and a note that the figures drift.
- [ ] **Step 2 (2.2):** Run `make check`. Expected: it passes, including `make test` with `httpsec` under the default timeout. Keep the log.
- [ ] **Step 3:** Commit `httpsec/mfa_enrol_porterr_test.go` with the message `test(httpsec): run port-error child rows in parallel`, staging exact paths.
- [ ] **Step 4 (2.3):** Push the branch `test/parallel-port-error-children` and open a pull request.
  - If `SCRTY_SKIP_LONG_CHECKS` skips `test`, start `gh workflow run ci.yml --ref test/parallel-port-error-children`.
  - Expected: both `test` legs pass, with `ok github.com/kartaladev/scrty/httpsec` at no more than 400 s in each leg's log.
  - Record both figures and the run ID in Measurements.

### Task 3: Fresh review (task 2.4)

**Model: Opus**, matching the implementer.

- [ ] **Step 1:** Dispatch a reviewer that wrote none of the change, edits nothing, and reads:
  - `git diff origin/main...HEAD -- httpsec/`;
  - `design.md`'s decisions 1–3 and failure-modes table.

  It must first list how the change can fail, by category: concurrency, state, time, resources, configuration and observability. It then reports each row of the table as handled, tested or accepted, or as a finding: `REPRODUCED` with a failing run, or `UNREPRODUCED` with the reason. It also checks that the godoc contract matches decision 2.
- [ ] **Step 2:** Findings go to a fresh dispatch of Task 1's lane. Rerun Task 2, Step 2 afterwards.
