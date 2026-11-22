# Tasks

This change touches test code only, in package `httpsec`. Its red step is a run that should fail, a package run under a 300 s timeout, with the reason it should fail. Then comes the change, then the run that passes. Restore a file you broke on purpose by editing it back, never with a git command that discards work.

Tasks marked **(main session)** push branches, open pull requests or record measurements in `design.md`. Agents do none of those.

## 1. Child-process rows run concurrently (design decisions 1–3, failure modes)

- [x] 1.1 Red: run `go test -race -count=1 -timeout 300s ./httpsec` on the unchanged tree.
  - Verify it fails with `panic: test timed out after 5m0s`, while the running tests listed are port-error rows. This is the failure this change removes.
  - Record the output's first 20 lines.
- [x] 1.2 Green: in `httpsec/mfa_enrol_porterr_test.go`, `limiterPortErrInChild` calls `t.Parallel()` right after `t.Helper()` (decision 1).
  - Extend its godoc with the contract:
    - call it once per subtest;
    - from a test with no `t.Setenv` or `t.Chdir` ancestor;
    - a caller that must act after its rows finish wraps them in `t.Run("group", …)` (decision 2).
  - Change no call site, wrapper or budget.
  - Verify:
    - `go test -race -count=1 -timeout 300s -json ./httpsec` passes;
    - report the package's elapsed time and the slowest child-process row's elapsed time from the JSON. Decision 3 says to stop and report if the slowest row exceeds 20 s.
- [x] 1.3 The guard still fails under concurrency (failure modes: a child that fails, a child that matches no row).
  - Temporarily make one child row's child exit non-zero, for example by failing a row in `TestPortErrors_RequestBody` in the child path only.
  - Verify the parent's run of that row fails, names the row, and shows the child's first output lines. Then edit it back.
  - Do the same with a marker that does not match (a child that prints the wrong marker). Verify "the child printed no line", then edit it back.
  - Verify `go test -race -count=1 -timeout 300s ./httpsec` passes again.
- [x] 1.4 Verify `make lint`, `make vet` and `gofmt -l httpsec` report nothing.

## 2. Gates and CI (main session)

- [x] 2.1 **(main session)** Record in `design.md` a `## Measurements` section with:
  - the red and green figures from 1.1 and 1.2: the package's elapsed time, and the slowest child row's;
  - the machine's CPU count.
- [x] 2.2 **(main session)** Run `make check`. Verify it passes, and keep the output.
- [x] 2.3 **(main session)** Push a branch and open a pull request. On its run, use a manual run if `SCRTY_SKIP_LONG_CHECKS` skips `test`.
  - Verify both `test` legs pass and report `httpsec` at no more than 400 s, the CI goal the design re-baselined on 2026-11-22.
  - Record both figures and the run ID in the design's Measurements.
- [x] 2.4 A fresh reviewer that wrote none of the change reviews the diff against decisions 1–3 and every row of the failure-modes table. It enumerates how the change fails before judging whether it works, and reports each row as handled, tested or accepted, or as a finding (`REPRODUCED` with a failing run, or `UNREPRODUCED` with the reason).

## Workflow follow-up

- Resume `split-ci-jobs` task 4.5 (`make check`, `make spec-check`, `openspec validate split-ci-jobs --strict`), then archive `split-ci-jobs`.
- Archive `parallel-port-error-children` after it merges.
