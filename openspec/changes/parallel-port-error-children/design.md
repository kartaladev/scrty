# Design

## Context

See proposal.md, Why, for the measurements and the cost.

**How a child-process row works today:**
- Every one goes through `limiterPortErrInChild(t, envName, marker, row)` in `httpsec/mfa_enrol_porterr_test.go`. Some go through a thin wrapper (`apiKeyPortErrInChild`, `loginPortErrInChild`, `redemptionPortErrInChild` and others), and some through the shared `runStepUpPortErrors`.
- In the parent process, the helper re-runs the test binary under a one-minute context, as `-test.run=^<top-level test>$ -test.count=1`, with `envName=row` added to the environment.
- It then requires that the child exits 0 and prints `marker+row` as a whole line.
- In the child, the same top-level test sees `envName` set, skips every other row, and runs only that one. A cyclic error that overflows the stack kills only the child, and the parent reports it.

**What the call-site audit found (2026-11-22):** a read-only audit of the call sites found the facts below. The review (task 2.4) corrected two of them, as marked. gopls finds 20 references to the helper: 16 direct calls and 4 thin wrappers. Together with `runStepUpPortErrors` and its 7 callers, they reach 26 top-level tests.
- every call is in a subtest exactly one `t.Run` below a sequential top-level test;
- the helper call comes after a guard that only lets the parent's child rows through, so each subtest calls the helper once;
- no ancestor calls `t.Parallel`, `t.Setenv` or `t.Chdir`, and the package has no `os.Setenv`, `t.Setenv` or `t.Chdir` at all;
- no enclosing function has code after its loop or a `defer`. *Corrected:* one has a parent-level `t.Cleanup` (next item);
- the helper's branch writes no state the parent shares;
- `slog.Default()` is swapped by `swapDefaultLogger` (`httpsec/lookup_abort_log_test.go`), mostly inside the rows that run in the parent, each of which restores it in its own `t.Cleanup`.
  - *Corrected:* `TestPortErrors_UserAndVerifierSites` (`httpsec/session_porterr_test.go:301`) swaps it on the top-level `t`, once per site, so its restores run after its parallel child rows finish.
  - This is harmless. The swapped logger is read only by that site's sequential rows, and the helper's branch never logs.

The main session spot-checked two of these claims against the tree: there is no `Setenv` or `Chdir` anywhere in the package, and nothing follows the loop of `TestPortErrors_RequestBody`.

**Go's rules that bound the change:** Go 1.27.4 `go doc testing`; see proposal References.
- A subtest that calls `t.Parallel` starts only after its parent's function returns. It runs alongside its parallel siblings and never with another top-level test.
- `Run` returns only after parallel subtests finish.
- `t.Parallel` panics on a second call. It does **not** panic in a test whose ancestor used `t.Setenv` or `t.Chdir`. Only `t.Setenv` under a parallel ancestor panics, which is the other direction. The review reproduced this on Go 1.27.4 with a throwaway module, after the first draft of this design claimed the opposite.
- `-parallel` bounds how many run at once. It defaults to `GOMAXPROCS`.

## Goals / Non-Goals

**Goals:**
- The parent runs child-process rows concurrently, within `-parallel`.
- Each row keeps the same three checks: the child exits 0, the child prints its marker, and the child finishes within its budget.
- `go test -race -count=1 ./httpsec` finishes in at most 300 s, half the default timeout. It is measured locally and on CI, before and after.

**Non-Goals:**
- Making the rows that run in the parent parallel. They swap the process-wide `slog.Default()`, and sharing it is a separate design.
- Changing the child-process guard itself: its budget, its arguments or its row selection.
- Any `Makefile`, CI or library change.

## Decisions

### 1. The helper marks its subtest parallel before it starts the child

- **What.** `limiterPortErrInChild` calls `t.Parallel()` as its first statement after `t.Helper()`. Every wrapper and call site is unchanged.
- **Why here.** It is the one seam all 236 child-process rows already share. A call site added later gets the concurrency without remembering to ask for it.
- **Why safe.** These rows run in the parent while the non-child rows of the same loop run one at a time in the loop body. The non-child rows swap `slog.Default()`, and they finish before the parallel subtests start, because those start only after the parent's function returns. Two top-level tests' children never overlap.
- **The helper's contract**, recorded in its godoc:
  - Call it once per subtest. A second call makes `t.Parallel` panic, which is loud.
  - Call it from a test with no `t.Setenv` or `t.Chdir` ancestor. Go does not refuse one, and the testing API cannot detect it. The row would then run after the parent returns, with whatever environment and working directory the ancestor holds by then. This is accepted, and documented, in the failure modes.
  - The calling test must not depend on its rows having finished, except after an enclosing `t.Run`. Break this and decision 2 applies.
- **Default:** concurrency up to `-parallel`, which is `GOMAXPROCS`. **Override:** a contributor passes `-parallel N` to `go test`. `-parallel 1` runs the rows one at a time, though not in the old order: each child row now runs after all of its parent's sequential rows. It also serialises the package's tests that were already parallel, so it is slower than before this change: it was killed at the 10-minute default on 2026-11-22. Use it with a longer `-timeout`. This is a test helper with no library consumer, so there is no other override point.
- **Alternatives considered:**
  - **Raising `make test`'s `-timeout`.** Rejected by the maintainer on 2026-11-22: it hides the growth instead of removing it.
  - **One child per top-level test, running all its rows.** It cuts 236 processes to 26. But the first row that kills the child hides every row after it, and per-row reporting is lost. It would also restructure 32 tests rather than one helper.
  - **Calling `t.Parallel` at each call site.** It gives the same effect in 25 places, and a new call site could forget it.

### 2. A call site whose parent depends on its rows wraps them in a group

- **The rule.** If a calling test ever needs to act after its child rows finish (an assertion, a tear-down or a restore), the rows go inside a `t.Run("group", …)`, the idiom the `testing` docs give. The action goes after that `Run`. The audit found no such site today, so no call site changes.
- **Override:** none. This is a rule for future test code, recorded in the helper's godoc.

### 3. The child's one-minute budget stays, and is measured under concurrency

- **What.** The budget is unchanged. Implementation records the slowest child's wall time in the concurrent run, locally and on CI.
- **The line.** If the slowest child goes over 20 s, a third of the budget, implementation stops and the design is revisited, for example by capping the helper's concurrency. The budget is not raised.
- **Override:** none. The budget is part of the guard, and changing it is out of scope.

## Failure modes

| Failure | State | What is seen |
|---|---|---|
| A future call site calls the helper twice on one `t` | Handled: `t.Parallel` panics | The test fails at once with Go's panic message. |
| A future call site has a `t.Setenv` or `t.Chdir` ancestor | Accepted: Go does not refuse it, and the testing API cannot detect it | The row runs after its parent returns, under whatever environment or working directory the ancestor holds then. A relative `os.Args[0]` under a `Chdir` would fail to start the child, which fails the row. The godoc states the contract. No site has such an ancestor today. |
| A future parent reads results after its loop without a group (decision 2) | Accepted | The parent's post-loop code runs before its child rows, so its check sees nothing. No site does this today. The godoc names the `t.Run("group", …)` idiom, and review of a new call site checks for it. |
| A non-child row swaps `slog.Default()` while a child row runs in the parent | Handled by construction; tested by the review's `-v` run of `TestPortErrors_RenewalLimiter`, where every child row's CONT follows the last sequential row | Parallel subtests start only after the parent's body, which contains every non-child row, returns (`testing` docs). |
| Children compete for CPU and one exceeds the one-minute budget | Handled by the existing guard; tested by measurement | The row fails with "the child did not finish within a minute". Decision 3's 20 s line catches the trend before that. |
| Memory pressure: up to `GOMAXPROCS` race-instrumented children at once, stack-overflow rows allowing 64 MB stacks | Accepted, measured | A child killed by the OS exits non-zero, and its row fails with the child's output. Implementation records the package's wall time; a failure here shows up as row failures, never as a pass. |
| A regression makes a cyclic error overflow the stack | Handled, unchanged | The child dies, and the parent's row fails with the first lines of its output. Concurrency does not merge rows, so the failing row is still named. |
| A child matches no row and exits 0 | Handled, unchanged | The parent finds no `marker+row` line and fails "the child printed no line … it did not run its row". |
| The package still exceeds 300 s after the change | Tested: task 2 measures it | Implementation stops and reports. Neither the target nor the timeout is relaxed. |

## Risks / Trade-offs

- **The speed-up depends on cores, and covers only the child rows.** The child rows' ~283 s divides by roughly `-parallel`. Slow rows that run in the parent and the tests that are already parallel do not change. → Task 2 measures the package locally and on CI, against the 300 s goal.
- **`-json` per-test `Elapsed` under-reports a test with child rows.** The parent's clock stops when its body returns, before its parallel rows run; `TestPortErrors_EnrolmentPorts` reports 0.1 s while its events span 3.2 s. → Measurements use the package's `Elapsed`, or event timestamps, never a parent test's `Elapsed`.
- **Interleaved output.** Concurrent subtests write their logs as they finish. → `go test` keeps each subtest's output under its own name, so a failure still names its row.
- **`-parallel 1` is slow.** It serialises the child rows and the tests that were already parallel, and was killed at the 10-minute default. → This is the override for debugging one row at a time, not a way to run the suite. Use it with `-run` or a longer `-timeout`.
- **Children outlive a dying parent.** When the parent process dies, for example from the `-timeout` panic, up to `-parallel` children are left running instead of one. → Accepted: each finishes within seconds, and the run has already failed.

## Measurements

Read on 2026-11-22 on the maintainer's machine: 14 CPUs, Go 1.27.4 darwin/arm64, `go test -race -count=1`. These drift as tests are added.

- **Before the change:**
  - with no timeout, the package `Elapsed` was 615.6 s;
  - under `-timeout 300s` (task 1.1) it failed with `panic: test timed out after 5m0s` while a `TestPortErrors_RequestBody` row ran.
- **After the change (task 1.2):** three runs under `-timeout 300s` passed.

  | Run | Package `Elapsed` | Slowest child row |
  |---|---|---|
  | Implementer, green | 242.3 s | 2.75 s, `TestPortErrors_RehashWrite/form_login/live/self-cycle_through_Unwrap()_[]error` |
  | Implementer, after the induced failures were edited back | 235.5 s | not reported |
  | Main session's verification, load average 2.7 at start | 234.1 s | 2.58 s, `TestPortErrors_RehashWrite/Basic/cancelled/self-cycle_through_Unwrap()_[]error` |

  Child rows are counted by their `pause` events: 236 rows in 26 top-level tests.
- **Under heavy outside load the 300 s goal does not hold.** One verification run failed at 300.9 s while another project's tests used about 6 CPUs and a VM about 2, with a load average of 43. The `make check` limit is 600 s, so this costs the goal, not the gate.
- **`-parallel 1`:** killed by the 10-minute default timeout at 601.1 s, because it also serialises the tests that were already parallel.
- **`make check` (task 2.2):** passed, with `httpsec` at 262.5 s while the task 2.4 reviewer ran beside it.
- **CI:** see task 2.3.

## Migration Plan

Test-only. Land it on a branch, check that CI's `test` legs pass within the target, and merge. Rollback is reverting one line in the helper.

## References

### Decision 1, the helper marks its subtest parallel; Decision 3, the budget under concurrency

**Researched (accessed 2026-11-22):**
- The per-test timings from `go test -race -count=1 -timeout 40m -json ./httpsec` on the maintainer's machine: 615.6 s in total, of which the 236 child-process rows took about 283 s. Local; it drifts.
- The `test` job log of CI run 45008682003: `httpsec` at 442.7 s and 464.4 s. Live; it drifts.
- A read-only audit of the call sites, spot-checked by the main session and corrected by the task 2.4 review (gopls references, a `-v` ordering run, and a reproduction of the `t.Setenv`/`t.Chdir` ancestor behaviour on Go 1.27.4), as summarised under Context.

**Primary documentation:**
- [`testing` package, "Subtests and Sub-benchmarks"](https://pkg.go.dev/testing#hdr-Subtests_and_Sub_benchmarks), with `T.Parallel` and `T.Setenv`: when parallel subtests start, the group tear-down idiom, and the panic rules. Checked with `go doc` on Go 1.27.4.
- [`go help testflag`](https://pkg.go.dev/cmd/go#hdr-Testing_flags): the `-parallel` and `-timeout` defaults. Checked locally on Go 1.27.4.

### Decision 2, grouping rows a parent depends on

**Primary documentation:**
- [`testing` package, "Subtests and Sub-benchmarks"](https://pkg.go.dev/testing#hdr-Subtests_and_Sub_benchmarks): the `TestTeardownParallel` example, where `Run` "will not return until the parallel tests finish".
