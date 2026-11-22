# Proposal

## Why

The `httpsec` test package no longer fits inside `go test`'s default 10-minute timeout, so `make check` fails on a clean `main`.

Measured 2026-11-22 (all these figures drift as tests are added):
- **Locally:** `go test -race -count=1 ./httpsec` on the maintainer's Mac (14 CPUs) took 615.6 s. Every one of its 911 top-level tests passed, but the package as a whole was killed at 600 s. This happened inside `make check` and again with the package run alone.
- **In CI:** the `test` legs of run 45008682003 took 442.7 s and 464.4 s, about three quarters of the limit. CI is still green, but the next few port-error tests will push it over too.

Nearly all of the time goes to one test pattern:
- **Who runs them.** The `TestPortErrors_*` tests and a few siblings check how the chain handles hostile errors from consumer ports, such as cyclic `Unwrap` chains.
- **The child processes.** A stack overflow is fatal to the Go runtime, and a test cannot recover from it. So the rows that guard against one re-run the test binary in a child process, one row per child. There are 236 such rows, in 26 top-level tests, each taking about 1 to 3 s under `-race`: about 283 s in total, almost half the package's runtime. The rest is mostly slow rows that run inside the parent process, and tests that are already parallel. This change leaves both alone.
- **Why they run one at a time.** The enclosing tests are not parallel because they replace the process-wide `slog.Default()` to assert that nothing reaches it. Every child therefore waits for the previous one, although a child row never touches the parent's `slog.Default()`.

The failure also breaks the `module-layout` promise that a clean checkout which passes CI also passes the local gate command. It blocks `split-ci-jobs` task 4.5, and with it every change sequenced behind `split-ci-jobs`.

## What Changes

- **Child-process rows run concurrently.** The single helper every such row already goes through, `limiterPortErrInChild`, marks its subtest parallel before starting the child. The rows that run in the parent process, which do swap `slog.Default()`, keep running one at a time, as they do today.
- **What each child row checks stays the same:**
  - the child must exit 0 within its time budget;
  - it must print its row's marker, so a row name that matches nothing still fails;
  - the parent reports the first lines of a failing child's output.
- **Call sites that cannot be made parallel are fixed or exempted, never left to panic.** A parent whose code after its loop depends on the child rows having finished is restructured. If it cannot be, it opts out of the concurrency, and the exception is recorded in the design.
- **Target:** the package runs well inside the 600 s limit on both the maintainer's machine and CI. The figures are recorded before and after.
- **Not in scope:**
  - changing `make test`'s `-timeout`, `-p`, `-parallel` or `-race` settings;
  - removing the child-process guard, or merging rows into fewer children (see design);
  - the parent-process rows' use of `slog.Default()`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None. This changes how a test package runs, not any specified behaviour of the library, so the change opts out of specs (`skip_specs: true`). The `module-layout` local and CI parity scenario is restored by the change, not modified.

## Impact

- **Test code only, in package `httpsec`:**
  - the helper `limiterPortErrInChild` in `httpsec/mfa_enrol_porterr_test.go`;
  - where the design requires it, the call sites in the port-error test files (`httpsec/*_porterr_test.go`, `httpsec/apikey_cause_test.go`, `httpsec/signin_notice_test.go`).
- **No library code, public API, dependency, `Makefile` or CI workflow change.**
- **Sequencing:** unblocks `split-ci-jobs` task 4.5, after which `split-ci-jobs` can be archived and `oidc-provider-device-grant` can start.

## References

### Child-process rows run concurrently

**Researched (accessed 2026-11-22):**
- `go test -race -count=1 -timeout 40m -json ./httpsec` on the maintainer's machine: per-test and per-subtest elapsed times, the 615.6 s package total and the ~283 s spent in the 236 child-process rows. The rows were identified exactly by implementation, from the `pause` events of a run after the change. An earlier count of "395 rows, ~501 s" took every leaf subtest of 0.5 s or more as a child row and was wrong. Local measurement; it drifts.
- The `test` job log of CI run 45008682003: `httpsec` at 442.7 s and 464.4 s. Live; it drifts.

**Primary documentation:**
- [`testing` package, "Subtests and Sub-benchmarks"](https://pkg.go.dev/testing#hdr-Subtests_and_Sub_benchmarks): grouped parallel subtests run "in parallel with each other, and only with each other, regardless of other top-level tests". `Run` does not return until parallel subtests have completed, and the `t.Run("group", …)` idiom is the documented way to tear down after them. `T.Parallel` "pauses until all non-parallel tests have finished", and `T.Setenv` "cannot be used in parallel tests or tests with parallel ancestors". Checked with `go doc` on Go 1.27.4.
- [`go help testflag`](https://pkg.go.dev/cmd/go#hdr-Testing_flags): `-parallel` defaults to `GOMAXPROCS`, and `-timeout` defaults to 10 minutes. Checked locally on Go 1.27.4.
