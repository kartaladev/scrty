## 1. Module skeleton

- [x] 1.1 Create the core `go.mod` (`module github.com/kartaladev/scrty`, `go 1.26`) and a `go.work` that lists it; verify `go work edit -json` lists the module and `go build ./...` succeeds
- [x] 1.2 Add `LICENSE` (license per the design's open question, resolved with the user first) and a `README.md` stating the module layout, the supported Go versions and that `pkg/id` identifiers are not secrets; verify both files exist and the README names Go 1.26 and 1.27

## 2. Dependency guard (module-layout)

- [x] 2.1 Test-first: add a `testdata/` fixture module whose non-test file imports `github.com/stretchr/testify/require`, and a test expecting the guard to fail naming the package and module; watch it fail, implement the production-import walk in `module_test.go`, and verify `go test -run TestModuleLayout -count=1 .` passes against both the fixture and the real tree
- [x] 2.2 Test-first: add fixtures for a test-only testify import (must pass), an exported `Mock*` type in a production file, and imports of `github.com/kartaladev/scrty/test` from both a production file and a `_test.go` file (all three must fail, naming the file and symbol); verify each case goes red before the check exists and green after
- [x] 2.3 Test-first: add fixture `go.mod` files requiring `github.com/gin-gonic/gin` and `github.com/kartaladev/scrty/test`, with tests expecting the guard to fail and name the module; implement the `go.mod` requirement check (direct requirements on integration modules, and any requirement on the test module); verify both tests pass and the real `go.mod` passes
- [x] 2.4 Test-first: add `TestConsumerModuleGraph`. It uses fixture module graphs under `testdata/graph/`: a `clean` graph where only the helper module requires a stub driver, and a `leaky` control graph where the core's `_test.go` imports the helper. It also uses a consumer of the real core, created in a temporary directory. Verify with `go list -m all` in each consumer: the clean consumer shows neither the driver nor the helper, the leaky control shows the driver, and the real-core consumer shows none of the integration modules. Temporarily add the helper requirement to the clean fixture's core and confirm the test fails, then revert

## 3. pkg/id (id-generation)

- [x] 3.1 Test-first: `ID` zero value, `Nil` and `IsZero`; verify `go test -run 'TestID_IsZero' ./pkg/id` was seen red, then green
- [x] 3.2 Test-first: `String` and strict `Parse` as one table test (RFC 9562 A.6 vector, uppercase input, every rejected layout from the spec, a v4 UUID parsing unchanged); verify red then green, and that errors identify the input as an invalid identifier
- [x] 3.3 Test-first: `MarshalText`/`UnmarshalText` for JSON (encode, reject `42` and `""`, `omitzero` omission); verify red then green
- [x] 3.4 Test-first: `Scan`/`Value` (string, 36-byte and 16-byte `[]byte`, `NULL` rejected, 15-byte and malformed rejected leaving the value unchanged); verify red then green. The spec's native PostgreSQL `uuid` round-trip scenario needs a database, so it is verified by the persistence change's integration tests in the `test` module, not here
- [x] 3.5 Test-first: `V7Generator` layout with a fixed clock and random source (version 7, variant `10`, 48-bit millisecond timestamp for 2022-02-22T19:22:22Z, identical sequences from identically configured generators); verify red then green
- [x] 3.6 Test-first: ordering (100,000 identifiers under a frozen clock strictly increasing bytewise and as strings; backwards clock still increasing; counter overflow advances the timestamp by 1 ms, forced by an in-package test that sets the counter to its maximum, because a seed can never start within 2^25 of the limit; T+1 across generators sorts later); verify red then green
- [x] 3.7 Test-first: concurrency (64 goroutines, no duplicates, byte order equals string order) under `go test -race`, plus a failing random source returning a wrapped error and no identifier; verify red then green
- [x] 3.8 Add `FuzzParse` (formatted identifiers round-trip; arbitrary strings either fail or round-trip to their lowercase form) and godoc with an `ExampleNewV7Generator` that states identifiers are not secrets and names each option's default; verify `go test -run=^$ -fuzz=FuzzParse -fuzztime=30s ./pkg/id` finds nothing and `go test ./pkg/id` runs the example
- [x] 3.9 Refactor: run `/simplify` over `pkg/id`, then verify `go test -race -count=1 ./pkg/id` is green

## 4. pkg/logsample (log-sampling)

- [x] 4.1 Test-first: one table test for the core `Allow` semantics (first event writes, later events suppressed, independent keys, count carried into the next window, zero when nothing suppressed); verify red then green
- [x] 4.2 Test-first: disabled sampling (zero and negative window, nil sampler) and the backwards-clock scenario from the spec; verify red then green
- [x] 4.3 Test-first: `WithReporter` on rotation (key goes quiet for one window, long silence drops both windows, keys with nothing suppressed are not reported, a later event for a reported key carries 0); verify red then green
- [x] 4.4 Test-first: `Flush` with and without a reporter, and discarded counts without a reporter (the lower-bound default); verify red then green
- [x] 4.5 Test-first: bounded memory (one million keys, then one event after more than two windows retains at most one key, observed through an in-package test of map sizes) and a reporter that calls `Allow` without deadlocking; verify red then green
- [x] 4.6 Test-first: randomized totals-balance property (suppressed counts on writes plus reporter counts equal events suppressed, after a final `Flush`), sequentially and with 64 goroutines under `-race`; verify red against an implementation that skips reporting on two-window rotation, then green
- [x] 4.7 Godoc stating the lower-bound default, that the reporter runs on the caller's goroutine after the lock is released and must be fast and must not panic, and naming each option's default; add an `ExampleNew`; verify `go doc ./pkg/logsample` shows them and the example runs
- [x] 4.8 Refactor: run `/simplify` over `pkg/logsample`, then verify `go test -race -count=1 ./pkg/logsample` is green

## 5. Build gates (module-layout)

- [x] 5.1 Add a separate `tools` module (`tools/go.mod`, not listed in `go.work`) with `tool` directives for golangci-lint v2.13.x, mockgen v0.6.0 and govulncheck. Add a `make tools` target that installs them into a git-ignored `.bin/` with `go install tool`. Verify `.bin/golangci-lint version`, `.bin/mockgen --version` and `.bin/govulncheck -version` run, and that the core `go.mod` gains no tool requirements
- [x] 5.2 Add `.golangci.yml` (v2 schema, `gofmt` and `goimports` formatters, the linter set from the design); verify `go tool golangci-lint run ./...` is clean, and that a deliberately misformatted file makes it fail before being reverted
- [x] 5.3 Add a `Makefile` whose `check` target runs, for every module in `go work edit -json`: `gofmt -l`, `go vet`, `golangci-lint run`, `go test -race`, `govulncheck` and `go generate` with `git diff --exit-code`; verify `make check` passes on a clean tree and fails, naming the file, for each injected fault (unformatted file, vet finding, stale generated file), each reverted afterwards
- [x] 5.4 Add `.github/workflows/ci.yml` running `make check` on Go 1.26.x and 1.27.x for pushes and pull requests; verify the workflow runs green on both matrix entries after it is pushed

## 6. Project conventions and final verification

- [x] 6.1 Amend `.claude/skills/use-testcontainers/SKILL.md`: for scrty, shared helpers, conformance suites and the tests that use them live in `github.com/kartaladev/scrty/test`, and no other scrty module imports it, test files included. State the reason: a test-only import still adds the helpers' drivers to that module's `go.mod` and to consumers' module graphs. Verify the skill's helper-layout section states the rule
- [x] 6.2 Final gate: verify `make check` is green locally on Go 1.27 and in CI on Go 1.26 and 1.27, and `openspec validate project-foundation --strict` passes
