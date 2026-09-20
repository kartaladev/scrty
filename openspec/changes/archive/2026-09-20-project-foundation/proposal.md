## Why

scrty is a new, public Go library for authentication and authorization. Before any security package is written, it needs the ground those packages stand on:
- a module layout that keeps consumers free of dependencies they did not choose;
- build gates that catch formatting drift, stale generated code and leaked test tooling;
- a sortable identifier for the records scrty owns;
- a log sampler that bounds repeated refusal logs without losing count of what it suppressed.

## What Changes

- Create the core Go module `github.com/kartaladev/scrty` and a `go.work` workspace, with layout rules every later change follows:
  - integrations with third-party frameworks, drivers, schedulers and DI containers each live in their own nested module, created by the change that first needs it;
  - shared test helpers, conformance suites and the tests that use them live in a separate `github.com/kartaladev/scrty/test` module, created by the first change that needs one. No other scrty module imports it, not even from a `_test.go` file, because a test-only import still adds the helpers' drivers to that module's `go.mod` and so to every consumer's module graph;
  - generated mocks never enter a production build.
- Add `pkg/id`: a sortable identifier with a UUIDv7 default generator, a replaceable generator port, and text, JSON and `database/sql` encodings.
- Add `pkg/logsample`: a per-key, per-window log sampler whose suppressed counts can be complete. When a key's count would age out, it is passed to an optional reporter, and a flush operation reports everything pending.
- Add build gates, run per module both locally and in GitHub Actions:
  - a `golangci-lint` configuration with formatters enabled, plus an explicit `gofmt -l` check;
  - `go vet`, `go test -race` and `govulncheck`;
  - a check that `go generate` leaves the tree unchanged;
  - a dependency guard enforcing the layout rules.
- Amend the project's `use-testcontainers` skill so its helper-placement rule names the `test` module.

Not in this change: an ambient-transaction package. Each persistence adapter will own its own transaction context default plus a resolver option, so that work lands with the adapters.

## Capabilities

### New Capabilities

- `id-generation`: sortable identifiers for library-owned records: generation order, canonical encodings, parsing and a replaceable generator.
- `log-sampling`: bounding repeated log records per key per window while accounting for every suppressed event exactly once when a reporter is configured.
- `module-layout`: the dependency guarantees consumers rely on: what the core module's production build may import, where integrations and test helpers live, which Go releases are supported, and the gates that enforce this.

### Modified Capabilities

None. scrty has no existing specs.

## Impact

- **New code:** `go.mod`, `go.work`, `pkg/id`, `pkg/logsample`, `module_test.go`, `.golangci.yml`, `Makefile`, `.github/workflows/`, `LICENSE`, `README.md`.
- **Dependencies:** no third-party runtime dependency in the core module. UUIDv7 is implemented in `pkg/id` against RFC 9562, so its ordering guarantee rests on scrty's own tested code. Lint and mock tools are pinned as `tool` directives, which do not enter consumers' builds.
- **Project tooling:** `.claude/skills/use-testcontainers/SKILL.md` gains the `test` module placement rule.
- **Later changes:** identity, authentication, sessions, persistence, HTTP integration and every other security package build on `pkg/id`, `pkg/logsample` and the gates defined here.
- **Consumers:** none yet; nothing is tagged, so no compatibility obligations apply.
