# module-layout Specification

## Purpose

Defines the dependency guarantees consumers of scrty rely on: what importing the core module brings into their build, where framework integrations and test helpers live, and which Go releases are supported.

## Requirements

### Requirement: The core module's production build excludes test tooling
The production build of every package in `github.com/kartaladev/scrty`, meaning its non-test files and their transitive imports, SHALL NOT import `go.uber.org/mock`, `github.com/stretchr/testify`, `github.com/testcontainers/testcontainers-go` or `github.com/jonboulle/clockwork`. This SHALL be enforced by a check that fails the build gates.

#### Scenario: Forbidden import introduced
- **WHEN** a non-test file in the core module imports `github.com/stretchr/testify/require`
- **THEN** the dependency check fails and names the importing package and the forbidden module

#### Scenario: Fake clock in production code
- **WHEN** a non-test file in the core module imports `github.com/jonboulle/clockwork`
- **THEN** the dependency check fails and names the importing package and the forbidden module

#### Scenario: Test-only use
- **WHEN** a `_test.go` file in the core module imports `github.com/stretchr/testify/require`
- **THEN** the dependency check passes

### Requirement: No mock types in production builds
No production file in any scrty module SHALL declare an exported type whose name begins with `Mock`. Generated mocks SHALL live in `_test.go` files, or in test-double packages that production packages never import.

#### Scenario: Mock generated into a production file
- **WHEN** a non-test file declares `type MockStore struct`
- **THEN** the dependency check fails and names the file and type

### Requirement: Framework and driver integrations are separate modules
Integrations with third-party frameworks, drivers and containers SHALL be published as modules nested under `github.com/kartaladev/scrty/`, so importing the core module does not add them to a consumer's module graph. The core module SHALL NOT require `github.com/gin-gonic/gin`, `github.com/gofiber/fiber`, `gorm.io/gorm`, `github.com/jackc/pgx`, `github.com/go-co-op/gocron` or `github.com/samber/do`.

#### Scenario: Consumer imports only the core
- **WHEN** a consumer module requires `github.com/kartaladev/scrty` and builds a program importing its packages
- **THEN** none of the listed framework, driver, scheduler or DI modules appear in the consumer's `go list -m all` output as a result

#### Scenario: Integration requirement added to the core
- **WHEN** the core module's `go.mod` gains a requirement on any listed module
- **THEN** the dependency check fails and names the module

### Requirement: Shared test helpers and the tests that use them live in the test module
Test helpers and conformance suites shared across scrty modules SHALL live in the module `github.com/kartaladev/scrty/test`. No other scrty module SHALL import it from any file, test files included, and no other scrty module's `go.mod` SHALL require it. Integration tests and conformance-suite runs that need those helpers SHALL live in the test module, which imports the modules under test.

#### Scenario: Production import of the test module
- **WHEN** a non-test file in any scrty module imports `github.com/kartaladev/scrty/test`
- **THEN** the dependency check fails and names the importing file

#### Scenario: Test-file import of the test module
- **WHEN** a `_test.go` file in the core module imports `github.com/kartaladev/scrty/test`
- **THEN** the dependency check fails and names the importing file

#### Scenario: Helper drivers stay out of consumers' module graphs
- **WHEN** the test module requires a PostgreSQL driver and testcontainers, and a consumer module requires only the core module
- **THEN** neither the driver nor testcontainers appears in the consumer's `go list -m all` output

### Requirement: Supported Go releases
Every scrty module SHALL declare Go 1.26 as its minimum version, and SHALL build and pass its tests on both Go 1.26 and Go 1.27.

#### Scenario: Continuous integration matrix
- **WHEN** a change is proposed to the repository
- **THEN** every module is built and tested on the latest patch releases of Go 1.26 and Go 1.27, and a failure on either fails the run

### Requirement: Build gates reject unformatted, unvetted, vulnerable or stale code
For every module, the build gates SHALL fail when any Go file is not `gofmt`-formatted, when `go vet` or the configured linters report a finding, when `go test -race` fails, when `govulncheck` reports a vulnerability reachable from the module's code, or when running `go generate` would change a committed file. The same gates SHALL run locally through one command and in continuous integration.

#### Scenario: Formatting drift
- **WHEN** a Go file in any module is not `gofmt`-formatted
- **THEN** the gates fail and name the file

#### Scenario: Stale generated mock
- **WHEN** an interface changes without its generated mock being regenerated
- **THEN** the gates fail and show the diff `go generate` would produce

#### Scenario: Local and CI parity
- **WHEN** a contributor runs the local gate command on a clean checkout that passes CI
- **THEN** it passes with the same set of checks
