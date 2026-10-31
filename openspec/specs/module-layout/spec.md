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
Integrations with third-party frameworks, drivers, containers and protocol libraries SHALL be published as modules nested under `github.com/kartaladev/scrty/`, so importing the core module does not add them to a consumer's module graph. The core module SHALL NOT require `github.com/gin-gonic/gin`, `github.com/gofiber/fiber`, `gorm.io/gorm`, `github.com/jackc/pgx`, `github.com/go-co-op/gocron`, `github.com/samber/do`, `github.com/go-webauthn/webauthn`, `github.com/fxamacker/cbor`, `github.com/google/go-tpm`, `github.com/redis/go-redis`, `github.com/pressly/goose`, `github.com/testcontainers/testcontainers-go/modules/postgres` or `github.com/testcontainers/testcontainers-go/modules/redis`, at any major version. WebAuthn verification SHALL live in the nested module `github.com/kartaladev/scrty/authenticate/passkey/webauthn`, which implements the core's passkey verification port. No type of the WebAuthn library SHALL appear in that module's exported API, nor in the core module's.

#### Scenario: Consumer imports only the core
- **WHEN** a consumer module requires `github.com/kartaladev/scrty` and builds a program importing its packages
- **THEN** none of the listed framework, driver, scheduler, DI or WebAuthn modules appear in the consumer's `go list -m all` output as a result

#### Scenario: Integration requirement added to the core
- **WHEN** the core module's `go.mod` gains a requirement on any listed module
- **THEN** the dependency check fails and names the module

#### Scenario: Listed module at a major-version path
- **WHEN** the core module's `go.mod` gains a requirement on a major-version path of a listed module, such as `github.com/jackc/pgx/v5`, `github.com/redis/go-redis/v9` or `github.com/go-co-op/gocron/v2`
- **THEN** the dependency check fails and names the module as required

#### Scenario: Passkeys without the WebAuthn library
- **WHEN** a consumer imports the core package `github.com/kartaladev/scrty/authenticate/passkey` and supplies their own verifier
- **THEN** `github.com/go-webauthn/webauthn` does not appear in the consumer's `go list -m all` output

#### Scenario: WebAuthn types stay inside the adapter
- **WHEN** the exported API of `github.com/kartaladev/scrty/authenticate/passkey/webauthn` is listed
- **THEN** no exported function, method, field or type refers to a type of `github.com/go-webauthn/webauthn`

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
Every scrty module SHALL declare Go 1.27 as its minimum version, and SHALL build and pass its tests on the latest patch release of every Go release the project supports that is at or above that minimum. The supported Go releases SHALL be the ones the security policy names.

#### Scenario: Continuous integration matrix
- **WHEN** a change is proposed to the repository
- **THEN** every module is built and tested on the latest patch release of each supported Go release, and a failure on any fails the run

#### Scenario: Declared minimum
- **WHEN** the `go` directive of every scrty module's `go.mod` is read
- **THEN** each declares `go 1.27`

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

### Requirement: Integration modules are published under the concept they extend
Each nested integration module SHALL have a module path under the directory of the core package whose concept it extends. Its package name SHALL be the last element of that path. A storage or rate-limit backend SHALL be named after its driver with a `store` suffix, so its package name never equals that of the driver library it wraps. The workspace SHALL contain no nested module other than the listed integrations, the test module and the tools module.

#### Scenario: Paths of the published integrations
- **WHEN** the repository's modules are listed, excluding the test and tools modules
- **THEN** the integrations are `github.com/kartaladev/scrty/authenticate/passkey/webauthn`, `.../store/pgxstore`, `.../store/gormstore`, `.../ratelimit/redisstore`, `.../expiry/sweep`, `.../httpsec/ginsec` and `.../httpsec/fibersec`, each under `github.com/kartaladev/scrty`

#### Scenario: Package name matches the module path
- **WHEN** the package clause at the root of each integration module is read
- **THEN** it is `webauthn`, `pgxstore`, `gormstore`, `redisstore`, `sweep`, `ginsec` or `fibersec` respectively, the last element of its module path

#### Scenario: A backend does not shadow its driver
- **WHEN** a consumer source file imports `github.com/kartaladev/scrty/store/pgxstore` with `github.com/jackc/pgx/v5`, `github.com/kartaladev/scrty/store/gormstore` with `gorm.io/gorm`, or `github.com/kartaladev/scrty/ratelimit/redisstore` with `github.com/redis/go-redis/v9`
- **THEN** it compiles without an import alias for either package

#### Scenario: An integration module at an unlisted path
- **WHEN** the workspace gains a nested module, other than the test and tools modules, whose path is not one of the listed integrations, such as a `go.mod` left at a directory an integration moved from
- **THEN** the layout check fails and names the module's directory
