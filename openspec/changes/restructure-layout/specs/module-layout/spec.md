# Spec Delta

## MODIFIED Requirements

### Requirement: Framework and driver integrations are separate modules
Integrations with third-party frameworks, drivers, containers and protocol libraries SHALL be published as modules nested under `github.com/kartaladev/scrty/`, so importing the core module does not add them to a consumer's module graph. The core module SHALL NOT require `github.com/gin-gonic/gin`, `github.com/gofiber/fiber`, `gorm.io/gorm`, `github.com/jackc/pgx`, `github.com/go-co-op/gocron`, `github.com/samber/do`, `github.com/go-webauthn/webauthn`, `github.com/fxamacker/cbor`, `github.com/google/go-tpm`, `github.com/redis/go-redis`, `github.com/pressly/goose`, `github.com/testcontainers/testcontainers-go/modules/postgres` or `github.com/testcontainers/testcontainers-go/modules/redis`. WebAuthn verification SHALL live in the nested module `github.com/kartaladev/scrty/authenticate/passkey/webauthn`, which implements the core's passkey verification port. No type of the WebAuthn library SHALL appear in that module's exported API, nor in the core module's.

#### Scenario: Consumer imports only the core
- **WHEN** a consumer module requires `github.com/kartaladev/scrty` and builds a program importing its packages
- **THEN** none of the listed framework, driver, scheduler, DI or WebAuthn modules appear in the consumer's `go list -m all` output as a result

#### Scenario: Integration requirement added to the core
- **WHEN** the core module's `go.mod` gains a requirement on any listed module
- **THEN** the dependency check fails and names the module

#### Scenario: Passkeys without the WebAuthn library
- **WHEN** a consumer imports the core `passkey` package and supplies their own verifier
- **THEN** `github.com/go-webauthn/webauthn` does not appear in the consumer's `go list -m all` output

#### Scenario: WebAuthn types stay inside the adapter
- **WHEN** the exported API of `github.com/kartaladev/scrty/authenticate/passkey/webauthn` is listed
- **THEN** no exported function, method, field or type refers to a type of `github.com/go-webauthn/webauthn`

### Requirement: Supported Go releases
Every scrty module SHALL declare Go 1.27 as its minimum version, and SHALL build and pass its tests on the latest patch release of Go 1.27.

#### Scenario: Continuous integration matrix
- **WHEN** a change is proposed to the repository
- **THEN** every module is built and tested on the latest patch release of Go 1.27, and a failure fails the run

## ADDED Requirements

### Requirement: Integration modules are published under the concept they extend
Each nested integration module SHALL have a module path under the directory of the core package whose concept it extends, or directly under the module root when it extends the library as a whole. Its package name SHALL be the last element of that path. A storage or rate-limit backend SHALL be named after its driver with a `store` suffix, so its package name never equals that of the driver library it wraps.

#### Scenario: Paths of the published integrations
- **WHEN** the repository's modules are listed, excluding the test and tools modules
- **THEN** the integrations are `github.com/kartaladev/scrty/authenticate/passkey/webauthn`, `.../store/pgxstore`, `.../store/gormstore`, `.../ratelimit/redisstore`, `.../expiry/sweep`, `.../httpsec/ginsec` and `.../httpsec/fibersec`, each under `github.com/kartaladev/scrty`

#### Scenario: Package name matches the module path
- **WHEN** the package clause at the root of each integration module is read
- **THEN** it is `webauthn`, `pgxstore`, `gormstore`, `redisstore`, `sweep`, `ginsec` or `fibersec` respectively, the last element of its module path

#### Scenario: A backend does not shadow its driver
- **WHEN** a consumer source file imports both `github.com/kartaladev/scrty/store/pgxstore` and `github.com/jackc/pgx/v5`
- **THEN** it compiles without an import alias for either package
