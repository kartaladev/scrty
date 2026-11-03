# Spec Delta

## ADDED Requirements

### Requirement: The core module does not require OpenTelemetry
The core module SHALL NOT require `go.opentelemetry.io/otel` or any module under `go.opentelemetry.io/`. The telemetry seam SHALL live in the core package `pkg/telemetry` and import nothing outside the standard library. The OpenTelemetry implementation SHALL live in the nested module `github.com/kartaladev/scrty/pkg/telemetry/oteltelemetry`, which SHALL require the OpenTelemetry API and never its SDK.

#### Scenario: Consumer imports only the core
- **WHEN** a consumer module requires `github.com/kartaladev/scrty` and builds a program that gives a chain a telemetry observer of their own
- **THEN** no module under `go.opentelemetry.io/` appears in the consumer's `go list -m all` output as a result

#### Scenario: OpenTelemetry added to the core
- **WHEN** the core module's `go.mod` gains a requirement on `go.opentelemetry.io/otel`
- **THEN** the dependency check fails and names the module

#### Scenario: The adapter never requires the SDK
- **WHEN** the requirements of `github.com/kartaladev/scrty/pkg/telemetry/oteltelemetry` are listed
- **THEN** none is `go.opentelemetry.io/otel/sdk` or a module under it

## MODIFIED Requirements

### Requirement: Integration modules are published under the concept they extend
Each nested integration module SHALL have a module path under the directory of the core package whose concept it extends. Its package name SHALL be the last element of that path. A storage or rate-limit backend SHALL be named after its driver with a `store` suffix, so its package name never equals that of the driver library it wraps. The workspace SHALL contain no nested module other than the listed integrations, the test module and the tools module.

#### Scenario: Paths of the published integrations
- **WHEN** the repository's modules are listed, excluding the test and tools modules
- **THEN** the integrations are `github.com/kartaladev/scrty/authenticate/passkey/webauthn`, `.../store/pgxstore`, `.../store/gormstore`, `.../ratelimit/redisstore`, `.../expiry/sweep`, `.../httpsec/ginsec`, `.../httpsec/fibersec` and `.../pkg/telemetry/oteltelemetry`, each under `github.com/kartaladev/scrty`

#### Scenario: Package name matches the module path
- **WHEN** the package clause at the root of each integration module is read
- **THEN** it is `webauthn`, `pgxstore`, `gormstore`, `redisstore`, `sweep`, `ginsec`, `fibersec` or `oteltelemetry` respectively, the last element of its module path

#### Scenario: A backend does not shadow its driver
- **WHEN** a consumer source file imports `github.com/kartaladev/scrty/store/pgxstore` with `github.com/jackc/pgx/v5`, `github.com/kartaladev/scrty/store/gormstore` with `gorm.io/gorm`, or `github.com/kartaladev/scrty/ratelimit/redisstore` with `github.com/redis/go-redis/v9`
- **THEN** it compiles without an import alias for either package

#### Scenario: An integration module at an unlisted path
- **WHEN** the workspace gains a nested module, other than the test and tools modules, whose path is not one of the listed integrations, such as a `go.mod` left at a directory an integration moved from
- **THEN** the layout check fails and names the module's directory
