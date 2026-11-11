# Spec Delta

## ADDED Requirements

### Requirement: The core module does not require the OpenAPI reflector
The core module SHALL NOT require `github.com/invopop/jsonschema` at any version. OpenAPI document generation SHALL live in the nested module `github.com/kartaladev/scrty/httpsec/openapisec`, and no type of that reflector SHALL appear in that module's exported API.

#### Scenario: Consumer imports only the core
- **WHEN** a consumer module requires `github.com/kartaladev/scrty` and builds a program importing `httpsec`
- **THEN** `github.com/invopop/jsonschema` does not appear in the consumer's `go list -m all` output as a result

#### Scenario: Reflector added to the core
- **WHEN** the core module's `go.mod` gains a requirement on `github.com/invopop/jsonschema`
- **THEN** the dependency check fails and names the module

#### Scenario: Reflector types stay inside the module
- **WHEN** the exported API of `github.com/kartaladev/scrty/httpsec/openapisec` is listed
- **THEN** no exported function, method, field or type refers to a type of `github.com/invopop/jsonschema`

## MODIFIED Requirements

### Requirement: Integration modules are published under the concept they extend
Each nested integration module SHALL have a module path under the directory of the core package whose concept it extends. Its package name SHALL be the last element of that path. A storage or rate-limit backend SHALL be named after its driver with a `store` suffix, so its package name never equals that of the driver library it wraps. The workspace SHALL contain no nested module other than the listed integrations, the test module and the tools module.

#### Scenario: Paths of the published integrations
- **WHEN** the repository's modules are listed, excluding the test and tools modules
- **THEN** the integrations are `github.com/kartaladev/scrty/authenticate/passkey/webauthn`, `.../store/pgxstore`, `.../store/gormstore`, `.../ratelimit/redisstore`, `.../expiry/sweep`, `.../httpsec/ginsec`, `.../httpsec/fibersec` and `.../httpsec/openapisec`, each under `github.com/kartaladev/scrty`

#### Scenario: Package name matches the module path
- **WHEN** the package clause at the root of each integration module is read
- **THEN** it is `webauthn`, `pgxstore`, `gormstore`, `redisstore`, `sweep`, `ginsec`, `fibersec` or `openapisec` respectively, the last element of its module path

#### Scenario: A backend does not shadow its driver
- **WHEN** a consumer source file imports `github.com/kartaladev/scrty/store/pgxstore` with `github.com/jackc/pgx/v5`, `github.com/kartaladev/scrty/store/gormstore` with `gorm.io/gorm`, or `github.com/kartaladev/scrty/ratelimit/redisstore` with `github.com/redis/go-redis/v9`
- **THEN** it compiles without an import alias for either package

#### Scenario: An integration module at an unlisted path
- **WHEN** the workspace gains a nested module, other than the test and tools modules, whose path is not one of the listed integrations, such as a `go.mod` left at a directory an integration moved from
- **THEN** the layout check fails and names the module's directory
