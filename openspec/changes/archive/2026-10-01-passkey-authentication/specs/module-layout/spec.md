# Spec Delta

## MODIFIED Requirements

### Requirement: Framework and driver integrations are separate modules
Integrations with third-party frameworks, drivers, containers and protocol libraries SHALL be published as modules nested under `github.com/kartaladev/scrty/`, so importing the core module does not add them to a consumer's module graph. The core module SHALL NOT require `github.com/gin-gonic/gin`, `github.com/gofiber/fiber`, `gorm.io/gorm`, `github.com/jackc/pgx`, `github.com/go-co-op/gocron`, `github.com/samber/do`, `github.com/go-webauthn/webauthn`, `github.com/fxamacker/cbor` or `github.com/google/go-tpm`. WebAuthn verification SHALL live in the nested module `github.com/kartaladev/scrty/passkey/webauthn`, which implements the core's passkey verification port. No type of the WebAuthn library SHALL appear in that module's exported API, nor in the core module's.

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
- **WHEN** the exported API of `github.com/kartaladev/scrty/passkey/webauthn` is listed
- **THEN** no exported function, method, field or type refers to a type of `github.com/go-webauthn/webauthn`
