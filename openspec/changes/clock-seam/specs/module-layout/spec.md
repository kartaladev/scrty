# Spec Delta

## MODIFIED Requirements

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
