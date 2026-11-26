## MODIFIED Requirements

### Requirement: Build gates reject unformatted, unvetted, vulnerable or stale code
For every module, the build gates SHALL fail when any Go file is not `gofmt`-formatted, when `go vet` or the configured linters report a finding, when `go test -race` fails, when `govulncheck` reports a vulnerability reachable from the module's code, or when running `go generate` would change a committed file. The same gates SHALL run locally through one command, and in continuous integration as one job per gate.

#### Scenario: Formatting drift
- **WHEN** a Go file in any module is not `gofmt`-formatted
- **THEN** the gates fail and name the file

#### Scenario: Stale generated mock
- **WHEN** an interface changes without its generated mock being regenerated
- **THEN** the gates fail and show the diff `go generate` would produce

#### Scenario: Local and CI parity
- **WHEN** a contributor runs the local gate command on a clean checkout that passes CI
- **THEN** it passes, having run the same build gates that CI's gate jobs run

#### Scenario: One gate run on its own
- **WHEN** a contributor runs the local command for a single gate, such as lint, on a fresh checkout
- **THEN** it installs the tool that gate needs, at the version the repository pins, and runs only that gate

#### Scenario: Checks that run only in CI
- **WHEN** CI runs code scanning and spec validation
- **THEN** neither is part of the local gate command, and the local gate command needs neither CodeQL nor the OpenSpec CLI
