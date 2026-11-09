## MODIFIED Requirements

### Requirement: Supported Go releases
Every scrty module SHALL declare Go 1.27 as its minimum version, and SHALL build and pass its tests on the latest patch release of every Go release the project supports that is at or above that minimum. The supported Go releases SHALL be the ones the security policy names.

#### Scenario: Continuous integration matrix
- **WHEN** a change is proposed to the repository
- **THEN** every module is built and tested on the latest patch release of each supported Go release, and a failure on any fails the run

#### Scenario: Declared minimum
- **WHEN** the `go` directive of every scrty module's `go.mod` is read
- **THEN** each declares `go 1.27`

## ADDED Requirements

### Requirement: Published modules resolve outside the repository
Every published scrty module SHALL be obtainable at a released version by a module outside this repository, with no workspace and no `replace` directive of its own. Each nested module's `go.mod` SHALL require the root module, and every sibling scrty module it uses, at the release version. A `replace` directive in a published `go.mod` SHALL point only inside this repository, and SHALL serve development only.

#### Scenario: Fresh consumer fetches a nested module
- **WHEN** an empty module outside the repository runs `go get github.com/kartaladev/scrty/store/pgxstore@v0.1.0` with the workspace off, and builds a program importing it
- **THEN** both commands succeed
- **AND** `go list -m all` lists `github.com/kartaladev/scrty v0.1.0`

#### Scenario: Nested module requires a version that does not exist
- **WHEN** a nested module's `go.mod` requires the root at `v0.0.0`
- **THEN** the release gate fails and names the module and the requirement

#### Scenario: Nested module builds without the workspace
- **WHEN** a nested module is built and tested with the workspace switched off
- **THEN** it builds and its tests pass
