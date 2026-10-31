## Purpose

States how the repository pins, updates, scans and describes what it builds from, so a compromised dependency or CI action cannot silently enter a scrty release.

## ADDED Requirements

### Requirement: CI actions are pinned to commit SHAs
Every third-party action used by the repository's CI workflows SHALL be referenced by a full commit SHA, with the release tag it corresponds to recorded beside it. A CI check SHALL fail when a workflow references an action by a tag or branch.

#### Scenario: Tag reference
- **WHEN** a workflow change references `actions/checkout@v5`
- **THEN** the pinning check fails, naming the workflow and the action

### Requirement: Dependency updates are proposed automatically
The repository SHALL configure automated update proposals for Go modules in every published module and for GitHub Actions, on at least a weekly schedule. Security updates SHALL be proposed as soon as they are published.

#### Scenario: New action release
- **WHEN** a pinned action publishes a new release
- **THEN** an update is proposed that moves the pin to the new release's commit SHA and tag

### Requirement: Every release carries a software bill of materials
Every release SHALL publish, for each published module, a software bill of materials listing the module's dependencies and their versions in a standard format. The release gate SHALL fail when one cannot be produced.

#### Scenario: Release
- **WHEN** a release is tagged
- **THEN** a bill of materials for each published module is attached to the release

### Requirement: Known vulnerabilities block a release
The release gate SHALL run the Go vulnerability check against every published module and SHALL fail when a reachable vulnerability is reported.

#### Scenario: Reachable vulnerability
- **WHEN** the vulnerability check reports a reachable vulnerability in a published module
- **THEN** the release gate fails, naming the module and the vulnerability
