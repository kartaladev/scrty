## Purpose

States how the repository pins, updates, scans and describes what it builds from, so a compromised dependency or CI action cannot silently enter a scrty release.

## ADDED Requirements

### Requirement: CI actions are pinned to commit SHAs
Every third-party action and reusable workflow used by the repository's CI workflows SHALL be referenced by a full 40-character commit SHA, with the release tag it corresponds to recorded beside it, and every container action by an image digest. Actions local to the repository SHALL be exempt. A CI check SHALL fail when a workflow references an action by a tag, a branch or a short SHA.

#### Scenario: Tag reference
- **WHEN** a workflow change references `actions/checkout@v5`
- **THEN** the pinning check fails, naming the workflow and the action

#### Scenario: Short SHA
- **WHEN** a workflow change references an action by a 7-character SHA
- **THEN** the pinning check fails

#### Scenario: Local action
- **WHEN** a workflow references `./.github/actions/setup`
- **THEN** the pinning check passes for that reference

### Requirement: Dependency updates are proposed automatically
The repository SHALL configure automated update proposals for Go modules in every module in the workspace, nested modules included, and in the tools module, and for GitHub Actions, on at least a weekly schedule. A repository check SHALL fail when a workspace module has no update entry. Once the repository's Dependabot security-updates setting is enabled, which no configuration file can enable and the README SHALL say so, security updates SHALL be proposed as soon as they are published. Every proposal SHALL be a pull request left open for a maintainer to review and merge: no workflow in the repository SHALL approve or merge one automatically, and the repository check SHALL fail when one does.

#### Scenario: New action release
- **WHEN** a pinned action publishes a new release
- **THEN** an update is proposed that moves the pin to the new release's commit SHA and tag

#### Scenario: Nested module
- **WHEN** a dependency of the gin adapter module publishes a new release
- **THEN** an update is proposed for that module

#### Scenario: Every module covered
- **WHEN** a module is added to `go.work` without an update entry
- **THEN** the repository check fails, naming the module

#### Scenario: Never merged automatically
- **WHEN** an update is proposed
- **THEN** it is opened as a pull request and stays open until a maintainer merges it

#### Scenario: Auto-merge workflow refused
- **WHEN** a workflow change approves or enables auto-merge for a pull request
- **THEN** the repository check fails, naming the workflow

### Requirement: The release gate produces a software bill of materials for each published module
The release gate SHALL produce, for each published module, a software bill of materials listing the module's dependencies and their versions in a standard format, and SHALL fail when one cannot be produced. Attaching them to a published release is the release workflow's requirement, not this one.

#### Scenario: Release gate run
- **WHEN** the release gate runs
- **THEN** a bill of materials is written for each published module

#### Scenario: Bill of materials cannot be produced
- **WHEN** the bill of materials for a published module cannot be produced
- **THEN** the release gate fails, naming the module

### Requirement: Known vulnerabilities block a release
The release gate SHALL run the Go vulnerability check against every published module and SHALL fail when a reachable vulnerability is reported.

#### Scenario: Reachable vulnerability
- **WHEN** the vulnerability check reports a reachable vulnerability in a published module
- **THEN** the release gate fails, naming the module and the vulnerability
