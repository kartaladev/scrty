## Purpose

Defines how scrty versions, gates, tags and announces its releases, and how vulnerabilities are reported and disclosed, so that consumers can depend on a released version and know what it promises.

## ADDED Requirements

### Requirement: Modules are released in lockstep with directory-prefixed tags
Every release SHALL give all published modules the same semantic version. The root module SHALL be tagged `vX.Y.Z`, and each nested module SHALL be tagged with its directory path as prefix, `<dir>/vX.Y.Z`, at the same commit. The published modules SHALL be the root, `httpsec/fibersec`, `httpsec/ginsec`, `store/gormstore`, `authenticate/passkey/webauthn`, `store/pgxstore`, `ratelimit/redisstore`, `expiry/sweep` and `test`. The `tools` module SHALL never be tagged.

#### Scenario: First release
- **WHEN** version `v0.1.0` is released
- **THEN** the tags `v0.1.0`, `httpsec/fibersec/v0.1.0`, `httpsec/ginsec/v0.1.0`, `store/gormstore/v0.1.0`, `authenticate/passkey/webauthn/v0.1.0`, `store/pgxstore/v0.1.0`, `ratelimit/redisstore/v0.1.0`, `expiry/sweep/v0.1.0` and `test/v0.1.0` exist and name one commit
- **AND** no tag carries the `tools/` prefix

#### Scenario: A module without changes
- **WHEN** a release changes only the root module
- **THEN** every published module is still tagged at the new version

### Requirement: A published version is never changed
A pushed release tag SHALL NOT be moved or deleted. A defective release SHALL be superseded by a new version, and SHALL be retracted in that version's `go.mod` when consumers must not select it.

#### Scenario: Defective release
- **WHEN** a defect is found in a published `v0.1.0`
- **THEN** the fix is released as `v0.1.1` with a `retract v0.1.0` directive where the defect makes `v0.1.0` unsafe to select, and the `v0.1.0` tags are unchanged

### Requirement: A release is gated before it is tagged
Before any tag is created, the release gate SHALL pass on the release commit:
- the build gates `module-layout` defines;
- every published module built and tested with the workspace switched off;
- every nested module's scrty requirements naming the release version;
- every published module's public API and dependency changes reported against the previous release, or against nothing for the first.

A failure SHALL stop the release.

#### Scenario: Stale requirement stops the release
- **WHEN** the gate runs on a commit where `expiry/sweep/go.mod` requires the root at `v0.0.0` and the release version is `v0.1.0`
- **THEN** the gate fails and names `expiry/sweep` and the requirement

#### Scenario: API report for the first release
- **WHEN** the gate runs for `v0.1.0`
- **THEN** it reports each published module's API with no previous release as base, and passes

### Requirement: A release is proven from outside the repository after tagging
After the tags are pushed, a fresh module outside the repository SHALL fetch every published module at the release version through the public module proxy, with the workspace off, and SHALL build a program importing a package from each. A failure SHALL be reported as a failed release, to be fixed by a new version.

#### Scenario: Release probe
- **WHEN** the probe runs after `v0.1.0` is pushed
- **THEN** each of the nine published modules is fetched at `v0.1.0` through the proxy and the probe program builds

#### Scenario: Probe failure
- **WHEN** one module cannot be fetched at the release version
- **THEN** the probe fails, naming the module, and the release is recorded as needing a new version rather than a moved tag

### Requirement: Every release has a changelog entry
The repository SHALL keep one changelog covering every published module, in the Keep a Changelog format. It SHALL keep an `Unreleased` section at the top, and each release SHALL move its changes into an entry headed by the version and the release date. An entry that fixes a vulnerability SHALL list it under `Security`. A change that breaks a published API SHALL be stated in the entry, including under v0.

#### Scenario: Release entry
- **WHEN** `v0.1.0` is released on 2026-11-02
- **THEN** the changelog has an entry headed `[0.1.0] - 2026-11-02`, and `Unreleased` is empty

#### Scenario: Vulnerability fix
- **WHEN** a release fixes a reported vulnerability
- **THEN** its changelog entry lists the fix under `Security`, with its advisory identifier once one is published

### Requirement: A security policy names one private reporting channel
The repository SHALL publish a security policy that names the repository's private vulnerability reporting as the only channel for reporting a vulnerability, states that public issues are not to be used for vulnerabilities, and states the response a reporter can expect.

#### Scenario: Reporter looks for a channel
- **WHEN** a reporter opens the repository's security policy
- **THEN** it names private vulnerability reporting as the only channel
- **AND** it states that public issues are not to be used for vulnerabilities

### Requirement: The security policy states what is supported and how fixes are disclosed
The security policy SHALL state which scrty versions receive security fixes, the latest minor release while the major version is 0, and which Go releases are supported. It SHALL state that a fixed vulnerability is disclosed through a repository security advisory and reported to the Go vulnerability database.

#### Scenario: Supported versions stated
- **WHEN** the latest release is `v0.3.1`
- **THEN** the policy's supported versions name the `0.3.x` line only

#### Scenario: Disclosure stated
- **WHEN** a reader looks for how fixed vulnerabilities are announced
- **THEN** the policy names the repository security advisory and the Go vulnerability database

### Requirement: The release procedure is documented
The repository SHALL document the release procedure in order: update the changelog and the nested requirements to the release version, run the release gate, tag the root and nested modules at one commit, push the tags, run the outside probe, and publish release notes. It SHALL state that pushing tags is a maintainer's action, and that a published tag is never changed.

#### Scenario: Procedure followed
- **WHEN** a maintainer follows the documented procedure for `v0.1.0`
- **THEN** each step names the command or check it runs, and the procedure ends with the outside probe passing
