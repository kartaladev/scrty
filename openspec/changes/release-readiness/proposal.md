## Why

No application outside this repository can depend on scrty's integration modules today.
- **Nested modules don't resolve.** Each nested `go.mod` requires the root at `v0.0.0` through a relative `replace` to the repository root. A dependent's build ignores `replace`, and no `v0.0.0` exists, so `GOWORK=off go get github.com/kartaladev/scrty/store/pgxstore@main` fails with "unknown revision v0.0.0".
- **The root resolves only as a pseudo-version,** because nothing is tagged.
- **No reporting channel or record.** There is no way to report a vulnerability privately, and no record of what changed between versions.

The first consumer's adoption is blocked on this, whatever else is built.

## What Changes

- **Lockstep versioning.**
  - Every published module carries the same version at every release.
  - The root is tagged `vX.Y.Z`. Each nested module is tagged with its directory as prefix: `httpsec/fibersec/vX.Y.Z`, `httpsec/ginsec/`, `store/gormstore/`, `authenticate/passkey/webauthn/`, `store/pgxstore/`, `ratelimit/redisstore/`, `expiry/sweep/`, `test/`.
  - `tools/` is internal build tooling and is never tagged.
  - The first release is `v0.1.0`.
- **Nested modules require real versions.**
  - Every nested `go.mod` requires the root, and any sibling it uses, at the release version.
  - The `replace` directives and `go.work` stay for development inside the repository only.
- **A release gate.**
  - Before tagging:
    - every module builds and tests with the workspace switched off;
    - every nested module's requirements name the release version;
    - each module's public API change is reported.
  - After tagging, a fresh module outside the repository fetches and builds every published module through the public proxy.
  - A release checklist states the order: bump, gate, tag the root and nested modules at one commit, push, probe. A published tag is never moved or deleted; a mistake is fixed by a new version, with `retract` where needed.
- **`CHANGELOG.md`.** In Keep a Changelog format, with an `Unreleased` section, dated entries, and a `Security` section in every entry that has one. One file covers every module.
- **`SECURITY.md`.**
  - The private reporting channel: GitHub private vulnerability reporting, as the only channel.
  - The response expectations.
  - Supported versions: the latest minor release, during v0.
  - Supported Go releases.
  - How fixed vulnerabilities are published, including the Go vulnerability database.
- **Repository setting, a step for the maintainer.** Enabling private vulnerability reporting is listed as such, since it is a change to the public repository's settings and is not made by tooling. It is off as of 2026-10-21.
- **Spec correction.**
  - The settled `module-layout` requirement still names Go 1.26 as the minimum and a CI run on Go 1.26 and Go 1.27.
  - The project already requires Go 1.27: the project configuration, the README, every `go.mod` and the CI matrix all say so.
  - The requirement is corrected to the 1.27 floor that a release must state truthfully.

## Capabilities

### New Capabilities

- `release-policy`: how scrty versions and tags its modules, what a release must prove before and after tagging, the changelog, the security policy and private reporting channel, and the supported versions.

### Modified Capabilities

- `module-layout`:
  - published modules resolve outside the repository at a released version;
  - the Go-release requirement is corrected to the 1.27 floor;
  - the CI requirement is corrected to the releases actually tested.

## Impact

- **Changed files:**
  - every nested `go.mod` and `go.sum` (`httpsec/fibersec`, `httpsec/ginsec`, `store/gormstore`, `authenticate/passkey/webauthn`, `store/pgxstore`, `ratelimit/redisstore`, `expiry/sweep`, `test`);
  - the `Makefile`, which gains release-gate targets;
  - `.github/workflows/`, which gains a release-gate workflow and a post-tag probe;
  - new `CHANGELOG.md`, `SECURITY.md` and `RELEASING.md`;
  - `README.md` (supported versions, install).
- **No library code changes,** and no API change.
- **Tags:** `v0.1.0` and eight prefixed `v0.1.0` tags, pushed by the maintainer, not by tooling.
- **Related changes:**
  - `first-party-sessions` is implemented first, so its session store port, its security-state migration and its session features ship in `v0.1.0` and are summarised in that entry;
  - `bff-resource-server` and `trusted-proxy-client-ip` are unaffected.
- **Dependencies:** `golang.org/x/exp/cmd/gorelease` is added to the `tools` module for the API report.

## References

### Lockstep versioning, tags and real requirements

**Researched (accessed 2026-10-21):**
- [Go Modules Reference: module paths and tags](https://go.dev/ref/mod#module-paths): the module subdirectory is the prefix of its version tags.
- [Go Modules Reference: replace](https://go.dev/ref/mod#go-mod-file-replace): `replace` applies only in the main module and is ignored in dependents.
- [Go Modules Reference: go.work](https://go.dev/ref/mod#go-work-file): `GOWORK=off` gives a single-module context, and committing a `go.work` is generally inadvisable.
- [Go Modules Reference: retract](https://go.dev/ref/mod#go-mod-file-retract) and [checksum database](https://go.dev/ref/mod#checksum-database): published versions stay available and their content cannot change.
- [Managing module source](https://go.dev/doc/modules/managing-source): a repository with several modules prefixes each module's tags with its subdirectory.
- [Module version numbering](https://go.dev/doc/modules/version-numbers): v0 carries no compatibility guarantee.
- [Module release and versioning workflow](https://go.dev/doc/modules/release-workflow) and [Publishing a module](https://go.dev/doc/modules/publishing): tag, push, prompt the proxy, and never change a published version.
- [opentelemetry-go RELEASING.md](https://github.com/open-telemetry/opentelemetry-go/blob/main/RELEASING.md) and [versions.yaml](https://github.com/open-telemetry/opentelemetry-go/blob/main/versions.yaml): lockstep module sets, a `gorelease` check before tagging, and no way to remove a bad tag.
- [testcontainers-go RELEASING.md](https://github.com/testcontainers/testcontainers-go/blob/main/RELEASING.md) and [modules/postgres/go.mod](https://github.com/testcontainers/testcontainers-go/blob/main/modules/postgres/go.mod): lockstep releases, nested modules requiring the root by real version beside a local `replace`.
- [aws-sdk-go-v2 service/s3/go.mod](https://github.com/aws/aws-sdk-go-v2/blob/main/service/s3/go.mod) and [google-cloud-go release-please configuration](https://github.com/googleapis/google-cloud-go/blob/main/release-please-individual-config.json): the independent model, which was considered and not chosen.
- The four repositories' stars and tags were read through the GitHub API on 2026-10-21. They drift.

### Release gate

**Researched (accessed 2026-10-21):**
- [gorelease](https://pkg.go.dev/golang.org/x/exp/cmd/gorelease): reports public API and dependency changes, and `-base=none` checks a first release. It is experimental.

### Changelog and security policy

**Researched (accessed 2026-10-21):**
- [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/): an `Unreleased` section, dated entries, and change types including `Security`.
- [GitHub: adding a security policy](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository): a security policy states the supported versions and how to report.
- [GitHub: privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability): repository owners enable private reporting. The repository's setting was read through the GitHub API on 2026-10-21 (disabled).
- [Go vulnerability management](https://go.dev/security/vuln/): reporting public vulnerabilities in Go packages to the Go vulnerability database.

### Supported Go releases

**Researched (accessed 2026-10-21):**
- [Go release history](https://go.dev/doc/devel/release): each major release is supported until two newer major releases exist. Go 1.27 and Go 1.26 are supported today, and scrty's floor of 1.27 follows from the project configuration.
