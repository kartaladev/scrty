## Context

See `proposal.md` for the motivation. This section covers only the state of the tree the design builds on.

- **Modules.**
  - `go.work` lists the root and eight nested modules: `httpsec/fibersec`, `httpsec/ginsec`, `store/gormstore`, `authenticate/passkey/webauthn`, `store/pgxstore`, `ratelimit/redisstore`, `expiry/sweep` and `test`.
  - `tools/` is outside the workspace, and holds the build tools as `tool` directives.
- **Requirements.**
  - Seven nested modules require the root at `v0.0.0` with a relative `replace` to the repository root (`../../`, or `../../../` for `authenticate/passkey/webauthn`). `authenticate/passkey/webauthn` requires it at the zero pseudo-version `v0.0.0-00010101000000-000000000000`.
  - `test` requires every sibling it imports at `v0.0.0` or the zero pseudo-version, each with its own `replace`.
- **Gates.**
  - `make check` runs fmt-check, vet, lint, test, vuln and generate-check over `MODULES := $(shell go list -m -f '{{.Dir}}')`, which only lists every module in workspace mode.
  - CI (`.github/workflows/ci.yml`) runs `make check` on Go `1.27.x` against PostgreSQL 15 and 18.
- **Layout checks.** `layout_test.go` in the root module already checks the module layout by reading `go.mod` files and building a consumer module (`TestConsumerModuleGraph`). That is the established home for checks of this kind.
- **Settings and history.**
  - The repository is public. Private vulnerability reporting is disabled (GitHub API, 2026-10-21).
  - No tags exist, and there is no changelog or security policy.
- **The established design** published no versioned modules and had no release process to depart from. Every decision below is new.

None of the decisions below is library behaviour a consumer configures. They govern how the repository is released. Where the configuration rule asks for a default and an override, the consumer's override is the ordinary Go one: a consumer picks any released version, or a pseudo-version, with `go get`.

## Goals / Non-Goals

**Goals:**

- A consumer outside the repository can `go get` any published module at a release version, with nothing else configured.
- A release that would not resolve is stopped before its tags exist, and a release that does not resolve once published is detected at once.
- One command runs each check, locally and in CI.

**Non-Goals:**

- Automated tagging, pushing or release-note publishing. Pushing tags is the maintainer's action.
- A compatibility promise. v0 promises none, and v1 is a later decision.
- Signing tags or artifacts, and provenance attestations. They are a possible later change.
- Independent module versions.

## Decisions

### 1. Lockstep versions with directory-prefixed tags

- **What a release is.** Every release tags the root `vX.Y.Z`, and each published nested module `<dir>/vX.Y.Z`, all at one commit. The prefix is the module's directory, as the Go module reference requires for a module in a subdirectory.
- **Never tagged:** `tools/`.
- **First release:** `v0.1.0`.
- **Why lockstep:**
  - Every nested module is an adapter of the root, tested against the root at the same commit.
  - One version answers "which adapter goes with which core" without a compatibility matrix.
  - One changelog and one procedure serve every module.
- **Alternative considered:** independent versions per module, the release model of the AWS SDK for Go v2 and Google Cloud's Go libraries. It suits hundreds of modules released by automation. With nine modules that move together, it would cost a compatibility matrix and nine changelogs to avoid an occasional unchanged release.

### 2. Nested modules require real versions and keep their local `replace`

- **The requirements.** Every nested `go.mod` requires the root and each sibling scrty module it imports at the release version. For `v0.1.0`, that is `github.com/kartaladev/scrty v0.1.0` and, in `test`, `github.com/kartaladev/scrty/store/pgxstore v0.1.0` and so on.
- **What stays.** The relative `replace` directives stay, and so does `go.work`.
- **Why this is safe:**
  - A dependent's build ignores both.
  - A developer inside the repository keeps building against the working tree.
  - This is the arrangement opentelemetry-go, testcontainers-go and the AWS SDK for Go v2 ship.
- **Between releases.** The requirements name the last release. The `replace` keeps development on the working tree, so a commit between releases is still buildable, and the next release bumps them in one commit.
- **The gap after the bump.** The bump commit names a version whose tags do not exist yet. Inside the repository it builds, because each nested module's own `replace` applies when that module is the main module, so the release gate (decision 3) can run on it. From outside, it resolves only once the tags are pushed, and that is what the probe (decision 4) checks.
- **Pinned by an always-on check.** A new root-module test, beside `TestConsumerModuleGraph`, fails on every run if any nested module requires a scrty module at `v0.0.0` or at a zero pseudo-version. The tree can never drift back into an unreleasable state between releases.

### 3. One release gate, run before tagging

- **The command.** `make release-check VERSION=vX.Y.Z` runs in order, stopping at the first failure:
  1. **Requirement check:** the root-module test of decision 2, run with `SCRTY_RELEASE_VERSION` set. It then also fails unless every nested module's scrty requirements name exactly that version. Without the variable, it runs only the always-on half.
  2. **The build gates with the workspace off:** the same fmt-check, vet, lint, test and vuln loops `make check` runs, with `GOWORK=off`, over a module list read from `go.work` rather than from `go list -m` (which lists only the root once the workspace is off). Each module is then built as its own main module, its own `replace` included. A module that only built because the workspace supplied something is caught. One pass replaces the workspace pass rather than doubling it.
  3. **The API report:** `gorelease` in each published module. It uses `-base=none -version=v0.1.0` for the first release, and `-base=<previous> -version=<new>` after it. The report is printed. Under v0 it does not fail on an incompatible change, but it fails the gate on any error the tool reports.
- **Where it runs.**
  - The maintainer runs it before tagging.
  - A `workflow_dispatch` CI job runs it with the version as input, on the same matrix as `ci.yml`, so a release is gated on both PostgreSQL majors.
- **The tool.** `gorelease` is added to `tools/go.mod` as a `tool` directive, like the other tools.
- **Alternative considered:** a separate workspace-off pass on every pull request. It would double CI time, for a failure that only matters at release. The always-on requirement check covers the cheap half of it on every run.

### 4. A probe from outside, after tagging

- **The workflow.** A CI workflow triggered by a pushed tag matching `v*`, the root tag:
  - creates an empty module in a temporary directory;
  - sets `GOWORK=off` and `GOPROXY=https://proxy.golang.org`, with no `direct` fallback, so the public proxy must serve the version;
  - runs `go get <module>@<tag>` for each of the nine published modules;
  - writes a `main.go` importing one package from each, and runs `go build`.
- **The probe's source** is a fixed list, kept beside the release-check module list and checked against `go.work` by the same root-module test, so a new module cannot be published without being probed.
- **Propagation.** The proxy fetches a version on first request, so `go get` through it is also the documented way to prompt it. The workflow retries the fetch a bounded number of times before failing, to absorb propagation delay.
- **A failure** opens no automatic action. The release is recorded as failed in the run, and the procedure (decision 7) says the fix is a new version, never a moved tag.

### 5. One changelog in Keep a Changelog format

- **The file.** `CHANGELOG.md` at the root, covering every module:
  - an `Unreleased` section at the top;
  - entries headed `[X.Y.Z] - YYYY-MM-DD`, using the change types Added, Changed, Deprecated, Removed, Fixed and Security;
  - a statement that the project follows semantic versioning, and that v0 carries no compatibility promise.
- **What an entry says.** A change that breaks a published API is stated, even under v0. Changes specific to one module name it.
- **The first entry** (`0.1.0`) summarises the capabilities the release contains, by module, without enumerating history.

### 6. A security policy with one private channel

- **The file.** `SECURITY.md` at the root.
- **Reporting.** GitHub private vulnerability reporting is the only channel, chosen by the maintainer. Public issues are not to be used for vulnerabilities.
- **Proposed response expectations** (the maintainer may change them in review):
  - acknowledgement within 7 days;
  - an assessment and fix plan within 30 days;
  - coordinated disclosure within 90 days of the report, sooner when a fix is released.
  - 90 days is the common industry disclosure deadline.
- **Supported versions:** the latest minor release while the major version is 0. The policy's table is updated at each release.
- **Supported Go releases:** Go 1.27, plus each later Go release while the Go project supports it.
- **Disclosure:**
  - a GitHub security advisory on the repository;
  - a report to the Go vulnerability database through its form, once the advisory is public;
  - an entry under `Security` in the changelog.
- **Enabling private reporting** is the maintainer's step, because it changes a public repository's settings. The procedure gives the command and how to verify it: `gh api repos/kartaladev/scrty/private-vulnerability-reporting`, which must report `"enabled": true`. The first release is not tagged until it is on.

### 7. The release procedure is a document, and tags are the maintainer's

- **The document.** `RELEASING.md` gives the steps, each with the command it runs:
  1. move `Unreleased` into a dated entry, and update `SECURITY.md`'s supported-versions table;
  2. bump every nested requirement to the release version (`go mod edit -require=...` per module, listed in full);
  3. merge;
  4. run the release gate;
  5. confirm private reporting is enabled;
  6. create annotated tags for the root and the eight nested modules at the merged commit;
  7. push the tags;
  8. watch the probe;
  9. publish GitHub release notes from the changelog entry.
- **A tag-list helper.** `make release-tags VERSION=vX.Y.Z` prints the nine `git tag -a` commands for the current commit, so the list cannot be mistyped. It never creates or pushes a tag itself.
- **Never move a tag.** The document states it, and states the recovery: a new patch version, with a `retract` directive when the bad version must not be selected.

### 8. The supported Go releases requirement matches the tree

- **The correction.**
  - The settled `module-layout` requirement still says Go 1.26 is the minimum and CI runs on 1.26 and 1.27. The project configuration, the README, every `go.mod` and `ci.yml` require 1.27, for the reason the project configuration records (the JOSE stack's use of `encoding/json/v2`).
  - The requirement changes to the 1.27 floor, tested on every supported Go release at or above it.
- **What CI tests.** The matrix stays `1.27.x` until Go 1.28 is released, when `1.28.x` is added. That is the requirement, not a new decision.

### 9. A queued-sender worker that ends abnormally is replaced

- **The defect.** `recover` cannot stop `runtime.Goexit`, so a wrapped sender that ends its goroutine (as `t.FailNow` does) kills the worker delivering its message. Once every worker is gone, `Send` still queues messages and returns no error, and nothing delivers them. This breaks `email-notification`'s rule that an accepted message is delivered. It was REPRODUCED by a scratch test while `idiomatic-api-shape` was implemented, and is older than that change.
- **The fix.** A deferred check notices a delivery that did not return normally. It logs the failure and starts a replacement worker, so the pool stays at its configured size. The message being delivered is reported as failed, as a panic's message already is.
- **Default and override:** automatic, with no option. A pool that silently shrinks has no use a consumer could want.
- **Alternative considered:** document the case and leave it. Rejected, because the sender would then accept messages it never delivers.
- **Order:** this change's `email-notification` delta copies the requirement as `idiomatic-api-shape` modifies it, so that change is archived first.

### 10. A missing sender address stays a configuration error

- **The mismatch.** `notify/smtp.go` wraps `ErrConfig` when a message has no `From` and the sender was built with no default address. `ErrConfig`'s godoc says it marks wiring mistakes, as opposed to failures at send time, and does not mention this case. UNREPRODUCED: the wording disagrees with the behaviour, and the behaviour is not wrong.
- **The decision.** The case is a wiring mistake: the consumer configured neither a default sender nor a sender on the message. `ErrConfig` keeps wrapping it, and its godoc names it.
- **Default and override:** unchanged. A consumer sets `WithSMTPFrom`, or `Message.From`.
- **Alternative considered:** a new sentinel for a missing address. Rejected, because it adds API for a case the existing sentinel already means.

### 11. The token subject is the user's identifier by default

- **The problem.** Issued tokens carry the principal's username as `sub`. A rename invalidates the user's live tokens, and a username can be reassigned to someone else, while `sub` is the claim every verifier keys on.
- **The decision.** By default the generator writes `Principal.ID` as `sub`, and the JWT authenticator builds the principal with that identifier. This departs from the established design, which carries the username. The departure exists because `sub` is meant to be stable and never reassigned, and a public claim cannot change after the first tag without breaking live tokens and external verifiers.
- **Default and override.** The default is the user identifier. A consumer whose own systems read the username sets `token.WithUsernameSubject()` on the generator and `authenticate.WithJWTUsernameSubject()` on the authenticator. The two components cannot see each other, so a mismatch cannot fail at construction; both options' godoc says they must agree.
- **Refusal.** Issuing for a principal whose chosen subject is empty fails, instead of minting a token no one can resolve.
- **Two bearer paths, two effects.**
  - The standalone `authenticate.JWTAuthenticator` builds its principal from the claims alone. Under the default it carries the identifier and no username.
  - The `httpsec` chain's session-backed bearer interceptor reloads the user and builds the principal from the reloaded details (`PrincipalFromDetails`), so `Username` stays filled. Today it reloads by username, keyed on `sub` (`lookupByUsername` in `httpsec/bearer.go`). Under the default it reloads by the session's user reference instead (`lookupBySessionUser`), and refuses a token whose `sub` is not that reference. Under the username option it keeps the lookup by username. Either way the user must still own the session, as now.
  - Anything reading `Principal.Username` behind the chain, such as a password re-proof, therefore keeps working.
- **Risk.** A reader of `Principal.Username` behind the standalone authenticator sees an empty name under the default. The first task audits every such reader with gopls before the change, and reports any consumer of the name.
- **User's choice, 2026-10-31:** an option, defaulting to the identifier.

### 12. Housekeeping deletes the keys it retires for age

- **The problem.** `signingkey.KeyStore` has no delete method. Housekeeping stops publishing old keys but leaves them in the store, which gains a row per algorithm per rotation, hourly by default, and every row is loaded at start and on each reload.
- **The decision.** `KeyStore` gains `Delete(ctx context.Context, kids ...string) error`. It is idempotent: a missing key is not an error. Housekeeping deletes every key it stops publishing because it is older than the key lifetime. Such a key can no longer verify a token, since token lifetimes are shorter than the key lifetime. A key it stops publishing because it is dated in the future is only unpublished, never deleted, because that date may come from another replica's clock. A failed delete is reported to the logger and the error hook and retried at the next run.
- **Implementations.** The in-memory store, `sqlstore`, `pgxstore`, `gormstore`, and the sealing decorator, which forwards the call. The store conformance suite gains delete cases.
- **Default and override.** Deletion is on by default. `WithRetiredKeysKept()` keeps retired keys in the store, for a consumer who audits them.
- **User's choice, 2026-10-31:** add the delete method before the tag.

### 13. The unused passkey store method is removed

- `passkey.CredentialStore.DeleteAwaitingSavedCodes` has not been called by the library since an earlier change stopped deleting credentials awaiting saved codes. It is removed from the port, the three SQL stores, the conformance suite and the mocks. Removing a port method after the tag would break every consumer store, so it goes now.
- **User's choice, 2026-10-31.**

### 14. The reported MFA confirmation race is settled before the tag

- **The claim.** The single-call `ConfirmEnrolment` reads the pending enrolment, then calls the store's `Confirm`, which checks neither the enrolment's generation nor the device proof. A device proof landing in between would go unseen. UNREPRODUCED.
- **The decision.** The first task writes the red test. If it passes, the claim is dropped and recorded here. If it fails, apply pauses so that this decision and a `multi-factor-auth` delta can be written before the fix, because fixing it changes the store's `Confirm` contract.
- **User's choice, 2026-10-31.**

## Risks / Trade-offs

- **`gorelease` may refuse a module whose `go.mod` has `replace` directives.**
  - Mitigation: the first task runs it against one module and records the outcome.
  - If it refuses, the gate runs it on a temporary copy with the scrty `replace` lines dropped, against the workspace-built versions.
  - This is unverified, and tested first.
- **Between the bump merge and the tag push, the bump commit names a version that does not exist yet,** so a consumer pinning that commit's pseudo-version cannot resolve it.
  - Mitigation: the procedure tags the merged commit immediately after the gate passes. The window is minutes, and only pseudo-version consumers of that exact commit see it.
- **The proxy may be slow to serve a new version.**
  - Mitigation: bounded retries in the probe. A probe that still fails is a reported failure, not a silent pass.
- **Lockstep tags release unchanged modules.**
  - Accepted: an unchanged module at a new version costs nothing to a consumer, and keeps one version meaning one tested set.
- **The response times in the security policy are a commitment.**
  - Mitigation: they are proposed defaults, for the maintainer to confirm or change in review before `SECURITY.md` is published.

## Post-release backlog

Open follow-ups from the archived changes that are not needed for `v0.1.0`. None is a breaking change to add later. Each names the change that recorded it.

- **Performance**
  - Cache the verification key set instead of rebuilding it on every verify (identity-and-tokens; measured at 1.7–5% of an RS256 verify).
  - Throttle the API key's `LastUsedAt` write (auth-methods).
  - Evaluate `PostAuthentication` once on the magic-link path (auth-methods; to be confirmed against the current code first).
- **Features**
  - A full-session listing of a user's enrolled second factors (mfa-multi-method).
  - Ending other sessions when TOTP is removed or a password changes (passkey-session-revocation).
  - A passkey or other begin-step method as an account-recovery proof (recovery-codes, passkey-authentication).
  - A general security-events port for login, logout and revocation (first-party-sessions).
  - A concurrency limit and a strength policy for password hashing (first-party-sessions).
  - A cap option for the shared limiters' local fall-back count (limiter-key-bounds).
  - A per-flow unavailable mode and exported limiter namespaces and defaults (shared-rate-limiting).
  - Per-user MFA grace windows (mfa-enrolment-path; additive through an optional interface).
  - Storing and enforcing the provider's `auth_time` and `max_age` (oidc-mfa-assurance; a later migration adds the column).
  - A constant-work decoy for magic-link requests (auth-methods).
- **Refactors** (first-party-sessions): the `gorm` session save through the shared column map; one savepoint protocol in `storekit`; one written form of the `stale` rule; `DeleteFamily`'s empty second pass.
- **Unmeasured or unreproduced**
  - Possible deadlocks (`40P01`) between user-wide deletes or the sweep and a re-rotation (first-party-sessions; fails loudly and safely).
  - The circuit breaker tripping on an encoding failure end to end, and the batched prune over a sparse table (postgres-limiter-hardening).
  - Two concurrent successful passkey finishes leaving one response's saved codes superseded, the earlier unconfirmed code set confirming in a gap, and clock skew in the "abandoned" rule (pre-release-hardening; stated limits).
  - Test failures seen once: the migration-rollback teardown timeout, the Keycloak container start, `TestPGLimiter_HeldRow`, the `hang` probe's read timeout, and the shared PostgreSQL server's first start (stabilize-intermittent-tests, testcontainers-optimize). Watched on the release gate's CI.
- **Code observations**
  - `authenticate`'s password and JWT providers stamp `Authentication.Time` with `time.Now()` and offer no time source. The `time-source` capability does not require one, and it could be added as an option later.
- **Process**
  - The reply to a consumer drafted during `lockout-honest-defaults` has no record of being sent. That is the maintainer's to confirm.

## Migration Plan

- **The work lands first:** the changes to `go.mod`, the checks, the workflows and the documents.
- **Then the maintainer:**
  - enables private reporting;
  - runs the gate;
  - tags `v0.1.0`, pushes it, and watches the probe.
- **Rollback.** Before the tags are pushed, revert the commit. After they are pushed, there is no rollback, only a new version.

## References

### Decisions 1 and 2: lockstep versions, prefixed tags, real requirements

**Researched (accessed 2026-10-21):**
- [Go Modules Reference: module paths](https://go.dev/ref/mod#module-paths): a module's subdirectory is the prefix of its version tags.
- [Go Modules Reference: replace](https://go.dev/ref/mod#go-mod-file-replace): `replace` applies only in the main module and is ignored in dependents.
- [Go Modules Reference: go.work](https://go.dev/ref/mod#go-work-file): `GOWORK=off` gives a single-module context.
- [Managing module source](https://go.dev/doc/modules/managing-source): each module root in a repository prefixes its tags with its subdirectory.
- [Module version numbering](https://go.dev/doc/modules/version-numbers): v0 carries no compatibility guarantee.
- [opentelemetry-go versions.yaml](https://github.com/open-telemetry/opentelemetry-go/blob/main/versions.yaml) and [otlptrace go.mod](https://github.com/open-telemetry/opentelemetry-go/blob/main/exporters/otlp/otlptrace/go.mod): lockstep module sets, and nested modules requiring the root by real version beside a local `replace`.
- [testcontainers-go RELEASING.md](https://github.com/testcontainers/testcontainers-go/blob/main/RELEASING.md) and [modules/postgres/go.mod](https://github.com/testcontainers/testcontainers-go/blob/main/modules/postgres/go.mod): lockstep releases that rewrite nested requirements before tagging.
- [aws-sdk-go-v2 service/s3/go.mod](https://github.com/aws/aws-sdk-go-v2/blob/main/service/s3/go.mod) and [google-cloud-go release-please configuration](https://github.com/googleapis/google-cloud-go/blob/main/release-please-individual-config.json): the independent model, considered and not chosen.
- The four repositories' stars and tags were read through the GitHub API on 2026-10-21. They drift.

### Decisions 3 and 4: the release gate and the probe

**Researched (accessed 2026-10-21):**
- [gorelease](https://pkg.go.dev/golang.org/x/exp/cmd/gorelease): an experimental tool that reports API and dependency changes, where `-base=none` checks a first release.
- [opentelemetry-go RELEASING.md](https://github.com/open-telemetry/opentelemetry-go/blob/main/RELEASING.md): `gorelease` run before tagging, and the warning that a bad tag cannot be removed.
- [Publishing a module](https://go.dev/doc/modules/publishing): prompting the public proxy with `go list -m` against a new tag, and never changing a published version.
- [Go Modules Reference: environment variables](https://go.dev/ref/mod#environment-variables): `GOPROXY` defaults to `https://proxy.golang.org,direct`.

### Decisions 5 and 7: changelog and procedure

**Researched (accessed 2026-10-21):**
- [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/): `Unreleased`, dated entries, change types including `Security`.
- [Go Modules Reference: retract](https://go.dev/ref/mod#go-mod-file-retract) and [checksum database](https://go.dev/ref/mod#checksum-database): retraction, and published content that cannot change.
- [Module release and versioning workflow](https://go.dev/doc/modules/release-workflow): the v0-to-v1 release flow.

### Decision 6: security policy

**Researched (accessed 2026-10-21):**
- [GitHub: adding a security policy](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository): what a security policy states.
- [GitHub: privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability): owners enable private reporting, and reporters use the Security tab. The repository's setting was read through the GitHub API on 2026-10-21 (disabled).
- [Go vulnerability management](https://go.dev/security/vuln/): reporting public vulnerabilities to the Go vulnerability database.

**Primary documentation:**
- The 90-day coordinated-disclosure deadline is common industry practice. It is not re-checked against a specific source on this date.

### Decisions 9 and 10: `notify` fixes

Reasoned from scrty's own settled specs (`email-notification`) and code, and from the review of `idiomatic-api-shape` that found both.

### Decisions 11–14: pre-release API fixes

**Primary documentation:**
- [OpenID Connect Core 1.0, §2 ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): `sub` is a locally unique identifier for the end user that is never reassigned. Not re-checked on this date.
- [RFC 7519, §4.1.2 "sub"](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2): the subject is unique within the issuer's context. Not re-checked on this date.

Decisions 12–14 are reasoned from scrty's own settled specs and code, and from the follow-up sweep of the archived changes. Decision 11 departs from the established design, as stated in that decision.

### Decision 8: supported Go releases

**Researched (accessed 2026-10-21):**
- [Go release history](https://go.dev/doc/devel/release): each major release is supported until two newer major releases exist, which is Go 1.27 and Go 1.26 today. scrty's 1.27 floor comes from its own project configuration.
