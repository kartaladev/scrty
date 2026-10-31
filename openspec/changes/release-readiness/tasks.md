# Tasks

Go checks are test-first: write the failing test, run it, and confirm it fails for the intended reason (a compile error is not a red step). Then implement, re-run, and refactor with the tests green. For Makefile targets, workflows and scripts, each task says how it is verified, including a run that is expected to fail. Tasks marked **(maintainer)** change the public repository or publish tags. Only the maintainer does them, never an agent.

## 1. `gorelease` against a module with `replace` (design: Risks, decision 3)

- [ ] 1.1 Add `golang.org/x/exp/cmd/gorelease` as a `tool` directive in `tools/go.mod`, and verify `make tools` installs it into `.bin/`. Run `GOWORK=off gorelease -base=none -version=v0.1.0` inside `store/pgxstore/` and record the exact output.
  - If it reports the module's API and exits 0, the gate runs it in place.
  - If it refuses because of the `replace` directive, record the error text. The gate then runs it on a temporary copy of the module with the scrty `replace` lines dropped and the workspace-built versions supplied. Report the outcome so the main session records it in `design.md`'s risk entry before group 3.

## 2. Nested modules require released versions (decision 2; module-layout requirement "Published modules resolve outside the repository")

- [ ] 2.1 Red: add `TestNestedModulesRequireReleasedVersions` to the root module's `layout_test.go`. It reads every module that `go.work` lists, with `go mod edit -json`. It fails, naming the module and the requirement, when any nested module requires a `github.com/kartaladev/scrty` module (direct or indirect) at `v0.0.0` or at a zero pseudo-version, or has a `replace` whose target is an absolute path or climbs out of the repository. Run it and verify it fails today, naming all eight nested modules.
- [ ] 2.2 Red: extend the test so that, when `SCRTY_RELEASE_VERSION` is set, every scrty requirement in every nested module must equal that version exactly. Verify `SCRTY_RELEASE_VERSION=v0.1.0 go test -run TestNestedModulesRequireReleasedVersions .` fails today, for the same modules.
- [ ] 2.3 Bump every nested module's scrty requirements to `v0.1.0` with `go mod edit -require`. This covers the root in all eight, and the siblings in `test`. Keep every `replace`, and run `go mod tidy` per module. Verify:
  - 2.1 and 2.2 pass (the latter with `SCRTY_RELEASE_VERSION=v0.1.0`);
  - `SCRTY_RELEASE_VERSION=v0.2.0` fails, naming every module;
  - `make check` passes.
- [ ] 2.4 Red: add `TestReleaseModuleListsAgree`. It asserts that the published-module list used by the release gate, the probe and the tag helper (one file, `release-modules.txt` at the root) lists exactly the nested modules in `go.work`, one directory per line, and never `tools`. Verify it fails before the file exists, and again after adding a deliberately wrong entry. Then add the file and verify it passes.
- [ ] 2.5 Red: add `TestModulesDeclareGoFloor`, asserting every workspace module's `go` directive is `1.27` or `1.27.x`. It passes on today's tree. To see it bite, temporarily change one `go.mod` to `go 1.26` and confirm it fails naming that module, then restore the file by editing it back. Verify it passes.

## 3. The release gate (decision 3; release-policy requirement "A release is gated before it is tagged")

- [ ] 3.1 Add `make release-check VERSION=vX.Y.Z`. It refuses a missing or non-semver `VERSION`, then runs in order, stopping on the first failure:
  - the requirement test with `SCRTY_RELEASE_VERSION=$(VERSION)`;
  - the fmt-check, vet, lint, test and vuln loops with `GOWORK=off`, over the modules in `release-modules.txt` plus the root.
  Verify:
  - `make release-check` with no version fails with a usage message;
  - `0.1.0`, `v0.1`, `v0.1.0.1` and `latest` are refused as versions, and `v0.1.0-rc.1` is accepted;
  - a run on a working tree with uncommitted or untracked files is refused before any check runs;
  - `make release-check VERSION=v0.2.0` fails at the requirement step, naming the modules;
  - `make release-check VERSION=v0.1.0` passes, and its output shows each module built with the workspace off.
- [ ] 3.2 Add the API report step to `release-check`, in the form 1.1 decided:
  - `-base=none` when no previous tag exists;
  - otherwise `-base=` the latest `v*` root tag.
  Verify that it prints a report for each of the nine modules for `v0.1.0`, and that the target fails if `gorelease` errors. Check the failure by pointing it at a non-existent module directory in a temporary copy of the list.
- [ ] 3.3 Add `.github/workflows/release-check.yml`, triggered by `workflow_dispatch` with a `version` input, running `make release-check VERSION=<input>` on `ci.yml`'s Go and PostgreSQL matrix. Verify `actionlint` (run ad hoc with `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`, the latest release per the GitHub API on 2026-10-21) reports nothing on it and on `ci.yml`.

## 4. The outside probe (decision 4; release-policy requirement "A release is proven from outside the repository after tagging")

- [ ] 4.1 Add `scripts/release-probe.sh VERSION`. It:
  - creates an empty module in a temporary directory;
  - sets `GOWORK=off` and `GOPROXY=https://proxy.golang.org` (no `direct`);
  - runs `go get` for each module in `release-modules.txt` and the root at `VERSION`, retrying each fetch up to 10 times, 30 s apart;
  - writes a `main.go` that imports one package per module (a fixed map, kept beside the list and checked by `TestReleaseModuleListsAgree`), then runs `go build`.
  - It unsets `GOFLAGS`, `GONOSUMDB`, `GONOSUMCHECK`, `GOPRIVATE`, `GOINSECURE` and `GONOPROXY`, so the public checksum database is always consulted.
  - On failure it prints the module that failed.
  Verify with `scripts/release-probe.sh v0.0.1`, a version that does not exist: it fails naming the root module after its retries. Lower the retries with `PROBE_RETRIES=1` for this check. Also run `shellcheck` on the script.
- [ ] 4.2 Add `.github/workflows/release-probe.yml`, triggered on push of tags matching `v[0-9]*` (root tags only), running `scripts/release-probe.sh "$GITHUB_REF_NAME"`. Verify with `actionlint`.

## 5. Documents and the tag helper (decisions 5, 6, 7; release-policy requirements on the changelog, the security policy and the procedure)

- [ ] 5.1 Add `make release-tags VERSION=vX.Y.Z`. It prints, for the current `HEAD`, one `git tag -a` command for the root and one per module in `release-modules.txt`. It never creates or pushes a tag. Verify that for `v0.1.0` it prints exactly nine commands with the tags listed in the release-policy spec, and that `git tag` lists nothing new afterwards.
- [ ] 5.2 Write `CHANGELOG.md` in Keep a Changelog 1.1.0 format:
  - an empty `Unreleased` section;
  - a statement on semantic versioning and v0;
  - a `[0.1.0]` entry with the date left as `YYYY-MM-DD` until tagging, summarising the capabilities by module.
  Verify that every published module is named in the entry, and that the headings match the format's change types.
  - Fold in `openspec/changes/archive/2026-10-24-pre-release-hardening/changelog-notes.md` (its breaking changes, new sentinels and security fixes), the API changes of decisions 11–13, and `idiomatic-api-shape`'s breaking changes. Then delete the notes file. Verify every entry of the notes file appears in `[0.1.0]`.
- [ ] 5.3 Write `SECURITY.md`:
  - private vulnerability reporting as the only channel, and no public issues;
  - the response expectations from design decision 6, as confirmed by the maintainer in review;
  - supported versions (`0.1.x`) and Go releases (1.27);
  - disclosure through a repository security advisory and the Go vulnerability database.
  Verify each item of the two security-policy requirements against the text.
- [ ] 5.4 Write `RELEASING.md` with the steps of design decision 7, each with its command: the bump commands, `make release-check`, the private-reporting check with `gh api`, `make release-tags`, the push, the probe, and the release notes. Include the never-move-a-tag rule and its recovery (a new patch version plus `retract`). Verify that each step's command exists and runs: `make release-check` and `make release-tags` from groups 3 and 5, and the `gh api` check returning JSON.
- [ ] 5.5 Update `README.md`: an install section (`go get github.com/kartaladev/scrty@v0.1.0` and one nested module), links to `CHANGELOG.md` and `SECURITY.md`, and a supported-versions sentence consistent with `SECURITY.md`, and a *Known limitations* section: the concurrent passkey finish, the magic-link timing difference, OIDC logout's replay window with no `jti` guard, `auth_time` and `max_age` not enforced, the rate limiter's burst overshoot and its N-replica multiplication, and the in-memory defaults' single-process scope. Verify the links resolve within the repository.
- [ ] 5.6 Record the outcome of each claim `pre-release-hardening` left unreproduced (U2, U4, U8, S7, the fiber `HEAD` bypass, the unparseable-hash half of M2, the Argon2id ceiling). For each, name the test that now pins the fixed behaviour, or state that it was dropped and why. Write them in this change's `design.md`; the archive is not edited. Verify every listed claim has an outcome.

## 6. Pre-release fixes in `notify` (decisions 9, 10; email-notification requirement "A queued sender returns without waiting for delivery")

- [ ] 6.1 Red: write `TestQueuedSender_WrappedSenderEndsItsGoroutine`, the scenario "Wrapped sender ends its goroutine", under `-race` with goleak. Run it and confirm it fails because the second message is never delivered. Then implement decision 9: a worker whose delivery did not return normally logs the failure and is replaced. Verify: the scenario and every queued-sender scenario pass under `-race`.
- [ ] 6.2 Pin the current behaviour with `TestSMTPSender_NoSenderAddressIsAConfigError`: a message with no `From`, through a sender with no default address, returns an error matching `ErrConfig`. It passes today, so prove it by temporarily wrapping a different error and watching it fail, then restore it. Then update `ErrConfig`'s godoc per decision 10. Verify: the test passes, and every place that wraps `notify.ErrConfig` outside a constructor is named in the godoc.

## 7. The token subject (decision 11; token-issuance and authentication deltas)

- [ ] 7.1 Audit, read-only: list every use of `identity.Principal.Username` reachable from a bearer-authenticated request, on both paths: the standalone `JWTAuthenticator`, and the chain's session-backed bearer interceptor (`httpsec/bearer.go`, which reloads the user and builds the principal from the reloaded details). Confirm that the chain path keeps filling `Username` from the reloaded user, and report which readers would see an empty username under the new default. The main session records the outcome in decision 11 before 7.2.
- [ ] 7.2 Red: write the `token-issuance` scenarios "Default token" (now `sub` `u-1`), "Consumer chooses the username as subject" and "Empty subject", and the `authentication` scenarios "Valid token" (principal identifier `u-1`) and "Consumer reads the subject as a username". Run them and confirm the default and empty-subject cases fail on their assertions. Also red: through the chain's bearer interceptor, a default token reloads its user by the session's user reference and the principal keeps the user's username; a token whose `sub` is not the session's user reference is refused. Then implement decision 11 with `token.WithUsernameSubject()` and `authenticate.WithJWTUsernameSubject()`, each naming the default it replaces. In `httpsec/bearer.go`, look the user up with `lookupBySessionUser` under the default and `lookupByUsername` under the username option. Verify: the scenarios pass, and so do the `token`, `authenticate`, `httpsec` and `test` suites.

## 8. Signing-key retention (decision 12; signing-keys delta)

- [ ] 8.1 Red: add delete cases to the key-store conformance suite (delete existing keys, delete a missing key without error, `LoadAll` no longer returns deleted keys), and the `signing-keys` scenarios "Old key removed" (also gone from the store), "Consumer keeps retired keys", "Failed delete retried", "Current key kept" and "Far-future key removed" (still stored). Run them and confirm they fail on their assertions, not on compiling: add `Delete` as a stub first.
- [ ] 8.2 Implement `KeyStore.Delete` in the in-memory store, `sqlstore`, `pgxstore`, `gormstore` and the sealing decorator, and the housekeeping deletion with `WithRetiredKeysKept()`. Verify: the conformance suite passes against every store, including the Docker suites, and every `signing-keys` scenario passes under `-race`.

## 9. Port clean-up (decisions 13, 14)

- [ ] 9.1 Remove `passkey.CredentialStore.DeleteAwaitingSavedCodes` from the port, the three SQL stores, `internal/pgschema`, the conformance suite and the mocks. This is a removal with no red step. Verify: every module builds and its tests pass, and `rg DeleteAwaitingSavedCodes` finds nothing outside `openspec/`.
- [ ] 9.2 Red: write `TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm`, which lands a device proof between `ConfirmEnrolment`'s read and the store's `Confirm` and asserts the outcome `mfa-enrolment-path` says is wrong is not what happens. Run it. If it passes, report it so the main session records the claim as dropped in decision 14. If it fails, stop and report it, so the main session writes the fix's decision and a `multi-factor-auth` delta before any fix.

## 10. Release-gate stability

- [ ] 10.1 Give each parallel case of `TestIdentityStore_Scenarios` its own database in all three drivers (`test/pgxstore`, `test/sqlstore`, `test/gormstore`), so no two cases rename tables in one database. Verify with `-count=5` per driver under `-race`.
- [ ] 10.2 Check the error of the trigger drop in `test/sqlstore/session_supersede_test.go` and `test/gormstore/session_supersede_test.go`. Verify the tests pass, and that a dropped trigger whose drop fails now fails the test: point it at a missing trigger temporarily, then restore it.

## 11. Integration gate

- [ ] 11.1 Run a whole-branch review against every requirement in this change's specs, with a fresh Sonnet reviewer that edits nothing. Verify every finding is fixed or explicitly declined in the design.
- [ ] 11.2 Run `make check`, `make release-check VERSION=v0.1.0` and `openspec validate release-readiness --strict`. Verify all three are clean, and keep the output.

## 12. First release (maintainer)

- [ ] 12.1 **(maintainer)** Enable private vulnerability reporting, and verify `gh api repos/kartaladev/scrty/private-vulnerability-reporting` reports `"enabled": true`.
- [ ] 12.2 **(maintainer)** After the branch is merged, date the `0.1.0` changelog entry, run `make release-check VERSION=v0.1.0` on the merged commit, then create the tags `make release-tags VERSION=v0.1.0` prints, and push them. Verify the release-probe workflow passes for `v0.1.0`.

## Workflow follow-up

- Archive the change once the probe has passed for `v0.1.0`, and sync `module-layout` and the new `release-policy` spec.
- Tell the consumer who requested the release that `v0.1.0` resolves.
