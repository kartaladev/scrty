# Tasks

Go checks are test-first: write the failing test, run it, and confirm it fails for the intended reason (a compile error is not a red step). Then implement, re-run, and refactor with the tests green. For Makefile targets, workflows and scripts, each task says how it is verified, including a run that is expected to fail. Tasks marked **(maintainer)** change the public repository or publish tags. Only the maintainer does them, never an agent.

The library fixes this change used to carry (its former groups 6–9) moved to `pre-release-api-fixes` on 2026-11-02. Groups 1–5 keep their numbers; the remaining groups are renumbered 6–8. Group 7 starts only after `close-security-gaps`, `pre-release-api-fixes` and `oidc-provider` have landed, because the gate must run on the tree that is tagged.

## 1. `gorelease` against a module with `replace` (design: Risks, decision 3)

- [x] 1.1 Add `golang.org/x/exp/cmd/gorelease` as a `tool` directive in `tools/go.mod`, and verify `make tools` installs it into `.bin/`. Run `GOWORK=off gorelease -base=none -version=v0.1.0` inside `store/pgxstore/` and record the exact output.
  - If it reports the module's API and exits 0, the gate runs it in place.
  - If it refuses because of the `replace` directive, record the error text. The gate then runs it on a temporary copy of the module with the scrty `replace` lines dropped and the workspace-built versions supplied. Report the outcome so the main session records it in `design.md`'s risk entry before group 3.

## 2. Nested modules require released versions (decision 2; module-layout requirement "Published modules resolve outside the repository")

- [x] 2.1 Red: add `TestNestedModulesRequireReleasedVersions` to the root module's `layout_test.go`. It reads every module that `go.work` lists, with `go mod edit -json`. It fails, naming the module and the requirement, when any nested module requires a `github.com/kartaladev/scrty` module (direct or indirect) at `v0.0.0` or at a zero pseudo-version, or has a `replace` whose target is an absolute path or climbs out of the repository. Run it and verify it fails today, naming all eight nested modules.
- [x] 2.2 Red: extend the test so that, when `SCRTY_RELEASE_VERSION` is set, every scrty requirement in every nested module must equal that version exactly. Verify `SCRTY_RELEASE_VERSION=v0.1.0 go test -run TestNestedModulesRequireReleasedVersions .` fails today, for the same modules.
- [x] 2.3 Bump every nested module's scrty requirements to `v0.1.0` with `go mod edit -require`. This covers the root in all eight, and the siblings in `test`. Keep every `replace`, and run `go mod tidy` per module. Verify:
  - 2.1 and 2.2 pass (the latter with `SCRTY_RELEASE_VERSION=v0.1.0`);
  - `SCRTY_RELEASE_VERSION=v0.2.0` fails, naming every module;
  - `make check` passes.
- [x] 2.4 Red: add `TestReleaseModuleListsAgree`. It asserts that the published-module list used by the release gate, the probe and the tag helper (one file, `release-modules.txt` at the root) lists exactly the nested modules in `go.work`, one directory per line, and never `tools`. Verify it fails before the file exists, and again after adding a deliberately wrong entry. Then add the file and verify it passes.
- [x] 2.5 Red: add `TestModulesDeclareGoFloor`, asserting every workspace module's `go` directive is `1.27` or `1.27.x`. It passes on today's tree. To see it bite, temporarily change one `go.mod` to `go 1.26` and confirm it fails naming that module, then restore the file by editing it back. Verify it passes.

## 3. The release gate (decision 3; release-policy requirement "A release is gated before it is tagged")

- [x] 3.1 Add `make release-check VERSION=vX.Y.Z`. It refuses a missing or non-semver `VERSION`, then runs in order, stopping on the first failure:
  - the requirement test with `SCRTY_RELEASE_VERSION=$(VERSION)`;
  - the fmt-check, vet, lint and test loops with `GOWORK=off`, over the modules in `release-modules.txt` plus the root;
  - `VERSION` reaches the recipe's shell through the environment, never by `$(VERSION)` substitution into the script, so a crafted value cannot run commands (added 2026-11-09).
  - Review of 3.1 (2026-11-09) found, and reproduced, that make still expands a command-line `VERSION` such as `v1.0.0$(shell touch x)` before the recipe runs. The targets therefore read the raw text with `$(value VERSION)`, never export `VERSION` itself, and accept only a whole single-line string matching a strict semantic version, with prerelease identifiers as semver defines them. The gate also runs `make check`'s remaining gates, `pincheck`, `tools-check`, `generate-check` and `test-isolated`, so a release is never gated while `make check` would fail. These are done in dispatch R3b, with task 3.3.
  - Both the gate's format step and the existing `fmt-check` check the `.go` files git knows about (`git ls-files --cached --others --exclude-standard '*.go'`), not every file under the module directories. `gofmt -l <dir>` walks into git-ignored directories such as `.claude/worktrees/`, so `make check` failed on a stale file in another checkout (found 2026-11-09).
  Verify:
  - `make release-check` with no version fails with a usage message;
  - `0.1.0`, `v0.1`, `v0.1.0.1` and `latest` are refused as versions, and `v0.1.0-rc.1` is accepted;
  - a run on a working tree with uncommitted or untracked files is refused before any check runs;
  - `make release-check VERSION=v0.2.0` fails at the requirement step, naming the modules;
  - `make release-check VERSION=v0.1.0` passes, and its output shows each module built with the workspace off;
  - with an unformatted `.go` file under a git-ignored directory, `make fmt-check` passes; with an unformatted, untracked but not ignored `.go` file, it fails, naming the file;
  - `VERSION='v1.0.0; echo PWNED'` is refused as not a semantic version, and nothing is echoed;
  - `VERSION='v1.0.0$(shell touch <scratch>/pwn)'`, given on the command line and through the environment, is refused, and the file is never created; so are a value containing a newline, `v1.0.0-01` and `v1.0.0-..`.
- [x] 3.2 Red, then green: add `tools/cmd/releaseproxy` (design decision 3, the local proxy). Given a source tree, a version and a list of module directories, it writes each module as a `GOPROXY` file tree (`<escaped path>/@v/list`, `<version>.info`, `<version>.mod`, `<version>.zip`), building each zip with `golang.org/x/mod/zip.CreateFromDir`. Write these tests first, each seen failing for its intended reason:
  - a module's zip leaves out a nested module's files;
  - a path with capitals is escaped as the proxy protocol requires;
  - a non-semver version, a missing directory, or a directory without `go.mod` is refused with an error naming it, and nothing is written;
  - an existing output path, even an empty directory, is refused, as is one whose parent is missing, one inside the source tree, or a symlink; on failure the run removes only the output directory it created (design decision 3, failure modes);
  - a fresh module with `GOPROXY=file://<out>`, `GONOSUMDB` set for that path, a temporary `GOMODCACHE` and `GOWORK=off` can `go get` a written module at the version.
  Verify with `make tools-check`.
- [x] 3.3 Add the supply-chain and API report steps to `release-check`, as design decision 3 states them: export `HEAD` into a throwaway repository, tag that repository locally with the nine tags `release-tags` prints, run `release-gate` there with `GOWORK` never exported to it (its `MODULES` would otherwise list only the root) and the repository's `SBOM_DIR` and `BIN`, then delete the local tags, write the local proxy with `releaseproxy`, drop the scrty `replace` lines in each exported module, and run `gorelease` with `GOPROXY=file://<proxy>,https://proxy.golang.org`, `GONOSUMDB=github.com/kartaladev/scrty`, a temporary `GOMODCACHE` and `GOWORK=off`, removing every temporary directory on every exit. Use `-base=none` when no `v*` root tag exists, and otherwise `-base=` the latest one. Verify:
  - remove the `SBOM_VERSION` handling and the `jq` rewrite from `sbom` (design decision 3: the SBOMs come from the tagged export);
  - harden the gate as design decision 3's review bullets (tasks 3.1b to 3.1e) state, each seen failing first: the `override`/`unexport`/`export` lines before any shell, pinned by `TestMakefileFixesReleaseVersionBeforeShell`; refuse a shallow clone, and a missing previous tag for any version but `v0.1.0` and its prereleases, before anything is built; pin `HEAD` at the start, export that commit, fail if `HEAD` moved or the tree (untracked files included) became dirty, and print the gated commit; write the SBOMs into the run's temporary directory (`SBOM_ROOT`) and move them into `$(SBOM_DIR)` only after every step passes, emptying `.bin/sbom` before any other refusal; refuse an `SBOM_DIR` outside `.bin` in both `sbom` and `release-check`; refuse a relative or unusual `TMPDIR`;
  - for `v0.1.0`, the vuln output names all nine modules, and `$(SBOM_DIR)` holds exactly nine `.cdx.json` files whose main component version is `v0.1.0`. To see the count check bite, export `GOWORK=off` to the sub-make in a temporary copy of the recipe: it writes one file, and the check fails;
  - no tag exists in the repository afterwards (`git tag --list` unchanged);
  - for `v0.1.0`, it prints a report for each of the nine modules and passes;
  - leaving one module out of the proxy fails the target, naming that module;
  - the developer's `go env GOMODCACHE` holds no `github.com/kartaladev/scrty*@v0.1.0` afterwards;
  - no temporary directory is left behind after a failed run.
- [x] 3.4 Add `.github/workflows/release-check.yml`, triggered by `workflow_dispatch` with a `version` input, running `make release-check VERSION=<input>` on the Go, PostgreSQL and Redis matrix of `ci.yml`'s `test` job, with the same service containers and environment. It has a `timeout-minutes` and a `concurrency` group keyed on the version, so two runs for one version never overlap. Its checkout fetches the full history (`fetch-depth: 0`) without keeping credentials. Verify `actionlint` (run ad hoc with `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`, the latest release per the GitHub API on 2026-10-21) reports nothing on it and on `ci.yml`.

## 4. The outside probe (decision 4; release-policy requirement "A release is proven from outside the repository after tagging")

- [x] 4.1 Add `scripts/release-probe.sh VERSION`. It:
  - creates an empty module in a temporary directory;
  - sets `GOWORK=off` and `GOPROXY=https://proxy.golang.org` (no `direct`);
  - runs `go get` for each module in `release-modules.txt` and the root at `VERSION`, retrying each fetch up to 10 times, 30 s apart;
  - writes a `main.go` that imports one package per module (a fixed map, kept beside the list and checked by `TestReleaseModuleListsAgree`), then runs `go build`.
  - It unsets `GOFLAGS`, `GONOSUMDB`, `GONOSUMCHECK`, `GOPRIVATE`, `GOINSECURE`, `GONOPROXY` and `GOVCS`, and sets `GOENV=off` and `GOTOOLCHAIN=local`, so neither the environment nor settings saved with `go env -w` can bypass the public proxy and checksum database (added 2026-11-09, review of 4.1). Its failure message says the release is fixed with a new version, never a moved tag.
  - On failure it prints the module that failed.
  Verify with `scripts/release-probe.sh v0.0.1`, a version that does not exist: it fails naming the root module after its retries. Lower the retries with `PROBE_RETRIES=1` for this check. Also run `shellcheck` on the script.
- [x] 4.2 Add `.github/workflows/release-probe.yml`, triggered on push of tags matching `v[0-9]*` (root tags only), running `scripts/release-probe.sh "$GITHUB_REF_NAME"`. Verify with `actionlint`.

## 5. Documents and the tag helper (decisions 5, 6, 7; release-policy requirements on the changelog, the security policy and the procedure)

- [x] 5.1 Add `make release-tags VERSION=vX.Y.Z`. It prints, for the current `HEAD`, one `git tag -a` command for the root and one per module in `release-modules.txt`. It never creates or pushes a tag. Verify that for `v0.1.0` it prints exactly nine commands with the tags listed in the release-policy spec, and that `git tag` lists nothing new afterwards.
- [x] 5.2 Write `CHANGELOG.md` in Keep a Changelog 1.1.0 format:
  - an empty `Unreleased` section;
  - a statement on semantic versioning and v0;
  - a `[0.1.0]` entry with the date left as `YYYY-MM-DD` until tagging, summarising the capabilities by module.
  Verify that every published module is named in the entry, and that the headings match the format's change types.
  - Fold in `openspec/changes/archive/2026-10-24-pre-release-hardening/changelog-notes.md` (its breaking changes, new sentinels and security fixes), `idiomatic-api-shape`'s breaking changes, and the breaking changes and new capabilities of `close-security-gaps`, `pre-release-api-fixes`, `session-signals` (the signal stream, and the `ResponseWriter.Stream` break) and `oidc-provider`, summarising the last as the OpenID Provider a consumer can now run, with its conformance status.
  - Also fold in the changes archived after this list was written (added 2026-11-09): `restructure-layout` (package moves), `reauthentication`, `key-port-context`, `bearer-stream-throttle-retry`, and `endpoint-inventory-base-path` (the endpoint path moves, `WithBasePath` and `Chain.Endpoints()`, which break `httpsec`).
  - Then delete the notes file. Verify every entry of the notes file appears in `[0.1.0]`, and that every change named in this task has its breaking items named there.
- [x] 5.3 Write `SECURITY.md`:
  - private vulnerability reporting as the only channel, and no public issues;
  - the response expectations from design decision 6, as confirmed by the maintainer in review;
  - supported versions (`0.1.x`) and Go releases (1.27);
  - disclosure through a repository security advisory and the Go vulnerability database.
  Verify each item of the two security-policy requirements against the text.
- [x] 5.4 Write `RELEASING.md` with the steps of design decision 7, each with its command: the bump commands, `make release-check`, the private-reporting check with `gh api`, `make release-tags`, the push, the probe, and the release notes published with `gh release create <tag> --notes-file <entry> .bin/sbom/*.cdx.json`, which attaches the nine SBOMs the gate wrote on the tagged commit. Include the never-move-a-tag rule and its recovery (a new patch version plus `retract`). Verify that each step's command exists and runs: `make release-check` and `make release-tags` from groups 3 and 5, and the `gh api` check returning JSON. Check the `gh release create` usage against `gh release create --help` only; never run it.
- [x] 5.5 Update `README.md`: the *Development* section names `make release-check` and `make release-tags`, and *Supply chain* says the release check runs `release-gate`'s vuln and SBOM steps and that the SBOMs are attached to each release; an install section (`go get github.com/kartaladev/scrty@v0.1.0` and one nested module), links to `CHANGELOG.md` and `SECURITY.md`, and a supported-versions sentence consistent with `SECURITY.md`, and a *Known limitations* section: the concurrent passkey finish, the magic-link timing difference, OIDC logout's replay window with no `jti` guard, `auth_time` and `max_age` not enforced, the rate limiter's burst overshoot and its N-replica multiplication, the in-memory defaults' single-process scope, and two of the OpenID Provider's: its browser session, which does not see a marker placed on the sign-in afterwards, such as a required password change, so a change that matters must end the sign-in, and whose removal through `WithoutBrowserSessions` fails the Basic OP conformance plan, as `prompt=none` then always answers `login_required` (`oidc-provider` R2); and a login finished in another browser than the one that started it, which needs a restart (`oidc-provider` R9). Verify the links resolve within the repository.
- [x] 5.6 Record the outcome of each claim `pre-release-hardening` left unreproduced (U2, U4, U8, S7, the fiber `HEAD` bypass, the unparseable-hash half of M2, the Argon2id ceiling). For each, name the test that now pins the fixed behaviour, or state that it was dropped and why. Write them in this change's `design.md`; the archive is not edited. Verify every listed claim has an outcome.
  - The fiber `HEAD` claim has no fiber-level test (2026-11-09). Add one in `httpsec/fibersec` asserting that a `HEAD` request to a route marked for the recovery cool-down as `GET` is held. It passes on today's code, so show it bites by temporarily removing the core's `HEAD`-as-`GET` matching: it must fail. Then edit the matching back.

## 6. Release-gate stability

- [x] 6.1 Give each parallel case of `TestIdentityStore_Scenarios` its own database in all three drivers (`test/pgxstore`, `test/sqlstore`, `test/gormstore`), so no two cases rename tables in one database. Verify with `-count=5` per driver under `-race`.
- [x] 6.2 Check the error of the trigger drop in `test/sqlstore/session_supersede_test.go` and `test/gormstore/session_supersede_test.go`. Verify the tests pass, and that a dropped trigger whose drop fails now fails the test: point it at a missing trigger temporarily, then restore it.

## 7. Integration gate

- [x] 7.1 Run a whole-branch review against every requirement in this change's specs, with a fresh Opus reviewer that edits nothing (the change gates release security). Verify every finding is fixed or explicitly declined in the design.
- [x] 7.2 Run `make check`, `make release-check VERSION=v0.1.0` and `openspec validate release-readiness --strict`, and confirm the `conformance` CI job (`oidc-provider` P9) is green on the commit. Verify all four are clean, and keep the output.

## 8. First release (maintainer)

- [x] 8.1 **(maintainer)** Enable private vulnerability reporting, and verify `gh api repos/kartaladev/scrty/private-vulnerability-reporting` reports `"enabled": true`.
- [ ] 8.2 **(maintainer)** After the branch is merged, date the `0.1.0` changelog entry, run `make release-check VERSION=v0.1.0` on the merged commit, then create the tags `make release-tags VERSION=v0.1.0` prints, and push them. Verify the release-probe workflow passes for `v0.1.0`.

## 9. The probe's trigger (decision 4, amended 2026-11-09)

- [x] 9.1 Add `workflow_dispatch` with a required `version` input to `.github/workflows/release-probe.yml`. The run step reads `inputs.version` on a dispatch and `github.ref_name` on a push, through `env`, never by `${{ }}` in the command. Verify, after merge:
  - `gh workflow run release-probe --ref main -f version=v0.1.0` passes (that run is task 9.3);
  - a dispatch with `-f version='v0.1.0;echo PWNED'` fails at the script's version check, and the log shows no `PWNED` line;
  - the push trigger is unchanged (`on.push.tags` still `["v[0-9]*"]`).
- [x] 9.2 Revise `RELEASING.md`:
  - step 7: push the eight nested tags in one `git push --atomic`, then the root tag alone, with decision 4's reason;
  - step 7: if the root tag's push is refused, fix the cause and push it, never deleting a nested tag;
  - step 8: when no run appears, start the probe with `gh workflow run release-probe --ref main -f version=$VERSION`.

  Verify that a reviewer finds each command runnable as written, that the nine tag names still match `make release-tags`' output, and that `TestReleaseModuleListsAgree` passes.
- [ ] 9.3 **(maintainer)** After 9.1 and 9.2 are merged, run `gh workflow run release-probe --ref main -f version=v0.1.0` and watch it. Verify that it passes, so that `v0.1.0` has a probe run on record and 8.2's verification is met.

## Workflow follow-up

- Archive the change once the probe has passed for `v0.1.0` in CI (task 9.3), and sync `module-layout` and the new `release-policy` spec. The archive commit leaves out every other change's directory.
- Then remove the `scrty-release` worktree and its `release-v0.1.0-gate` branch, and delete `scrty-release-notes.md`, `scrty-release-gate.log` and `scrty-release-probe.log` next to the repository.
- Tell the consumer who requested the release that `v0.1.0` resolves.
