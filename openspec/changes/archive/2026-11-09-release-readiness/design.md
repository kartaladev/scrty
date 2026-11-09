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
  - CI (`.github/workflows/ci.yml`) runs each gate as its own job (`make fmt-check`, `make vet`, `make lint`, and so on), behind one aggregate `ci-ok` job. The `test` job runs on a matrix of Go `1.27.x`, PostgreSQL 15 and 18, and Redis (corrected 2026-11-09: CI no longer runs `make check` as one job).
  - `make release-gate` already exists. `close-security-gaps` shipped it as a placeholder for this change's gate: it runs `vuln`, then `sbom`, which writes one CycloneDX SBOM per workspace module to `$(SBOM_DIR)` (default `.bin/sbom`). Its `SBOM_VERSION` stamping never worked (decision 3). Its design states that `release-check` calls it, and the settled `supply-chain` spec requires both steps of the release gate (recorded 2026-11-09).
- **Layout checks.** `layout_test.go` in the root module already checks the module layout by reading `go.mod` files and building a consumer module (`TestConsumerModuleGraph`). That is the established home for checks of this kind.
- **Settings and history.**
  - The repository is public. Private vulnerability reporting is disabled (GitHub API, 2026-10-21).
  - No tags exist, and there is no changelog or security policy.
- **The established design** published no versioned modules and had no release process to depart from. Every decision below is new.

- **Split (2026-11-02).** The library fixes moved to `pre-release-api-fixes`, and `oidc-provider` is delivered before the tag. The order is `close-security-gaps`, `pre-release-api-fixes`, `oidc-provider`, then this change's gate and tag.

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
  2. **The build gates with the workspace off:** the same fmt-check, vet, lint and test loops `make check` runs, with `GOWORK=off`, over the published modules: the root plus `release-modules.txt`, which `TestReleaseModuleListsAgree` keeps equal to `go.work`'s published entries (`go list -m` lists only the root once the workspace is off). Each module is then built as its own main module, its own `replace` included. A module that only built because the workspace supplied something is caught. One pass replaces the workspace pass rather than doubling it.
  3. **The supply-chain gate:** `release-gate` runs in the throwaway export of `HEAD` that step 4 also uses, after that export is tagged locally with the nine release tags `make release-tags` prints. It runs the vulnerability check (already per module with `GOWORK=off`) and writes the nine SBOMs, each naming the release version, into the run's temporary directory; the gate moves them into `$(SBOM_DIR)` only once every step has passed, as the `supply-chain` spec requires. The local tags exist only in the throwaway repository, are removed before step 4, and are never pushed. The vuln loop is therefore not repeated in step 2. The sub-make runs in workspace mode, so its `MODULES` lists every module (see Risks).
- **The release version is read as raw text (decided 2026-11-09, review of task 3.1).** Make expands a command-line variable before a recipe runs, so `VERSION='v1.0.0$(shell ...)'` ran the command (reproduced). The targets take `override RELEASE_VERSION := $(value VERSION)`, never export `VERSION`, and accept only a whole single-line strict semantic version. `override` is needed because a command-line `RELEASE_VERSION=` would otherwise be expanded on export. The gate needs `jq`, which it checks for before any step, for the SBOM version check.
  - **GNU make 4.4 and later pass exported variables to `$(shell)`** (review of task 3.1b, 2026-11-09). A command-line `VERSION` stays exported until the `unexport` line, so a `$(shell ...)` assignment read before that line expanded it: two hits on GNU Make 4.4.1, none on 3.81 (reproduced). Handled: the `override`, `unexport` and `export` lines come before any `$(shell ...)` in the Makefile. A root-module test pins that order in the Makefile's text, counting every shell assignment form (`!=` with `export`, `override` or `private`, indented), `include` and `$(eval` as a shell boundary, and refusing a continuation, `define` block or conditional that could hide the three lines (review of task 3.1d: two such forms ran the injected shell on make 4.4.1 while the first test passed, reproduced), a `!=` whose name is itself an expansion, and `load`. Accepted, because a textual check cannot see them and the Makefile uses none: a shell reached through `$(call)` or a macro, a `$(shell` assembled from parts, `$( shell` with a space, a tab-indented recipe copy of one of the three lines, and CRLF line endings; and the fix was reproduced on make 4.4.1 and 3.81. Accepted: `VERSION:=`, `::=` and `!=` on the command line, and a `MAKEFLAGS` in the environment, are evaluated by make itself; whoever sets them already controls make, and the workflow sets neither.
  - **The gated commit is pinned.** The gate reads `HEAD` once, at the start, exports that commit rather than `HEAD`, fails if `HEAD` moved by the end, and prints the commit it gated. Without it, a commit made during the run would give SBOMs and an API report for a different commit than the tests ran on.
  - **A failed or refused run leaves no SBOMs that look like a passing run's.** `$(SBOM_DIR)` is emptied when the gate starts, before any refusal (review of task 3.1c: a refused run kept an earlier run's nine SBOMs, which step 9's check accepted; reproduced). The SBOMs are written inside the gate's temporary directory and moved to `$(SBOM_DIR)` only after every step has passed, so `RELEASING.md`'s check of nine files naming the version can only be met by a passing run. Accepted: an interrupt during the move leaves fewer than nine files, which step 9's count rejects; two runs at once into one `$(SBOM_DIR)` are not guarded, and step 9's per-file version check catches a mixed set.
  - **`$(SBOM_DIR)` is removed with `rm -rf`**, and `?=` lets the environment set it. `SBOM_DIR=.` deleted the whole checkout (review of task 3.1c, reproduced). Handled: `release-check` and `sbom` refuse an `SBOM_DIR` that does not resolve, physically, to a strict subdirectory of `SBOM_ROOT`, and remove only the resolved path. `SBOM_ROOT` is a simple assignment to `$(BIN)`, so a plain environment variable cannot move it. Accepted: `make -e` or `MAKEFLAGS=e` can (review of task 3.1d, reproduced), as they can any make variable; `override` would stop that but also ignore the command-line handoff below, which breaks the gate (shown in task 3.1e); `release-check` alone passes its run's temporary directory as `SBOM_ROOT` to its own `release-gate` sub-make. Because `.bin/sbom` is emptied before any refusal, a refused run on a fresh clone leaves an empty `.bin/sbom`. Accepted: a directory swapped for a symlink between the check and the removal is followed, which only the same user can do inside `.bin`; `SBOM_ROOT`, `BIN` or `SBOM_DIR` given on the command line are trusted, as all command-line make text is, and `SBOM_DIR`'s text is placed in the recipe as make text, so whoever sets it already controls make (every accidental value tried, such as an unbalanced quote or a newline, fails closed with a shell syntax error). An `SBOM_DIR` that is refused, or that names another directory, leaves `.bin/sbom` as it was; `RELEASING.md` tells the maintainer to leave it unset.
  - **A relative `TMPDIR` is refused** before anything is created, because the temporary module cache and the proxy path must be absolute. It is also limited to letters, digits and `._+@/-`, because the run's directory reaches the `release-gate` sub-make as make text, where a `$` would be expanded. The `tools` build moved from a prerequisite into the recipe, after the refusals, so a refused run builds nothing.
  - **The working tree becoming dirty during the run** would mean the tests ran on files outside the gated commit. Handled: the gate fails at the end unless the tree is still clean. Both clean-tree checks list untracked files explicitly, because a user's `status.showUntrackedFiles=no` hid an untracked `.go` file that `go test` compiled and `git archive` left out (review of task 3.1c, reproduced). Accepted: `HEAD` moving away and back during a run passes both end checks; it needs a deliberate action during the gate, and the tests are rerun by CI on the merged commit.
  - **`make -n release-check` runs the gate for real.** The recipe calls `$(MAKE)`, and make runs such a line even under `-n`. Accepted: GNU make defines it so, and `RELEASING.md` never uses `-n`; the Makefile comment says it is not a preview.
- **Why the SBOMs come from a locally tagged export (decided 2026-11-09, task 3.1).** `make sbom SBOM_VERSION=...` as `close-security-gaps` shipped it never worked: `cyclonedx-gomod` v1.12.0 has no `-main-version` flag (`flag provided but not defined: -main-version`, reproduced). The tool takes a module's version from the git tag on `HEAD`, directory-prefixed for a nested module (checked 2026-11-09: tags `v0.1.0` and `sub/v0.1.0` give both modules `v0.1.0` and matching package URLs). Tagging a throwaway copy lets the tool state the version itself. Rewriting the pseudo-version in its output with `jq` was tried and rejected: it edits a supply-chain artifact after the tool wrote it, by string replacement over the whole document. `SBOM_VERSION` is removed; `make sbom` outside the gate names the commit's pseudo-version, which is what it is.
  4. **The API report:** `gorelease` in each published module. It uses `-base=none -version=v0.1.0` for the first release, and `-base=<previous> -version=<new>` after it. The report is printed. Under v0 it does not fail on an incompatible change, but it fails the gate on any error the tool reports. It runs against a local module proxy (next bullet).
- **The API report runs against a local proxy (decided 2026-11-09, after task 1.1).** `gorelease` loads a module as a consumer would. It ignores `replace`, resolves every requirement through `GOPROXY`, and refuses a repository with uncommitted changes. Run in place on a nested module, it failed with `unknown revision v0.0.0`, and dropping the `replace` only moves that failure to the release version, whose tags do not exist yet. So the gate:
  1. exports `HEAD` with `git archive` into a temporary directory, and commits it there in a throwaway repository, so `gorelease` sees a clean tree;
  2. writes every published scrty module of that export at `$(VERSION)` into a second temporary directory laid out as a `GOPROXY` file tree (`<escaped path>/@v/list`, `.info`, `.mod`, `.zip`), using a new `tools/cmd/releaseproxy` program built on `golang.org/x/mod/zip`;
  3. drops the scrty `replace` lines in each exported module, and runs `gorelease` there with `GOWORK=off`, `GOPROXY=file://<proxy>,https://proxy.golang.org`, `GONOSUMDB=github.com/kartaladev/scrty` and a temporary `GOMODCACHE`.
  - **What it adds:** before any tag exists, each nested module is shown to resolve and build against exactly the root and siblings about to be tagged, as a consumer will load them. The probe (decision 4) still proves the published copy.
  - **Default:** this is the only form the gate takes. **Override:** none. It is the repository's release process, not library behaviour.
  - **Alternatives considered:** running `gorelease` on the root only, which would leave the nested modules' API and dependency changes unreported, against the `release-policy` requirement; and dropping the report for `v0.1.0`. Both were declined by the maintainer.
  - **Failure modes:**
    - **The locally built `v0.1.0` must never reach the developer's module cache.** It is built from the working tree, so a run before merge would cache content that differs from the published version and later fail its checksum. Handled: a temporary `GOMODCACHE`, removed on every exit path.
    - **Skipping the checksum database for scrty modules** is scoped to this one command's environment and never exported. It covers the modules the local proxy serves and, once a previous release exists, the base version `gorelease` fetches from the public proxy for comparison. Accepted: the base is only compared, never built into anything, and the post-tag probe checks every published version against `sum.golang.org`.
    - **A module the local proxy lacks** fails `gorelease` only when another module requires it. A leaf module such as `expiry/sweep` was left out and every report still passed (found by R3b, 2026-11-09). Handled: after writing the proxy, the gate fetches every published module at the release version from the local proxy alone, and fails naming any that is missing. Tested by leaving one out.
    - **Dropping the `replace` lines leaves `go.sum` without the scrty modules' sums**, and `gorelease` then refuses (`go.sum: one or more sums are missing`). Handled: the export runs `go mod download` for each dropped module, which adds exactly those sums, and commits the result, because `gorelease` needs a clean tree. `go mod tidy` is not used, because it would also add unrelated sums and hide an untidy `go.mod`.
    - **A clone without tags would compare against nothing** (review of task 3.1b, 2026-11-09). `actions/checkout` fetches one commit and no tags by default, so the gate found no previous tag and ran `-base=none`, which accepts any API change (shown in a scratch module with a `v0.1.0` tag). Handled: the gate refuses a shallow repository, and the workflow checks out the full history with its tags. A full clone fetched without tags is not shallow, so the gate also refuses to find no previous tag for any version but the first release, `v0.1.0` or one of its prereleases. That refusal runs with the others, before anything is built. Asking the remote for its tags was rejected: it would make the gate depend on the network for a check the version alone can make.
    - **The base is the highest root tag strictly lower than the release version** in SemVer 2.0.0 precedence (whole-branch review, 2026-11-09: the highest tag overall was chosen, so re-running the gate after tagging compared `v0.1.0` with itself and `gorelease` refused, reproduced). A lower prerelease of the same core counts: `v0.1.0` after `v0.1.0-rc.1` reports the changes since the release candidate. Accepted: the comparison function lives in the recipe and is pinned by the review's table run on bash 3.2 and 5, not by a test in the repository; ordering of mixed-case prerelease identifiers under an exported non-C glibc `LC_ALL` is unverified, and the gate's runners use C ordering.
    - **A `GOFLAGS` set in the environment or with `go env -w`** would change what the workspace-off loop builds and tests. Handled: the gate refuses a non-empty `go env GOFLAGS` before building. The probe's version pattern is the gate's, pinned by `TestReleaseProbeSemverMatchesMakefile`, so a version the gate passes is never refused by the probe.
    - **A module added after the base tag** is accepted: it has no base version, and its first report fails. Such a release passes `-base=none` for that module by hand, as `RELEASING.md` will state when it first happens.
    - **A zip carrying files from a nested module or from outside the module** would misrepresent the release. Handled: `releaseproxy` builds each zip with `zip.CreateFromDir`, which leaves out nested modules, and its tests pin this.
    - **Temporary directories left behind on failure:** removed by a trap on every exit. Handled.
    - **`releaseproxy` removing something it did not create** (review of task 3.2, 2026-11-09: a dangling symlink given as the output, and an output path with `..` through a symlink, were each removed or caused an unrelated directory to be removed; reproduced). Handled: the output is resolved once to a canonical path whose parent must already exist. It must be absent, and is created with `os.Mkdir` (mode `0700`), so the run owns it alone. On failure the run removes only that directory. When creation fails, including a race with another process creating the same path, it removes nothing. An existing directory, even an empty one, is refused (changed 2026-11-09, second review: removing only "what the run wrote" inside a shared empty directory still deleted files another process wrote there, reproduced).
    - **A symlink swapped into the output during a run** would be followed. Accepted: the output is created fresh by the run with mode `0700` inside the gate's own temporary directory, so only the same user can swap anything in.
    - **Nested modules' zips lack the root `LICENSE`** that `cmd/go` adds to a subdirectory module's published zip. Accepted: the API report does not read it. The tool's godoc says so rather than claiming identical zips.
    - **An output directory inside the source tree** would put the proxy's own files into the root module's zip (reproduced in the same review). Handled: refused, as is a module directory that resolves outside the source tree through a symlink.
- **Where it runs.**
  - The maintainer runs it before tagging.
  - A `workflow_dispatch` CI job runs it with the version as input, on the same Go, PostgreSQL and Redis matrix as `ci.yml`'s `test` job, so a release is gated on both PostgreSQL majors.
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
- **The trigger (amended 2026-11-09, after `v0.1.0`).**
  - **What happened.** The `v0.1.0` tags went up in one atomic push of nine tags, and the probe never started. GitHub creates no push event when more than three tags are pushed at once. The probe was then run by hand (`scripts/release-probe.sh v0.1.0`) and passed: all nine modules resolved, checksums were verified, and the program built. CI has no record of it.
  - **The fix.**
    - The workflow also accepts `workflow_dispatch` with a required `version` input. It passes the input to the script through the environment, never by `${{ }}` substitution into the command. The script's existing semantic-version check refuses anything else before fetching.
    - Step 7 of `RELEASING.md` pushes the eight nested tags in one atomic push, then the root tag alone, so the root tag's push is an event the trigger sees.
    - Step 8 says to start the probe by hand when no run appears.
  - **The trade-off.** The nine tags are no longer one all-or-nothing push. If the root tag's push is refused after the nested tags are up, the nested tags are public without their root. The procedure says to fix the cause and push the root tag, never to delete the nested ones (decision 7). Until then, a consumer's `go get` of a nested module at that version fails to resolve the root. It is a loud failure, closed by the next push.
  - **Rejected alternative.** Keep the atomic nine-tag push and always start the probe by hand. It keeps the all-or-nothing push, but the probe would then depend on a manual step every time.

| Failure | State | Outcome |
|---|---|---|
| More than three tags in one push create no event | Handled | The root tag is pushed alone; the manual trigger covers a missed run |
| A dispatched `version` crafted to inject a command | Handled, verified by a refused dispatch (task 9.1) | The script refuses it before fetching; the value never reaches a `run:` line |
| The root tag's push is refused after the nested tags are up | Accepted | Nested modules fail to resolve until the root tag is pushed; never fixed by deleting a tag |
| A dispatch on a version that was never tagged | Handled | The probe fails, naming the first module that does not resolve |

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
  9. publish GitHub release notes from the changelog entry, with the nine SBOMs the gate wrote attached (`gh release create <tag> --notes-file <entry> .bin/sbom/*.cdx.json`).
- **The SBOMs come from the gate run on the tagged commit.** Step 4 runs on the merged commit that step 6 tags, so the files in `.bin/sbom` describe exactly what is published, stamped with its version. Attaching them is the maintainer's step, like publishing the notes. Automated publishing is a non-goal. This fills the gap `close-security-gaps` left to this change: the `supply-chain` spec makes attaching SBOMs to a release the release workflow's requirement (recorded 2026-11-09).
- **A tag-list helper.** `make release-tags VERSION=vX.Y.Z` prints the nine `git tag -a` commands for the current commit, so the list cannot be mistyped. It never creates or pushes a tag itself.
- **Never move a tag.** The document states it, and states the recovery: a new patch version, with a `retract` directive when the bad version must not be selected.

### 8. The supported Go releases requirement matches the tree

- **The correction.**
  - The settled `module-layout` requirement still says Go 1.26 is the minimum and CI runs on 1.26 and 1.27. The project configuration, the README, every `go.mod` and `ci.yml` require 1.27, for the reason the project configuration records (the JOSE stack's use of `encoding/json/v2`).
  - The requirement changes to the 1.27 floor, tested on every supported Go release at or above it.
- **What CI tests.** The matrix stays `1.27.x` until Go 1.28 is released, when `1.28.x` is added. That is the requirement, not a new decision.

### 9–14. Moved to `pre-release-api-fixes` (2026-11-02)

The library fixes this change used to carry (the `notify` worker replacement and `ErrConfig` wording, the token subject, signing-key deletion, the unused passkey store method, and the MFA confirmation race) are now decisions 1–6 of `pre-release-api-fixes`, unchanged. The numbers 9–14 are left unused here, so existing references to decisions 1–8 still hold.

## Risks / Trade-offs

- **`gorelease` may refuse a module whose `go.mod` has `replace` directives.**
  - Mitigation: the first task runs it against one module and records the outcome.
  - **Outcome (task 1.1, 2026-11-09):** confirmed. In the working tree it refused because the repository had uncommitted changes. In a clean export it ignored the `replace` and failed to fetch the root: `unknown revision v0.0.0` for `store/pgxstore`, and `unknown revision 000000000000` for `authenticate/passkey/webauthn`. A temporary copy with the `replace` lines dropped, as first planned, cannot work either, because `v0.1.0` has no tag before the release. Decision 3 now runs it against a local proxy.
  - **PostgreSQL test teardown under heavy load (UNREPRODUCED).** One `make check`, run while two other agents' test runs shared the machine, failed three tests in `test/pgxstore` and `test/sqlstore` when rolling back migrations exceeded the shared 30-second `postgresTeardownBudget`. The final gate on an idle machine (2026-11-09, commit `2f795101`) passed the same suites. Accepted for this change: no run has failed it without competing load. If it fails in CI, its first test is the teardown under a saturated database, and the fix belongs to the test helper, not to the release gate.
  - **Adding the tool moved `golang.org/x/tools` in the `tools` module to a pseudo-version** (`v0.52.1-0.20261106145633-d407941a339a`), because `golang.org/x/exp` has no tagged releases and requires it. Accepted: `tools` is never published, and only the gate's own tools use it.
- **The supply-chain sub-make could scan and stamp only the root.** `release-gate`'s `MODULES` comes from `go list -m`, which lists only the root once `GOWORK=off`. If `release-check` exported `GOWORK=off` to the sub-make, vuln and sbom would cover one module and still pass.
  - Handled: `release-check` sets `GOWORK=off` per command, never in the environment it passes to `$(MAKE) release-gate`. Task 3.1 verifies that a `v0.1.0` run writes nine SBOM files and that vuln names nine modules.
- **Between the bump merge and the tag push, the bump commit names a version that does not exist yet,** so a consumer pinning that commit's pseudo-version cannot resolve it.
  - Mitigation: the procedure tags the merged commit immediately after the gate passes. The window is minutes, and only pseudo-version consumers of that exact commit see it.
- **The proxy may be slow to serve a new version.**
  - Mitigation: bounded retries in the probe. A probe that still fails is a reported failure, not a silent pass.
- **Lockstep tags release unchanged modules.**
  - Accepted: an unchanged module at a new version costs nothing to a consumer, and keeps one version meaning one tested set.
- **The response times in the security policy are a commitment.**
  - Mitigation: they are proposed defaults, for the maintainer to confirm or change in review before `SECURITY.md` is published.

## Outcomes of the claims `pre-release-hardening` left unreproduced (task 5.6, 2026-11-09)

No change after 2026-10-24 records a red-step outcome or a drop for any of them, so each outcome rests on the test that pins the behaviour now. Each listed test was run on 2026-11-09 and passes.

| Claim | Outcome | Pinned by |
|---|---|---|
| U2, user-wide deletes that loop without bound | Fixed | `TestUntilSettled` (`internal/storekit`); `TestSessionDelete_SettlesUnderConcurrentCreates` in `test/{pgxstore,sqlstore,gormstore}` |
| U4, a failed first-use write with successor recovery on | Fixed | `TestLoad_FailedFirstUseWrite` (`session`) |
| U8, relying-party ID validation | Fixed | `TestValidateRPID` (`authenticate/passkey`) |
| S7, `(nil, nil)` recovery records and nil passkey list elements | Fixed | `TestRecoverer_FinishFailures`, case "a record store that finds no record and no error is refused as missing" (`recovery`); `TestCredentialList_NilElementIsMissing` (`authenticate/passkey`) |
| The fiber `HEAD`-reaches-`GET` bypass of the recovery cool-down | Fixed in the core, and pinned through fiber | `TestRecoveryCooldown_Matching`, case "HEAD on a marked GET is held" (`httpsec`), and `TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute`, case "HEAD on the marked GET route", with a control case when no hold is active (`httpsec/fibersec`, task 5.6). |
| M2, the unparseable-hash half | Fixed | `TestPasswordProvider_UnrecognisedHashCostsOneVerification` (`authenticate`); `TestRecognizer_BuiltInEncodersRecognizeOnlyWhatTheyWouldVerify` (`authenticate/password`) |
| The Argon2id parameter ceiling | Fixed | `TestEncoderConstruction` (`authenticate/password`) |

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

**Researched (accessed 2026-11-09), for decision 4's trigger amendment:**
- [GitHub Docs: Webhook events and payloads, `push`](https://docs.github.com/en/webhooks/webhook-events-and-payloads#push): "Events will not be created for tags when more than three tags are pushed at once", which is why the atomic nine-tag push started no probe.


**Primary documentation:**
- [GitHub Docs: Events that trigger workflows, `workflow_dispatch`](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch): a workflow started by hand with typed inputs.

The supply-chain step and the SBOM attachment (decisions 3 and 7, 2026-11-09) are reasoned from scrty's own settled specs (`supply-chain`) and the archived `close-security-gaps` design.

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

### Decision 8: supported Go releases

**Researched (accessed 2026-10-21):**
- [Go release history](https://go.dev/doc/devel/release): each major release is supported until two newer major releases exist, which is Go 1.27 and Go 1.26 today. scrty's 1.27 floor comes from its own project configuration.
