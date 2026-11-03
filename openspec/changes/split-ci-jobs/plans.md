# Split CI Jobs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every file-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself. Tasks marked **(maintainer)** are never done by an agent, and **(main session)** tasks push, open pull requests or read GitHub state.

**Goal:** Replace the single `make check` CI job with one job per check, a CodeQL job, an OpenSpec validation job and one aggregate `ci-ok` result. Every check job runs the same `make` target a contributor runs.

**Architecture:**
- **Makefile.** One file target per tool, so every gate target installs only what it calls. A new `spec-check` target stays outside `check`.
- **`ci.yml`.** Rewritten into jobs:
  - `format`, `vet`, `lint`, `generate`, `vuln`, `pincheck` and `tools-check`, once each;
  - `test`, on the existing matrix;
  - `codeql`, with `go` and `actions` legs;
  - `openspec`;
  - `ci-ok`, which runs `always()`, checks that its `needs` lists every job, and fails on any result other than `success`.
- **`.github/scripts/ci-needs-check.sh`.** Holds the completeness check, so it can be tested locally against fixtures.

**Tech Stack:**
- GNU Make, bash and GitHub Actions;
- `jq` and a YAML tool preinstalled on `ubuntu-latest` (task 3.2 confirms which);
- OpenSpec CLI 1.16.0 through `npx`;
- `actionlint` v1.7.12 and `shellcheck`, for verification only.

**Spec:** `openspec/changes/split-ci-jobs/`:
- `proposal.md`;
- `design.md` (decisions 1 to 8, Risks, Migration Plan);
- `specs/continuous-integration/spec.md` and `specs/module-layout/spec.md`;
- `tasks.md`.

Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **Not part of `make check`.** `make check`'s prerequisites and order stay `tools pincheck tools-check fmt-check vet lint test vuln generate-check`, then `test-isolated` from the recipe. `spec-check` is never added to it.
- **Tool versions** come only from `tools/go.mod`, installed with `cd tools && GOWORK=off GOBIN=$(BIN) go install <package>`.
- **Static jobs' Go release:** workflow-level `GO_VERSION: "1.27.x"`.
- **Test matrix, unchanged:**
  - `go: ["1.27.x"]`;
  - `postgres:15.19-alpine` paired with `redis:7.4.11-alpine`;
  - `postgres:18.6-alpine` paired with `redis:8.10.2-alpine`;
  - `SCRTY_TEST_POSTGRES_IMAGE` and `SCRTY_TEST_REDIS_IMAGE` set from it.
- **Draft condition, on every check job:** `github.event_name != 'pull_request' || !github.event.pull_request.draft`. On `ci-ok`: `always() && (<that condition>)`.
- **Triggers and permissions.** Triggers are unchanged. The workflow-level `permissions` stays `contents: read`, and only `codeql` widens it, at job level.
- **Pinning.** Every `uses:` is a full 40-character SHA with `# vX.Y.Z` after it.
- **OpenSpec CLI default:** `npx --yes @fission-ai/openspec@1.16.0`, never with `--strict`.
- **Agents never:**
  - run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`;
  - commit, push, or use `gh` with a write method;
  - touch a file outside their dispatch's list: another session commits on this branch and shares this tree.
  - edit `openspec/`.

  A deliberately broken file is restored by editing it back.
- **Verification commands,** run from the worktree root:
  - `make check` and `make spec-check`;
  - `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`;
  - `shellcheck .github/scripts/ci-needs-check.sh`.

## Review Focus

1. **A dependency of `ci-ok` that was cancelled or skipped,** not failed.
   - Expected: `ci-ok` fails, because a skipped job counts as a passing check.
   - Test: in task 3.6, the result expression is run locally against JSON fixtures in which one result is `cancelled`, then `skipped`, then `failure`. Each must exit non-zero, and all-`success` must exit 0.
2. **A `SPEC_BASE` that is all zeros or names a commit not in the clone,** as on the first push of a branch, or with a shallow fetch.
   - Expected: `spec-check` falls back to the merge base with `origin/main`, says so, and still validates.
   - Test: in task 2.1, run `SPEC_BASE=0000000000000000000000000000000000000000` and `SPEC_BASE=1111111111111111111111111111111111111111`. Both pass and print the fallback line.
3. **A change archived inside the diff,** whose directory under `openspec/changes/` no longer exists.
   - Expected: it is skipped as an active change, and `validate --archived` covers it.
   - Test: in task 2.1, run `SPEC_BASE=e8762b6^`. That range archives `key-port-context`, and the run must not report `key-port-context` as not found.
4. **Untracked files in an active change.**
   - Expected: they count as touched, because the spec says "the working tree", so a new change that is not yet committed is validated.
   - Test: in task 2.1, an untracked `openspec/changes/<tmp>/proposal.md` with no deltas makes `spec-check` fail, naming `<tmp>`. Then delete the directory.
5. **`make -j check` on an empty `.bin`,** where `tools` and a gate's own tool prerequisite could both write the same binary.
   - Expected: each binary is installed exactly once.
   - Test: in task 1.2, `tools` depends on the five file targets instead of running `go install tool`, and `make -n -j8 check | grep -c 'go install'` prints `5` with `.bin` removed.

---

## Before any dispatch (main session)

This change is delivered in pull request #68, on `feat/pre-release-api-fixes`, together with `pre-release-api-fixes`. Its artifacts came onto that branch from `docs/split-ci-jobs`, and #41 is closed as superseded once #68 carries them.

Dispatches run in the main working tree, because the branch cannot be checked out in a second worktree. Another session commits on the same branch, so each dispatch owns only the files named below, and the main session commits by exact path.

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | M1 | 1.1, 1.2, 2.1 | `Makefile` | Sonnet: Makefile plumbing to stated names and a stated order |
| 1 (parallel) | W1 | 3.1, 3.2, 3.3 | `.github/workflows/ci.yml`, `.github/scripts/ci-needs-check.sh`, `.github/scripts/testdata/` | Sonnet: a workflow to a stated layout, and a script to a stated contract |
| 2 (after W1) | W2 | 3.4, 3.5, 3.6 | the same files as W1 | Sonnet: more jobs in the same file. Its review gets the Review Focus 1 fixtures |
| 2 (after M1) | D1 | 1.3, 2.2 | `README.md` | Sonnet: documentation of targets that now exist |
| 3 | main | 4.1–4.5 | — | Only if 4.3 finds a module missing: a Sonnet dispatch that owns `ci.yml` |
| 4 | reviewer | 4.6 | — | Sonnet: a whole-branch review of a tooling change with no concurrency or security logic |

W1 and M1 share no file. W1 depends only on the target names fixed below (`fmt-check`, `vet`, `lint`, `generate-check`, `vuln`, `pincheck`, `tools-check`, `test`, `test-isolated`, `spec-check`, and the variables `SPEC_BASE` and `OPENSPEC`), so they run at the same time. Every dispatch gets a fresh Sonnet reviewer that edits nothing.

---

### Task 1.1: Red, gate targets need `tools` today

**Files:** none changed.

- [ ] **Step 1:** `mv .bin .bin.aside`.
- [ ] **Step 2:** For each target, run it with a `PATH` that hides any other copy of the tool:

  ```sh
  env PATH="/usr/bin:/bin:$(dirname "$(command -v go)")" make <target>
  ```

  Run it for `lint`, `vuln` and `generate-check`.
  - Expected: each fails with `golangci-lint: command not found`, `govulncheck: command not found` and `mockgen: executable file not found` (or similar) respectively.
  - Report the three lines.
- [ ] **Step 3:** `mv .bin.aside .bin`.

### Task 1.2: One file target per tool

**Files:** Modify `Makefile`.

**Interfaces:**
- Produces:
  - `TOOLS_DEPS := tools/go.mod tools/go.sum`;
  - the file targets `$(BIN)/golangci-lint`, `$(BIN)/govulncheck`, `$(BIN)/mockgen`, `$(BIN)/benchstat` and `$(BIN)/cyclonedx-gomod`, built from `github.com/golangci/golangci-lint/v2/cmd/golangci-lint`, `golang.org/x/vuln/cmd/govulncheck`, `go.uber.org/mock/mockgen`, `golang.org/x/perf/cmd/benchstat` and `github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod`;
  - `TOOL_BINS`, listing those five file targets.

- [ ] **Step 1: Implement.**
  - Each file target depends on `$(TOOLS_DEPS)`, and its recipe is `cd tools && GOWORK=off GOBIN=$(BIN) go install <package>`.
  - `tools: $(TOOL_BINS)`, with an empty recipe.
  - `lint: $(BIN)/golangci-lint`, `vuln: $(BIN)/govulncheck` and `generate-check: $(BIN)/mockgen`.
  - `tools-check` and `sbom` keep depending on `tools`, and `pincheck` needs no tool.
  - Keep the existing comment explaining `GOWORK=off`.
- [ ] **Step 2: Verify.** With `.bin` moved aside, run each of `make lint`, `make vuln` and `make generate-check` under the `PATH` from 1.1. Expected:
  - each passes;
  - `ls .bin` after each shows only the tools installed so far.
- [ ] **Step 3: Verify.** `touch tools/go.mod && make -n lint | grep 'go install'` prints one install line.
- [ ] **Step 4: Verify (Review Focus 5).** With `.bin` removed, `make -n -j8 check | grep -c 'go install'` prints `5`. Then `make tools && ls .bin` lists exactly `benchstat cyclonedx-gomod golangci-lint govulncheck mockgen`.
- [ ] **Step 5: Verify.** `make check` passes.

### Task 2.1: `make spec-check`

**Files:** Modify `Makefile`.

**Interfaces:**
- Produces:
  - `OPENSPEC ?= npx --yes @fission-ai/openspec@1.16.0`;
  - `SPEC_BASE ?= $(shell git merge-base HEAD main 2>/dev/null)`;
  - `.PHONY: spec-check`.
- The output lines W2 and the reviewers rely on, exactly:
  - `spec-check: base <sha>`;
  - `spec-check: base <given> unusable, falling back to merge-base with origin/main`;
  - `spec-check: change <name> touched, validating`;
  - `spec-check: change <name> untouched, skipped`.

- [ ] **Step 1: Red.** `make spec-check` fails with `No rule to make target 'spec-check'`.
- [ ] **Step 2: Implement the recipe,** with `set -eu -o pipefail` as the other looping recipes do.
  1. **Resolve the base.** If `SPEC_BASE` is empty, all zeros, or `git cat-file -e "$SPEC_BASE^{commit}"` fails, use `git merge-base HEAD origin/main` and print the fallback line.
  2. **Validate the specs:** `$(OPENSPEC) validate --specs --no-interactive`.
  3. **Validate the archive:** `$(OPENSPEC) validate --archived --no-interactive`.
  4. **Find what is touched:** `git diff --name-only <base>` plus `git ls-files --others --exclude-standard`, filtered to `openspec/changes/<name>/` with `<name>` not equal to `archive`.
  5. **Validate each active change.** For each directory `openspec/changes/*/` (not `archive`): if it is touched, print the touched line and run `$(OPENSPEC) validate <name> --type change --no-interactive`. Otherwise print the untouched line.

  A touched name whose directory no longer exists is ignored.
- [ ] **Step 3: Verify the clean tree.** `make spec-check` passes. Its output shows `split-ci-jobs` and `pre-release-api-fixes` as `touched, validating`, and `bff-resource-server` and `trusted-proxy-client-ip` as `untouched, skipped`.
- [ ] **Step 4: Verify a touched invalid change.** Create `openspec/changes/zz-invalid-fixture/` with a `proposal.md` and a `specs/time-source/spec.md` delta whose added requirement has no scenario. `make spec-check` fails, and its output names `zz-invalid-fixture`. Then `rm -r openspec/changes/zz-invalid-fixture`.
- [ ] **Step 5: Verify a broken settled spec.** In `openspec/specs/time-source/spec.md`, delete the `#### Scenario:` line of a requirement with exactly one scenario, choosing it with `grep -n`. `make spec-check` fails, naming `time-source`. Put the line back. `git diff --stat openspec/specs` is empty.
- [ ] **Step 6: Verify Review Focus 2, 3 and 4.**
  - `make spec-check SPEC_BASE=0000000000000000000000000000000000000000` passes and prints the fallback line.
  - The same holds for `1111111111111111111111111111111111111111`.
  - `make spec-check SPEC_BASE=e8762b6^` reports nothing about `key-port-context`. It may fail on another touched change it names; record which.
  - With `mkdir openspec/changes/zz-tmp && printf '## Why\n\nx\n' > openspec/changes/zz-tmp/proposal.md`, `make spec-check` fails, naming `zz-tmp`. Then `rm -r openspec/changes/zz-tmp`.

  The agent only runs these. The main session confirms that `openspec/` is unchanged afterwards.
- [ ] **Step 7: Verify the override and isolation.**
  - `make spec-check OPENSPEC=openspec` passes, when a local CLI exists.
  - `make -n check | grep -c openspec` prints `0`.

### Task 1.3 and 2.2: README development section

**Files:** Modify `README.md`, the `## Development` section only.

- [ ] **Step 1:** Replace the two-line block and the sentence "`make check` is what continuous integration runs." The new text says:
  - `make check` runs every build gate;
  - any gate runs alone (`make lint`, `make vuln`, `make generate-check`, `make fmt-check`, `make vet`, `make test`) and installs its own tool;
  - CI runs each gate as its own job, plus CodeQL and OpenSpec validation, behind one `ci-ok` result;
  - `make spec-check` validates the settled specs, the archived changes and the changes touched against `main`. It needs Node `>=22.12`, or `OPENSPEC=openspec` for a local CLI, and is not part of `make check`.
- [ ] **Step 2: Verify.** Run every command the section shows. Each runs as written.

### Task 3.1: Resolve action SHAs

**Files:** none changed. The output feeds 3.3 to 3.6.

- [ ] **Step 1:** For each of `actions/checkout@v7.0.1`, `actions/setup-go@v7.0.0`, `actions/setup-node@v7.1.0`, `actions/cache@v6.1.0` and `github/codeql-action@v4.39.2`:
  - read `gh api repos/<o>/<r>/git/ref/tags/<tag>`;
  - if `.object.type` is `tag`, follow it with `gh api repos/<o>/<r>/git/tags/<sha>`.

  First check `gh api repos/<o>/<r>/releases/latest`. If it names a newer release, use that release and report it.
- [ ] **Step 2: Verify.** `gh api repos/<o>/<r>/commits/<sha> --jq .sha` echoes each SHA. Report the table of action, tag and SHA.

### Task 3.2: `ci-needs-check.sh`

**Files:**
- Create `.github/scripts/ci-needs-check.sh` (executable).
- Create the fixtures `.github/scripts/testdata/needs-complete.yml` and `.github/scripts/testdata/needs-missing.yml`.

**Interfaces:**
- Produces: `ci-needs-check.sh <workflow-file> <aggregate-job-id>`.
  - It exits 0 when the aggregate's `needs` holds every other job id.
  - Otherwise it prints `ci-needs-check: <aggregate-job-id> does not need: <id>`, one line per missing id, and exits 1.
  - It exits 2 with a usage line on wrong arguments.

- [ ] **Step 1:** Confirm from the `actions/runner-images` Ubuntu 24.04 readme that `yq` (mikefarah, v4) is preinstalled. Report the line. If it is not, the script uses the preinstalled `python3`, with only the standard library and a minimal parse of the `jobs:` keys, and the report says so.
- [ ] **Step 2: Fixtures.**
  - `needs-missing.yml` has jobs `a`, `b`, `c` and `ok`, where `ok` needs `[a, b]`.
  - `needs-complete.yml` is the same, except that `ok` needs `[a, b, c]`.
  - Neither holds a `uses:` line, because `pincheck` scans all of `.github`.
- [ ] **Step 3: Red.** Write the script, then run `.github/scripts/ci-needs-check.sh .github/scripts/testdata/needs-missing.yml ok`. Expected: exit 1, with `ci-needs-check: ok does not need: c`.
- [ ] **Step 4: Verify.**
  - The complete fixture exits 0.
  - Running with no arguments exits 2.
  - `shellcheck` reports nothing.

### Task 3.3: Check jobs and `test`

**Files:** Modify `.github/workflows/ci.yml`.

**Interfaces:**
- Produces: the job ids `format`, `vet`, `lint`, `generate`, `vuln`, `pincheck`, `tools-check` and `test`. W2 adds `codeql`, `openspec` and `ci-ok`.

- [ ] **Step 1: Implement.**
  - `env: GO_VERSION: "1.27.x"`, with a comment pointing to the matrix's `go`, and the matrix carries the reverse comment.
  - **Each static job:** checkout, then setup-go with `go-version: ${{ env.GO_VERSION }}` and `cache: false`, then `make <target>`.
    - `format` runs `make fmt-check` and caches nothing.
    - `vet`, `lint`, `generate`, `vuln`, `pincheck` and `tools-check` each cache `~/go/pkg/mod` and `~/.cache/go-build`, with key `go-${{ github.job }}-${{ runner.os }}-${{ env.GO_VERSION }}-${{ hashFiles('**/go.sum') }}` and restore key `go-${{ github.job }}-${{ runner.os }}-${{ env.GO_VERSION }}-`.
    - `lint` and `tools-check` also cache `~/.cache/golangci-lint`.
  - **`test`:** the existing matrix, `strategy` and `env`. Its cache key uses `matrix.go` in place of `env.GO_VERSION`. Its steps are `make test`, then `make test-isolated`, each named for its target.
  - Keep the existing comments on the matrix and the draft trigger.
- [ ] **Step 2: Verify.** `actionlint` prints nothing, and `grep -E 'uses: ' .github/workflows/ci.yml | grep -vE '@[0-9a-f]{40} # v'` prints nothing.

### Task 3.4: `codeql`

**Files:** Modify `.github/workflows/ci.yml`.

- [ ] **Step 1: Implement.**
  - A matrix with `include`:
    - `{language: go, build-mode: autobuild}`;
    - `{language: actions, build-mode: none}`.
  - Job-level `permissions: {security-events: write, contents: read, actions: read}`.
  - **Steps:** checkout. For `go` only (`if: matrix.language == 'go'`): setup-go with `GO_VERSION` and `cache: false`, plus the per-job cache, with `${{ matrix.language }}` added to the key. Then `github/codeql-action/init` with `languages` and `build-mode` from the matrix, then `github/codeql-action/analyze` with `category: "/language:${{ matrix.language }}"`.
  - Follow the action's own README for what `autobuild` mode needs between `init` and `analyze`.
- [ ] **Step 2: Verify.** `actionlint` prints nothing, and `grep -ci python .github/workflows/ci.yml` prints `0`.

### Task 3.5: `openspec`

**Files:** Modify `.github/workflows/ci.yml`.

- [ ] **Step 1: Implement.**
  - checkout with `fetch-depth: 0`;
  - setup-node with `node-version: lts/*`;
  - a step whose `env` sets `SPEC_BASE: ${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}`, and that runs `make spec-check SPEC_BASE="$SPEC_BASE"`;
  - no Go setup.
- [ ] **Step 2: Verify.** `actionlint` prints nothing.

### Task 3.6: `ci-ok`

**Files:** Modify `.github/workflows/ci.yml`.

**Interfaces:**
- Consumes: `ci-needs-check.sh` (task 3.2).

- [ ] **Step 1: Red (Review Focus 1).** Write the result expression, then run it locally against four inline JSON fixtures in the shape of `toJSON(needs)`, each `{"a":{"result":"success"},"b":{"result":"<r>"}}` with `<r>` set to `cancelled`, `skipped`, `failure` and `success`:

  ```sh
  jq -e 'to_entries | map(select(.value.result != "success")) | if length == 0 then true else (map("ci-ok: \(.key) \(.value.result)") | .[] | stderr) | false end'
  ```

  Expected: the first three exit non-zero and name `b`. `success` exits 0. Report the four exit codes.
- [ ] **Step 2: Implement.**
  - `needs: [format, vet, lint, generate, vuln, pincheck, tools-check, test, codeql, openspec]`;
  - `if: always() && (<draft condition>)`;
  - checkout;
  - a step running `.github/scripts/ci-needs-check.sh .github/workflows/ci.yml ci-ok`;
  - a step with `env: NEEDS: ${{ toJSON(needs) }}` that runs the expression on `"$NEEDS"`.
- [ ] **Step 3: Verify.**
  - `actionlint` prints nothing.
  - `.github/scripts/ci-needs-check.sh .github/workflows/ci.yml ci-ok` exits 0.
  - Removing `vuln` from `needs` makes it exit 1 with `does not need: vuln`. Then restore it.

### Tasks 4.1–4.5: Proof on GitHub (main session)

Follow `tasks.md` 4.1 to 4.5 as written. What the main session checks at each one:

- **4.1:**
  - `gh run list --branch feat/pre-release-api-fixes` shows no run for the pushed commit while #68 is a draft.
  - After it is marked ready, `gh run view <id> --json jobs` lists `format`, `vet`, `lint`, `generate`, `vuln`, `pincheck`, `tools-check`, two `test` legs, two `codeql` legs, `openspec` and `ci-ok`, all `success`.
  - Record the wall-clock time and the summed job durations against run 41356788862.
- **4.2:** the disposable pull request shows only `format` and `openspec` failing, `openspec`'s log naming `zz-invalid-fixture`, and `ci-ok` as `failure`, not `skipped`.
- **4.3:**
  - `gh api 'repos/kartaladev/scrty/code-scanning/analyses?ref=refs/pull/<n>/merge'` lists `go` and `actions`.
  - The `codeql (go)` log shows extraction for each of the nine `go.work` modules.
  - If any module is missing, run a Sonnet dispatch that owns `ci.yml` to switch to `build-mode: manual`, with a step running `go build ./...` in each workspace module. Then re-verify, and record the outcome in design decision 5.
- **4.4:** the second run's cache steps report hits on their own keys, and `gh api repos/kartaladev/scrty/actions/cache/usage` is under 10 GB.
- **4.5:** `make check`, `make spec-check` and `openspec validate split-ci-jobs --strict` all pass. Keep their output.

### Task 4.6: Whole-branch review

- [ ] A fresh Sonnet reviewer, who edits nothing, reads the change's own files in `git diff origin/main...HEAD` (`Makefile`, `README.md`, `.github/`) and both spec deltas. For every requirement and scenario in those deltas, it reports one of:
  - met, with the file, line or run that shows it;
  - a finding, `REPRODUCED` with a failing run or test, or `UNREPRODUCED` with the reason.

  Findings go back to a fresh dispatch of the lane that owns the file.

### Commits (main session)

Commit one per dispatch, after its verification and review, staging exact paths:
1. `build(make): let each gate target install its own tool`;
2. `build(make): add spec-check for OpenSpec validation`;
3. `ci: run each check as its own job behind ci-ok`;
4. `ci: add CodeQL and OpenSpec jobs`;
5. `docs: describe per-gate targets and spec-check`.
