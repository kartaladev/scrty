# Tasks

This change has no Go code. It touches `Makefile` targets, a workflow file, a small shell script and the README. Each task still runs red before green:
- first a run that is expected to fail, and why it should fail;
- then the change;
- then the run that passes.

Restore a deliberately broken file by editing it back, never with a git command that discards work. Tasks marked **(main session)** push branches or open pull requests. Tasks marked **(maintainer)** change the public repository's settings. Agents do neither.

## 1. Gate targets that stand alone (design decision 2; module-layout scenario "One gate run on its own")

- [ ] 1.1 Red: move `.bin` aside, then run `make lint`, `make vuln` and `make generate-check` one at a time. Record that each fails because its tool (`golangci-lint`, `govulncheck`, `mockgen`) is not found.
- [ ] 1.2 Add one file target per tool in `tools/go.mod`, for example `$(BIN)/golangci-lint`.
  - Each builds that one package from `tools/`, with `GOWORK=off GOBIN=$(BIN)`, and depends on `tools/go.mod` and `tools/go.sum`.
  - Make `lint`, `vuln` and `generate-check` depend on their own tool.
  - Keep `tools` installing every tool, and leave `check`'s prerequisites and its `test-isolated` recipe line unchanged.

  Verify:
  - with `.bin` removed, each of `make lint`, `make vuln` and `make generate-check` passes alone, and afterwards `.bin` holds only the binary that target needed;
  - after `touch tools/go.mod`, `make -n lint` shows the reinstall;
  - `make tools` installs all five tools;
  - `make check` passes.
- [ ] 1.3 Update the README's development section (around "`make check` is what continuous integration runs"):
  - any single gate can be run on its own;
  - CI runs each gate as its own job;
  - `make check` remains the one local command for the build gates.

  Verify that every command the section shows runs as written.

## 2. `make spec-check` (design decision 6; continuous-integration requirements "Spec validation checks settled specs and the changes a run touches" and "Spec validation runs locally on its own command")

- [ ] 2.1 Red: `make spec-check` fails as an unknown target. Then add the target, with these defaults:
  - `OPENSPEC ?= npx --yes @fission-ai/openspec@1.16.0`;
  - `SPEC_BASE ?=` the merge base of `HEAD` and `main`, falling back to `origin/main` when the base is unreachable or all zeros.

  It runs, non-interactively and never with `--strict`:
  - `validate --specs`;
  - `validate --archived`;
  - `validate <name> --type change` for each still-existing directory under `openspec/changes/` (other than `archive`) with a file changed between `SPEC_BASE` and the working tree.

  Do not add it to `check`. Verify each of these, editing every broken file back afterwards:
  - **Clean tree:** on this branch it passes, and its output shows `split-ci-jobs` validated and the untouched drafts `bff-resource-server` and `trusted-proxy-client-ip` not validated.
  - **Touched invalid change:** a throwaway directory `openspec/changes/zz-invalid-fixture/`, holding a proposal and a delta whose requirement has no scenario, makes it fail, naming `zz-invalid-fixture`. Delete the directory afterwards.
  - **Broken settled spec:** deleting one `#### Scenario:` heading line from a requirement that has only one scenario, in a settled spec, makes it fail, naming that spec.
  - **Override:** `make spec-check OPENSPEC=openspec` uses the locally installed CLI.
  - **Build gates without Node:** `make check` still runs no OpenSpec command (`make -n check | grep -c openspec` prints `0`).
- [ ] 2.2 Document `make spec-check` in the README's development section:
  - what it validates;
  - that it needs Node `>=22.12` or a local OpenSpec CLI through `OPENSPEC=`;
  - that it is not part of `make check`.

  Verify that the documented commands run as written.

## 3. The workflow (design decisions 1, 3, 4, 5, 7 and 8; every continuous-integration requirement)

- [ ] 3.1 Resolve the commit SHA of each release design decision 8 names: `actions/checkout` v7.0.1, `actions/setup-go` v7.0.0, `actions/setup-node` v7.1.0, `actions/cache` (the design records v6.1.0 and v5.1.0 from two reads; settle the newest from the tags) and `github/codeql-action` v4.39.2. Use the GitHub API and dereference annotated tags. If a newer release exists when the work starts, use it, and report the change so the main session updates decision 8. Verify `gh api repos/<owner>/<repo>/commits/<sha>` resolves each SHA, and report the table of tags and SHAs.
- [ ] 3.2 Add `.github/scripts/ci-needs-check.sh`. It takes the workflow file and the aggregate job's id, and fails, naming each missing id, when the aggregate's `needs` leaves out any other job in the workflow.
  - Use a YAML tool that is preinstalled on `ubuntu-latest`, and confirm from the runner image's documentation that it is. If none is, install one pinned in the step and report it.
  - Red: run it against a fixture workflow whose aggregate omits one job, and confirm it fails naming that job.
  - Verify it passes against a fixture that lists every job, and that `shellcheck` reports nothing.
- [ ] 3.3 Rewrite `.github/workflows/ci.yml`:
  - **Static jobs:** `format`, `vet`, `lint`, `generate`, `vuln`, `pincheck` and `tools-check`, each running its `make` target on a workflow-level `GO_VERSION`.
  - **`test`:** on the existing matrix, with `make test` and then `make test-isolated` as separate steps.
  - **Caching:** per-job `actions/cache` keys for the building jobs, and `cache: false` on setup-go.
  - **Drafts:** the draft condition on every job.
  - **Pinning:** every action pinned by SHA with its tag in a comment.
  - **Cross-references:** comments linking `GO_VERSION` and the matrix's Go entry.

  Verify:
  - `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12` reports nothing on it;
  - every `uses:` line references a 40-character SHA (`grep -E 'uses: ' .github/workflows/ci.yml | grep -vE '@[0-9a-f]{40}( |$)'` prints nothing).
- [ ] 3.4 Add the `codeql` job to `ci.yml`:
  - a matrix over `go` (`build-mode: autobuild`) and `actions` (`build-mode: none`);
  - job-level permissions `security-events: write`, `contents: read` and `actions: read`;
  - the draft condition and a per-job cache.

  Verify `actionlint` reports nothing, and that no `python` language appears in the file.
- [ ] 3.5 Add the `openspec` job to `ci.yml`:
  - `fetch-depth: 0`;
  - setup-node with `lts/*`;
  - `make spec-check SPEC_BASE=<base>`, where the base is the pull request's base SHA, or the push's `before`.

  Verify `actionlint` reports nothing.
- [ ] 3.6 Add the `ci-ok` aggregate job:
  - `needs` lists every other job;
  - `if: always() && (<draft condition>)`;
  - one step runs `ci-needs-check.sh` on the workflow;
  - one step fails unless every `needs.*.result` is `success`.

  Verify:
  - `actionlint` reports nothing;
  - `ci-needs-check.sh .github/workflows/ci.yml ci-ok` passes;
  - removing one id from `needs` makes it fail naming that job, and adding the id back makes it pass.

## 4. Proof on GitHub (integration: every continuous-integration requirement; design decisions 3, 5 and 7)

- [ ] 4.1 **(main session)** Push the branch to pull request #68, which carries this change, while it is a draft. Verify that no workflow job runs. Mark it ready for review, and verify that every job runs on its head commit and `ci-ok` passes. Record:
  - the run's wall-clock time and longest job;
  - the total job time, against run 41356788862.
- [ ] 4.2 **(main session)** On a disposable branch from this one, open a pull request with an unformatted Go file and the throwaway invalid change from task 2.1. Verify:
  - only `format` and `openspec` fail;
  - `openspec` names `zz-invalid-fixture`;
  - every other check job passes;
  - `ci-ok` runs and fails rather than being skipped.

  Then close the pull request and delete the branch.
- [ ] 4.3 Check CodeQL coverage on the run from 4.1:
  - the Go analysis log shows packages from every module that `go.work` lists;
  - `gh api 'repos/kartaladev/scrty/code-scanning/analyses?ref=<pr ref>'` lists a `go` and an `actions` analysis for the head commit.

  If any workspace module is missing, switch `go` to `build-mode: manual`, with a build of each workspace module, and re-verify. Report the outcome so the main session records it in design decision 5.
- [ ] 4.4 After a second run on the pull request, verify:
  - each building job reports a cache hit on its own key;
  - `gh api repos/kartaladev/scrty/actions/cache/usage` reports the repository's total under 10 GB.

  Record the sizes.
- [ ] 4.5 Run `make check`, `make spec-check` and `openspec validate split-ci-jobs --strict`. Verify all three pass, and keep their output.
- [ ] 4.6 Review the whole branch against every requirement in this change's two spec deltas, with a reviewer that wrote none of it. Verify that the review lists each requirement and scenario as met, or files a finding.

## Workflow follow-up

- **(maintainer)** Confirm that CodeQL default setup is off, and add `ci-ok` to the `default` ruleset's required status checks once the pull request's run is green.
- If `release-readiness` lands after this change, its `design.md` stops describing CI as running `make check`.
- Archive `split-ci-jobs` after the maintainer steps, and verify that the archived `module-layout` and `continuous-integration` specs validate.
