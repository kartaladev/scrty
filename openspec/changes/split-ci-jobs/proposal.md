## Why

CI is one job that runs `make check` on each PostgreSQL leg of the matrix. That causes three problems.

- **One status line for every concern.** A gofmt slip, a lint finding, a vulnerability and a failing test all show up as the same red job. To learn which gate failed, someone has to read the log.
- **Duplicated work on the long path.** gofmt, vet, lint, govulncheck and the generate check do not depend on the database, yet each leg runs all of them. A leg takes about 11.5 minutes: about 7 for the tests, and the rest mostly for gates that run twice. Run 41356788862 was read on 2026-11-02.
- **Two gates the repository needs are missing.**
  - **CodeQL.** The repository's ruleset requires CodeQL code scanning results, and CodeQL is not configured. GitHub blocks a merge while a required tool is not configured, so every pull request today merges only through the maintainer's bypass.
  - **OpenSpec validation.** Nothing validates the OpenSpec artifacts. `release-readiness` already fails validation: its delta to the authentication spec leaves out three scenarios that the archive of `key-port-context` added afterwards. No check flagged it.

## What Changes

- **One CI job per check.**
  - `format`, `vet`, `lint`, `generate` and `vuln` each run once, on the Go release in the matrix, without a database.
  - `test` alone runs on the PostgreSQL and Redis matrix. It also runs the test that must not run beside the suite.
  - Each job calls the same `make` target a contributor runs locally.
- **One aggregate result.**
  - A final job passes only when every other job passed.
  - Its name is the single status the repository's ruleset needs to require, so adding, renaming or removing a job never touches the ruleset.
- **A CodeQL job** in the same workflow, analysing Go and the workflow files (`actions`).
  - Python is excluded: the only Python in the repository is evidence kept in an archived change.
  - GitHub's default setup stays off, because the workflow replaces it.
- **An OpenSpec validation job.** It runs from a new `make spec-check` target, which is not part of `make check`, so Go contributors need no Node toolchain. The job validates:
  - the settled specs;
  - the archived changes;
  - every change that the pushed commits or the pull request touch.
- **`make` targets that stand alone.** Each gate target installs only the tool it uses, at the version pinned in the `tools` module. A single CI job therefore never builds tools it does not need. `make check` still runs every Go build gate, in the same order.
- **Spec correction.** The `module-layout` parity scenario promises that local and CI runs share "the same set of checks". That stays true for the build gates, and is narrowed to them. CodeQL and OpenSpec validation are named as checks that run only in CI.
- **Not in scope.**
  - Scheduled runs: scans run on push and pull request only, by decision on 2026-11-02.
  - Strict OpenSpec validation: 252 warnings about over-long requirements would fail 32 of 36 settled specs. That clean-up is its own change.
  - Fixing `release-readiness`'s delta.
- **Repository setting, a step for the maintainer.** Adding the aggregate job to the ruleset's required status checks is a change to the public repository's settings, so tooling does not make it. Today the ruleset requires no status check at all.

## Capabilities

### New Capabilities

- `continuous-integration`: what the repository's CI runs and how it reports.
  - Each check runs as its own job, and only the test job runs on the database matrix.
  - One aggregate result.
  - CodeQL code scanning.
  - OpenSpec validation.
  - Draft pull requests are skipped.

### Modified Capabilities

- `module-layout`: the build-gates requirement keeps its gates. Its local and CI parity is stated for the build gates, and names CodeQL and OpenSpec validation as checks that run only in CI.

## Impact

- **Changed files:**
  - `.github/workflows/ci.yml`, rewritten into per-check jobs, a CodeQL job and an aggregate job;
  - the `Makefile`, which gains per-tool install targets and `spec-check`, and makes each gate target install its own tool;
  - `README.md`, whose line "`make check` is what continuous integration runs" becomes stale.
- **No library code, API or `go.mod` change.**
- **Related changes:**
  - `close-security-gaps` (in progress) pins every workflow action to a commit SHA and adds a CI check for the pinning. This change adds new action references, such as `github/codeql-action` and a Node setup action. They are pinned the same way from the start, so it does not matter which change lands first. The pinning check becomes one more job under the aggregate result.
  - `release-readiness` adds `release-check.yml` "on `ci.yml`'s matrix". It reads the matrix only, which stays the same here. Its `design.md` describes CI as running `make check`, and whichever change lands second updates that line.
- **Repository settings (maintainer):**
  - require the aggregate job in the `default` ruleset;
  - leave CodeQL default setup off.

## References

### Per-check jobs and the aggregate result

**Researched (accessed 2026-11-02):**
- Job and step timings of run 41356788862 and its log, read through the GitHub API: the duplicated static gates and the test job's share of each leg. These drift with every run.
- The `default` ruleset (id 26279791), read through the GitHub API: no required status checks, a required CodeQL code-scanning rule, and the maintainer's bypass. Live; it drifts.

### CodeQL

**Researched (accessed 2026-11-02):**
- [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets): the code-scanning rule blocks a merge when "a required tool is not configured for the repository".
- [CodeQL code scanning for compiled languages](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/codeql-code-scanning-for-compiled-languages): Go is analysed with `autobuild` or manual build steps, and manual steps need advanced setup.
- The repository's CodeQL default-setup state, read through the GitHub API: `not-configured`, with detected languages `actions`, `go` and `python`. Live; it drifts.
- [github/codeql PR 20675](https://github.com/github/codeql/pull/20675) and a [docker-cli autobuild fix](https://git.coopcloud.tech/p4u1/docker-cli/src/commit/24186d8008ecbd5e00b09185cd42ac88aac6f701): `autobuild` has misbehaved on multi-module repositories and `go.work` workspaces. Anecdotal and unverified for the current CodeQL release.

### OpenSpec validation

**Researched (accessed 2026-11-02):**
- `openspec validate --help` and runs of `--specs`, `--archived`, `--all` and `--strict` against the tree, with OpenSpec CLI 1.15.0.
- The `@fission-ai/openspec` package on npm: version 1.16.0, which needs Node `>=22.12.0`. Live; it drifts.
