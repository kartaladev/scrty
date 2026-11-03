## Context

See `proposal.md` for why. What shapes the approach:

- **CI today.** `.github/workflows/ci.yml` has one job, `check`, on a matrix:
  - one Go release (`1.27.x`);
  - two PostgreSQL and Redis pairings (15.19 with 7.4.11, 18.6 with 8.10.2).

  Each leg runs `make check`, which runs:
  - `tools`;
  - `pincheck` and `tools-check`, for the workflow pins and the `tools` module, which sits outside the workspace;
  - `fmt-check`, `vet`, `lint`, `test`, `vuln` and `generate-check`, over every workspace module;
  - then `test-isolated`, from the recipe so that it never runs beside the suite.

  Drafts are skipped through an `if:` on the job. The workflow has `contents: read` only.
- **Gate targets assume `tools` already ran.** `lint`, `vuln` and `generate-check` call `golangci-lint`, `govulncheck` and `mockgen` from `.bin`. Only `check` depends on `tools`, and `tools` runs `go install tool`, which builds all five tools pinned in `tools/go.mod`.
- **The ruleset.**
  - It requires no status check.
  - It does require CodeQL results, blocking on high-or-higher security alerts and on errors.
  - It also has a `code_quality` rule, which passes today: on a merge to `main`, `code_scanning` was the only rule that failed (rule suite 4880674338, read 2026-11-03).
  - The maintainer can bypass it.
- **Other changes touch the same files.**
  - `close-security-gaps` (archived 2026-11-03) pinned every workflow action to a full commit SHA and added `pincheck` and `tools-check` to `make check`.
  - `release-readiness` adds `release-check.yml` on `ci.yml`'s matrix.
- **Library-design rule.** CI is repository tooling, not library behaviour, so no decision here has a consumer override. Where contributors get a default they can change, the decision says so.

## Goals / Non-Goals

**Goals:**
- A gate's failure is visible from its job's name, without reading a log.
- Every job runs the same `make` target a contributor runs, so the two cannot drift apart.
- The ruleset's CodeQL rule can be satisfied without the bypass.
- The wall-clock time of a run is bounded by the test job, not by gates repeated on every leg.

**Non-Goals:**
- Scheduled scans (decided 2026-11-02).
- Strict OpenSpec validation.
- Shortening the test job itself, or changing the matrix.
- Cancelling superseded runs (`concurrency`). It is useful, but no concern here needs it.
- Enabling GitHub Code Quality: the ruleset's `code_quality` rule does not block merges today (see Context).

## Decisions

### 1. One job per check; only `test` runs on the matrix

- **The jobs:**
  - `format`, `vet`, `lint`, `generate`, `vuln`, `pincheck` and `tools-check`, once each, on the Go release in a workflow-level `GO_VERSION` (`1.27.x`);
  - `test`, on the existing matrix, unchanged;
  - `codeql`;
  - `openspec`;
  - the aggregate.
- **Inside `test`:** `make test` runs as one step and `make test-isolated` as the next. Steps on one runner run in order, so the isolated test still never runs beside the suite. The two steps also give the two parts separate logs.
- **Go release of the static jobs.** They run on the newest Go release CI tests. When a second release joins the test matrix, `GO_VERSION` moves to the newest one and the static jobs stay single runs.
- **Alternatives considered:**
  - A grouped `static` job for format, vet and generate. It would need fewer runners, but would report gofmt as "static". Rejected by the maintainer on 2026-11-02.
  - Keeping `make check` per leg, with the static gates still running twice. That keeps the problem this change exists to fix.
- **Override:** none. This is repository tooling (see Context).

### 2. Jobs call `make` targets, and each target installs its own tool

- **One file target per tool.** Each tool in `tools/go.mod` gets a target, for example `$(BIN)/golangci-lint`:
  - it runs `cd tools && GOWORK=off GOBIN=$(BIN) go install <package>`, which builds the version `tools/go.mod` pins;
  - it depends on `tools/go.mod` and `tools/go.sum`, so bumping a tool reinstalls it on the next run.
- **Each gate depends on its own tool.** `lint`, `vuln` and `generate-check` depend on the file target of the tool they call. `tools` keeps installing everything, `benchstat` included.
- **`make check` is unchanged.** It runs the same targets in the same order, and `test-isolated` still runs from its recipe.
- **Alternative considered:** `golangci/golangci-lint-action` and `golang/govulncheck-action` instead of `make`. That would give each tool two version sources, the action input and `tools/go.mod`, and CI could then pass with a linter a contributor never ran. Rejected for parity.
- **Override:** a contributor runs `make lint` or any other gate alone, with no `make tools` first. Running `make tools` first still works.

### 3. The aggregate job: `ci-ok`

- **`needs`:** every other job.
- **Runs whatever the other jobs did:** `if: always()`, combined with the draft condition of decision 4.
- **Pass rule:** its single step fails unless every entry of `needs.*.result` is `success`. So a `failure`, `cancelled` or `skipped` dependency fails it.
- **Why `always()` is required.** By default, a job whose dependency failed is skipped. GitHub reports a skipped job as a successful check. Without `always()`, a failing gate would leave a required `ci-ok` "successful", and the pull request mergeable.
- **The `needs` list must stay complete.** The same step checks that `needs` names every other job id in the workflow, and fails naming any that is missing. This is the spec's "Job added" scenario. It reads the job ids from the workflow file with a YAML tool available on the runner. The implementer confirms that tool is preinstalled on `ubuntu-latest`, and otherwise installs it pinned.
- **Name.** The name `ci-ok` stays fixed, so the maintainer requires it once, and later job changes never touch the ruleset.
- **Alternative considered:** requiring every job by name in the ruleset. Every added, renamed or removed job, including each matrix leg, would then be a ruleset edit, and a forgotten one lets a gate go unrequired.
- **Override:** none.

### 4. Drafts: the existing trigger, on every job

- **Triggers:** unchanged.
- **Check jobs:** each carries the current condition, `github.event_name != 'pull_request' || !github.event.pull_request.draft`.
- **`ci-ok`:** carries `always() && (<that condition>)`, so it is also skipped for a draft. That is harmless: a draft cannot be merged.

### 5. CodeQL: advanced setup, in `ci.yml`

- **Where.** A `codeql` job in `ci.yml`, so `ci-ok` can depend on it. A separate `codeql.yml` would be a separate workflow that `needs` cannot reach. With no schedule wanted, nothing argues for a separate file.
- **Languages.** A matrix over `go` and `actions`:
  - `actions` uses `build-mode: none`;
  - `go` starts with `build-mode: autobuild`.
- **Workspace coverage.** Whether autobuild extracts every workspace module is unverified for the current CodeQL release (proposal References). A task checks the analysis log for every workspace module's packages. If any module is missing, the job switches `go` to `build-mode: manual`, with a build of each workspace module as the manual step.
- **Python is left out**, so the archived evidence scripts are not analysed.
- **Permissions, at job level:** `security-events: write` to upload the results, and `contents: read` and `actions: read`. The workflow-level default stays `contents: read`.
- **Default setup stays off.** GitHub refuses results from advanced setup while default setup is on for the same language. This is listed for the maintainer.
- **Alternative considered:** default setup. It needs no file, but:
  - it analyses Python;
  - it cannot take a manual build;
  - it is not versioned or reviewed;
  - it reports outside `ci-ok`.
- **Override:** none.

### 6. Spec validation: `make spec-check`, outside `make check`

- **The target runs, in order:**
  1. `$(OPENSPEC) validate --specs`;
  2. `$(OPENSPEC) validate --archived`;
  3. `$(OPENSPEC) validate <name> --type change`, for each directory under `openspec/changes/` (other than `archive`) that has a file changed between `$(SPEC_BASE)` and the working tree, and still exists. A change archived by the same pull request no longer exists, and step 2 covers it.

  All three use the CLI's non-interactive mode, and none uses `--strict`.
- **Defaults:**
  - `OPENSPEC ?= npx --yes @fission-ai/openspec@1.16.0`. Version 1.16.0 passed `--specs` (36/36) and `--archived` (35/35) on 2026-11-02.
  - `SPEC_BASE ?= $(shell git merge-base HEAD main)`. Locally that covers committed and uncommitted edits against `main`.
- **In CI:**
  - the job checks out the full history (`fetch-depth: 0`);
  - it sets up Node with `lts/*` (OpenSpec 1.16.0 needs `>=22.12.0`);
  - it passes `SPEC_BASE`: the pull request's base SHA, or for a push the `before` SHA.
  - If the base is unreachable or all zeros, the target falls back to the merge base with `origin/main`.
- **Not in `make check`.** Go contributors then need no Node (decided 2026-11-02). The `module-layout` delta narrows the parity promise to the build gates.
- **Alternatives considered:**
  - Validating every active change. It fails today on two drafts with no deltas yet.
  - `--strict`. It fails 32 of 36 settled specs on 252 length warnings.
- **Override:** a contributor with OpenSpec installed runs `make spec-check OPENSPEC=openspec`, and can widen or narrow what is checked with `SPEC_BASE=<ref>`.

### 7. Go caches: a key per job

- **setup-go caching is off** (`cache: false`).
- **Each building job** (`vet`, `lint`, `generate`, `vuln`, `pincheck`, `tools-check`, `test`, `codeql`) caches the module and build caches with `actions/cache`:
  - key: `go-<job>-<os>-<Go version>-<hash of every go.sum>`;
  - restore keys: the same prefix without the hash.
- **`format` and `openspec`** build nothing and cache nothing.
- **Why per job.** A save under a key that already exists creates no new entry. If jobs shared one key, as setup-go's does, the first job to finish would write the cache for all of them, and that might be `vet` saving none of `test`'s race-built packages.
- **Alternative considered:** setup-go with `cache-dependency-path: "**/go.sum"`. It fixes the key's inputs but still shares one key across jobs.
- **Override:** none.

### 8. Actions pinned to commit SHAs from the start

- **Every action reference** this change writes is a full 40-character SHA with its tag in a comment. That satisfies `pincheck`.
- **Releases at writing** (GitHub API, 2026-11-03):

  | Action | Release |
  |---|---|
  | `actions/checkout` | v7.0.1 |
  | `actions/setup-go` | v7.0.0 |
  | `actions/setup-node` | v7.1.0 |
  | `actions/cache` | v6.1.0 as read on 2026-11-02; a release query on 2026-11-03 returned v5.1.0 first, so task 3.1 settles it from the tags |
  | `github/codeql-action` | v4.39.2 |

- **Current majors.** `ci.yml` already pins `checkout` v7.0.1 and `setup-go` v7.0.0. The other SHAs are resolved from the tags through the API when the change is implemented.
- **`pincheck` runs as its own job under `ci-ok`,** so a new reference that is not pinned fails that job.
- **Override:** none.

## Risks / Trade-offs

- **More runner time in total, less wall-clock time.** About ten jobs each pay roughly 25 s of setup. The static gates no longer run twice. → The longest path is the test job, about 7.5 minutes against about 11.5 today. Total runner time is measured on the first green run and recorded in the tasks' evidence.
- **The `codeql` Go job may become the longest path.** → It runs in parallel. Its time is measured on the first run. If it exceeds the test job, that is recorded, and nothing else here changes.
- **The 10 GB repository cache limit.** Six per-job caches, the race-built test cache the largest, may evict each other. → Least-recently-used entries are evicted, so the worst case is a cold cache, never a wrong result. The total size is checked after the first runs.
- **`GO_VERSION` and the test matrix name the Go release in two places.** → A comment beside each points to the other. `module-layout`'s supported-releases requirement governs the matrix.
- **Rollback while `ci-ok` is required.** Reverting this change removes `ci-ok`. A required check that never reports blocks every pull request. → Remove `ci-ok` from the ruleset before reverting.

## Migration Plan

1. Land the change. `ci-ok` and every job run on the pull request that brings it in, which also gives the first CodeQL results.
2. **(Maintainer)** Confirm that CodeQL default setup is off, and add `ci-ok` to the `default` ruleset's required status checks.
3. If `release-readiness` lands after this change, it updates its description of CI as `make check`.

## Open Questions

- None. The earlier question, whether the ruleset's `code_quality` rule blocks merges, is answered: it passed on a merge to `main`, and `code_scanning` was the only rule that failed (see Context).

## References

### Per-check jobs, `make` targets and the aggregate result

**Researched (accessed 2026-11-02):**
- Job and step timings of run 41356788862 and its log, read through the GitHub API: the duplicated static gates and the test job's share of each leg. These drift with every run.
- The `default` ruleset (id 26279791), read through the GitHub API: no required status checks, a required CodeQL code-scanning rule, a `code_quality` rule, and the maintainer's bypass. Live; it drifts.
- [Troubleshooting required status checks](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks): a job skipped by a conditional "reports Success", and `skipped` is a successful check status. This is decision 3's reason for `always()`.

### CodeQL

**Researched (accessed 2026-11-02):**
- [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets): the code-scanning rule blocks a merge when "a required tool is not configured for the repository".
- [CodeQL code scanning for compiled languages](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/codeql-code-scanning-for-compiled-languages): Go uses `autobuild` or manual build steps, and manual steps need advanced setup.
- The repository's CodeQL default-setup state, read through the GitHub API: `not-configured`, with detected languages `actions`, `go` and `python`. Live; it drifts.
- Rule suite 4880674338, read through the GitHub API on 2026-11-03: `code_scanning` failed with "Waiting for Code Scanning results", and every other rule passed. It confirms which rule blocks merges.
- [CodeQL supported languages and frameworks](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/), accessed 2026-11-03: Go up to 1.27.
- [github/codeql PR 20675](https://github.com/github/codeql/pull/20675) and a [docker-cli autobuild fix](https://git.coopcloud.tech/p4u1/docker-cli/src/commit/24186d8008ecbd5e00b09185cd42ac88aac6f701): `autobuild` has misbehaved on multi-module repositories and `go.work` workspaces. Anecdotal and unverified for the current release; it is the reason for decision 5's coverage check.

### Spec validation

**Researched (accessed 2026-11-02):**
- `openspec validate --help`, and runs of `--specs`, `--archived`, `--all` and `--strict` against the tree with OpenSpec CLI 1.15.0. `--specs` and `--archived` were also run with 1.16.0 through `npx`.
- The `@fission-ai/openspec` package on npm: 1.16.0, published 2026-10-30, needs Node `>=22.12.0`. Live; it drifts.

### Caching and action versions

**Researched (accessed 2026-11-02):**
- [actions/setup-go README](https://github.com/actions/setup-go/blob/main/README.md): caches modules and build outputs, keyed by default on the root `go.mod`'s hash.
- [actions/cache README](https://github.com/actions/cache/blob/main/README.md): "If the provided `key` matches an existing cache, a new cache is not created". Also a 10 GB per-repository limit with least-recently-used eviction.
- The latest releases of `actions/checkout`, `actions/setup-go`, `actions/setup-node`, `actions/cache`, `github/codeql-action` and `rhysd/actionlint` (v1.7.12), read through the GitHub API. Live; they drift.

**Primary documentation:**
- [Workflow syntax: `jobs.<job_id>.needs`](https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idneeds): dependents of a failed job are skipped unless a condition such as `always()` keeps them running.
