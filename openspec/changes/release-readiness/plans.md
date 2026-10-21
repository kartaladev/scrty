# Release Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every file-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself. Tasks marked **(maintainer)** are never done by an agent.

**Goal:** Make every published scrty module obtainable at a released version from outside the repository, gated before tagging and proven after, with a changelog, a security policy and a documented procedure.

**Architecture:**
- **Root-module tests.** Two new tests in `layout_test.go`, reusing `layout_guard_test.go`'s `workspaceModules`, `goCmd` and `violation` helpers, pin the requirements (no `v0.0.0` ever, the exact release version on request) and keep one list of published modules in agreement with `go.work`.
- **Makefile targets.** `release-check` runs the gates with the workspace off, plus a `gorelease` report. `release-tags` prints the tag commands.
- **The probe.** A shell script fetches the modules through the public proxy from an empty module. Two workflows wire the gate and the probe into GitHub Actions.

**Tech Stack:**
- Go 1.27, GNU Make, POSIX shell (bash) and GitHub Actions;
- `golang.org/x/exp/cmd/gorelease`, added as a `tool` directive;
- `actionlint` and `shellcheck`, used ad hoc for verification only.

**Spec:** `openspec/changes/release-readiness/`:
- `proposal.md`;
- `design.md` (decisions 1 to 8, plus Risks);
- `specs/module-layout/spec.md` and `specs/release-policy/spec.md`;
- `tasks.md`.

Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **The release.**
  - First release `v0.1.0`, in lockstep.
  - Tags: `v0.1.0`, `fibersec/v0.1.0`, `ginsec/v0.1.0`, `gorm/v0.1.0`, `passkey/webauthn/v0.1.0`, `pgx/v0.1.0`, `redis/v0.1.0`, `sweep/v0.1.0` and `test/v0.1.0`.
  - `tools` is never tagged and never listed.
- **Requirements.** Every nested `go.mod` keeps its `replace` lines. Requirements on scrty modules name the release version, and a `replace` points only inside the repository.
- **Go floor:** `go 1.27` in every workspace module.
- **Never tag or push.** No agent creates or pushes a tag, changes repository settings, or runs `gh` with a write method. `make release-tags` only prints commands.
- **Go checks are test-first** (`.claude/rules/golang-tdd.md`):
  - see the failure for the intended reason, then make it pass;
  - table tests use the `table-test` skill's `assert`-closure form with `t.Context()`;
  - violation checks are pure functions over parsed data, tested on in-memory fixtures, plus one run against the real tree, following `layout_guard_test.go`.
- **Destructive git commands.** Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.
- **No names.** No document names a consumer project or a person.
- **Verification commands**, run from the repository root:
  - `go test -count=1 -run '<Name>' .`;
  - `make check`;
  - `make release-check VERSION=v0.1.0`;
  - `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`;
  - `shellcheck scripts/release-probe.sh`.

## Review Focus

1. **The gate run on a working tree with uncommitted changes.**
   - Expected: `release-check` refuses, because tags would name a commit the gate never saw.
   - Test: in task 3.1, a run with an untracked file fails with "working tree is not clean".
2. **A release version that is not a semantic version.**
   - Expected: `0.1.0`, `v0.1`, `v0.1.0.1` and `latest` are refused. `v0.1.0` and `v0.1.0-rc.1` are accepted.
   - Test: in task 3.1, a loop over those inputs, asserting the exit status of each.
3. **A `replace` that points outside the repository,** such as an absolute path or a path climbing above the root.
   - Expected: the requirement test fails, naming the module, as the module-layout requirement says.
   - Test: in task 2.1, fixture cases for `=> /tmp/x` and `=> ../../outside`.
4. **The probe environment silently bypassing the public checksum database,** through `GOFLAGS=-mod=mod`, `GONOSUMDB`, `GONOSUMCHECK`, `GOPRIVATE`, `GOINSECURE` or `GONOPROXY` set on the runner.
   - Expected: the probe unsets them, so the proxy and `sum.golang.org` both vouch for the version.
   - Test: in task 4.1, run the probe with `GONOSUMDB=github.com/kartaladev/*` exported, and assert the script prints the effective `go env` with those unset.
5. **An indirect requirement on a scrty module,** for example `test` requiring `redis // indirect`.
   - Expected: it is held to the same version rule as a direct one.
   - Test: in task 2.1, a fixture case with an indirect `v0.0.0` requirement that must be reported.

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | R1 | 1.1 | `tools/go.mod`, `tools/go.sum` | Sonnet: add one tool directive and record a tool's output |
| 1 (parallel) | R2 | 2.1–2.5 | `layout_test.go`, `layout_guard_test.go`, `release-modules.txt`, every nested `go.mod` and `go.sum` | Sonnet: checks against a stated contract, plus mechanical bumps |
| 2 (after R1, R2; the main session records 1.1's outcome in `design.md` first) | R3 | 3.1–3.3, 5.1 | `Makefile`, `.github/workflows/release-check.yml` | Sonnet: Makefile plumbing to a stated order |
| 2 (parallel with R3) | R4 | 4.1–4.2 | `scripts/release-probe.sh`, `.github/workflows/release-probe.yml` | Sonnet: a script to a stated contract |
| 2 (parallel with R3) | R5 | 5.2–5.5 | `CHANGELOG.md`, `SECURITY.md`, `RELEASING.md`, `README.md` | Sonnet: documents from the decisions |
| 3 | main | 6.1–6.2 | — | Sonnet reviewer for 6.1 |
| 4 | maintainer | 7.1–7.2 | — | — |

R3 and R4 both read `release-modules.txt`, which R2 owns and finishes first. R5 needs R3's target names, which are fixed here (`release-check` and `release-tags`), so it runs in parallel. Each dispatch gets a fresh Sonnet reviewer that edits nothing.

---

### Task 1.1: `gorelease` against a module with `replace`

**Files:**
- Modify: `tools/go.mod` and `tools/go.sum`

- [ ] **Step 1: add the tool.**

```sh
cd tools && GOWORK=off go get -tool golang.org/x/exp/cmd/gorelease@latest && GOWORK=off go mod tidy
```

  Then run `make tools && ls .bin/gorelease`. Expected: the binary exists.
- [ ] **Step 2: run it in place.**

```sh
cd pgx && GOWORK=off ../.bin/gorelease -base=none -version=v0.1.0; echo "exit=$?"
```

  Record the full output and the exit status.
- [ ] **Step 3: report** one of the two outcomes, with the output quoted:
  - (a) "runs in place": it printed an API report and the exit status was 0;
  - (b) "refuses replace": it printed an error naming the `replace` directive.
  - Do not edit `design.md`; the main session does.
- [ ] **Step 4: commit** `chore(tools): add gorelease for the release gate`.

---

### Task 2.1–2.5: Nested modules require released versions

**Files:**
- Modify: `layout_guard_test.go`, which gains `scrtyRequirement`, `readScrtyRequirements`, `readReplaces`, `releaseRequirementViolations` and `releaseListViolations`
- Modify: `layout_test.go`, which gains `TestNestedModulesRequireReleasedVersions`, `TestReleaseModuleListsAgree` and `TestModulesDeclareGoFloor`
- Create: `release-modules.txt`
- Modify: `fibersec/go.mod`, `ginsec/go.mod`, `gorm/go.mod`, `passkey/webauthn/go.mod`, `pgx/go.mod`, `redis/go.mod`, `sweep/go.mod`, `test/go.mod`, and their `go.sum` files

**Interfaces:**
- Produces:
  - `release-modules.txt`, which R3 and R4 consume. One line per nested module: `<dir> <import path of one package in it>`.

```
fibersec github.com/kartaladev/scrty/fibersec
ginsec github.com/kartaladev/scrty/ginsec
gorm github.com/kartaladev/scrty/gorm
passkey/webauthn github.com/kartaladev/scrty/passkey/webauthn
pgx github.com/kartaladev/scrty/pgx
redis github.com/kartaladev/scrty/redis
sweep github.com/kartaladev/scrty/sweep
test github.com/kartaladev/scrty/test/storetest
```

  - Confirm each import path names a package that exists, with `go list <path>` in the workspace. Adjust it to a real package in that module if the module root has none, and record the change in the report.
  - The `SCRTY_RELEASE_VERSION` environment variable, read by the requirement test.

- [ ] **Step 1 (2.1 red): the pure check and its table.**

```go
type scrtyRequirement struct {
	Module   string // the requiring module's directory, e.g. "pgx"
	Path     string // e.g. "github.com/kartaladev/scrty"
	Version  string
	Indirect bool
}

// releaseRequirementViolations reports requirements that could never resolve
// outside the repository (v0.0.0 or a zero pseudo-version), requirements that
// do not name want when want is set, and replaces that leave the repository.
func releaseRequirementViolations(reqs []scrtyRequirement, replaces map[string][]string, want string) []violation
```

  Table cases, each with an `assert` closure using `hasViolation`:
  - `v0.0.0` direct: reported;
  - `v0.0.0-00010101000000-000000000000`: reported;
  - an indirect `v0.0.0` (Review Focus 5): reported;
  - `v0.1.0` with want empty: clean;
  - `v0.1.0` with want `v0.2.0`: reported, naming module and path;
  - replace `=> ../`: clean;
  - replace `=> /tmp/x` (Review Focus 3): reported;
  - replace `=> ../../outside`, resolved against the module's directory, escaping the repository root: reported.

  The real-tree test reads every directory from `workspaceModules(t)` except `.`, parses `go mod edit -json` output through `goCmd`, and asserts no violations with `os.Getenv("SCRTY_RELEASE_VERSION")` as want. Run `go test -count=1 -run 'TestNestedModulesRequireReleasedVersions' .`. Expected: the table passes and the real-tree subtest FAILs, naming all eight modules.
- [ ] **Step 2 (2.2 red):** run with `SCRTY_RELEASE_VERSION=v0.1.0`. Expected: FAIL, naming the same modules.
- [ ] **Step 3 (2.3): bump.** For each nested module, `(cd <dir> && go mod edit -require=github.com/kartaladev/scrty@v0.1.0)`. In `test/`, also bump each sibling: `-require=github.com/kartaladev/scrty/<dir>@v0.1.0` for `fibersec`, `ginsec`, `gorm`, `passkey/webauthn`, `pgx` and `redis`. Then run `go mod tidy` in each with `GOWORK=off`. Expected: tidy succeeds through the local `replace`. Run, expecting PASS, PASS, FAIL and PASS respectively:
  - step 1's command;
  - the same with `SCRTY_RELEASE_VERSION=v0.1.0`;
  - the same with `SCRTY_RELEASE_VERSION=v0.2.0`;
  - `make check`.
- [ ] **Step 4 (2.4 red):** `releaseListViolations(listed []string, workspace []string) []violation`. Its table:
  - equal sets: clean;
  - a module missing from the list: reported;
  - an extra entry: reported;
  - `tools` listed: reported;
  - `.` listed: reported.
  The real-tree test reads `release-modules.txt`, and fails if the file is missing. It also checks, with `go list` in the workspace, that each import path builds. Run it and expect FAIL with the file missing. Add the file with one entry wrong, run it and expect FAIL. Correct the entry, run it and expect PASS.
- [ ] **Step 5 (2.5):** `TestModulesDeclareGoFloor` reads the `go` directive of every workspace module, and passes only for `1.27` or `1.27.<n>`. Run it and expect PASS. Then change `sweep/go.mod` to `go 1.26`, run it and expect a FAIL naming `sweep`. Edit it back and run it again, expecting PASS.
- [ ] **Step 6: commit** `build: nested modules require v0.1.0 and the release list`.

---

### Task 3.1–3.3, 5.1: Release gate, tag helper and the gate workflow

**Files:**
- Modify: `Makefile`
- Create: `.github/workflows/release-check.yml`

**Interfaces:**
- Consumes: `release-modules.txt`, `SCRTY_RELEASE_VERSION`, `.bin/gorelease`, and 1.1's recorded outcome.
- Produces: `make release-check VERSION=` and `make release-tags VERSION=`.

- [ ] **Step 1 (3.1): `release-check`.**

```make
RELEASE_DIRS := . $(shell cut -d' ' -f1 release-modules.txt)
SEMVER := ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$$

.PHONY: release-check release-tags

release-check: tools
	@set -eu -o pipefail; \
	[ -n "$(VERSION)" ] || { echo "usage: make release-check VERSION=vX.Y.Z"; exit 2; }; \
	echo "$(VERSION)" | grep -Eq '$(SEMVER)' || { echo "not a semantic version: $(VERSION)"; exit 2; }; \
	[ -z "$$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 2; }; \
	SCRTY_RELEASE_VERSION="$(VERSION)" go test -count=1 -run 'TestNestedModulesRequireReleasedVersions|TestReleaseModuleListsAgree|TestModulesDeclareGoFloor' .; \
	out="$$(GOWORK=off gofmt -l $(RELEASE_DIRS))"; [ -z "$$out" ] || { echo "gofmt needed:"; echo "$$out"; exit 1; }; \
	for m in $(RELEASE_DIRS); do (cd "$$m" && echo "== $$m (GOWORK=off)" && GOWORK=off go vet ./... && GOWORK=off golangci-lint run ./... && GOWORK=off go test -race -count=1 ./... && GOWORK=off govulncheck ./...); done
```

  Verify each of these:
  - `make release-check` exits 2 with the usage message;
  - for each of `0.1.0`, `v0.1`, `v0.1.0.1` and `latest`, it exits 2 (Review Focus 2);
  - `v0.1.0-rc.1` passes the format check, then fails at the requirement test, which is expected;
  - `touch x.tmp && make release-check VERSION=v0.1.0` exits 2 with "working tree is not clean", then `rm x.tmp` (Review Focus 1);
  - `VERSION=v0.2.0` fails in the requirement test, naming the modules;
  - `VERSION=v0.1.0` passes, printing `== <dir> (GOWORK=off)` for all nine.
- [ ] **Step 2 (3.2): the API report.** Append it to the recipe, in 1.1's form:

```make
	prev="$$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1)"; base="$${prev:-none}"; \
	for m in $(RELEASE_DIRS); do (cd "$$m" && echo "== gorelease $$m" && GOWORK=off $(BIN)/gorelease -base="$$base" -version="$(VERSION)"); done
```

  With outcome (b), each iteration instead copies the module to `$$(mktemp -d)`, drops the scrty `replace` lines with `go mod edit -dropreplace=github.com/kartaladev/scrty` (and each sibling path), and runs `gorelease` there. Verify:
  - for `v0.1.0`, there are nine `== gorelease` sections;
  - a temporary `release-modules.txt` edit adding `nosuch github.com/x/y` makes the target fail. Revert it by editing the file back.
- [ ] **Step 3 (5.1): `release-tags`.**

```make
release-tags:
	@set -eu -o pipefail; \
	[ -n "$(VERSION)" ] || { echo "usage: make release-tags VERSION=vX.Y.Z"; exit 2; }; \
	echo "$(VERSION)" | grep -Eq '$(SEMVER)' || { echo "not a semantic version: $(VERSION)"; exit 2; }; \
	head="$$(git rev-parse HEAD)"; \
	echo "git tag -a $(VERSION) -m 'scrty $(VERSION)' $$head"; \
	for d in $$(cut -d' ' -f1 release-modules.txt); do echo "git tag -a $$d/$(VERSION) -m 'scrty $$d $(VERSION)' $$head"; done
```

  Verify: `make release-tags VERSION=v0.1.0 | wc -l` prints 9, the tags match Global Constraints, and `git tag --list` is unchanged.
- [ ] **Step 4 (3.3): the workflow** `.github/workflows/release-check.yml`.
  - Trigger: `on: workflow_dispatch: inputs: version: {required: true, type: string}`.
  - Use the same `permissions`, matrix, `env` and setup steps as `ci.yml`, then `run: make release-check VERSION="${{ inputs.version }}"`.
  - Verify: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/release-check.yml .github/workflows/ci.yml` prints nothing.
- [ ] **Step 5: commit** `build: release gate and tag helper`.

---

### Task 4.1–4.2: The outside probe

**Files:**
- Create: `scripts/release-probe.sh` (executable) and `.github/workflows/release-probe.yml`

- [ ] **Step 1 (4.1): the script.**

```bash
#!/usr/bin/env bash
# Proves a released version resolves from outside the repository, through the
# public proxy and checksum database, the way a consumer's build sees it.
set -euo pipefail
version="${1:?usage: release-probe.sh vX.Y.Z}"
retries="${PROBE_RETRIES:-10}"
root="$(cd "$(dirname "$0")/.." && pwd)"
unset GOFLAGS GONOSUMDB GONOSUMCHECK GOPRIVATE GOINSECURE GONOPROXY
export GOWORK=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
go env GOPROXY GOSUMDB GONOSUMDB GOPRIVATE GOFLAGS

dir="$(mktemp -d)"; trap 'rm -rf "$dir"' EXIT
cd "$dir" && go mod init probe.example >/dev/null

fetch() {
	local mod="$1" n=1
	until go get "$mod@$version"; do
		[ "$n" -ge "$retries" ] && { echo "probe: $mod@$version did not resolve"; return 1; }
		n=$((n + 1)); sleep 30
	done
}

imports=("github.com/kartaladev/scrty/session")
fetch github.com/kartaladev/scrty
while read -r d pkg; do
	fetch "github.com/kartaladev/scrty/$d"
	imports+=("$pkg")
done < "$root/release-modules.txt"

{ echo 'package main'; echo 'import ('; for p in "${imports[@]}"; do echo "	_ \"$p\""; done; echo ')'; echo 'func main() {}'; } > main.go
go build ./...
echo "probe: $version resolves for every published module"
```

  Verify:
  - `shellcheck scripts/release-probe.sh` prints nothing;
  - `PROBE_RETRIES=1 scripts/release-probe.sh v0.0.1` exits nonzero with `probe: github.com/kartaladev/scrty@v0.0.1 did not resolve`;
  - `GONOSUMDB='github.com/kartaladev/*' PROBE_RETRIES=1 scripts/release-probe.sh v0.0.1` prints an empty `GONOSUMDB` in its `go env` lines (Review Focus 4).
- [ ] **Step 2 (4.2): the workflow** `.github/workflows/release-probe.yml`.
  - Trigger: `on: push: tags: ['v[0-9]*']`. Nested tags such as `pgx/v0.1.0` begin with their directory, so they do not match.
  - `permissions: contents: read`, `actions/checkout@v5`, `actions/setup-go@v6` with `1.27.x`, then `run: scripts/release-probe.sh "$GITHUB_REF_NAME"`.
  - Verify with `actionlint`, which should print nothing.
- [ ] **Step 3: commit** `ci: probe a released version from outside the repository`.

---

### Task 5.2–5.5: Documents

**Files:**
- Create: `CHANGELOG.md`, `SECURITY.md`, `RELEASING.md`
- Modify: `README.md`

- [ ] **Step 1 (5.2): `CHANGELOG.md`.**
  - The header states that the format follows Keep a Changelog 1.1.0 and the project follows semantic versioning, and that v0 makes no compatibility promise.
  - `## [Unreleased]` is empty.
  - `## [0.1.0] - YYYY-MM-DD` has an `### Added` list, one item per published module, naming what it provides. Draw on the module's package docs (`go doc ./...` per module), and keep to one line each.
  - Verify: `grep -c` finds each of the nine module names, and only Keep a Changelog headings appear.
- [ ] **Step 2 (5.3): `SECURITY.md`**, with sections Reporting a vulnerability, What to expect, Supported versions and Disclosure.
  - **Reporting:** use the repository's Security tab and "Report a vulnerability"; do not open public issues.
  - **What to expect:** design decision 6's three time frames, as the maintainer confirms them in review.
  - **Supported versions:** a table with `0.1.x` as supported and earlier as none, plus Go 1.27.
  - **Disclosure:** a repository security advisory, a report to the Go vulnerability database, and a `Security` entry in the changelog.
  - No other contact is named. Verify the text against both security-policy requirements, item by item.
- [ ] **Step 3 (5.4): `RELEASING.md`.** Write the nine steps of design decision 7, each with its exact command:
  - the `go mod edit -require` lines for all eight modules and `test`'s siblings;
  - `make release-check VERSION=vX.Y.Z`;
  - `gh api repos/kartaladev/scrty/private-vulnerability-reporting`, which must show `"enabled": true`;
  - `make release-tags VERSION=vX.Y.Z`, then running the printed commands;
  - `git push origin <each tag>`;
  - the release-probe run;
  - `gh release create vX.Y.Z --notes-file <entry>`.
  - Add a "Never move a tag" section with the recovery: a new patch version, and `retract vX.Y.Z` in each affected `go.mod`.
  - Verify that each read-only command runs (`make release-check`, `make release-tags`, the `gh api` read). Don't run the tag, push or release commands.
- [ ] **Step 4 (5.5): `README.md`.**
  - An Install section with `go get github.com/kartaladev/scrty@v0.1.0` and `go get github.com/kartaladev/scrty/pgx@v0.1.0`.
  - Links to `CHANGELOG.md` and `SECURITY.md`.
  - Keep the existing Supported Go versions section, and add that security fixes go to the latest minor release, per `SECURITY.md`.
  - Verify the relative links name existing files.
- [ ] **Step 5: commit** `docs: changelog, security policy and release procedure`.

---

### Task 6.1–6.2: Integration gate (main session)

- [ ] **6.1:** dispatch a fresh Sonnet reviewer that edits nothing. It gets both spec deltas, the design, and `git diff main...HEAD`. Findings are labelled `REPRODUCED` (with a failing check) or `UNREPRODUCED`, and go back to the owning dispatch.
- [ ] **6.2:** run `make check`, `make release-check VERSION=v0.1.0` (on a clean tree) and `openspec validate release-readiness --strict`, and keep the outputs.

### Task 7.1–7.2: First release (maintainer)

- [ ] **7.1 (maintainer):** `gh api -X PUT repos/kartaladev/scrty/private-vulnerability-reporting`, then read it back and expect `"enabled": true`.
- [ ] **7.2 (maintainer):** after merge, follow `RELEASING.md` for `v0.1.0`, and watch `release-probe` pass.
