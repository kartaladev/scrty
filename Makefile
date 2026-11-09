SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# .SHELLFLAGS needs GNU Make 3.82 or newer. macOS ships 3.81, which ignores it
# silently and runs recipes under a bare `-c`: no -e, no pipefail. A `for` loop
# then reports only its LAST iteration's status, so a failure in any module but
# the last was reported as success — a gate that printed findings and passed.
# Every looping recipe below therefore sets the flags itself, which works on
# either version. Verify with: make --version.

# The release version, exactly as typed. These three lines come before every $(shell)
# in this file, and must stay there. Make expands a variable wherever it is referenced,
# and when it exports one: `VERSION='v1.0.0$(shell touch x)'` on the command line ran the
# $(shell) as soon as a recipe used $(VERSION), or exported VERSION to it (reproduced
# 2026-11-09). GNU make 4.4 and later also pass exported variables to $(shell), so a
# `MODULES := $(shell ...)` read while VERSION was still exported ran it too, before any
# recipe (reproduced on 4.4.1, 2026-11-09; 3.81 does not do this).
#
# $(value VERSION) is the raw text, unexpanded, and this simply expanded copy is exported
# as it stands, never expanded again. VERSION itself is never exported. `override` keeps
# a RELEASE_VERSION given on the command line from replacing the copy: that one would be
# a recursive variable, and exporting it would expand it.
#
# Sub-makes see VERSION only when it was given on the command line: make passes it in
# MAKEFLAGS, writing `$` as `$$`, so the text arrives intact and is again read only
# through $(value VERSION). A VERSION from the environment reaches no sub-make: it is
# unexported, so the sub-make has no VERSION, and its own `override` line below sets
# RELEASE_VERSION to empty, replacing the value exported to it (reproduced 2026-11-09:
# `VERSION=v1.2.3 make` gave a sub-make RELEASE_VERSION=[]). A sub-make that needs the
# version must be given VERSION on its command line; none in this file does.
#
# Only the plain `VERSION=...` form is raw text. `VERSION:=...`, `VERSION::=...` and
# `VERSION!=...` typed on the command line, and any assignment in a MAKEFLAGS taken from
# the environment, ask make to evaluate the value (`!=` runs it as shell), which make
# does by definition; nothing in this file can prevent it.
override RELEASE_VERSION := $(value VERSION)
unexport VERSION
export RELEASE_VERSION

BIN := $(CURDIR)/.bin
export PATH := $(BIN):$(PATH)

# Every module listed in go.work. The tools module is deliberately outside the
# workspace, so the per-module loops below skip it; tools-check gates it instead.
MODULES := $(shell go list -m -f '{{.Dir}}')

.PHONY: tools tools-check check fmt-check vet lint test test-isolated vuln generate-check pincheck sbom release-gate release-check release-tags spec-check conformance

# GOWORK=off because tools/ is deliberately outside go.work: in workspace mode the
# tool pattern resolves against the workspace modules, which declare no tools.
#
# One file target per tool, so a gate installs only the tool it calls, and `make -j`
# installs each binary once: `tools` and a gate that needs the same binary share
# the one target. A change to the tools module's requirements rebuilds them all.
TOOLS_DEPS := tools/go.mod tools/go.sum

$(BIN)/golangci-lint: $(TOOLS_DEPS)
	cd tools && GOWORK=off GOBIN=$(BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint

$(BIN)/govulncheck: $(TOOLS_DEPS)
	cd tools && GOWORK=off GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck

$(BIN)/mockgen: $(TOOLS_DEPS)
	cd tools && GOWORK=off GOBIN=$(BIN) go install go.uber.org/mock/mockgen

$(BIN)/benchstat: $(TOOLS_DEPS)
	cd tools && GOWORK=off GOBIN=$(BIN) go install golang.org/x/perf/cmd/benchstat

$(BIN)/cyclonedx-gomod: $(TOOLS_DEPS)
	cd tools && GOWORK=off GOBIN=$(BIN) go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod

$(BIN)/gorelease: $(TOOLS_DEPS)
	cd tools && GOWORK=off GOBIN=$(BIN) go install golang.org/x/exp/cmd/gorelease

TOOL_BINS := $(BIN)/golangci-lint $(BIN)/govulncheck $(BIN)/mockgen $(BIN)/benchstat $(BIN)/cyclonedx-gomod $(BIN)/gorelease

tools: $(TOOL_BINS)

# The tools module holds pincheck, a gate in its own right, and sits outside
# go.work, so no loop over MODULES reaches it. This target vets, lints and tests
# it with the workspace off, as `pincheck` and `tools` do. gofmt is checked here
# too, because fmt-check only names the workspace modules.
tools-check: $(BIN)/golangci-lint
	@set -eu -o pipefail; out="$$(gofmt -l tools)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi; \
	cd tools && GOWORK=off go vet ./... && GOWORK=off golangci-lint run ./... && GOWORK=off go test -race -count=1 ./...

# test-isolated runs from the recipe, after every prerequisite has finished, so
# that make -j never runs it beside the rest of the suite.
check: tools pincheck tools-check fmt-check vet lint test vuln generate-check
	@$(MAKE) --no-print-directory test-isolated

# The .go files git knows about: tracked, plus untracked that are not ignored. Walking
# the module directories with `gofmt -l <dir>` also entered git-ignored directories
# such as .claude/worktrees/, so a stale file in another checkout failed the target.
#
# Written to survive its own failure modes. It is one pipeline, used inside "$$(...)"
# by recipes that set pipefail, so a git that fails fails the command substitution and
# stops the target, instead of yielding an empty list that passes (a process
# substitution's status is lost, which is how the earlier form let a failing second
# git call pass). A tracked file deleted from the working tree is skipped rather than
# reported by gofmt as unreadable. An empty list never reaches gofmt, which with no
# argument formats stdin: `xargs -r` runs nothing on empty input (GNU needs the flag;
# BSD xargs accepts it and behaves so anyway). The list is NUL separated and follows
# `--`, so any file name is safe, including one starting with a dash, which gofmt
# would otherwise parse as a flag. The fragment prints the names gofmt wants changed
# and nothing else. Recursive (=) on purpose: `$$` is resolved where it is used.
GOFMT_LIST = git ls-files -z --cached --others --exclude-standard -- '*.go' \
	| while IFS= read -r -d '' f; do if [ -e "$$f" ]; then printf '%s\0' "$$f"; fi; done \
	| xargs -0 -r gofmt -l --

# gofmt -l exits 0 whether or not it names files, so the output is what fails.
fmt-check:
	@set -eu -o pipefail; out="$$($(GOFMT_LIST))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && go vet ./...); done

lint: $(BIN)/golangci-lint
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && golangci-lint run ./...); done

test:
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && go test -race -count=1 ./...); done

# TestPGLimiter_PruneUnderRecords measures lock waits caused by the prune and asserts
# no gap between its samples reaches the operation timeout. Inside `go test ./...`
# the packages run concurrently and starve the host, which that guard takes for a
# wait on the prune, so the test skips there and runs alone here.
test-isolated:
	@set -eu -o pipefail; cd test && SCRTY_TEST_ISOLATED=1 go test -race -count=1 -p 1 -run '^TestPGLimiter_PruneUnderRecords$$' -v .

# govulncheck exits non-zero on a reachable vulnerability, and the subshell's
# status stops the loop under the explicit flags above, so a finding in any
# module fails the target. GOWORK=off scans each module against its own go.mod
# requirements, which is what a consumer of that published module gets: in
# workspace mode every module is scanned against the versions the whole
# workspace selects, so a module pinned to a vulnerable release passes whenever a
# sibling lifts it. The same reason `sbom` runs with the workspace off.
vuln: $(BIN)/govulncheck
	@set -eu -o pipefail; for m in $(MODULES); do echo "vuln: $$m"; (cd "$$m" && GOWORK=off govulncheck ./...); done

# Every action and reusable workflow must be pinned to a full commit SHA. The
# checker is in the tools module, so it runs there with the workspace off.
pincheck:
	@cd tools && GOWORK=off go run ./cmd/pincheck $(CURDIR)/.github

# cyclonedx-gomod takes a module's version from a git tag on HEAD (directory-prefixed
# for a nested module), else a pseudo-version, and has no flag to state one. Run on its
# own, `make sbom` therefore names the commit's pseudo-version, which is what it is.
# release-check runs it in a throwaway export tagged with the release tags, so the
# SBOMs it keeps name the release version without the tool's output being edited.
#
# SBOM_DIR receives one CycloneDX JSON file per module in MODULES, named after
# the module path. MODULES is the workspace module list, which is the published
# set: tools is outside go.work and is never published. The generator is a tool
# directive in the tools module. A module whose SBOM cannot be generated fails
# the target, and no stale file survives: the directory is emptied first.
SBOM_DIR ?= $(BIN)/sbom

# SBOM_DIR is emptied with `rm -rf`, and `?=` lets the environment set it: an exported
# SBOM_DIR=. deleted the whole checkout, .git included (reproduced 2026-11-09). So `sbom`
# and `release-check` refuse, before removing anything, an SBOM_DIR that is not strictly
# inside SBOM_ROOT, which is $(BIN). SBOM_ROOT is a simple assignment, so the
# environment cannot move it, but `make -e` / MAKEFLAGS=e and a command-line value can; both
# are trusted, since whoever sets them controls make. release-check gives its own sub-make
# the run's temporary directory as a command-line value. An `override` assignment would
# also stop `make -e`, but it beats a command-line value too, which would break that handoff.
#
# Both paths are resolved physically, without `realpath` (macOS has no `realpath -m`):
# made absolute against the working directory, then `cd -P` and `pwd -P`, with CDPATH
# unset. An SBOM_DIR that exists as a directory is resolved whole, so a symlink leading
# out, `..`, `.`, $(BIN) itself, or a path outside all resolve to where they really point
# and are refused. One that does not exist yet is resolved through its parent, which must
# exist; its last component may not be `.` or `..`. The fragment leaves the resolved path
# in `sbomdir`, and only that path is ever removed, never the text as given. A value
# holding make or shell syntax is expanded as any make variable is; whoever sets it
# already controls make. Accepted: a directory swapped for a symlink between the check
# and the `rm` is followed; only the same user can do that inside $(BIN).
SBOM_ROOT := $(BIN)

SBOM_DIR_CHECK = \
	unset CDPATH; \
	sbomgiven="$(SBOM_DIR)"; sbomroot="$(SBOM_ROOT)"; \
	sbomrefuse() { printf '%s: SBOM_DIR must be a directory strictly inside %s, not %q (%s)\n' "$@" "$$sbomroot" "$$sbomgiven" "$$1"; exit 2; }; \
	[ -n "$$sbomgiven" ] || sbomrefuse "empty"; \
	[ -n "$$sbomroot" ] || sbomrefuse "SBOM_ROOT is empty"; \
	case "$$sbomroot" in /*) ;; *) sbomroot="$$PWD/$$sbomroot";; esac; \
	sbomroot="$$(cd -P -- "$$sbomroot" && pwd -P)" || sbomrefuse "SBOM_ROOT does not resolve"; \
	[ "$$sbomroot" != / ] || sbomrefuse "SBOM_ROOT is /"; \
	sbompath="$$sbomgiven"; case "$$sbompath" in /*) ;; *) sbompath="$$PWD/$$sbompath";; esac; \
	if [ -d "$$sbompath" ]; then \
		sbomdir="$$(cd -P -- "$$sbompath" && pwd -P)" || sbomrefuse "does not resolve"; \
	else \
		sbombase="$$(basename -- "$$sbompath")"; \
		case "$$sbombase" in ""|.|..|/) sbomrefuse "no usable last component";; esac; \
		sbomparent="$$(cd -P -- "$$(dirname -- "$$sbompath")" && pwd -P)" || sbomrefuse "its parent does not exist"; \
		sbomdir="$$sbomparent/$$sbombase"; \
	fi; \
	[[ $$sbomdir == "$$sbomroot"/* ]] || sbomrefuse "resolves to $$sbomdir";

sbom: tools
	@set -eu -o pipefail; \
	$(SBOM_DIR_CHECK) \
	rm -rf -- "$$sbomdir"; mkdir -p -- "$$sbomdir"; \
	for m in $(MODULES); do \
		echo "sbom: $$m"; \
		path="$$(cd "$$m" && GOWORK=off go list -m)"; \
		out="$$sbomdir/$$(echo "$$path" | tr '/' '_').cdx.json"; \
		(cd "$$m" && GOWORK=off cyclonedx-gomod mod -json -licenses -output "$$out" .); \
		test -s "$$out"; \
		echo "sbom: $$out"; \
	done

# The release gate: a reachable vulnerability or a module whose SBOM cannot be
# produced stops the release. vuln is a prerequisite, so it blocks the gate.
release-gate: tools vuln sbom

# The published modules: the root, then each directory in release-modules.txt (one
# `<dir> <import path>` per line). The list is read when make starts.
RELEASE_DIRS := . $(shell cut -d' ' -f1 release-modules.txt)

# A semantic version with the `v` prefix and no build metadata. A prerelease
# identifier is a number without a leading zero, or alphanumerics and hyphens with at
# least one non-digit, as semver 2.0.0 defines it: `v1.0.0-01` and `v1.0.0-..` are
# refused. Matched by bash `[[ =~ ]]` against the whole string, so a value with a
# newline, or any trailing text, fails; `grep -E`, used before, matched line by line.
SEMVER_ID := (0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)
SEMVER_RE := ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$(SEMVER_ID)(\.$(SEMVER_ID))*)?$$

# Refuses a missing or malformed RELEASE_VERSION, and leaves the pattern in `re`. The
# value is printed with %q, so a refused value stays on one line and cannot pass for a
# CI workflow command or forge a line of the log.
RELEASE_VERSION_CHECK = \
	[ -n "$${RELEASE_VERSION:-}" ] || { echo "usage: make $@ VERSION=vX.Y.Z"; exit 2; }; \
	re='$(SEMVER_RE)'; \
	[[ $$RELEASE_VERSION =~ $$re ]] || { printf 'not a semantic version: %q\n' "$$RELEASE_VERSION"; exit 2; };

# The environment of every go command that reads the local proxy, set on that command
# only and never exported. The workspace is off; the module cache is the run's own, so
# the locally built release never reaches the developer's cache, where it would later
# fail the checksum of the published copy; the checksum database is skipped for scrty
# modules only, which are the ones the local proxy serves. GOENV=off ignores the user's
# go env file, and the explicit empty GONOPROXY and GOPRIVATE keep scrty modules on the
# proxy rather than direct VCS. Callers add GOPROXY and GOFLAGS.
RELEASE_GOENV = GOWORK=off GOENV=off GOTOOLCHAIN=local GONOSUMDB=github.com/kartaladev/scrty \
	GONOPROXY= GOPRIVATE= GOMODCACHE="$$work/modcache"

# The gate a release must pass before any tag is created, on the commit to be tagged.
# The version reaches the shell only as RELEASE_VERSION in the environment, never
# spliced into the script, so a crafted value cannot run as shell or as make.
#
# In order, stopping at the first failure: SBOM_DIR is checked (see SBOM_ROOT above) and
# emptied; the refusals (version, module list, jq, a shallow clone, no previous v tag for
# a version after the first release, a relative or unusual TMPDIR, a dirty tree,
# untracked files included whatever status.showUntrackedFiles says); the tools, built
# from the recipe rather than as a prerequisite so that nothing is built before the
# refusals; the requirement test; make check's gates (pincheck, tools-check, the
# format check, vet, lint and test with the workspace off per module, generate-check,
# test-isolated); the supply-chain gate in a tagged export; the API report.
#
# Every module is built as its own main module: GOWORK=off is set on each go and
# golangci-lint command and never exported. release-gate lists its modules with
# `go list -m`, which names only the root once the workspace is off, so an exported
# GOWORK=off would make vuln and sbom cover one module and pass; the SBOM count
# below fails that case.
#
# What a run proves, and what it leaves behind:
#   - HEAD is read once, before any step, and that commit is the one exported, so the
#     SBOMs and the API report describe the commit the tests ran on. The run fails if
#     HEAD moved or the tree became dirty by the end, and on success prints the commit
#     it gated: tag exactly that one.
#   - A shallow clone is refused: it holds no tags, so the API report would silently
#     compare against nothing (-base=none). With the full history, "no v tag" can only
#     mean the first release.
#   - A relative TMPDIR is refused: the temporary module cache and the proxy path must be
#     absolute. So is one with characters outside letters, digits and ._+@/-, because the
#     run's directory is handed to the release-gate sub-make as make text, where a `$`
#     would be expanded. An unset or empty TMPDIR means /tmp.
#   - SBOM_DIR is emptied when the gate starts, right after it is checked and before
#     every refusal, so a refused run leaves it empty too: one that kept an earlier run's
#     SBOMs let them pass for this run's (reproduced 2026-11-09). The SBOMs are written
#     inside the run's temporary directory and moved into SBOM_DIR only after every step
#     has passed, so nine SBOMs naming the version there can only come from a passing
#     run. `make sbom` on its own still writes straight into SBOM_DIR.
#   - A version other than v0.1.0 or one of its prereleases is refused when no earlier v
#     tag is found: a full clone fetched without tags would otherwise report against
#     nothing.
#   - `make -n release-check` is not a preview: the recipe calls $(MAKE), and make runs
#     such a line even under -n, so it runs the gate. Accepted; GNU make defines it so.
#
# The supply-chain gate and the API report run in a throwaway export of HEAD, in one
# `mktemp -d` directory that a trap removes on every exit, interruption included. It
# never touches this repository's tags or module cache:
#   - the export is committed in a fresh repository and tagged there with the release
#     tags, so cyclonedx-gomod names the release version; `release-gate` runs there,
#     without GOWORK in its environment, writing into the run's temporary directory.
#     The tags are deleted before the API report;
#   - releaseproxy writes every published module at the version as a GOPROXY tree,
#     and each module is fetched from it alone, so a module missing from it fails here,
#     named, rather than only where another module happens to require it;
#   - each exported module's scrty `replace` lines are dropped, the go.sum lines for
#     the modules they replaced are added from the local proxy, and the result is
#     committed, because gorelease refuses a dirty tree and reports missing sums as an
#     error; then gorelease runs per module against the latest `v` root tag, or none.
# GIT_DIR and the other repository-selecting variables are cleared before any git
# command on the export, so a run from a git hook cannot write into this repository.
release-check:
	@set -eu -o pipefail; \
	mkdir -p -- "$(SBOM_ROOT)"; \
	$(SBOM_DIR_CHECK) \
	rm -rf -- "$$sbomdir"; mkdir -p -- "$$sbomdir"; \
	$(RELEASE_VERSION_CHECK) \
	[ -s release-modules.txt ] || { echo "release-modules.txt is missing or empty"; exit 2; }; \
	command -v jq >/dev/null || { echo "release-check needs jq"; exit 2; }; \
	shallow="$$(git rev-parse --is-shallow-repository)"; \
	[ "$$shallow" = false ] || { echo "release-check: this is a shallow clone, which lacks the tags the API report compares against; fetch the full history (git fetch --unshallow --tags) and run it again"; exit 2; }; \
	tags="$$(git -c versionsort.suffix=- tag --list 'v[0-9]*' --sort=-v:refname)"; \
	base=none; while IFS= read -r t; do if [[ $$t =~ $$re ]]; then base="$$t"; break; fi; done <<< "$$tags"; \
	if [ "$$base" = none ] && ! [[ $$RELEASE_VERSION =~ ^v0\.1\.0(-[0-9A-Za-z.-]+)?$$ ]]; then \
		echo "release-check: no previous v tag found, but $$RELEASE_VERSION is not the first release (v0.1.0); fetch the tags (git fetch --tags) and run it again" >&2; exit 2; fi; \
	tmp="$${TMPDIR:-/tmp}"; \
	tre='^/[A-Za-z0-9._+@/-]*$$'; \
	[[ $$tmp =~ $$tre ]] || { printf 'release-check: TMPDIR must be an absolute path of letters, digits and ._+@/- only, not %q\n' "$$tmp"; exit 2; }; \
	st="$$(git status --porcelain --untracked-files=all)"; [ -z "$$st" ] || { echo "working tree is not clean"; exit 2; }; \
	head="$$(git rev-parse --verify 'HEAD^{commit}')"; readonly head; \
	echo "release-check: gating commit $$head"; \
	echo "release-check: API report base $$base"; \
	$(MAKE) --no-print-directory tools; \
	SCRTY_RELEASE_VERSION="$$RELEASE_VERSION" go test -count=1 -run 'TestNestedModulesRequireReleasedVersions|TestReleaseModuleListsAgree|TestModulesDeclareGoFloor' .; \
	$(MAKE) --no-print-directory pincheck; \
	$(MAKE) --no-print-directory tools-check; \
	out="$$($(GOFMT_LIST))"; [ -z "$$out" ] || { echo "gofmt needed:"; echo "$$out"; exit 1; }; \
	for m in $(RELEASE_DIRS); do (cd "$$m" && echo "== $$m (GOWORK=off)" && GOWORK=off go vet ./... && GOWORK=off golangci-lint run ./... && GOWORK=off go test -race -count=1 ./...); done; \
	$(MAKE) --no-print-directory generate-check; \
	$(MAKE) --no-print-directory test-isolated; \
	made=""; work=""; \
	cleanup() { \
		rc=$$?; trap - EXIT INT TERM HUP; \
		if [ -n "$$made" ] && [ "$$work" = "$$made" ] && [ -d "$$made" ]; then \
			chmod -R u+w "$$made" || true; \
			rm -rf -- "$$made" || { echo "release-check: could not remove $$made" >&2; [ "$$rc" -ne 0 ] || rc=1; }; \
		fi; \
		exit "$$rc"; \
	}; \
	trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP; \
	made="$$(mktemp -d "$$tmp/scrty-release.XXXXXXXX")"; readonly made; work="$$made"; \
	[ -n "$$work" ] && [ -d "$$work" ] || { echo "release-check: mktemp -d gave no directory"; exit 1; }; \
	mkdir -- "$$work/src"; \
	git archive --format=tar "$$head" | tar -x -f - -C "$$work/src"; \
	unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_CEILING_DIRECTORIES; \
	g() { git -C "$$work/src" -c user.name=release -c user.email=release@localhost -c commit.gpgsign=false -c tag.gpgsign=false -c core.hooksPath=/dev/null -c init.defaultBranch=main "$$@"; }; \
	g init -q; g add -A; g commit -q -m "scrty $$RELEASE_VERSION"; \
	g tag "$$RELEASE_VERSION"; \
	for d in $(filter-out .,$(RELEASE_DIRS)); do g tag "$$d/$$RELEASE_VERSION"; done; \
	env -u GOWORK $(MAKE) --no-print-directory -C "$$work/src" release-gate BIN="$(abspath $(BIN))" SBOM_ROOT="$$work" SBOM_DIR="$$work/sbom"; \
	n="$$(find "$$work/sbom" -maxdepth 1 -type f -name '*.cdx.json' | wc -l | tr -d ' ')"; \
	[ "$$n" -eq $(words $(RELEASE_DIRS)) ] || { echo "release-gate wrote $$n SBOMs, want $(words $(RELEASE_DIRS))"; exit 1; }; \
	for f in "$$work/sbom"/*.cdx.json; do \
		v="$$(jq -er '.metadata.component.version' "$$f")" || { echo "SBOM $$f names no main version"; exit 1; }; \
		[ "$$v" = "$$RELEASE_VERSION" ] || { echo "SBOM $$f names $$v as its main version, want $$RELEASE_VERSION"; exit 1; }; \
		echo "sbom version: $$v $$f"; \
	done; \
	g tag -d "$$RELEASE_VERSION" >/dev/null; \
	for d in $(filter-out .,$(RELEASE_DIRS)); do g tag -d "$$d/$$RELEASE_VERSION" >/dev/null; done; \
	left="$$(g tag --list)"; [ -z "$$left" ] || { echo "release-check: tags left in the export: $$left"; exit 1; }; \
	(cd tools && GOWORK=off go run ./cmd/releaseproxy -src "$$work/src" -version "$$RELEASE_VERSION" -out "$$work/proxy" $(RELEASE_DIRS)); \
	for d in $(RELEASE_DIRS); do \
		p="$$(cd "$$work/src/$$d" && go mod edit -json | jq -er '.Module.Path')"; \
		(cd "$$work" && $(RELEASE_GOENV) GOFLAGS= GOPROXY="file://$$work/proxy" go mod download "$$p@$$RELEASE_VERSION") \
			|| { echo "release-check: the local proxy lacks $$p@$$RELEASE_VERSION ($$d)"; exit 1; }; \
		echo "proxy: $$p@$$RELEASE_VERSION"; \
	done; \
	for d in $(RELEASE_DIRS); do \
		drops="$$(cd "$$work/src/$$d" && go mod edit -json | jq -r '.Replace // [] | .[].Old | select(.Path == "github.com/kartaladev/scrty" or (.Path | startswith("github.com/kartaladev/scrty/"))) | .Path + (if .Version then "@" + .Version else "" end)')"; \
		for r in $$drops; do \
			(cd "$$work/src/$$d" && go mod edit -dropreplace="$$r" \
				&& $(RELEASE_GOENV) GOFLAGS=-mod=mod GOPROXY="file://$$work/proxy,https://proxy.golang.org" go mod download "$${r%@*}"); \
		done; \
	done; \
	g add -A; g commit -q --allow-empty -m "drop scrty replaces"; \
	st="$$(g status --porcelain --untracked-files=all)"; [ -z "$$st" ] || { echo "release-check: the export is not clean:"; echo "$$st"; exit 1; }; \
	for d in $(RELEASE_DIRS); do \
		echo "== gorelease $$d"; \
		(cd "$$work/src/$$d" && $(RELEASE_GOENV) GOFLAGS=-mod=mod GOPROXY="file://$$work/proxy,https://proxy.golang.org" \
			"$(abspath $(BIN))/gorelease" -base="$$base" -version="$$RELEASE_VERSION"); \
	done; \
	now="$$(git rev-parse --verify 'HEAD^{commit}')"; \
	[ "$$now" = "$$head" ] || { echo "release-check: HEAD moved during the run, from $$head to $$now; nothing was gated, run it again"; exit 1; }; \
	st="$$(git status --porcelain --untracked-files=all)"; [ -z "$$st" ] || { echo "release-check: the working tree changed during the run; nothing was gated, run it again"; echo "$$st"; exit 1; }; \
	mv -- "$$work/sbom"/*.cdx.json "$$sbomdir"/ || { rm -rf -- "$$sbomdir"; mkdir -p -- "$$sbomdir"; echo "release-check: could not move the SBOMs into $$sbomdir"; exit 1; }; \
	n="$$(find "$$sbomdir" -maxdepth 1 -type f -name '*.cdx.json' | wc -l | tr -d ' ')"; \
	[ "$$n" -eq $(words $(RELEASE_DIRS)) ] || { rm -rf -- "$$sbomdir"; mkdir -p -- "$$sbomdir"; echo "release-check: $$sbomdir holds $$n SBOMs, want $(words $(RELEASE_DIRS))"; exit 1; }; \
	echo "release-check: passed for $$RELEASE_VERSION at commit $$head; SBOMs in $$sbomdir"

# Prints, for HEAD, the commands that tag a release: one for the root and one per
# module in release-modules.txt, all at one commit. It creates and pushes nothing;
# the maintainer runs the output. tools is never listed.
release-tags:
	@set -eu -o pipefail; \
	$(RELEASE_VERSION_CHECK) \
	[ -s release-modules.txt ] || { echo "release-modules.txt is missing or empty"; exit 2; }; \
	head="$$(git rev-parse HEAD)"; \
	echo "git tag -a $$RELEASE_VERSION -m 'scrty $$RELEASE_VERSION' $$head"; \
	for d in $$(cut -d' ' -f1 release-modules.txt); do echo "git tag -a $$d/$$RELEASE_VERSION -m 'scrty $$d $$RELEASE_VERSION' $$head"; done

# Measures what go generate itself changed, by checksumming every .go file in the
# workspace modules before and after the run. It used to `git diff` instead, which
# cannot tell stale generated output from any uncommitted Go edit: `make check` on
# a working tree with hand-written changes failed here, reporting the author's own
# test code as stale generated output. Comparing before against after is immune to
# whatever was already dirty, and still catches a generator whose committed output
# no longer matches its input. Scoped to .go because mockgen is the only generating
# tool and it emits nothing else; widen it deliberately if that changes.
generate-check: $(BIN)/mockgen
	@set -eu -o pipefail; \
	before="$$(gofiles() { find $(MODULES) -name '*.go' -not -path '*/.*' -print0 | sort -z | xargs -0 shasum; }; gofiles)"; \
	for m in $(MODULES); do (cd "$$m" && go generate ./...); done; \
	after="$$(gofiles() { find $(MODULES) -name '*.go' -not -path '*/.*' -print0 | sort -z | xargs -0 shasum; }; gofiles)"; \
	if [ "$$before" != "$$after" ]; then \
		echo "go generate changed committed output; regenerate and commit:"; \
		diff <(echo "$$before") <(echo "$$after") || true; \
		exit 1; \
	fi

# Validates the OpenSpec artifacts. It is not part of `check`: it needs Node and
# the OpenSpec CLI, which a Go contributor need not have. OPENSPEC replaces the
# CLI invocation, for example OPENSPEC=openspec for a locally installed one.
#
# The settled specs and the archive are always validated. An active change is
# validated only when the working tree differs from SPEC_BASE under
# openspec/changes/<name>/, untracked files included, so a new uncommitted change
# is checked too. A SPEC_BASE that is empty, all zeros (the first push of a
# branch) or absent from the clone (a shallow fetch) falls back to the merge base
# with origin/main. Every touched change is validated even after one fails, so one run
# names them all. A change archived inside the diff has no directory left under
# openspec/changes/, so it is not looked up there; `--archived` covers it.
OPENSPEC ?= npx --yes @fission-ai/openspec@1.16.0
SPEC_BASE ?= $(shell git merge-base HEAD main 2>/dev/null)

spec-check:
	@set -eu -o pipefail; \
	base="$(SPEC_BASE)"; \
	if [ -z "$$base" ] || [ -z "$${base//0/}" ] || ! git cat-file -e "$$base^{commit}" 2>/dev/null; then \
		echo "spec-check: base $${base:-<empty>} unusable, falling back to merge-base with origin/main"; \
		base="$$(git merge-base HEAD origin/main)"; \
	fi; \
	echo "spec-check: base $$base"; \
	$(OPENSPEC) validate --specs --no-interactive; \
	$(OPENSPEC) validate --archived --no-interactive; \
	touched="$$( { git diff --name-only "$$base" -- openspec/changes; git ls-files --others --exclude-standard -- openspec/changes; } \
		| awk -F/ 'NF >= 4 && $$3 != "archive" { print $$3 }' | sort -u)"; \
	failed=0; \
	for dir in openspec/changes/*/; do \
		name="$$(basename "$$dir")"; \
		[ "$$name" != archive ] || continue; \
		if grep -qxF -- "$$name" <<< "$$touched"; then \
			echo "spec-check: change $$name touched, validating"; \
			$(OPENSPEC) validate "$$name" --type change --no-interactive || failed=1; \
		else \
			echo "spec-check: change $$name untouched, skipped"; \
		fi; \
	done; \
	exit $$failed

# The OpenID Foundation's conformance suite against the conformance OP, in Docker Compose.
# Outside `check`: it builds the suite from source and takes minutes, so CI runs it as its own
# job. The suite is pinned by the full commit hash in compose.yaml, which is read from there so
# it is named once; the runner script comes from a checkout of the same commit.
#
# All four plans run in ONE invocation: the expected failure occurs only in the Basic plan,
# and the runner fails any plan run alone for an expected result that "did not happen".
# CONFORMANCE_OUT receives the runner's exports and the containers' logs (default: a fresh
# temporary directory). The stack is torn down, volumes included, whatever the outcome, and the
# target keeps the status of the run.
CONFORMANCE_DIR := $(CURDIR)/test/conformance
CONFORMANCE_COMPOSE := docker compose -f $(CONFORMANCE_DIR)/compose.yaml
CONFORMANCE_SUITE_REF := $(shell sed -n 's|.*conformance-suite\.git\#\([0-9a-f]\{40\}\).*|\1|p' $(CONFORMANCE_DIR)/compose.yaml | head -n 1)
CONFORMANCE_PLANS := \
	"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" \
	"oidcc-config-certification-test-plan" \
	"oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code]" \
	"oidcc-backchannel-rp-initiated-logout-certification-test-plan[client_registration=static_client][response_type=code]"

conformance:
	@set -eu -o pipefail; \
	ref="$(CONFORMANCE_SUITE_REF)"; \
	if [ -z "$$ref" ]; then echo "conformance: no suite commit hash in compose.yaml"; exit 1; fi; \
	out="$${CONFORMANCE_OUT:-$$(mktemp -d)}"; \
	work="$$(mktemp -d)"; \
	mkdir -p "$$out/export"; \
	echo "conformance: logs and exports in $$out"; \
	teardown() { \
		rc=$$?; trap - EXIT; \
		$(CONFORMANCE_COMPOSE) logs --no-color > "$$out/compose.log" 2>&1 || true; \
		$(CONFORMANCE_COMPOSE) down -v || true; \
		rm -rf "$$work"; \
		exit $$rc; \
	}; \
	trap teardown EXIT; \
	git init -q "$$work/suite"; \
	git -C "$$work/suite" fetch -q --depth 1 https://gitlab.com/openid/conformance-suite.git "$$ref"; \
	git -C "$$work/suite" checkout -q FETCH_HEAD; \
	python3 -m venv "$$work/venv"; \
	"$$work/venv/bin/pip" install -q -r "$$work/suite/scripts/requirements.txt"; \
	$(CONFORMANCE_COMPOSE) up -d --build; \
	for i in $$(seq 1 120); do \
		code="$$(curl -ksS -o /dev/null -w '%{http_code}' https://localhost.emobix.co.uk:8443/api/runner/available || true)"; \
		[ "$$code" = 200 ] && break; \
		if [ "$$i" = 120 ]; then echo "conformance: the suite did not come up"; exit 1; fi; \
		sleep 5; \
	done; \
	cd "$(CONFORMANCE_DIR)"; \
	CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443 CONFORMANCE_DEV_MODE=1 \
		"$$work/venv/bin/python" "$$work/suite/scripts/run-test-plan.py" \
		--export-dir "$$out/export" \
		--expected-failures-file expected-failures.json \
		--expected-skips-file expected-skips.json \
		--verbose \
		$(foreach p,$(CONFORMANCE_PLANS),$(p) oidcc.json) 2>&1 | tee "$$out/run-test-plan.log"
