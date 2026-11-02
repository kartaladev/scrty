SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# .SHELLFLAGS needs GNU Make 3.82 or newer. macOS ships 3.81, which ignores it
# silently and runs recipes under a bare `-c`: no -e, no pipefail. A `for` loop
# then reports only its LAST iteration's status, so a failure in any module but
# the last was reported as success — a gate that printed findings and passed.
# Every looping recipe below therefore sets the flags itself, which works on
# either version. Verify with: make --version.

BIN := $(CURDIR)/.bin
export PATH := $(BIN):$(PATH)

# Every module listed in go.work. The tools module is deliberately outside the
# workspace, so the per-module loops below skip it; tools-check gates it instead.
MODULES := $(shell go list -m -f '{{.Dir}}')

.PHONY: tools tools-check check fmt-check vet lint test test-isolated vuln generate-check pincheck sbom release-gate

# GOWORK=off because tools/ is deliberately outside go.work: in workspace mode the
# tool pattern resolves against the workspace modules, which declare no tools.
tools:
	cd tools && GOWORK=off GOBIN=$(BIN) go install tool

# The tools module holds pincheck, a gate in its own right, and sits outside
# go.work, so no loop over MODULES reaches it. This target vets, lints and tests
# it with the workspace off, as `pincheck` and `tools` do. gofmt is checked here
# too, because fmt-check only names the workspace modules.
tools-check: tools
	@set -eu -o pipefail; out="$$(gofmt -l tools)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi; \
	cd tools && GOWORK=off go vet ./... && GOWORK=off golangci-lint run ./... && GOWORK=off go test -race -count=1 ./...

# test-isolated runs from the recipe, after every prerequisite has finished, so
# that make -j never runs it beside the rest of the suite.
check: tools pincheck tools-check fmt-check vet lint test vuln generate-check
	@$(MAKE) --no-print-directory test-isolated

# gofmt -l exits 0 whether or not it names files, so the output is what fails.
fmt-check:
	@out="$$(gofmt -l $(MODULES))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && go vet ./...); done

lint:
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
vuln:
	@set -eu -o pipefail; for m in $(MODULES); do echo "vuln: $$m"; (cd "$$m" && GOWORK=off govulncheck ./...); done

# Every action and reusable workflow must be pinned to a full commit SHA. The
# checker is in the tools module, so it runs there with the workspace off.
pincheck:
	@cd tools && GOWORK=off go run ./cmd/pincheck $(CURDIR)/.github

# SBOM_DIR receives one CycloneDX JSON file per module in MODULES, named after
# the module path. MODULES is the workspace module list, which is the published
# set: tools is outside go.work and is never published. The generator is a tool
# directive in the tools module. A module whose SBOM cannot be generated fails
# the target, and no stale file survives: the directory is emptied first.
SBOM_DIR ?= $(BIN)/sbom

sbom: tools
	@set -eu -o pipefail; rm -rf "$(SBOM_DIR)"; mkdir -p "$(SBOM_DIR)"; \
	for m in $(MODULES); do \
		echo "sbom: $$m"; \
		path="$$(cd "$$m" && GOWORK=off go list -m)"; \
		out="$(SBOM_DIR)/$$(echo "$$path" | tr '/' '_').cdx.json"; \
		(cd "$$m" && GOWORK=off cyclonedx-gomod mod -json -licenses $(if $(SBOM_VERSION),-main-version $(SBOM_VERSION)) -output "$$out" .); \
		test -s "$$out"; \
		echo "sbom: $$out"; \
	done

# The release gate: a reachable vulnerability or a module whose SBOM cannot be
# produced stops the release. vuln is a prerequisite, so it blocks the gate.
release-gate: tools vuln sbom

# Measures what go generate itself changed, by checksumming every .go file in the
# workspace modules before and after the run. It used to `git diff` instead, which
# cannot tell stale generated output from any uncommitted Go edit: `make check` on
# a working tree with hand-written changes failed here, reporting the author's own
# test code as stale generated output. Comparing before against after is immune to
# whatever was already dirty, and still catches a generator whose committed output
# no longer matches its input. Scoped to .go because mockgen is the only generating
# tool and it emits nothing else; widen it deliberately if that changes.
generate-check:
	@set -eu -o pipefail; \
	before="$$(gofiles() { find $(MODULES) -name '*.go' -not -path '*/.*' -print0 | sort -z | xargs -0 shasum; }; gofiles)"; \
	for m in $(MODULES); do (cd "$$m" && go generate ./...); done; \
	after="$$(gofiles() { find $(MODULES) -name '*.go' -not -path '*/.*' -print0 | sort -z | xargs -0 shasum; }; gofiles)"; \
	if [ "$$before" != "$$after" ]; then \
		echo "go generate changed committed output; regenerate and commit:"; \
		diff <(echo "$$before") <(echo "$$after") || true; \
		exit 1; \
	fi
