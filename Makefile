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
# workspace, so it is never linted or tested here.
MODULES := $(shell go list -m -f '{{.Dir}}')

.PHONY: tools check fmt-check vet lint test test-isolated vuln generate-check

# GOWORK=off because tools/ is deliberately outside go.work: in workspace mode the
# tool pattern resolves against the workspace modules, which declare no tools.
tools:
	cd tools && GOWORK=off GOBIN=$(BIN) go install tool

# test-isolated runs from the recipe, after every prerequisite has finished, so
# that make -j never runs it beside the rest of the suite.
check: tools fmt-check vet lint test vuln generate-check
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

vuln:
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && govulncheck ./...); done

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
