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

.PHONY: tools check fmt-check vet lint test vuln generate-check

# GOWORK=off because tools/ is deliberately outside go.work: in workspace mode the
# tool pattern resolves against the workspace modules, which declare no tools.
tools:
	cd tools && GOWORK=off GOBIN=$(BIN) go install tool

check: tools fmt-check vet lint test vuln generate-check

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

vuln:
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && govulncheck ./...); done

# Scoped to what go generate can touch: an unrelated edit elsewhere in the tree
# must not make this gate cry wolf. Go source is the whole of that scope today,
# because mockgen is the only generating tool and it emits nothing but .go, while
# every tracked yaml, json and sql file is hand-authored. Diffing those reported an
# uncommitted config edit as stale generated output, which is the false alarm this
# comment rules out. Widen the pathspec deliberately if a generator ever emits
# another format.
generate-check:
	@set -eu -o pipefail; for m in $(MODULES); do (cd "$$m" && go generate ./...); done
	@git diff --exit-code -- '*.go'
