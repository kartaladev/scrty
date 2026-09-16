SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

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
	@for m in $(MODULES); do (cd "$$m" && go vet ./...); done

lint:
	@for m in $(MODULES); do (cd "$$m" && golangci-lint run ./...); done

test:
	@for m in $(MODULES); do (cd "$$m" && go test -race -count=1 ./...); done

vuln:
	@for m in $(MODULES); do (cd "$$m" && govulncheck ./...); done

# Scoped to what go generate can touch: an unrelated edit elsewhere in the tree
# must not make this gate cry wolf.
generate-check:
	@for m in $(MODULES); do (cd "$$m" && go generate ./...); done
	@git diff --exit-code -- '*.go' '*.sql' '*.json' '*.yaml' '*.yml'
