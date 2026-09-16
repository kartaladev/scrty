SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

BIN := $(CURDIR)/.bin
export PATH := $(BIN):$(PATH)

.PHONY: tools
# GOWORK=off because tools/ is deliberately outside go.work: in workspace mode the
# tool pattern resolves against the workspace modules, which declare no tools.
tools:
	cd tools && GOWORK=off GOBIN=$(BIN) go install tool
