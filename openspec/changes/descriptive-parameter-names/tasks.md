# Tasks

**How tasks are worked:**
- **Test-first.** The layout test in group 1 is the red step for every lane. Each lane runs it before and after, and the count of violations in its packages must reach zero.
- **Renames only.** Renames go through gopls. An agent edits doc comments to follow, and makes no other change.
- **Model per dispatch.** Lanes are Sonnet dispatches with Sonnet reviewers. They are mechanical renames whose rules the design fixes. Each lane owns its packages and touches no other.
- **When to start.** At any time; it does not depend on `release-readiness`. It must be merged to `main` before `harden-chain-boundary` task 1.2 cuts the private-fork branch (task 3.2).

## 1. The guard (design decisions 1 and 2)

- [x] 1.1 Red: add `TestExportedParametersHaveDescriptiveNames` to the root module's `layout_test.go`. It parses every non-test `.go` file of the root module and of each module in `release-modules.txt`, skipping `internal/` and generated files. It reports `file:line Func: parameter "x" (Type)` for each one-letter parameter of:
  - an exported function;
  - an exported method on an exported type;
  - a method of an exported interface;
  - an exported function type.

  The allowed names are `w http.ResponseWriter`, `r *http.Request`, `t`/`b`/`f` for testing types, and `_`. A table test of the checker covers each allowed name, a receiver, an unexported function, an exported interface method and an exported function type. Verify:
  - the checker's table passes;
  - `go test -run TestExportedParametersHaveDescriptiveNames .` fails today, listing about 385 entries;
  - the list matches the 2026-11-09 sweep's packages.

## 2. Renames, in parallel lanes, each verified by the guard

- [x] 2.1 Lane A, `httpsec`, `httpsec/fibersec` and `httpsec/ginsec` (122 parameters): rename by design decision 2's table, with doc comments following. Split into two sequential dispatches if it grows past one session: options files first, then everything else. Verify:
  - the guard lists no `httpsec` entry;
  - `go build ./... && go vet ./httpsec/...` and `go test ./httpsec/... -count=1` pass;
  - `go doc` on five sampled options shows the new names in the text.
- [x] 2.2 Lane B, `oidcprovider`, `authenticate/oidc` (49): the same rules. Verify that the guard lists no entry in them and that their tests pass.
- [x] 2.3 Lane C, `recovery`, `session`, and these `authenticate` packages: `authenticate`, `password`, `passkey`, `mfa`, `magiclink`, `apikey` (about 110). Verify the same way.
- [x] 2.4 Lane D, the remaining packages: `store/*`, `policy/*`, `token/*`, `ratelimit/*`, `expiry/*`, `notify`, `outbound`, `identity`, `pkg/*`, `authorize`, `event`, the `test` module's exported helpers (`test/storetest`, `test/identity`, `test/ratelimittest`, `test/httpsecconformance`) and the nested module `authenticate/passkey/webauthn` (lane C's second dispatch takes it, beside `authenticate/passkey`). The guard counted 572 parameters on 2026-11-09 (`httpsec` 115, `oidcprovider` 56, `test/storetest` 41), so lanes C and D each run as two sequential dispatches split by package. Verify that the guard passes as a whole and that each nested module's tests pass with `GOWORK=off`.
- [x] 2.5 The `Example` functions and `README.md`: their variables of the types in decision 2's table use those names. Verify that `go test -run Example ./...` passes in every module, and that the reviewer finds no one-letter variable of those types left in the README's code blocks.

## 3. Integration gate

- [x] 3.1 Run a whole-branch review with a fresh Sonnet reviewer that edits nothing. It confirms that every hunk is a rename or a doc comment following one. Then run `make check` and `openspec validate descriptive-parameter-names --strict`. Verify that all are clean.

- [ ] 3.2 Open the pull request, let CI pass, and merge it to `main` before `harden-chain-boundary` task 1.2. Verify that `git grep -n TestExportedParametersHaveDescriptiveNames origin/main -- layout_test.go` finds the guard, and that CI's run on the merge commit is green.

## Workflow follow-up

- The renames ship in `v0.1.1`. `harden-chain-boundary` task 9.1 writes their changelog line under `Changed`: "Exported signatures use descriptive parameter names (no API change)."
- Archive the change after merge, before `harden-chain-boundary` starts.
