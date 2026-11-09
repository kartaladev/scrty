# Descriptive parameter names: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every parameter of an exported signature in a published module reads by its role, and a layout test keeps it that way.

**Architecture:**
- A root-module layout test parses the published modules' Go files with `go/parser` and lists one-letter parameter names outside an allowlist.
- Four Sonnet lanes rename by package with gopls until the list is empty.
- Doc comments follow each rename.

**Tech Stack:** Go 1.27, `go/ast`, `go/parser`, gopls rename, testify.

**Spec:** `openspec/changes/descriptive-parameter-names/design.md`, decisions 1 to 3, and `tasks.md`. The change sets `skip_specs: true`.

## Global Constraints

- The allowed one-letter names are `w http.ResponseWriter`, `r *http.Request`, `t`/`b`/`f` for `*testing.T`/`*testing.B`/`*testing.F`, and `_` (decision 1).
- The name table is decision 2's. A name that would shadow an imported package used in the same function takes the short form: `sess`, `clk` or `ciph`.
- Renames go through gopls. A dispatch makes no edit other than a rename and the doc comment that follows it.
- This change merges to `main` before `harden-chain-boundary` cuts its private-fork branch (task 3.2). Nothing else touching `httpsec` merges between the two.
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never commit.

## Review Focus

1. **Generated files** (mockgen output, `*_mock_test.go`, files with a `Code generated` header) must be skipped by the guard and left untouched. This is added to task 1.1's table as the case "generated file is skipped".
2. **A parameter of a method on an unexported type** must not be reported, even when the method is exported. This is added to task 1.1 as "exported method on unexported type".
3. **Grouped parameters** (`func F(a, b int)`) must report each name. This is added to task 1.1 as "grouped names".
4. **A doc comment naming the old parameter** in backticks or prose must be updated. The reviewer of each lane reads `go doc` for every symbol in the lane's diff.
5. **Nested modules tested with the workspace off** must still build after the renames. Lane D runs `GOWORK=off go test ./...` in each nested module.

---

### Task 1.1: The guard

**Files:**
- Modify: `layout_test.go` (root module)

**Interfaces:**
- **Produces:**
  - `func shortParamViolations(fset *token.FileSet, file *ast.File) []violation`, returning one `violation{Where: "path:line", What: "Func: parameter \"x\" (Type)"}` per finding;
  - `TestExportedParametersHaveDescriptiveNames`, which walks the root module plus every directory in `release-modules.txt`.

- [ ] **Step 1: Write the checker's table test.** `TestShortParamViolations` has these cases, each built from a source string:
  - "allowed http pair": `func H(w http.ResponseWriter, r *http.Request)`, with no violation;
  - "testing": `func Helper(t *testing.T)`, with no violation;
  - "receiver": `func (s *S) Do(ctx context.Context)`, with no violation;
  - "unexported function": `func do(m *session.Sessions)`, with no violation;
  - "exported function": `func WithSessions(m *session.Sessions) Option`, with one violation naming `m`;
  - "exported interface method": `type Store interface{ Put(k string) error }`, with one violation;
  - "exported function type": `type Responder func(e *Exchange) error`, with one violation;
  - "grouped names": `func F(a, b int)`, with two violations;
  - "exported method on unexported type": `func (s *impl) Do(m int)`, with no violation;
  - "generated file is skipped": a file whose first comment is `// Code generated ... DO NOT EDIT.`, with no violation;
  - "underscore": `func F(_ int)`, with no violation.
- [ ] **Step 2: Run** `go test -run TestShortParamViolations -count=1 .`. Expected: FAIL, because `shortParamViolations` is undefined. That is a compile error, so it does not count as the red step yet. Add a stub returning nil, then expect FAIL on every case that wants a violation.
- [ ] **Step 3: Implement** `shortParamViolations`, then `TestExportedParametersHaveDescriptiveNames` over the module directories, skipping `_test.go`, `internal/` and generated files.
- [ ] **Step 4: Verify.**
  - `go test -run TestShortParamViolations -count=1 .` passes;
  - `go test -run TestExportedParametersHaveDescriptiveNames -count=1 .` FAILS, listing about 385 entries.

  Save the list to the scratchpad and compare its packages with the 2026-11-09 sweep.

### Tasks 2.1–2.4: Lanes (four parallel Sonnet dispatches; Sonnet reviewers)

**Files:**
- Lane A: `httpsec/*.go`
- Lane B: `oidcprovider/**`, `authenticate/oidc/**`
- Lane C: `recovery/**`, `session/**`, `authenticate/{,password,passkey,mfa,magiclink,apikey}/*.go` (passkey's nested `webauthn` module goes to lane D)
- Lane D: everything else listed in task 2.4, the `test` module's exported helpers included
- Dispatches (counts are the guard's 572 parameters):
  - A: `httpsec`, `httpsec/fibersec`, `httpsec/ginsec` (122)
  - B: `oidcprovider`, `authenticate/oidc` (83)
  - C1: `session`, `recovery`, `authenticate`, `authenticate/apikey`, `authenticate/magiclink` (88)
  - C2: `authenticate/mfa`, `authenticate/passkey`, `authenticate/password`, `authenticate/passkey/webauthn` (73)
  - D1: `store/*`, `test/*` (120)
  - D2: `policy/*`, `token/*`, `ratelimit/*`, `expiry/*`, `notify`, `outbound`, `identity`, `pkg/*`, `authorize`, `event` (86)

  Directories are disjoint, so all six run in parallel.

Each lane touches only its own files.

**Interfaces:**
- **Consumes:** the guard (task 1.1) and decision 2's table.

- [ ] **Step 1:** Run the guard, filtered to the lane's paths, and save the count.
- [ ] **Step 2:** For each entry, rename with `gopls rename -w <file>:<line>:<col> <name>` using decision 2's table, and update any doc comment that names the parameter.
- [ ] **Step 3: Verify.** The guard lists no entry under the lane's paths. `go build ./... && go vet` on the lane's packages pass. `go test` on the lane's packages passes, run with `GOWORK=off` in the nested modules. `go doc` on five symbols per lane shows the new names in the prose.
- [ ] **Step 4:** Report the files changed, the count before and after, and any shadowing short form used, with its reason.

### Task 2.5: Examples and README (Sonnet)

- [ ] **Step 1:** In every `example*_test.go` file and in `README.md`'s Go blocks, rename variables of the types in decision 2's table to their table names.
- [ ] **Step 2: Verify.** `go test -run Example -count=1 ./...` passes in each module, and `grep -nE '\b[a-z] :?= ' README.md` shows none of those types.

### Task 3.1: Integration gate

- [ ] **Step 1:** A fresh Sonnet reviewer reads the whole diff and rejects any hunk that is not a rename or a doc comment following one.
- [ ] **Step 2:** Run `make check` and `openspec validate descriptive-parameter-names --strict`. Both must pass.

### Task 3.2: Merge before the security fork (main session; maintainer merges)

- [ ] **Step 1:** Push the branch and open the pull request (no session link in its body). Wait for CI with `gh pr checks --watch`.
- [ ] **Step 2:** After the merge, run `git fetch origin && git grep -n TestExportedParametersHaveDescriptiveNames origin/main -- layout_test.go`. Expected: one match. Check that `gh run list --branch main --limit 1` shows success.
