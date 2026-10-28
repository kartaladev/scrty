# restructure-layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Regroup scrty into concept directories, consolidate files into feature families with table-driven tests, and apply the decided renames, without changing any behaviour.

**Architecture:** There are four sequential phases (moves, renames, file families, shared helpers). Each one ends with the same evidence gate, `evidence/check.sh`. It compares tests, API, declarations and coverage against a baseline through `evidence/rename-map.tsv`.
- Moves and renames touch callers in every package, so they run in a single lane.
- File families stay inside one package, so they run as parallel lanes.

**Tech Stack:** Go 1.27 workspace (`go.work` lists 9 modules; `tools` sits outside it, by design), gopls v0.24 for moves and renames, `golang.org/x/exp/cmd/apidiff`, testify, mockgen v0.6 (`--typed`), GitHub Actions with testcontainers.

**Spec:** `openspec/changes/restructure-layout/proposal.md`, `design.md` (decisions D1–D13), `specs/module-layout/spec.md` and `tasks.md`. Step numbers below cite `tasks.md` task numbers.

## Global Constraints

- **No behaviour change.** Every option and port keeps its default. A renamed option's godoc still names the default it replaces.
- **No feature is removed.** Every exported identifier, option, port, endpoint, sentinel, `Example` function and test has a successor. Every baseline top-level declaration, exported or not, maps to a declaration that exists. The only allowed absences are the D5 copies, each mapped to its `storekit` successor. `evidence/check.sh decls` enforces this at every gate.
- **`policy.AttemptStore` stays in `policy`** (D3), and **`txKey` stays in each backend** (D5).
- **Godoc describes the code, not its history.** No comment or godoc says that something was moved, renamed, merged or split, or names a former package, path or identifier ("formerly", "moved from", "was `Manager`", "see the old …"). A comment that already explains the code keeps its wording, apart from the names that changed. History belongs in the commit message and in this change's artifacts.
- **Module paths**, exactly:
  - `github.com/kartaladev/scrty/authenticate/passkey/webauthn`
  - `…/store/pgxstore`
  - `…/store/gormstore`
  - `…/ratelimit/redisstore`
  - `…/expiry/sweep`
  - `…/httpsec/ginsec`
  - `…/httpsec/fibersec`

  The test module stays `github.com/kartaladev/scrty/test`.
- **Package name equals the last element of the path,** for every moved package and module (`redisstore`, not `scrtyredis`).
- **Error strings** keep the form `"<package>: …"`, using the new package name (D11).
- **Renames go through `gopls rename` or a gopls package move,** never through text replacement of Go identifiers. File moves use `git mv`.
- **Never run** `git checkout --`, `git restore`, `git reset --hard`, `git stash` or `git clean`. An agent that needs to undo an edit does it by editing the file back.
- **`.claude/.legacy` is never read, cited or copied.** Exclude it from every search.
- **Mocks** stay `<source>_mock_test.go`, produced by their `//go:generate` directive. Regenerate them; never edit them by hand.
- **Table tests** follow `.claude/skills/table-test`: an `assert` closure, a `ctx` modifier for context-sensitive components, and `t.Context()`. Parallelism is never added: a case calls `t.Parallel()` only if its original function did.
- **Any defect found** is reported as `REPRODUCED` with its failing test, as `defect-claims.md` requires, and is never fixed in this change.
- **Only the main session** edits `openspec/` files, including `evidence/`. Agents never edit them.

## Review Focus

1. **A moved nested module builds in the workspace but not on its own.** Its `replace` paths gain a level (`../` becomes `../../`). Task 2.2 adds `GOWORK=off go build ./...` per moved module.
2. **An `Example…` function names a type or method that no longer exists.** `go vet` reports misnamed examples. Task 3.1 renames them alongside their identifiers, and its verification runs `go vet ./...` in every module.
3. **A `//go:generate` directive points at a source file that was merged away.** The directive must move with its interface. Tasks 4.1–4.6 verify that `go generate ./... && git status --porcelain` reports nothing beyond the task's own diff.
4. **A renamed type changes observable text through `%T` or `reflect`** (a log attribute, an error string). Task 3.1 lists every production `%T` and `reflect.TypeOf` use and either shows it emits no renamed name, or pins the new text in that package's test.
5. **A merged helper loses an identity that was separate on purpose.** Each backend's `txKey` is what keeps one backend from seeing another's transaction, and `gorm/tx_test.go` uses its own `foreignTxKey`, so a shared key would pass every test. Task 17 keeps `txKey` out of the move, and its verification checks that `type txKey struct{}` is still declared in each of the three backends. The reviewer reads every merged declaration's godoc for a "this package alone" guarantee.

---

## Dispatches and models

| Dispatch | Tasks | Lane | Model, reason | Reviewer |
|---|---|---|---|---|
| main session | 1.1–1.4 | evidence | main session: `openspec/` and verification are its own | none |
| P1a | 2.1–2.3 | moves | Opus: touches several packages and the interfaces every later lane compiles against | Opus |
| P1b | 2.4–2.5 | moves | Opus: the lockout split extracts code and must keep its behaviour | Opus |
| main session | 2.6 | gate | main session | Opus phase review |
| P2a | 3.1–3.3 | renames | Sonnet: every diff is fixed by `rename-map.tsv` and applied by gopls | Sonnet |
| P2b | 3.4–3.6 | renames | Sonnet: same reason | Sonnet |
| main session | 3.7 | gate | main session | Sonnet phase review |
| P3-httpsec | 4.1, then 4.2 | httpsec | 4.1 Sonnet (file moves fixed by D6's map); 4.2 Opus (a weakened table would pass the tests and still be wrong) | Sonnet, Opus |
| P3-oidc | 4.3 | oidc | Opus: same reason as 4.2 | Opus |
| P3-authn | 4.4 | policy, lockout, recovery, passkey | Opus | Opus |
| P3-core | 4.5 | session, mfa, … | Opus | Opus |
| P3-rest | 4.6 | remaining packages and modules | Opus | Opus |
| main session | 4.7 | gate | main session | per-lane reviews above |
| P4 | 5.1 | backends | Opus: extracts shared code while keeping behaviour | Opus |
| main session | 5.2, 6.1–6.2, 7.2 | | main session | none |
| review | 7.1 | whole branch | Opus | |

The five P3 lanes run in parallel, each owning only the packages its task names. All other dispatches run in sequence. Each dispatch starts only after the previous one's gate is green and its review is clean.

---

### Task 1: Baseline and evidence (tasks 1.1–1.4, main session)

**Files:**
- Create: `openspec/changes/restructure-layout/evidence/README.md`
- Create: `evidence/baseline/tests.jsonl` (one `{module, package, test, result}` per test or subtest), `evidence/baseline/testlist-test-module.txt`, `evidence/baseline/coverage.txt` (`package<TAB>percent`), `evidence/baseline/api/<import-path>.export`, `evidence/baseline/decls.tsv` (`import-path<TAB>kind<TAB>name`, where kind is `func`, `method`, `type`, `var`, `const` or `embed`, and a method's name is `Recv.Method`)
- Create: `evidence/rename-map.tsv` (columns `kind  old  new`). The kind is one of `path`, `ident`, `test`, `errprefix`, or `merged`: a D5 copy, whose `new` is its `storekit` successor.
- Create: `evidence/decls.sh`, which writes the declaration inventory for every non-generated production `.go` file (`gopls symbols` for the top-level declarations and methods, plus the `//go:embed` lines). It skips `*_test.go` and files that carry a `Code generated … DO NOT EDIT.` header.
- Create: `evidence/check.sh`

**Interfaces:**
- Produces: `evidence/check.sh [tests|api|decls|coverage|all]`. It exits 0 when all of the following hold:
  - every baseline test maps through `rename-map.tsv` to a present, passing entry;
  - every `apidiff` removal is a map key and every addition a map value;
  - every baseline declaration maps to a present declaration, or is a `merged` entry whose successor is present;
  - no package's coverage is lower.

  Otherwise it prints each unmapped, missing or failing entry and exits 1.

- [ ] **Step 1 (1.1):** `git fetch origin && git switch -c refactor/restructure-layout origin/main`. `openspec list` must not show `stabilize-intermittent-tests`, and no other change may be in implementation. Run `make check` minus the Docker suites. Expected: PASS.
- [ ] **Step 2 (1.2):** `GOBIN=<scratch>/bin go install golang.org/x/exp/cmd/apidiff@latest`. Write export data for `./pkg/clock`, and diff it against itself. Expected: an empty report. Record the exact command lines in `evidence/README.md`.
- [ ] **Step 3 (1.3):** For each module from `go list -m -f '{{.Dir}}'`, except `test` and `tools`, run `go test -json -count=1 -coverprofile=… ./...` and reduce the output into `tests.jsonl` and `coverage.txt`. Run `go test -list '.*' ./...` in `test/`. Write one `apidiff` export file per public package. Run `evidence/decls.sh > evidence/baseline/decls.tsv`. Expected: the counts are recorded in `README.md`.
- [ ] **Step 4 (1.4):** Fill `rename-map.tsv` from D1 (paths), D3, D8, D9 and D10 (identifiers), D11 (prefixes), and D5 (`merged` rows for every copy except `txKey`). Write `check.sh`. Run `evidence/check.sh all` on the unchanged tree. Expected: exit 0.
- [ ] **Step 5 (1.4), control:** Point `decls.sh` at a scratch copy of the tree with one unexported function deleted from one file, then run `check.sh decls` on it. Expected: exit 1, naming that function. Delete the scratch copy afterwards; the working tree is never touched.
- [ ] **Step 6:** `git add openspec/changes/restructure-layout/evidence && git commit -m "docs(openspec): capture restructure-layout's baseline evidence"`

### Task 2: Layout test for the new module paths (task 2.1, P1a)

**Files:**
- Modify: `layout_test.go` (add the tests below; change the `dir` of `TestWebAuthnTypesStayInsideTheAdapter` (line 278) to `authenticate/passkey/webauthn`, and the loop and helper path of `TestSoftwareAuthenticatorStaysOutOfProduction` (lines 318–320) to `github.com/kartaladev/scrty/authenticate/passkey/webauthn/webauthntest`; add a `github.com/jackc/pgx/v5` case to `TestCoreDependencies`)
- Modify: `layout_guard_test.go` (add `modulePath(t, dir) string`, which reads the `module` line; `packageClause(t, dir) string`, which reads the package clause of the first non-test `.go` file; and `unlistedModules(t, root string, listed []string) []string`, which returns the `workspaceModules` of `root` that are neither `.`, `test`, `tools` nor in `listed`)
- Create: `testdata/layout/wsunlisted/` (`go.work` using `.`, `./store/pgxstore` and `./pgx`, each with a one-line `go.mod`; the control fixture for exhaustiveness, in the style of `testdata/layout/wsmock`)
- Create: `testdata/layout/noalias/` (one module, `go.mod` and `go.sum`, holding `pgx.go`, `gorm.go` and `redis.go`. Each file imports one backend together with its driver, with no alias, and uses one exported identifier from each. `go.mod` replaces the root module and the three backends with relative paths, and `go.sum` is assembled from the three backends' own `go.sum`)

**Interfaces:**
- Consumes: `workspaceModules(t, root) []string` (`layout_guard_test.go:477`), and `integrationModules` (`layout_guard_test.go:49`).
- Produces: `var integrationDirs = []string{"authenticate/passkey/webauthn", "store/pgxstore", "store/gormstore", "ratelimit/redisstore", "expiry/sweep", "httpsec/ginsec", "httpsec/fibersec"}`, in `layout_guard_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestIntegrationModulesUnderTheirConcept` is a table over `{dir, pkg}` with these rows: `authenticate/passkey/webauthn` `webauthn`; `store/pgxstore` `pgxstore`; `store/gormstore` `gormstore`; `ratelimit/redisstore` `redisstore`; `expiry/sweep` `sweep`; `httpsec/ginsec` `ginsec`; `httpsec/fibersec` `fibersec`. Each `assert` closure checks:
    - `slices.Contains(workspaceModules(t, "."), dir)`;
    - `modulePath(t, dir) == "github.com/kartaladev/scrty/" + dir`;
    - `packageClause(t, dir) == pkg`.
  - `TestNoUnlistedIntegrationModule` is a table over `{root, assert}`:
    - `"."` asserts `assert.Empty(t, unlistedModules(t, ".", integrationDirs))`;
    - the control `"testdata/layout/wsunlisted"` asserts `assert.Equal(t, []string{"pgx"}, unlistedModules(t, root, integrationDirs))`.
  - `TestBackendDoesNotShadowDriver` runs `go build ./...` in `testdata/layout/noalias` with `GOWORK=off` and `GOFLAGS=-mod=mod`, and asserts it succeeds. Spec scenario: "A backend does not shadow its driver".
  - `TestModulesDeclareGoMinimum` is a table over the directories of `workspaceModules(t, ".")` plus `tools`. Each case asserts `assert.Equal(t, "go1.27", version.Lang("go"+goDirective(t, dir)))`, where `goDirective(t, dir) string` (new, in `layout_guard_test.go`) reads the `go` line. Spec scenario: "Declared minimum". It passes at once, so its red step is in Step 3.
  - `TestCoreDependencies` gains the case `"a major-version path of a listed driver is refused"`: `reqs: {{Path: "github.com/jackc/pgx/v5"}}`, asserting `hasViolation("go.mod", "github.com/jackc/pgx/v5")`.
- [ ] **Step 2:** `go test -run 'TestIntegrationModulesUnderTheirConcept|TestNoUnlistedIntegrationModule|TestBackendDoesNotShadowDriver|TestWebAuthn|TestSoftwareAuthenticator' -count=1 .` Expected: FAIL.
  - Every concept row reports its `dir` missing from the workspace.
  - The `"."` case names `pgx`, `gorm`, `redis`, `sweep`, `ginsec`, `fibersec` and `passkey/webauthn`. The control case passes.
  - `noalias` fails because its replace targets do not exist.

  Record the output in the dispatch report.
- [ ] **Step 3, red step for the pinned cases:** The `pgx/v5` case and `TestModulesDeclareGoMinimum` pass at once, because the code already behaves this way. For each one in turn, invert the expectation (`assert.Empty` for the `pgx/v5` case; `"go1.26"` for the Go minimum). Run `go test -run 'TestCoreDependencies|TestModulesDeclareGoMinimum' -count=1 .`, confirm it FAILS on that case, restore the expectation by editing it back, and record the output.
- [ ] **Step 4:** Commit with tasks 2.2–2.3 (the tests turn green there).

### Task 3: Move the nested modules (task 2.2, P1a)

**Files:**
- Move: `pgx/` → `store/pgxstore/`, `gorm/` → `store/gormstore/`, `redis/` → `ratelimit/redisstore/`, `sweep/` → `expiry/sweep/`, `ginsec/` → `httpsec/ginsec/`, `fibersec/` → `httpsec/fibersec/`
- Modify: each module's `go.mod` (`module` line, `replace` paths), `go.work`, every `go.mod` that requires them (`test/go.mod`, siblings), every import, and the package clause in `ratelimit/redisstore/*.go`
- Modify: `layout_guard_test.go:458` (`redisClientOwners = []string{"ratelimit/redisstore", "test"}`), and the module-directory inputs of `TestRedisClientStaysInItsModules` (`layout_test.go:356`, `"ginsec"` → `"httpsec/ginsec"`; `layout_test.go:364`, `"redis"` → `"ratelimit/redisstore"`)

- [ ] **Step 1:** `git mv` each directory, then rewrite each `module` line, its `replace` paths and `go.work`.
- [ ] **Step 2:** gopls moves packages, not modules, so rewrite the import-path prefix of each moved module (for example `"github.com/kartaladev/scrty/pgx` → `"github.com/kartaladev/scrty/store/pgxstore`) in quoted import paths only, across every workspace module. Update the requirements with `go mod edit -droprequire/-require`, and run `goimports -w` on the touched files. Change `package scrtyredis` to `package redisstore` with gopls, which also renames every qualified use.
- [ ] **Step 3:** For each moved module: `go build ./... && go vet ./...`, then `GOWORK=off go build ./...` (Review Focus 1). Expected: PASS everywhere.
- [ ] **Step 4:** `go test -run 'TestIntegrationModulesUnderTheirConcept|TestBackendDoesNotShadowDriver' -count=1 .` Expected: every row except `authenticate/passkey/webauthn` passes, and `noalias` builds.

### Task 4: Move core packages under `authenticate/` (task 2.3, P1a)

**Files:**
- Move (gopls package move): `factor`, `password`, `apikey`, `magiclink`, `oidc`, `mfa`, `passkey` → `authenticate/<name>`. `passkey/webauthn` (module) moves with `passkey`, and its `go.mod` and `go.work` entries are updated.

- [ ] **Step 1:** Move each package, leaves first (`factor`, `password`, then the rest), and rebuild after each move: `go build ./...` in every module.
- [ ] **Step 2:** `go test -count=1 ./...` in the core module and in `authenticate/passkey/webauthn`, plus `GOWORK=off go build ./...` in the module. Expected: PASS.
- [ ] **Step 3:** `go test -run 'TestIntegrationModulesUnderTheirConcept|TestNoUnlistedIntegrationModule|TestBackendDoesNotShadowDriver|TestCoreDependencies|TestWebAuthn|TestSoftwareAuthenticator|TestRedisClientStaysInItsModules|TestModuleLayout' -count=1 .` Expected: PASS. No module is left at a former path.
- [ ] **Step 4:** Commit: `refactor!: group integrations and login methods by concept`. The message names the moved paths.

### Task 5: `token/`, `store/` and `storeerr` → `store` (task 2.4, P1b)

**Files:**
- Move: `signingkey`, `onetime` → `token/<name>`; `sqlstore`, `migrate` (with `identity/` and `securitystate/`), `seal` → `store/<name>`
- Move and rename: `storeerr/` → `store/` (package `store`). Keep its file names; D6 runs later.

**Interfaces:**
- Produces: `store.ErrIsolationTooStrong`, aliased as `sqlstore.ErrIsolationTooStrong`, `pgxstore.ErrIsolationTooStrong` and `gormstore.ErrIsolationTooStrong`.

- [ ] **Step 1:** Move the packages with gopls, then build every module.
- [ ] **Step 2:** `go test -count=1 ./...` in the core module, `store/pgxstore` and `store/gormstore`. Expected: PASS. The existing backend tests that use `errors.Is(err, …ErrIsolationTooStrong)` stay green.
- [ ] **Step 3:** Commit: `refactor!: group tokens and stores under their parents`.

### Task 6: Split `policy/lockout` (task 2.5, P1b)

**Files:**
- Create: `policy/lockout/` holding:
  - `lockout.go`, `lockout_error.go`, `lockout_observer.go`, `attempts.go`, `streak.go` and `expiry.go`, with their tests (`lockout*_test.go`, `attempts*_test.go`, `streak_test.go`, `expiry_test.go`) and mocks;
  - a `doc.go` for package `lockout`;
  - `export_test.go`, taking the `AccountLockoutPolicy` and `MemoryAttemptStore` accessors out of `policy/export_test.go`;
  - `example_test.go`, taking the lockout `Example` functions out of `policy/example_test.go`.
- Keep in `policy`: `attempt_views.go` (`AttemptViewRequirer`, `RequiredAttemptView`), the `AttemptStore` interface (moved out of `attempts.go` into `attempt_views.go`, its godoc unchanged), and `engine.go`
- Move: the method `(*AccountLockoutPolicy).RequiredAttemptView` from `policy/attempt_views.go` into `policy/lockout/lockout.go`
- Modify: every caller (`httpsec`, `recovery`, the backends, and the test module), and the `policy_test` files that use lockout as a collaborator (`engine_test.go`, `example_test.go`, `returned_errors_test.go`, `store_failure_test.go`), which import `lockout`

**Interfaces:**
- Produces: D3's table. For example:
  - `lockout.New(opts ...lockout.Option) (*lockout.Policy, error)`
  - `lockout.WithThreshold`
  - `lockout.WithAttemptStore(s policy.AttemptStore) lockout.Option`
  - `lockout.Error`
  - `lockout.ExpiryTask(p *lockout.Policy) expiry.Task`
  - `lockout.NewMemoryAttemptStore(opts ...lockout.MemoryAttemptOption) *lockout.MemoryAttemptStore`
  - `(*lockout.Policy).RequiredAttemptView() (policy.AttemptStore, bool)`
- Unchanged: `policy.AttemptStore`, `policy.AttemptViewRequirer`, `policy.RequiredAttemptView`, and `policy.ErrConfig` (lockout wraps it; there is no `lockout.ErrConfig`).

- [ ] **Step 1:** Move `AttemptStore` into `policy/attempt_views.go`. `git mv` the group files into `policy/lockout/` and set `package lockout`. Move the `RequiredAttemptView` method beside its type. Qualify the `policy` names the group uses (`policy.Phase`, `policy.Decision`, `policy.Input`, `policy.ErrConfig`, `policy.ErrPolicyDenied`, `policy.AttemptStore`). Apply D3's renames with gopls.
- [ ] **Step 2:** Split `export_test.go` and `example_test.go` as listed. Add `var _ policy.AttemptViewRequirer = (*lockout.Policy)(nil)` to `lockout`'s tests.
- [ ] **Step 3:** `go list -deps ./policy | grep -c policy/lockout`. Expected: 0. `go doc ./policy AttemptStore`. Expected: resolves. Then run `go test -count=1 ./policy/... ./httpsec/... ./recovery/...` and build every module. Expected: PASS.
- [ ] **Step 4:** Add D3's test renames to `rename-map.tsv` (main session). Run `evidence/check.sh tests decls`. Expected: every former lockout test and `Example` function maps to a passing test, and every lockout declaration maps to one that exists.
- [ ] **Step 5:** Commit: `refactor!: split account lockout into policy/lockout`.

### Task 7: Phase-1 gate (task 2.6, main session)

- [ ] **Step 1:** `evidence/check.sh all && make check` (everything but the Docker suites). Expected: exit 0.
- [ ] **Step 2:** `git push -u origin refactor/restructure-layout`, and wait for CI on that head. Expected: green, including the testcontainers suites.
- [ ] **Step 3:** Dispatch the Opus phase reviewer with D1–D4, the `module-layout` delta and the phase diff. Expected: a clean report, or findings sent to a fresh P1 dispatch.

### Task 8: `Manager` renames (task 3.1, P2a)

**Files:** every module, through gopls. This includes `Example…` functions and their test files.

**Interfaces:**
- Produces: D8's table:
  - `oidc.NewRelyingParty(registry *Registry, broker IdentityBroker, opts ...Option) (*RelyingParty, error)`
  - `oidc.NewHandoff(...) (*Handoff, error)`
  - `authenticate.NewFirstOf(delegates ...Authenticator) (*FirstOf, error)`
  - `authorize.NewFirstOf(authorizers ...Authorizer) (*FirstOf, error)`
  - `session.New(opts ...Option) (*Sessions, error)`
  - `passkey.New(deps Deps, opts ...Option) (*Passkeys, error)`
  - `signingkey.New(ctx context.Context, opts ...Option) (*Keys, error)`
  - `apikey.New(opts ...Option) (*Keys, error)`
  - `onetime.New(purpose string, opts ...Option) (*Tokens, error)`
  - `magiclink.New(tokens *onetime.Tokens, users identity.UserLoader, sender notify.Sender, ...) (*Links, error)`
  - `httpsec.WithSessions(s *session.Sessions) Option`

- [ ] **Step 1:** Apply each row with `gopls rename`. Rename `Example<Old>…` functions to match (Review Focus 2).
- [ ] **Step 2:** List the production uses of `%T` and `reflect.TypeOf` (`rg -n '%T|reflect\.TypeOf' --glob '!*_test.go' --glob '!.claude/.legacy'`). For each one that can emit a renamed type name, pin the new text in that package's test (Review Focus 4).
- [ ] **Step 3:** In every module: `go build ./... && go vet ./... && go test -count=1 ./...`, then run `evidence/check.sh api tests decls` (main session). Expected: PASS, and only mapped differences.

### Task 9: Outliers, sentinels and the `policy` suffix (tasks 3.2–3.3, P2a)

- [ ] **Step 1 (3.2):** Apply D9 with gopls, including the `KeySource.Signer` interface method together with its implementations and mocks (regenerate the mocks with `go generate`), and `mfa.MaxEmailCodeAttempts`.
- [ ] **Step 2 (3.3):** Apply D10's sentinel table and the `policy` type and constructor renames. Rename the backend aliases of renamed sentinels too, if any.
- [ ] **Step 3:** Verify as in Task 8, Step 3, and run `go generate ./... && git status --porcelain` (expected: the task's own diff only). Commit: `refactor!: name types, sentinels and policies by what they are`.

### Task 10: Options and enums (task 3.4, P2b)

- [ ] **Step 1:** Apply D10's option table and the enum-prefix renames, package by package, with gopls. After each package, check the godoc of each renamed option: it must still name the default it replaces.
- [ ] **Step 2:** Verify as in Task 8, Step 3.

### Task 11: Error prefixes (task 3.5, P2b)

- [ ] **Step 1:** Rewrite the `"pgx: "`, `"gorm: "`, `"scrtyredis: "`, `"storeerr: "` and lockout `"policy: "` prefixes in production strings to `"pgxstore: "`, `"gormstore: "`, `"redisstore: "`, `"store: "` and `"lockout: "`.
- [ ] **Step 2:** Run `go test -count=1 ./...` in every module, and update only the prefix in each failing assertion.
- [ ] **Step 3:** `git diff -U0 -- '*_test.go' | grep '^[-+]' | grep -v '^[-+][-+]'`. Expected: every changed string pair differs only in its `"<package>: "` prefix. Commit: `refactor!: name error prefixes after their new packages`.

### Task 12: Prose sweep and phase-2 gate (tasks 3.6–3.7)

- [ ] **Step 1 (3.6, P2b):** For each left-hand entry of `rename-map.tsv` (kinds `path` and `ident`), `rg -n --glob '!openspec/**' --glob '!.claude/.legacy/**' '<old>'`, and rewrite each hit in godoc, examples and the README to the new name, without recording the old one. Then run `rg -n -i 'formerly|previously|renamed (from|to)|moved (from|to|into)|was (called|named)|used to be' --glob '*.go' --glob '!.claude/.legacy/**'` and compare it with the same search on the baseline commit. Expected: no hits remain, and no history hit is new.
- [ ] **Step 2 (3.7, main session):** Run `evidence/check.sh all && make check`, push, and confirm CI green. Then dispatch the Sonnet phase review against D8–D11. Expected: green, and a clean review.

### Task 13: `httpsec` families (tasks 4.1–4.2, lane P3-httpsec)

**Files:** `httpsec/` only. Production files follow D6's `httpsec` map, which gives 45 targets. Tests follow D6 rule 4, with `integration_test.go` and `helpers_test.go`.

- [ ] **Step 1 (4.1):** Merge the production files by the map. Each merge is a `git mv` of the larger source, and then the others' declarations are moved into it. Move each feature's `Enable…` function, option type and options out of `options.go` (§ in D6). Then `ls httpsec/*.go | grep -v _test`. Expected: exactly the 45 map targets.
- [ ] **Step 2 (4.1):** `go build ./... && go test -count=1 ./httpsec/...` and `go generate ./httpsec/... && git status --porcelain httpsec`. Expected: PASS, and no mock drift beyond directives moved with their interfaces (Review Focus 3). Commit.
- [ ] **Step 3 (4.2):** Merge the test files into one per production file. Where functions call the same SUT, convert them into a table per D7: the case name is the old suffix in lower case with spaces (`TestMFAVerify_BodyOnly` becomes `TestMFAVerify/body only`), and the assertions move unchanged into `assert`. Add the case's new name to `rename-map.tsv` (report it to the main session).
- [ ] **Step 4 (4.2), red step for each table:** Invert one case's expectation, run `go test -run 'TestX' -count=1 ./httpsec/`, and confirm it FAILS on that case. Revert the inversion, and record the failing output in the dispatch report (Review Focus 5).
- [ ] **Step 5:** The main session runs `evidence/check.sh tests decls coverage`. Expected: every baseline `httpsec` test maps to a passing test, every declaration survives, and coverage is not lower. Commit.

### Task 14: `oidc` families (task 4.3, lane P3-oidc)

**Files:** `authenticate/oidc/` only. Production files follow D6's `oidc` map, which gives 17 targets.

- [ ] **Steps:** As in Task 13, Steps 1–5, against the `oidc` map. Expected: exactly 17 production files.

### Task 15: Remaining packages (tasks 4.4–4.6, lanes P3-authn, P3-core, P3-rest)

**Files:** only the packages each task in `tasks.md` names.

- [ ] **Step 1:** For each package, write its file map in D6's table form (target ← sources), applying the five rules, and include it in the dispatch report before moving anything.
- [ ] **Step 2:** As in Task 13, Steps 1–5, for each package.
- [ ] **Step 3 (4.6 only):** `go generate ./... && git status --porcelain` in every module the lane owns. Expected: no drift.

### Task 16: Phase-3 gate (task 4.7, main session)

- [ ] **Step 1:** `evidence/check.sh all && make check`, push, and confirm CI green.
- [ ] **Step 2:** One reviewer per lane, at the lane's own model, against D6 and D7. Each reviewer compares every converted case's assertions with its original function's in the baseline commit. Expected: clean reviews.

### Task 17: Shared backend helpers (tasks 5.1–5.2, P4)

**Files:** `internal/storekit/`, `store/sqlstore/`, `store/pgxstore/`, `store/gormstore/`, `internal/pglimiter/`.

**Interfaces:**
- Produces, in `internal/storekit`: `BestEffort`, `CheckUser`, `ParseUserID`, `SurvivingRoles`, `DBFailed`, `DetachedError`, `DetachedText`, `ErrPasskeyHandleHeld`, `ErrStreakContended`, `OptionKind`, `SQLStater`. Each keeps the signature of the copies it replaces, now exported within `internal`.
- Not produced: `TxKey`. Each backend keeps its own unexported `type txKey struct{}` (D5).

- [ ] **Step 1:** For each helper, confirm the copies are textually identical (`diff` of their declarations, ignoring only the package's error prefix). Read each one's godoc. One that promises something to "this package alone" does not move: report it, and stop for the main session. Move one copy into `storekit`, point every backend at it, and delete the other copies.
- [ ] **Step 2:** `rg -c 'func bestEffort|func checkUser|…' store internal`. Expected: 0 outside `storekit`'s exported versions. `rg -c '^type txKey struct\{\}' store/sqlstore store/pgxstore store/gormstore`. Expected: 1 in each. Then `go test -count=1 ./...` in the core module and both backend modules.
- [ ] **Step 3 (5.2):** The main session runs `evidence/check.sh all && make check`, pushes, and confirms CI green (the store-conformance suites). Then the Opus review against D5. Commit: `refactor: share the SQL backends' identical helpers`.

### Task 18: The repository's own references (tasks 6.1–6.2, main session)

- [ ] **Step 1 (6.1):** Edit the `openspec/config.yaml` context: the integration module list (the D1 paths), the adapter names, and the `pkg/` line. Run `openspec validate --all --strict`. Expected: PASS.
- [ ] **Step 2 (6.2):** Rewrite the old paths and names in the artifacts of `trusted-proxy-client-ip`, `release-readiness` (its tag prefixes become the D2 list), `di-wiring`, `bff-resource-server`, and `minimize-test-containers` once it is on `main`. Check `idiomatic-api-shape` and `key-port-context` against the names that actually landed, and correct any that differ, for example a `lockout.ErrConfig` that D3 never creates. For each change whose `tasks.md` content changed, rerun `/superpowers:writing-plans` into its `plans.md`.
- [ ] **Step 3:** `rg -n -f <(cut -f2 evidence/rename-map.tsv) openspec/changes --glob '!restructure-layout/**'`. Expected: no hits. Commit: `docs(openspec): point active changes and config at the new layout`.

### Task 19: Final integration (tasks 7.1–7.2)

- [ ] **Step 1 (7.1):** Dispatch the Opus whole-branch reviewer with the `module-layout` delta, D1–D13 and `git diff origin/main...HEAD`. Expected: a clean report, with every finding fixed by a fresh dispatch of its lane.
- [ ] **Step 2 (7.2):** `evidence/check.sh all` against the group-1 baseline, `openspec validate restructure-layout --strict`, and CI green on the final head. Expected: exit 0, valid, and green.
