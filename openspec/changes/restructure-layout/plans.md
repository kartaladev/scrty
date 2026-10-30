# restructure-layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Regroup scrty into concept directories, consolidate files into feature families with table-driven tests, and apply the decided renames, without changing any behaviour. Then name every bound after what it bounds, and fix the four behaviours and one hazard that the 2026-10-31 security review proved.

**Architecture:** There are four sequential phases (moves, renames, file families, shared helpers). Each one ends with the same evidence gate, `evidence/check.sh`. It compares tests, API, declarations and coverage against a baseline through `evidence/rename-map.tsv`.
- Moves and renames touch callers in every package, so they run in a single lane.
- File families stay inside one package, so they run as parallel lanes.

**Tech Stack:** Go 1.27 workspace (`go.work` lists 9 modules; `tools` sits outside it, by design), gopls v0.24 for moves and renames, `golang.org/x/exp/cmd/apidiff`, testify, mockgen v0.6 (`--typed`), GitHub Actions with testcontainers.

**Spec:** `openspec/changes/restructure-layout/proposal.md`, `design.md` (decisions D1–D20), the deltas under `specs/` (`module-layout`, `test-provisioning`, `token-issuance`, `authentication`, `http-error-propagation`, `http-security-chain`, `api-keys`, `rate-limiting`, `account-recovery`) and `tasks.md`. Step numbers below cite `tasks.md` task numbers.

## Global Constraints

- **No behaviour change, outside groups 12–16.** Every option and port keeps its default. A renamed option's godoc still names the default it replaces. Groups 12–16 (D16–D20) change exactly what their decisions and deltas state, and each states its default and the consumer's override.
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
- **Error strings** keep the form `"<package>: …"`, using the new package name, and an identifier a message names uses its new name (D11). A message that stands for another package's sentinel starts with that sentinel's text (`"policy: denied by policy: …"`, `"policy: invalid configuration: …"`, `"ratelimit: invalid configuration: …"`).
- **Renames go through `gopls rename` or a gopls package move,** never through text replacement of Go identifiers. File moves use `git mv`.
- **Never run** `git checkout --`, `git restore`, `git reset --hard`, `git stash` or `git clean`. An agent that needs to undo an edit does it by editing the file back.
- **`.claude/.legacy` is never read, cited or copied.** Exclude it from every search.
- **Mocks** stay `<source>_mock_test.go`, produced by their `//go:generate` directive. Regenerate them; never edit them by hand.
- **Table tests** follow `.claude/skills/table-test`: an `assert` closure, a `ctx` modifier for context-sensitive components, and `t.Context()`. Parallelism is never added: a case calls `t.Parallel()` only if its original function did.
- **Any defect found** is reported as `REPRODUCED` with its failing test, as `defect-claims.md` requires, and is never fixed in this change. There are three exceptions: a difference this change itself introduced against `main`, such as the `storeDenied` text that task 8.2 restores; the second PR review's reproduced defects, which the user folded into this change as group 9 (2026-10-29); the test module's shared HTTP transport (D14), which the user folded in as group 10 (2026-10-30); and the security review's proven claims (D16–D20), which the user folded in as groups 12–16 (2026-10-31).
- **Only the main session** edits `openspec/` files, including `evidence/`. Agents never edit them.

## Review Focus

1. **A moved nested module builds in the workspace but not on its own.** Its `replace` paths gain a level (`../` becomes `../../`). Task 2.2 adds `GOWORK=off go build ./...` per moved module.
2. **An `Example…` function names a type or method that no longer exists.** `go vet` reports misnamed examples. Task 3.1 renames them alongside their identifiers, and its verification runs `go vet ./...` in every module.
3. **A `//go:generate` directive points at a source file that was merged away.** The directive must move with its interface. Tasks 4.1–4.6 verify that `go generate ./... && git status --porcelain` reports nothing beyond the task's own diff.
4. **A renamed type changes observable text through `%T` or `reflect`** (a log attribute, an error string). Task 3.1 lists every production `%T` and `reflect.TypeOf` use and either shows it emits no renamed name, or pins the new text in that package's test.
5. **A merged helper loses an identity that was separate on purpose.** Each backend's `txKey` is what keeps one backend from seeing another's transaction, and `gorm/tx_test.go` uses its own `foreignTxKey`, so a shared key would pass every test. Task 17 keeps `txKey` out of the move, and its verification checks that `type txKey struct{}` is still declared in each of the three backends. The reviewer reads every merged declaration's godoc for a "this package alone" guarantee.


**Review Focus for groups 11–16:**

6. **A framework adapter answers its own status for `ErrUnavailable`.** If `ginsec` or `fibersec` map errors without `StatusForError`, an outage could still answer 401 or 500 there. Task 42 adds a case per adapter asserting 503.
7. **A degraded shared limiter charges nothing.** With `internal/unavailable` in a degrade mode, a charge during an outage must hit the local fallback, or every recovery code during an outage is unthrottled. Task 51 adds the degraded-path charge case.
8. **A refund removes another request's failure.** Two concurrent charges with equal stamps, then one refund, must leave exactly one failure. Task 50's conformance case charges twice, refunds once, and asserts one failure remains.
9. **A renamed option still appears in README or `Example` code.** Task 37's sweep covers README; `go vet` covers `Example` names.
10. **A verifier waiver is passed together with its configured check.** Task 47's table asserts `ErrConfig` for both pairs.

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
| R1 | 8.1 | `internal/storekit` tests | Sonnet: the finding states the fix; exact texts are given below | Sonnet (combined R-review) |
| R2 | 8.2 | `policy/lockout` | Sonnet: the text to restore and the table to extend are given | Sonnet (combined R-review) |
| R3 | 8.3 | `httpsec` godoc | Haiku: a godoc edit whose exact diff is given | Sonnet (combined R-review) |
| R4 | 8.4 | `test/httpsecconformance`, README | Sonnet: gopls field renames plus their comments | Sonnet (combined R-review) |
| main session | 8.5 | gate | main session | one Sonnet review of R1–R4 |
| P5 | 9.1, then 9.2 | `internal/storekit`, `store/sqlstore`, `store/pgxstore`, `store/gormstore` | Opus: extracts security-relevant redaction code and the UPDATE allow-list while keeping behaviour | Opus |
| R5 | 9.3, 9.4, 9.6 | `policy/lockout`, `httpsec/options.go` and `httpsec/options_test.go`, `session` godoc | Sonnet: each text and its test are given | Sonnet (combined R5/R6 review) |
| R6 | 9.5 | `layout_test.go`, `layout_guard_test.go`, `testdata/layout/noalias*` | Sonnet: each guard's new shape and its red test are given | Sonnet (combined R5/R6 review) |
| main session | 9.7 | gate | main session | the reviews above |
| T1 | 10.1 | `test/oidc/idp_test.go` | Sonnet: the helper change and its red test are given | Sonnet (combined T1/T2 review) |
| T2 | 10.2 | `test/testutils.go`, `test/oidc_keycloak_test.go`, `test/testutils_http_test.go` | Sonnet: same reason | Sonnet (combined T1/T2 review) |
| main session | 10.3 | gate | main session | the review above |
| N1 | 11.1–11.3 | renames, workspace-wide | Sonnet: every diff is fixed by D15's table and applied by gopls | Sonnet |
| main session | 11.4–11.5 | evidence, gate | main session | the review above |
| S1 | 12.1–12.2 | `internal/storekit`, `store/sqlstore/identity.go`, `store/pgxstore/identity.go`, `identity/ports.go` | Sonnet: the constructor, its test and the godoc text are given | Sonnet |
| U1 | 13.1–13.3 | `authenticate`, `httpsec/basic*.go`, `httpsec/login*.go`, `httpsec/errors*.go` | Opus: changes what a refusal means across two packages, and a wrong mapping would pass most tests | Opus |
| U3 | 13.5 | `authenticate/password*.go`, `httpsec/password_outage_test.go`, `httpsec/basic.go`, `httpsec/recovery.go` | Opus: refusal semantics under cancellation | Opus (one review of U1–U3) |
| U2 | 13.4 | `recovery/recover*.go`, `httpsec/login_options.go` | Opus: same reason as U1, and it touches a security refusal path | Opus (one review of U1–U2) |
| K1 | 14.1–14.2 | `httpsec/apikey*.go` | Opus: refusal logic written for the first time | Opus |
| V1 | 15.1–15.3 | `token/**` | Opus: token verification logic | Opus |
| V3 | 15.5 | `token/**` | Opus: verification refusal logic | Opus (one review of V1–V3) |
| V2 | 15.4 | `token/**`, `test/oidc/idp_test.go`, `test/oidc_keycloak_test.go`, README | Opus: same reason, and it extends V1's construction rule | Opus (one review of V1–V2) |
| L1 | 16.1 | `ratelimit` (memory), `test/ratelimittest` | Opus: concurrency, and the interface L2 and L3 compile against | Opus (one review of L1–L3) |
| L2 | 16.2 | `internal/pglimiter`, `internal/unavailable`, `store/sqlstore/limiter*.go`, `store/pgxstore/limiter*.go`, `ratelimit/redisstore`, the test module's limiter suites | Opus: atomic writes in SQL and Lua | Opus (one review of L1–L3) |
| L3 | 16.3 | `ratelimit/limiter.go`, every `limiter_mock_test.go`, `test/ratelimittest/doubles_test.go`, `test/pg_ratelimit_fault_test.go`, `recovery/codes*.go` | Opus: widens a port and fixes a race | Opus (one review of L1–L3) |
| main session | 12.3, 13.6, 14.3, 15.6, 16.4, 17.1–17.2 | gates, `openspec/` references | main session | the reviews above; Opus whole-branch review at 17.2 |

The five P3 lanes run in parallel, each owning only the packages its task names. R1–R4 own disjoint files and run in parallel too, and so do P5, R5 and R6, and T1 and T2. Groups 11–16 run in four rounds: N1 alone; then S1, U1, V1 and L1 in parallel; then U2 (after U1), L2 (after L1) and V2 (after V1) in parallel, and K1 after U2; then L3 (after L2 and K1, because it regenerates `httpsec/limiter_mock_test.go`). All other dispatches run in sequence. Each dispatch starts only after the previous one's gate is green and its review is clean.

---

### Task 1: Baseline and evidence (tasks 1.1–1.4, main session)

**Files:**
- Create: `openspec/changes/restructure-layout/evidence/README.md`
- Create: `evidence/examples.py`, and `evidence/baseline/examples.tsv` (`import-path<TAB>Example name`, read from source, because `go test` lists only the examples that have an output comment)
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
  - `lockout.go`, `lockout_error.go`, `lockout_observer.go`, `attempts.go`, `streak.go` and `expiry.go`, with their tests (`lockout*_test.go`, `attempts*_test.go`, `streak_test.go`, `expiry_test.go`, and `returned_errors_test.go`, whose one test exercises the lockout policy's own methods) and mocks;
  - a `doc.go` for package `lockout`;
  - `export_test.go`, taking the `AccountLockoutPolicy` and `MemoryAttemptStore` accessors out of `policy/export_test.go`;
  - `example_test.go`, taking the lockout `Example` functions out of `policy/example_test.go`.
- Keep in `policy`: `attempt_views.go` (`AttemptViewRequirer`, `RequiredAttemptView`), the `AttemptStore` interface (moved out of `attempts.go` into `attempt_views.go`, its godoc unchanged), and `engine.go`
- Move: the method `(*AccountLockoutPolicy).RequiredAttemptView` from `policy/attempt_views.go` into `policy/lockout/lockout.go`
- Modify: every caller (`httpsec`, `recovery`, the backends, and the test module), and the `policy_test` files that use lockout as a collaborator (`engine_test.go`, `example_test.go`, `store_failure_test.go`), which import `lockout`

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

### Task 11: Error messages (task 3.5, P2b)

- [ ] **Step 1:** Rewrite the `"pgx: "`, `"gorm: "`, `"scrtyredis: "`, `"storeerr: "` and lockout `"policy: "` prefixes in production strings to `"pgxstore: "`, `"gormstore: "`, `"redisstore: "`, `"store: "` and `"lockout: "`.
- [ ] **Step 2:** In production error strings, rewrite every identifier the map renames (kinds `ident` and `path`) to its new name: for example lockout's `"WithLockoutCap must be positive"` → `"WithCap must be positive"`, and `(policy.FailureStreakStore)` → `(lockout.FailureStreakStore)`. Expected: `rg` over production `.go` string literals for each left-hand identifier of `rename-map.tsv` finds none.
- [ ] **Step 3:** Run `go test -count=1 ./...` in every module, and in each failing assertion update only the prefix and the renamed identifiers.
- [ ] **Step 4:** Diff filter over `git diff -U0 -- '*_test.go'`: for every changed string pair, apply the D11 prefixes and the map's identifier renames to the old string. Expected: it equals the new string. Commit: `refactor!: name error messages after the new packages and identifiers`.

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

### Task 20: `storekit` refusal tests assert exact text (task 8.1, R1)

**Files:** Modify `internal/storekit/storekit_test.go` (`TestCheckUser`, its three refusing cases) only.

**Interfaces:** Consumes `storekit.CheckUser(username string, u *identity.UserChange) error` and the unexported `unstorable(field string) error` in `internal/storekit/storekit.go`. Neither changes.

- [ ] **Step 1: Replace each refusing case's assertions with the whole text**

```go
// "username with a NUL byte"
require.EqualError(t, err, "the username holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
// "name with invalid UTF-8"
require.EqualError(t, err, "the name holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
// "role with a NUL byte"
require.EqualError(t, err, "the role holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store")
```

The `Contains` and `NotContains` lines in those three cases go; the exact text subsumes them. Case names, order and `t.Parallel()` stay.

- [ ] **Step 2: Red step.** Temporarily change `unstorable` to `fmt.Errorf("the %s holds a NUL byte or invalid UTF-8, which PostgreSQL text cannot store: %q", field, value)` (threading the value through `CheckStorable`'s loop for the experiment only). Run: `go test -count=1 -run 'TestCheckUser' ./internal/storekit/`. Expected: FAIL in all three refusing cases, each showing the leaked value in the actual text. Record the lines. Edit the experiment back; `git diff internal/storekit/storekit.go` must be empty.

- [ ] **Step 3: Verify.** `go test -count=1 -race ./internal/storekit/` passes. `go test -count=1 -coverprofile=<scratch>/sk.out ./internal/storekit/` covers at least 185 of 190 statements.

### Task 21: Restore `storeDenied`'s text (task 8.2, R2)

**Files:** Modify `policy/lockout/lockout.go` (`storeDenied`) and `policy/lockout/lockout_test.go` (`TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer`).

**Interfaces:** `storeDenied(err error) policy.Decision` keeps its signature, its `diag.Wrap` call and its `policy.ErrDenied` kind. Only the fixed text changes.

- [ ] **Step 1: Write the failing assertion.** In every case of `TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer` whose decision comes from `storeDenied` (the store returned an error), add beside the existing `ErrorIs` checks:

```go
assert.EqualError(t, d.Reason,
	"policy: denied by policy: the attempt store could not say how often this identifier has failed")
```

The existing `ErrorIs(d.Reason, errAttemptStoreDown)` and `ErrorIs(d.Reason, policy.ErrDenied)` stay: the text must not replace identity.

- [ ] **Step 2: Run it.** `go test -count=1 -run 'TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer' ./policy/lockout/`. Expected: FAIL, actual text `"lockout: denied by policy: …"`. Record the line.

- [ ] **Step 3: Implement.** In `storeDenied`, change the text to `"policy: denied by policy: the attempt store could not say how often this identifier has failed"`.

- [ ] **Step 4: Verify.** `go test -count=1 -race ./policy/...` and `go test -count=1 ./httpsec/...` pass. Then search the production `diag.Wrap` and `fmt.Errorf` texts that carry another package's sentinel as a kind or `%w`: each must start with that sentinel's text. Expected: no other mismatch (on 2026-10-29 only `storeDenied` differed). Report any found; do not fix it in this task.

### Task 22: Doc links to `lockout.Policy.Attempts` (task 8.3, R3)

**Files:** Modify the godoc at `httpsec/basic.go:252`, `httpsec/login_options.go:42` and `httpsec/options.go:1052`.

- [ ] **Step 1:** In each of the three comments, replace `lockout.Attempts()` with `[lockout.Policy.Attempts]`, rewrapping the comment line if it then passes the file's comment width. No other wording changes.
- [ ] **Step 2: Verify.** `rg -n 'lockout\.Attempts\(\)' --glob '!.claude/.legacy' .` finds nothing. `go doc ./httpsec BasicAuthDeps` shows `lockout.Policy.Attempts`. `gofmt -l httpsec` prints nothing.

### Task 23: Conformance fixture fields and README names (task 8.4, R4)

**Files:** `test/httpsecconformance/passkey_scenarios.go`, `oidc_scenarios.go`, `oidc_assurance_scenarios.go` and any other caller gopls finds; `README.md`.

**Interfaces:** Produces `PasskeyFixture.Passkeys *passkey.Passkeys` and `OIDCFixture.RelyingParty *oidc.RelyingParty`. `Handoffs` and every other field are unchanged.

- [ ] **Step 1:** `gopls rename` `PasskeyFixture.Manager` → `Passkeys` and `OIDCFixture.Manager` → `RelyingParty`. Rewrite their field comments to name what they hold ("Passkeys runs the ceremonies the chain's endpoints serve"; "IDP is the in-process provider, RelyingParty and Handoffs the relying party and handoff store the chain was given").
- [ ] **Step 2:** In `README.md`, rename the variable bound to `oidc.NewRelyingParty(...)` from `manager` to `relyingParty`, with every use of it in the same snippet.
- [ ] **Step 3: Verify.** In `test/`: `go build ./... && go vet ./...` pass, and `go test -list . ./httpsecconformance/... ./...` lists the same top-level tests as `evidence/baseline/testlist-test-module.txt` mapped through the rename map (`check.sh tests` reports nothing unaccounted). `rg -n '\.Manager\b' test/` finds nothing.

### Task 24: Re-run the final gate (task 8.5, main session)

- [ ] **Step 1:** After R1–R4 report, run `make check` and `evidence/check.sh all` against the group-1 baseline, and `openspec validate restructure-layout --strict`. Expected: pass, 0 unaccounted, valid.
- [ ] **Step 2:** One Sonnet reviewer reads the R1–R4 diff against D5, D8, D11 and D12 and the recorded red-step lines. Expected: a clean report.
- [ ] **Step 3:** Commit (`fix: answer PR #27's review: exact refusal text, the policy denial prefix, doc links and fixture names`), push, and confirm CI green on the new head, including the Docker suites.

### Task 25: Shared detached-error builder and SQLSTATE filter (task 9.1, P5)

**Files:**
- Modify: `internal/storekit/storekit.go`, `internal/storekit/storekit_test.go`
- Modify: `store/sqlstore/identity_errors.go`, `store/pgxstore/identity_errors.go`, `store/gormstore/identity_errors.go` (remove `detached` and `validSQLState`/`isSQLState`; `dbFailed` calls `storekit.Detached`)
- Not owned: `openspec/` (the main session adds the `merged` rows)

**Interfaces:**
- Consumes: `storekit.SQLStater`, `storekit.DetachedText(err error, text string, kept []error) error` (unchanged).
- Produces: `storekit.ValidSQLState(code string) bool`; `storekit.Detached(err error, kept []error) error`, whose text is `"database failure"`, followed by `" (SQLSTATE " + code + ")"` when `errors.As(err, &SQLStater)` reports a code `ValidSQLState` accepts. Its godoc states everything the three backends' `detached` godoc promised: the driver's error value is out of the chain, no driver text is kept, and the result stays matchable against the kept sentinels err matched.

- [ ] **Step 1: Stub.** Declare both functions in `storekit.go` returning `false` and `nil`, so the tests compile and fail on behaviour.
- [ ] **Step 2: Write the failing tables** (`table-test` form):
  - `TestValidSQLState`: `"23505"` and `"P0001"` → true; `"2350"`, `"235050"`, `"p0001"`, `"23 05"`, `""` → false.
  - `TestDetached`: a SQLStater error reporting `"40001"` with text `"secret value"` → `EqualError(err, "database failure (SQLSTATE 40001)")`; one reporting `"bad!!"` → `EqualError(err, "database failure")`; a plain error → `"database failure"`; an error wrapping `context.Canceled`, with `kept = []error{context.Canceled}` → `ErrorIs(err, context.Canceled)` and `NotErrorIs(err, <the driver error>)`; a kept sentinel err does not match → `NotErrorIs`.
- [ ] **Step 3: Run.** `go test -count=1 -run 'TestValidSQLState|TestDetached' ./internal/storekit/`. Expected: FAIL on the true cases and every `EqualError`. Record the lines.
- [ ] **Step 4: Implement.** Move the body of `validSQLState` and of `detached` (its list now the `kept` parameter) into `storekit`. In each backend, delete both functions and write `dbFailed` as `failed(op, storekit.Detached(err, detachedKept))`. `detachedKept`, `scanFailed` and `failed` stay.
- [ ] **Step 5: Verify.** `go test -count=1 -race ./internal/storekit/` passes; `go test -count=1 ./...` passes in the core module, `store/pgxstore` and `store/gormstore`; `rg -n 'func (detached|validSQLState|isSQLState)\b' store/` finds nothing. Report the six removed declarations by package for the `merged` rows.

### Task 26: Shared partial user UPDATE (task 9.2, P5, after Task 25)

**Files:**
- Modify: `internal/storekit/storekit.go`, `internal/storekit/storekit_test.go`
- Modify: `store/sqlstore/identity.go` (~lines 750–797), `store/pgxstore/identity.go` (~lines 780–829): remove `userColumns`, `updateUserQuery`, and `column` if nothing else uses it; the callers (`sqlstore/identity.go:384`, `pgxstore/identity.go:395`) call `storekit`.
- Not touched: `store/gormstore/identity.go` (`userColumns` builds a `map[string]any` for gorm; D5).

**Interfaces:**
- Produces:
  - `type Column struct { Name string; Value any }`
  - `func UserColumns(u *identity.UserChange, org any, ts func(time.Time) any) []Column`: in this order, `name` (`u.Name`), `password` (`OrEmpty(u.Password)`), `organization_id` (`org`), `password_changed_at` (`ts(u.PasswordChangedAt)`), each only when `u.IsSet` names its field. The godoc keeps the allow-list wording of the backends' `userColumns`.
  - `func UpdateUserQuery(set []Column, now time.Time, userID any) (string, []any)`
- The callers pass `nullTs` (wrapped as `func(t time.Time) any { return nullTs(t) }` in `pgxstore`), and `pgxstore` passes `uuidArg(userID)` as `userID`.

- [ ] **Step 1: Stub** both functions returning zero values.
- [ ] **Step 2: Write the failing tables.**
  - `TestUpdateUserQuery`: no column → `"UPDATE users SET updated_at = $1 WHERE id = $2"`, args `[now, id]`; `name` alone → `"UPDATE users SET name = $1, updated_at = $2 WHERE id = $3"`, args `["Ada", now, id]`; all four columns → `$1`…`$4`, `updated_at = $5`, `WHERE id = $6`.
  - `TestUserColumns`: nothing set → empty; each field set alone → its one column; every field set → the four names in the order above; `FieldEmail` set → no column; `ts` is called only for `password_changed_at` (a `ts` that returns a marker value appears there and nowhere else).
- [ ] **Step 3: Run.** `go test -count=1 -run 'TestUpdateUserQuery|TestUserColumns' ./internal/storekit/`. Expected: FAIL on every case but the empty one. Record the lines.
- [ ] **Step 4: Implement.** Move the bodies, and switch both callers.
- [ ] **Step 5: Verify.** `go test -count=1 -race ./internal/storekit/` passes; `go test -count=1 ./...` passes in the core module and `store/pgxstore`; `GOWORK=off go build ./...` in `store/pgxstore`. The test module's store-conformance Update cases run in CI at Task 31. Report the removed declarations for the `merged` rows.

### Task 27: `storeDenied`'s prefix from the sentinel (task 9.3, R5)

**Files:** Modify `policy/lockout/lockout.go` (`storeDenied`) and `policy/lockout/lockout_test.go` (`storeDeniedText`, `TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer`).

- [ ] **Step 1: Write the failing case.** Add to `TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer` a case whose store's `FailureCount` returns `errAttemptStoreDown`, asserting `assert.True(t, strings.HasPrefix(d.Reason.Error(), policy.ErrDenied.Error()+": "))`. If its setup cannot share the table's shape, make it the standalone `TestStoreDeniedLeadsWithTheDeniedSentinelText`, with the one-line comment `table-test` asks for.
- [ ] **Step 2: Red.** Temporarily change `ErrDenied` in `policy/policy.go:34` to `errors.New("policy: denied")`. Run `go test -count=1 -run 'TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer|TestStoreDeniedLeadsWithTheDeniedSentinelText' ./policy/lockout/`. Expected: FAIL, the reason still reading `"policy: denied by policy: …"`. Record the line.
- [ ] **Step 3: Implement.** `storeDenied`'s text becomes `policy.ErrDenied.Error() + ": the attempt store could not say how often this identifier has failed"`, and `storeDeniedText` becomes the same expression. Run Step 2's command again with `ErrDenied` still changed. Expected: PASS.
- [ ] **Step 4: Restore and verify.** Edit `ErrDenied` back. `git diff policy/policy.go` is empty, and `go test -count=1 -race ./policy/...` passes.

### Task 28: `httpsec` names `lockout.Policy.Attempts` (task 9.4, R5)

**Files:** Modify `httpsec/options.go:1103-1104` and `httpsec/options_test.go` (`TestLockoutCapWiring`).

- [ ] **Step 1: Write the failing assertion.** In `TestLockoutCapWiring`, the cases that use `refusedNaming` for a login given a store other than the capped policy's view gain `assert.EqualError(t, err, <the whole text>)`. Take the whole text from the current failure output, with `(Attempts() for an account-lockout policy)` replaced by `(lockout.Policy.Attempts for an account-lockout policy)`.
- [ ] **Step 2: Run.** `go test -count=1 -run TestLockoutCapWiring ./httpsec/`. Expected: FAIL, the actual text holding `Attempts()`. Record the line.
- [ ] **Step 3: Implement.** Change the message text to `"give it that policy's view (lockout.Policy.Attempts for an account-lockout policy)"`.
- [ ] **Step 4: Verify.** `go test -count=1 -race ./httpsec/...` passes.

### Task 29: The `session` godoc reads as English (task 9.6, R5)

**Files:** Modify the comments in `session/reuse.go` (lines 16–17, 34) and every other hit of `rg -n 'the Sessions' session/` that does not read as English (on 2026-10-29 also `store.go:128`, `store.go:250`, `store_memory.go:292`, `sessions.go:822`, `sessions_options.go:40`). Comments only.

- [ ] **Step 1:** Rewrite each such sentence so its subject is the method that acts, as a doc link (`ErrReused is what [Sessions.Load] returns …`, after checking in `sessions.go` which methods return it), or "a [Sessions]" where no one method acts. A sentence that already reads as English ("Option configures the Sessions") may stay. No other wording changes, and no history wording.
- [ ] **Step 2: Verify.** `go doc ./session ErrReused` and `go doc ./session ErrRenewalRequired` read correctly; `gofmt -l session` prints nothing; `go vet ./session` is clean.

### Task 30: Layout guards (task 9.5, R6)

**Files:**
- Modify: `layout_test.go` (`TestBackendDoesNotShadowDriver`, `TestModulesDeclareGoMinimum`), `layout_guard_test.go` (`workspaceModules` at ~line 479, `belowGoMinimum` at ~line 657)
- Delete: `testdata/layout/noaliaspgx/`, `testdata/layout/noaliasgorm/`, `testdata/layout/noaliasredis/` (`git rm -r`)
- Root `go.mod` and `go.sum`: unchanged.

**Interfaces:**
- Consumes: `goCmd(t, dir, env, args...) string` (`layout_guard_test.go:258`), `packageClause(t, dir) string`, `goDirective(t, dir) string`.
- Produces: `offGoMinimum(t *testing.T, root string) map[string]string`, mapping each module directory whose `go` directive's `version.Lang` is not `go1.27` to the version it declares. `workspaceModules` keeps its signature.

- [ ] **Step 1: Write the failing test for `workspaceModules`.** `TestWorkspaceModulesReadsSingleLineUse`: a `t.TempDir()` holding `go.work` (`go 1.27`, `use ./a`, `use ( ./b )`) and a one-line `go.mod` in `a` and `b`; assert `assert.ElementsMatch(t, []string{"a", "b"}, workspaceModules(t, root))`.
- [ ] **Step 2: Run.** `go test -count=1 -run TestWorkspaceModulesReadsSingleLineUse .` Expected: FAIL, `"a"` missing. Record the line.
- [ ] **Step 3: Implement.** `workspaceModules` runs `go work edit -json <root>/go.work` and returns `filepath.Clean(u.DiskPath)` for each `Use` entry of the decoded `struct{ Use []struct{ DiskPath string } }`. Run Step 2's command, then `go test -count=1 -run 'TestGoWorkListsEveryModule|TestIntegrationModulesUnderTheirConcept|TestNoUnlistedIntegrationModule' .` Expected: PASS.
- [ ] **Step 4: Rewrite `TestBackendDoesNotShadowDriver`** as a table over `{backend dir, driver path}`: `store/pgxstore` with `github.com/jackc/pgx/v5`, `store/gormstore` with `gorm.io/gorm`, `ratelimit/redisstore` with `github.com/redis/go-redis/v9`. Each case asserts `assert.NotEqual(t, strings.TrimSpace(goCmd(t, dir, nil, "list", "-f", "{{.Name}}", driver)), packageClause(t, dir))`. The godoc says the names differ exactly when a file can import both without an alias. Delete the three fixture directories.
- [ ] **Step 5: Red for Step 4.** Change one case's assertion to `assert.Equal`, run `go test -count=1 -run TestBackendDoesNotShadowDriver .`, and see it FAIL naming `pgx` and `pgxstore` (or the row inverted); edit it back. Record the line.
- [ ] **Step 6: Rename.** `belowGoMinimum` becomes `offGoMinimum` with the signature above, and `TestModulesDeclareGoMinimum`'s cases assert `assert.Empty(t, off, "modules declaring another go version: %v", off)` and the matching control expectation. Run `go test -count=1 -run TestModulesDeclareGoMinimum .` Expected: PASS.
- [ ] **Step 7: Verify.** `go test -count=1 -run 'TestBackendDoesNotShadowDriver|TestWorkspaceModules|TestGoWorkListsEveryModule|TestIntegrationModulesUnderTheirConcept|TestNoUnlistedIntegrationModule|TestModulesDeclareGoMinimum' .` passes; `git diff --exit-code go.mod go.sum`. In a disposable export (`git archive HEAD` plus the working changes, outside the project), `GOFLAGS=-mod=mod go get golang.org/x/crypto@v0.58.0` at the root, then run the same layout tests. Expected: no failure.

### Task 31: Group-9 gate (task 9.7, main session)

- [ ] **Step 1:** Add the `merged` rows that Tasks 25 and 26 report to `evidence/rename-map.tsv`, each mapped to its `storekit` successor.
- [ ] **Step 2:** `make check`, `evidence/check.sh all` against the group-1 baseline, and `openspec validate restructure-layout --strict`. Expected: pass, 0 unaccounted, valid.
- [ ] **Step 3:** An Opus reviewer reads the P5 diff against D5 (and `txKey` still declared in each backend). A Sonnet reviewer reads the R5 and R6 diffs against D2, D8 and D11, with the recorded red-step lines. Expected: clean reports.
- [ ] **Step 4:** Commit (`fix: answer PR #27's second review: shared SQLSTATE and UPDATE helpers, layout guards and message texts`), push, and confirm CI green on the new head, including the Docker suites.

### Task 32: `test/oidc`'s client owns its transport (task 10.1, T1)

**Files:** Modify `test/oidc/idp_test.go` (`httpClient` at ~line 104, and the new test).

**Interfaces:**
- Produces: `httpClient(t *testing.T) *http.Client`, unchanged signature, now with `Transport` set to a clone of `http.DefaultTransport` whose `CloseIdleConnections` is registered with `t.Cleanup`. Jar and `CheckRedirect` stay as they are.

- [ ] **Step 1: Write the failing test** `TestHTTPClientKeepsItsConnectionsWhenAnotherServerCloses`:
  - `own := httptest.NewServer(<200 handler>)` and `other := httptest.NewServer(<200 handler>)`, each closed at `t.Cleanup`; `client := httpClient(t)`.
  - A `get` closure sends `GET own.URL` with `httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }})`, then reads the body to EOF and closes it, so the connection returns to the pool.
  - `get()`; `other.Close()`; `get()`; `assert.True(t, reused, "the second request to its own server opened a new connection after another server closed")`.
  - No `t.Parallel()`: the test must not depend on what other tests close.
  - `TestHTTPClientReleasesItsConnectionsWhenItsTestEnds`: one `own` server closed at the outer `t.Cleanup`; inside `t.Run("build", …)` set `client = httpClient(t)` (the subtest's `t`) and `get()`; after `t.Run` returns, `get()` again and `assert.False(t, reused, "the client kept a connection after the test that built it ended")`.
- [ ] **Step 2: Run.** `cd test && go test -count=1 -run 'TestHTTPClientKeepsItsConnectionsWhenAnotherServerCloses|TestHTTPClientReleasesItsConnectionsWhenItsTestEnds' ./oidc/`. Expected: FAIL on both messages. Record the lines.
- [ ] **Step 3: Implement** the transport in `httpClient` as in Interfaces.
- [ ] **Step 4: Verify.** Step 2's command passes; `cd test && go test -count=1 -race ./oidc/` passes; `go test -count=20 -run TestTestIdentityProviderMalformedTokens ./oidc/` passes; `gofmt -l oidc` prints nothing.

### Task 33: The root test package's clients own their transport (task 10.2, T2)

**Files:**
- Modify: `test/testutils.go` (new helpers; `SMTPConn` gains an unexported field; `SMTPConn.get` at ~line 276; the SMTP helper's `return SMTPConn{…}` at ~line 217), `test/oidc_keycloak_test.go` (`keycloakBrowser` at ~line 231)
- Create: `test/testutils_http_test.go`
- Not owned: `test/oidc/` (Task 32).

**Interfaces:**
- Produces, in `test/testutils.go`:
  - `ownTransport(t *testing.T) *http.Transport`: `http.DefaultTransport.(*http.Transport).Clone()`, with its `CloseIdleConnections` registered at `t.Cleanup`.
  - `smtpAPIClient(t *testing.T) *http.Client`: `&http.Client{Transport: ownTransport(t)}`.
  - `SMTPConn` field `client *http.Client`, set by the SMTP helper from `smtpAPIClient(t)`; `SMTPConn.get` sends through `c.client`.
- `keycloakBrowser` keeps its signature, jar, timeout and `CheckRedirect`, and sets `Transport: ownTransport(t)`.
- The `KeycloakConn` clients built over the container's own TLS transport (~lines 1195–1285) already own a transport and are not changed.

- [ ] **Step 1: Stub** `smtpAPIClient` returning `http.DefaultClient`, so the test compiles and fails on behaviour.
- [ ] **Step 2: Write the failing table** `TestHTTPClientsKeepTheirConnectionsWhenAnotherServerCloses` in `test/testutils_http_test.go`, in the `table-test` form: cases `"keycloak browser"` (`client: keycloakBrowser`) and `"smtp message API"` (`client: smtpAPIClient`), each running Task 32's Step 1 sequence with the constructor under test, and asserting with the same message. `TestHTTPClientsReleaseTheirConnectionsWhenTheirTestEnds` is the same table over Task 32's cleanup check. No `t.Parallel()`.
- [ ] **Step 3: Run.** `cd test && go test -count=1 -run 'TestHTTPClientsKeepTheirConnectionsWhenAnotherServerCloses|TestHTTPClientsReleaseTheirConnectionsWhenTheirTestEnds' .`. Expected: FAIL in every case. Record the lines.
- [ ] **Step 4: Implement** the Interfaces above: `ownTransport`, the real `smtpAPIClient`, the `SMTPConn` field and `get`, and `keycloakBrowser`'s transport.
- [ ] **Step 5: Verify.** Step 3's command passes; `cd test && go test -count=1 -race -run 'TestHTTPClients|SMTP' .` passes with Docker; `rg -n 'http\.Default(Client|Transport)' test --glob '*.go'` finds only `ownTransport` and Task 32's `httpClient`; `go vet ./...` and `gofmt -l .` in `test` are clean.

### Task 34: Group-10 gate (task 10.3, main session)

- [ ] **Step 1:** `make check`, `evidence/check.sh all` against the group-1 baseline, and `openspec validate restructure-layout --strict`. Expected: pass, 0 unaccounted (the new tests and helpers appear only as additions), valid.
- [ ] **Step 2:** A Sonnet reviewer reads the T1 and T2 diffs against D14 and the `test-provisioning` delta, with the recorded red-step lines. Expected: a clean report.
- [ ] **Step 3:** Commit (`test: give the test module's HTTP clients a transport of their own`), push, and confirm CI green on the new head, including the Docker suites.

### Task 35: Lockout bound names (task 11.1, N1)

**Files:** every file that references a renamed identifier, across all modules (gopls finds them). Declarations live in `policy/lockout/lockout_options.go`, `policy/lockout/lockout.go`, `policy/lockout/attempts.go` and the report-kind file.

**Interfaces:**
- Produces, in `lockout`: `WithFailureStreakLimit(n int) Option`, `const NISTFailureStreakLimit = 100`, `WithFailureStreakRetention(d time.Duration) Option`, `(*Policy).FailureStreakLimit() int`, `(*Policy).FailureStreakRetention() time.Duration`, `WithWindowFailureLimit(n int) Option`, `ReportAtWindowFailureLimit ReportKind`, `WithWaitThreshold(n int) Option`, `(*Policy).WaitThreshold() int`, `WithFailureWindow(d time.Duration) Option`, `(*Policy).FailureWindow() time.Duration`, `WithAttemptStoreMaxIdentifiers(n int) MemoryAttemptOption`. Signatures are unchanged; only names change.

- [ ] **Step 1:** For each pair in D15's `lockout` rows, run `gopls rename -w <file>:#<offset> <NewName>` from the workspace root, so every module is updated.
- [ ] **Step 2:** Change the error strings that name a renamed option to the new name (`"WithFailureStreakLimit must be positive"`, and the same pattern for each), and update the tests that assert those exact texts.
- [ ] **Step 3:** In the godoc of `WithFailureStreakLimit` and `NISTFailureStreakLimit`, name the quantity as NIST SP 800-63B-4 §3.2.2 does: "consecutive failed authentication attempts". Keep each option's "The default is …" sentence.
- [ ] **Step 4: Verify.** `go build ./... && go vet ./...` in the core module and every nested module; `go test -count=1 -race ./policy/... ./httpsec/...`; `cd test && go vet ./... && go test -list . ./httpsecconformance/...` lists the same names as before. Expected: all pass, and the list is unchanged.

### Task 36: The other bound names (task 11.2, N1)

**Files:** as Task 35, for the packages in D15's other rows.

**Interfaces:**
- Produces: `passkey.WithPerUserLimit`, `passkey.ErrPerUserLimitReached`, `recovery.WithHoldDelay`, `recovery.WithHoldCompletionWindow`, `recovery.WithPendingSessionLifetime`, `recovery.RemainingCodes`, `token.WithTokenLifetime`, `signingkey.WithKeyLifetime`, `signingkey.WithLogInterval`, `onetime.WithTokenTTL`, `(*onetime.Tokens).TokenTTL`, `(*policy.IdleTimeout).Deadlines`, `mfa.WithTimeStep`, `oidc.LongestLogoutTokenMaxAge`, `notify.WithQueueMaxMessages`, `(*notify.QueuedSender).QueueMaxMessages`, `httpsec.WithEnrolmentSessionLifetime`. Signatures are unchanged.
- Untouched: `session.WithIdleTimeout`, `session.WithAbsoluteTimeout`, `session.WithAbsoluteLifetime`, `session.WithMaxAbsoluteLifetime`, `policy.WithIdleAbsoluteTimeout`.

- [ ] **Step 1:** Rename each with `gopls rename`, as in Task 35. `signingkey.WithLogSampleWindow` → `WithLogInterval`: confirm with `go doc ./token/signingkey` that no other `WithLogInterval` exists in the package first.
- [ ] **Step 2:** Update the error strings and log messages that name a renamed identifier, and the tests asserting them.
- [ ] **Step 3: Verify.** As Task 35, with `go test -count=1 -race ./...` in the core module. Expected: all pass.

### Task 37: Text sweep for the bound names (task 11.3, N1)

- [ ] **Step 1:** For every old name of Tasks 35–36, run `rg -n '\b<old>\b' -g '!.claude/.legacy'` over the whole repository.
- [ ] **Step 2:** Fix each hit in Go comments, godoc, README, strings and `%T`/`reflect` output. Leave D13-frozen test function names. List every hit under `openspec/` in the report, unedited.
- [ ] **Step 3: Verify.** Rerun Step 1. Expected: only frozen test names and the hits under `openspec/` that were reported.

### Task 38: Rename map and group-11 gate (tasks 11.4–11.5, main session)

- [ ] **Step 1:** Add an `ident` row per rename to `evidence/rename-map.tsv`. Where a row already maps a baseline name to an interim name (`WithLockoutCap` → `WithCap`, `NISTLockoutCap` → `NISTCap`, `LockoutAtCeiling` → `ReportAtCeiling`, `WithPasskeyLimit` → `WithLimit`), change its new column to the D15 name.
- [ ] **Step 2:** `evidence/check.sh all && make check && openspec validate restructure-layout --strict`. Expected: 0 unaccounted, pass, valid.
- [ ] **Step 3:** A Sonnet reviewer checks the N1 diff against D15: every row landed, nothing else was renamed, and godoc still names each default. Expected: clean.
- [ ] **Step 4:** Commit (`refactor!: name every bound after what it bounds`), push, and confirm CI green, including the Docker suites.

### Task 39: `storekit` column constructors and the `WithUserRoles` godoc (tasks 12.1–12.2, S1)

**Files:**
- Modify: `internal/storekit/storekit.go` (`Column`, `UserColumns`, `UpdateUserQuery`), `internal/storekit/storekit_test.go`, `store/sqlstore/identity.go` and `store/pgxstore/identity.go` (the role column literal), `identity/ports.go` (`WithUserRoles` godoc).

**Interfaces:**
- Produces: `type Column struct{ name string; value any }`, with no exported field; `func RoleColumn(value any) Column`, whose column name is `role`. `UserColumns` and `UpdateUserQuery` keep their signatures.

- [ ] **Step 1: Stub** `func RoleColumn(value any) Column { return Column{} }`.
- [ ] **Step 2: Write the failing tests.**
  - `TestColumnExportsNoField`: `typ := reflect.TypeFor[Column]()`; for each field, `assert.False(t, typ.Field(i).IsExported(), "storekit.Column exports %s, so a caller can put any text into the SQL", typ.Field(i).Name)`.
  - A `TestUpdateUserQuery` case `"role column"`: `UpdateUserQuery([]Column{RoleColumn("admin")}, now, 7)` returns exactly `"UPDATE users SET role = $1, updated_at = $2 WHERE id = $3"` and the args `[]any{"admin", now, 7}`.
- [ ] **Step 3: Run.** `go test -count=1 -run 'TestColumnExportsNoField|TestUpdateUserQuery' ./internal/storekit/`. Expected: FAIL on `Name` exported, and on the role-column text. Record the lines.
- [ ] **Step 4: Implement** the unexported fields and `RoleColumn`. Change both backends' `storekit.Column{Name: "role", …}` to `storekit.RoleColumn(…)`.
- [ ] **Step 5: Rewrite** the `WithUserRoles` godoc: the first name is the primary role; on `Update`, naming no usable role leaves every stored grant and the primary role untouched, so a filtered claim cannot strip a user's access; on `Provision`, it creates a user with no roles.
- [ ] **Step 6: Verify.** Step 3's command passes; `go test -count=1 -race ./internal/storekit/`; `go test ./...` in the core module and `store/pgxstore`; `rg 'storekit\.Column\{' -g '!.claude/.legacy'` finds nothing; `go doc ./identity WithUserRoles` reads as Step 5.

### Task 40: Group-12 gate (task 12.3, main session)

- [ ] **Step 1:** Extend `evidence/check.py` to accept `added` and `changed` rows (D13, phase 6). Add `changed` rows for `Column.Name`/`Column.Value` and an `added` row for `RoleColumn`.
- [ ] **Step 2:** `evidence/check.sh all && make check && openspec validate restructure-layout --strict`. Expected: 0 unaccounted.
- [ ] **Step 3:** A Sonnet review against D16. Then commit (`fix: build SQL column names only inside storekit`), push, and CI green including the identity-store conformance suites.

### Task 41: `authenticate.ErrUnavailable` (task 13.1, U1)

**Files:** Modify `authenticate/authenticate.go` (sentinels), `authenticate/password.go`, and the password authenticator's test file.

**Interfaces:**
- Produces: `var ErrUnavailable = errors.New("authenticate: the user store is unavailable")`. The password authenticator returns an error for which `errors.Is(err, ErrUnavailable)` is true and `errors.Is(err, ErrAuthenticationFailed)` is false, whenever `LoadByUsername` fails with an error that is not `identity.ErrUserNotFound`. Its message carries no driver text.

- [ ] **Step 1: Declare** `ErrUnavailable` only.
- [ ] **Step 2: Change** the load-failure case of `TestPasswordAuthenticatorDoesNotRevealWhyItFailed` to assert `ErrorIs(err, ErrUnavailable)`, `NotErrorIs(err, ErrAuthenticationFailed)`, and that `err.Error()` does not contain the loader's error text. Add the case `"a load failure spends the unknown-user password work"`: the encoder double records one `Match` against the dummy hash, exactly as the unknown-username case does.
- [ ] **Step 3: Run.** `go test -count=1 -run TestPasswordAuthenticatorDoesNotRevealWhyItFailed ./authenticate/`. Expected: FAIL, because `ErrAuthenticationFailed` is returned. Record the lines.
- [ ] **Step 4: Implement** the return in `password.go`, after the dummy `Match` and the error-level log record.
- [ ] **Step 5: Verify.** `go test -count=1 -race ./authenticate/...`. Expected: PASS, with the log assertion unchanged.

### Task 42: 503 for `ErrUnavailable` (task 13.2, U1)

**Files:** Modify `httpsec/errors.go` (the public status table) and `httpsec/errors_test.go`. Test only: `httpsec/ginsec` and `httpsec/fibersec` (Review Focus 6).

- [ ] **Step 1: Write** a `StatusForError` table case `"user store unavailable"`: `fmt.Errorf("login: %w", authenticate.ErrUnavailable)` → `http.StatusServiceUnavailable`. Add one case in each adapter's error-response test, asserting a guard that returns `ErrUnavailable` answers 503.
- [ ] **Step 2: Run.** `go test -count=1 -run 'TestStatusForError' ./httpsec/`. Expected: FAIL with 500, and `TestStatusForErrorCoversEverySentinel` fails on the unregistered sentinel. Record the lines.
- [ ] **Step 3: Implement** the row: `authenticate.ErrUnavailable` → 503, placed before the `ErrAuthenticationFailed` row.
- [ ] **Step 4: Verify.** `go test -count=1 -race ./httpsec/` and the adapters' tests (`cd httpsec/ginsec && go test ./...`, likewise `fibersec`). Expected: PASS.

### Task 43: Form login and Basic do not count an outage (task 13.3, U1)

**Files:** Modify `httpsec/basic.go` and `httpsec/login.go`. Create `httpsec/password_outage_test.go`.

**Interfaces:**
- Consumes: `authenticate.ErrUnavailable` (Task 41); `lockout.WithFailureStreakLimit` (Task 35).

- [ ] **Step 1: Write** `TestPasswordLoginStoreOutageIsNotACredentialFailure`, a table over `"basic"` and `"form login"`. Each row:
  - uses a mock `identity.UserLoader` that returns a connection error for three requests, then the real user;
  - uses `lockout.New(lockout.WithWaitThreshold(2), lockout.WithWait(time.Nanosecond, time.Nanosecond), lockout.WithFailureStreakLimit(3))`, with the policy's attempt view as the endpoint's store;
  - asserts each outage response is 503; `FailureCount` for the username is 0; the source guard's limiter received no `RecordFailure` (mock expectation); and a final request with the correct password succeeds.
  - The Basic row also asserts no `WWW-Authenticate` header on the outage responses.
- [ ] **Step 2: Run.** `go test -count=1 -run TestPasswordLoginStoreOutageIsNotACredentialFailure ./httpsec/`. Expected: FAIL. Record the lines.
- [ ] **Step 3: Implement.** In both endpoints, an authentication error matching `authenticate.ErrUnavailable` returns at once with that error. It does not record, count or clear anything, and sets no challenge header.
- [ ] **Step 4: Verify.** `go test -count=1 -race ./httpsec/...`. Expected: PASS. `httpsecconformance` is left to CI.

### Task 43a: Recovery's password proof does not count an outage (task 13.4, U2, after Task 43)

**Files:** Modify `recovery/recover.go` (the password-proof refusal near `r.refuse(ctx, v.user, err, true)`) and its tests; `httpsec/recovery.go` (`countsAgainstRecoverySource`, where the endpoint counts unmarked failures against the source) and `httpsec/recovery_test.go`; `httpsec/recovery_options.go` and `httpsec/login_options.go` (godoc).

**Interfaces:**
- Consumes: `authenticate.ErrUnavailable` (Task 41).
- Produces: no new API. A password check returning an error that matches `authenticate.ErrUnavailable` makes `Recover` return that error without counting anything against the user or the source.

- [ ] **Step 1: Write** a table case `"an unavailable user store is not a failed proof"` in the recovery tests. A password check returns `authenticate.ErrUnavailable`. Assert `ErrorIs(err, authenticate.ErrUnavailable)`, and that the user limiter and the source guard record no failure (mock expectations or counters, as the existing recovery tests observe counting). Where an HTTP-level recovery test exists, also assert 503.
- [ ] **Step 2: Run** it. Expected: FAIL, because the outage is counted. Record the lines.
- [ ] **Step 3: Implement.** Return an `ErrUnavailable` error from the password proof before `refuse` counts it.
- [ ] **Step 4: Godoc.** `EnableFormLogin`'s step-4 text says an unavailable user store is refused with 503 and counted nowhere.
- [ ] **Step 5: Verify.** `go test -count=1 -race ./recovery/... ./httpsec/...` passes; `cd test && go test -count=1 -run 'Recover' .` with Docker.

### Task 43b: Fold the U-lane review (task 13.5, U3, after Task 43a)

**Files:** `authenticate/password.go` and its tests, `httpsec/password_outage_test.go`, `httpsec/basic.go` (godoc reflow), `httpsec/recovery.go` (godoc of `countsAgainstRecoverySource`).

- [ ] **Step 1: Write** the cancelled-context cases: the loader fails with the request context's own error after it was cancelled. Expect `ErrAuthenticationFailed`, not `ErrUnavailable`, at the provider; at the endpoints expect 401, one source charge and one recorded failure. Tighten the load-failure case to `assert.Same`/`Equal(t, authenticate.ErrUnavailable, err)`.
- [ ] **Step 2: Run.** Expected: FAIL with `ErrUnavailable` returned. Record the lines.
- [ ] **Step 3: Implement.** In the provider, when `ctx.Err() != nil` and `errors.Is(loadErr, ctx.Err())`, take the uniform-failure path. Fix the two godoc items.
- [ ] **Step 4: Verify.** `go test -count=1 -race ./authenticate/... ./httpsec/... ./recovery/...`.

### Task 44: Group-13 gate (task 13.6, main session)

- [ ] **Step 1:** Add an `added` row for `ErrUnavailable`, and list Task 41's changed case for the assertion review. Run `evidence/check.sh all && make check && openspec validate restructure-layout --strict`.
- [ ] **Step 2:** An Opus review of the U1 and U2 diffs against D19 and the `authentication`, `http-error-propagation`, `http-security-chain` and `account-recovery` deltas, with the recorded red lines. Then commit (`fix!: a user-store outage is unavailable, not a failed login`), push, and CI green.

### Task 45: API key owners (tasks 14.1–14.2, K1, after Task 44)

**Files:** Modify `httpsec/apikey.go`. Test in `httpsec/apikey_test.go`, or `httpsec/apikey_owner_test.go` if the existing table's setup differs.

**Interfaces:**
- Consumes: `authenticate.ErrUnavailable`; `identity.UserLoader.LoadByUserID`.
- Produces: `func WithAPIKeyOwners(users identity.UserLoader) APIKeyOption`. A nil `users` makes `New` fail with an error wrapping the chain's configuration sentinel.

- [ ] **Step 1: Declare** `WithAPIKeyOwners` as a no-op that rejects nothing.
- [ ] **Step 2: Write** `TestAPIKeyOwners`, a table over:
  - `"no loader looks nothing up"`: authenticated; the loader mock has no expectation;
  - `"inactive owner"`: 401, the same error as a wrong key, and one `RecordFailure` on the source limiter;
  - `"missing owner"`: `ErrUserNotFound`, then the same as inactive;
  - `"active owner"`: authenticated, principal `Kind` is service, with the key's reference;
  - `"loader outage"`: `errors.Is(err, authenticate.ErrUnavailable)`, 503, no `RecordFailure`;
  - `"nil loader"`: `New` returns an error.
- [ ] **Step 3: Run.** `go test -count=1 -run TestAPIKeyOwners ./httpsec/`. Expected: FAIL on the inactive, missing, outage and nil rows. Record the lines.
- [ ] **Step 4: Implement** the lookup after `Verify` succeeds and before the stateless phase.
- [ ] **Step 5: Godoc.** `EnableAPIKey` says that without `WithAPIKeyOwners` no owner is looked up, so deactivating a user stops none of that reference's keys. `WithAPIKeyOwners` names the default it replaces ("no lookup").
- [ ] **Step 6: Verify.** `go test -count=1 -race ./httpsec/...`. Expected: PASS.

### Task 46: Group-14 gate (task 14.3, main session)

- [ ] As Task 44, with `WithAPIKeyOwners` as an `added` row, an Opus review against D17 and the `api-keys` delta, and the commit `feat(httpsec): an API key can require an active owner`.

### Task 47: Verifier construction requires issuer and audience (task 15.1, V1)

**Files:** Modify `token/verifier.go` and `token/config.go`. Create `token/verifier_claims_required_test.go`.

**Interfaces:**
- Produces: `func WithoutVerifyIssuer() VerifyOption` and `func WithoutVerifyAudience() VerifyOption`. `NewVerifier` returns an error wrapping `ErrConfig` when, for either claim, the verifier has neither the `WithVerify…` option nor the waiver, or has both.

- [ ] **Step 1: Declare** both waivers as no-ops.
- [ ] **Step 2: Write** `TestNewVerifierRequiresIssuerAndAudience`, a table built on a real `signingkey.Keys`:
  - `"neither issuer nor waiver"` → `ErrorIs(err, ErrConfig)`;
  - `"neither audience nor waiver"` → `ErrConfig`;
  - `"issuer and its waiver"` → `ErrConfig`;
  - `"audience and its waiver"` → `ErrConfig`;
  - `"waived issuer accepts any iss"`: verifies a token with `iss` `https://other.example`;
  - `"token for another service"`: a generator with `WithAudience("service-a")`, a verifier with `WithVerifyAudience("service-b")` and `WithoutVerifyIssuer()`, gives `ErrorIs(err, ErrInvalid)`.
- [ ] **Step 3: Run.** `go test -count=1 -run TestNewVerifierRequiresIssuerAndAudience ./token/`. Expected: FAIL on the four construction rows. Record the lines.
- [ ] **Step 4: Implement** the construction checks.
- [ ] **Step 5: Verify.** Step 3's command passes. The rest of `./token/` is now expected to fail until Task 48.

### Task 48: Existing verifier tests and the `token` docs (tasks 15.2–15.3, V1)

**Files:** Modify `token/verifier_test.go`, `token/generator_test.go`, `token/signingkey/keys_lifecycle_test.go`, `token/doc.go`, and the godoc in `token/verifier.go`.

- [ ] **Step 1:** In each failing test (the 11 in `token` and `TestRestartedManager`), add the configured claim where the test is about it, and otherwise `WithoutVerifyIssuer()` and `WithoutVerifyAudience()`. Change no assertion.
- [ ] **Step 2:** Rewrite the package doc and the godoc of `NewVerifier`, `WithVerifyIssuer` and `WithVerifyAudience`. Construction now refuses an unconfigured issuer or audience. Each waiver says what it gives up: any token signed by a key in the source is accepted whatever its issuer, or audience.
- [ ] **Step 3: Verify.** `go test -count=1 -race ./token/...` passes; `rg -n 'NewVerifier\(' -g '!.claude/.legacy' -g '!openspec/**'` shows both claims configured or waived at every call; `go doc -all ./token | rg 'exactly when the consumer configured'` finds nothing.

### Task 48a: The generator follows the same rule (task 15.4, V2, after Task 48)

**Files:** Modify `token/generator.go` and `token/config.go`, `token/generator_test.go` and the other `token/**` tests that call `NewGenerator`, `test/oidc/idp_test.go`, `test/oidc_keycloak_test.go`, and README examples that build a generator. Create `token/generator_claims_required_test.go`.

**Interfaces:**
- Consumes: Task 47's waived-claim configuration and its construction check.
- Produces: `func WithoutIssuer() Option` and `func WithoutAudience() Option`. `NewGenerator` returns an error wrapping `ErrConfig` when, for either claim, it has neither `WithIssuer`/`WithAudience` nor the waiver, or has both. A waived claim is neither minted nor checked by the generator's own `Verify`.

- [ ] **Step 1: Declare** both waivers as no-ops.
- [ ] **Step 2: Write** `TestNewGeneratorRequiresIssuerAndAudience`, a table built on a real `signingkey.Keys`:
  - `"neither issuer nor waiver"` → `ErrConfig`;
  - `"neither audience nor waiver"` → `ErrConfig`;
  - `"issuer and its waiver"` → `ErrConfig`;
  - `"audience and its waiver"` → `ErrConfig`;
  - `"two services sharing a key source"`: generator B (`WithAudience("service-b")`, `WithIssuer("https://b.example")`) rejects a token from generator A (`WithAudience("service-a")`, same issuer) with `ErrInvalid`;
  - `"waived on purpose"`: a generator with both waivers issues a token with no `iss` and no `aud`, and verifies it.
- [ ] **Step 3: Run.** `go test -count=1 -run TestNewGeneratorRequiresIssuerAndAudience ./token/`. Expected: FAIL on the four construction rows. Record the lines.
- [ ] **Step 4: Implement** the check in `NewGenerator`, reusing Task 47's claim rule.
- [ ] **Step 5: Update callers.** Each `NewGenerator` call lacking a claim gains the configured value where the test is about it, otherwise the waiver: the token tests, the two test-module IdP helpers, README. Change no other assertion. Update `NewGenerator`'s godoc defaults sentence ("no issuer; no audience" becomes a refusal), and the `Generator` godoc.
- [ ] **Step 6: Verify.** `go test -count=1 -race ./token/...`; `go build ./... && go vet ./...` in every module; `cd test && go test -count=1 ./oidc/` with Docker; `rg -n 'NewGenerator\(' -g '!.claude/**' -g '!openspec/**'` shows both claims configured or waived at every call.

### Task 48b: Empty claims are refused (task 15.5, V3, after Task 48a)

**Files:** `token/config.go`, `token/verifier_claims_required_test.go`, `token/generator_claims_required_test.go`, `token/verifier_test.go` (the rows pinning an enforced empty value), and the godoc of the four configure options.

- [ ] **Step 1: Write** the refusal rows for `WithIssuer("")`, `WithAudience("")`, `WithVerifyIssuer("")` and `WithVerifyAudience("")`, each expecting `ErrConfig`. Add the row in which a generator that waived both claims verifies a token carrying `iss` `https://other.example` and `aud` `other`.
- [ ] **Step 2: Run.** Expected: FAIL on the empty rows. Record the lines.
- [ ] **Step 3: Implement** the refusal in `validateClaims`. Turn the base "configured as the empty string is still enforced" rows into refusal rows. Each configure option's godoc says an empty value is refused and names the waiver.
- [ ] **Step 4: Verify.** `go test -count=1 -race ./token/...`; `go vet ./...` in every module.

### Task 49: Group-15 gate (task 15.6, main session)

- [ ] As Task 44, with the four waivers as `added` rows, the changed tests of Tasks 48 and 48a listed for the assertion review, an Opus review of V1 and V2 against D18 and the `token-issuance` delta, and the commit `fix(token)!: verifiers and generators require an issuer and an audience, or a waiver`.

### Task 50: `Charger` and the in-memory charge (task 16.1, L1)

**Files:** Create `ratelimit/charge.go`. Modify `ratelimit/memory.go`, `test/ratelimittest/suite.go`, `test/ratelimittest/broken_test.go` and `test/ratelimittest/memory_test.go`.

**Interfaces:**
- Produces, in `ratelimit`:
  - `type Receipt struct{ key string; stamp time.Time }`, with no exported field, built by `func NewReceipt(key string, stamp time.Time) Receipt` and read through `(Receipt).Key() string` and `(Receipt).Stamp() time.Time`, so the shared limiters in other packages can issue and redeem one;
  - `type Charger interface { Charge(ctx context.Context, key string) (r Receipt, exceeded bool, err error); Refund(ctx context.Context, r Receipt) error }`;
  - `*MemoryLimiter` implements `Charger`.
- `Charge` on an at-limit key returns `exceeded=true` and records nothing. On an error it returns `exceeded=true` with the error, matching `Exceeded`'s fail-closed habit.
- `Refund` removes one stamp equal to `r.stamp` from `r.key`, if one is still in the window. A zero `Receipt` is a no-op.

- [ ] **Step 1: Write** the conformance cases in the suite, run for any `Charger`:
  - `"concurrent charges stop at the limit"`: 64 goroutines released by one barrier charge one key against a limit of 5, and exactly 5 report `exceeded=false`;
  - `"refund returns the allowance"`: 4 charges, a 5th, refund the 5th, and the next charge is below the limit;
  - `"refund removes only its own failure"`: 2 charges at the same instant on a fixed clock, refund one, and the next 4 charges succeed, the 5th does not, under a limit of 5;
  - `"refund after the window removes nothing"`.
- [ ] **Step 2: Run them against a broken `Charger`** in `broken_test.go`, whose `Charge` calls `Exceeded`, yields (`runtime.Gosched()`), then `RecordFailure`. Expected: the concurrent case FAILS. Record the lines.
- [ ] **Step 3: Run them against `*MemoryLimiter`** with stub methods returning zero values. Expected: FAIL. Record the lines.
- [ ] **Step 4: Implement** both methods under the limiter's existing lock.
- [ ] **Step 5: Verify.** `go test -count=50 -race -run Charge ./ratelimit/... ` and `cd test && go test -count=1 -race ./ratelimittest/`. Expected: PASS, while the broken `Charger` still fails the concurrent case.

### Task 51: Atomic charge on the shared limiters (task 16.2, L2, after Task 50)

**Files:** Modify `internal/pglimiter` (backend and statements), `store/sqlstore/limiter.go` and `store/pgxstore/limiter.go` (their runners), `ratelimit/redisstore/limiter.go` (a Lua script), `internal/unavailable/wrap.go`, and the test module's shared-limiter suites.

**Interfaces:**
- Consumes: `ratelimit.Charger`, `ratelimit.Receipt`, `ratelimit.NewReceipt` and its accessors (Task 50).
- Produces: `Charger` on the `pglimiter` backend, the `redisstore` limiter, and the `unavailable` decorator.

- [ ] **Step 1: Stub** `Charge`/`Refund` on each, returning zero values, and run Task 50's conformance cases against each. Expected: FAIL. Record the lines.
- [ ] **Step 2: `pglimiter`.** One statement charges: `UPDATE rate_limit_buckets SET stamps = <in-window stamps> || $now … WHERE namespace = $1 AND key = $2 AND cardinality(<in-window stamps>) < $limit RETURNING …`. For a key with no row, use `INSERT … ON CONFLICT DO UPDATE … WHERE` with the same condition. Time comes from the database, as the limiter's existing statements take it. Refund removes one element equal to the receipt's stamp with `array_remove` limited to one occurrence. No migration.
- [ ] **Step 3: `redisstore`.** One `EVAL` script trims the window, compares the count with the limit, and adds the stamp only below it. Refund is one script removing one member equal to the stamp.
- [ ] **Step 4: `unavailable`.** Pass both through while the backend answers. When degraded to a local fallback, charge and refund the fallback; when failing closed, `Charge` returns `exceeded=true` with the unavailable error. Add a test for each degraded mode (Review Focus 7).
- [ ] **Step 5: Verify.** `go test -count=1 -race ./...` in the core module, `ratelimit/redisstore`, `store/sqlstore` and `store/pgxstore`; `cd test && go test -count=1 -race ./ratelimittest/ ./sqlstore/ ./pgxstore/` with Docker; `git diff --stat store/migrate` empty.

### Task 52: Widen the port, and recovery charges first (task 16.3, L3, after Tasks 51 and 45)

**Files:** Modify `ratelimit/limiter.go`, `recovery/codes.go`, `test/ratelimittest/doubles_test.go` and `test/pg_ratelimit_fault_test.go`. Regenerate every `limiter_mock_test.go` with `go generate`. Create `recovery/codes_burst_test.go`.

**Interfaces:**
- Produces: `type Limiter interface { Exceeded(…); RecordFailure(…); Charger }`, whose godoc states that `Charge` must be atomic and that the conformance suite proves it.
- `recovery.Codes` charges with `context.WithoutCancel(ctx)` before `Match`, refunds after a valid match, and no longer calls `Exceeded` or `RecordFailure` on the presentation path.

- [ ] **Step 1: Widen** `Limiter`, regenerate the mocks, and add both methods to the two hand-written doubles. Verify `go build ./...` and `go vet ./...` in every module.
- [ ] **Step 2: Write** `TestCodes_ConcurrentWrongCodesStayWithinLimit` in the `table-test` form. A test-local decorator over the memory limiter holds every caller at a barrier after its limit decision; a counting decorator over the memory code store counts `Match`. 20 distinct, well-formed wrong codes go through `Confirm` under the default 5 per 15 minutes, asserting `LessOrEqual(t, matches, 5)`. Add case `"a valid code spends no allowance"`: one valid code, then 4 wrong ones, and a 5th wrong code is still looked up.
- [ ] **Step 3: Run.** `go test -count=20 -race -run TestCodes_ConcurrentWrongCodesStayWithinLimit ./recovery/`. Expected: FAIL every run, with `"20" is not less than or equal to "5"`. Record the lines.
- [ ] **Step 4: Implement** `Codes`' charge-before-match and refund-on-success.
- [ ] **Step 5: Verify.** `go test -count=100 -race -run TestCodes_ConcurrentWrongCodesStayWithinLimit ./recovery/` passes every run; `go test -count=1 -race ./...` in the core and every nested module; `go generate ./... && git status --porcelain` shows only this task's files.

### Task 53: Group-16 gate (task 16.4, main session)

- [ ] As Task 44, with `Receipt`, `NewReceipt`, its accessors, `Charger` and each limiter's two methods as `added` rows. An Opus review of L1–L3 against D20 and the `rate-limiting` and `account-recovery` deltas covers refund precision, the decorator's degraded paths, and the conditional statement under PostgreSQL's default isolation. Commit `fix(recovery)!: saved codes hold their limit under concurrency`.

### Task 54: Active changes and the whole-branch gate (tasks 17.1–17.2, main session)

- [ ] **Step 1:** Update the old names Task 37 reported, and the artifacts of `idiomatic-api-shape`, `key-port-context` and `trusted-proxy-client-ip` that name a renamed identifier or a changed default. Run `openspec validate --all --strict`. Expected: valid.
- [ ] **Step 2:** `make check && evidence/check.sh all && openspec validate restructure-layout --strict`, push, and confirm CI green, including the Docker suites.
- [ ] **Step 3:** One Opus whole-branch review against every requirement in the change's nine deltas. Every claimed defect carries a failing test or `UNREPRODUCED`. Expected: clean.
