# Tasks

Test-first applies to every task that adds or changes behaviour that a test can observe: the new layout requirement (group 2) and the table conversions (group 4). Moves and renames that the existing tests already cover are exempt, as `golang-tdd.md` allows. They are verified instead by the D13 checks at the end of each group.

## 1. Baseline and evidence

- [x] 1.1 Start a fresh working branch from an up-to-date `main`, which already has `fix/stabilize-intermittent-tests` merged and archived. Confirm that no other change is being implemented on another branch. Verify: `openspec list` no longer shows `stabilize-intermittent-tests`, and `make check` passes locally (everything but the Docker suites).
- [x] 1.2 Confirm the `apidiff` invocation: install it in a scratch location, and run it once on an unchanged package against itself. Verify: the command and its empty report are recorded in `evidence/README.md`. This settles the invocation that `design.md` (D13) left to implementation.
- [x] 1.3 Capture the D13 baseline into `evidence/baseline/`:
  - the test and subtest inventory, with results, from `go test -json` over the core and nested modules;
  - `go test -list` output for the test module;
  - per-package coverage;
  - per-package API export data;
  - the declaration inventory of D13: every top-level declaration, exported or not, in every non-generated production file, with its package and kind, and every `//go:embed` pattern.

  Verify: each file exists, and its counts are recorded in `evidence/README.md`.
- [x] 1.4 Write `evidence/rename-map.tsv`, mapping every old import path and exported identifier to its new one, from `design.md` D1, D3 and D8–D10. Write `evidence/check.sh`, which compares a fresh inventory with the baseline through the map, for tests, API, declarations and coverage. The only absences it allows are the D5 copies, each mapped to its `storekit` successor. Verify: `check.sh` against the unchanged tree reports no difference, and it reports a declaration deleted from a scratch copy of one file, which is then restored by editing.

## 2. Phase 1: module and directory moves (D1–D4)

- [x] 2.1 Red: add the root layout tests for "Integration modules are published under the concept they extend". They cover:
  - the seven module paths;
  - package names equal to the last path element;
  - exhaustiveness: every workspace module other than `test` and `tools` is one of the seven, and an unlisted module fails by its directory. A control case checks this against a fixture workspace that has an extra module;
  - three compiled fixtures, each importing a backend with its driver and no alias: `store/pgxstore` with `github.com/jackc/pgx/v5`, `store/gormstore` with `gorm.io/gorm`, and `ratelimit/redisstore` with `github.com/redis/go-redis/v9`.

  Add `TestModulesDeclareGoMinimum` for "Supported Go releases": every module in the workspace, and `tools`, declares language version 1.27 in its `go` directive. It compares `go/version.Lang` values, because `tools/go.mod` writes it as `go 1.27.0`. It pins what the code already does, so its red step is an inverted expectation.

  Add a case to `TestCoreDependencies` for a major-version path of a listed module that is not covered yet: `github.com/jackc/pgx/v5`. Point the existing WebAuthn layout tests at `authenticate/passkey/webauthn`. Verify: `go test -run 'TestIntegrationModule|TestWebAuthn|TestSoftwareAuthenticator' -count=1 .` fails because the modules are still at their old paths, and the exhaustiveness case names the old directories. The failure output is recorded. The new `TestCoreDependencies` case pins behaviour the guard already has, so its red step is an inverted expectation that fails and is then reverted.
- [x] 2.2 Move the nested modules:
  - `pgx` → `store/pgxstore`;
  - `gorm` → `store/gormstore`;
  - `redis` → `ratelimit/redisstore` (package `redisstore`);
  - `sweep` → `expiry/sweep`;
  - `ginsec` and `fibersec` → under `httpsec/`.

  Move each with `git mv`, and update its `module` line, the `replace` directives, `go.work`, every requirement on it, and every import of it. Verify: the 2.1 cases for these modules pass, and `go build ./...` and `go vet ./...` pass in every module.
- [x] 2.3 Move `factor`, `password`, `apikey`, `magiclink`, `oidc`, `mfa` and `passkey` (with the `passkey/webauthn` module) under `authenticate/`, through gopls package moves. Verify: every 2.1 case passes, and `go test ./...` passes in the core module and in `authenticate/passkey/webauthn`.
- [x] 2.4 Move `signingkey` and `onetime` under `token/`. Turn `storeerr` into the package `store`. Move `sqlstore`, `migrate` (with its two sets) and `seal` under `store/`. Verify: `go test ./...` passes in the core module, and the backends' `ErrIsolationTooStrong` aliases still satisfy `errors.Is` against `store.ErrIsolationTooStrong`.
- [x] 2.5 Split `policy/lockout` as D3 says, with D3's names. `attempt_views.go` and the `AttemptStore` port stay in `policy`. `(*AccountLockoutPolicy).RequiredAttemptView`, all of `expiry.go` and `expiry_test.go` move to `lockout`. `export_test.go` splits into a `lockout/export_test.go`. Verify:
  - `go list -deps ./policy` does not contain `policy/lockout`;
  - `go doc ./policy AttemptStore` still resolves, and `lockout.Policy` still satisfies `policy.AttemptViewRequirer` (a compile-time assertion in `lockout`'s tests);
  - the lockout tests pass under `lockout`, and `policy`'s tests pass;
  - `evidence/check.sh` maps every former lockout test, and every moved `Example` function, to a passing test.
- [x] 2.6 Phase-1 gate: run `evidence/check.sh` (tests, API, declarations, coverage) and `make check`, push, and confirm CI is green, including the Docker suites. Then run the phase review against D1–D4 and the `module-layout` delta. Verify: no unmapped difference, a green CI run on the pushed head, and a clean review.

## 3. Phase 2: renames (D8–D11)

- [x] 3.1 Rename every `Manager` type, constructor, option type and dependent signature as D8 says, through gopls across the workspace. This includes `httpsec`'s `Enable…` parameters and `WithSessions`, and `NewFirstOf` for `authenticate` and `authorize`. Verify: `go build ./...` and `go test ./...` pass in every module, and `evidence/check.sh` reports only mapped API differences.
- [x] 3.2 Rename the outliers in D9, including both the interface method and the implementation of `KeySource.Signer`, and `mfa.MaxEmailCodeAttempts`. Verify: as in 3.1.
- [x] 3.3 Apply D10's sentinel rule (`session`, `password`, `token`, `policy`) and its `policy` suffix rule (`IdleTimeout`, `ConcurrentSessions`, `PasswordAge`, `NewMFA`, `NewMFARequirement`). Verify: as in 3.1, and every backend alias still satisfies `errors.Is` against its source.
- [x] 3.4 Apply D10's option table and the enum-prefix renames, package by package. Verify: as in 3.1, and every renamed option's godoc still names the default it replaces.
- [x] 3.5 Change error-message prefixes to the new package names, and the identifiers that messages name to their new names (D11). In the assertions that check them, update only the prefix and those identifiers. Verify:
  - `go test ./...` passes in every module;
  - a diff filter over the test files shows every changed assertion string becomes equal to its new form once `evidence/rename-map.tsv` and the D11 prefixes are applied to the old one;
  - a search of production error strings for every left-hand identifier of the map finds none.
- [x] 3.6 Sweep godoc, examples, the README and other non-Go docs for the old paths and names that gopls cannot rewrite, leaving out `openspec/` and `.claude/.legacy`. Rewrite each hit to the new name, without recording the old one: godoc describes the code, not its history (design D12). Verify:
- a search for every left-hand entry of `evidence/rename-map.tsv` finds no match outside `openspec/`, `.claude/.legacy` and `evidence/`;
- a search of the Go files for history wording ("formerly", "renamed", "moved from", "was called") finds nothing that the baseline commit did not already have.
- [x] 3.7 Phase-2 gate: `evidence/check.sh`, `make check`, push and CI green, then the phase review against D8–D11. Verify: no unmapped difference, a green CI run on the pushed head, and a clean review.

## 4. Phase 3: file families and table tests (D6, D7)

Each task below is one parallel lane that owns only the packages it names. Each table conversion is verified at its own red step: one case's expectation is temporarily inverted, the table is seen to fail on that case, and the inversion is reverted. A new cancelled-context case that fails stops that table, and is reported as `REPRODUCED` instead of committed (D7).

- [x] 4.1 `httpsec` production files, by D6's map. Verify: the production file list equals the map's 45 targets, `go build ./...` passes in every module, and `go test ./httpsec/...` passes.
- [x] 4.2 `httpsec` tests: one test file per production file, plus `integration_test.go` and `helpers_test.go`, with the D7 table conversion. Verify:
  - every conversion's inverted-case failure was seen;
  - `evidence/check.sh` maps every baseline `httpsec` test to a passing test;
  - `httpsec` coverage is not lower.
- [x] 4.3 `oidc` production files by D6's map, and its tests by D6 rule 4 and D7. Verify: its production files equal the map's 17 targets, the inverted-case failures were seen, `check.sh` maps every test, and coverage is not lower.
- [x] 4.4 `policy`, `policy/lockout`, `recovery` and `authenticate/passkey`, by the D6 rules. Report each package's file map. Verify: the maps follow the five rules, the inverted-case failures were seen, `check.sh` maps every test, and coverage is not lower.
- [x] 4.5 `session`, `authenticate/mfa`, `authenticate`, `authorize`, `identity`, `authenticate/password`, `authenticate/apikey`, `authenticate/magiclink`, `token`, `token/signingkey` and `token/onetime`, by the D6 rules. Verify: as in 4.4.
- [x] 4.6 `ratelimit`, `expiry`, `notify`, `outbound`, `store`, `store/sqlstore`, `store/seal`, `store/migrate`, `pkg/*`, `internal/*` and the nested modules (`pgxstore`, `gormstore`, `redisstore`, `sweep`, `ginsec`, `fibersec`, `webauthn`), by the D6 rules. Verify: as in 4.4, and `go generate ./...` changes no committed mock.
- [x] 4.7 Phase-3 gate: `evidence/check.sh`, `make check`, push and CI green, then one review per lane against D6 and D7. The review compares every converted case's assertions with its original function's. Verify: no unmapped difference, a green CI run on the pushed head, and clean reviews.

## 5. Phase 4: shared backend helpers (D5)

- [x] 5.1 Move the helpers that are identical across `sqlstore`, `pgxstore` and `gormstore` (and their `storekit` and `pglimiter` copies) into `internal/storekit`, and remove the copies. `txKey` stays in each backend (D5). Verify:
  - each listed helper is declared once, and `txKey` is still declared in each of the three backends;
  - no merged declaration's godoc promised something to "this package alone";
  - `go test ./...` passes in the core module and both backend modules;
  - the store-conformance suites under `test/` pass in CI.
- [x] 5.2 Phase-4 gate: `evidence/check.sh`, `make check`, push and CI green, then the phase review against D5. Verify: no unmapped difference, a green CI run on the pushed head, and a clean review.

## 6. The repository's own references

- [x] 6.1 Update the `openspec/config.yaml` context: the integration module list, the adapter names and the module paths. Verify: `openspec validate --all --strict` reports no failure that `main` does not already have (on 2026-10-29, the same 34 items fail on `main`: long requirements in archived specs, and three changes with no deltas), `restructure-layout` and `release-readiness` validate, and the context names no old path.
- [x] 6.2 Update the path and identifier references in the artifacts of the active changes: `trusted-proxy-client-ip`, `release-readiness` (including its tag prefixes and its `module-layout` scenarios), `di-wiring`, `bff-resource-server`, and `minimize-test-containers` once it is on `main`. Check `idiomatic-api-shape` and `key-port-context`, which already use this change's names, against the names that actually landed, and correct any that differ. Regenerate `plans.md` for any change whose `tasks.md` content changes, as `tasks-plans.md` requires. Verify: a search of `openspec/changes/` for every left-hand entry of `evidence/rename-map.tsv` finds matches only in this change's own artifacts.

## 7. Final integration

- [x] 7.1 Run the whole-branch review against the `module-layout` delta and every decision D1–D13. Verify: a clean review, with every finding resolved.
- [x] 7.2 Run `evidence/check.sh` for the whole branch against the group-1 baseline, run `openspec validate restructure-layout --strict`, and confirm CI is green on the final head, including the Docker suites. Verify: no unmapped difference, a valid change, and a green CI run.

## 8. PR review findings

The code review of PR #27 (2026-10-29) found no correctness defect. These tasks resolve its five low-severity findings as `design.md` D5, D8, D11 and D12 now record. 8.1 and 8.2 are test-first; 8.3 and 8.4 are documentation and renames that existing tests cover.

- [ ] 8.1 Strengthen `TestCheckUser` in `internal/storekit/storekit_test.go` (D5): every refusing case asserts the whole error text with `EqualError`, as the package's other refusal tests do. The cases are "username with a NUL byte", "name with invalid UTF-8" and "role with a NUL byte". Red step: temporarily make `unstorable` include the value it refused (`%q`), and see all three cases fail on the text; then edit it back. Verify: the failing lines are recorded, and `go test -count=1 -race ./internal/storekit/` passes with coverage not lower than 185/190.
- [ ] 8.2 Restore the text of lockout's store-failure refusal (D11): `storeDenied` in `policy/lockout/lockout.go` reads `"policy: denied by policy: the attempt store could not say how often this identifier has failed"`. Red step first: a test in `policy/lockout` asserts that a policy whose attempt store fails denies with that exact text, that the reason satisfies `errors.Is(reason, policy.ErrDenied)` and still unwraps to the store's error, and that it fails on the current `"lockout: …"` text. Fold it into the existing table for that path if one calls the same function. Verify: the failing line is recorded, `go test -count=1 -race ./policy/...` passes, and a search of production error strings finds no other message that stands for another package's sentinel under a different prefix.
- [ ] 8.3 Replace `lockout.Attempts()` in the godoc of `httpsec/basic.go`, `httpsec/login_options.go` and `httpsec/options.go` with the doc link `[lockout.Policy.Attempts]` (D12). Verify: a search finds no package-qualified call to a function that does not exist in any godoc touched by this change, and `go doc ./httpsec BasicAuthDeps` shows the link text.
- [ ] 8.4 Rename `PasskeyFixture.Manager` to `Passkeys` and `OIDCFixture.Manager` to `RelyingParty` in `test/httpsecconformance`, with their callers and field comments, and rename README variables that hold a `RelyingParty` to `relyingParty` (D8). Verify: `go build ./...` and `go vet ./...` pass in the test module, and `go test -list . ./httpsecconformance/...` lists the same tests as before.
- [ ] 8.5 Re-run the final gate: `make check`, `evidence/check.sh all` against the group-1 baseline, `openspec validate restructure-layout --strict`, push, and confirm CI is green on the new head, including the Docker suites. Then a Sonnet review of the 8.1–8.4 diff against D5, D8, D11 and D12. Verify: no unmapped difference, a valid change, a green CI run and a clean review.

## Workflow follow-up

- Archive the change with `/opsx:archive` once the branch is merged, which syncs the `module-layout` delta into the main spec.
- Open the pull request only when the user asks for it.
