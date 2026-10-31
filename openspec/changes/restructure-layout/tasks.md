# Tasks

Test-first applies to every task that adds or changes behaviour that a test can observe: the new layout requirement (group 2), the table conversions (group 4), and the security fixes (groups 12–16), each of which starts from the red test that proved its claim. Moves and renames that the existing tests already cover are exempt, as `golang-tdd.md` allows. They are verified instead by the D13 checks at the end of each group.

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

- [x] 8.1 Strengthen `TestCheckUser` in `internal/storekit/storekit_test.go` (D5): every refusing case asserts the whole error text with `EqualError`, as the package's other refusal tests do. The cases are "username with a NUL byte", "name with invalid UTF-8" and "role with a NUL byte". Red step: temporarily make `unstorable` include the value it refused (`%q`), and see all three cases fail on the text; then edit it back. Verify: the failing lines are recorded, and `go test -count=1 -race ./internal/storekit/` passes with coverage not lower than 185/190.
- [x] 8.2 Restore the text of lockout's store-failure refusal (D11): `storeDenied` in `policy/lockout/lockout.go` reads `"policy: denied by policy: the attempt store could not say how often this identifier has failed"`. Red step first: a test in `policy/lockout` asserts that a policy whose attempt store fails denies with that exact text, that the reason satisfies `errors.Is(reason, policy.ErrDenied)` and still unwraps to the store's error, and that it fails on the current `"lockout: …"` text. Fold it into the existing table for that path if one calls the same function. Verify: the failing line is recorded, `go test -count=1 -race ./policy/...` passes, and a search of production error strings finds no other message that stands for another package's sentinel under a different prefix.
- [x] 8.3 Replace `lockout.Attempts()` in the godoc of `httpsec/basic.go`, `httpsec/login_options.go` and `httpsec/options.go` with the doc link `[lockout.Policy.Attempts]` (D12). Verify: a search finds no package-qualified call to a function that does not exist in any godoc touched by this change, and `go doc ./httpsec BasicAuthDeps` shows the link text.
- [x] 8.4 Rename `PasskeyFixture.Manager` to `Passkeys` and `OIDCFixture.Manager` to `RelyingParty` in `test/httpsecconformance`, with their callers and field comments, and rename README variables that hold a `RelyingParty` to `relyingParty` (D8). Verify: `go build ./...` and `go vet ./...` pass in the test module, and `go test -list . ./httpsecconformance/...` lists the same tests as before.
- [x] 8.5 Re-run the final gate: `make check`, `evidence/check.sh all` against the group-1 baseline, `openspec validate restructure-layout --strict`, push, and confirm CI is green on the new head, including the Docker suites. Then a Sonnet review of the 8.1–8.4 diff against D5, D8, D11 and D12. Verify: no unmapped difference, a valid change, a green CI run and a clean review.

## 9. Second review of PR #27

The second code review of PR #27 (2026-10-29) found nine items. Three were reproduced as defects, in the layout guards and in `storeDenied`'s text (`design.md` D2, D11); the others are duplication, a misleading name and wording (D2, D5, D8, D11). 9.1–9.5 are test-first; 9.6 is documentation. Three lanes run in parallel and own disjoint files: 9.1–9.2 (`internal/storekit` and the three SQL backends), 9.3, 9.4 and 9.6 (`policy/lockout`, `httpsec/options.go` and its test, `session` godoc), and 9.5 (the root layout tests and `testdata/layout/noalias*`).

- [x] 9.1 Share the detached-error builder and the SQLSTATE filter (D5): add `storekit.ValidSQLState(code string) bool` and `storekit.Detached(err error, kept []error) error`, remove `isSQLState`/`validSQLState` and `detached` from `store/sqlstore`, `store/pgxstore` and `store/gormstore`, and have each backend's `dbFailed` call `storekit.Detached`. Red step: declare each new function as a stub returning its zero value, add `storekit`'s table tests, and see them fail on the stub:
  - `ValidSQLState`: five upper-case letters or digits pass; lower case, another length and punctuation do not;
  - `Detached`: the text is `"database failure"`, with `" (SQLSTATE XXXXX)"` only for a valid code, asserted with `EqualError`; the driver's own text never appears; the result still matches each kept sentinel through `errors.Is`, and nothing else.

  Then move the bodies. Verify: each name is declared once; `go test -count=1 -race ./internal/storekit/` passes, and `go test ./...` passes in the core module, `store/pgxstore` and `store/gormstore`; `evidence/rename-map.tsv` gains `merged` rows for the six removed declarations, and `evidence/check.sh decls` reports nothing unmapped.
- [x] 9.2 Share the partial user UPDATE between `sqlstore` and `pgxstore` (D5): add `storekit.Column`, `storekit.UserColumns(u *identity.UserChange, org any, ts func(time.Time) any) []storekit.Column` and `storekit.UpdateUserQuery(set []storekit.Column, now time.Time, userID any) (string, []any)`. Each backend passes its own `nullTs`, and `pgxstore` passes `uuidArg(userID)`. `gormstore` keeps its own `userColumns`. Red step: against stubs, `storekit` table tests pin the column order and allow-list, and the exact SQL text and argument list for no field, each single field and all fields; see them fail, then move the bodies. Verify: `go test -count=1 -race ./internal/storekit/` passes; `go test ./...` passes in the core module and `store/pgxstore`; the store-conformance suites under `test/` pass in CI, which proves both backends still write what they did; `merged` rows cover each removed declaration (`column` too, if nothing else in the backend uses it).
- [x] 9.3 Build `storeDenied`'s prefix from `policy.ErrDenied.Error()` (D11), and derive `storeDeniedText` in `policy/lockout/lockout_test.go` the same way. Red step: add a case to `TestAccountLockoutPolicyDeniesWhenTheStoreCannotAnswer` (or a standalone `TestStoreDeniedLeadsWithTheDeniedSentinelText` if its setup differs) asserting the reason starts with `policy.ErrDenied.Error() + ": "`. Temporarily change `ErrDenied`'s text in `policy/policy.go`, see the case fail on the stale literal, implement, see it pass with the changed text, then edit `ErrDenied` back. Verify: the failing line is recorded, `git diff policy/policy.go` is empty, and `go test -count=1 -race ./policy/...` passes.
- [x] 9.4 Name `lockout.Policy.Attempts` in `httpsec`'s configuration error for a lockout policy given another attempt store (D11): `"(lockout.Policy.Attempts for an account-lockout policy)"`. Red step: no test asserts this text today. Add an exact-text assertion to the test that builds a chain with that mismatch, or a case to its table, and see it fail on `Attempts()`; then change the message. Verify: `go test -count=1 -race ./httpsec/...` passes.
- [x] 9.5 Fix the layout guards (D2):
  - `TestBackendDoesNotShadowDriver` compares each backend's package clause with its driver's package name, from `go list -f '{{.Name}}' <driver>` run in the backend's module directory. Remove `testdata/layout/noaliaspgx`, `noaliasgorm` and `noaliasredis`. Red step: invert one row's expected relation, see it fail, and edit it back.
  - `workspaceModules` reads `go work edit -json <root>/go.work`. Red step: `TestWorkspaceModulesReadsSingleLineUse`, over a temporary `go.work` holding `use ./a` and `use ( ./b )`, fails returning only `b`.
  - Rename `belowGoMinimum` to `offGoMinimum`, and make `TestModulesDeclareGoMinimum`'s failure name each module with the version it declares. Its existing cases cover the rename.

  Verify: `go test -count=1 -run 'TestBackendDoesNotShadowDriver|TestWorkspaceModules|TestGoWorkListsEveryModule|TestIntegrationModulesUnderTheirConcept|TestNoUnlistedIntegrationModule|TestModulesDeclareGoMinimum' .` passes; the root `go.mod` is unchanged; and in a disposable export, raising `golang.org/x/crypto` in the root `go.mod` fails no layout test.
- [x] 9.6 Rewrite the `session` godoc sentences whose subject is "the Sessions" (D8): `ErrReused` and `ErrRenewalRequired` in `reuse.go`, and every other hit of `rg -n 'the Sessions' session/` that does not read as English. Each names the method that acts (`[Sessions.Load]`), or reads "a [Sessions]". Wording only. Verify: `go doc ./session ErrReused` reads correctly, and `gofmt -l session` and `go vet ./session` are clean.
- [x] 9.7 Gate: `make check`, `evidence/check.sh all` against the group-1 baseline (with the 9.1 and 9.2 `merged` rows), `openspec validate restructure-layout --strict`, push, and CI green on the new head, including the Docker suites. Then an Opus review of 9.1–9.2 against D5, and a Sonnet review of 9.3–9.6 against D2, D8 and D11. Verify: no unmapped difference, a valid change, a green CI run and clean reviews.

## 10. Test HTTP clients own their transport

A one-off CI failure on PR #27 (2026-10-29) traced to the test module's HTTP clients sharing `http.DefaultTransport` (`design.md` D14). The user folded the fix into this change on 2026-10-30. 10.1 and 10.2 are test-first and own disjoint files, so they run in parallel.

- [x] 10.1 Give `httpClient` in `test/oidc/idp_test.go` a transport of its own (D14). Red step: `TestHTTPClientKeepsItsConnectionsWhenAnotherServerCloses` sends a request to one `httptest.Server` and reads and closes the body, closes a second `httptest.Server`, then sends a second request to the first server and asserts through `httptrace.ClientTrace.GotConn` that `GotConnInfo.Reused` is true. `TestHTTPClientReleasesItsConnectionsWhenItsTestEnds` builds the client inside a subtest and sends one request there; after the subtest ends, a request on the same client must report `Reused` false. See both fail on the current helper. Then `httpClient` uses a clone of `http.DefaultTransport` whose `CloseIdleConnections` runs at `t.Cleanup`. Verify: `cd test && go test -count=1 -race ./oidc/` passes, and so does `go test -count=20 -run TestTestIdentityProviderMalformedTokens ./oidc/`.
- [x] 10.2 Give the root test package's two clients a transport of their own (D14): one unexported helper in `test/testutils.go` builds a cloned transport closed at `t.Cleanup`. `keycloakBrowser` (`test/oidc_keycloak_test.go`) uses it, and so does a new unexported `smtpAPIClient(t)`, which the SMTP helper stores in an unexported `SMTPConn` field for `SMTPConn.get` to use in place of `http.DefaultClient`. Red step: a table test `TestHTTPClientsKeepTheirConnectionsWhenAnotherServerCloses` in `test/testutils_http_test.go`, one case per constructor, with 10.1's assertion, and `TestHTTPClientsReleaseTheirConnectionsWhenTheirTestEnds`, the same table over 10.1's cleanup check. Declare `smtpAPIClient` first returning `http.DefaultClient`, and see every case fail. Verify: `cd test && go test -count=1 -race -run 'TestHTTPClientsKeepTheirConnectionsWhenAnotherServerCloses|TestHTTPClientsReleaseTheirConnectionsWhenTheirTestEnds' .` passes; `rg -n 'http\.Default(Client|Transport)' test --glob '*.go'` finds only the two clone sources; `go vet ./...` in `test` is clean.
- [x] 10.3 Gate: `make check`, `evidence/check.sh all` against the group-1 baseline, `openspec validate restructure-layout --strict`, push, and CI green on the new head, including the Docker suites. Then a Sonnet review of 10.1–10.2 against D14 and the `test-provisioning` delta. Verify: no unmapped difference, a valid change, a green CI run and a clean review.

## 11. Names that say what they bound (D15)

The naming sweep of 2026-10-31 found names that do not say what they bound, starting with `lockout.WithCap` (`design.md` D15). The renames are mechanical and the existing tests cover them, so they are exempt from test-first, as the file header says, and are verified by the D13 checks (phase 5). One lane, because a workspace-wide rename touches callers in every package; it runs before groups 12–16 so that every fix is written against the final names.

- [x] 11.1 Rename the lockout family with `gopls rename` across the `go.work` workspace (D15 table, `lockout` rows; D3's table already shows the results): `WithCap`, `NISTCap`, `WithCapRetention`, `Cap`, `CapRetention`, `WithCeiling`, `ReportAtCeiling`, `WithThreshold`, `Threshold`, `WithWindow`, `Window`, `WithAttemptStoreCapacity`. Error strings that name an option follow it (D11: `"WithFailureStreakLimit must be positive"`). The godoc of `WithFailureStreakLimit` and `NISTFailureStreakLimit` names the quantity in NIST SP 800-63B-4 §3.2.2's words, "consecutive failed authentication attempts". Verify: `go build ./...` and `go vet ./...` in the core module and every nested module; `go test -count=1 -race ./policy/... ./httpsec/...`; and in the test module `go vet ./...` and `go test -list . ./httpsecconformance/...` lists the same tests as before.
- [x] 11.2 Rename the rest of D15's table the same way: `passkey` (`WithLimit`, `ErrLimitReached`), `recovery` (`WithDelay`, `WithCompletionWindow`, `WithSessionLifetime`, `Count`), `token.WithLifetime`, `signingkey` (`WithLifetime`, `WithLogSampleWindow`), `onetime` (`WithTTL`, `TTL`), `policy.(*IdleTimeout).Thresholds`, `mfa.WithPeriod`, `oidc.MaxLogoutTokenMaxAge`, `notify` (`WithQueueSize`, `QueueSize`) and `httpsec.WithEnrolmentSessionTTL`. Leave the session timeouts and `policy.WithIdleAbsoluteTimeout` as they are (D15, vocabulary rules). Verify: as 11.1, over every module, with `go test -count=1 -race ./...` in the core module.
- [x] 11.3 Text sweep (D12): `rg` for every old name of 11.1–11.2 outside `.claude/.legacy`, in godoc, comments, README, strings, `%T` output and test-case names that are not D13-frozen function names. The agent fixes the Go and README hits and reports the hits under `openspec/`, which the main session updates (`subagent-delegation.md`). Verify: the sweep finds no old name outside the frozen test-function names and the change's own history in `design.md` and `evidence/`.
- [x] 11.4 Main session: add an `ident` row to `evidence/rename-map.tsv` for every rename of 11.1–11.2, mapping each baseline identifier to its final name. Where this change already renamed one (`WithLockoutCap` → `WithCap`), change the existing row's new name rather than adding a second row. Verify: `evidence/check.sh all` against the group-1 baseline reports no unmapped difference.
- [ ] 11.5 Gate: `make check`, `evidence/check.sh all`, `openspec validate restructure-layout --strict`, push, and CI green on the new head, including the Docker suites. Then a Sonnet review of the group-11 diff against D15: every rename in the table landed, nothing outside it was renamed, and every option's godoc still names its default. Verify: no unmapped difference, a valid change, a green CI run and a clean review.

## 12. Column constructors and the `WithUserRoles` godoc (D16)

`storekit.Column`'s exported name reaches the SQL text, and the `WithUserRoles` godoc contradicts `default-identity-store` (`design.md` D16). One lane, Sonnet, owning `internal/storekit`, `store/sqlstore/identity.go`, `store/pgxstore/identity.go` and `identity/ports.go`. It runs in parallel with 15 and 16.1.

- [x] 12.1 Make `storekit.Column`'s fields unexported, and add `storekit.RoleColumn(value any) Column` (D16). Red step:
  - `TestColumnExportsNoField` in `internal/storekit` asserts through `reflect` that `Column` has no exported field, which is the guarantee D16 makes. See it fail on `Name`.
  - A `TestUpdateUserQuery` case builds the role column with `RoleColumn` and asserts the exact SQL text and arguments. Declare `RoleColumn` as a stub returning the zero `Column`, and see the case fail.

  Then unexport the fields, implement `RoleColumn`, and change the `sqlstore` and `pgxstore` callers from a struct literal to `RoleColumn`. Verify: the failing lines are recorded; `go test -count=1 -race ./internal/storekit/` passes; `go test ./...` passes in the core module and `store/pgxstore`; the identity-store conformance suites under `test/` pass in CI; `rg 'storekit\.Column\{' -g '!.claude/.legacy'` finds nothing.
- [x] 12.2 Rewrite the `identity.WithUserRoles` godoc (D16): on `Update`, a list with no usable role name leaves every stored grant and the primary role untouched; on `Provision`, it creates a user with no roles. Documentation only. Verify: `go doc ./identity WithUserRoles` reads as `default-identity-store`'s "A role list that names nothing leaves grants untouched" requires, and `gofmt -l identity` is clean.
- [ ] 12.3 Gate: `make check`; `evidence/check.sh all`, with the `Column` fields as `changed` rows and `RoleColumn` as an `added` row (D13, phase 6; the main session extends `check.sh` to accept both kinds first); `openspec validate restructure-layout --strict`; push; CI green. Then a Sonnet review against D16. Verify: as 11.5.

## 13. A user-store outage is unavailable, not a failed login (D19)

Proven by `TestBasicAuth_IdentityStoreOutageIsNotACredentialFailure` (`design.md`, Context for D15–D20). One lane, Opus, because the change crosses `authenticate` and `httpsec` and changes what a refusal means. It owns `authenticate` (errors, the password authenticator and their tests), `httpsec/basic*.go`, `httpsec/login*.go` and `httpsec/errors*.go`. It runs in parallel with 15 and 16.1–16.2.

- [x] 13.1 Add `authenticate.ErrUnavailable` and return it from the password authenticator for a load failure other than "not found" (D19). Red step: change the load-failure case of `TestPasswordAuthenticatorDoesNotRevealWhyItFailed` to expect `ErrUnavailable`, not `ErrAuthenticationFailed`, with no driver text in the message. Add a case asserting the encoder spends the same password work as for an unknown username, counted through the encoder double. Declare the sentinel first, and see both cases fail on the current code. Verify: the failing lines are recorded; `go test -count=1 -race ./authenticate/...` passes; the error-level log record is still asserted.
- [x] 13.2 Map `ErrUnavailable` to 503 in the public status table (D19). Red step: a `StatusForError` table case for a wrapped `ErrUnavailable` expects 503 and fails on 500; `TestStatusForErrorCoversEverySentinel` fails until the row exists. Verify: `go test -count=1 -race -run 'TestStatusForError' ./httpsec/` passes.
- [x] 13.3 Form login and Basic authentication refuse an unavailable outcome without recording, counting or clearing anything, and Basic sets no `WWW-Authenticate` for it (D19). Red step: port the export's `TestBasicAuth_IdentityStoreOutageIsNotACredentialFailure` into `httpsec`, following `table-test` and `use-mockgen`, as a table over Basic and form login. Each row asserts: 503; no failure recorded for the username; none counted against the source; and, after the store recovers, a correct password succeeds under `lockout.WithFailureStreakLimit(3)`. Basic rows also assert no `WWW-Authenticate`. See every row fail on the current code. Verify: `go test -count=1 -race ./httpsec/...` passes; the test module's `httpsecconformance` suite passes in CI.
- [x] 13.4 A recovery's password proof does not count an unavailable outcome (D19, recovery bullet), and `EnableFormLogin`'s godoc names the unavailable outcome. Red step: a table test in `recovery` (or the recovery tests of `httpsec`, wherever the password proof is wired) over the `account-recovery` delta's "Outage during a recovery's password proof". It asserts the unavailable error, 503 where the HTTP layer answers, and that nothing is counted against the user's recovery limit or the source, through mock expectations. See it fail on the current counting. Verify: the failing lines are recorded; `go test -count=1 -race ./recovery/... ./httpsec/...` passes; `go doc ./httpsec EnableFormLogin` names the unavailable outcome.
- [x] 13.5 Fold the U-lane review (D19, caller-cancellation bullet). Red step: a case in the password authenticator's table and one in `TestPasswordLoginStoreOutageIsNotACredentialFailure` where the request's context is cancelled and the loader fails with that cancellation. They expect the uniform failure (a 401 at the endpoints), charged to the source and recorded for the username. See both fail on the current `ErrUnavailable`. The rows where the client hung up but the store failed with a connection error stay uncounted. Also:
  - assert in the load-failure case that the error is exactly `authenticate.ErrUnavailable`;
  - narrow `countsAgainstRecoverySource`'s godoc to what it exempts;
  - reflow the `httpsec/basic.go` godoc lines the edit left long.

  Verify: the failing lines are recorded, and `go test -count=1 -race ./authenticate/... ./httpsec/... ./recovery/...` passes.
- [x] 13.6 Fold the U3 review (D19, hang-up bullet). Red step: in the password authenticator's table, the caller-cancelled case asserts one debug-level record under its own reason, `caller-ended`, and no error-level record, while the connection-error case keeps its error-level `user-loader` record. See it fail on the current error-level `user-loader` record. Also:
  - a caller context ended with a cause (`WithCancelCause`, `WithTimeoutCause`) whose loader returns `context.Cause(ctx)` is the uniform failure too. Red step: `TestPasswordAuthenticator_CallerCancelCauseIsUniformFailure`'s case in the authenticator's table, seen to fail with `ErrUnavailable`;
  - a recovery whose password proof's load is ended by the caller is refused and counted as any refusal after the codes passed is. A test case pins it; where it passes on the current code, invert `causedByCaller` temporarily and see it fail;
  - the godoc of `ErrUnavailable` and `ErrAuthenticationFailed` says that a load the caller's own cancellation or deadline ended is the uniform failure, not unavailable, and `ErrUnavailable`'s names recovery's password proof among the paths that record nothing;
  - `countsAgainstRecoverySource`'s godoc says a caller-ended load is counted as any refusal after the codes passed is;
  - the recovery test messages that say an outage is not counted against the source say what `countsAgainstRecoverySource` does: an outage is not marked as a refusal after a valid code;
  - the `httpsec/login.go` paragraph left short by an earlier edit is reflowed, and the outage test's godoc names its hung-up rows.

  Verify: the failing lines are recorded, and `go test -count=1 -race ./authenticate/... ./httpsec/... ./recovery/...` passes, with `httpsec/ginsec` and `httpsec/fibersec`.
- [x] 13.7 Charge a caller-ended load to the source only (D19, caller-cancellation bullet), and fold the group-13 review's wording. Red step:
  - port `TestBasicAuth_SlowStoreWithClientTimeoutsHoldsAccount` into `httpsec` as a row of `TestPasswordLoginStoreOutageIsNotACredentialFailure`, over Basic and form login: under `lockout.WithFailureStreakLimit(3)`, three correct-password requests each time out while the loader blocks until the context ends and returns `ctx.Err()`; then the store answers and the correct password succeeds. See it fail with "held after 3 consecutive failures";
  - the hung-up rows of that test expect one source charge and no failure recorded for the username; the recovery hung-up case expects one source charge and none against the user's recovery limit; the authenticator's caller-ended cases assert that the error also matches the context's error. See each fail on the current code.

  Then the provider joins the uniform failure with the context's error for a caller-ended load, and form login, Basic and the recovery's password proof charge that outcome to the source only. A password that was compared and refused stays recorded for the username. Also:
  - `Authenticate`'s godoc says "or its cause";
  - the `authenticate/authenticate.go` paragraph at lines 69–73 is reflowed, and `ErrUnavailable`'s godoc says that it never matches `ErrAuthenticationFailed`;
  - the Basic hung-up row asserts its `WWW-Authenticate` challenge.

  Verify: the failing lines are recorded, and `go test -count=1 -race ./authenticate/... ./httpsec/... ./recovery/...` passes, with `httpsec/ginsec` and `httpsec/fibersec`.
- [x] 13.8 Answer an unavailable store as a wrong password, and charge it to the source (D19, "The client sees a wrong password" and "The source pays" bullets). Red step: port the security review's tests into `httpsec`, following `table-test` and `use-mockgen`, with a mock user loader in place of PostgreSQL:
  - "a held account answers an outage as a free one does": concealed locks, a failing loader, one held and one free username, over form login and Basic; both answer the same status and headers;
  - "known and unknown users answer a partial outage alike": the loader fails for a known username and misses an unknown one; both answer the same status and headers and are charged to the source once;
  - "outages are charged to the source": a loader failing every load; more requests than the source limit; the guard refuses those beyond it, and the encoder double counts no more password work than the limit;
  - the outage rows of `TestPasswordLoginStoreOutageIsNotACredentialFailure`, the recovery outage case and the `StatusForError` case expect 401, the Basic challenge, one source charge, and nothing for the username or the recovery limit; the adapters' cases in `ginsec` and `fibersec` expect 401; the API key owner outage row expects 401 and no source charge.

  See each fail on the current code. Then map `ErrUnavailable` to 401, set Basic's challenge for it, and charge the source at form login, Basic and the recovery's password proof. Godoc: `ErrUnavailable`, `EnableFormLogin`, `EnableBasicAuth`, `EnableAccountRecovery` (which also names the caller-ended case), `WithAPIKeyOwners`, and the error-response docs say that a consumer error handler answering 503 for `ErrUnavailable` brings back the lock-state and partial-outage oracles. Verify: the failing lines are recorded; `go test -count=1 -race ./authenticate/... ./httpsec/... ./recovery/...` passes, with `httpsec/ginsec` and `httpsec/fibersec`.
- [x] 13.9 Report input a store cannot represent as "not found" (D19, input bullet; `identity-model` delta). Red step:
  - a `storekit` table test of the lookup classifier: an error whose `storekit.SQLStater` reports SQLSTATE 22021 or 22P05, bare and wrapped, is a miss; 08006 and 40001 are not;
  - port `TestShippedStoreOnLatin1Database_UnencodableUsernameIsChargedToTheSource`'s setup into the test module's identity-store conformance as "a username the database cannot encode is not found", for `sqlstore` over a LATIN1 database, and see it fail with SQLSTATE 22P05.

  Then classify both codes as `identity.ErrUserNotFound` in `LoadByUsername` and `LoadByUserID` of `sqlstore`, `pgxstore` and `gormstore`, through one `storekit` helper, and state the rule in `identity.UserLoader`'s godoc. Verify: the failing lines are recorded; `go test -count=1 -race ./internal/storekit/ ./store/...` and the nested store modules pass; the conformance case passes for every backend it runs on.
- [x] 13.10 Fold the group-13 review's endpoint findings (D19, recovery lookup bullet). Red step:
  - port `TestReview_RecoveryPartialOutageAnswersKnownAndUnknownAlike` as a recovery row of `TestPasswordLoginOutageAnswersEveryUsernameAlike` (or its own table beside it): a recovery for a user whose load fails and one for an unknown user answer the same status and headers and are each charged once to the source. See it fail with 500 against 401;
  - a `TestRecoveryComplete_HTTP` row: an outage during the password proof under `WithRecoveryCountRefusals(false)` is still charged once to the source. Mutate `countsAgainstRecoverySource` to follow the option for `ErrUnavailable`, see the row fail, and edit it back;
  - a `recovery` row: the password check returns a bare `ErrAuthenticationFailed` while the context is cancelled; it is counted against the user's recovery limit. Mutate `passwordLoadEndedByCaller` to decide from the context alone, see the row fail, and edit it back.

  Then `resolveForRecover` returns `ErrUnavailable` for a load failure the caller did not end, logged as now. Also: `WithErrorHandler`'s godoc, and the handler docs of `ginsec` and `fibersec`, point to the 503 oracle warning; reflow `httpsec/basic.go` 173–186 and `httpsec/recovery_options.go` 174. Verify: the failing lines are recorded, and `go test -count=1 -race ./httpsec/... ./recovery/...` passes, with `httpsec/ginsec` and `httpsec/fibersec`.
- [x] 13.11 Narrow the lookup classification (D19, input bullet). Red step: port `TestReview_StoredRowTheConnectionCannotEncodeIsNotAMiss` into each backend's LATIN1 test as a row: a UTF-8 database read through `client_encoding=LATIN1`, an existing user whose name holds `€`; `LoadByUserID` and `LoadByUsername("ada")` return a failure, not `ErrUserNotFound`. See it fail. Then `storekit.LookupMiss` takes the looked-up value and is true only when it is not ASCII; only `LoadByUsername` uses it; its godoc says why. Verify: the failing lines are recorded; `go test -count=1 -race ./internal/storekit/ ./store/...`, the nested store modules, and the three backends' LATIN1 tests pass.
- [ ] 13.12 Gate: as 12.3, with `ErrUnavailable` as an `added` row and the changed assertion of 13.1 listed for the assertion review. Then an Opus review of 13.1–13.6 (done), of 13.7–13.9 (done) and a Sonnet review of 13.10–13.11 against D19 and the `authentication`, `http-error-propagation`, `http-security-chain` and `account-recovery` deltas. Verify: as 11.5.

## 14. API key authentication can require an active owner (D17)

Proven by `TestAPIKey_RefusesKeyOfInactiveOwner`. One lane, Opus, because it is refusal logic written for the first time. It owns `httpsec/apikey*.go`. It starts after group 13, because it returns 13's `ErrUnavailable`.

- [x] 14.1 Add `httpsec.WithAPIKeyOwners(identity.UserLoader)` (D17). Red step: a table test in `httpsec` over the `api-keys` delta's scenarios:
  - with no loader, a key authenticates and the loader mock expects no call;
  - an inactive owner and a missing owner are refused exactly as a wrong key is, and counted against the source;
  - an active owner authenticates as the key's service principal;
  - a loader connection error is refused with `ErrUnavailable`, answered 503, and not counted;
  - an owner load the request's own context ended is refused with an error matching that context's error, not `ErrUnavailable`, and not counted;
  - `WithAPIKeyOwners(nil)` is a configuration error from `New`.

  Declare the option as a no-op first, and see the inactive, missing, outage and nil rows fail. Verify: the failing lines are recorded, and `go test -count=1 -race ./httpsec/...` passes.
- [x] 14.2 State the default in `EnableAPIKey`'s godoc (D17): without `WithAPIKeyOwners`, deactivating a user stops none of the keys issued for that user's reference. Verify: `go doc ./httpsec EnableAPIKey` says so and names the option.
- [x] 14.3 Fold the K1 review (D17, mismatch bullet). Red step: a row in `TestAPIKeyOwners` where the loader returns an active user whose ID differs from the key's principal reference; it expects the wrong-key refusal, one source charge and one error-level record with reason `owner-mismatch`. See it fail. Also:
  - the caller-left rows assert `ErrAuthenticationFailed`, `StatusForError` 401 and exactly one debug-level record;
  - a row pins a loader answering `(nil, nil)`: refused as a wrong key and counted;
  - `WithAPIKeyOwners`' godoc names the mismatch refusal and that a refused key keeps its last-use time.

  Verify: the failing lines are recorded, and `go test -count=1 -race ./httpsec/...` passes, with `httpsec/ginsec` and `httpsec/fibersec`.
- [ ] 14.4 Gate: as 12.3, with `WithAPIKeyOwners` as an `added` row. Then an Opus review of 14.1–14.2 (done) and a Sonnet review of 14.3 against D17 and the `api-keys` delta. Verify: as 11.5.

## 15. A verifier requires an issuer and an audience (D18)

Proven by `TestVerifier_RefusesTokenForAnotherAudienceWhenNoneConfigured`. One lane, Opus, because it is verification logic. It owns `token/**`, including `token/signingkey/keys_lifecycle_test.go`. It runs in parallel with 12, 13 and 16.

- [x] 15.1 Require an issuer and an audience at construction, each waivable (D18). Red step: port the export's test into `token` as a table over the `token-issuance` delta:
  - a verifier with neither issuer nor waiver, and one with neither audience nor waiver, fail with `ErrConfig`;
  - configuring and waiving the same check fails with `ErrConfig`;
  - a waived check accepts any value;
  - a token minted for `service-a` is rejected by a verifier configured for `service-b`.

  Declare `WithoutVerifyIssuer` and `WithoutVerifyAudience` as no-ops first, and see the construction rows fail. Verify: the failing lines are recorded, and `go test -count=1 -race -run <the new test> ./token/` passes.
- [x] 15.2 Give every existing test that builds a verifier without an issuer or an audience, and without the matching waiver, what it now needs (D18, D13 phase 6). These are the 11 tests in `token` and `TestRestartedManager` in `token/signingkey` that the export's blast-radius run listed. A test about the issuer or audience gets the configured value; any other gets the waiver for the claim it does not exercise. No other assertion changes. Verify: `go test -count=1 -race ./token/...` passes, and `rg -n 'NewVerifier\(' -g '!.claude/.legacy' -g '!openspec/**'` shows every call configures or waives both.
- [x] 15.3 Rewrite the `token` package doc and the godoc of `NewVerifier`, `WithVerifyIssuer` and `WithVerifyAudience` (D18): the defaults are now refusals, and each waiver states what it gives up. Verify: `go doc -all ./token` no longer says the issuer or audience is "enforced exactly when the consumer configured one".
- [x] 15.4 Make the generator follow the same rule (D18, generator bullet). Red step: a table test `TestNewGeneratorRequiresIssuerAndAudience` in `token`, over the `token-issuance` delta's generator requirement. Its rows: neither issuer nor waiver, and neither audience nor waiver, fail with `ErrConfig`; a claim and its waiver fail with `ErrConfig`; generators for `service-a` and `service-b` sharing a key source reject each other's tokens; a generator that waived both issues a token with neither claim and verifies it. Declare `WithoutIssuer` and `WithoutAudience` as no-ops first, and see the construction rows fail. Then give every existing `NewGenerator` call that lacks a claim the configured value or the waiver: the tests in `token/**`, `test/oidc/idp_test.go`, `test/oidc_keycloak_test.go`, and any README example. Change no other assertion. Verify: the failing lines are recorded; `go test -count=1 -race ./token/...`; `go vet ./...` and `go build ./...` in every module; `cd test && go test -count=1 ./oidc/` passes; `rg -n 'NewGenerator\(' -g '!.claude/**' -g '!openspec/**'` shows both claims configured or waived at every call.
- [x] 15.5 Refuse an empty issuer or audience in `NewVerifier` and `NewGenerator` (D18, empty-value bullet), and cover the generator's waived check. Red step:
  - rows in both construction tables expect `ErrConfig` for `WithIssuer("")`, `WithAudience("")`, `WithVerifyIssuer("")` and `WithVerifyAudience("")`;
  - the export's reproduction, two generators with empty settings accepting each other's tokens, becomes a refusal row;
  - a row shows a generator that waived both claims accepts a token carrying a foreign `iss` and `aud`.

  See the empty-value rows fail. The base rows "configured as the empty string is still enforced" become refusal rows. Verify: the failing lines are recorded, and `go test -count=1 -race ./token/...` passes.
- [x] 15.6 Refuse a blank issuer or audience, and pin the waiver's name in the refusal (D18, white-space bullet). Red step:
  - rows in both construction tables expect `ErrConfig` for `WithIssuer(" ")`, `WithAudience("\t")`, `WithVerifyIssuer(" ")` and `WithVerifyAudience("\n ")`;
  - every empty and blank row asserts that the error names the matching waiver (`WithoutIssuer`, `WithoutAudience`, `WithoutVerifyIssuer`, `WithoutVerifyAudience`);
  - a row shows `WithAudience(" svc ")` is accepted and enforced as given.

  See the blank rows fail. Where a waiver-name assertion passes on the current code, break the message temporarily and see it fail. Then the failure lists in the godoc of `NewVerifier` and `NewGenerator` name the empty-or-blank refusal. Verify: the failing lines are recorded; `go test -count=1 -race ./token/...` passes; `go doc ./token NewVerifier` and `go doc ./token NewGenerator` name the refusal.
- [ ] 15.7 Gate: as 12.3, with the four waivers as `added` rows, and the changed tests of 15.2, 15.4, 15.5 and 15.6 listed for the assertion review. Then an Opus review of 15.1–15.5 against D18 (done, clean) and a Sonnet review of 15.6 and the `token-issuance` delta. Verify: as 11.5.

## 16. Limiters charge and refund atomically (D20)

Proven by `TestCodes_ConcurrentWrongCodesStayWithinLimit`, which failed 100 of 100 runs. Concurrency, so Opus. It is one lane in four sequential dispatches, so that the tree compiles after each one. The port is widened only in 16.4, once every implementation exists. The lane owns:
- `ratelimit/**`, including `ratelimit/redisstore`;
- `internal/pglimiter` and `internal/unavailable`;
- `store/sqlstore/limiter*.go` and `store/pgxstore/limiter*.go`;
- `recovery/codes*.go`;
- `test/ratelimittest`, `test/pg_ratelimit_fault_test.go`, and the test module's limiter suites;
- in 16.4, every generated `limiter_mock_test.go`.

- [x] 16.1 Add `ratelimit.Receipt` and an interface `ratelimit.Charger` with D20's `Charge` and `Refund`, implement them on the in-memory limiter, and add the conformance cases (D20). Red step:
  - In `test/ratelimittest`, add the conformance cases: 64 goroutines charge one key against a limit of 5, and exactly five succeed; a refund returns the allowance; a refund after the window removes nothing.
  - Run them against a deliberately broken `Charger` that checks and records in two steps, and see the concurrent case fail.
  - Then run them against the in-memory limiter with stub methods, and see them fail.

  Verify: the failing lines are recorded; `go test -count=1 -race ./ratelimit/...` passes, run with `-count=50` for the concurrent case; the test module's in-memory limiter suite passes.
- [x] 16.2 Implement `Charger` on `internal/pglimiter` (with the `sqlstore` and `pgxstore` runners), on `redisstore`, and through the `internal/unavailable` decorator (D20). Each shared limiter runs 16.1's conformance cases, and each is first seen to fail against a stub. `pglimiter` charges with one `INSERT … ON CONFLICT DO UPDATE … WHERE` on the key's row, in its own READ COMMITTED transaction, refunds with `array_position` and slicing, and needs no migration. `redisstore` charges with one Lua script and keeps its trimming rule. The decorator passes both methods through, and charges its local fallback when degraded. Verify: `go test -count=1 -race ./...` in the core module and in `ratelimit/redisstore`, `store/sqlstore` and `store/pgxstore`; the Docker-backed limiter suites in the test module pass in CI; `git diff --stat store/migrate` is empty.
- [x] 16.3 Fold the L1–L2 review (D20). Red step: add the conformance case "refund removes its own failure, not a newer one" to `test/ratelimittest`: limit 2, window 1m; charge A; advance 30s; charge B; refund A; advance 31s; a charge succeeds, and the key is then exceeded. Add the flaw `refund-removes-newest-instead` to the suite's broken variants, and see the case fail against it with `expected: true actual: false` while the existing cases pass it. Also:
  - `Refund`'s godoc says a receipt belongs to the limiter that issued it;
  - `Charger`'s godoc names every limiter scrty ships, not only the in-memory one;
  - the decorator's `Refund` godoc says "the same microsecond", not "the same instant";
  - the odd line wraps at `ratelimit/memory.go:548` and `ratelimit/redisstore/limiter.go:349` are reflowed.

  Verify: the failing lines are recorded; `cd test && go test -count=1 -race ./ratelimittest/` passes, including the catch-broken test; the new case passes against the memory limiter, `sqlstore`, `pgxstore` and every Redis and Valkey image in the test module's limiter suites.
- [x] 16.4 Widen `ratelimit.Limiter` to embed `Charger`, and make `recovery/codes.go`'s `causedByCaller` match `context.Cause(ctx)` too, as the password path does, regenerate every limiter mock with `go generate`, and give the test module's hand-written limiter doubles both methods. Then make `recovery.Codes` charge before the lookup, on a context whose cancellation is stripped, and refund on a valid code (D20). Red step: port the export's `TestCodes_ConcurrentWrongCodesStayWithinLimit` into `recovery`, following `table-test`, with its barrier decorator, and add the `account-recovery` delta's "A valid code spends no allowance" case. See both fail on the check-then-record code; then switch `Codes` to `Charge` and `Refund`. Verify:
  - the failing lines are recorded;
  - `go test -count=100 -race -run TestCodes_ConcurrentWrongCodesStayWithinLimit ./recovery/` passes every run;
  - `go test -count=1 -race ./...` passes in the core module and every nested module;
  - `go generate ./...` leaves no drift.
- [x] 16.5 Pin the charge's fail-closed error paths (D20; `golang-tdd`, error paths that change an observable outcome). Tests only:
  - `redisstore`: a charge whose script fails returns `exceeded=true` with the error, and records nothing;
  - `internal/unavailable`: in fallback mode, a charge whose caller's context has ended while the breaker is open is refused with the "charge abandoned" error, and the local count records nothing.

  Each passes on the current code; invert the branch it pins, see it fail, and edit it back. Verify: the failing lines are recorded, and `go test -count=1 -race ./internal/unavailable/` and the `ratelimit/redisstore` module pass.
- [x] 16.6 Fold the group-16 review (D20). Tests and their harnesses only:
  - the PostgreSQL conformance harnesses of `sqlstore` and `pgx` give the limiter an operation timeout of 30 seconds instead of 5, because 64 charges on one key serialize on its row and, under a loaded CI runner, the queue outlasts 5 seconds (the review reproduced 13 and 31 of 64 charges failing at 5.0s with `DeadlineExceeded`). The concurrent case keeps `NoError`, and its failure message counts the errors and names the timeout;
  - `TestPGLimiter_HeldRow` waits up to 5 seconds for the server to drop the waiting session, and logs `pg_stat_activity` when it fails; the `lock-timeout-off` variant still fails it;
  - the `TestCodes` case "a good code has its charge refunded, by the charge's receipt" cancels the context in its `Match` mock, so the refund's stripped cancellation is pinned. Mutate `recovery/codes.go`'s refund to pass `ctx`, see it fail, and edit it back;
  - `causedByCaller`'s godoc in `recovery/codes.go` says that a deadline a dependency met on its own context does not count while the caller's context is still live.

  Verify: the failing lines are recorded; `go test -count=1 -race ./recovery/` passes; `cd test && go test -count=5 -race -run 'Limiter_Conformance/concurrent|TestPGLimiter_HeldRow' .` passes while the core module's `go test -race ./...` runs beside it.
- [ ] 16.7 Make the PostgreSQL limiter tests hold under the full parallel `make check` (D13, phase 6; `make check` is also CI's gate). Three of five full runs after group 16 landed failed, each on a different timing-sensitive case: the concurrent charge on `sqlstore` and on `pgx` (`backend unavailable` at the operation timeout), `TestPGLimiter_HeldRow`, and the warm-up `Exceeded` of `TestPGLimiter_Unavailable/pgx` (`backend unavailable` within `pgOutageTimeout`, 2 seconds, while the server was running). Each passed alone. For every PostgreSQL limiter test whose outcome depends on wall-clock time under load, choose one, and say why:
  - a wait that tolerates a loaded host without weakening what the test proves, such as a readiness check on a plain connection before a limiter's first call;
  - or a move into `make test-isolated`, beside `TestPGLimiter_PruneUnderRecords`, with the same skip under `go test ./...` and the same environment switch.

  Every broken variant the changed tests catch is still caught. Verify: three consecutive full `make check` runs are green; `make test-isolated` is green; each changed test's broken-variant check still fails its variant.
- [ ] 16.8 Gate: as 12.3, with `Receipt`, `Charger`, and the two methods on each limiter type as `added` rows, and the charge-first `TestCodes` cases listed for the assertion review. Then an Opus review of 16.1–16.5 (done), and a Sonnet review of 16.6 and 16.7 against D20 and the `rate-limiting` and `account-recovery` deltas, with attention to:
  - refund precision under concurrent charges;
  - the decorator's degraded path;
  - the conditional `UPDATE` under PostgreSQL's default isolation.

  Verify: as 11.5.

## 17. Whole-branch gate

- [ ] 17.1 Main session: update the old names that 11.3 reported under `openspec/`. Update the artifacts of the active changes that name a renamed identifier or a changed default:
  - `idiomatic-api-shape` and `key-port-context`, checked against the names that actually landed (Migration Plan step 4);
  - `trusted-proxy-client-ip`, whose resolver D15's vocabulary now names.

  Verify: `openspec validate --all --strict` is valid, and `rg` finds no old name in an active change's artifacts outside their own history.
- [ ] 17.2 Final gate: `make check`, `evidence/check.sh all` against the group-1 baseline, `openspec validate restructure-layout --strict`, push, and CI green on the new head, including the Docker suites. Then one Opus whole-branch review against every spec requirement the change covers, including the seven security deltas. Each claimed defect needs a failing test or is labelled `UNREPRODUCED`. Verify: no unmapped difference, a valid change, a green CI run and a clean review.

## Workflow follow-up

- Archive the change with `/opsx:archive` once the branch is merged, which syncs the `module-layout`, `test-provisioning`, `token-issuance`, `authentication`, `http-error-propagation`, `http-security-chain`, `identity-model`, `api-keys`, `rate-limiting` and `account-recovery` deltas into the main specs.
- Open the pull request only when the user asks for it.
