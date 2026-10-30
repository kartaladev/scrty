# Design

## Context

See `proposal.md` (Why) for the motivation. The facts below shaped the approach. Counts are as of 2026-10-25, and were checked again against `main` on 2026-10-28, after `stabilize-intermittent-tests` merged.

- **The import graph.**
  - `httpsec` imports 24 core packages.
  - `passkey` and `recovery` import `mfa`, `session`, `policy` and `onetime`.
  - `factor` imports nothing, by design: its doc makes it the import-free owner of the first-factor vocabulary.
  - In Go a parent directory is only a namespace. Nesting a package changes its import path and never its import edges.
- **The lockout group in `policy` is almost self-contained.** It is made up of `lockout.go`, `lockout_error.go`, `lockout_observer.go`, `attempts.go`, `streak.go` and `expiry.go`, which holds only `LockoutExpiryTask`. Its files use only exported `policy` names (`Phase`, `Decision`, `Input`, `ErrConfig`, `ErrPolicyDenied`), and all its tests are in the external `policy_test` package. The rest of `policy`'s production code reaches it through `attempt_views.go` alone:
  - `AttemptViewRequirer.RequiredAttemptView` returns an `AttemptStore`, and the struct `RequiredAttemptView` has an `AttemptStore` field. `Engine.RequiredAttemptViews` reads both.
  - The same file declares the method `(*AccountLockoutPolicy).RequiredAttemptView`, which reads the policy's unexported `attempts` and `capLimit`.

  In the tests, `export_test.go` (package `policy`) exposes `AccountLockoutPolicy` and `MemoryAttemptStore` internals. `engine_test.go`, `example_test.go`, `expiry_test.go`, `returned_errors_test.go` and `store_failure_test.go` (all `policy_test`) use lockout names.
- **`httpsec` is one package of 60 production files and 153 test files.** About 30 of the test files are generated mocks. Its `options.go` (2,659 lines) holds the chain core (configuration, `New`, the build and the chain-level options) and the `Enable…` function and option set of ten features. oidc, recovery, passkey and MFA enrolment keep theirs in their own files.
- **No `httpsec` feature group can become a sub-package** without first moving its shared machinery (`config`, the login tail, the source throttle, the request readers) into an internal package. `Option` is `func(*config) error` over an unexported `config`.
- **The three SQL backends repeat helpers with identical declarations:** `bestEffort` (also in `storekit`), `checkUser`, `parseUserID`, `survivingRoles`, `dbFailed`, `detachedError`/`detachedText`, `errPasskeyHandleHeld`, `errStreakContended`, `txKey`, `optionKind` and `sqlStater` (also in `internal/pglimiter`). A comparison of the declarations on 2026-10-28 found them byte-identical, apart from each package's error prefix. `txKey`'s identity is part of its behaviour, though. Its godoc in each backend says the key "belongs to this package alone, so a transaction another backend attaches … is never seen by these stores" (D5).
- **Error strings are prefixed with their package name** (`"pgx: …"`, `"policy: …"`, `"scrtyredis: …"`). The tests assert on some of these texts.
- **Docker is not available in the planning session.** The testcontainers suites under `test/` run in CI.

## Goals / Non-Goals

**Goals:**
- **No feature is removed.** Every exported identifier, option, port, endpoint, sentinel, `Example` function and test has a successor after the change, and does what it did before. The only declarations that may disappear are D5's duplicate helper copies, each replaced by its single `storekit` declaration. D13 checks this mechanically, through the API inventory and a declaration inventory, not by review alone.
- **Every move and rename is mechanical, and checkable after the fact.** Each one comes with a before-and-after inventory that a script compares.
- **Each dispatch fits one lane's file ownership.** Phases that touch callers across packages run in one lane; phases confined to one package run in parallel.

**Non-Goals:**
- **No default changes and no behaviour changes, outside D16–D20.** Every option and port keeps its default through the moves and renames. A renamed option's godoc still names the default it replaces. D16–D20 are the exception: the security review of 2026-10-31 proved each one's defect with a failing test (D15–D20's context below), and the user folded the fixes into this change on 2026-10-31. Each of those decisions states its default and the consumer's override, as `library-design` requires.
- **No change to the test module's own layout.** `test/` keeps its sub-packages (`test/pgxstore`, `test/sqlstore`, …) and file layout. Only its imports and the names it references change, apart from D14's HTTP client helpers.
- **No consolidation of generated mocks.** Each one stays `<source>_mock_test.go`, produced by its `//go:generate` directive, as `use-mockgen` requires.
- **None of `idiomatic-api-shape`'s or `key-port-context`'s items** (see `proposal.md`, Not in this change).

## Decisions

### D1. Concept directories, with a real package as the parent where one exists

The parents are `authenticate`, `token`, `policy`, `store`, `expiry`, `httpsec` and `ratelimit`, each of which already exists as a package or becomes one (`store`). This follows the standard-library pattern (`crypto` → `crypto/ecdsa`, `net/http` → `net/http/httptest`).

| Today | Target import path (under `github.com/kartaladev/scrty/`) | Package |
|---|---|---|
| `factor` | `authenticate/factor` | `factor` |
| `password`, `apikey`, `magiclink`, `oidc`, `mfa` | `authenticate/<name>` | unchanged |
| `passkey` | `authenticate/passkey` | `passkey` |
| `passkey/webauthn` (module) | `authenticate/passkey/webauthn` (module) | `webauthn` |
| `signingkey`, `onetime` | `token/<name>` | unchanged |
| lockout group of `policy` | `policy/lockout` | `lockout` (D3) |
| `storeerr` | `store` | `store` (D4) |
| `sqlstore`, `migrate` (+ `migrate/identity`, `migrate/securitystate`), `seal` | `store/<name>` | unchanged |
| `pgx` (module) | `store/pgxstore` (module) | `pgxstore` |
| `gorm` (module) | `store/gormstore` (module) | `gormstore` |
| `redis` (module) | `ratelimit/redisstore` (module) | `redisstore` (was `scrtyredis`) |
| `sweep` (module) | `expiry/sweep` (module) | `sweep` |
| `ginsec`, `fibersec` (modules) | `httpsec/ginsec`, `httpsec/fibersec` (modules) | unchanged |

**Unchanged:** `identity`, `authenticate`, `authorize`, `session`, `recovery`, `policy`, `ratelimit`, `token`, `expiry`, `httpsec`, `outbound`, `notify`, `pkg/*`, `internal/*`, `test` and `tools`.

**Why these placements:**
- **`recovery` stays at the root.** It restores access after losing any authenticator, with two independent proofs, so it is account-level rather than MFA-level.
- **`ratelimit` stays at the root.** `mfa`, `recovery`, `passkey` and `httpsec` use it, and `policy` does not import it.
- **`seal` goes under `store`.** Its capability, secrets-at-rest, belongs with persistence.
- **`onetime` goes under `token`.** It is a primitive that several flows issue and redeem, not a login method of its own.

**Alternatives considered:**
- **A flat layout with merges only.** It leaves 20 root directories, and the root still mixes concept levels.
- **A few large merged packages.** These make catch-all namespaces, force many identifier collisions, and risk import cycles.
- **Merging `factor` into `identity` or `authenticate`.** Merging into `identity` collides with `identity.Kind`. Merging into `authenticate` loses the import-free property `factor` documents.

### D2. Module paths, and wiring that follows the modules

The seven nested integration modules take the paths in D1, as the `module-layout` delta requires. Every other module requires them at the new paths. Both of the following are rewritten for the new paths:
- the `replace` directives and `go.work`;
- the module directories that the layout tests name: the WebAuthn adapter's directory and helper path in `layout_test.go` (`TestWebAuthnTypesStayInsideTheAdapter`, `TestSoftwareAuthenticatorStaysOutOfProduction`), the `ginsec` and `redis` inputs of `TestRedisClientStaysInItsModules`, and `redisClientOwners` in `layout_guard_test.go`.

The `Makefile` takes its modules from `go list -m`, and so from `go.work`. The CI workflow names no module directory, and neither do the `testdata/layout` and `testdata/graph` fixtures. None of them needs an edit.

The new layout test, for "Integration modules are published under the concept they extend", is exhaustive. Every workspace module other than `test` and `tools` must be one of the seven listed integrations. A module left at a former path, or added outside the list, fails it by name.

The test module's path stays `github.com/kartaladev/scrty/test`.

`release-readiness` names tag prefixes after module directories. It is updated to `authenticate/passkey/webauthn/`, `store/pgxstore/`, `store/gormstore/`, `ratelimit/redisstore/`, `expiry/sweep/`, `httpsec/ginsec/`, `httpsec/fibersec/` and `test/`. Nothing is tagged, so no published version is affected.

**Layout guards, as revised after the second PR review (2026-10-29):**
- **"A backend does not shadow its driver" is checked by comparing names, not by building fixtures.** A Go source file can import two packages without an alias exactly when their package names differ, so the comparison proves what the build proved. `TestBackendDoesNotShadowDriver` compares each backend's package clause with its driver's package name, as `go list -f '{{.Name}}' <driver>` reports it inside the backend's own module, whose `go.mod` already pins the driver. The three fixture modules `testdata/layout/noaliaspgx`, `noaliasgorm` and `noaliasredis` are removed. They pinned the whole indirect graph under `-mod=readonly`, so a routine requirement bump in the root module failed the test with no layout rule broken. `REPRODUCED` on 2026-10-29 in a disposable export: raising `golang.org/x/crypto` from v0.57.0 to v0.58.0 in the root `go.mod` failed all three subtests with `go: updates to go.mod needed, disabled by -mod=readonly`, and they passed again once the bump was reverted.
- **`workspaceModules` reads `go.work` through `go work edit -json`,** the toolchain's own parser, instead of scanning for a `use (` block. The scan ignored a single-line `use ./dir` directive. `REPRODUCED` on 2026-10-29 by `TestWorkspaceModulesReadsSingleLineUse`: over a `go.work` holding `use ./a` and `use ( ./b )`, it returned `["b"]`. The toolchain adds no requirement to the core module.
- **The Go-minimum guard is named for what it checks.** The "Supported Go releases" requirement asks every module to declare exactly `go 1.27`, so the guard rightly flags `go 1.28` too. Its helper was nevertheless called `belowGoMinimum`. It becomes `offGoMinimum`, and the test's failure names each module with the version it declares. This is not a defect: the check was right, and only its name misled.

### D3. `policy/lockout` takes the lockout group; attempt views stay with the engine

**What moves to `lockout`:**
- the lockout policy and its options, including the method `RequiredAttemptView` that `attempt_views.go` declares on it today (a method moves with its type);
- the error, observer and report types;
- the in-memory attempt store, the reaper port and the failure streak;
- the lockout expiry task: all of `expiry.go`, with `expiry_test.go`.

**What stays in `policy`:**
- `attempt_views.go`, holding `AttemptViewRequirer` and `RequiredAttemptView`, because `Engine` reads them;
- the `AttemptStore` port. The attempt-view contract returns it, so moving it would make `policy` import `lockout`, which imports `policy`: an import cycle. The SQL backends implement it, and `lockout` names it `policy.AttemptStore`.

**Import direction:** `lockout` imports `policy` for `Phase`, `Decision`, `Input`, `ErrConfig`, `ErrPolicyDenied`, `AttemptStore` and the attempt-view types. `policy` never imports `lockout`, so no cycle can form. `policy`'s external tests (`policy_test`) may import `lockout`, which is no cycle.

**Tests:**
- `export_test.go` splits: the `AccountLockoutPolicy` and `MemoryAttemptStore` accessors move to `lockout/export_test.go`.
- The tests of the moved files move with them.
- `policy_test` files that only use lockout as a collaborator (`engine_test.go`, `example_test.go`, `store_failure_test.go`) stay, and import `lockout`. `returned_errors_test.go` moves to `lockout`: its one test exercises the lockout policy's own methods, so it is a test of the moved files. An `Example` function for a lockout name moves to `lockout`'s `example_test.go`, so that it stays attached to its identifier.

**Alternative considered:** move `AttemptStore` to `lockout` and have `AttemptViewRequirer` return `any`. That avoids the cycle, but it weakens a typed contract, which is an API-shape change and out of scope.

| `policy` today | `lockout` |
|---|---|
| `AccountLockoutPolicy`, `NewAccountLockoutPolicy`, `LockoutOption` | `Policy`, `New`, `Option` |
| `WithLockoutCap`, `…CapRetention`, `…Ceiling`, `…Clock`, `…Threshold`, `…Wait`, `…Window`, `…Logger`, `…Observer` | `WithFailureStreakLimit`, `WithFailureStreakRetention`, `WithWindowFailureLimit`, `WithClock`, `WithWaitThreshold`, `WithWait`, `WithFailureWindow`, `WithLogger`, `WithObserver` (the bound names as D15 sets them) |
| `WithSlidingLockout`, `WithAttemptStore` | `WithSliding`, `WithAttemptStore` |
| `LockoutError`, `LockoutObserver`, `LockoutReport`, `LockoutReportKind` | `Error`, `Observer`, `Report`, `ReportKind` |
| `LockoutAtCeiling`, `LockoutCleared`, `LockoutHeld`, `LockoutLocked`, `LockoutReleased` | `ReportAtWindowFailureLimit`, `ReportCleared`, `ReportHeld`, `ReportLocked`, `ReportReleased` |
| `NISTLockoutCap`, `LockoutExpiryTask` | `NISTFailureStreakLimit`, `ExpiryTask` |
| `AttemptStore` | stays `policy.AttemptStore` (see above) |
| `WithAttemptStoreCapacity` | `WithAttemptStoreMaxIdentifiers` (D15) |
| `AttemptReaper`, `FailureStreak`, `FailureStreakStore`, `MemoryAttemptStore`, `NewMemoryAttemptStore`, `MemoryAttemptOption`, `ErrAccountLocked`, `ErrAccountHeld`, `ErrAttemptStoreFull`, `ErrReapUnsupported`, `ErrRetainSinceRequired` | same names in `lockout` |

**Alternative considered:** leave the group in `policy`. That keeps 21 files and the `Lockout…` prefix stutter on every name.

### D4. `storeerr` becomes the parent package `store`

`storeerr.ErrIsolationTooStrong` becomes `store.ErrIsolationTooStrong`. The backends keep their aliases (`sqlstore.ErrIsolationTooStrong`, and the same in `pgxstore` and `gormstore`), so a consumer can match the sentinel from either package.

`session.ErrDeleteDidNotSettle` stays where it is. Where it should live is part of API shape, so it belongs to `idiomatic-api-shape`.

**Alternative considered:** `internal/storekit`. That would force a consumer to import a backend in order to match the sentinel.

### D5. Identical backend helpers move into `internal/storekit`

The helpers listed in Context, together with their `storekit` and `pglimiter` copies, become single `storekit` declarations. Each backend calls those declarations.

Only helpers with identical bodies move. Near-duplicates that differ by driver API stay in their backend. The one exception is a near-duplicate that differs only in how a value is converted for the driver: it is shared, and the conversion is passed in as a parameter (see "As landed"). The store-conformance suites under `test/` prove that nothing changed.

**`txKey` stays in each backend.** Its declarations are identical, but each backend's distinct key type is the guarantee its godoc states: a transaction another backend attaches is never seen. A shared `storekit` key would let one backend's `WithTx` replace another's transaction in a shared context, and the stores of the first would silently run outside it. That is a behaviour change. The existing tests would not catch it: `gorm/tx_test.go` uses a `foreignTxKey` type of its own. The claim is `UNREPRODUCED`, because the merged code does not exist. The scenario that would reproduce it: one context carries both a `pgx` transaction and a `database/sql` transaction, and each backend's stores must still run on their own.

`errPasskeyHandleHeld` and `errStreakContended` carry no package prefix and are unexported, so sharing them changes no text a consumer sees.

**As landed (2026-10-29):**
- `BestEffort`, `ParseUserID`, `CheckUser`, `SurvivingRoles`, `ErrPasskeyHandleHeld`, `ErrStreakContended`, `SQLStater` and `DetachedError` move into `internal/storekit` with their bodies unchanged.
- `DetachedText` takes the backend's list of sentinels to keep as a parameter. The bodies were identical, but each read its own package's list, and the pgx list differs (`pgx.ErrTxClosed`, `pgx.ErrTxCommitRollback` against `sql.ErrTxDone`, `sql.ErrConnDone`). The lists stay in each backend.
- `detached` and the SQLSTATE filter (`isSQLState` in `pgxstore`, `validSQLState` in `sqlstore` and `gormstore`) move as `storekit.Detached(err, kept)` and `storekit.ValidSQLState`. Their bodies were identical, and their only backend-specific input is the list of sentinels to keep, which `Detached` takes as `DetachedText` does. The filter decides which driver-reported text may reach an error, so a single copy keeps the three backends from drifting apart (second PR review, 2026-10-29). Each backend worded `detached`'s godoc differently; `storekit`'s godoc states everything any of them promised.
- `dbFailed` stays in each backend, as `failed(op, storekit.Detached(err, detachedKept))`. `failed` carries the backend's own error prefix.
- **The partial UPDATE of a user is shared by `sqlstore` and `pgxstore`,** as `storekit.Column`, `storekit.UserColumns(u, org, ts)` and `storekit.UpdateUserQuery(set, now, userID)`. This is the exception to "only identical bodies move". The two copies differed only in value conversion: the timestamp goes through each backend's own `nullTs` (`pgtype.Timestamptz` in `pgxstore`), and `pgxstore` passes the user id through `uuidArg`. Those conversions become parameters, as `DetachedText` takes its list. The builder is where column names meet SQL text and the column allow-list holds, so a column added to one copy and not the other would make the two backends write different fields. `gormstore` keeps its own `userColumns`: it builds a `map[string]any` for gorm's `Updates`, which is a different driver API.
- `optionKind` stays in each backend with its constants. It is the vocabulary of each backend's own option plumbing, and moving the type alone would leave `storekit` a bare integer whose values live elsewhere.
- **`storekit`'s refusal tests assert the whole error text** (added 2026-10-29 after the PR review). A refusal of unstorable text names the field, never the value, so the value cannot reach a log through the error (CWE-209). Only an exact-text assertion proves that: a leaked byte or a wrong field name changes the text. A `NotContains` check proves only the absence of the one substring it names, and a `Contains("name")` check also matches `"username"`. The package's other refusal tests already assert exact text; `TestCheckUser`'s refusing cases are brought into line.

**Alternative considered:** a driver-neutral executor port that would remove more of the duplication. It is a redesign, not a move, so it is out of scope.

### D6. Files consolidate into feature families

These rules apply to every package in the core module and the nested modules, except the test module:

1. **File names.** A production file is `<concept>.go` or `<concept>_<aspect>.go`, with the concept first and an underscore, so that `ls` groups each family. Multi-word concepts use the package's own word for them (`magiclink`, `passkey`, `session_bearer`).
2. **Options sit beside their feature.** A feature's `Enable…` function, option type and options live in its family. They go in the feature file, or in `<concept>_options.go` when the feature file would otherwise pass about 800 lines. In `httpsec`, `options.go` keeps only the chain core.
3. **Small files fold into their family.** A production file under about 100 lines merges into its family's main file. `doc.go`, and seams kept deliberately apart, stay as they are.
4. **One test file per production file.**
   - Each production file has at most one `_test.go`, named after it.
   - A test of several features working together goes into the package's `integration_test.go`.
   - Helpers shared by several test files go into `helpers_test.go`.
   - Generated mocks, `example_*_test.go`, `export_test.go` and `main_test.go` keep their own files.
   - In-package tests that must read unexported state go into `<file>_internal_test.go`, beside the external `<file>_test.go`. Go does not let one file hold both packages. Where an `export_test.go` accessor serves just as well, the test moves to the external file instead. Files whose tests differ only by build tag (`_race`, `_norace`) also stay apart.
5. **Shared code is filed by what it is,** not under the first feature that used it.

**Kept apart on purpose:** each backend's `identity_errors.go` fell under the ~100-line threshold once D5 moved its shared helpers out. It stays apart, because folding it into `identity.go` would take that file past rule 2's ~800 lines.

The `httpsec` production map follows. In this map, "§X" means the `Enable…` function, option type and options of feature X, taken out of today's `options.go`.

| Target | From |
|---|---|
| `chain.go` | `chain.go`, `order.go`, `expiry.go`, `refusallog.go`, `now` from `clock.go` |
| `options.go` | chain core of `options.go`, `WithClock` from `clock.go`, `lockout_wiring.go` |
| `exchange.go`, `resolve.go`, `throttle.go`, `guards.go`, `redemption.go`, `doc.go` | unchanged |
| `session.go` | `context.go`, `sessiontouch.go` |
| `errors.go` | `errors.go`, `status.go` |
| `posted.go` | `postedfield.go`, `postedjson.go` |
| `nethttp.go` | `nethttp.go`, `middleware.go` |
| `complete.go` | `logincomplete.go` (the login tail every feature uses), plus `declaresJSON` from `login.go` |
| `login.go`, `login_options.go` | `login.go`; §login, including `WithLoginLifetime` |
| `basic.go`, `bearer.go`, `apikey.go`, `logout.go`, `jwks.go`, `authorization.go` | each file plus its § |
| `password_change.go` | `passwordchange.go` + §password change |
| `magiclink.go`, `magiclink_options.go` | `magiclink.go`; §magic link |
| `mfa_begin.go` | `mfabegin.go`, `mfapath.go` |
| `mfa_verify.go` | `mfaverify.go`, `mfachallengeerr.go`, `mfalisting.go` |
| `mfa_options.go` | §MFA |
| `mfa_enrol.go`, `mfa_enrol_options.go` | `mfaenrol.go`; `mfaenroloptions.go` |
| `passkey.go` | `passkey.go`, `passkeyoptions.go` |
| `passkey_login.go`, `passkey_manage.go` | `passkeylogin.go`; `passkeymanage.go` |
| `passkey_register.go` | `passkeyregister.go`, `passkeyconfirm.go` |
| `oidc.go`, `oidc_options.go`, `oidc_backchannel.go` | unchanged names |
| `oidc_login.go` | `oidc_authorize.go`, `oidc_callback.go` |
| `oidc_redeem.go` | `oidc_redeem.go`, `federated.go` |
| `recovery.go` | `recoverycomplete.go`, `recoverystart.go`, `recoveryhold.go` |
| `recovery_codes.go`, `recovery_gate.go`, `recovery_cooldown.go`, `recovery_options.go` | the matching files today |
| `session_bearer.go`, `session_renewal.go` | `sessionbearer.go`; `renewal.go` |

This brings `httpsec` from 60 production files to 45.

The `oidc` production map follows (31 files to 17):

| Target | From |
|---|---|
| `relying_party.go` | `manager.go`, `options_manager.go` |
| `broker.go` | `broker.go`, `options_broker.go` |
| `broker_provision.go`, `broker_roles.go`, `broker_password.go` | `provision.go` with `mirror.go`; `roles.go`; `passwordclaim.go` |
| `handoff.go` | `handoff.go`, `options_handoff.go`, `handoffstore_memory.go`, `HandoffExpiryTask` |
| `flow.go` | `flow.go`, `flowstore_memory.go`, `FlowExpiryTask` |
| `link.go` | `link.go`, `linkstore_memory.go` |
| `login.go` | `authorize.go`, `callback.go`, `exchange.go` |
| `assurance.go` | `assurance.go`, `assurance_source.go` |
| `verify.go` | `verify.go`, `claims.go` |
| `logout.go` | `logouttoken.go`, `endsession.go` |
| `remote.go` | `keycache.go`, `discovery.go` (documents fetched from a provider) |
| `registry.go`, `ports.go`, `errors.go`, `doc.go` | unchanged (`expiry.go` is dissolved into `flow.go` and `handoff.go`) |

**Every other package** applies the five rules. The dispatch that consolidates a package reports its file map in the same form as the tables above, and the reviewer checks the map against the rules.

**Alternatives considered:**
- **One file per concept.** Files of up to about 3k lines, which also reduces how much work can run in parallel under the file-ownership rule.
- **Renames only.** The naming becomes consistent, but the file count stays the same.

### D7. Tests merge, and same-shaped scenarios become table cases

When the test files of one unit merge, the test functions that call the same SUT become cases of a table. They follow the project's `table-test` rule: an `assert` closure, a `ctx` modifier where the component reads its context, and `t.Context()`.

Five constraints keep the conversion from weakening any test:
- **A case's name keeps its old function's suffix.** `TestMFAVerify_Attempts` becomes `TestMFAVerify/attempts`. Its assertions move into the case's closure unchanged.
- **A function with a structurally different setup stays standalone,** as `table-test` allows, with its one-line comment explaining why.
- **A function that is already a table** may fold into its sibling table, its subtests becoming cases under their own names, since nesting them under the old suffix would add a level that means nothing. Or it stays as it is, with a comment, where folding would make its subtest names collide or need a nested group.
- **Parallelism is preserved, not added.** A case runs `t.Parallel()` only if its original did. Adding concurrency to a test that never ran concurrently is a change in what the test exercises.
- **New cases are limited.** The only new case allowed is the cancelled-context case that `table-test` requires of a context-sensitive table.
- **A new case that fails stops that table's conversion.** The case is not committed, and the defect is reported as `REPRODUCED`, as `defect-claims.md` requires. Fixing it is a behaviour change, which belongs in its own change, decided by the user.

**Alternative considered:** move test functions unchanged, without converting them to tables. That keeps the strictest proof, but it was declined so that `table-test` is applied while each file is being touched anyway.

### D8. Every `Manager` is renamed to what its type is

| Today | New type, constructor, option type |
|---|---|
| `oidc.Manager`, `NewManager`, `ManagerOption` | `RelyingParty`, `NewRelyingParty`, `Option` (main type; see D10) |
| `oidc.HandoffManager`, `NewHandoffManager` | `Handoff`, `NewHandoff` |
| `authenticate.Manager`, `NewManager` | `FirstOf`, `NewFirstOf` |
| `authorize.Manager`, `NewManager` | `FirstOf`, `NewFirstOf` |
| `session.Manager`, `NewManager`, `ManagerOption` | `Sessions`, `New`, `Option` |
| `passkey.Manager` (built by `New`) | `Passkeys` (still built by `New`) |
| `signingkey.KeyManager`, `NewKeyManager` | `Keys`, `New` |
| `apikey.Manager`, `NewManager` | `Keys`, `New` |
| `onetime.Manager`, `NewManager` | `Tokens`, `New` |
| `magiclink.Manager`, `NewManager` | `Links`, `New` |
| `httpsec.WithSessionManager` | `WithSessions` |

`FirstOf` is a type, so its constructor cannot also be called `FirstOf`: Go allows only one package-level identifier of a given name. It is therefore `NewFirstOf(delegates...)`.

Prose names a `Sessions` value the way it names any type: through the method that acts (`[Sessions.Load]` returns …), or as "a [Sessions]" where no single method acts. It never makes "the Sessions" the subject of a sentence ("the Sessions has revoked"). The phase-2 text sweep left such sentences in `session`'s godoc, which the second PR review found on 2026-10-29.

An exported field that holds one of these types is named after the new type too. In the test module, the conformance fixtures' `PasskeyFixture.Manager` becomes `Passkeys` and `OIDCFixture.Manager` becomes `RelyingParty`, and README variables that hold a `RelyingParty` are named `relyingParty`.

**Alternatives considered:**
- **`Chain`.** It clashes in meaning with `httpsec.Chain`.
- **`Composite`.** It names how the type is built rather than what it does.
- **`oidc.Client`.** In Go, "Client" usually names a client for a remote API.

### D9. Outlier names follow the rule the rest of the API keeps

| Today | New |
|---|---|
| `authenticate.JwtOption`, `NewJwtAuthenticator`, `WithJwtVerifier`, `WithJwtIDGenerator` | `JWTOption`, `NewJWTAuthenticator`, `WithJWTVerifier`, `WithJWTIDGenerator` |
| `signingkey.KeySource.GetSigner` and its implementation | `Signer` |
| `signingkey.NewInMemoryKeyStore` | `NewMemoryKeyStore` |
| `policy.ErrMFAEnrollmentRequired` | `ErrMFAEnrolmentRequired` |
| `seal.ErrInvalidConfiguration` | `ErrConfig` |
| `token.VerifyWithAudience`, `…Clock`, `…Issuer`, `…KeySource`, `…MaxTokenSize` | `WithVerifyAudience`, `WithVerifyClock`, `WithVerifyIssuer`, `WithVerifyKeySource`, `WithVerifyMaxTokenSize` |
| `identity.NewUser` (struct) | `UserChange` |
| `passkey.NewCredential` (struct) | `CredentialInput` |
| `scrtyredis.Factory` | `redisstore.LimiterFactory` |
| `policy.UnknownPasswordAge`, `AllowUnknown`, `ChallengeUnknown` | `UnknownAgeMode`, `UnknownAgeAllow`, `UnknownAgeChallenge` |
| `passkey.UVRequired`, `UVPreferred` | `UserVerificationRequired`, `UserVerificationPreferred` |
| `passkey.AwaitingSavedCodes`, `AwaitingEmailCode` | `PendingSavedCodes`, `PendingEmailCode` |
| `httpsec.IssuerSessions`, `AllSessions` | `BackchannelLogoutScopeIssuer`, `BackchannelLogoutScopeAll` |
| `oidc.MatchAny`, `MatchAll` | `AssuranceMatchAny`, `AssuranceMatchAll` |
| `ratelimit.UnavailableFallBackToLocal` | `UnavailableFallbackToLocal` |
| `passkey.NormaliseName` | `NormalizeName` |
| `mfa.MaxEmailCodeFailures` | `MaxEmailCodeAttempts` (it counts attempts charged, as `passkey`'s constant does) |

**Kept on purpose:**
- `sweep.Sweeper`, `clock.Timed`, `notify.NonBlocking`, `recovery.AuthenticatorKind`, `ratelimit.PolicyReporter`, `policy.FederatedAssuranceUser`;
- `passkey.EndOtherSessions` and `KeepOtherSessions` (per-call options that read as English);
- `session.Session`, `id.ID`, `clock.Clock`, `policy.Policy` (the `time.Time` precedent).

### D10. Naming rules applied across the API

**Sentinels drop the package noun:**

| Package | Today | New |
|---|---|---|
| `session` | `ErrSessionExpired`, `ErrSessionNotFound`, `ErrSessionRenewalConflict`, `ErrSessionRenewalRequired`, `ErrSessionReused`, `ErrSessionSuperseded`, `ErrSessionUnreadable` | `ErrExpired`, `ErrNotFound`, `ErrRenewalConflict`, `ErrRenewalRequired`, `ErrReused`, `ErrSuperseded`, `ErrUnreadable` |
| `password` | `ErrPasswordReused`, `ErrPasswordContainsNUL`, `ErrPasswordTooLong` | `ErrReused`, `ErrContainsNUL`, `ErrTooLong` |
| `token` | `ErrTokenInvalid` | `ErrInvalid` |
| `policy` | `ErrPolicyDenied` | `ErrDenied` |

A sentinel that names something other than its package keeps its noun (`identity.ErrUserNotFound`).

**`policy` types drop the `Policy` suffix:**
- `IdleTimeoutPolicy` → `IdleTimeout`, `ConcurrentSessionPolicy` → `ConcurrentSessions`, `PasswordAgePolicy` → `PasswordAge`, each with a matching `New…`.
- `NewMFAPolicy` → `NewMFA`, `NewMFARequirementPolicy` → `NewMFARequirement`.

**Options.**
- **Main type.** A package's main type has the option type `Option` and options named `With<Thing>`.
- **Other types.** Every other configurable type `T` has `<Stem>Option` and `With<Stem><Thing>`. The stem is `T`'s name, or the distinctive part of it that the package already uses (`Throttle` for `mfa.VerifyThrottle`, `Guard` for `httpsec.Guards`, whose `GuardOption` and `WithGuard…` already follow the rule).
- **Packages with no main type** prefix every option.
- **Per-call option types** (`CreateOption`, `RotateOption`, `IssueOption`, `RemoveOption`) are named after the call and stay as they are.
- **A name that already carries the stem and reads as English** keeps its word order (`WithMaxPasswordAge`, `WithIPv6SourcePrefix`).
- **Kept on purpose:** `policy.WithMFAEnrolmentPath` and `WithMFARequiredForAll` configure the MFA requirement with the shorter `MFA` stem. They read as English, and `WithMFARequirementRequiredForAll` would not (decided 2026-10-28).

The main types:

| Package | Main type |
|---|---|
| `apikey` | `Keys` |
| `expiry` | the runner |
| `magiclink` | `Links` |
| `mfa` | `TOTP` |
| `oidc` | `RelyingParty` |
| `onetime` | `Tokens` |
| `outbound` | the client |
| `passkey` | `Passkeys` |
| `recovery` | `Recoverer` |
| `seal` | the sealing stores |
| `session` | `Sessions` |
| `signingkey` | `Keys` |
| `token` | `Generator` |
| `httpsec` | `Chain` |
| `lockout` | `Policy` |
| `pgxstore`, `gormstore`, `sqlstore` | the stores |
| `redisstore` | `LimiterFactory` |
| none | `authenticate`, `identity`, `notify`, `password`, `policy`, `ratelimit` |

The option renames:

| Package | Today | New |
|---|---|---|
| `session` | `WithSessionLogger`; `WithHousekeepingInterval` (MemoryStore) | `WithLogger`; `WithMemoryStoreHousekeepingInterval` |
| `oidc` | `WithAllowedRoles`, `WithClaimMirror`, `WithDefaultRole`, `WithJIT`, `WithJITAllowUnverifiedEmail`, `WithJITEmailDomains`, `WithNameClaim`, `WithPasswordClaim`, `WithPasswordClaimCostRange`, `WithPasswordEncoder`, `WithProvisioner`, `WithRoleClaim`, `WithRoleMapping`, `WithRoleSync` | `WithBroker…` with the same `<Thing>` |
| `oidc` | `WithMaxFlows` | `WithMemoryFlowStoreMaxFlows` |
| `mfa` | `TOTPOption`, `WithTOTPIDGenerator`, `WithTOTPLogger` | `Option`, `WithIDGenerator`, `WithLogger` |
| `mfa` | `ThrottleOption`, `WithVerifyClock`, `WithVerifyLimiter`, `WithVerifyLimiterFactory`, `WithVerifyLogInterval`, `WithVerifyLogger` | `ThrottleOption`, `WithThrottleClock`, `WithThrottleLimiter`, `WithThrottleLimiterFactory`, `WithThrottleLogInterval`, `WithThrottleLogger` |
| `mfa` | `WithoutSessionRevocation` (reset) | `WithoutResetSessionRevocation` |
| `authenticate` | `WithPasswordAuthenticatorLogInterval`, `WithPasswordAuthenticatorLogger`, `WithUsernameInRefusalLogs` | `WithPasswordLogInterval`, `WithPasswordLogger`, `WithPasswordUsernameInRefusalLogs` |
| `policy` | `WithIdlePolicyTimeout`, `WithIdlePolicyAbsoluteTimeout` | `WithIdleTimeout`, `WithIdleAbsoluteTimeout` |
| `policy` | `WithMFAPolicyClock`, `WithMFAPolicyLogInterval`, `WithMFAPolicyLogger`, `WithFederatedChallengeWhenUnmet`, `WithSameChannelEnrolment` | `WithMFAClock`, `WithMFALogInterval`, `WithMFALogger`, `WithMFAFederatedChallengeWhenUnmet`, `WithMFASameChannelEnrolment` |
| `policy` | `WithFederatedAssurance` (MFA requirement) | `WithMFARequirementFederatedAssurance` |
| `recovery` | `WithCodeLimiter`, `WithCodeLimiterFactory`, `WithCodeStore`, `WithLowThreshold`, `WithSetSize` | `WithCodesLimiter`, `WithCodesLimiterFactory`, `WithCodesStore`, `WithCodesLowThreshold`, `WithCodesSetSize` |
| `seal` | `WithEncryptionKey`, `WithRetiredEncryptionKey` | `WithKeyringEncryptionKey`, `WithKeyringRetiredEncryptionKey` |
| `token` | `GenerateOption`; `VerifyOption` | `Option`; `VerifyOption` (the functions as in D9) |
| `passkey` | `WithPasskeyLimit` | `WithPerUserLimit` (matches `ErrPerUserLimitReached`; D15 revises the earlier `WithLimit`) |
| `redisstore` | `WithLimiterClock`, `WithUnavailableProbeInterval` | `WithClock`, `WithProbeInterval` (the same `<Thing>` as the SQL limiters) |
| `httpsec` | `WithAllowedOrigins`, `WithAllowedRedirects`, `WithBindingCookieName` (magic link) | `WithMagicLinkAllowedOrigins`, `WithMagicLinkAllowedRedirects`, `WithMagicLinkBindingCookieName` |
| `httpsec` | `WithBackchannelLogoutPath`, `WithBackchannelLogoutScope`, `WithCallbackSuccess`, `WithHandoffCountRefusals`, `WithHandoffLimiter`, `WithHandoffRateLimit`, `WithHandoffRedeemer` | `WithOIDC…` with the same `<Thing>` |
| `httpsec` | `WithContactResolver`, `WithLabelResolver`, `WithoutEmailConfirmation` (enrolment) | `WithEnrolmentContactResolver`, `WithEnrolmentLabelResolver`, `WithoutEnrolmentEmailConfirmation` |
| `httpsec` | `WithPasswordlessLogin`, `WithPasswordlessPrefix` | `WithPasskeyPasswordlessLogin`, `WithPasskeyPasswordlessPrefix` |
| `httpsec` | `WithRegenerationFreshness` | `WithRecoveryRegenerationFreshness` |
| `httpsec` | `WithChangePasswordEndpoint` | `WithPasswordChangeEndpoint` |

**Typed enum constants carry their type's name, or its distinctive part, as a prefix** (D9 lists the renames).

### D11. Error messages follow the new names

An error string keeps the `"<package>: "` form under the new package name:
- `"pgx: …"` → `"pgxstore: …"`, `"gorm: …"` → `"gormstore: …"`, `"scrtyredis: …"` → `"redisstore: …"`, `"storeerr: …"` → `"store: …"`;
- the lockout messages → `"lockout: …"`.

An identifier that an error string names follows its rename too: lockout's `"WithLockoutCap must be positive"` becomes `"WithFailureStreakLimit must be positive"`, and `(policy.FailureStreakStore)` becomes `(lockout.FailureStreakStore)`. A message names only things a consumer can find.

**A message that stands for another package's sentinel starts with that sentinel's text**, as Go's `%w` wrapping prints it. Only a package's own messages take its own prefix. This is already the convention in the tree: `redisstore` and `pglimiter` report `ratelimit.ErrConfig` as `"ratelimit: invalid configuration: …"`. So:
- lockout's own sentinels and failures read `"lockout: …"` (`ErrAccountHeld`, `"lockout: record a failed attempt"`);
- `lockout.New`'s configuration errors wrap `policy.ErrConfig` and read `"policy: invalid configuration: …"`;
- the refusal for an attempt store that cannot answer (`storeDenied`) stands for `policy.ErrDenied` and reads `"policy: denied by policy: the attempt store could not say how often this identifier has failed"`, as it did before the split. The phase-2 prefix sweep had turned it into `"lockout: denied by policy: …"`, which the PR review found on 2026-10-29.
- **That prefix is built from `policy.ErrDenied.Error()`, not written out,** and the tests derive their expected text the same way. A literal does not follow the sentinel if its text changes. `REPRODUCED` on 2026-10-29 in a disposable export: with `ErrDenied`'s text changed, lockout's suite stayed green, because its expected text was the same literal. `TestStoreDeniedLeadsWithTheDeniedSentinelText` failed with `reason "policy: denied by policy: …" does not lead with "policy: denied: "`, and passed once `storeDenied` built its prefix from the sentinel.

`httpsec`'s configuration error for a lockout policy given an attempt store other than its own names `lockout.Policy.Attempts`, not `Attempts()`. Since the split, that method lives in another package, and a bare `Attempts()` names nothing a consumer can find.

A consumer matches these errors with `errors.Is`, never by text, so the refusal still fails closed whatever it says. The rule keeps the text truthful about which contract the error answers to.

Sentinel identity does not change, so `errors.Is` behaves as before.

This is the one place where a test assertion may change: only the package prefix of an asserted string, and the renamed identifiers inside it. D13 checks this: every changed pair of asserted strings becomes equal once the rename map is applied to the old one.

**Alternatives considered:**
- **Keep the old prefixes.** Packages would then report errors under names that no longer exist.
- **Change only the prefix,** and leave the identifiers inside messages as they were. That is the narrowest assertion change, but consumers would read errors that name options which no longer exist. Declined on 2026-10-28.
- **A `lockout.ErrConfig` that wraps `policy.ErrConfig`,** so lockout's configuration errors could read `"lockout: …"`. It would add exported API to a change that adds none (D13 would report it), and it would break the convention `redisstore` and `pglimiter` follow. Declined on 2026-10-29.

### D12. How the work is carried out

- **Renames go through gopls, not text replacement.** Every identifier rename and package move uses `gopls rename`, or the equivalent refactor, across the whole `go.work` workspace, so every caller in every module is updated.
  - A text sweep afterwards catches what gopls cannot see: doc comments, README, OpenSpec prose, strings, `%T` output and `reflect` uses.
  - That sweep excludes `.claude/.legacy`.
- **Godoc describes the code, not its history.** A comment the change touches names only the new names. No godoc or comment says that something was moved, renamed, merged or split, or names a former package, path or identifier. Comments that already explain the code keep their wording, apart from the names that changed. The history is in the commit messages and in this change's artifacts.
- **Godoc names a method in another package with a doc link,** `[lockout.Policy.Attempts]`, never as a package-qualified call. Where a variable once shared a package's new name, a call such as `lockout.Attempts()` reads as a package function that does not exist. `go doc` and pkg.go.dev resolve a doc link to the method itself.
- **File moves use `git mv`,** so history follows each file.
- **Four phases, in order:**
  1. **Moves.** Directory and module moves (D1, D2, D4, then D3), in a single lane, because a package move rewrites the imports of every caller.
  2. **Renames.** The identifier renames (D8–D10) and the error-prefix change (D11), in a single lane, leaf packages first. A workspace-wide rename touches callers in many packages, so two parallel renamers would edit the same files.
  3. **Families.** File families and table conversion (D6, D7). One lane per package, running in parallel, because these edits stay inside one package.
  4. **Helpers.** The `storekit` de-duplication (D5), in one lane over the three backends.

  Each phase ends with the D13 checks before the next one starts.
- **Two more phases, after the review fixes of groups 8–10:**
  5. **Bound names.** D15's renames, in a single lane, for the same reason as phase 2. They run before any security fix, so the fixes are written against the final names.
  6. **Security fixes.** D16–D20, each test-first from the red test that proved its claim (D15–D20's context). Lanes are split by file ownership in `tasks.md`; D17 follows D19, because it returns D19's unavailable error.

### D13. Proof that nothing broke

These checks run before phase 1 starts, and again after each phase:
1. **Test inventory.**
   - A run of the core module and the nested modules with `go test -json` records every test and subtest name together with its result.
   - For the Docker-backed suites in the test module, `go test -list` gives the top-level names, and CI supplies their results.
   - The new inventory, mapped through D1–D10, must contain every old name: an old function name maps to its D7 case name. Every test must pass.
2. **API inventory.** An old-to-new map of every exported identifier is checked against `golang.org/x/exp/cmd/apidiff` output for each package:
   - every reported removal is a key of the map;
   - every reported addition is a value of the map;
   - nothing else is reported.
3. **Declaration inventory.** Every top-level declaration in every non-generated production file, exported or not, is listed with its package and kind. This covers functions, methods, types, variables, constants and `//go:embed` patterns. After each phase, every baseline declaration maps through the rename map to a declaration that exists. The only allowed absences are the D5 copies, each mapped to its `storekit` successor. This catches code dropped during a file merge that the build, the API diff and the tests would all miss.
4. **Coverage.** No package's statement coverage drops. The conversion in D7 must exercise the same code as before.
5. **Test names.** Test function names that name a renamed type (`TestManager…`, `TestNewJwtAuthenticator`, `TestNormaliseName`) keep their old wording. gopls does not rename them, and renaming them would only churn the test inventory this decision compares. The D7 conversions rename only the functions they fold, through `test` rows of the map.
6. **Assertion review.** Outside D7 and D14, a test diff touches only import paths, identifiers, file placement and D11 prefixes. D14 changes how three test helpers build their HTTP clients and adds the tests that pin it, and changes no existing assertion. A reviewer compares every D7 case's assertions with its original function's.
7. **Gates.** `make check` (gofmt, vet, lint, race tests, `go generate` drift and the layout checks) passes locally where it can, and in CI with the Docker suites.

**Phase 5** runs checks 1–7 unchanged: D15's renames are rows of the rename map like any other.

**Phase 6** changes behaviour, so the no-change checks apply to it only as far as they still can:
- **Test inventory.** Every old name still exists and passes, except the cases D16–D20 name as changing. Each new test is listed with the decision it proves.
- **API inventory.** New identifiers (the waiver options, `ErrUnavailable`, `WithAPIKeyOwners`, the limiter's charge and refund, `storekit`'s column constructors) are `added` rows of the map, each naming its decision. Nothing is removed apart from `storekit.Column`'s exported fields, which become `changed` rows (D16).
- **Assertion review.** A test diff changes an existing assertion only where its decision says so: verifier tests gain an issuer and an audience, or a waiver (D18); the password authenticator's load-failure case expects the unavailable error (D19). A reviewer checks each changed assertion against its decision.
- **Coverage and gates** as in checks 4 and 7.

### D14. The test module's HTTP clients own their transport

Three test-module helpers send through `http.DefaultTransport`: `httpClient` in `test/oidc`, `keycloakBrowser`, and the SMTP helper's message-API reads, which use `http.DefaultClient`. `httptest.Server.Close` calls `CloseIdleConnections` on `http.DefaultTransport`, and that closes every idle connection the transport holds, not only those to the closing server. In a package whose tests run in parallel, one test's server shutdown can therefore close a connection another test has just taken from the pool, and that request fails with `http: CloseIdleConnections called`.

CI saw this once, on 2026-10-29: `TestTestIdentityProviderMalformedTokens/no_subject` failed on a commit that changed only `tasks.md`, and passed on rerun. The flake is `UNREPRODUCED`: 150 plain runs and 100 runs with `-race -cpu 2` passed locally. The mechanism underneath it is deterministic, and that is what the red tests pin: after another server's `Close`, a client on the default transport cannot reuse its idle connection.

**Decision.** Each helper's client sends through a clone of `http.DefaultTransport` (`(*http.Transport).Clone`), and the helper registers the clone's `CloseIdleConnections` with `t.Cleanup`, so a test's connections end with the test. The root test package has one unexported helper for both of its clients. `test/oidc` builds its own, because it imports nothing from the root package. The SMTP helper keeps its client in an unexported field of `SMTPConn`, so `SMTPConn`'s exported shape does not change.

**Default and override.** These are test helpers. No consumer-facing default, option or port changes.

**Alternatives considered:**
- **Disable keep-alives.** Also immune, but every request then opens a connection, and the clients still share state they do not need to share.
- **Stop running the subtests in parallel.** It removes the trigger from one test only, and D7 keeps every test's parallelism as it was.
- **Retry a failed request.** It would also hide a real connection failure a test should see.

### Context for D15–D20: the security review of 2026-10-31

A security review of PR #27 made nine claims. Each was tested in a disposable export of the tree before any decision was taken (`defect-claims`), and the main session reran every red step:

| Claim | Proof | Outcome |
|---|---|---|
| An empty role list on `Update` keeps every grant | The identity-store conformance cases "an empty role list leaves the stored grants untouched" and "a list of only empty names leaves the stored grants untouched" pass on all three backends; `default-identity-store` requires it | Intended. Only the `WithUserRoles` godoc misleads (D16) |
| An API key keeps working for an inactive owner | `TestAPIKey_RefusesKeyOfInactiveOwner` failed: "handler ran for a key issued to a disabled user" | `REPRODUCED` (D17) |
| `token.NewVerifier` checks no issuer or audience by default | `TestVerifier_RefusesTokenForAnotherAudienceWhenNoneConfigured` failed: a token minted for `service-a` verified at a verifier with no audience | Documented default, against the standards (D18) |
| A user-store outage counts as a failed login | `TestBasicAuth_IdentityStoreOutageIsNotACredentialFailure` failed: three outage requests recorded three failures, and the correct password was then refused, "held after 3 consecutive failures" | `REPRODUCED` (D19) |
| The net/http adapter has no trusted-proxy client address | `TestNetHTTPClientAttribution` failed (401 for a valid key behind a proxy, and for a socket peer) | Documented; `trusted-proxy-client-ip` owns it |
| `storekit.Column.Name` reaches the SQL text unchecked | `TestUpdateUserQuery_DoesNotWriteAForeignColumnNameIntoTheSQL` failed: the query contained `role = 'admin'` and `DROP TABLE` verbatim. Every caller passes a literal today | `REPRODUCED` as a hazard this change created (D16) |
| Recovery codes check the limit, then record later | `TestCodes_ConcurrentWrongCodesStayWithinLimit` failed 100 of 100 runs under `-race`: 20 lookups against a limit of 5 | `REPRODUCED` (D20) |
| A full in-memory limiter refuses every new source | `TestMemoryLimiter_Full` already pins it | Documented fail-closed bound |
| API key verification leaks key-ID existence by timing | `TestVerify_DigestWorkIsUniform` showed no digest on a miss, but benchmarks put the miss path slower (201 ns) than a wrong secret (155 ns), from building log attributes; both answer the same 401 | Not reproduced as claimed |

Every red test above becomes its decision's first failing test.

### D15. Names say what they bound

`lockout.WithCap(100)` does not say that it limits consecutive failed logins, in a package that also has a threshold, a ceiling, a window, waits and a store capacity. A sweep of every package's exported API on 2026-10-31 found the same fault elsewhere: a bare quantity word (Cap, Limit, Window, Lifetime, Size, Period) where the package has more than one thing it could bound.

**The lockout family takes the noun it already uses.** The package calls the consecutive count a `FailureStreak`, stores it in a `FailureStreakStore` and refuses a held identifier with `ErrAccountHeld`. Naming the limit after the streak gives option, constant, accessor, record and store one word. Its godoc maps the word to NIST SP 800-63B-4 §3.2.2, which limits "consecutive failed authentication attempts". The user chose this family on 2026-10-31 over NIST's own phrase, which would add a second noun, and over a name for the effect (`WithHoldAfter`), which says less about what is counted.

| Package | Today | New |
|---|---|---|
| `lockout` | `WithCap`, `NISTCap`, `WithCapRetention`, `(*Policy).Cap`, `(*Policy).CapRetention` | `WithFailureStreakLimit`, `NISTFailureStreakLimit`, `WithFailureStreakRetention`, `FailureStreakLimit`, `FailureStreakRetention` |
| `lockout` | `WithCeiling`, `ReportAtCeiling` | `WithWindowFailureLimit`, `ReportAtWindowFailureLimit` |
| `lockout` | `WithThreshold`, `(*Policy).Threshold` | `WithWaitThreshold`, `WaitThreshold` |
| `lockout` | `WithWindow`, `(*Policy).Window` | `WithFailureWindow`, `FailureWindow` |
| `lockout` | `WithAttemptStoreCapacity` | `WithAttemptStoreMaxIdentifiers` |
| `passkey` | `WithLimit`, `ErrLimitReached` | `WithPerUserLimit`, `ErrPerUserLimitReached` |
| `recovery` | `WithDelay`, `WithCompletionWindow`, `WithSessionLifetime`, `Count` | `WithHoldDelay`, `WithHoldCompletionWindow`, `WithPendingSessionLifetime`, `RemainingCodes` |
| `token` | `WithLifetime` | `WithTokenLifetime` |
| `signingkey` | `WithLifetime`, `WithLogSampleWindow` | `WithKeyLifetime`, `WithLogInterval` |
| `onetime` | `WithTTL`, `(*Tokens).TTL` | `WithTokenTTL`, `TokenTTL` |
| `policy` | `(*IdleTimeout).Thresholds` | `Deadlines` |
| `mfa` | `WithPeriod` | `WithTimeStep` |
| `oidc` | `MaxLogoutTokenMaxAge` | `LongestLogoutTokenMaxAge` |
| `notify` | `WithQueueSize`, `(*QueuedSender).QueueSize` | `WithQueueMaxMessages`, `QueueMaxMessages` |
| `httpsec` | `WithEnrolmentSessionTTL` | `WithEnrolmentSessionLifetime` |

`passkey.WithPerUserLimit` revises D10's earlier choice of `WithLimit`: the package also has a registration-challenge limit, so the bare word no longer says which. `token.WithLifetime` and `signingkey.WithLifetime` shared a name for two different lifetimes, a token's validity and a key's publication.

**Vocabulary rules,** added to D10's naming rules so the fault does not return:
- **Limit** names a count per subject (per user, per source, per window); **`Max<Entity>`** names a container's size or a bound on a duration. Cap, Ceiling and Capacity are not used.
- **Timeout** is how long to wait for something: a response, an operation, activity. It also keeps the two session deadlines OWASP's Session Management Cheat Sheet calls the idle and absolute timeouts, so `session.WithIdleTimeout`, `session.WithAbsoluteTimeout` and `policy.WithIdleAbsoluteTimeout` keep their names. **Lifetime** is how long one issued key, token or session lives from its creation. **TTL** is how long a one-time artifact (a challenge, a code, a flow, a handoff) stays redeemable.
- Every log sampler's window is a **`…LogInterval`**.

**Considered and kept:** byte lengths named `Size`, `Length`, `Limit` and `Bytes` each carry a noun (`seal.KeySize`, `WithLoginBodyLimit`, `WithMaxResponseBytes`), and the issuance limits (`WithIssuedCodeLimit`, `WithIssuanceLimit`, `WithMFAChallengeLimit`) each name what they issue. Neither is ambiguous alone, and renaming them would only churn.

**Default and override:** names only. Every option keeps its default, and its godoc still names it.

### D16. Column names reach SQL only from `storekit`, and `WithUserRoles` says what an empty list does

**Columns.** D5 made `storekit.Column` a shared type with an exported `Name`, which `UpdateUserQuery` writes into the statement text. A comment was the only thing keeping caller input out of it. `Column`'s fields become unexported. A column is built only by `storekit`: `UserColumns` for the fields of a `UserChange`, and a new `RoleColumn(value)` for the primary role, which `sqlstore` and `pgxstore` add today with a struct literal. A name is then fixed when `storekit` compiles, and no backend can pass another. This is preferred to an allow-list checked when the query is built, which would add an error path to every update for a mistake the compiler can refuse.

**Godoc.** The `identity.WithUserRoles` godoc says that naming no roles "lets Update tell 'leave the grants alone' apart from 'these are the grants now'", which reads as "an empty list clears the grants". `default-identity-store` requires the opposite, and the conformance suite pins it: on `Update`, a list with no usable role leaves every grant untouched, so a filtered claim can never strip a user's access; on `Provision`, it creates a user with no roles. The godoc says that, in those words.

**Default and override:** none changes. `storekit` is internal.

### D17. API key authentication can require an active owner

A key's principal is "the consumer's own reference for the machine caller", stored and returned unchanged (`api-keys`, "Keys are bound to a service principal"). It need not name a user, so the library cannot load it by default without interpreting consumer data (`library-design` rule 5). The established design had no owner check either. But a consumer whose keys do belong to users has no way to stop them when the user is deactivated, short of revoking each key.

**Decision.**
- **Default:** no lookup, as today. The godoc of `EnableAPIKey` says that deactivating a user then stops none of the keys issued for that reference, and names the option.
- **Override:** `httpsec.WithAPIKeyOwners(identity.UserLoader)`. After a key verifies, its principal reference is loaded with `LoadByUserID`. A user that is not found or not active is refused exactly as a wrong key is, and counted against the source. A loader failure of any other kind returns D19's `authenticate.ErrUnavailable`, answered 503, and is not counted against the source, because the caller's key was not refused.
- A nil loader is a configuration error.

**Departure from the established design,** which had no such check: recorded here, justified by `TestAPIKey_RefusesKeyOfInactiveOwner`.

### D18. A verifier requires an issuer and an audience, or an explicit waiver

`token.NewVerifier` checks the issuer and the audience only when configured, and `token-issuance` says so. Two services that share a key source then accept each other's tokens, which the red test shows. The standards require both checks of a token's recipient:
- RFC 8725 §3.9: the relying party "MUST validate the audience value", and §3.8 the issuer;
- RFC 9068 §4: a resource server's issuer "MUST exactly match", and it "MUST validate" `aud`;
- OpenID Connect Core §3.1.3.7: both, for an ID token.

Microsoft.IdentityModel's `TokenValidationParameters` validates both by default. The user asked on 2026-10-31 for the common security practice, so the verifier follows it.

**Decision.**
- **Default:** `NewVerifier` fails with `token.ErrConfig` unless it has `WithVerifyIssuer` or `WithoutVerifyIssuer()`, and `WithVerifyAudience` or `WithoutVerifyAudience()`.
- **Override:** each waiver. Its godoc states what it gives up: any token signed by a key in the source is accepted whatever its issuer, or whatever its audience.
- Configuring and waiving the same check is a configuration error.
- **An empty issuer or audience is a configuration error,** for the verifier and the generator alike. An empty value would be enforced as the empty string, so two services that each pass an unset setting would mint `iss: ""` and `aud: [""]` and accept each other's tokens, which is D18's threat through a typo (`library-design` rule 6). A consumer who wants no claim uses the waiver. The base rows that pinned an enforced empty value become refusal rows. The V-lane review reproduced this, and the user chose the refusal on 2026-10-31.
- **A value made only of white space counts as empty.** It comes from the same unset setting (an environment variable holding a space), and RFC 7519 compares `iss` and `aud` as exact strings, so it would be enforced literally. The refusal names the waiver. The V-lane review noted the gap, and the user chose the refusal on 2026-10-31. Surrounding white space on a value that is otherwise set is kept: it is the consumer's string (`library-design` rule 5).
- Verification itself is unchanged once configured.
- The library builds no verifier of its own. `httpsec` and `authenticate` take one from the consumer, so the change reaches consumers through their own construction.
- **The generator follows the same rule.** `token.Generator` embeds a `Verifier` and verifies with its own issuer and audience, so a generator used as the bearer's verifier would otherwise skip both checks. `NewGenerator` fails with `ErrConfig` unless it has `WithIssuer` or `WithoutIssuer()`, and `WithAudience` or `WithoutAudience()`. A configured claim goes into every token and is checked on verification. A waived one is neither minted nor checked. V1's implementation surfaced this gap, and the user extended D18 to the generator on 2026-10-31.

**Departure from the established design and from `token-issuance`,** which both skip an unconfigured check: recorded here, justified by `TestVerifier_RefusesTokenForAnotherAudienceWhenNoneConfigured` and the standards above. The tests that build a verifier or a generator with neither gain both, or a waiver where the test is about something else. That includes the two test-module identity-provider helpers that build a generator.

### D19. A user-store outage is unavailable, not a failed credential

The password authenticator returns the uniform failure for a user it could not load, as `authentication` requires, and form login and Basic record every uniform failure against the username and the source. An outage therefore counts as a guess. With a consecutive-failure limit (D15) it holds real accounts, and a hold never expires. The established design also recorded outage failures, but had no hold, so an outage there locked an account only until its window passed.

OWASP's Authentication Cheat Sheet asks for one generic answer to a wrong user, a wrong password and a locked or disabled account. It does not cover a system error, and an outage is the same for every account, so it reveals nothing about one. NIST SP 800-63B-4 §3.2.2 counts failed authentication attempts; an attempt whose authenticator was never checked has not failed.

**Decision.**
- `authenticate.ErrUnavailable` is a new sentinel. The password authenticator returns it, without the driver's text, for a load failure other than "not found". It no longer matches `ErrAuthenticationFailed`.
- It still spends the dummy password work, so timing does not change. The error-level log record stays.
- Form login and Basic authentication refuse with it. They record no failure for the username, count none against the source, clear nothing, and set no `WWW-Authenticate` challenge.
- The public status table maps it to 503.
- D17's owner check uses it the same way.
- **A load that the caller's own cancellation ended is not an outage.** When the request's context has ended and the load fails with that context's error or its cause (`context.Cause`), the password authenticator returns the uniform failure, as before, and the endpoints charge it as before, on a context with its cancellation stripped. A client that hangs up mid-login therefore cannot spend password work that no source pays for. `recovery` already draws the same line (`causedByCaller`). The U-lane review reproduced the gap, and the main session closed it under D19's own wording, which concerns a store outage.
- **A hang-up is logged at debug level, under its own sampler key.** It is not a fault an operator can act on, and under the outage's key a burst of hang-ups would crowd the outage records out of the sampled window. The user chose this on 2026-10-31.
- **Account recovery's password proof** goes through the same password check, so it follows the same rule: an unavailable outcome is answered 503 and counted against neither the user's recovery limit nor the source. U1's implementation surfaced this path, and the user extended D19 to it on 2026-10-31.
- **Default and override:** 503 is the default answer through the default error response. A consumer error handler, which already replaces the default, can answer as it likes. There is no option to count outages as failures: that is the defect.

**Departure from the established design and from `authentication`'s "User store unavailable" scenario,** recorded here, justified by `TestBasicAuth_IdentityStoreOutageIsNotACredentialFailure`. `TestPasswordAuthenticatorDoesNotRevealWhyItFailed`'s load-failure case changes to expect the unavailable error. `TestStatusForErrorCoversEverySentinel` gains its row.

### D20. Limiters charge and refund atomically, and saved recovery codes use it

`recovery.Codes` asks the limiter whether a user is over the limit, looks the code up, and records a failure afterwards. Every presentation in a concurrent burst passes the check before any is recorded. The `ratelimit` guards document the same bound and accept it. Recovery does not document it, and `account-recovery` says a user at the limit is refused. The established design had no recovery codes. scrty's TOTP already avoids the bound by charging the attempt first, in one conditional write, and refunding it on success.

**Decision.** The `ratelimit.Limiter` port gains two methods:

```go
// Charge records one failure for key and reports exceeded=false, or
// reports exceeded=true and records nothing, in one indivisible step.
Charge(ctx context.Context, key string) (r Receipt, exceeded bool, err error)

// Refund removes the failure r recorded, if it is still in the window.
Refund(ctx context.Context, r Receipt) error
```

A `Receipt` is a value carrying the key and the stamp the charge recorded, so a refund removes that failure and no other. An error from `Charge` is treated as a refusal, as `Exceeded`'s is.

- **Implementations:**
  - the in-memory limiter does it under its existing lock;
  - `internal/pglimiter`, shared by `sqlstore` and `pgxstore`, charges with one `INSERT … ON CONFLICT DO UPDATE … WHERE` on the key's `rate_limit_buckets` row (one row per key, with its stamps), so a first charge and a later one take the same statement and no migration is needed. It runs in its own READ COMMITTED transaction, through `Runner.QueryRowReadCommitted`, because the conflicting row's lock and the re-checked `WHERE` give the indivisible step only at that level. On a database whose default isolation is REPEATABLE READ or SERIALIZABLE, a plain statement's concurrent charge fails with a serialization error, which the limiter reports as unavailable. The limiter never joins a consumer's transaction, so nothing of the consumer's is bypassed. The isolation suite pins this (`TestIsolation_RepeatableReadDefault`). A refund removes the receipt's one stamp with `array_position` and slicing, because `array_remove` removes every equal element. The statements live in `internal/pgschema/ratelimit.go`, beside the limiter's other statements;
  - `redisstore` uses one Lua script, which Redis runs atomically. It keeps the store's existing trimming rule (it caps the stamps at the newest `limit`, and trims nothing by window), because a shorter-window instance sharing the key must not disarm a longer one;
  - the `internal/unavailable` decorator passes both through, and charges its local fallback when it has degraded to one. **A refund goes where the breaker's state at refund time sends it,** because a receipt carries no mark of where it was charged: to the backend while the breaker is closed, and while it is open, by mode, to the local fallback, to nothing (allow), or to an unavailable error (refuse). A receipt that crosses an outage's start or end reaches the side that does not hold its failure. There it removes nothing, unless that side holds a failure of the same key in the same microsecond, and never more than one. The failure stays counted until its window passes: the user loses one attempt, the fail-closed direction.
- **A receipt belongs to the limiter that issued it.** It carries the key but not the namespace, so a receipt refunded on another limiter can remove that limiter's same-key, same-stamp failure. `Refund`'s godoc says so.
- **Conformance:** the suite gains a concurrent-charge case and a refund case. Each is seen to fail against a limiter whose charge checks and records in two steps.
- **Callers:** `recovery.Codes` charges before it looks the code up, on a context whose cancellation is stripped, as recording is today, and refunds on a valid code. The source guards keep their check and record.
- **Default and override:** the port has no consumers yet. A consumer limiter must implement both methods atomically, which the port's godoc states as the line its guarantee needs (`library-design` rule 4). `WithCodesLimiter` and `WithCodesLimiterFactory` still replace recovery's limiter.

**Alternatives considered:**
- **Count attempts in the recovery code store,** as TOTP's enrolment store does. Atomic too, but it moves counting out of the limiter, which `account-recovery`'s "Consumer limiter" scenario requires recovery to use.
- **Document the burst bound.** Codes carry 128 bits, so a burst gains nothing practical. But it leaves the spec's promise false.

## Review claims not acted on

- **An empty role list on `Update`.** Intended and specified (`default-identity-store`, "A role list that names nothing leaves grants untouched"). D16 fixes the godoc only.
- **The net/http client address behind a proxy.** Documented behaviour (`httpRequest.ClientIP` reads no forwarding header) and pinned by `TestHTTPRequestClientIP`. `trusted-proxy-client-ip` adds the resolver. A socket peer with no address stays refused, as `rate-limiting`'s "Unattributable sources are refused, not pooled" requires.
- **A full in-memory limiter.** Its fail-closed refusal of new sources is `rate-limiting`'s "A full in-memory limiter refuses new keys and keeps counting held ones". `WithMemoryLimiterMaxKeys` raises the bound, and a shared limiter removes it.
- **API key timing.** The claimed oracle did not hold. A miss is slower than a wrong secret, because the miss path builds log attributes before the logger drops them. The store's own hit and miss also differ. Every refusal is the same 401, and the source guard allows 20 failures a minute. Making the timing uniform would need a dummy lookup and padding, a design change no test calls for.

## Risks / Trade-offs

- **gopls misses a mention it cannot resolve** (prose, strings, `%T`, `reflect`). → The text sweep in D12, and a reviewer search for every old name in the D8–D10 tables.
- **A converted table asserts less than the functions it replaced.** → The case-name mapping, the per-case assertion review and the coverage check in D13. Cases keep their original parallelism.
- **A new cancelled-context case fails** (a real defect). → D7 stops that table, records the defect as `REPRODUCED`, and hands it to the user. It is not fixed in this change.
- **The diff is very large and hard to review.** → One commit per phase and per lane. Each phase is reviewed against its own decisions, and the whole branch is reviewed once at the end.
- **The layout tests hard-code module directories** (D2 lists them). → They are updated in phase 1, and the layout tests prove the new paths before any rename runs.
- **A shared helper merges an identity that was deliberately separate** (`txKey`). → D5 keeps it per backend. The phase-4 review checks every merged declaration's godoc for a "this package alone" guarantee.
- **The main spec names the security policy before it exists.** The "Supported Go releases" text matches `release-readiness`'s, word for word, and names "the security policy", which `release-readiness` writes. If this change is archived first, the main spec names that policy before it exists. → Accepted: the two changes land in order, and 1.27 is the only release either names today.
- **Other branches in flight conflict with the moves.** → The order in `proposal.md`. The moves start from a `main` that has `fix/stabilize-intermittent-tests` merged, and no other change is implemented until this one is merged.
- **Longer import paths** (`authenticate/passkey/webauthn`). → Accepted, in exchange for the concept grouping. Package names stay short.
- **The security fixes widen a PR that was a pure refactor.** Its review can no longer rest on "nothing changed". → Phase 6 runs after every rename. Each fix is its own lane and commit with its own red test, and is reviewed against its own decision (D13, phase 6).
- **A 503 tells an attacker the user store is down** (D19). → Accepted: an outage is the same for every account, and the operator learns of it anyway. One edge remains. If a single account's row fails to load (corrupt data) while others load, that account answers 503 where others answer 401, which reveals that it exists. → Accepted and stated in `ErrUnavailable`'s godoc. Such a row is already an incident the error-level log reports.
- **In a recovery, a 503 from the password proof follows a valid code** (D19). Codes are checked first, so an unavailable outcome there tells the caller its codes were valid. → Accepted: the same store answers the user lookup earlier in the request, so a real outage fails there first. Reaching the password proof's 503 needs the store to answer one load and fail the next within one request.
- **A consumer limiter written against the old port stops compiling** (D20). → There are no consumers yet. The port's godoc states the atomicity it requires, and the conformance suite is how a consumer proves it.
- **Charging before the lookup spends allowance on a request that then fails for another reason** (D20). → The charge is refunded only on a valid code, so an outage during the lookup costs the user one attempt. This is the fail-closed direction `rate-limiting` already takes.
- **Renames collide with the names other active changes were written against** (D15). → Migration Plan step 4 already checks `idiomatic-api-shape` and `key-port-context` against the names that actually land.

## Migration Plan

1. Branch from `main`. `fix/stabilize-intermittent-tests` is already merged and archived.
2. Capture the D13 baseline: test inventory, API inventory and coverage.
3. Run phases 1–4 (D12), with D13 after each.
4. In the same branch, update the repository's own references:
   - the `openspec/config.yaml` context (the module list and the `pkg/` and adapter names);
   - the README;
   - the path and identifier references in the artifacts of the active changes: `trusted-proxy-client-ip`, `release-readiness` (with its tag prefixes and its "Fresh consumer fetches a nested module" scenario), `di-wiring`, `bff-resource-server`, and `minimize-test-containers` once it is on `main`;
   - `idiomatic-api-shape` and `key-port-context`, which are already written against this change's names: they are checked against the names that actually landed, not rewritten.
5. Run the whole-branch review, then merge.

**Rollback:** revert the merge. Nothing is tagged and there are no consumers, so a revert is complete.

## References

### Directory grouping (D1, D3, D4)

**Researched (accessed 2026-10-25):**
- [Organizing a Go module](https://go.dev/doc/modules/layout): a module's packages may be structured hierarchically and nested; supporting packages go in `internal/`.
- [Go blog: Package names](https://go.dev/blog/package-names): a directory only arranges files and implies no relationship between packages; avoid stutter and catch-all packages.
- [volatiletech/authboss](https://github.com/volatiletech/authboss): a flat layout with one package per feature, considered and not chosen.
- [ory/fosite](https://github.com/ory/fosite): a concept-grouped layout (`handler/oauth2`, `handler/openid`, `token`, `storage`).

### Type names (D8, D9, D10)

**Researched (accessed 2026-10-25):**
- [OpenID Connect Core 1.0, Terminology](https://openid.net/specs/openid-connect-core-1_0.html): the Relying Party, also called the Client.
- [zitadel/oidc, package rp](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rp): a Go relying party exported as `RelyingParty`.
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc): no `Manager` type; its parts are named `Provider` and `IDTokenVerifier`.

**Primary documentation:**
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments): initialisms, getters, error strings with a lowercase package prefix.
- [Effective Go: Names](https://go.dev/doc/effective_go#names): getters without `Get`, MixedCaps.

### Adapter package names (D1, D2)

**Researched (accessed 2026-10-25):**
- [alexedwards/scs](https://github.com/alexedwards/scs): storage adapters named `<driver>store` (`pgxstore`, `gormstore`, `redisstore`).

### Lockout split and shared helpers (D3, D5)

Reasoned from scrty's own code and settled specs. On 2026-10-28, gopls references across the `policy` package showed the `AttemptStore` edge, and a declaration-by-declaration comparison of the three backends showed the identical helpers. The godoc of each backend's `txKey` states the per-package guarantee D5 keeps.

**Primary documentation:**
- [The Go Programming Language Specification: Import declarations](https://go.dev/ref/spec#Import_declarations): a package may not import itself, directly or indirectly.
- [Package context: WithValue](https://pkg.go.dev/context#WithValue): a key should be of an unexported type of its own, to avoid collisions between packages.

### Review findings: refusal text, error prefixes, doc links and layout guards (D2, D5, D8, D11, D12)

**Researched (accessed 2026-10-29):**
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html): the weakness storekit's exact-text refusal tests guard against (D5).
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html): error messages that do not reveal implementation details, to avoid information leakage (D5).
- [Go blog: Working with Errors in Go 1.13](https://go.dev/blog/go1.13-errors): programs inspect errors with `errors.Is` and `errors.As`; wrapped text reads "description: wrapped error" (D11).
- [Go Doc Comments](https://go.dev/doc/comment): `[pkg.Name1.Name2]` links to an identifier in another package (D12).

- [`go help work edit`](https://pkg.go.dev/cmd/go#hdr-Edit_go_work_from_tools_or_scripts): `-json` prints the parsed `go.work`, its `Use` entries carrying `DiskPath`. Read from the local go1.27.3 toolchain (D2).

**Primary documentation:**
- [The Go Programming Language Specification: Import declarations](https://go.dev/ref/spec#Import_declarations): an import with no alias declares the package's own name in the file block, so two imports need an alias only when their package names are equal (D2).

The D5 sharing of the SQLSTATE filter, the detached-error builder and the user UPDATE, and the D8 prose rule, are reasoned from scrty's own code and settled specs.

The sentinel-prefix convention in D11 is reasoned from scrty's own code: `ratelimit/redisstore/verify.go` and `internal/pglimiter/runner.go` already follow it.

### Test HTTP clients (D14)

**Primary documentation:**
- `net/http/httptest`, `Server.Close`: its source (`src/net/http/httptest/server.go`, read from the local go1.27.3 toolchain) calls `CloseIdleConnections` on `http.DefaultTransport`. The [package documentation](https://pkg.go.dev/net/http/httptest#Server.Close) does not state it.
- [`http.Transport.Clone`](https://pkg.go.dev/net/http#Transport.Clone): a copy of a transport's settings, which keeps a connection pool of its own.
- [`httptrace.GotConnInfo`](https://pkg.go.dev/net/http/httptrace#GotConnInfo): `Reused` reports whether a request was sent on a connection used before, which the red tests observe.

### Proof of no regression (D13)

**Researched (accessed 2026-10-25):**
- [golang.org/x/exp/cmd/apidiff](https://pkg.go.dev/golang.org/x/exp/cmd/apidiff): "determines whether two versions of a package are compatible". The page does not document its flags; the invocation is to be confirmed when the change is implemented.

### Bound names (D15)

**Researched (accessed 2026-10-31):**
- [NIST SP 800-63B-4, §3.2.2 Rate Limiting (Throttling)](https://pages.nist.gov/800-63-4/sp800-63b.html): the verifier "SHALL limit consecutive failed authentication attempts" on one account to no more than 100. This is the quantity `WithFailureStreakLimit` bounds, and the value of `NISTFailureStreakLimit`.
- [Effective Go: Names](https://go.dev/doc/effective_go#names): exported names are read with their package qualifier, and "long names don't automatically make things more readable". Each new name adds only the noun its package leaves ambiguous.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): names the two session deadlines "Idle Timeout" and "Absolute Timeout", which is why the session timeouts keep their word.

### Security review fixes (D16–D20)

**Researched (accessed 2026-10-31):**
- [RFC 8725, JSON Web Token Best Current Practices, §3.8–3.9](https://www.rfc-editor.org/rfc/rfc8725.html): the relying party "MUST validate the audience value" and must reject a JWT whose issuer is invalid (D18).
- [RFC 9068, JWT Profile for OAuth 2.0 Access Tokens, §4](https://www.rfc-editor.org/rfc/rfc9068.html): a resource server's issuer "MUST exactly match" and it "MUST validate" `aud` (D18).
- [OpenID Connect Core 1.0, §3.1.3.7 ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html): the issuer "MUST exactly match" and the client "MUST validate" the audience (D18).
- [Microsoft.IdentityModel `TokenValidationParameters.ValidateAudience`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.validateaudience) and [`ValidateIssuer`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.validateissuer): both default to `true`, as established practice in a major token library (D18).
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): one generic answer for a wrong user, a wrong password, and a locked or disabled account. It does not address system errors, and it warns that lockout can be used to deny service to other users' accounts (D19).
- [NIST SP 800-63B-4, §3.2.2](https://pages.nist.gov/800-63-4/sp800-63b.html): the limit counts failed authentication attempts (D19, D20).

**Primary documentation:**
- [Redis: scripting with Lua](https://redis.io/docs/latest/develop/interact/programmability/eval-intro/): a script runs atomically, which `redisstore`'s charge relies on (D20).
- [PostgreSQL: INSERT, `ON CONFLICT DO UPDATE`](https://www.postgresql.org/docs/current/sql-insert.html) and [explicit locking](https://www.postgresql.org/docs/current/explicit-locking.html): the conflicting row is locked and its `WHERE` evaluated on it, which serialises concurrent charges of one key; `pglimiter`'s charge relies on it (D20).
- [PostgreSQL: transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html): READ COMMITTED re-checks a concurrently updated row, where REPEATABLE READ and SERIALIZABLE fail with a serialization error, which is why the charge runs in its own READ COMMITTED transaction (D20).
- [PostgreSQL: array functions](https://www.postgresql.org/docs/current/functions-array.html): `array_remove` removes every equal element and `array_position` finds the first, which is why a refund uses the latter (D20).
- [RFC 7519, JSON Web Token, §4.1.1 and §4.1.3](https://www.rfc-editor.org/rfc/rfc7519.html): `iss` and `aud` are case-sensitive strings compared exactly, so a blank value would be enforced literally (D18).

D16 and D17 are reasoned from scrty's own settled specs (`default-identity-store`, `api-keys`) and the established design. D19's debug-level hang-up record is the user's choice of 2026-10-31, reasoned from scrty's own `log-sampling` spec.
