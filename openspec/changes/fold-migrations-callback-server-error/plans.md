# Fold the migration sets and answer unclassified callback failures — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For v0.6.0:
- each migration set becomes one baseline that creates only `scrty_` relations, recorded in a new
  version table;
- an unclassified broker or store failure at a parked login's SSO callback answers `server_error`
  and is logged at error level.

**Architecture:**
- **Migrations:** the two embedded goose sets in `store/migrate` are each replaced by one SQL
  baseline, with no detection of earlier histories. A frozen copy of the v0.5.0 chain, kept as test
  data in the `test` module, proves the baselines produce the same schema.
- **Callback:** `callbackCode` in `httpsec/oidc_login.go` lists its exclusions and answers
  `server_error` by default. The callback writes one `diag.Failure` error record for that answer.

**Tech Stack:** Go 1.27, goose v3.30.1, PostgreSQL 15 and 18 through testcontainers
(`RunTestPostgres`), testify.

**Spec:** `openspec/changes/fold-migrations-callback-server-error/` (`proposal.md`, `design.md`,
`specs/schema-migrations`, `specs/default-identity-store`, `specs/oidc-login`, `tasks.md`).

## Global Constraints

- **Baseline files:** `store/migrate/securitystate/20261126000000_security_state.sql` and
  `store/migrate/identity/20261126000000_identity.sql`. They are the only files in their directories.
  Neither carries a `NO TRANSACTION` annotation.
- **Default version tables:** `migrate.SecurityStateVersionTable = "scrty_state_migrate"` and
  `migrate.IdentityVersionTable = "scrty_identity_migrate"`. The Go names stay the same.
- **No guard:** neither baseline detects or refuses an earlier history (D3).
- **Rollback:** each down section starts with `SET LOCAL lock_timeout = '5s'` and drops everything
  its up section created.
- **Prefix:** every table, index, index-backed constraint and sequence is named `scrty_…`, within
  63 bytes. The security-state set creates twenty-five tables.
- **The callback's default code:** `oidcprovider.CodeServerError` (`"server_error"`).
- **These keep their plain answer:** an unspent flow (`oidc.ErrFlowUnspent`), an invalid state, a
  hung-up caller, `ErrOIDCReauthenticate`, `oidc.ErrUnknownProvider`, an aborted walk, and a login
  that is not parked.
- **The error record for a `server_error` answer:** level ERROR, attributes from
  `diag.Failure(reason, err)`. It holds no handle, state, redirect target or error text.
- **Rules that bind every dispatch:**
  - test-first: the red step fails for the intended reason, and a compile error does not count;
  - the `table-test` skill;
  - `use-testcontainers` (`RunTestPostgres`, never a hand-rolled container);
  - `defensive-coding.md`, `defect-claims.md` and `library-design.md`;
  - the legacy reference is not consulted.
- **Git:** no agent runs `checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and no agent
  edits an OpenSpec artifact.

## Review Focus

1. **Column order:** a baseline that reorders a column passes every store test but breaks
   `INSERT … SELECT *` between `scrty_sessions` and the lineage table. The equivalence test
   compares attnum order.
2. **Identity generation:** `scrty_password_history.seq` must stay `GENERATED ALWAYS AS IDENTITY`.
   A `BY DEFAULT` baseline passes a type-only comparison, so the equivalence test compares
   `attidentity` and `pg_sequence`.
3. **Storage parameters and persistence of `scrty_rate_limit_buckets`** are pinned by a settled
   scenario. The test compares `reloptions` and `relpersistence`.
4. **A partial baseline:** pre-creating the *first* relation proves nothing about atomicity. Tasks
   1 and 2 pre-create the *last* relation and assert that every earlier one is absent.
5. **A consumer-supplied OIDC manager that fails before spending without `ErrFlowUnspent`:** its
   `CallbackResult.Next` is empty, so `parkedDestination` refuses and the plain error stays. Task 3
   pins this.

---

## Lanes, dispatches and models

| Lane | Dispatch | Tasks | Model | Why | Owns | Must not touch |
|---|---|---|---|---|---|---|
| M (migrations) | M1 | 1.1–1.6 | Opus | Reworks thousands of lines of tests and DDL whose mistakes can pass tests, and sets the pattern M2 follows | `store/migrate/**`, `store/gormstore/models_test.go`, `test/testdata/migrate/**`, `test/migrate_*_test.go`, `test/schema_inventory_test.go`, `test/prefix_schema_test.go`, `test/identity_prefix_test.go`, `test/crossbackend/populated_test.go`, `test/baseline_equivalence_test.go` (new), comments in `store/{sqlstore,pgxstore,gormstore}/oidcprovider_device.go` and `store/{sqlstore,pgxstore}/limiter_factory.go` | `httpsec/**` |
| M (migrations) | M2 | 2.1–2.5 | Sonnet (Opus reviewer) | Applies M1's pattern to the identity set; its DDL gets the stronger review | as M1, plus godoc in `store/{sqlstore,pgxstore,gormstore}/identity.go` | `httpsec/**` |
| C (callback) | C1 | 3.1–3.4 | Sonnet | The exclusions are decided (D5), and the log record follows an existing pattern (D7) | `httpsec/oidc_login.go`, `httpsec/oidc_parked_failure*.go` and their `_test.go` files, `httpsec/oidc_login_test.go` | `store/**`, `test/**` |

**Order:**
- M1 and C1 run in parallel. C1 runs only the `httpsec` and adapter legs of Lane C's commands,
  because M1 is rewriting the `test` module in the same tree.
- The main session runs Lane C's `test`-module leg once M1 has landed.
- M2 starts after M1 is verified and reviewed.
- M1 keeps every test package compiling: identity tests still use the identity chain, and the
  constants they use (`versionScrtyPrefix`, `versionIdentityBeforeName`, …) stay until M2.
- 4.1 is written by the main session after M2 and C1. 5.x belongs to the main session.

**Reviewers:** M1 and M2 get Opus reviewers. C1 gets a Sonnet reviewer.

### Scoped verification commands

`dependents <pkg>` lists every package of the current module whose build or tests depend on
`<pkg>`, transitively:

```sh
dependents() { go list -test -f '{{.ImportPath}} {{join .Deps " "}}' ./... \
  | awk -v p="$1" '{for(i=2;i<=NF;i++) if($i==p){print $1; break}}' \
  | sed 's/\.test$//' | sort -u; }
```

**Lane M:**

```sh
go test -race -count=1 ./store/... && go vet ./store/... && test -z "$(gofmt -l store)"
for m in store/pgxstore store/gormstore; do (cd $m && go test -race -count=1 ./... && go vet ./...); done
cd test && pkgs=$(dependents github.com/kartaladev/scrty/store/migrate) && go test -race -count=1 $pkgs && go vet $pkgs && test -z "$(gofmt -l .)"
```

**Lane C:**

```sh
pkgs=$(dependents github.com/kartaladev/scrty/httpsec) && go test -race -count=1 $pkgs && go vet $pkgs && test -z "$(gofmt -l httpsec)"
for m in httpsec/fibersec httpsec/ginsec httpsec/prblmsec; do (cd $m && go test -race -count=1 ./...); done
# test-module leg, run by the main session after M1 lands:
cd test && pkgs=$(dependents github.com/kartaladev/scrty/httpsec) && go test -race -count=1 $pkgs
```

---

### Task 1: Security-state baseline (tasks.md 1.1–1.6, dispatch M1)

**Files:**
- Create: `test/testdata/migrate/v0.5.0/securitystate/*.sql` (eight files, byte-identical to tag `v0.5.0`)
- Create: `test/baseline_equivalence_test.go`
- Create: `store/migrate/securitystate/20261126000000_security_state.sql`
- Delete: the eight current files in `store/migrate/securitystate/`
- Modify: `store/migrate/migrate.go` (constant and godoc), `store/migrate/migrate_test.go`, `store/gormstore/models_test.go`
- Modify or trim: `test/migrate_securitystate_test.go`, `test/schema_inventory_test.go`,
  `test/prefix_schema_test.go`, `test/crossbackend/populated_test.go`,
  `test/migrate_rollback_bound_test.go`
- Modify (comments only): `store/{sqlstore,pgxstore,gormstore}/oidcprovider_device.go`,
  `store/{sqlstore,pgxstore}/limiter_factory.go`

**Interfaces:**
- Produces, for M2: `catalogOf(t *testing.T, db *sql.DB) schemaCatalog`,
  `assertCatalogsEqual(t *testing.T, want, got schemaCatalog)` and the frozen-chain option
  `WithTestPostgresMigrations(os.DirFS("testdata/migrate/v0.5.0"), set, versionTable)`, all in
  `test/baseline_equivalence_test.go`.

- [ ] **Step 1 (1.1): Freeze the chain.** For each `f` in
  `git ls-tree --name-only v0.5.0 store/migrate/securitystate/`, write `git show v0.5.0:$f` to
  `test/testdata/migrate/v0.5.0/securitystate/$(basename $f)`. Verify with `cmp` for each file.
  Expected: no output.

- [ ] **Step 2 (1.2): Write the equivalence test.** Add `TestBaselineMatchesV050Chain` as a table
  over `{set} × {postgres15Image, postgres18Image}`. Each case applies the frozen chain to one
  `RunTestPostgres` database and the embedded set to another, then compares two `schemaCatalog`s.
  A `schemaCatalog` is a set of sorted string lists, read from:
  - `pg_attribute` joined to `pg_class`: `relname, attnum, attname, format_type(atttypid, atttypmod), attnotnull, attidentity, pg_get_expr(adbin, adrelid)`, for `attnum > 0 AND NOT attisdropped`;
  - `pg_class`: `relname, relkind, relpersistence, reloptions`;
  - `pg_indexes`: `indexname, indexdef`, with the schema name removed;
  - `pg_sequence` joined to `pg_class`: `relname, seqtypid, seqstart, seqincrement, seqmin, seqmax, seqcycle`;
  - `pg_constraint`: `conrelid::regclass, contype, pg_get_constraintdef(oid)`, plus `conname` when
    `contype IN ('p','u','x')`.

  Exclude the version table and its own relations.

- [ ] **Step 3: Show the red step.** Delete one column line from a scratch copy of the frozen
  fixture, point the test at it, and run
  `cd test && go test -race -count=1 -run '^TestBaselineMatchesV050Chain$' .`. Expected: FAIL with
  the diff naming that column. Restore the fixture and run again. Expected: PASS (the embedded set
  is still the chain).

- [ ] **Step 4 (1.3): Write the baseline tests.** Add `TestSecurityStateBaseline` as a table with
  an `assert` closure. Each case prepares an empty `RunTestPostgres` database with no migrations,
  then applies the set through goose:
  - `"one migration recorded"`: `scrty_state_migrate` holds exactly one row with
    `version_id > 0`, `20261126000000`.
  - `"beside consumer sessions and users"`: prepare
    `CREATE TABLE sessions(id int); CREATE TABLE users(id int); INSERT INTO users VALUES (1)`.
    Apply succeeds, all twenty-five `scrty_` tables exist, and `users` holds one row.
  - `"last relation present"`: prepare `CREATE TABLE scrty_rate_limit_buckets(id int)`. Apply
    fails, no other `scrty_%` relation exists, and no `version_id > 0` is recorded.
  - `"consumer version table"`: with table `auth_schema_versions`, it records `20261126000000`,
    and `scrty_state_migrate` does not exist.

- [ ] **Step 5: See each fail for its reason.** Run
  `go test -race -count=1 -run '^TestSecurityStateBaseline$' .` on the current set. Expected:
  - `"one migration recorded"` fails with `relation "scrty_state_migrate" does not exist`;
  - `"beside consumer…"` fails with `relation "sessions" already exists`;
  - `"last relation present"` fails because earlier migrations' relations remain (each chain step
    is its own transaction).

  Record the lines.

- [ ] **Step 6 (1.4): Write the baseline.** Create `20261126000000_security_state.sql`.
  - **Up section:** every `CREATE` of v0.5.0's final schema under `scrty_` names. Columns follow the
    chain's attnum order. Keep the identity, persistence and storage parameters.
    `scrty_rate_limit_buckets` comes last.
  - **Down section:** `SET LOCAL lock_timeout = '5s';` then `DROP … IF EXISTS` of every relation.

  Delete the eight earlier files. Set `SecurityStateVersionTable = "scrty_state_migrate"`, with
  godoc naming the default and that any other name may be passed. Run Steps 3 and 5 again.
  Expected: PASS.

- [ ] **Step 7 (1.5): Fold the chain tests.**
  - **Delete** the cases that only walk intermediate versions: SessionFamilies, StrictRotation,
    SessionSignIns, ExistingSessionsReadBack, SignInStateReadsBackEmpty,
    StrictMarkReadsBackUnmarked, the DeviceGrant and SelectedRole upgrade cases,
    `TestPopulatedPrefixRenameKeepsRows`, and the rename cases of `schema_inventory_test.go`.
  - **Keep and repoint at the baseline:**
    - Schema, with the twenty-five-table count;
    - VersionTable;
    - Lifecycle (rollback to zero, "table already dropped", re-apply);
    - GooseDirect;
    - the consumer-schema case of `prefix_schema_test.go`, and the 63-byte check;
    - `TestMigrationRollback_LockBound`'s security-state case, now on the baseline's down section;
    - the synthetic `testdata/migrations/populated` test.
  - **Unit tests:** in `store/migrate/migrate_test.go`, the security-state set holds one `.sql`
    file, and its version table is `scrty_state_migrate`. Update `store/gormstore/models_test.go`
    to read the baseline.
  - **Keep compiling:** leave every identity test and constant compiling.
  - **Verify:** run Lane M's commands. Expected: PASS.

- [ ] **Step 8 (1.6): Fix the comments.** Replace the comments naming
  `20261122000000_oidc_provider_device` or "the scrty_ prefix migration" with the security-state
  baseline. Then run Lane M's vet and gofmt lines. Expected: clean.

- [ ] **Step 9: Report.** Do not commit. Report:
  - files changed, and tests added or removed (names);
  - the red output of Steps 3 and 5;
  - the scoped result;
  - anything left unfinished.

### Task 2: Identity baseline (tasks.md 2.1–2.5, dispatch M2)

**Files:**
- Create: `test/testdata/migrate/v0.5.0/identity/*.sql` (three files) and
  `store/migrate/identity/20261126000000_identity.sql`
- Delete: the three current identity files
- Modify: `store/migrate/migrate.go`, `store/migrate/migrate_test.go`,
  `test/baseline_equivalence_test.go`, `test/migrate_identity_test.go`,
  `test/identity_prefix_test.go`, `test/schema_inventory_test.go`,
  `test/migrate_rollback_bound_test.go`, and the godoc in
  `store/{sqlstore,pgxstore,gormstore}/identity.go`

**Interfaces:**
- Consumes: `catalogOf`, `assertCatalogsEqual` and the frozen-chain option from Task 1.
- Produces: `migrate.IdentityVersionTable == "scrty_identity_migrate"`.

- [ ] **Step 1 (2.1): Freeze the identity chain** as in Task 1 Step 1. Verify with `cmp`. Expected:
  no output.
- [ ] **Step 2 (2.2): Add identity rows** to `TestBaselineMatchesV050Chain`, then show the red
  step by mutation as in Task 1 Step 3. Expected: FAIL naming the mutated column, then PASS once
  the fixture is restored.
- [ ] **Step 3 (2.3): Add `TestIdentityBaseline`**, with cases as in Task 1 Step 4:
  - `"one migration recorded"`, in `scrty_identity_migrate`;
  - `"beside consumer users"`: a consumer `users` table with two rows still has two rows;
  - `"last relation present"`: `scrty_password_history` pre-created, and no other `scrty_%`
    relation exists afterwards;
  - `"live email unique ignoring case"`: `Ana@example.com`, then `ana@example.com`, fails with
    SQLSTATE `23505`;
  - `"deleted user's email is free"`: after the first user's `deleted_at` is set, the insert
    succeeds;
  - `"privilege without scope loads as all"`: insert a `scrty_resource_privileges` row naming no
    scope, then load it through the store with scope `all`.

  Run it and record the failures.
- [ ] **Step 4 (2.4): Write the identity baseline.** Create `20261126000000_identity.sql`:
  - **Up section:** every identity and administration relation under `scrty_` names, in the chain's
    column order, with `scrty_password_history` last. `seq` stays `GENERATED ALWAYS AS IDENTITY`.
  - **Down section:** `SET LOCAL lock_timeout = '5s';` then the drops.

  Delete the three earlier files. Set `IdentityVersionTable = "scrty_identity_migrate"` with its
  godoc. Extend `TestSecurityStateFilesAvoidNoTransactionAnnotation` to `migrate.Identity()`. Run
  Steps 2 and 3 again. Expected: PASS.
- [ ] **Step 5 (2.5): Fold the identity chain tests.**
  - **Delete:** Administration, AdministrationDown, AdministrationPopulated, FailsAtomically (the
    administration-step one), the rename cases of `identity_prefix_test.go`,
    `TestPrefix_SetsIndependent`'s step-wise cases, and the identity constants Task 1 left behind.
  - **Keep, against the baseline:** Independent (with `app_identity_versions`), Schema,
    QueriesMatchSchema, IdentifierLockKeys, and `TestMigrationRollback_LockBound`'s identity case.
  - **Unit tests:** in `store/migrate/migrate_test.go`, the identity set holds one `.sql` file, and
    its version table is `scrty_identity_migrate`.
  - **Verify:** run Lane M's commands. Expected: PASS.
- [ ] **Step 6: Report** as in Task 1 Step 9.

### Task 3: Callback `server_error` (tasks.md 3.1–3.4, dispatch C1)

**Files:**
- Modify: `httpsec/oidc_login.go` (`callbackCode`, its godoc, and the callback's failure branch)
- Test: `httpsec/oidc_parked_failure_internal_test.go` (`TestParkedFailureCode`),
  `httpsec/oidc_parked_failure_callback_test.go` (`TestCallback_ParkedFailureReturnsToLogin`),
  `httpsec/oidc_parked_failure_client_test.go` (`TestParkedFailureToClient`,
  `TestParkedFailure_EventsAndLogs`)

**Interfaces:**
- Consumes: `readCallbackFailure`, `parkedFailureCode`, `oidcprovider.CodeServerError` and
  `diag.Failure`. None of them change signature.
- Produces: `callbackCode(f callbackFailure) string`, and the new `callbackFailure` fields
  `reauthenticate, unknownProvider bool`, set by `readCallbackFailure` through
  `walk.is(ErrOIDCReauthenticate)` and `walk.is(oidc.ErrUnknownProvider)`.

- [ ] **Step 1 (3.1): Change the tests.**
  - **`TestParkedFailureCode`:** the unclassified-broker case (`errBroker`) now asserts
    `code == "server_error"` and `ok == true`. The re-authentication case and a new bare
    `oidc.ErrUnknownProvider` case assert `ok == false`.
  - **`TestCallback_ParkedFailureReturnsToLogin`:** add cases where the library broker's sign-in
    hook `Apply` returns `errors.New("apply down")`, and where the hook returns
    `errors.New("hook down")`. Each answers 303 with
    `Location == <login URL>?req=h-1&error=server_error`, and `h-1` still resumes.
  - **`TestParkedFailureToClient`:** add the `Apply` failure case. It answers 303 to the client
    redirect URI with `error=server_error`, `state=s-1` and `iss`, and `h-1` is spent.
- [ ] **Step 2: See them fail.** Run
  `go test -race -count=1 -run '^(TestParkedFailureCode|TestCallback_ParkedFailureReturnsToLogin|TestParkedFailureToClient)$' ./httpsec/`.
  Expected: the new server_error cases fail on `code ""`, `ok false`, or a non-303 status. The
  re-authentication and unknown-provider cases pass, because they are guards.
- [ ] **Step 3 (3.2): Implement the mapping.** Add the two fields. Make `callbackCode`'s first case
  `f.flowUnspent, f.invalidState, f.hungUp, f.reauthenticate, f.unknownProvider: return ""`, keep
  the refusal and outage cases, and make the default
  `return oidcprovider.CodeServerError`. Rewrite the godoc. Run Step 2's command again. Expected:
  PASS.
- [ ] **Step 4 (3.3): Add the error record.**
  - **Test first:** in `TestParkedFailure_EventsAndLogs`, an `Apply` failure answered
    `server_error` writes exactly one ERROR record whose attributes include `error_type`, with no
    handle, state, redirect target or `"apply down"` text. An `access_denied` refusal writes no
    ERROR record. Run it and see it fail on zero ERROR records.
  - **Then implement:** before `returnParked` in the callback's failure branch, when
    `code == oidcprovider.CodeServerError`, write
    `i.logCallbackRecord(ex, slog.LevelError, callbackReasonServerError, provider, diag.Failure(callbackReasonServerError, err)...)`
    with the new constant `callbackReasonServerError = "server-error"`. Run again. Expected: PASS.
- [ ] **Step 5 (3.4): Pin what keeps its answer.** Add `TestCallback_ParkedFailureReturnsToLogin`
  cases:
  - `"ordinary destination keeps plain error"`: destination `/welcome`, with the `Apply` failure;
  - `"custom manager without marker before spend"`: a manager stub returning `errors.New("x")` with
    an empty `CallbackResult`.

  Both answer the plain error with no `Location`. Confirm that `TestParkedFailure_EventsAndLogs`
  sees no `event.AuthnLoginFail` for the `Apply` failure. Then run Lane C's `httpsec` and adapter
  legs. Expected: PASS.
- [ ] **Step 6: Report** as in Task 1 Step 9.

### Task 4: Documentation (tasks.md 4.1, main session)

- [ ] **Step 1:** write the `CHANGELOG.md` `## [Unreleased]` entries, with the drop statements
  `DROP TABLE IF EXISTS scrty_… CASCADE` and the four version tables. Fix `README.md` where it
  names `goose_security_state`, `goose_identity`, `20261122000000_oidc_provider_device`, the
  fresh-install steps or "Rolling back the rename". Verify with
  `git diff -- CHANGELOG.md README.md`.

### Task 5: Final gate (tasks.md 5.1–5.2, main session)

- [ ] **Step 1 (5.1):** run `make check && make spec-check` after the last edit. Expected: exit 0.
  Read the whole output.
- [ ] **Step 2 (5.2):** dispatch a fresh Opus reviewer over the branch diff, against every
  requirement and scenario of the three delta specs and design D1–D7. The reviewer enumerates
  failures first and edits nothing. Findings go to a fresh dispatch of the owning lane, then Step 1
  runs again.
- [ ] **Step 3:** commit, push and update the pull request.
