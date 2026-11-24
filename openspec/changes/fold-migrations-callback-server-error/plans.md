# Fold the migration sets and answer unclassified callback failures — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** For v0.6.0, Each migration set becomes one baseline that creates only `scrty_` relations,
recorded in a new version table, and an unclassified failure at a parked login's SSO callback
answers `server_error`.

**Architecture:**
- **Migrations:** the two embedded goose sets in `store/migrate` are each replaced by one SQL
  baseline. Each baseline opens with a guard that refuses an earlier history. A frozen copy of the
  v0.5.0 chain, kept as test data in the `test` module, proves the baselines produce the same
  schema.
- **Callback:** `callbackCode` in `httpsec/oidc_login.go` gains `server_error` as its default
  answer after the flow is spent.

**Tech Stack:** Go 1.27, goose v3.30.1, PostgreSQL 15 and 18 through testcontainers
(`RunTestPostgres`), testify.

**Spec:** `openspec/changes/fold-migrations-callback-server-error/` (`proposal.md`, `design.md`,
`specs/schema-migrations`, `specs/default-identity-store`, `specs/oidc-login`, `tasks.md`).

## Global Constraints

- **Baseline files:** `store/migrate/securitystate/20261126000000_security_state.sql` and
  `store/migrate/identity/20261126000000_identity.sql`. They are the only files in their
  directories.
- **Default version tables:** `migrate.SecurityStateVersionTable = "scrty_state_migrate"` and
  `migrate.IdentityVersionTable = "scrty_identity_migrate"`. The Go names stay the same.
- **Guard error text:** `scrty: this database was migrated by a release before v0.6.0; recreate it`.
- **Guard condition:** the earlier default version table (`goose_security_state` or
  `goose_identity`) resolves through `to_regclass` and holds a row with `version_id > 0`.
- **Prefix:** every table, index, index-backed constraint and sequence is named `scrty_…`, within
  63 bytes.
- **Callback code:** the value is `oidcprovider.CodeServerError` (`"server_error"`).
- **These keep their plain answer:** an invalid or unknown state, a flow left unspent
  (`oidc.ErrFlowUnspent`), an aborted walk, a hung-up caller, and a login that is not parked.
- **Rules that bind every dispatch:**
  - test-first: the red step fails for the intended reason, and a compile error does not count;
  - the `table-test` skill;
  - `use-testcontainers` (`RunTestPostgres`, never a hand-rolled container);
  - `defensive-coding.md`, `defect-claims.md` and `library-design.md`;
  - the legacy reference is not consulted for this change.
- **Git:** no agent runs `checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and no agent
  edits an OpenSpec artifact.

## Review Focus

1. **A database with the old version table but an empty history** (only goose's version-0 row) must
   apply. Covered by the "old name chosen as version table" case in Tasks 1 and 2.
2. **A consumer-supplied OIDC manager that fails before spending, without `ErrFlowUnspent`**: its
   `CallbackResult.Next` is empty, so `parkedDestination` refuses and the plain error stays. Task 3
   adds a case that pins this.
3. **Column order:** a baseline that reorders a column passes every store test but breaks
   `INSERT … SELECT *` between `scrty_sessions` and the lineage table. Task 1's equivalence test
   compares attnum order.
4. **Storage parameters of `scrty_rate_limit_buckets`** (fill factor, autovacuum) are pinned by a
   settled scenario and are easy to drop when rewriting the DDL. They are compared by
   `pg_class.reloptions` in the equivalence test.
5. **A partial baseline:** a guard placed after the first `CREATE`, or outside goose's transaction
   (no `NO TRANSACTION` annotation is allowed), would leave relations behind. The atomic-failure
   cases in Tasks 1 and 2 assert that nothing remains.

---

## Lanes, dispatches and models

| Lane | Dispatch | Tasks | Model | Why | Owns | Must not touch |
|---|---|---|---|---|---|---|
| M (migrations) | M1 | 1.1–1.6 | Opus | Reworks thousands of lines of tests and DDL whose mistakes can pass tests; sets the pattern M2 follows | `store/migrate/**`, `test/testdata/migrate/**`, `test/migrate_*_test.go`, `test/schema_inventory_test.go`, `test/prefix_schema_test.go`, `test/identity_prefix_test.go`, `test/crossbackend/populated_test.go`, `test/baseline_equivalence_test.go` (new), godoc in `store/{sqlstore,pgxstore,gormstore}/oidcprovider_device.go` | `httpsec/**` |
| M (migrations) | M2 | 2.1–2.5 | Sonnet | Applies M1's pattern to the smaller identity set | same as M1, plus `store/{sqlstore,pgxstore,gormstore}/identity.go` godoc | `httpsec/**` |
| C (callback) | C1 | 3.1–3.3 | Sonnet | The finding states the fix: one default case plus tests | `httpsec/oidc_login.go`, `httpsec/oidc_parked_failure_*_test.go`, `httpsec/oidc_login_test.go` | `store/**`, `test/**` |

- **Order:**
  - M1 and C1 run in parallel, because their files are disjoint.
  - M2 starts after M1 is verified and reviewed.
  - 4.1 is written by the main session (docs), after M2 and C1.
  - v0.6.0 release preparation is not part of this change; it runs once every v0.6.0 change has merged.
  - 5.x is the main session's.
- **Reviewers:** M1 gets an Opus reviewer. M2 and C1 get Sonnet reviewers.

### Scoped verification commands

**Lane M**, after each dispatch:

```sh
go test -race -count=1 ./store/...
go vet ./store/... && gofmt -l store
cd test && pkgs=$(go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
  | awk '/github.com\/kartaladev\/scrty\/store\/migrate( |$)/{print $1}' | sort -u) \
  && go test -race -count=1 $pkgs && go vet $pkgs && gofmt -l .
```

The `PG_IMAGE`-style second leg is exercised inside the equivalence test itself, which runs on both
`postgres15Image` and `postgres18Image`.

**Lane C:**

```sh
go test -race -count=1 ./httpsec/... && go vet ./httpsec/... && gofmt -l httpsec
for m in httpsec/fibersec httpsec/ginsec httpsec/prblmsec; do (cd $m && go test -race -count=1 ./...); done
cd test && pkgs=$(go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
  | awk '/github.com\/kartaladev\/scrty\/httpsec( |$)/{print $1}' | sort -u) && go test -race -count=1 $pkgs
```

---

### Task 1: Security-state baseline (tasks.md 1.1–1.6, dispatch M1)

**Files:**
- Create: `test/testdata/migrate/v0.5.0/securitystate/*.sql` (eight files, byte-identical to tag `v0.5.0`)
- Create: `test/baseline_equivalence_test.go`
- Create: `store/migrate/securitystate/20261126000000_security_state.sql`
- Delete: the eight current files in `store/migrate/securitystate/`
- Modify: `store/migrate/migrate.go` (constant and godoc), `store/migrate/migrate_test.go`
- Modify or trim: `test/migrate_securitystate_test.go`, `test/schema_inventory_test.go`,
  `test/prefix_schema_test.go`, `test/crossbackend/populated_test.go`,
  `test/migrate_rollback_bound_test.go`
- Modify (godoc only): `store/{sqlstore,pgxstore,gormstore}/oidcprovider_device.go`

**Interfaces:**
- Produces, for M2 to reuse:
  - `catalogOf(t *testing.T, db *sql.DB) schemaCatalog` and
    `assertCatalogsEqual(t *testing.T, want, got schemaCatalog)` in
    `test/baseline_equivalence_test.go`;
  - `frozenChain(set string) postgresMigrations`, the option built with
    `WithTestPostgresMigrations(os.DirFS("testdata/migrate/v0.5.0"), set, "goose_"+…)`;
  - the guard pattern in SQL.

- [ ] **Step 1 (1.1): Freeze the v0.5.0 chain.** Run
  `mkdir -p test/testdata/migrate/v0.5.0/securitystate && for f in $(git ls-tree --name-only v0.5.0 store/migrate/securitystate/); do git show v0.5.0:$f > test/testdata/migrate/v0.5.0/securitystate/$(basename $f); done`.
  Then check the copy with `diff -r <(git archive v0.5.0 store/migrate/securitystate | tar -xO) <(cat test/testdata/migrate/v0.5.0/securitystate/*)`.
  Expected: no output.

- [ ] **Step 2 (1.2): Write the equivalence test.** Add
  `TestBaselineMatchesV050Chain(t *testing.T)` as a table over `{set: "securitystate"} × {postgres15Image, postgres18Image}`.
  - **Databases:** apply the frozen chain to one database and `migrate.SecurityState()` to another
    (two `RunTestPostgres` calls).
  - **`schemaCatalog`:** sorted string lists built from:
    - `information_schema.columns`: `table_name, ordinal_position, column_name, data_type, udt_name, is_nullable, column_default`;
    - `pg_indexes`: `indexname, indexdef`, with the schema name removed;
    - `information_schema.sequences`: `sequence_name, data_type, start_value, increment`;
    - `pg_constraint` joined to `pg_class`: `relname, contype, pg_get_constraintdef(oid)`, plus
      `conname` only when `contype IN ('p','u','x')`;
    - `pg_class`: `relname, reloptions`.
  - **Scope:** exclude the version table and its index and sequence from both catalogs.

- [ ] **Step 3: Run it and see it fail.**
  `cd test && go test -race -count=1 -run '^TestBaselineMatchesV050Chain$' .`
  Expected: it fails with a catalog diff, because the embedded set still records into
  `goose_security_state`, or its catalog differs. A compile error or a container failure is not the
  red step.

  If the current chain already matches the frozen copy (it is the same SQL), the red step must be
  shown another way: comment out one column in a scratch copy of the frozen fixture, see the diff,
  and restore it.

- [ ] **Step 4 (1.3): Write the behaviour tests.** Add `TestSecurityStateBaseline(t *testing.T)` as
  a table with an `assert` closure. Each case prepares an empty database through `RunTestPostgres`
  with no migrations, applies the set through goose with the case's version table, and asserts:
  - `"one migration recorded"`: the default table `scrty_state_migrate` holds exactly one row with
    `version_id > 0`, and it is `20261126000000`.
  - `"beside consumer sessions and users"`: prepare
    `CREATE TABLE sessions(id int); CREATE TABLE users(id int); INSERT INTO users VALUES (1)`. Apply
    succeeds, every `scrty_` table exists, and `users` still holds one row.
  - `"earlier history refused"`: prepare `goose_security_state(version_id bigint, is_applied bool)`
    with the row `(20261124000000, true)`. Apply fails, the error contains
    `migrated by a release before v0.6.0`, no `scrty_%` relation exists, and
    `scrty_state_migrate` holds no row with `version_id > 0`.
  - `"relation already present"`: prepare `CREATE TABLE scrty_sessions(id int)`. Apply fails,
    `scrty_signing_keys` does not exist, and no version is recorded.
  - `"old name chosen as version table"`: apply with version table `goose_security_state` to an
    empty database. It succeeds and `goose_security_state` records `20261126000000`.

- [ ] **Step 5: Run and see each fail for its reason.**
  `go test -race -count=1 -run '^TestSecurityStateBaseline$' .` against the current set.
  Expected:
  - "one migration recorded" fails, with 8 rows in the wrong table;
  - "beside consumer…" fails with `relation "sessions" already exists`;
  - "earlier history refused" fails because applying succeeds or errors with a different message.

  Record each failing line for the report.

- [ ] **Step 6 (1.4): Write the baseline.** Create
  `20261126000000_security_state.sql`.
  - **Up section:** first the guard, then every `CREATE` of v0.5.0's final schema under `scrty_`
    names, with columns in the chain's attnum order and the bucket table's storage parameters.
  - **Down section:** `DROP … IF EXISTS` of every relation, in dependency order.
  - **The guard:**

    ```sql
    -- +goose StatementBegin
    DO $$
    DECLARE earlier boolean := false;
    BEGIN
      IF to_regclass('goose_security_state') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM goose_security_state WHERE version_id > 0)' INTO earlier;
      END IF;
      IF earlier THEN
        RAISE EXCEPTION 'scrty: this database was migrated by a release before v0.6.0; recreate it';
      END IF;
    END $$;
    -- +goose StatementEnd
    ```

  Then delete the eight earlier files, and set
  `SecurityStateVersionTable = "scrty_state_migrate"`. Its godoc must name the default and that a
  consumer may pass any other name.

- [ ] **Step 7: Run Steps 3 and 5 again.**
  Expected: `TestBaselineMatchesV050Chain` (securitystate rows) and `TestSecurityStateBaseline` pass.

- [ ] **Step 8 (1.5): Fold the chain tests.**
  - **Delete** the tests that exist only to walk intermediate versions:
    - in `test/migrate_securitystate_test.go`: SessionFamilies, StrictRotation, SessionSignIns,
      ExistingSessionsReadBack, SignInStateReadsBackEmpty, StrictMarkReadsBackUnmarked,
      DeviceGrant upgrade cases, SelectedRole upgrade cases, and the version constants
      `version*` for removed files;
    - `TestPopulatedPrefixRenameKeepsRows`;
    - the rename cases of `test/schema_inventory_test.go`;
    - the populated-upgrade cases.
  - **Keep and repoint at the baseline:** Schema, VersionTable (default now
    `scrty_state_migrate`, consumer name `auth_schema_versions`), Lifecycle (rollback to zero,
    "table already dropped", re-apply), GooseDirect, the consumer-schema (`search_path`) case of
    `prefix_schema_test.go`, the 63-byte name check, and `TestMigrationRollback_LockBound` if it
    still applies.
  - **`store/migrate/migrate_test.go`:** the security-state set holds exactly one `.sql` file, and
    its version table is `scrty_state_migrate`.
  - **Verify:** run Lane M's scoped commands. Expected: all pass.

- [ ] **Step 9 (1.6): Update the godoc.** Fix the three `oidcprovider_device.go` comments that name
  `20261122000000_oidc_provider_device`, so they name the security-state baseline instead. Then run
  `go vet ./store/... && gofmt -l store`. Expected: clean.

- [ ] **Step 10: Report.** Do not commit. Report:
  - files changed and tests added or removed (names);
  - the red output of Steps 3 and 5;
  - the scoped run's result;
  - anything left unfinished.

### Task 2: Identity baseline (tasks.md 2.1–2.5, dispatch M2)

**Files:**
- Create: `test/testdata/migrate/v0.5.0/identity/*.sql` (three files) and
  `store/migrate/identity/20261126000000_identity.sql`
- Delete: the three current identity files
- Modify: `store/migrate/migrate.go`, `store/migrate/migrate_test.go`,
  `test/baseline_equivalence_test.go`, `test/migrate_identity_test.go`,
  `test/identity_prefix_test.go`, and the identity godoc in `store/{sqlstore,pgxstore,gormstore}/identity.go`
  where it names a version table or a removed migration

**Interfaces:**
- Consumes: `catalogOf`, `assertCatalogsEqual` and `frozenChain` from Task 1, and the guard
  pattern.
- Produces: `migrate.IdentityVersionTable == "scrty_identity_migrate"`.

- [ ] **Step 1 (2.1): Freeze the v0.5.0 identity chain** as in Task 1 Step 1, for
  `store/migrate/identity`. Run the same `diff -r`. Expected: no output.
- [ ] **Step 2 (2.2): Add `{set: "identity"}` rows** to `TestBaselineMatchesV050Chain`, then run
  `-run '^TestBaselineMatchesV050Chain$'`. Expected: the identity rows fail for the reason stated in
  Task 1 Step 3.
- [ ] **Step 3 (2.3): Add `TestIdentityBaseline`**, with cases and assertions like Task 1 Step 4:
  - `"one migration recorded"`, in `scrty_identity_migrate`;
  - `"beside consumer users"`: a consumer `users` table with two rows stays at two rows;
  - `"earlier history refused"`, through `goose_identity`;
  - `"relation already present"`: `scrty_users` pre-created, so `scrty_roles` is absent afterwards;
  - `"live email unique ignoring case"`: inserting `Ana@example.com` and then `ana@example.com` for
    two live users fails with SQLSTATE `23505`;
  - `"deleted user's email is free"`: set `deleted_at` on the first user, and the second insert
    succeeds.

  Run it and record the failures.
- [ ] **Step 4 (2.4): Write the identity baseline.** Create
  `20261126000000_identity.sql`: the guard on `goose_identity`, every identity and administration
  relation under `scrty_` names in the chain's column order, and the down section. Delete the three
  earlier files. Set `IdentityVersionTable = "scrty_identity_migrate"` with its godoc. Run Steps 2
  and 3 again. Expected: pass.
- [ ] **Step 5 (2.5): Fold the identity chain tests.**
  - **Delete:** Administration, AdministrationDown, AdministrationPopulated, FailsAtomically (the
    administration-step one), the rename cases of `identity_prefix_test.go`, and
    `TestPrefix_SetsIndependent`'s step-wise cases.
  - **Keep, against the baseline:** Independent (with the consumer-named `app_identity_versions`),
    Schema, QueriesMatchSchema, IdentifierLockKeys.
  - **`store/migrate/migrate_test.go`:** the identity set holds exactly one `.sql` file, and its
    version table is `scrty_identity_migrate`.
  - **Verify:** run Lane M's scoped commands. Expected: all pass.
- [ ] **Step 6: Report** as in Task 1 Step 10.

### Task 3: Callback `server_error` (tasks.md 3.1–3.3, dispatch C1)

**Files:**
- Modify: `httpsec/oidc_login.go:291-306` (`callbackCode` and its godoc)
- Test: `httpsec/oidc_parked_failure_internal_test.go` (`TestParkedFailureCode`),
  `httpsec/oidc_parked_failure_callback_test.go` (`TestCallback_ParkedFailureReturnsToLogin`),
  `httpsec/oidc_parked_failure_client_test.go` (`TestParkedFailureToClient`,
  `TestParkedFailure_EventsAndLogs`)

**Interfaces:**
- Consumes: `readCallbackFailure`, `parkedFailureCode`, `oidcprovider.CodeServerError`. None of
  these change signature.
- Produces: `callbackCode(f callbackFailure) string`, which returns `CodeServerError` in its
  default case.

- [ ] **Step 1 (3.1): Change the tests.**
  - **`TestParkedFailureCode`:** the existing unclassified-broker case (`errBroker`) must now
    assert `code == "server_error"` and `ok == true`. Add the case `"flow unspent stays"`, where
    `errors.Join(errStore, oidc.ErrFlowUnspent)` gives `ok == false`.
  - **`TestCallback_ParkedFailureReturnsToLogin`:** add cases where the broker returns an opaque
    error. Use the library broker with a sign-in hook whose `Apply` returns
    `errors.New("apply down")`, and another case whose hook itself returns
    `errors.New("hook down")`. Each must answer `303` with
    `Location == <login URL>?req=h-1&error=server_error`, and the request `h-1` must still resume.
  - **`TestParkedFailureToClient`:** add a case for the `Apply` failure. It must answer 303 to the
    client's redirect URI with `error=server_error`, `state=s-1` and `iss`, and `h-1` must be spent.
- [ ] **Step 2: Run and see them fail.**
  `go test -race -count=1 -run '^(TestParkedFailureCode|TestCallback_ParkedFailureReturnsToLogin|TestParkedFailureToClient)$' ./httpsec/`
  Expected:
  - the new cases fail on `code ""` / `ok false`, and on a non-303 status (the plain error);
  - the `"flow unspent stays"` case passes already, which is a guard rather than a red step.
- [ ] **Step 3 (3.2): Implement.** In `callbackCode`, replace `default: return ""` with
  `default: return oidcprovider.CodeServerError`. Leave the first case
  (`flowUnspent, invalidState, hungUp`) first. Rewrite the godoc to say that every failure after the
  flow is spent that matches no listed code is `server_error`, and that the four exclusions keep
  their answer. Run Step 2's command again. Expected: PASS.
- [ ] **Step 4 (3.3): Pin the exclusions and events.**
  - **`TestParkedFailureCode`:** confirm the invalid-state, hung-up and aborted-walk cases still
    assert `ok == false`.
  - **`TestCallback_ParkedFailureReturnsToLogin`:** add `"ordinary destination keeps plain error"`
    (destination `/welcome`, the `Apply` failure) and
    `"custom manager without marker before spend"` (a manager stub returning `errors.New("x")` with
    an empty `CallbackResult`). Both answer the plain error, with no `Location`.
  - **`TestParkedFailure_EventsAndLogs`:** an `Apply` failure emits no `event.AuthnLoginFail`, and
    exactly one sampled record naming `server_error`.
  - **Verify:** run Lane C's scoped commands. Expected: all pass.
- [ ] **Step 5: Report** as in Task 1 Step 10.

### Task 4: Documentation (tasks.md 4.1)

- [ ] **Step 1 (4.1, main session): Write the docs.**
  - **`CHANGELOG.md` → `## [Unreleased]`:**
    - `Changed` (breaking): the baselines, the new version tables, and the refusal of earlier
      databases, with the drop statements: every `scrty_%` relation, `goose_security_state` and
      `goose_identity`.
    - `Fixed`: the shared-schema `users` collision, and parked callback failures answering
      `server_error`.
  - **`README.md`:** fix every mention of `goose_security_state`, `goose_identity` or the upgrade
    path.
  - **Check:** `git diff -- CHANGELOG.md README.md`.

### Task 5: Final gate (tasks.md 5.1–5.2, main session)

- [ ] **Step 1 (5.1):** run `make check && make spec-check` after the last edit. Expected: exit 0.
  Read the whole output.
- [ ] **Step 2 (5.2):** dispatch a fresh Opus reviewer over the branch diff, against every
  requirement and scenario in the change's three delta specs and design D1–D6. The reviewer
  enumerates failures first and edits nothing. Fix its findings by a fresh dispatch of the owning
  lane, then repeat Step 1.
- [ ] **Step 3:** commit, push the branch and update the pull request. The change ships in v0.6.0; the maintainer tags.
