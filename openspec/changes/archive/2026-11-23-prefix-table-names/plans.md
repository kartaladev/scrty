# scrty_ Table Prefix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Ticking boxes in `tasks.md` is the main session's job alone.

**Goal:** Rename every table, index, index-backed constraint and sequence that scrty's two migration
sets create to `scrty_<former name>`, through one new migration per set. Move every statement, model
and test to the new names.

**Architecture:** Each set gets `20261124000000_scrty_prefix.sql`. It holds an explicit, reviewable
list of `ALTER TABLE/INDEX/SEQUENCE … RENAME` statements under `SET LOCAL lock_timeout = '5s'`, and
a down section that reverses them. A shared relation inventory in the `test` module is the source of
truth for the catalog tests. `internal/pgschema` and the gorm models move to the new names, and a
Docker-free guard test stops a statement from naming an old table.

**Tech Stack:** Go 1.27, PostgreSQL 15 and 18 via testcontainers (`test.RunTestPostgres`), goose v3
providers, plain SQL migrations.

**Spec:** `openspec/changes/prefix-table-names/`: `proposal.md`, `design.md` (D1–D8, Failure modes
F1–F14), `specs/schema-migrations/spec.md`, `specs/default-identity-store/spec.md`, `tasks.md`.
Every plan task names the `tasks.md` items it covers.

## Global Constraints

- **Test-first, always** (`golang-tdd.md`): write the test, run it, and see it fail **for the
  intended reason**. A compile error is not a red step. Then implement, and report the red output.
- **Table tests** follow the `table-test` skill (`assert` closure, `ctx` modifier, `t.Context()`).
  **Databases** follow `use-testcontainers`: use `test.RunTestPostgres` and the existing helpers in
  `test/migrate_securitystate_test.go` (`provider`, `migrated`, `queryStrings`, `runDownSection`,
  `freshSecurityState`, `regclassExists`, `appliedVersionCount`). No new container helper.
- **Defensive coding** (`defensive-coding.md`) is binding. Every failure mode in design.md that a
  task touches is tested in that task.
- **Released migrations are never edited.** That covers every file under `store/migrate/` except
  the two new ones, and also the unreleased `20261122000000_oidc_provider_device.sql` (design D5).
- **Exact values:**
  - prefix `scrty_`, fixed;
  - new migration version `20261124000000` in both sets, file name `20261124000000_scrty_prefix.sql`;
  - `SET LOCAL lock_timeout = '5s'` as the first statement of each Up section;
  - version tables unchanged: `goose_security_state`, `goose_identity`;
  - the identity sequence `password_history_seq_seq` → `scrty_password_history_seq_seq`;
  - names at most 63 bytes (today's maximum prefixed name is 53);
  - inventory size: 32 tables (25 security-state, 7 identity) and 104 indexes, 52 of them backing a
    primary key or unique constraint.
- **Index-backed constraints are renamed through `ALTER INDEX`**, never `RENAME CONSTRAINT` as
  well: PostgreSQL renames the constraint with its index. NOT NULL constraint names are left alone
  (D3).
- **No blanket search-and-replace.** `sessions`, `users`, `roles` and `groups` are also Go
  identifiers, sweep task names (`expiry/sweep`), OIDC claim names and spec prose. Change a name
  only where it is a table, index or sequence in SQL, or a gorm `TableName()`.
- **No legacy citations** (`legacy-reference.md`).
- **Agents never edit `openspec/`**, never run `git checkout --`, `restore`, `reset --hard`,
  `stash` or `clean`, and never commit.

### Lanes, dispatches and models

The work is one lane, run as three sequential dispatches. It does not split:

- every dispatch edits the `test` module's migration tests and shares the inventory file;
- dispatch C's statement changes are meaningless before the migrations exist.

| Dispatch | Plan tasks (`tasks.md`) | Model | Why | Reviewer |
|---|---|---|---|---|
| A | Tasks 1–2 (1.1, 2.1–2.5) | Sonnet | Mechanical rename list against a catalog test; the lock test is a known pattern (hold a lock in a tx, expect SQLSTATE 55P03) | Sonnet |
| B | Task 3 (3.1–3.3) | Sonnet | Same pattern for the identity set | Sonnet |
| C | Tasks 4–5 (4.1–4.6) | Sonnet | Literal renames across files the guard and the suites check; escalate to Opus if the consumer-schema test (4.3) needs a design choice | Sonnet |

Between A and C the store suites are red, because the schema has moved and the statements have
not. A and B verify only their migration tests. C restores every scoped suite.

### Verification during the change

The `test` module is a separate workspace module, so commands in it run from `test/`.

| Dispatch | Run |
|---|---|
| A, B | `go test -count=1 ./store/migrate/...` and `(cd test && go test -race -count=1 -run 'TestRelationInventory\|TestSecurityStateMigrations\|TestIdentityMigrations\|TestGooseDirect\|TestSchemaSnapshot' . ./crossbackend/...)` |
| C | `go test -race -count=1 ./internal/pgschema/... ./store/...`, `(cd store/pgxstore && go test -race -count=1 ./...)`, `(cd store/gormstore && go test -race -count=1 ./...)`, `(cd test && go test -race -count=1 ./...)` |

C runs the whole `test` module because every package in it depends on the renamed schema
(`test-scope.md`: transitive dependents are never skipped). Every dispatch also runs `go vet` and
`gofmt -l` on what it touched. The full gate (`make check`, `make spec-check`) runs once, at task
5.1, in the main session.

## Review Focus

1. **Rollback after a table was dropped.** The existing spec scenario "Table already dropped" requires
   rollback to zero to succeed when a table is gone. The new Down section must therefore use
   `ALTER TABLE IF EXISTS`, `ALTER INDEX IF EXISTS` and `ALTER SEQUENCE IF EXISTS`. The Up section
   stays strict, with no `IF EXISTS`, so a missing relation fails the upgrade. Pinned in Task 2,
   step 7.
2. **PostgreSQL 15 and 18 produce the same inventory.** Index and constraint names must not differ
   by version. Pinned by running Task 1's test under both images.
3. **The limiter's `to_regclass` check moves with the table.** `LimiterServerFacts` must resolve
   `scrty_rate_limit_buckets`. Otherwise `Verify` would refuse every correctly migrated database.
   Pinned by Task 4's consumer-schema test, which runs `Verify` on a migrated schema.
4. **The lock bound actually applies.** `SET LOCAL` must run inside the migration's transaction,
   before the first `ALTER`. Pinned by Task 2's lock test, with its red step proving the test
   notices the bound's absence.
5. **Blanket replace damage.** A sweep task or claim named `sessions` or `groups` must keep its name.
   Pinned by Task 4, step 9: the expiry-sweep and userinfo suites stay green unchanged.

---

### Task 1: Relation inventory (tasks.md 1.1)

**Files:**
- Create: `test/schema_inventory_test.go`

**Interfaces:**
- Produces:
  - `var securityStateInventory = relationInventory{Tables: []string{…25}, Indexes: []string{…},
    Sequences: nil}`
  - `var identityInventory = relationInventory{Tables: []string{…7}, Indexes: []string{…},
    Sequences: []string{"password_history_seq_seq"}}`
  - `type relationInventory struct{ Tables, Indexes, Sequences []string }`
  - `func catalogRelations(t *testing.T, db *sql.DB) relationInventory`, which lists the current
    schema's tables (`relkind 'r'`), indexes (`'i'`) and sequences (`'S'`), each sorted, excluding
    the version tables and their indexes.

- [ ] **Step 1:** Write `TestRelationInventory`, a table test with one case per set and per image
  (postgres 15 and 18). Each case applies the set up to the version before `20261124000000` and
  asserts `catalogRelations(t, db)` equals the set's inventory. Start with empty inventories.
- [ ] **Step 2:** Run `(cd test && go test -run TestRelationInventory -count=1 .)`. Expected: FAIL,
  and the diff lists every name.
- [ ] **Step 3:** Fill both inventories from the diff. Check the totals: 25 + 7 tables and 104
  indexes.
- [ ] **Step 4:** Run the test again. Expected: PASS on both images.

### Task 2: Security-state rename migration (tasks.md 2.1–2.5)

**Files:**
- Create: `store/migrate/securitystate/20261124000000_scrty_prefix.sql`
- Modify: `test/migrate_securitystate_test.go` (schema checks, `pg_indexes` list, the
  `Lifecycle` test's dropped table), `test/testutils_postgres_test.go` (snapshot names),
  `test/testdata/migrations/populated/*.sql`, `test/crossbackend/populated_test.go`
- Test: `test/schema_inventory_test.go` (new tests below)

**Interfaces:**
- Consumes: `relationInventory`, `catalogRelations` (Task 1).
- Produces: `func prefixed(inv relationInventory) relationInventory`, which maps every name to
  `"scrty_" + name`, and `func catalogSnapshot(t *testing.T, db *sql.DB) []string`, which renders
  the existing tables, columns, indexes, constraints and sequences checks as sorted strings. Task 3
  reuses both.

- [ ] **Step 1:** Write `TestSecurityStatePrefix_Catalog`. At the latest version,
  `catalogRelations` equals `prefixed(securityStateInventory)`, every name is ≤ 63 bytes, and
  `appliedVersionCount(t, db, "goose_security_state")` includes `20261124000000`.
- [ ] **Step 2:** Run it focused. Expected: FAIL listing `sessions` and the other unprefixed names.
- [ ] **Step 3:** Write the migration. The Up section is `SET LOCAL lock_timeout = '5s';`, then one
  `ALTER TABLE <t> RENAME TO scrty_<t>;` per inventory table, then one
  `ALTER INDEX <i> RENAME TO scrty_<i>;` per inventory index. The Down section reverses them in
  reverse order, with `IF EXISTS` (Review Focus 1). Add a header comment saying what it renames,
  that it is catalog-only, and that old replicas must be stopped first (D7).
- [ ] **Step 4:** Run step 1's test. Expected: PASS on 15 and 18.
- [ ] **Step 5:** Update `securityStateSchemaChecks`, the `pg_indexes` expectations, the snapshot in
  `testutils_postgres_test.go`, and the table that `TestSecurityStateMigrations_Lifecycle` drops, to
  the new names. Run `TestSecurityStateMigrations` and `TestGooseDirect`. Expected: they FAIL before
  the edit and PASS after.
- [ ] **Step 6:** Write `TestSecurityStatePrefix_Failures`, a table test with three cases. Each
  starts at the version before the rename.
  - **lock held:** a second connection runs `BEGIN; LOCK TABLE sessions IN ACCESS SHARE MODE`. Up
    returns an error whose `pgconn.PgError.Code` is `55P03` within 10 s. Then `regclassExists(t,
    db, "sessions")` is true and no version `20261124000000` is recorded. After the lock is
    released, Up succeeds.
  - **name taken:** `CREATE TABLE scrty_sessions(x int)` before Up. Up fails, `sessions` still
    exists, `scrty_sessions` still has its single column `x`, and no version is recorded.
  - **partial:** covered by the name-taken case, because the failure comes after the
    `sessions`-preceding renames. Assert that the first table in the list keeps its old name.

  Red: delete the `SET LOCAL` line temporarily and see the lock case hit its 10 s deadline. Restore
  the line, and see it pass.
- [ ] **Step 7:** Write `TestSecurityStatePrefix_Rollback`.
  - `catalogSnapshot` at the version before the rename equals the snapshot after Up then down by one.
  - DownTo(0) after `DROP TABLE scrty_sessions` succeeds, which is the "Table already dropped"
    scenario.
  - Re-applying gives the prefixed catalog.

  Red: remove one Down statement and see the test name the relation left behind. Restore it.
- [ ] **Step 8:** Populated rename. Update the populated fixture SQL to `scrty_` names, and add a
  case to `test/crossbackend/populated_test.go`. It seeds rows in sessions, signing keys,
  `op_grants`, `op_device_authorizations` and `rate_limit_buckets` at the version before the
  rename, applies the rename, and reads each row back through the sql store. Run
  `(cd test && go test -race -count=1 ./crossbackend/...)`. Expected: PASS. The red step is the
  run before the fixture rename, which fails on `relation "sessions" does not exist`.
- [ ] **Step 9:** Run dispatch A's verification row.

### Task 3: Identity rename migration (tasks.md 3.1–3.3)

**Files:**
- Create: `store/migrate/identity/20261124000000_scrty_prefix.sql`
- Modify: `test/migrate_identity_test.go` (`identitySchemaChecks`, the `pg_indexes` list,
  `TestIdentityQueriesMatchSchema`'s table names)
- Test: `test/schema_inventory_test.go`

**Interfaces:**
- Consumes: `identityInventory`, `prefixed`, `catalogRelations`, `catalogSnapshot` (Tasks 1–2).

- [ ] **Step 1:** Write `TestIdentityPrefix_Catalog`, the Task 2 step 1 assertions against
  `identityInventory` and `goose_identity`, plus
  `pg_get_serial_sequence('scrty_password_history','seq') = 'public.scrty_password_history_seq_seq'`
  (use `current_schema()` for the qualifier). Run it. Expected: FAIL listing `users`.
- [ ] **Step 2:** Write the identity migration, Task 2 step 3's shape plus
  `ALTER SEQUENCE password_history_seq_seq RENAME TO scrty_password_history_seq_seq;`. Run the test.
  Expected: PASS.
- [ ] **Step 3:** Update the identity schema checks to the new names. Run `TestIdentityMigrations`
  and `TestIdentityQueriesMatchSchema`. Expected: PASS.
- [ ] **Step 4:** Write `TestIdentityPrefix_Populated`. Seed a user, a role grant and three history
  entries before the rename, apply it, read them back through `sqlstore.IdentityStore`, record a
  fourth entry, and assert that it is newest. Red: drop the `ALTER SEQUENCE` line and see step 1's
  sequence assertion fail. Restore it.
- [ ] **Step 5:** Write `TestPrefix_SetsIndependent`, a table test with two cases.
  - **security-state renamed, identity not:** security-state catalog and versions are as expected,
    the identity catalog is unprefixed, and the identity rename then changes no security-state
    relation.
  - **identity rename rolled back:** only the identity relations revert, and the
    `goose_security_state` rows are unchanged.

  Run it. Expected: PASS.
- [ ] **Step 6:** Run dispatch B's verification row.

### Task 4: Code and tests on the new names (tasks.md 4.1–4.6)

**Files:**
- Modify:
  - `internal/pgschema/*.go` (every statement constant, `LimiterTable`, `LimiterServerFacts`);
  - `store/gormstore/models.go`;
  - `store/sqlstore/limiter.go`, `store/sqlstore/limiter_factory.go`, `store/pgxstore/doc.go`,
    `store/pgxstore/limiter.go`, `store/pgxstore/limiter_factory.go` (godoc and error text);
  - every `test/**` file whose SQL names a table, including `test/gormstore/broken_test.go`'s
    `TableName`s;
  - `README.md`, `CHANGELOG.md`.
- Create: `internal/pgschema/prefix_test.go`, `test/prefix_schema_test.go`

**Interfaces:**
- Consumes: the migrations from Tasks 2–3.
- Produces: `pgschema.LimiterTable == "scrty_rate_limit_buckets"`.

- [ ] **Step 1:** Write `TestStatementsUsePrefixedTables` in `internal/pgschema/prefix_test.go`. It
  parses the package's own `.go` files with `go/parser`, collects every exported `const` string, and
  fails for any match of
  `(?i)\b(FROM|INTO|UPDATE|JOIN|TABLE|to_regclass\(')\s*(<inventory table names>)\b`. The test
  holds its own copy of the 32 old table names, because the inventory lives in another module.
- [ ] **Step 2:** Run `go test -run TestStatementsUsePrefixedTables -count=1 ./internal/pgschema/`.
  Expected: FAIL listing the constants.
- [ ] **Step 3:** Rename the tables in every statement, `LimiterTable` and `LimiterServerFacts`. Run
  it again. Expected: PASS. Run `go test -count=1 ./internal/pgschema/`. Expected: PASS.
- [ ] **Step 4:** Change every gorm `TableName()` to return the `scrty_` name, and keep the godoc
  promise about naming strategies. Red: before the change,
  `(cd test && go test -count=1 ./gormstore/...)` fails on missing relations. After it, PASS.
- [ ] **Step 5:** Move the remaining `test/**` SQL to the new names (Global Constraints: no blanket
  replace). Run `(cd test && go test -race -count=1 ./...)`. Expected: PASS.
- [ ] **Step 6:** Write `TestPrefix_ConsumerSchema`. Create schema `auth`, open a pool with
  `search_path=auth`, apply both sets there, and run one round-trip through the sql, pgx and gorm
  session stores, `IdentityStore.Load`, and both limiter factories' `Verify`. Then
  `CREATE TABLE auth.sessions(id int)` and `CREATE TABLE auth.users(id int)` succeed, and both stay
  empty after a store write. Expected: PASS. Red: point the pool's `search_path` at `public`, and
  see `Verify` refuse.
- [ ] **Step 7:** Write `TestLimiterVerify_RefusesUnrenamedSchema`, a table test over the sql and pgx
  factories. With the security-state set at the version before the rename, `Verify` returns an
  error matching `ratelimit.ErrConfig` whose text names `scrty_rate_limit_buckets`. Red: run it
  before the error text and godoc name the new table. Update the limiter godoc in both adapters.
  Expected: PASS.
- [ ] **Step 8:** Update README and CHANGELOG.
  - README: the migration sections name the new tables, state that the prefix is fixed and a schema
    is the way to isolate it (D1), and give the upgrade and rollback order (D7).
  - CHANGELOG, under *Unreleased → Changed*: a **BREAKING** entry with the old → new table list, the
    upgrade order, and the unchanged version tables.

  Verify with `rg -n '\b(sessions|users|rate_limit_buckets|op_grants)\b' README.md CHANGELOG.md`:
  the only matches are prose or the old → new list.
- [ ] **Step 9:** Run dispatch C's verification row, plus `go test -count=1 ./expiry/... ./oidcprovider/...`
  (Review Focus 5). Expected: PASS. `go vet` and `gofmt -l` are clean.

### Task 5: Integration (tasks.md 5.1–5.2)

- [ ] **Step 1:** The main session runs `make check` and `make spec-check` after the last code edit,
  and reads the output. Expected: PASS on both PostgreSQL images.
- [ ] **Step 2:** A fresh Sonnet reviewer, with failure modes enumerated first, checks the whole
  branch against both spec deltas and design F1–F14. The main session folds the findings, then
  re-runs step 1.
