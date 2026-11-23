# Tasks

Every task is test-first: write the failing test, run it, see it fail for the intended reason
(not a compile error), then implement. Groups 2 to 4 leave the store suites red between them,
because the schema and the statements must move together. Group 2 and 3 verify only their schema
tests; group 4 restores the full scoped suites.

## 1. Relation inventory

- [ ] 1.1 Add to the `test` module the inventory of every table, index and sequence each set
  creates before the rename (32 tables, 104 indexes, `password_history_seq_seq`), as data the
  catalog tests share. Red: a test that applies both sets up to the version before the rename and
  compares the catalog to the inventory, run against an empty inventory, fails listing the missing
  names. Green: the full inventory. Verify: `go test -run 'TestRelationInventory' -count=1 ./test/`
  passes on PostgreSQL 15 and 18.

## 2. Security-state rename migration

- [ ] 2.1 Catalog test: at the latest version, every relation the set created is `scrty_` plus an
  inventory name, no unprefixed one remains, every name is at most 63 bytes, and the versions are
  in `goose_security_state` (spec "Fresh database", "Names fit the identifier limit"; design F7,
  F9). Red: it fails listing `sessions` and the rest. Green: add
  `store/migrate/securitystate/20261124000000_scrty_prefix.sql`, with `SET LOCAL lock_timeout =
  '5s'` and an explicit `ALTER TABLE`/`ALTER INDEX … RENAME` per relation, and a down section in
  reverse order. Verify: the focused test passes.
- [ ] 2.2 Update the security-state schema checks in `test/migrate_securitystate_test.go` (the
  `pg_indexes` list, the column and constraint checks) and the snapshot in
  `test/testutils_postgres_test.go` to the new names. Red: they fail against the renamed schema.
  Verify: `go test -run 'TestSecurityState|TestSchemaSnapshot' -count=1 ./test/` passes.
- [ ] 2.3 Failure tests for the rename migration (spec "A table is held by another transaction",
  "The new name is already taken"; design F4, F5, F6): a held lock fails within the bound and a
  retry succeeds; a pre-existing `scrty_sessions` fails and leaves it untouched; in each case no
  relation is renamed and no version is recorded. Red: invert the migration temporarily (drop the
  `lock_timeout` line) and see the lock test time out at the test's own deadline. Verify: the
  focused tests pass.
- [ ] 2.4 Rollback test (spec "Rolling back the rename", "Full rollback and re-apply"): a catalog
  snapshot taken before the migration equals the snapshot after up then down-by-one. Down to zero
  leaves no relation, and re-applying prefixes everything. Red: with one down statement removed,
  the test names the relation left behind. Verify: the focused test passes.
- [ ] 2.5 Populated rename (spec "Populated database"): seed sessions, signing keys, provider grants,
  device authorizations and rate-limit buckets at the version before the rename, apply it, and read
  every row back through the stores. Update the fixture `test/testdata/migrations/populated` to the
  new names. Verify: `go test -count=1 ./test/crossbackend/` passes.

## 3. Identity rename migration

- [ ] 3.1 Identity catalog test (spec "Identity set alone"): every identity relation, the sequence
  included, is prefixed, and the versions are in `goose_identity`. Red: it fails listing `users`.
  Green: add `store/migrate/identity/20261124000000_scrty_prefix.sql`, with the bounded lock wait,
  renames and down section. Update the identity `pg_indexes` and column checks in
  `test/migrate_identity_test.go`. Verify: `go test -run 'TestIdentityMigrations' -count=1 ./test/`
  passes.
- [ ] 3.2 Populated identity rename (spec "Populated identity database"; design F10): users, grants
  and history read back, `pg_get_serial_sequence` names `scrty_password_history_seq_seq`, and the
  next history entry orders after the existing ones. Red: with the sequence rename removed from the
  migration, the catalog assertion fails. Verify: the focused test passes.
- [ ] 3.3 Independence (spec "One set renamed, the other not yet", "Rolling back the identity
  rename"): renaming or rolling back one set changes no relation or version record of the other.
  Verify: the focused test passes.

## 4. Code and tests on the new names

- [ ] 4.1 Guard test in `internal/pgschema`: no exported statement constant names an unprefixed
  inventory table after `FROM`, `INTO`, `UPDATE`, `JOIN`, `TABLE` or `to_regclass(` (design D6,
  F8). Red: it fails listing every current statement. Green: move every statement and
  `LimiterTable` to the new names. Verify: `go test -count=1 ./internal/pgschema/` passes.
- [ ] 4.2 `store/gormstore/models.go`: every `TableName()` returns the prefixed name, and the godoc
  says so. Red: the gorm conformance suite fails against the renamed schema. Verify: the gormstore
  suites in `./test/gormstore/` pass.
- [ ] 4.3 Consumer-schema test (spec "Consumer schema", "Consumer tables of the old names in the same
  schema"): apply both sets in schema `auth` with `search_path=auth`, then run one store of each
  adapter and the limiter's `Verify`, which pass. Creating consumer `sessions` and `users` tables
  afterwards succeeds, and the stores touch only the prefixed ones. Verify: the focused test passes.
- [ ] 4.4 Limiter `Verify` on a database without the rename (design F2): it refuses with
  `ratelimit.ErrConfig`, naming `scrty_rate_limit_buckets` and the migration set. Update the limiter
  godoc in `store/sqlstore` and `store/pgxstore`. Red: before the error text and godoc change, the
  assertion on the named table fails. Verify: the focused test passes for both adapters.
- [ ] 4.5 Move every SQL string in the `test` module to the new names: the rate-limiter suites,
  `storetest` suites, broken-store tests, durable OIDC tests, and `test/gormstore/broken_test.go`
  `TableName`s. Verify: the scoped run from `plans.md` (`./internal/pgschema/ ./store/... ./test/...`
  and the adapter modules) passes, `go vet` and `gofmt -l` are clean.
- [ ] 4.6 Docs: the README migration sections name the new tables, say that the prefix is fixed, that
  a schema is the way to isolate it, and give the upgrade and rollback order. The CHANGELOG
  *Unreleased → Changed* gets a **BREAKING** entry with the old → new list, the upgrade order and
  the version tables unchanged (design D7). Verify: `rg` in README and CHANGELOG finds no unprefixed
  table name outside the old → new list.

## 5. Integration

- [ ] 5.1 Final gate: `make check` and `make spec-check` pass, read by the main session after the
  last code edit, on PostgreSQL 15 and 18.
- [ ] 5.2 Whole-branch review against every requirement in this change's specs, with failure modes
  enumerated first. Findings are fixed and 5.1 re-run.

## Workflow follow-up

- Rebase onto `feat/oidc-provider-device-grant` until PR #135 merges, then onto `main`.
- Archive after PR #135's change is archived, so the device tables are in the main spec first.
