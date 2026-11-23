# Proposal

## Why

scrty's tables have generic names: `sessions`, `users`, `roles`, `groups`, `api_keys`. A consumer
embeds the library in their own database, often in the schema that already holds their application
tables, and those names are the first ones an application picks for itself. Today a consumer with
their own `users` or `sessions` table cannot apply scrty's migrations into the same schema. They
fail with "relation already exists", or worse, a consumer's tooling may read scrty's table as
theirs. The same collision applies to the index and sequence names PostgreSQL derives from the
table names (`sessions_pkey`, `users_username_key`), which share the schema's relation namespace.
Prefixing every name with `scrty_` makes the library's footprint unambiguous. Once a database is
migrated, the generic names are free for the consumer. It is done now because the schema is still
small enough to rename in one migration per set, before more consumers build reporting or tooling on
the current names.

One limit remains, and is accepted (see `design.md`). Released migrations cannot be edited, so a
fresh install still creates the unprefixed tables first and renames them in the last migration. A
schema that already holds a consumer table named `sessions` or `users` still refuses the install.
Installing scrty into a schema of its own remains the remedy for that case.

## What Changes

- **BREAKING**: every table created by the security-state and identity migration sets is renamed
  to carry the `scrty_` prefix, for example `sessions` → `scrty_sessions`, `users` →
  `scrty_users`, `rate_limit_buckets` → `scrty_rate_limit_buckets` and `op_device_authorizations`
  → `scrty_op_device_authorizations`. The tables the device-grant change adds are included.
- Every index, every index-backed constraint (primary keys and unique constraints) and the identity
  sequence of the password-history table are renamed with the same prefix, so that no relation
  the library creates in a schema keeps an unprefixed name.
- One new migration in each set performs the rename on existing databases: `ALTER … RENAME`,
  metadata-only and atomic, with a bounded lock wait. Its rollback renames everything back. Released
  migrations are not edited. A fresh install runs the same migrations and ends with the same names.
- The prefix is fixed. A consumer who wants further isolation places scrty in a schema of its own.
  The stores already resolve tables through the connection's `search_path`.
- Every statement in the shared SQL, the gorm models, the limiter's construction-time table check,
  and the tests and documentation that name tables, move to the new names.
- The goose version tables (`goose_security_state`, `goose_identity`) keep their default names. They
  are already consumer-configurable, and renaming the default would make goose re-run every
  migration against existing databases.
- Upgrading needs the old replicas stopped before the rename migration runs. An old binary
  queries the old names and fails once the migration has committed. This is stated in the CHANGELOG
  entry and the migration godoc.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `schema-migrations`: the security-state set's tables and derived relation names carry the `scrty_`
  prefix; a rename migration upgrades existing databases in place, bounds its lock wait, and rolls
  back to the previous names.
- `default-identity-store`: the identity set's tables and derived relation names carry the `scrty_`
  prefix, through the identity set's own rename migration, independent of the security-state set.

## Impact

- **Migrations**: `store/migrate/securitystate` and `store/migrate/identity` each gain one rename
  migration. No existing file changes.
- **Shared SQL**: `internal/pgschema` (every statement constant and `LimiterTable`), used by
  `store/sqlstore` and `store/pgxstore`; the limiter's `Verify` table check and its godoc in both
  adapters.
- **gorm adapter**: `store/gormstore/models.go`, the `TableName` methods.
- **Tests**: the `test` module's schema checks (`pg_indexes` lists, the column, constraint and
  snapshot checks), the rate-limiter suites, the store conformance suites and every test that names
  a table in SQL. Roughly 80 files. Core packages carry no table names.
- **Docs**: README (migration sections and the limiter's table), CHANGELOG (a BREAKING entry under
  *Changed*), package godoc that names tables.
- **Consumers**: any SQL, reporting, backup filter or grant that names a scrty table must switch to
  the new names. A rolling deploy across the rename is not supported: old replicas stop before the
  migration. Under v0 the break is allowed, and it is announced in the next minor release.
- **Depends on**: the `oidc-provider-device-grant` change (PR #135), whose migration this change's
  rename migration follows.

## References

All accessed 2026-11-23. The decisions and their full sources are in `design.md`.

**Researched:**
- [PostgreSQL, CREATE INDEX](https://www.postgresql.org/docs/current/sql-createindex.html): an index
  name must be distinct from every other relation (table, sequence, index, view) in the schema. This
  is why derived names are renamed too.
- [PostgreSQL, ALTER TABLE](https://www.postgresql.org/docs/current/sql-altertable.html): RENAME has
  "no effect on the stored data" and takes an ACCESS EXCLUSIVE lock.
- [GitLab, renaming database tables](https://docs.gitlab.com/development/database/rename_database_tables/):
  the two-release, view-based alternative for rolling deploys, considered and not chosen.
- [River, migrations](https://riverqueue.com/docs/migrations): a Go library with fixed prefixed table
  names (`river_job`, `river_migration`) and a schema option rather than a prefix option.
