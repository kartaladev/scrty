# Design

## Context

See `proposal.md` for why. The current state that shapes the approach:

- Two migration sets, embedded as goose-annotated plain SQL. The security-state set is at
  `store/migrate/securitystate` (six files, the last being the device grant's
  `20261122000000_oidc_provider_device.sql`). The identity set is at `store/migrate/identity` (one
  file). Each records its versions in its own table, `goose_security_state` and `goose_identity` by
  default, and a consumer may rename either.
- `v0.2.1` is tagged. It holds every security-state migration up to `20261103000000` and the
  identity migration. The schema-migrations spec forbids editing released migrations. The device
  migration `20261122000000` is not released yet. It lands with PR #135, which this change is stacked
  on.
- An inventory taken on PostgreSQL 18 with every migration applied (2026-11-23) found:
  - 32 tables: 25 security-state and 7 identity;
  - 104 indexes, 52 of them backing a primary key or unique constraint;
  - one identity sequence, `password_history_seq_seq`;
  - no named CHECK constraints;
  - a longest relation name of 47 bytes, so prefixed names are at most 53, under PostgreSQL's
    63-byte limit.
- Every SQL statement the sql and pgx adapters run is a constant in `internal/pgschema`. The gorm
  adapter names its tables through `TableName()` methods in `store/gormstore/models.go`. The rate
  limiter's construction-time check (`Verify`) resolves `rate_limit_buckets` through `to_regclass`,
  and so through the connection's `search_path`. No code depends on a constraint name: there is no
  `ConstraintName` check and no `ON CONFLICT ON CONSTRAINT`. Core packages hold no table names.
- About 80 files in the `test` module name tables in SQL. They include:
  - the `pg_indexes` and catalog snapshot checks in `test/migrate_*_test.go`;
  - the schema snapshot in `test/testutils_postgres_test.go`;
  - the rate-limiter suites;
  - the populated-upgrade fixture `test/testdata/migrations/populated`, which alters every
    security-state table by name.

## Goals / Non-Goals

**Goals:**

- Every relation that either set creates is named `scrty_<former name>` once the set is at its
  latest version, whether the database was installed fresh or upgraded.
- One forward migration per set upgrades a populated database in place, atomically, with a bounded
  lock wait. Rolling it back restores the previous names exactly.
- Every store, the limiter and the tests use only the new names. A statement left on an old name
  fails a test.

**Non-Goals:**

- A configurable prefix (D1).
- Rolling deploys across the rename (D2).
- Renaming the goose version tables (D4).
- Renaming the expiry sweep's task names (`sessions`, …). They are task identifiers, not tables.
- Making a fresh install succeed in a schema that already holds a consumer table with one of the
  old names. That needs released migrations edited or a new baseline set (D5).

## Decisions

### D1. A fixed `scrty_` prefix; the PostgreSQL schema is the consumer's override (decided by the user 2026-11-23)

**Default:** every table, index, index-backed constraint and sequence is named `scrty_` followed by
its former name, e.g. `scrty_sessions`, `scrty_sessions_pkey`, `scrty_password_history_seq_seq`.

**Override:** the prefix itself has none. A consumer who wants scrty's relations kept apart from
their own installs the sets in a schema of their own and points the pool's `search_path` at it. The
stores and the limiter's `Verify` already resolve through `search_path`. The spec pins this with
the "Consumer schema" scenario, and a test proves it (task 4.3).

**Why there is no prefix option.** A configurable prefix would need three things:

- every `internal/pgschema` statement turned into a template built at construction;
- every gorm model given a dynamic table name;
- migrations that substitute the prefix at apply time.

goose can do that last part only through `-- +goose ENVSUB ON` (v3.18.0 and later), and that would
break the spec's promise that any tool reading the format produces the same schema. Each prefix
value would also need its own test run. A schema gives the same isolation with none of that. River
takes the same approach: fixed `river_` names and a schema option. Quartz (`tablePrefix`) and Spring
Session (a configurable table name) are the configurable alternative, considered and not chosen.

`library-design.md` asks for the line to be documented, not relaxed silently. The README's migration
section will say that the names are fixed and that the schema is the way to isolate them.

### D2. One-step rename, no compatibility views (decided by the user 2026-11-23)

Each set gets one new migration, version `20261124000000`, named `…_scrty_prefix.sql`. It renames in
place:

- `ALTER TABLE <t> RENAME TO scrty_<t>` for each table;
- `ALTER INDEX <i> RENAME TO scrty_<i>` for each index. For an index that backs a primary key or a
  unique constraint, PostgreSQL renames the constraint with it;
- `ALTER SEQUENCE password_history_seq_seq RENAME TO scrty_password_history_seq_seq` in the
  identity set.

Checked on PostgreSQL 15 on 2026-11-23:

- a table rename leaves its index and sequence names unchanged, so they must be renamed explicitly;
- an index rename renames its constraint;
- a renamed identity sequence stays linked: `pg_get_serial_sequence` returns the new name, and
  inserts keep working.

Renames change catalog entries only. "There is no effect on the stored data", so no row is copied or
rewritten. Grants, row-level security policies, views and publications reference a relation by
OID, so they follow the rename.

**The statement list is static and explicit**, written out name by name. It is not a `DO` block
that walks the catalog. A static list:

- is reviewable;
- never touches a relation the set did not create;
- runs the same on every tool that reads the format.

A test checks it against the catalog, so a relation the list misses fails the test (task 2.1).

**The lock wait is bounded.** The migration begins with `SET LOCAL lock_timeout = '5s'`. Every
`ALTER … RENAME` takes ACCESS EXCLUSIVE. Without a bound, a long transaction holding any table
would leave the migration queued, and every query behind it would queue too. With the bound, the
migration fails, the transaction rolls back every rename, no version is recorded, and the operator
retries. `SET LOCAL` ends with the transaction, so the consumer's session setting is untouched.

**Override:** none for the 5 s. A consumer who needs a longer wait applies the files with their own
tool after editing a copy, which the format allows. A failure is safe and retryable, so a shorter or
longer default changes only how often it is retried.

**Down section:** the same statements in reverse order, renaming each relation back. It uses `IF EXISTS`
on each statement, because the spec requires rollback to finish even when a table is gone. The Up
section has no `IF EXISTS`: a relation missing at upgrade time is a fault, and the upgrade should
fail on it. The migration is fully reversible, as the schema-migrations spec requires of every
migration.

**Alternative not chosen: expand/contract with views.** This is GitLab's documented two-release
procedure, and Fowler's Parallel Change. The rename would also create auto-updatable views under the
old names, so old replicas keep working through a rolling deploy, and a later release would drop
them. PostgreSQL supports `INSERT … ON CONFLICT` on such views. The user chose the one-step rename
because:

- the views would hold the old names for a whole release, which delays the point of the change;
- the change would span two releases;
- it doubles the rollback paths that need tests;
- under v0 a short stop of old replicas is an acceptable upgrade cost.

### D3. What is renamed, and what is not

**Renamed:** every table, every index (including the index behind each primary key and unique
constraint), and the identity sequence. These all share the schema's relation namespace ("index
names must be unique across all relations within the same schema"). An unprefixed index such as
`sessions_pkey` would block a consumer's `sessions` table, whose primary key PostgreSQL would also
name `sessions_pkey`.

**Not renamed:**

- **NOT NULL constraint names.** PostgreSQL 18 records them as `<table>_<column>_not_null`, and
  PostgreSQL 15 does not record them at all. Constraint names are scoped to their table, not the
  schema, so they cannot collide. Renaming them would need version-dependent SQL. Accepted: on
  PostgreSQL 18 an upgraded database keeps names like `sessions_user_id_not_null` on
  `scrty_sessions`, while a fresh install gets the same, since the fresh install also creates
  before it renames. The two paths therefore never differ.
- **TOAST relations.** They are named by OID and live in `pg_toast`.

### D4. Version tables keep their names

`goose_security_state` and `goose_identity` stay the defaults. goose finds a database's history
through the version table. If the default changed, an existing deployment's goose would see an
empty history and re-run migration 1 against a populated schema, which would fail on the first
`CREATE TABLE`. A migration also cannot rename the table its own runner is writing to. The names are
already consumer-replaceable (`WithTableName`). The spec states that they are unchanged.

### D5. Released migrations stay untouched, and so does the unreleased device migration

The rename is a new migration that follows every existing one. The device-grant migration
`20261122000000` is not released, so it could legally be rewritten to create prefixed names
directly. It is left alone instead:

- the branch it lives on is still moving;
- the rename migration covers its relations the same way as all the others;
- fresh and upgraded databases go through one path.

**Accepted consequence.** A fresh install still runs `CREATE TABLE sessions` and the rest before
the rename. In a schema that already holds a consumer `sessions` or `users`, the first migration
fails with "relation already exists", and atomically, as today. The remedy is a schema of its own
(D1). Removing this limit would take a new baseline set with prefixed names, plus a way to adopt
existing databases into it. That is a separate change, if it is ever wanted.

### D6. Code moves to the new names; a guard catches a missed statement

- `internal/pgschema`: every statement constant and `LimiterTable` move to the prefixed names, as
  literal edits. A shared name constant concatenated into each statement was considered. It would
  make the statements harder to read and to grep, for no runtime benefit, since the names are fixed
  (D1). It was rejected.
- **Guard test** in `internal/pgschema`, which reflects over the package's exported string
  constants. No statement may name an unprefixed table from the inventory as a whole word after
  `FROM`, `INTO`, `UPDATE`, `JOIN`, `TABLE` or `to_regclass(`. It is cheap, runs without Docker, and
  fails at the line that was missed. The store conformance suites, run against the renamed schema,
  are the second net.
- `store/gormstore/models.go`: each `TableName()` returns the prefixed name. Its godoc keeps the
  existing promise that a consumer's gorm naming strategy never renames them.
- Limiter godoc and the `Verify` error text name `scrty_rate_limit_buckets`.

### D7. Compatibility

The library is past its first tag, so this is a compatibility decision (`library-design.md` §7).
Under v0 a minor release may break, and the break is stated (release-policy spec). The change ships
in the next minor, v0.3.0. The CHANGELOG entry under *Changed* is marked **BREAKING** and states:

- **The new names.** Any consumer SQL, reporting query, backup filter (`pg_dump -t`) or function body
  that names a scrty table must be updated. Grants, RLS policies and views follow by OID and need
  nothing.
- **The upgrade order:**
  1. stop every replica running ≤ v0.2.x;
  2. apply the security-state set;
  3. apply the identity set, if it is used;
  4. start the new release.
- **The rollback:** stop the new release, roll back the two rename migrations, start the old release.

### D8. Departure from the established design

The established design names its tables without a prefix. scrty departs from it because the user
decided to (2026-11-23), to keep a library-owned footprint apart from the consumer's own tables in a
shared schema. It is not a defect fix, so no reproduction is involved.

## Failure modes

| # | Failure | State | What the caller or operator sees |
|---|---|---|---|
| F1 | An old (≤ v0.2.x) replica is still running when the rename commits | Accepted (D2, D7) | Its store calls fail with "relation does not exist". scrty's stores already map storage errors to refusals, so sign-in and token checks fail closed; nothing is granted. The documented upgrade order prevents it. |
| F2 | The new release starts before the security-state rename is applied | Handled, tested (task 4.4) | The limiter's `Verify` refuses at construction with `ratelimit.ErrConfig`, naming the missing `scrty_rate_limit_buckets` and the migration set. Stores without a construction check fail closed on first use, as with any missing table today. |
| F3 | The security-state set is renamed but the identity set is not | Accepted, documented | Security-state stores work. Identity store calls fail with a database error, and its MFA-required lookup denies, as the identity set's godoc already states for a missing table. |
| F4 | A long transaction holds a lock on a table the migration renames | Handled, tested (task 2.3) | After about 5 s, applying fails with a lock timeout error. Nothing is renamed and no version is recorded. Retrying succeeds once the lock is gone. |
| F5 | A relation named `scrty_<x>` already exists in the schema | Handled, tested (task 2.3) | Applying fails ("relation already exists"). The transaction rolls back every rename, and the consumer's relation is untouched. |
| F6 | The migration fails partway through its statements | Handled, tested (task 2.3) | The whole migration is one transaction: no partial rename, no version recorded. |
| F7 | The rename list misses a relation, or a later migration adds one without the prefix | Handled, tested (tasks 2.1, 3.1) | The catalog test lists every table, index and sequence the set created and fails on any name without `scrty_`. |
| F8 | A statement, gorm model or test still uses an old name | Handled, tested (task 4.1) | The pgschema guard test fails at the constant. A missed gorm model or test SQL fails its conformance or store test against the renamed schema. |
| F9 | A prefixed name exceeds 63 bytes and is silently truncated | Handled, tested (task 2.1) | The catalog test asserts that every name is ≤ 63 bytes and equals `scrty_` plus the inventory name. Today's maximum is 53. |
| F10 | The identity sequence loses its position, or its link to the column | Handled, tested (task 3.2) | A populated rename followed by a new history entry orders it after every existing one, and `pg_get_serial_sequence` names the renamed sequence. |
| F11 | The rename is rolled back while the new release is still running | Accepted, documented | That is the reverse of F1: the new release fails closed. The documented rollback order stops it first. |
| F12 | A fresh install into a schema that already holds a consumer `sessions` or `users` table | Accepted (D5) | The first migration fails atomically ("relation already exists"), as today. The remedy is a schema of its own. |
| F13 | A consumer applies the files with a tool that does not wrap each migration in a transaction | Accepted | It is outside the format's contract, which the spec already requires to be transactional. `SET LOCAL` would warn and have no effect, and a failure could leave a partial rename. The README already names the transactional requirement. |
| F14 | PostgreSQL 18 NOT NULL constraint names keep the old table name | Accepted (D3) | Cosmetic only: they are scoped to their table and cannot collide. A fresh install and an upgrade produce identical names. |

## Risks / Trade-offs

- [Upgrade needs a stop of old replicas] → The CHANGELOG and README give the order. The migration
  itself is fast (catalog only), so the stop is short. The lock bound keeps a stuck migration from
  queueing traffic.
- [Consumer SQL that names scrty tables breaks silently until run] → It is stated as BREAKING, with
  the full old → new list in the CHANGELOG.
- [The ~80 test files churn on a branch that PR #135 is still changing] → Rebase onto the device
  branch before each dispatch. Test-file edits are mechanical renames, and the guard and catalog
  tests catch anything missed.
- [The static rename list drifts from the inventory] → The catalog test is the source of truth
  (F7).

## Migration Plan

1. Release v0.3.0 with both rename migrations and the code on the new names.
2. Operators follow D7's order: stop the old replicas, apply the security-state set, apply the
   identity set if it is used, start v0.3.0.
3. Rollback: stop v0.3.0, roll back each set by one version (`goose down` once per set), start the
   previous release.

## References

All accessed 2026-11-23.

### D1: a fixed prefix, the schema as override

**Researched:**
- [River, migrations](https://riverqueue.com/docs/migrations): a Go library with fixed `river_job`,
  `river_leader`, `river_migration` and `river_queue` tables, and an alternate-schema option rather
  than a prefix option.
- [pressly/goose README](https://github.com/pressly/goose): `-- +goose ENVSUB ON` substitutes
  environment variables in SQL migrations. It is off by default, and per the
  [CHANGELOG](https://raw.githubusercontent.com/pressly/goose/main/CHANGELOG.md) it was added in
  v3.18.0. A secondary summary placed it in v3.20.0; this is unverified, and the CHANGELOG is taken
  as authoritative.
- [Spring Session, JDBC configuration](https://docs.spring.io/spring-session/reference/configuration/jdbc.html):
  a configurable table name, default `SPRING_SESSION`. This is the configurable alternative.
- Quartz `org.quartz.jobStore.tablePrefix`, default `QRTZ_`, letting several table sets share one
  database: read through search summaries of the
  [Quartz 2.2.2 JobStoreTX configuration](https://www.quartz-scheduler.org/documentation/quartz-2.2.2/configuration/ConfigJobStoreTX.html).
  The page itself was not fetched, so this is unverified at the source.
- [Django, model Meta options](https://docs.djangoproject.com/en/stable/ref/models/options/): an
  app-label prefix by default (`bookstore_book`), overridable per model with `db_table`.

### D2, D3: one-step rename, what is renamed

**Researched:**
- [PostgreSQL, ALTER TABLE](https://www.postgresql.org/docs/current/sql-altertable.html): RENAME has
  "no effect on the stored data" and takes ACCESS EXCLUSIVE. Renaming a constraint with an
  underlying index renames the index as well. The page does not say whether a table rename
  renames its indexes. That was checked on PostgreSQL 15 instead (D2).
- [PostgreSQL, ALTER INDEX](https://www.postgresql.org/docs/current/sql-alterindex.html): renaming an
  index associated with a UNIQUE, PRIMARY KEY or EXCLUDE constraint renames the constraint too.
- [PostgreSQL, ALTER SEQUENCE](https://www.postgresql.org/docs/current/sql-altersequence.html):
  RENAME TO. Its effect on an identity sequence is not documented there, and was checked on
  PostgreSQL 15 (D2).
- [PostgreSQL, CREATE INDEX](https://www.postgresql.org/docs/current/sql-createindex.html) and
  [CREATE TABLE](https://www.postgresql.org/docs/current/sql-createtable.html): index names must be
  distinct from every relation in the schema, and constraint-backed indexes share the constraint's
  name.
- [PostgreSQL, lexical structure](https://www.postgresql.org/docs/current/sql-syntax-lexical.html):
  identifiers are truncated to NAMEDATALEN−1 = 63 bytes.
- [GitLab, renaming database tables](https://docs.gitlab.com/development/database/rename_database_tables/):
  the two-release, view-based rename that keeps old instances working during a rolling deploy. This
  is the alternative not chosen.
- [Martin Fowler, Parallel Change](https://martinfowler.com/bliki/ParallelChange.html):
  expand/migrate/contract, the pattern behind that alternative.
- [PostgreSQL, CREATE VIEW: updatable views](https://www.postgresql.org/docs/current/sql-createview.html):
  single-table views are auto-updatable, and `INSERT … ON CONFLICT` is supported on them. This is
  the basis for judging the alternative feasible.

### D4: version tables

**Primary documentation:**
- [goose `WithTableName`](https://pkg.go.dev/github.com/pressly/goose/v3): sets the version table
  that tracks applied migrations. Its default is `goose_db_version`; scrty's sets pass their own.

### D5, D6, D7, D8: reasoned from scrty's own settled specs and the established design

The schema-migrations spec (released migrations never edited, every migration reversible and
atomic), the release-policy spec (breaks stated under v0), `library-design.md`, and the inventory
taken from this repository on 2026-11-23.
