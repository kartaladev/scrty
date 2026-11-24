# Design: fold the migration sets, and answer unclassified callback failures with server_error

## Context

See `proposal.md` for why.

**Migrations.** `store/migrate` embeds two goose-format sets:
- **Security state:** eight files, ending with `20261124000000_scrty_prefix` and
  `20261125000000_scrty_selected_role`.
- **Identity:** three files, `20260928000000_identity`, `20261124000000_scrty_prefix` and
  `20261125000000_scrty_administration`.

Both prefix migrations rename relations that earlier migrations created unprefixed. Goose ignores
versions recorded in the database that have no file, and applies every file version not yet
recorded. The `test` module holds about 3,800 lines of tests that walk the chain step by step:
populated upgrades, backfills, rename locks and rollbacks of single steps.

**Callback.** `httpsec/oidc_login.go` reads a callback's error once (`readCallbackFailure`) and maps
it to a code through `callbackCode`. Today only refusals (`access_denied`) and outages
(`temporarily_unavailable`) map. Everything else gets no code, so a parked login falls through to
the plain error. A failed sign-in hook, or a failed `Apply`, reaches the callback as the broker's
opaque `hookFailure`, which matches no sentinel by design.

## Goals / Non-Goals

**Goals:**
- Each set applies cleanly to a schema that already holds application tables of the old names.
- The resulting schema is provably the same as v0.5.0's.
- A database with an earlier scrty history is refused loudly, never silently duplicated.
- A parked login never ends in a bare 500 for a failure that occurs after its flow is spent.

**Non-Goals:**
- **Upgrading an earlier database in place.** No consumer runs scrty in production, and the user
  chose recreation.
- **Changing any table, column or index.** The fold is schema-neutral.
- **Provider access tokens on the chain.** That is a separate change, `provider-resource-server`,
  planned for v0.6.0.

## Decisions

### D1. One baseline migration per set, created directly under `scrty_` names

**Files:**
- `store/migrate/securitystate/20261126000000_security_state.sql`
- `store/migrate/identity/20261126000000_identity.sql`

**Content:**
- Each file's up section creates every table, index, constraint and sequence of v0.5.0's final
  schema, directly under its `scrty_` name.
- Columns that later migrations added are folded into each `CREATE TABLE` in the column order the
  chain produced (attnum order), so `INSERT … SELECT *` and the lineage table's "same columns as
  sessions" rule behave as before.
- Column defaults and backfill-only defaults are kept exactly as the chain left them.
- Each down section drops everything its up section created.
- The version is one timestamp newer than every v0.5.0 file. The two sets record into separate
  tables, so sharing a version number is harmless.

**Default and override:** there is no option. The prefix is fixed, as settled before. A consumer
isolates the relations with a schema plus `search_path`, as today.

**Alternatives considered:**
- **Keep the chain and only change the first migrations.** That edits released files just the same,
  and leaves the rename steps doing nothing.
- **Make the creates conditional (`CREATE TABLE IF NOT EXISTS`).** That would silently adopt a
  consumer's own table of the same name. Refused under `defensive-coding.md`.

### D2. New default version tables

- The defaults change:
  - `SecurityStateVersionTable` becomes `"scrty_state_migrate"`;
  - `IdentityVersionTable` becomes `"scrty_identity_migrate"`.
- The Go names stay the same, and the user chose the new values on 2026-11-25.
- A fresh history table means a database's old version records can never make the baseline look
  applied.

**Default and override:** the constants are the defaults. A consumer passes any other name to their
runner (`goose.WithTableName`), as today.

**Alternative considered:** keep `goose_*` and reuse the last v0.5.0 version number, so v0.5.0
databases would see nothing pending. The user preferred a clean history.

### D3. The baseline refuses an earlier history

Each up section starts with a guarded `DO` block that runs before any `CREATE`:
- **Condition:** the earlier default version table (`goose_security_state` or `goose_identity`)
  resolves on the `search_path` and records a version greater than 0.
- **Result:** the block raises `scrty: this database was migrated by a release before v0.6.0;
  recreate it`.
- **Dynamic SQL:** the check uses `EXECUTE`, so a database without that table never parses a
  reference to it.
- **Atomicity:** the migration runs in one transaction, so a refusal leaves no relation and no
  version record.

**Why version > 0 rather than "the table exists":**
- Goose creates the consumer's chosen version table, with a version-0 row, before running the
  migration.
- A consumer who picks the old name for a fresh database must not be refused (scenario "Consumer
  reuses the old name").

A v0.5.0 database whose history sits under a custom table name is still refused: the first
`CREATE TABLE scrty_…` fails because the relation exists.

**Default and override:** there is no override. Proceeding over an earlier history would silently
create empty tables beside the old ones, which `library-design.md` rules out.

### D4. Equivalence is proven against a frozen copy of the v0.5.0 chain

**The frozen copy:**
- The v0.5.0 files of both sets are copied, unchanged, into the `test` module under
  `testdata/migrate/v0.5.0/`.
- They are test fixtures: never embedded in the library and never shipped.

**The test:**
- It applies the frozen chain in one schema and the baseline in another, on both CI PostgreSQL
  majors (15 and 18).
- It compares, per table:
  - columns in attnum order, with type, nullability and default;
  - index names and definitions, with the schema name normalised;
  - sequences;
  - constraint definitions (`pg_get_constraintdef`), compared by definition and owning table.
- Index names, and the names of the constraints that indexes back, must match exactly. Names of
  check constraints that no index backs may differ: the chain kept their pre-rename names, and the
  baseline gives them PostgreSQL's natural prefixed names.

**Alternative considered:** a golden JSON inventory. A frozen chain is checked live on each
PostgreSQL major, and it cannot drift from what v0.5.0 actually shipped.

### D5. Every unclassified callback failure after the flow is spent answers `server_error`

**The change:**
- `callbackCode`'s default case returns `oidcprovider.CodeServerError` instead of no code.
- The cases that keep their plain answer stay exactly as they are, ahead of the default:
  - the flow left unspent;
  - an invalid state;
  - a hung-up caller;
  - an error whose walk aborted, which `readCallbackFailure` already returns before any code.

**Precedence:** a refusal still wins over an outage, and both win over the default, so no existing
mapping changes.

**What is unaffected:**
- **Events:** `emitCallbackRefused` is unchanged. A server-side failure is not a refused login, so
  it emits no `AuthnLoginFail`.
- **Logs:** the sampled log record of the redirect names the code, as for the other codes.
- **Non-parked logins:** a login that is not parked is unchanged. `parkedDestination` still gates
  the redirect.

**Default and override:** this is the default for parked logins under completion.
`WithOIDCFailToClient` still moves the answer to the client's redirect URI. There is no option to
restore the plain 500. `server_error` names nothing about the account or the failure, the error is
still logged at the redirect site, and a consumer that wants plain errors does not enable
completion.

**Departure:** this revises D4 of the archived `parked-request-error-answers` design, whose last
item kept an unclassified broker failure's plain answer "as a default refusal rather than a
guess". RFC 6749 §4.1.2.1 defines `server_error` as the generic answer for an unexpected
condition, so mapping to it is not a guess. The user decided on 2026-11-25.

### D6. Released migrations are edited once, by decision

The settled rule "released migrations are never edited" is suspended for this release only, by the
user's decision of 2026-11-25. The rule applies again from v0.6.0: the baselines are released
files.

## Failure modes

| # | Failure | State | What the caller sees |
|---|---|---|---|
| F1 | Schema already holds an application `users` or `sessions` table | Handled, tested | Baseline applies; the application table is untouched |
| F2 | Database migrated by an earlier release under the default version table | Handled, tested | The baseline raises an error naming an earlier release; nothing created, no version recorded |
| F3 | Database migrated by v0.5.0 under a consumer-named version table | Handled, tested | `CREATE TABLE scrty_…` fails on the existing relation; the transaction leaves nothing |
| F4 | Database migrated before v0.5.0 under a consumer-named version table, or with its history in a schema off the `search_path` | Accepted | Not detected. New empty `scrty_` tables are created beside the old unprefixed ones. No consumer runs scrty in production; the changelog tells every earlier database to be recreated |
| F5 | Fresh database with the old name chosen as the version table | Handled, tested | Applies; only goose's version-0 row exists when the guard runs |
| F6 | Baseline differs from v0.5.0's schema (column order, default, index, constraint) | Handled, tested | The equivalence test fails on PostgreSQL 15 and 18 |
| F7 | A statement of the baseline fails partway | Handled, tested | The migration's transaction rolls back; no relation and no version remain |
| F8 | Rollback to zero | Handled, tested | Every relation of the set is dropped; the version table records no applied version |
| F9 | Unclassified failure after the flow is spent, for a parked login (hook decide or `Apply` failure, store or loader fault) | Handled, tested | 303 to the login page with `error=server_error`; the request stays parked |
| F10 | The same, under `WithOIDCFailToClient` | Handled, tested | 303 to the client's redirect URI with `error=server_error`, `state` and `iss`; the request is spent |
| F11 | Ending the parked request fails under `WithOIDCFailToClient` | Handled, tested (existing) | The login's original error is answered, and an error record is logged |
| F12 | Invalid state, unspent flow, unreadable error or hung-up caller | Handled, tested | Unchanged: the plain error, with no redirect |
| F13 | Unclassified failure for a login that is not parked | Handled, tested | Unchanged: the plain error |
| F14 | A broker's own deadline expires while the caller is still connected | Handled | Now `server_error` for a parked login rather than a plain error. Intended: the user can retry from the login page |

## Risks / Trade-offs

- **[A forgotten database with an earlier history]** → D3's guard catches the default name. F4 is
  documented in the changelog with the drop statements.
- **[The equivalence test only compares what it queries]** → It covers every catalog facet a store
  depends on: columns, types, defaults, nullability, indexes, constraints and sequences. Table
  storage parameters (the rate-limit bucket table's fill factor and autovacuum settings) are added
  to the comparison explicitly, because a settled scenario pins them.
- **[Removing the chain's tests loses coverage of backfills]** → The backfills only ever served
  upgrades, and no database can upgrade now. Column-level facts stay pinned by the equivalence
  test and the existing schema scenarios.
- **[`server_error` hides a consumer's bug behind a generic page]** → The cause is still logged at
  the redirect site, as for the other codes.

## Migration Plan

1. **Consumers:** stop every instance and drop the scrty relations and the old version tables, or
   recreate the database. The changelog gives the statements. Then start v0.6.0, which applies the
   baselines.
2. **Rollback:** go back to v0.5.0 on a recreated database. A database v0.6.0 created cannot be
   used by v0.5.0, whose history table differs.

## References

**Researched** (consulted 2026-11-25):
- Reasoned from scrty's own settled specs (`schema-migrations`, `default-identity-store`,
  `oidc-login`), the archived `parked-request-error-answers` design D4, and the code:
  `store/migrate`, `httpsec/oidc_login.go`, `httpsec/oidc_parked_failure.go`,
  `authenticate/oidc/broker_hook.go` (D1–D5).
- goose v3.30.1 source, `internal/gooseutil` `UpVersions`: versions recorded in the database with
  no file are ignored, and every unrecorded file version is applied (D2, D3).

**Primary documentation:**
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) §4.1.2.1: `server_error` as the code for an
  unexpected condition. Supports D5.
- [PostgreSQL: `to_regclass`](https://www.postgresql.org/docs/current/functions-info.html) and
  [`pg_get_constraintdef`](https://www.postgresql.org/docs/current/functions-info.html): name
  resolution through `search_path` and constraint definitions. Support D3 and D4.
