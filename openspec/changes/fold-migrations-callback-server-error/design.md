# Design: fold the migration sets, and answer unclassified callback failures with server_error

## Context

See `proposal.md` for why.

**Migrations.** `store/migrate` embeds two goose-format sets:
- **Security state:** eight files, ending with `20261124000000_scrty_prefix` and
  `20261125000000_scrty_selected_role`.
- **Identity:** three files, `20260928000000_identity`, `20261124000000_scrty_prefix` and
  `20261125000000_scrty_administration`.

Both prefix migrations rename relations that earlier migrations created unprefixed. The migrations
v0.3.0 to v0.5.0 ship are identical. Goose creates its version table, with a version-0 row, before
it runs a migration's transaction. It ignores versions recorded in the database that have no file,
and applies every file version not yet recorded. The `test` module holds about 3,800 lines of tests
that walk the chain step by step.

**Callback.** `httpsec/oidc_login.go` reads a callback's error once (`readCallbackFailure`) and maps
it to a code through `callbackCode`:
- refusals map to `access_denied`;
- outages map to `temporarily_unavailable`;
- everything else, including the re-authentication refusal and a bare unknown provider, falls to
  the default and gets no code.

With no code, the parked login answers the plain error, which the chain logs as a server failure. A
failed sign-in hook, or a failed `Apply`, reaches the callback as the broker's opaque `hookFailure`.
Today `returnParked` logs a returned login only at INFO, with the code and no cause.

## Goals / Non-Goals

**Goals:**
- Each set applies cleanly to a schema that already holds application tables of the old names.
- The resulting schema is provably the same as v0.5.0's.
- A parked login never ends in a bare 500 for an unclassified fault after its flow is spent.
- Such a fault stays visible to operators.

**Non-Goals:**
- **Detecting, upgrading or adopting a database migrated by an earlier release, and going back to
  v0.5.0.** The user decided on 2026-11-25 to fold the migrations and not to go back, so earlier
  databases are recreated.
- **Changing any table, column or index.** The fold is schema-neutral.
- **Provider access tokens on the chain.** That is `resource-server`, PR #151, in v0.6.0. Its new
  security-state migration is a later file after this change's baseline.

## Decisions

### D1. One baseline migration per set, created directly under `scrty_` names

**Files:**
- `store/migrate/securitystate/20261126000000_security_state.sql`
- `store/migrate/identity/20261126000000_identity.sql`

**Up section:**
- It creates every table, index, constraint and sequence of v0.5.0's final schema, directly under
  its `scrty_` name.
- Columns that later migrations added are folded into each `CREATE TABLE`, in the column order the
  chain produced (attnum order). That keeps `INSERT … SELECT *` and the lineage table's "same
  columns as sessions" rule working.
- Defaults, identity generation (`scrty_password_history.seq` stays `GENERATED ALWAYS AS
  IDENTITY`), table persistence and storage parameters are kept exactly.

**Down section:**
- It drops everything the up section created.
- It keeps the chain's `SET LOCAL lock_timeout = '5s'`, so a rollback blocked by a long transaction
  fails within the bound rather than queueing every query. `TestMigrationRollback_LockBound` keeps
  pinning that against the baseline.
- One `goose down` now drops the whole set and its data (F12).

**Transactions:** both files keep goose's per-migration transaction, so no `NO TRANSACTION`
annotation is allowed. The existing annotation check is extended to the identity set.

**Version:** one timestamp newer than every v0.5.0 file. The two sets record into separate tables,
so sharing a version number is harmless.

**Default and override:** there is no option. The prefix is fixed, as settled before. A consumer
isolates the relations with a schema plus `search_path`, as today.

**Alternatives considered:**
- **Keep the chain and only change the first migrations.** That edits released files just the same,
  and leaves the rename steps doing nothing.
- **Make the creates conditional (`CREATE TABLE IF NOT EXISTS`).** That would silently adopt a
  consumer's own table of the same name.
- **Adopt a v0.5.0-head database by reusing v0.5.0's last version number.** It would need no
  recreation, but the user chose a clean history.

### D2. New default version tables

- The defaults change:
  - `SecurityStateVersionTable` becomes `"scrty_state_migrate"`;
  - `IdentityVersionTable` becomes `"scrty_identity_migrate"`.
- The Go names stay the same, and the user chose the new values on 2026-11-25.

**Default and override:** the constants are the defaults. A consumer passes any other name to their
runner (`goose.WithTableName`), as today.

### D3. No detection of an earlier history

The baselines do not look for an earlier scrty history. A database migrated by an earlier release
meets one of two outcomes:
- **It holds `scrty_` relations** (v0.5.0 to v0.3.0): the first `CREATE` fails on the existing
  relation, and the transaction leaves nothing (F3).
- **It holds only unprefixed scrty tables** (v0.2.x and earlier): the baseline creates new, empty
  `scrty_` tables beside them (F4).

This is accepted by the user's decision. The changelog tells every consumer to recreate the
database.

**Alternative considered:** a guard that refuses when the old default version table records
history. The user declined it on 2026-11-25 as beyond a fold.

### D4. Equivalence is proven against a frozen copy of the v0.5.0 chain

**The frozen copy:**
- The v0.5.0 files of both sets are copied, unchanged, into the `test` module under
  `testdata/migrate/v0.5.0/`.
- They are never embedded in the library. They do ship inside the released `test` module's zip,
  as its other test data does.

**The test:**
- It applies the frozen chain to one database and the baseline to another, on both CI PostgreSQL
  majors (15 and 18).
- It compares:
  - columns in attnum order, with type, nullability, default and `attidentity`;
  - each table's `relpersistence` and `reloptions`;
  - index names and definitions, with the schema name normalised;
  - sequences with their `pg_sequence` parameters;
  - constraint definitions (`pg_get_constraintdef`), compared by definition and owning table.
- Index names, and the names of constraints that indexes back, must match exactly. Names of check
  constraints that no index backs may differ: the chain kept their pre-rename names, and the
  baseline gives them PostgreSQL's natural prefixed names.

**Red step:** the two catalogs come from byte-identical SQL until the baseline exists, so the test
is shown red by mutation. A column is dropped from a scratch copy of the frozen fixture, the diff
is seen, and the copy is restored.

**Alternative considered:** a golden JSON inventory. A frozen chain is checked live on each
PostgreSQL major, and it cannot drift from what v0.5.0 actually shipped.

### D5. Unclassified broker and store failures after the flow is spent answer `server_error`

**The change:** `callbackCode` lists its exclusions explicitly, ahead of the mapped codes, then
returns `oidcprovider.CodeServerError` by default.

**The exclusions, which keep the plain answer:**
- the flow left unspent;
- an invalid state;
- a hung-up caller;
- `ErrOIDCReauthenticate`;
- `oidc.ErrUnknownProvider`.

An error whose walk aborted is already returned before any code, by `readCallbackFailure`.

**Why those two stay plain:** the earlier design kept re-authentication and a bare unknown provider
out of the closed set only by letting them fall to the default. The user decided on 2026-11-25 that
both keep their plain answer: re-authentication is a deliberate answer, not a fault.

**Unchanged:**
- **Precedence:** a refusal still wins over an outage, and both win over the default.
- **The parked-request checks:** a request that fails them keeps its answer, as the settled
  "Returning to the login page passes the parked-request checks first" requires.
- **Ending under `WithOIDCFailToClient`:** if ending the request fails, the original error is still
  answered.
- **Non-parked logins:** a login that is not parked is unchanged, because `parkedDestination` gates
  the redirect.
- **Events:** `emitCallbackRefused` is unchanged, so a server-side failure emits no
  `AuthnLoginFail`.

**Default and override:** this is the default for parked logins under completion.
`WithOIDCFailToClient` moves the answer to the client's redirect URI. There is no option to restore
the plain 500. `server_error` names nothing about the account, the fault is logged (D7), and a
consumer that wants plain errors does not enable completion.

**Departure:** this revises D4 of the archived `parked-request-error-answers` design, whose last
item kept an unclassified broker failure's plain answer. RFC 6749 §4.1.2.1 defines `server_error`
for an unexpected condition at the client's redirect URI, which supports the `WithOIDCFailToClient`
path. The login page's `error` parameter is scrty's own convention, which reuses the same code set.
The user decided on 2026-11-25.

### D6. Released migrations are removed once, by decision

The settled rule "released migrations are never edited" is suspended for this release only, by the
user's decision of 2026-11-25. From v0.6.0 the rule reads "never edited or removed", and the
baselines are released files.

### D7. A `server_error` answer is logged at error level with its cause's type

**The record:**
- When the code is `server_error`, the callback writes one error-level record built with
  `diag.Failure(reason, err)`, which names the reason and the cause's Go type.
- It goes through the chain's sampler, as `returnParked`'s other error records do.
- It never holds the error text, the handle, the state or the redirect target.

**What stays as it was:** the existing INFO record of the redirect is unchanged, and refusals and
outages write no error-level record.

**Why:** without it, a broken hook or store turns into quiet 303s, and alerting that watches 5xx
answers goes silent.

**Default and override:** this is always on. The consumer controls the logger and sampler as for
every chain record.

## Failure modes

| # | Failure | State | What the caller sees |
|---|---|---|---|
| F1 | Schema already holds an application `users` or `sessions` table | Handled, tested | Baseline applies; the application table is untouched |
| F2 | Baseline differs from v0.5.0's schema (column order, default, identity, persistence, storage parameters, index, constraint) | Handled, tested | The equivalence test fails on PostgreSQL 15 and 18 |
| F3 | Database migrated by v0.3.0–v0.5.0 | Handled, tested | `CREATE TABLE scrty_…` fails on the existing relation. The transaction leaves no relation and no version; goose's own version table, with its version-0 row, remains |
| F4 | Database migrated by v0.2.x or earlier (unprefixed tables only), or with relations in a schema later on the `search_path` | Accepted (user decision) | Not detected. New empty `scrty_` tables are created in the current schema; the stores read them. The changelog tells every earlier database to be recreated |
| F5 | A statement of the baseline fails partway | Handled, tested | Rolled back; the test pre-creates the last relation and asserts every earlier one is absent |
| F6 | Going back to v0.5.0 on a v0.6.0 database | Accepted (user decision) | Not supported. v0.5.0's chain fails partway, on `relation … already exists`. The changelog says never to run v0.5.0's migrations on a v0.6.0 database |
| F7 | Two replicas apply the set at once without a session locker | Accepted | The second fails on an existing relation, with nothing applied; it succeeds on retry. The changelog and the goose example recommend `goose.WithSessionLocker` |
| F8 | Unclassified broker or store failure after the flow is spent, for a parked login | Handled, tested | 303 to the login page with `error=server_error`; the request stays parked; one error record names the cause's type |
| F9 | The same, under `WithOIDCFailToClient` | Handled, tested | 303 to the client with `error=server_error`, `state` and `iss`. The request is spent, so a transient fault now ends it where a plain 500 left it retryable. Accepted as the user's choice |
| F10 | Ending the parked request fails under `WithOIDCFailToClient` | Handled, tested (existing) | The login's original error is answered, and an error record is logged |
| F11 | Invalid state, unspent flow, re-authentication, unknown provider, unreadable error, hung-up caller, failed parked-request check, or a login that is not parked | Handled, tested | Unchanged: the plain error, with no redirect |
| F12 | `goose down` on the baseline | Handled, tested | Drops the whole set and its data, bounded by `lock_timeout`; the changelog warns |
| F13 | A broker's own deadline expires while the caller is still connected | Handled | `server_error` for a parked login rather than a plain error. Intended: the user can retry from the login page |

## Risks / Trade-offs

- **[The unverified claim that no consumer runs scrty in production]** → The user's decision rests
  on it. The changelog states the recreate requirement prominently.
- **[The equivalence test only compares what it queries]** → It covers every catalog facet a store
  or a settled scenario depends on (D4).
- **[Removing the chain's tests loses coverage of backfills]** → The backfills only ever served
  upgrades, and no database can upgrade now. One synthetic populated-migration test
  (`testdata/migrations/populated`) keeps the "later migrations apply to populated databases" rule
  pinned.

## Migration Plan

1. **Consumers:** stop every instance and drop the database, or drop every `scrty_%` relation and
   the version tables `goose_security_state`, `goose_identity`, `scrty_state_migrate` and
   `scrty_identity_migrate`. Then start v0.6.0, which applies the baselines.
2. **Rollback:** not supported (F6). Going back means recreating the database for the older release.

## References

**Researched** (consulted 2026-11-25):
- Reasoned from scrty's own settled specs (`schema-migrations`, `default-identity-store`,
  `oidc-login`), the archived `parked-request-error-answers` design D4, and the code:
  `store/migrate`, `httpsec/oidc_login.go`, `httpsec/oidc_parked_failure.go`,
  `authenticate/oidc/broker_hook.go`, `authenticate/oidc/login.go`, `internal/diag` (D1–D7).
- goose v3.30.1 source, `internal/gooseutil` `UpVersions` and the provider's version-table setup:
  versions recorded with no file are ignored, unrecorded file versions are applied, and the version
  table is created before the migration's transaction (D2, D3, F3).
- An adversarial review of PR #149, dated 2026-11-25, reproduced two findings in a disposable copy:
  - `TestParkedFailureCode/the_re-authentication_refusal` failing under a bare default (D5);
  - `TestRollbackToV050_OnFoldedDatabase_LeavesUnprefixedTables` failing with
    `relation "scrty_account_recoveries" already exists` (F6).

**Primary documentation:**
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) §4.1.2.1: `server_error` at the client's
  redirect URI. Supports D5's `WithOIDCFailToClient` path.
- [PostgreSQL system catalogs](https://www.postgresql.org/docs/current/catalogs.html) and
  [`pg_get_constraintdef`](https://www.postgresql.org/docs/current/functions-info.html): the facets
  D4 compares.
