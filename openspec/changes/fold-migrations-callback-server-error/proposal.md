# Proposal: fold the migration sets, and answer unclassified callback failures with server_error

## Why

The first consumer to run scrty beside its own tables cannot start. The identity set's first
migration creates a table named `users`, and only a later migration renames it to `scrty_users`.
On a database that already has an application `users` table, the first migration fails with
`relation "users" already exists`, so the rename never runs. The security-state set has the same
create-then-rename shape. No consumer runs scrty in production yet, so both sets can be reset to a
single migration that creates the prefixed names directly.

The same consumer's design expects a failed sign-in-hook `Apply` at the SSO callback to return the
browser to the provider's login page with `error=server_error`. Today it answers a plain 500. That
outcome is deliberate: the settled design maps only listed failures, and a broker failure that
cannot be classified keeps its plain answer. RFC 6749 §4.1.2.1 defines `server_error` as "an
unexpected condition", which is exactly an unclassified failure. A plain 500 strands the user
outside the login flow they started.

## What Changes

- **BREAKING (schema): one baseline migration per set.**
  - The security-state set and the identity set each become one migration.
  - Each creates every table, index, constraint and sequence directly under its `scrty_` name. The
    identity baseline includes the administration columns and tables.
  - The schema each produces is identical to the one v0.5.0's full chain produces.
  - The create-then-rename migrations and the later incremental migrations are removed.
- **BREAKING (schema): new default version tables.**
  - The defaults become `scrty_state_migrate` and `scrty_identity_migrate`, replacing
    `goose_security_state` and `goose_identity`.
  - Their names stay replaceable.
  - The exported constants keep their Go names and change value.
- **BREAKING (upgrade): earlier databases are refused.**
  - A database migrated by an earlier release must be recreated.
  - Each baseline refuses to apply, and changes nothing, when it finds the earlier release's
    default version table, so the stale history cannot pass silently.
- **Released migrations are again never edited**, from this release on.
- **A parked login's unclassified callback failure answers `server_error`.**
  - Covered: any callback failure after the flow is spent that maps to no other code of the closed
    set, such as a sign-in hook's or its `Apply`'s failure, or a broker or store fault.
  - Such a failure returns to the login page with `error=server_error`, or to the client under
    `WithOIDCFailToClient`.
  - Still keeping their answer: an invalid or unknown state, a flow left unspent, a failure whose
    cause cannot be read, and a caller that has gone.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `schema-migrations`: the security-state set's history is reset to one baseline with a new default
  version table; earlier-release databases are refused; the per-migration and rename requirements
  give way to the baseline's.
- `default-identity-store`: the identity set's history is reset to one baseline with a new default
  version table; the rename requirement is removed.
- `oidc-login`: the closed set's `server_error` covers every unclassified failure after the flow is
  spent; the failures that keep their answer narrow accordingly.

## Impact

- **Migrations:** `store/migrate/securitystate/*.sql` and `store/migrate/identity/*.sql` (replaced),
  and the version-table constants and godoc in `store/migrate`.
- **Tests:** the migration tests in the `test` module that walk the incremental chain or the
  renames are replaced by baseline, equivalence and refusal tests. The `store/migrate` unit tests
  follow the new files.
- **httpsec:** the callback failure mapping in `httpsec/oidc_login.go`, with its tests.
- **Godoc** that names a removed migration version: `store/sqlstore`, `store/pgxstore`,
  `store/gormstore` (`oidcprovider_device.go`).
- **Docs:** `CHANGELOG.md` and `README.md`, which name the version tables and the upgrade steps.
- **Consumers:**
  - Any database already migrated by scrty must be dropped and recreated.
  - A consumer that pins the old version-table names must rename them or recreate the database.
- **Release:** v0.6.0. Every module is tagged by the maintainer.
