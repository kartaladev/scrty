# Proposal: fold the migration sets, and answer unclassified callback failures with server_error

## Why

The first consumer to run scrty beside its own tables cannot start. The identity set's first
migration creates a table named `users`, and only a later migration renames it to `scrty_users`.
On a database that already has an application `users` table, the first migration fails with
`relation "users" already exists`, so the rename never runs. The security-state set has the same
create-then-rename shape. The user decided on 2026-11-25 to fold every migration of each set into
one migration that creates the prefixed names directly. That decision rests on the user's statement
that no consumer runs scrty in production. scrty has been tagged since v0.1.0, so this side has not
verified it.

The same consumer's design expects a failed sign-in-hook `Apply` at the SSO callback to return the
browser to the provider's login page with `error=server_error`. Today it answers a plain 500. That
outcome is deliberate: the settled design maps only listed failures, and a broker failure it cannot
classify keeps its plain answer. A plain 500 strands the user outside the login flow they started.

## What Changes

- **BREAKING (schema): one baseline migration per set.**
  - The security-state set and the identity set each become one migration.
  - Each creates every table, index, constraint and sequence directly under its `scrty_` name. The
    identity baseline includes the administration columns and tables.
  - The schema each produces is identical to the one v0.5.0's full chain produces.
  - Every earlier file of both sets is removed.
- **BREAKING (schema): new default version tables.**
  - The defaults become `scrty_state_migrate` and `scrty_identity_migrate`, replacing
    `goose_security_state` and `goose_identity`.
  - Their names stay replaceable.
  - The exported constants keep their Go names and change value.
- **BREAKING (upgrade): earlier databases must be recreated.**
  - A database migrated by an earlier release is not upgraded.
  - Going back to v0.5.0 from a v0.6.0 database is not supported.
- **Released migrations are again never edited or removed**, from this release on.
- **A parked login's unclassified callback failure answers `server_error`.**
  - Covered: a broker or store failure after the flow is spent that maps to no other code, such as a
    sign-in hook's or its `Apply`'s failure.
  - It returns to the login page with `error=server_error`, or to the client under
    `WithOIDCFailToClient`, and is logged at error level with its cause's type.
  - Still keeping their plain answer: an invalid or unknown state, a flow left unspent, an unknown
    provider, a re-authentication refusal, a failure whose cause cannot be read, and a caller that
    has gone.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `schema-migrations`: the security-state set's history is reset to one baseline with a new default
  version table; the per-migration and rename requirements give way to the baseline's; the table
  count is corrected to twenty-five.
- `default-identity-store`: the identity set's history is reset to one baseline with a new default
  version table; the rename requirement is removed; the privilege-scope default no longer refers to
  a removed migration.
- `oidc-login`: the closed set's `server_error` covers unclassified broker and store failures after
  the flow is spent; the failures that keep their answer are listed in full; a `server_error`
  answer is logged with its cause's type.

## Impact

- **Migrations:** `store/migrate/securitystate/*.sql` and `store/migrate/identity/*.sql` (replaced),
  and the version-table constants and godoc in `store/migrate`.
- **Tests:** the migration tests in the `test` module that walk the incremental chain or the renames
  are replaced by baseline and equivalence tests. The `store/migrate` unit tests and
  `store/gormstore/models_test.go` follow the new files.
- **httpsec:** the callback failure mapping and its logging (`httpsec/oidc_login.go`), with tests.
- **Godoc and comments that name a removed migration:**
  - `store/{sqlstore,pgxstore,gormstore}`: `oidcprovider_device.go` and `identity.go`;
  - `store/{sqlstore,pgxstore}/limiter_factory.go`.
- **Docs:** `CHANGELOG.md` and `README.md`, which name the version tables, a removed migration, the
  fresh-install steps and the rename's limits.
- **Consumers:** any database already migrated by scrty must be dropped and recreated.
- **Release:** v0.6.0. Every module is tagged by the maintainer.
