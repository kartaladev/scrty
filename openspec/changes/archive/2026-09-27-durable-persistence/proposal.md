## Why

scrty's security packages keep their state in memory by default. That is right for tests and a single process, but lost on restart, invisible to other replicas, and unable to enforce single use across them. Applications running more than one process need that state in PostgreSQL, through the database access style they already use. The long-lived secrets in that state (signing keys, MFA secrets, retained provider ID tokens) must not be usable by anyone who only has a database dump or write access to a table.

## What Changes

- Add durable stores for every security-state record: sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows and OIDC handoffs. They ship on three backends that behave identically:
  - `database/sql`, in the core module;
  - `pgx`, in the nested module `github.com/kartaladev/scrty/pgx`;
  - `gorm`, in the nested module `github.com/kartaladev/scrty/gorm`.
- The storage model:
  - library-owned primary keys are `pkg/id.ID` values in native `uuid` columns;
  - user references are opaque `text`;
  - there are no foreign keys to, and no joins with, identity tables.
- Single-use consumption and link uniqueness are enforced by one conditional write, never by a read followed by a write.
- Each adapter joins a caller's transaction:
  - by default, it uses a transaction the caller attached through that adapter's `WithTx`;
  - a resolver option plugs in the consumer's own transaction manager instead.

  There is no transaction spanning backends.
- Add the security-state migration set:
  - embedded, plain SQL in goose's annotated format;
  - its own version table;
  - no goose helper: goose or the consumer's own tool runs the files, and the goose recipe is compiled as an example in the `test` module;
  - rollback verified all the way down in tests.
- Seal the three long-lived secrets at rest (signing-key private material, MFA secrets, session provider ID tokens):
  - each value is bound to its row, so a ciphertext copied to another row fails to open;
  - a failure to open is an error, never absence;
  - retired keys are re-sealed on read;
  - a durable store holding them cannot be built without a cipher;
  - the cipher is a port, and the default is AES-256-GCM over a keyring with separately named active and retired keys.
- Create the `github.com/kartaladev/scrty/test` module. It holds a PostgreSQL testcontainers helper that verifies full rollback at cleanup, and the store conformance suites that every scrty adapter, every in-memory default and any consumer store can run.

## Capabilities

### New Capabilities

- `security-state-stores`: durable security-state stores on three backends, covering:
  - persistence across processes;
  - atomic single use and link uniqueness;
  - opaque user references;
  - ambient-transaction participation and its override;
  - construction-time validation.
- `schema-migrations`: the security-state migration set, covering:
  - its contents and version table;
  - atomic ordered application;
  - verified rollback;
  - use with goose or the consumer's own tool;
  - the rules for changing released migrations.
- `store-conformance`: the shared suites and PostgreSQL helper that define what every store implementation must prove, including races, transactions, sealed columns and rollback.
- `secrets-at-rest`: sealing of long-lived secrets, covering:
  - binding each value to its row;
  - failing closed;
  - key configuration and rotation;
  - replacing the cipher.

### Modified Capabilities

None. No specs have been archived yet.

## Impact

- **New code, core module:**
  - `sqlstore`: the `database/sql` adapters, `WithTx` and the resolver option;
  - `migrate`: the embedded security-state set;
  - `seal`: the cipher and keyring ports, the envelope and the AES-256-GCM default.
- **New modules:**
  - `pgx` (depends on `jackc/pgx/v5`);
  - `gorm` (depends on `gorm.io/gorm`);
  - `test` (depends on testcontainers-go, testify, goose and the pgx `database/sql` driver).

  Each new module is added to `go.work`, its dependency guard and CI.
- **Goose helper:** it cannot live in the core module, because goose's own module requires `jackc/pgx/v5` and other drivers. Its home is an open question in design.md.
- **Dependencies:** the core module gains none; AES-GCM comes from the standard library.
- **Depends on:**
  - the store contracts defined by `sessions`, `one-time-tokens`, `security-policy`, `signing-keys`, `multi-factor-auth`, `api-keys`, `oidc-login`, `identity-linking` and `oidc-logout`;
  - `id-generation` and `module-layout`.

  The adapters for a contract land once that contract exists.
- **Later changes:**
  - `default-identity-store` reuses the migration conventions and the `test` module for its own set;
  - `expiry-sweeping` schedules the deletion operations these stores expose;
  - `di-wiring` composes these constructors.
- **Consumers:** none yet. No tag has been cut, so no compatibility obligations apply.
