## Why

scrty authenticates and authorizes users, but it does not own them. Its identity ports (user loader, role loader, user provisioner and MFA requirement lookup) are the only way it learns who a user is. A consumer starting from nothing still needs somewhere to keep users, and the ports carry rules that are easy to break quietly:
- provisioning must never adopt an existing account;
- an update must not reset the password-age clock;
- a role rebuild must not drop a locally granted super role;
- a concurrent double submit must not surface a raw driver error.

This change ships an optional PostgreSQL identity store that keeps those rules. It also ships a public conformance suite, so a consumer who keeps their own user tables can prove their port implementations keep the same rules.

## What Changes

- Add a **default identity store**, an opt-in implementation of the four identity ports over six tables: users, roles, assigned roles, organizations, groups and resource privileges.
  - `users.id` is a native PostgreSQL `uuid` holding a UUIDv7 from `pkg/id`. The user reference the rest of scrty sees is its canonical string.
  - The password hash, the password-changed-at time and the MFA-required flag live on `users`.
  - There are no foreign keys anywhere in the identity tables, and none to or from security-state tables. No query joins across the two groups.
- Add **three adapters**, each implementing all four ports:
  - `database/sql` in the core module, with no driver dependency;
  - `pgx` in the `pgx` module;
  - `gorm` in the `gorm` module.
  Each participates in the caller's ambient transaction through the same `WithTx` default and resolver option the security-state adapters use.
- Add a **separate migration set** for the identity tables, with its own version table, so it can be applied, skipped or rolled back independently of the security-state set.
- Add an **identity-port conformance suite** in the `test` module. It is public, it drives any implementation only through the ports plus required seeding hooks, and it never skips an obligation. The three adapters must pass it; consumers can run it against their own implementations.
- Make provisioning safe under concurrency:
  - a username collision is detected by the insert itself;
  - an update locks the user row before rebuilding grants.
- Keep grant order in an explicit column, because scrty's identifier generator is replaceable and grant order decides which duplicate grant survives.
- Leave the password-changed-at time and the MFA-required flag unwritten by any port call. The consumer's own user management owns both.

## Capabilities

### New Capabilities

- `default-identity-store`: the optional PostgreSQL implementation of the identity ports. Covers what loading returns, the create-only and amend-only provisioning rules, role-grant rebuilds, the MFA requirement lookup, concurrency and ambient-transaction behaviour, the identity migration set, and the public conformance suite any port implementation can run.

### Modified Capabilities

None. scrty has no archived specs yet.

## Impact

- **New code:**
  - core module: the `database/sql` identity store, the embedded identity migrations, and shared query text in an internal package;
  - `pgx` and `gorm` modules: their identity stores;
  - `test` module: the identity-port conformance suite, fixtures that prove the suite catches known defects, and the `database/sql` adapter's PostgreSQL integration tests.
- **Dependencies:**
  - the core gains no third-party dependency;
  - the `pgx` and `gorm` modules already exist for security-state stores (durable-persistence);
  - the conformance suite uses testify in the `test` module only.
- **Depends on other changes:**
  - `identity-model` (identity-and-tokens) for the port signatures, user details, sentinel errors and provisioning options, including the accessor that reports which fields a caller named;
  - `schema-migrations` and `security-state-stores` (durable-persistence) for the migration runner, version-table mechanics and the `WithTx`/resolver pattern;
  - `di-wiring` (operations) for including this store in the default wiring;
  - `id-generation` (project-foundation) for identifiers.
- **Consumers:** none yet. A consumer with their own user tables does not import this store and applies only the security-state migrations.
