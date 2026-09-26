## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** `project-foundation` provides the following:
  - the core module, `go.work` and build gates;
  - `pkg/id`: a 16-byte `ID` whose `Scan` accepts text and 16-byte binary, and whose `Value` sends canonical text;
  - the dependency guard.

  The `test` module does not exist yet. That change deferred it to this one, together with `RunTestPostgres`.
- **Store contracts are owned elsewhere.** The capabilities that own each behaviour define its record shape and store contract:
  - `sessions` and `one-time-tokens` (authn-authz-core);
  - `security-policy` (login attempts);
  - `signing-keys` (identity-and-tokens);
  - `multi-factor-auth` and `api-keys` (auth-methods);
  - `oidc-login`, `identity-linking` and `oidc-logout` (oidc-brokering).

  Each of those changes also ships the in-memory default. This change implements the same contracts durably and does not restate them.
- **Product decisions already made:**
  - the security-state tables hold only security state;
  - primary keys are `pkg/id.ID` in native `uuid` columns;
  - user references are `text`, with no foreign keys or joins to identity tables;
  - there are three adapters (`database/sql` in core, `pgx` and `gorm` nested);
  - each adapter owns `WithTx(ctx, tx)` plus a resolver option, and no transaction spans backends;
  - migrations are embedded plain SQL with their own version table per group. No goose helper ships; goose (or any tool that reads the format) runs them, and the goose recipe is a compiled `Example` in the `test` module;
  - constructors are the primary API, and DI wiring is optional.
- **Project rules:**
  - library-design: every default is replaceable, and wiring mistakes fail at construction;
  - golang-tdd;
  - table-test;
  - use-testcontainers.
- **Target database:** PostgreSQL only.

- **Inbound needs from `oidc-brokering`** (reported by that change on completion; its in-memory stores and contracts are final):
  - tables matching the records `oidc.Link`, `oidc.Flow` and `oidc.HandoffRecord` as the table model below now describes them: the handoff row keys the user by reference (`user_id`), not by username, and both flows and handoffs store `next`;
  - the durable adapters run the `test/oidc` conformance suites `RunLinkStoreSuite`, `RunFlowStoreSuite` and `RunHandoffStoreSuite`, which each come with a load-bearing guard. They pin a refused zero cutoff on `DeleteExpired` (`oidc.ErrRetainSinceRequired`), a strictly-before cutoff (a record expiring exactly at the cutoff is kept), single completion and single consumption under 8 racing callers, and refusal of an identical re-insert of a link;
  - a `session.Cipher` implementation for the existing `session.NewEncryptedStore`, which seals the federated session's retained ID token (`secrets-at-rest`).

## Goals / Non-Goals

**Goals:**
- One schema and three adapters whose parity is proven by shared suites, not assumed.
- Single use and link uniqueness that hold under concurrency and across replicas.
- Long-lived secrets that a database dump or table write access cannot use.
- Migrations whose rollback has actually been executed in tests.

**Non-Goals:**
- Identity tables and their migration set. These belong to `default-identity-store`.
- Scheduling expiry deletion, which belongs to `expiry-sweeping`.
- DI container wiring, which belongs to `di-wiring`.
- Databases other than PostgreSQL. A consumer can implement the contracts elsewhere and prove them with the suites.
- A transaction spanning backends.
- Sealing the short-lived OIDC flow and handoff values (decision 9).
- A batch re-seal operation. Retiring a key therefore cannot be proven safe mechanically (see Risks).

## Decisions

### 1. Where the code lives

| Module | Package | Contents |
|---|---|---|
| core | `sqlstore` | `database/sql` adapters, `WithTx`, options |
| core | `migrate` | embedded security-state set (`FS()`, `Dir`, default version table name) |
| core | `seal` | `Cipher` and `Keyring` ports, envelope, AES-256-GCM default, the signing-key and MFA sealing wrappers, `SessionCipher` |
| core | `internal/pgschema` | SQL text shared by `sqlstore` and `pgx` (identical `$n` SQL) |
| `…/pgx` | `pgx` | native pgx v5 adapters over `pgxpool.Pool` / `pgx.Tx`, `WithTx` |
| `…/gorm` | `gorm` | gorm adapters, `WithTx`, models |
| `…/test` | `test` (root), `storetest` | `RunTestPostgres` in `testutils.go` beside `RunTestSMTP` and `RunTestKeycloak`, conformance suites |

- **Row scanning:** each adapter keeps its own. Query text is shared only where the SQL is identical.
- **Sealing logic:** it lives once, beside the store contracts, as wrappers that seal on write and open on read. Adapters compose them (decision 9), so the invariant is not restated per adapter.
- **Default:** a `database/sql` consumer gets no pgx, gorm, goose or test dependency.
- **Override:** a consumer requires the module for their access style.

### 2. Table model

Tables are created unqualified, in the connection's `search_path`. Each owning capability's record defines the remaining columns.

| Table | Primary key | Unique | Sealed | Notes |
|---|---|---|---|---|
| `sessions` | `id uuid` | `id_digest` | `external_id_token text NOT NULL DEFAULT ''` (base64url envelope; `''` = none) | `id_digest bytea`: SHA-256 of the session identifier, which is never stored (decision 10); `user_id text`; `data jsonb`; `external_provider`, `external_issuer`, `external_session_id text NOT NULL DEFAULT ''`; partial indexes `(external_issuer, external_session_id) WHERE external_session_id <> ''` and `(user_id, external_issuer) WHERE external_issuer <> ''` |
| `signing_keys` | `id uuid` | `kid` | `private_key bytea NOT NULL` (envelope over PKCS8 DER) | public JWK not sealed: it is published |
| `login_attempts` | `id uuid` | — | — | `username text`; indexes `(username, attempted_at)` and `(attempted_at)`; the second serves deletion, which cannot range-scan the composite, so the two must not be consolidated |
| `mfa_enrolments` | `id uuid` | `user_id` | `secret text NOT NULL` (base64url envelope) | `confirmed_at timestamptz NULL` (`NULL` = pending); `last_step bigint NOT NULL DEFAULT 0` (last accepted TOTP time step; the contract's zero value); `created_at`. A new pending enrolment replaces a pending one and resets `last_step`; a confirmed one is never replaced (`multi-factor-auth`) |
| `api_keys` | `id uuid` (the key's own id) | — | — | `user_id text` (the principal); `name text`; `scopes jsonb` (ordered array); `secret_digest bytea` one-way digest; `expires_at`, `revoked_at`, `last_used_at timestamptz NULL`; `created_at` |
| `one_time_tokens` | `id uuid` (the token's own id) | — | — | `purpose`, `subject`; `secret_hash`, `binding_hash` digests; `consumed_at timestamptz NULL`; index `(purpose, subject)` |
| `oidc_links` | `id uuid` (the link's own id) | `(provider, issuer, subject)` | — | `user_id text` (the opaque user reference, compared byte for byte), indexed for deletion by user; `username`, `email text` kept for operators only, never used for lookup and never keyed on; `created_at` |
| `oidc_flows` | `id uuid` | `handle` | — | `provider`, `state`, `nonce`, `verifier`, `next text` (untrusted, stored verbatim); `expires_at`; `completed_at NULL`; index `expires_at`. `handle` is minted by the store from `crypto/rand` and returned by `Begin`. `Complete(handle, provider, state)` is one conditional `UPDATE … WHERE handle = $1 AND provider = $2 AND state = $3 AND state <> '' AND completed_at IS NULL AND expires_at > $now`, with `$now` from the store's clock |
| `oidc_handoffs` | `id uuid` (the record's own id) | `token_id` | — | `secret_hash` digest; `user_id text` (the user reference the code was issued for; redemption loads the user by it and checks the loaded reference still matches byte for byte); `next text` (untrusted, re-resolved through the redirect allowlist at redemption); `provider`, `issuer text`; `session_id`, `id_token text NOT NULL DEFAULT ''`; `consumed_at NULL`; index `expires_at`; no roles column (roles are resolved at redemption) |

Rules and why:
- **Primary keys.** Where the record already carries its own `id.ID` (one-time tokens, API keys, links, handoffs), that id is the primary key, stored as given. Where it carries none (sessions, signing keys, login attempts, MFA enrolments, flows), the store mints one from its `id.Generator`. Default: `id.NewV7Generator()`. Override: `WithIDGenerator` on those five stores' adapters.
- **Natural keys** (`id_digest`, `kid`, `user_id` on enrolments, `token_id`, `handle`) are unique indexes, so their format stays with the owning capability.
- **Tests:** the id-generation capability's native-`uuid` round-trip scenario is verified in this change's `test` module.
- **Guard columns are nullable.** Every consumption guard (`consumed_at`, `completed_at`) is nullable, because a `NOT NULL` default makes `IS NULL` unsatisfiable and silently turns single use into multiple use. The migration file carries that comment, and a migration test pins it.
- **Empty strings instead of NULL.** Absent federation and handoff values are `NOT NULL DEFAULT ''` rather than `NULL`, so every adapter scans plain strings.
- **Empty arguments never match.** Deletions by issuer or session id carry `$n <> ''` guards, so an empty argument never matches unfederated rows.
- **Issuer always leads session matching.** A session id is unique only within its issuer, so a match on the session id alone would let one provider end another provider's sessions.
- **Consumer-owned session data** is `jsonb`, written and returned unchanged.

### 3. Single use and uniqueness are enforced by the write

- **One-time token and handoff consumption:** `UPDATE … SET consumed_at = $2 WHERE token_id = $1 AND consumed_at IS NULL`.
  - Zero rows affected is the refusal.
  - An unknown record and an already-consumed record return the same sentinel, and the first `consumed_at` is kept.
  - Expiry and the secret comparison belong to the owning capability, which runs them before consuming. This is the check-then-consume ordering that the `one-time-tokens` capability requires.
- **Flow completion:** it puts the provider, the state, the "not yet completed" condition and the expiry in one `UPDATE`.
  - A caller who does not know the state cannot burn the flow.
  - Every refusal is reported identically.
  - The state comparison is the database's, not constant-time. Timing a 32-byte comparison behind an index seek over a network is not a practical attack, and the atomicity is not negotiable.
- **Link insert:** `INSERT … ON CONFLICT (provider, issuer, subject) DO NOTHING`. Zero rows affected maps to the owning capability's "already exists" sentinel. The stored link is never overwritten, because the last writer would otherwise own the external identity. An identical re-insert is refused too.
- **MFA confirmation:** `UPDATE mfa_enrolments SET confirmed_at = $3, last_step = $2 WHERE user_id = $1 AND confirmed_at IS NULL`. Zero rows affected means already confirmed, or no enrolment.
- **TOTP step acceptance:** `UPDATE mfa_enrolments SET last_step = $2 WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_step < $2`.
  - Zero rows affected is a replay refusal.
  - Two concurrent verifications of the same step, or of an older step, cannot both succeed.
  - The `multi-factor-auth` capability validates the code against the secret before calling it.
- **Deletions that report a count:** deleting links by user reference returns the number of links removed. Deleting sessions by user and external issuer, and by issuer and external session id, also returns counts.
- **Session writes:** `Create` is `INSERT … ON CONFLICT (id_digest) DO NOTHING`, and zero rows affected is the duplicate refusal. `Save` is an `UPDATE` only, and zero rows affected is `session.ErrSessionNotFound`, so a save racing a logout never re-creates the session (`sessions`).
- **Pending enrolment:** `PutPending` is `INSERT … ON CONFLICT (user_id) DO UPDATE SET secret = …, created_at = …, last_step = 0 WHERE mfa_enrolments.confirmed_at IS NULL`. Zero rows affected is `mfa.ErrAlreadyEnrolled`, and the confirmed enrolment is unchanged.
- **API key revocation:** `UPDATE … SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`. Zero rows affected is `apikey.ErrKeyNotFound`, and the first revocation time is kept.
- **Upserts by design:** only signing keys upsert (by `kid`), as their contract defines.
- **Override:** none. Atomicity is the guarantee. A consumer who needs other semantics implements the contract and runs the suites.
- **Alternative rejected:** a read followed by a write. It passes every sequential test and permits double consumption or double linking under concurrency.

### 4. Time

- **Session and flow stores:** they use their configured clock, sessions for expiry checks, counts and `DeleteExpired`, flows for the expiry condition in `Complete`. Default: `time.Now`. Override: `WithClock`.
- **Other stores:** they take the comparison time from the caller (deletion cutoffs, the consumption time, a login attempt's time).
- **Precision:** stored times are UTC at microsecond precision. The suites compare with `time.Time.Equal`.

### 5. Ambient transactions

Each adapter resolves the handle to run each operation on, in this order:
1. **Resolver:** if a resolver option is configured and reports a transaction, that transaction is used.
2. **Context:** otherwise, a transaction attached with that adapter's own `WithTx` is used.
3. **Base handle:** otherwise, the handle passed to the constructor is used.

| Adapter | Attach | Resolver option | Base handle |
|---|---|---|---|
| `sqlstore` | `WithTx(ctx, *sql.Tx)` | `WithTxResolver(func(ctx) (DBTX, bool))`, where `DBTX` is the `ExecContext`/`QueryContext`/`QueryRowContext` subset | `*sql.DB` |
| `pgx` | `WithTx(ctx, pgx.Tx)` | `WithTxResolver(func(ctx) (pgx.Tx, bool))` | `*pgxpool.Pool` |
| `gorm` | `WithTx(ctx, *gorm.DB)` | `WithTxResolver(func(ctx) (*gorm.DB, bool))` | `*gorm.DB` |

- **Default:** the adapter's own context key.
- **Override:** the resolver. It replaces the context lookup, so a consumer's transaction manager needs no second attachment.

Containment:
- **Refusals** are expressed as zero rows affected, never as a failed statement, so they never abort the caller's transaction.
- **Multi-statement operations** run inside a savepoint when a transaction is ambient, and inside their own transaction otherwise:
  - `sqlstore` issues `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` / `RELEASE` itself, with names from a process-local counter, never from input;
  - pgx uses `Tx.Begin`;
  - gorm uses `SavePoint`/`RollbackTo`.
- **Why savepoints:** PostgreSQL aborts the whole transaction on the first failed statement, so without one the caller's `COMMIT` becomes a rollback. `ROLLBACK TO SAVEPOINT` is the one statement an aborted transaction still accepts.
- **Limit, stated in the `WithTx` godoc:** an unexpected backend error on a single-statement write inside a caller's transaction aborts that transaction, as PostgreSQL defines.
- **No transaction across backends.** A transaction attached for one adapter is invisible to the others. Consumers pick one backend per deployment. A conformance scenario pins this.

### 6. Construction-time validation

Every adapter constructor returns `(store, error)`. It rejects:
- a nil base handle;
- a nil option value;
- for stores with sealed columns, a nil `Cipher` (decision 9).

Constructors do not query the database.

### 7. Errors

- **Refusals:** they return the owning capability's sentinels.
- **Backend failures:** they are wrapped with the operation name and are never converted into a refusal or into absence.
- **No stored values in errors:** error text never includes stored values, secrets or user references. Refusals that would otherwise come from constraint violations are handled by the write (decision 3), so no raw constraint error, which embeds the conflicting value, reaches the caller.

### 8. Migrations

**Files.**
- **Location:** `migrate/securitystate/`, embedded, exposed as `migrate.SecurityState()` with `FS()`, `Dir` and `VersionTable`.
- **Format:** plain SQL in goose's annotated format (`-- +goose Up`, `-- +goose Down`, `StatementBegin`/`StatementEnd`), named with a UTC timestamp version (`YYYYMMDDHHMMSS_name.sql`).
- **Down sections:** they drop in reverse creation order with `DROP TABLE IF EXISTS`, so a teardown still completes after a test has deliberately dropped a table to simulate an outage.
- **Comments:** comments that record a choice (nullable guards, issuer-leading indexes, the second `login_attempts` index, the absence of foreign keys) are kept in the file.
- **Forbidden text:** the literal goose annotation for opting out of a transaction must not appear anywhere in a file, not even inside a comment, because goose parses every comment line for annotations.
- **Transactions:** each migration runs in its own transaction (goose's default), and PostgreSQL DDL is transactional, so a failed migration leaves nothing behind.

**Version table.**
- **Default:** `goose_security_state`, used only by this set. The identity set uses its own table.
- **Override:** the consumer passes any name to goose's store, or to their own tool.

**Applying.**
- **Consumer's own tool:** the consumer runs the files with goose or any tool that reads the format. The documented goose recipe is `goose.NewProvider` with a store named after the version table, then `Up` or `DownTo`. No helper wraps it (see Open Questions).

**Squashing and released files.**
- **Before the first tag:** the set may be squashed, because no deployed database carries its history yet. Once a consumer exists, a squash would break deployments.
- **After a tag:** files are append-only.
- **Populated tables:** a new migration that adds a `NOT NULL` column must apply to a populated table. A data migration is tested against seeded rows, because on an empty database its statements do nothing.

**Rollback verified.**
- **At cleanup:** `RunTestPostgres` rolls a set back with `DownTo(0)`, not with a single `Down`, which undoes only the most recent migration. A rollback error fails the test with `t.Errorf`; it is not merely logged.
- **Leftover tables:** the set's own test adds a finalizer, run after rollback, that fails when any non-goose table remains and names it. `IF EXISTS` would otherwise hide a table the `Down` forgot.
- **Per-migration down sections:** each migration's `Down` is also executed on its own against a migrated database, since a full rollback can mask a `Down` that forgot a column on a table a later `Down` drops.

### 9. Secrets at rest

**What is sealed.** Three long-lived secrets:

| Secret | Why it is sealed |
|---|---|
| signing-key private material | valid until rotation |
| MFA secrets | valid indefinitely |
| the provider ID token retained on sessions | lives as long as the session |

Deliberately not sealed:
- **OIDC flow verifiers and nonces, and the handoff's ID token:** each is single-use, guarded against double use, scoped to one login and deleted within minutes. Its value expires before a dump is usable.
- **API key, one-time token and handoff secrets:** they are stored only as one-way digests.
- **The public JWK:** it is published.

**Ports** (`seal`):

```go
type Cipher interface {
    Seal(plaintext, aad []byte) ([]byte, error)
    Open(sealed, aad []byte) (plaintext []byte, keyID string, err error)
    ActiveKeyID() (string, error)
}
type Keyring interface {
    Active() (id string, key []byte, err error)
    ByID(id string) ([]byte, error)
}
func NewKeyring(opts ...KeyringOption) (Keyring, error)
func WithEncryptionKey(id string, key []byte) KeyringOption        // seals and opens; exactly one
func WithRetiredEncryptionKey(id string, key []byte) KeyringOption // opens only; zero or more
func NewAEADCipher(kr Keyring) Cipher                              // AES-256-GCM
var ErrDecryptionFailed, ErrUnknownKeyID, ErrInvalidConfiguration error
```

- **Active and retired keys are named separately.** A "first key wins" rule is how the wrong key ends up sealing production data.
- **Keyring validation:** `NewKeyring` returns `ErrInvalidConfiguration` for:
  - zero or two active keys;
  - a key that is not 32 bytes;
  - an empty or duplicate id;
  - an id outside `[A-Za-z0-9._-]{1,64}`.
- **Errors:**
  - `ErrDecryptionFailed` is opaque: a wrong key, a wrong AAD, a tampered value and a truncated value look the same;
  - `ErrUnknownKeyID` is distinct, because it signals an operator who removed a key that values still need.
- **Replacing the default:** any `Cipher`, for example one backed by a key management service, replaces the AES-256-GCM implementation wholesale. No cloud SDK becomes a dependency.

**Composition.**
- **Sessions:** the durable session stores compose the existing `session.NewEncryptedStore` with `seal.SessionCipher(c)`, an adapter from `seal.Cipher` to `session.Cipher`. The sealing rule for sessions stays in one place, owned by `sessions`.
- **Signing keys and MFA:** `seal` holds one wrapper per contract, sealing on write and opening on read. Re-seal on read calls a small exported port that each adapter implements with the conditional write, and that port writes nothing when a caller's transaction is ambient (decision 10).
- **No unsealed durable store is exported:** each adapter's exported constructor for these three stores takes the cipher and returns the wrapped store. The unwrapped store is unexported.

**Envelope.**
- **Layout:** `magic(4) | keyIDLen(1) | keyID | nonce(12) | ciphertext‖tag`, with a random nonce for each seal.
- **What the tag covers:** the magic turns "not a sealed value" into a clear error. The header is not covered by the GCM tag, but a tampered key id resolves to the wrong key (or `ErrUnknownKeyID`), and a tampered nonce fails the tag.
- **Encoding per column:** `bytea` for signing keys. MFA secrets and session ID tokens are stored base64url-encoded in text columns.

**Row binding (AAD).**

| Sealed value | AAD |
|---|---|
| signing key | `"scrty/signingkey:private:" + kid` |
| MFA secret | `"scrty/mfa:secret:" + user_id` |
| session ID token | `"scrty/session:external-id-token:" + session identifier`, the prefix the existing `session.NewEncryptedStore` already binds with |

- **What it stops:** an attacker with `UPDATE` but no key who copies a known ciphertext into a victim's row. The per-table prefix also stops a value moving between tables.
- **One scheme:** the signing-key and MFA prefixes follow the `scrty/<package>:<field>:` form the `sessions` wrapper already stores, so the three read as one convention.
- **Stored format:** these strings are part of the stored format. Changing one makes every existing value unopenable, indistinguishable from tampering, so they are constants with a golden test.
- **Known limit, stated:** the AAD covers only the sealed column, not the whole row. For example, the public JWK beside a sealed key is not bound to it.

**Fail closed (absence versus failure).**
- **MFA:** an `Open` failure on an MFA secret is returned as an error with "enrolled" false. It is never a clean "not enrolled", which would skip the second factor.
- **Signing keys:** loading them fails as a whole when any key cannot be opened, rather than skipping it and letting a fresh key be minted, which would orphan every token the skipped key signed.
- **Sessions:** a session whose ID token cannot be opened returns an "unreadable" error distinct from not found, wrapping the cause. The `sessions` capability maps it.
- **Absence:** `''` or `NULL` is the only absence, and it never consults the cipher.

**Rotation.**
- **Default:** when `Open` reports a key id other than the active one, the signing-key and MFA stores re-seal the value, ignoring any failure.
- **Override:** `WithResealOnRead(false)`.
- **Sessions are never re-sealed on read.** The `sessions` capability forbids a load from rewriting the record, and a load is the hottest path in the library. Sessions re-seal naturally on their next write and expire absolutely.
- **Consequence, stated:** a retired key is provably unused only once every row sealed under it has been read or rewritten. Removing it earlier makes those rows fail closed with `ErrUnknownKeyID`.

### 10. Departures from the default design, and why

| scrty does | Justification |
|---|---|
| uuid primary keys, `text` user references, no identity foreign keys, a separate security-state migration set with its own version table | (a) settled product decisions |
| An own `WithTx` plus a resolver option on each adapter | (a) settled decision |
| Adapters that hold sealed columns take the `Cipher` as a required constructor argument, and no unsealed constructor for those stores is exported | (a) constructors are the primary API and wiring mistakes must fail at construction, so a check that runs only inside DI wiring would never run for most consumers. (b) A design that seals through wrappers composed at wiring time must still export the unsealed store constructors. Any caller who uses those constructors directly stores plaintext, with nothing to stop or warn them |
| The goose helper is not in the core module | (a) module-layout: `github.com/pressly/goose/v3` v3.28.0's `go.mod` requires `github.com/jackc/pgx/v5`, `github.com/go-sql-driver/mysql`, ClickHouse, MSSQL, Vertica, YDB and SQLite drivers. A core requirement on goose would put pgx in every core-only consumer's module graph, which the module-layout spec forbids |
| Re-seal on read is a conditional write (`UPDATE … SET col = $new WHERE id = $1 AND col = $old`), not a re-run of the store's upsert | (b) A re-seal that re-runs the store's write loses concurrent changes: on MFA enrolments, a new pending enrolment committed between the read and the re-seal is overwritten with the old secret, and the error is discarded, so nothing reports it |
| Re-seal on read is skipped when the read runs inside a caller's transaction | (b) The re-seal discards its write failure, and a failed statement aborts a PostgreSQL transaction (the caller's next statement fails with 25P02, and `COMMIT` becomes a rollback, which is the reason multi-statement operations use savepoints in decision 5). A best-effort write could therefore silently discard the caller's unrelated work |
| Re-seal on read can be switched off (`WithResealOnRead`) | (a) library-design: every default is replaceable |
| The race and ambient-transaction suites are shared suites, run for every durable store, with a harness that declares its pool width | (a) this change's settled scope for store-conformance. A portable race case built on a bare store factory cannot size the connection pool, so it passes even against a read-then-write implementation. Declaring the pool width in the harness, and refusing a narrower pool, removes that gap |
| Sessions are keyed by a SHA-256 digest of the session identifier (`id_digest`), behind a generated uuid primary key, and the identifier itself is never stored | (b) The session identifier is a live bearer credential (32 random bytes). Stored as the key, as it is by default, a database dump or read access to the table replays every live session, which defeats this change's goal that a dump is not usable. API keys, one-time tokens and handoff secrets are already stored only as digests. A plain SHA-256 suffices because the identifier carries 256 bits of entropy. The ID token's AAD still uses the plaintext identifier, which the wrapper holds in memory. Chosen by the user over the raw key |
| Links can be deleted by user reference, and the number of links removed is returned | Addition required by the `identity-linking` capability (unlinking every external identity of a user) |
| MFA enrolments record confirmation (`confirmed_at`) and the last accepted TOTP step (`last_step`). Both are set by conditional updates, and the step race has its own conformance suite | Addition required by the `multi-factor-auth` capability (unconfirmed enrolments must not act as a second factor, and a TOTP code must not be accepted twice) |

### 11. The `test` module

`github.com/kartaladev/scrty/test`, Go 1.27, created by `identity-and-tokens` and extended here.
- **No other scrty module imports it**, test files included (module-layout).
- **Tests that live here:** the integration tests for the core `database/sql` adapters, the conformance runs against core's in-memory defaults, and the `pgx` and `gorm` adapter runs.
- **Goose recipe:** a compiled `ExampleApplySecurityStateMigrations` shows the goose recipe, so CI keeps it compiling.

**`test.RunTestPostgres(t *testing.T, opts ...TestOption) PostgresConn`**, in `test/testutils.go` as the `use-testcontainers` skill requires, returning `PostgresConn{DB *sql.DB; DSN string}` in the shape of the existing `SMTPConn` and `KeycloakConn`, so pgx and gorm tests open their own handle from `DSN`:
- **Container:** one container per call, on a pinned PostgreSQL 18 alpine image (exact minor tag) by default. Override: `WithTestPostgresImage`.
- **CI versions:** the oldest and newest community-supported majors, currently 15 and 18. 19 is added and becomes the default when it is generally available; 15 is dropped after its end of life on 11 Nov 2027.
- **Migrations:** `WithTestPostgresMigrations(fsys, dir, versionTable)` applies a set with goose.
- **Cleanup:** it runs `DownTo(0)` and fails the test on error.
- **Finalizers:** `WithTestPostgresFinalizeScripts(sql...)` runs scripts after rollback, in declared order under one cleanup, within a 30-second teardown budget.

**`storetest` suites.**

```go
type Harness[S any] struct{ New func(t *testing.T) S }
type DurableHarness[S any] struct {
    Harness[S]
    Raw      *sql.DB                                                    // same database, out of band
    Begin    func(t *testing.T) (ctx context.Context, commit, rollback func() error)
    PoolSize int
}
```

- **Portable suites:** one per store contract. The in-memory defaults, all three adapters and consumers' own stores run them.
- **Where they live:** the OIDC suites already exist in `test/oidc` (`RunFlowStoreSuite`, `RunLinkStoreSuite`, `RunHandoffStoreSuite`) and stay there. This change adds `storetest` suites for the six contracts that have none yet (sessions, one-time tokens and their reaper, login attempts and their reaper, signing keys, MFA enrolments, API keys), each run against its in-memory default.
- **Durable suites** (`RunConsumeRace`, `RunLinkInsertRace`, `RunStepAcceptRace`, `RunAmbientTx`, `RunSealedColumns`): every nil field fails the suite immediately. There is no skip, because an obligation that can be skipped is green in CI.
- **Race suites:**
  - they start K records × N racers (defaults 50 × 8) off one barrier, because a single contended row serialises on PostgreSQL's row lock and hides a read-then-write almost every run;
  - they fail when `PoolSize < N`, because racers queueing for connections on the client side never reach the database together.
- **Sealed-column suites:**
  - they read the raw column and assert the plaintext is absent;
  - for base64url text columns they decode first and compare the decoded bytes, since base64 alone already defeats a substring check;
  - they copy a sealed MFA secret into another user's row and assert the open fails;
  - they reopen with a keyring lacking the key and assert an error, never absence;
  - they re-seal under a new active key and prove where the value landed by opening it with a keyring that holds only the new key.
- **Every suite has been seen to fail.** Each durable suite is run once against a deliberately broken variant kept in the adapter's tests:
  - a read-then-write consume;
  - an upsert link insert;
  - an identity cipher;
  - a missing AAD;
  - a store that bypasses the ambient transaction.

  The suite must go red.

### 12. Test-first throughout

- **Migrations first:** the migration tests are written first: tables exist, guard columns are nullable, the `login_attempts` indexes exist, full rollback leaves nothing, each `Down` runs on its own.
- **Store contracts, one at a time:**
  1. The suite is written or extended.
  2. The in-memory default's run is confirmed green.
  3. The suite is run red against the new adapter, then turned green.
  4. The broken variant is run to confirm the suite catches it.
- **`seal`:** it is table-tested for round trip, wrong AAD, wrong key, tampered byte, truncated envelope, missing magic, retired-key open, unknown key id and keyring validation.
- **Finishing:** each group ends with a `/simplify` pass and a re-run.

## Risks / Trade-offs

- [Unqualified table names in the consumer's `search_path` can collide with a consumer's own `sessions` or `api_keys` table] → The consumer can point the connection's `search_path` at a dedicated schema (Open Questions).
- [A single-statement write that fails unexpectedly inside a caller's transaction aborts it] → PostgreSQL semantics, stated on `WithTx`. Refusals never cause it, and multi-statement operations are contained.
- [A retired key cannot be proven unused, and there is no batch re-seal] → Re-seal on read shrinks the set. The godoc says to keep retired keys until every row has been touched.
- [A live session sealed under a removed key fails closed until its absolute expiry] → The session store reports it as unreadable, distinct from not found, so the `sessions` capability can make it a re-login rather than a server error.
- [Three adapters triple the maintenance of every contract] → Shared SQL text and shared suites keep the differences to scanning and handle types.
- [One container per call multiplies test time] → The suites run in parallel packages. Sharing a container is a later optimisation, and it would need suites that do not assume exclusive state.

## Migration Plan

Not applicable: this is a new library with no consumers and no tags. Once the first tag exists, the rules in decision 8 apply.

## Open Questions

- **Goose helper: resolved.** No helper ships in any module. The recipe is documented and compiled as an `Example` in the `test` module (decision 11).
- **Apply order: resolved, kept whole.** When this change was drafted, the MFA, API key and OIDC contracts did not exist yet, so splitting it was recommended. By the time it was applied, `auth-methods` and `oidc-brokering` had been archived with their contracts and in-memory stores final. The alternative the recommendation named, which applies this change whole after them, is therefore the one taken, and every adapter here is written against an existing contract.
- **Unqualified table names: resolved as a stated limit.** A consumer whose own tables collide points the connection's `search_path` at a dedicated schema. The migrations and stores stay unqualified, so the consumer can pick the schema at connection time.
