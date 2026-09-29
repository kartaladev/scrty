## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **What other changes provide:**
  - `identity-model` (identity-and-tokens) defines the four ports, user details, the opaque `identity.UserID` string, the sentinel errors (user-not-found, user-already-exists, privileges-not-found) and the provisioning options, with an accessor reporting which fields a caller named;
  - `security-state-stores` and `schema-migrations` (durable-persistence) define the `WithTx(ctx, tx)` context default, the transaction resolver option, the embedded-SQL migration runner and its version-table mechanics;
  - `id-generation` (project-foundation) provides `pkg/id`;
  - `password-encoding` (identity-and-tokens) provides the encoder whose matching the optional password history uses, and `http-security-chain` / `http-error-propagation` (http-security) provide the password-change resolve endpoint and the status table.
  This change uses all of these and restates none of them.
- **Product decisions already made:**
  - the store is optional. Including it in the default wiring belongs to `di-wiring` (operations), which consumes this store; this change does not depend on it;
  - `users.id` is a native `uuid` holding a UUIDv7 from `pkg/id`, and the user reference is an opaque string;
  - there are no foreign keys to or from security-state tables;
  - the identity migration set is separate, with its own version table;
  - there are three adapters that pass one conformance suite, which lives in the `test` module and is usable by consumers.
- **Module-layout constraint:** the core `go.mod` may not require a PostgreSQL driver, even from a test file. The `database/sql` adapter's integration tests therefore run from the `test` module.
- **Project rules:**
  - every default must be documented and replaceable, and wiring mistakes fail at construction (library-design);
  - behaviour is driven by a test first seen to fail (golang-tdd);
  - PostgreSQL comes from the shared testcontainers helper (use-testcontainers).

## Goals / Non-Goals

**Goals:**
- A store a consumer can wire with a database handle and nothing else, and that keeps every provisioning rule under concurrency.
- One conformance suite that makes the port contract executable, for scrty's adapters and consumers' own implementations alike.
- A schema that can be removed or never applied without touching security state.

**Non-Goals:**
- An administration API. The consumer's own user management writes organizations, groups, the role catalogue, privileges and `mfa_required`. It records a local password change by naming the change time on update (Decision 5).
- Password rules other than reuse: strength, length or breached-password checks stay in the consumer's own change function. Password history (Decision 12) is the only password rule this change adds, and it is off unless the consumer constructs it.
- A new in-memory identity implementation. The existing one in the `test` module (`identitytest.InMemoryStore`) is updated only where this change's contract changes it: the named password-changed-at time, organizations by reference, and the unknown-user answer (Decisions 5, 7 and 10).
- Deciding what the active flag, validity windows, super roles or the MFA-required flag mean. Authentication, authorization and security policy own that.
- Backends other than PostgreSQL, and configurable table names.

## Decisions

### 1. Package placement

The layout follows what durable-persistence settled for the security-state stores:
- **Core module:**
  - `sqlstore.NewIdentityStore`: the `database/sql` store, beside the security-state stores, with the same `Option`, `ErrConfig` and transaction resolution;
  - `migrate.Identity()` and `migrate.IdentityVersionTable`: the embedded SQL under `migrate/identity`, exposed as a `migrate.Set` like `migrate.SecurityState()`;
  - `internal/pgschema`: the query text shared by `database/sql` and `pgx`, whose only difference is row scanning.
- **Nested modules:** `pgx.NewIdentityStore` and `gorm.NewIdentityStore`, in the existing adapter packages.
- **Test module:** the conformance suite extends `test/identity` (package `identitytest`), the identity ports' existing public suite (Decision 10). The PostgreSQL runs of it live beside the security-state runs in `test/sqlstore`, `test/pgxstore` and `test/gormstore`.

- **Default:** one store value per adapter, implementing all four identity ports and the optional password-history port (Decision 12).
- **Override:** skip the store and implement the ports; or wire any subset of the store's ports alongside the consumer's own.

### 2. Schema

```
groups              (id uuid PK, name text NOT NULL, internal boolean NOT NULL DEFAULT false, created_at, updated_at)
organizations       (id uuid PK, name text NOT NULL, group_id uuid NULL, created_at, updated_at)
roles               (id uuid PK, name text NOT NULL UNIQUE, super_role boolean NOT NULL DEFAULT false, created_at, updated_at)
users               (id uuid PK, name text NOT NULL DEFAULT '', username text NOT NULL UNIQUE,
                     password bytea NOT NULL, active boolean NOT NULL DEFAULT true,
                     role text NOT NULL DEFAULT '', organization_id uuid NULL,
                     password_changed_at timestamptz NULL,
                     mfa_required boolean NOT NULL DEFAULT false, created_at, updated_at)
assigned_roles      (id uuid PK, user_id uuid NOT NULL, role_name text NOT NULL, position integer NOT NULL,
                     is_primary boolean NOT NULL DEFAULT false, super_role boolean NOT NULL DEFAULT false,
                     start_date timestamptz NULL, valid_until timestamptz NULL, created_at, updated_at)
                     INDEX (user_id)
resource_privileges (id uuid PK, role_name text NOT NULL, resource_group text NOT NULL,
                     resource text NOT NULL, privilege text NOT NULL,
                     granted boolean NOT NULL DEFAULT false, created_at, updated_at)
                     INDEX (role_name)
```

Choices a later tidy-up could undo, recorded so it does not:
- **Types and timestamps follow the security-state set:** string columns are `text`. `created_at` and `updated_at` are `timestamptz NOT NULL` with no database default, as in every security-state table. The store binds them from its clock, so a consumer clock (`WithClock`) governs every time the store writes. Every identity store therefore honours `WithClock`, with the system clock as its default.
- **`mfa_required` on `users`, `NOT NULL DEFAULT false`:**
  - losing an enrolment row must not clear the requirement;
  - a NULL would scan as "not required" and fail open;
  - the default lets the column be added to a populated table.
- **`password bytea NOT NULL` with no default:** a user without a credential stores an empty hash, never NULL.
- **`users.role`** holds the primary role name. It is written by provisioning and by a role rebuild, never independently of the grants.
- **No foreign keys anywhere:** an organization reference that resolves to nothing loads as no organization, and a missing group loads as an organization without one. Drop order in Down is still kept meaningful, so adding a key later cannot produce a Down that fails.
- **Role names are not constrained to `roles`:** just-in-time provisioning assigns claim-derived names that may not be in the catalogue.
- **No unique index on `(user_id, role_name)`:** provisioning permits duplicate grants, and update collapses them. A unique index would turn a rule into a constraint error.
- **Empty role names:** provisioning stores one grant per occurrence, an empty name included, as the identity model states; so provisioning `("", "admin")` makes `""` the primary role. Update skips empty names, and a list of only empty names leaves the grants untouched. The asymmetry follows the two requirements as written.

- **Default:** fixed table names in the schema selected by the connection's `search_path`.
- **Override:** a different `search_path`; or, for a different layout, the consumer's own port implementations.

### 3. Provisioning: the insert is the check, and an update locks the parent row

- **Provision** inserts the user with `ON CONFLICT (username) DO NOTHING`:
  - zero rows affected is the collision, returned as user-already-exists;
  - there is no `SELECT` beforehand, because a check the write does not honour only makes the race look handled;
  - `DO NOTHING` never touches the existing row;
  - one grant is inserted per occurrence of a role name;
  - `password_changed_at` is written only when the caller names it, and is NULL otherwise.
- **gorm:** reaches the same statement through its on-conflict clause and the affected-row count.
- **Update** selects the user row `FOR UPDATE`, then:
  - builds a partial `UPDATE users SET …` from the fields the caller named, using the identity model's field-was-set accessor, never field values;
  - rebuilds grants by deleting the user's grants and re-inserting the surviving ones with their original identifiers and attributes;
  - re-selects the complete record.
- **Why lock the parent row:** row locks on existing grants cannot serialise against another writer's inserts. Lock order is users then grants, matching provisioning, so no deadlock cycle appears.
- **Password writes:** `password_changed_at` is in the update's column list only when the caller named it. Naming the password alone never puts it there.
- **Atomicity:** each verb runs in its own transaction, or in a savepoint inside an ambient transaction (Decision 6).
- **Default and override:** none. These are correctness properties of the port contract. A consumer wanting upsert semantics composes the two verbs and owns the account-takeover risk.

### 4. Loading

- **User load:** one query for the user row, one for grants (primary first, then stored order), one for the organization and one for its group, all through the same resolved handle. Any failure returns an error and no partial record.
- **Organization or group that resolves to nothing:** loads as absent, with no error.
- **Role privileges:** one query ordered by resource group and resource, grouped in Go. Denied entries are kept.
- **Grants and the active flag:** returned as stored. Validity windows are not filtered; authorization interprets them.

### 5. A local password change records its time by default; the store never stamps it

The password-changed-at time is an ordinary named field that the store writes only when the caller names it. The library's local-change path names it by default, so skipping it takes deliberate effort. This is the user's decision, taken during this change's planning: a per-call option alone left a consumer's change route one forgotten option away from a user that password-age policy never challenges. It is built in three layers:
1. **`identity.WithUserPasswordChange(hash, at)`** names the password and the time together, as one option for a local change. `WithUserPassword` alone remains the mirror's option, so the two paths are spelled differently. `WithUserPasswordChangedAt(at)` stays for backfilling or clearing the time on its own.
2. **`ReuseGuard.Change` hands the time to the consumer's write.** Its `WriteFunc` receives `changedAt`, read from the guard's clock (`WithReuseClock`, default `time.Now`).
3. **`password.ProvisionerWrite(p)`** builds a ready-made `WriteFunc` over any `identity.UserProvisioner`. It calls `Update(ctx, user.Username, WithUserPasswordChange(hash, changedAt))`, and joins an attached transaction because the store's update does. A consumer of the default store records the time with no extra code.

- **Why the store never stamps the time itself:** a provider-mirrored password is written through update on every federated login. Stamping the time on every password write would keep a mirrored password permanently fresh and exempt that user from password-age policy. The store cannot tell a local change from a mirrored one, but the caller can. The library's own mirror and just-in-time provisioning (`oidc`) build their options with `WithUserPassword` alone, and a test pins that neither names the time.
- **One record keys the change:** `Change` takes the user's loaded `*identity.Details`. Its `ID` keys history, its `Password` is the current hash, and `ProvisionerWrite` updates its `Username`. Passing a user reference and a username separately could check one user's history and write another user's password.
- **Naming a zero time** clears the stored value, like naming any empty value.
- **Why no port writes the MFA flag:** it is account policy for the consumer's own user management.
- **Limit, stated in godoc (library-design rule 4):** the time is recorded by default only on the guard's path with `ProvisionerWrite`, or wherever a caller uses `WithUserPasswordChange`. `WithUserPassword` alone, or a custom `WriteFunc` that ignores `changedAt`, leaves the time as stored. The godoc of each says that this gives up password-age policy for that user.
- **Default:** a change through `ReuseGuard.Change` with `ProvisionerWrite` records the time from the guard's clock. The store writes the time only when named, and never writes the MFA flag.
- **Override:** a consumer `WriteFunc` for their own storage, which receives `changedAt`; `WithReuseClock` for the clock; `WithUserPasswordChangedAt` to set or clear the time directly. The consumer's tooling writes the MFA flag, and the store returns what it finds.
- **Rejected:**
  - A hook on the reuse guard duplicates the guard's `write` callback, and it fails after the password is already written.
  - A store-only local-password writer is a second, unported write path, and the conformance suite could not check it.
  - Leaving the time outside the ports forces the consumer to write SQL against library-owned tables, and silently leaves password-age policy inert.
  - The named field alone, with no default path, was this change's first answer. The user tightened it to the three layers above.

### 6. Ambient transactions

Each adapter uses its module's `WithTx` and resolver option exactly as `security-state-stores` defines.
- **Loaders and the lookup** read through the resolved handle.
- **Provision and update** use a savepoint inside an ambient transaction:
  - PostgreSQL aborts the whole transaction on the first failed statement, so an unguarded failure would turn the caller's commit into a rollback of work the store never knew about;
  - every adapter issues `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` / `RELEASE SAVEPOINT` itself, with names derived from a store-owned counter, never from input, and releases the savepoint after rolling back to it as well as after success;
  - **why not the drivers' own nesting:** pgx's `Tx.Begin` and gorm's `SavePoint`/`RollbackTo` roll back to a savepoint without releasing it. Every failed call inside a caller's transaction, including a plain refusal such as user-already-exists, then leaves a savepoint open. Past 64 open subtransactions PostgreSQL overflows the backend's subtransaction cache, which slows snapshots for every session on the server. A bulk import that meets many refusals in one transaction reaches that. Reproduced for pgx during implementation (70 refused provisions left `pg_stat_get_backend_subxact` at 64, overflowed); a test in each adapter's suite pins that a refused call leaves no savepoint open. Issuing the statements directly also keeps them on the resolved handle, so a consumer's transaction wrapper sees every statement without having to wrap `Begin`.
- **Default:** the context's `WithTx` value, otherwise the pool.
- **Override:** the resolver option.

### 7. MFA requirement stays a separate lookup

The lookup reads `users.mfa_required` fresh on every call, and user details do not carry the flag.
- **Why:** details are populated when a credential is proved. A flag on details travels with the authentication event, so a path that authenticates from a session or token without reloading details would evaluate a stale copy. A separate lookup has one place to be wrong: its query.
- **Cost, accepted:** one primary-key read per evaluation, with no cache. A cache would be per replica and would delay a flag change by its TTL.
- **Default:** the store's lookup.
- **Override:** a consumer lookup, for example one backed by a directory.
- **An unknown user is user-not-found, never "not required".** This is the user's decision, taken during this change. A user reference with no stored user, or one that is not a valid UUID string, fails the lookup with the identity model's user-not-found error.
  - **Why:** the reference comes from an already-authenticated principal, so an unknown user means something changed after the login, such as a deletion, or a lookup and a loader that disagree. Answering "not required" would fail open. A user who was required to use MFA and is then deleted would have their outstanding bearer tokens refused before the deletion and let through after it (UNREPRODUCED: this follows from the policy and spec text, and the suite case below becomes its first failing test). The MFA requirement policy already denies on any lookup error, so it needs no change.
  - **Consistency:** the loaders already report an unknown user as user-not-found, and `identity-model` already requires a lookup failure to be an error, not "not required".
  - **Cost, accepted:** the identity ports' suite had a case asserting the opposite, "an unknown user is answered rather than refused". That case, the in-memory store, and any consumer lookup that answers `false` for an unknown user change before the first tag (`identity-model` delta).
  - **Sparse lookups:** a consumer lookup that stores flags only for users who need MFA must still tell "user exists, no flag" (`false`) from "no such user" (user-not-found), which can cost an existence check.
  - **Stated limit:** a denial caused this way is logged as a lookup failure, not as a deleted user.
- **Dependency:** identity-and-tokens is considering putting the flag on details. If it does, the store's loader returns the column as well, with no schema change. The lookup stays until that change removes the port.

### 8. Email is passed through, not stored

The provisioning options carry an email so a consumer's own provisioner can store it in their table. This store has no email column and discards it, and it is never a lookup key: matching external identities by email is an account-takeover vector.
- **Default:** discarded.
- **Override:** a consumer provisioner that stores it.

### 9. Migrations

- **Files:** plain SQL under `migrate/identity`, exposed as `migrate.Identity()`, embedded with `embed.FS`, in the same goose-compatible format as the security-state set (`schema-migrations`), so goose or the consumer's own tool can run them.
- **Version table:** the default is `goose_identity`, named in the same pattern as the security-state set's `goose_security_state`, and replaceable by the consumer.
- **History:** one consolidated initial migration before any tag. After the first tag, changes are additive files.
- **Down:** drops the seven tables (the six identity tables and `password_history`, Decision 12) in reverse creation order with `IF EXISTS`, and never touches another set's tables.
- **Default:** nothing applies migrations automatically. Neither the stores nor the wiring (`di-wiring`) applies or checks them. The consumer applies the identity set, alongside the security-state set, before deploying a release that wires this store.
- **Override:** apply only the security-state set and bring your own identity ports, or run the embedded files with the consumer's own tool.

### 10. The conformance suite

The identity ports already have one public conformance suite: `test/identity` (package `identitytest`), with a `Fixture` of the four ports plus seeding and fault hooks, an in-memory store, and self-tests that feed it deliberately broken stores. This change extends that suite rather than adding a second one, because two public suites for the same ports would drift.
- **Additions:**
  - cases for every rule in this capability that is observable through the ports and not yet covered, including the named password-changed-at time (Decision 5);
  - `RunAmbientTx(t, h)`, a separate ambient-transaction part whose harness adds four hooks: one that begins a caller-owned transaction, one that writes an unrelated row inside it, one that reports whether that row was stored, and one that makes a grant write fail;
  - `RunPasswordHistory(t, h)`, a separate password-history part (Decision 12);
  - a seeding hook for an organization with its group, which the ports cannot create when the store keeps organizations as references.
- **Removed:** `SeedPasswordChangedAt`. The suite sets the time through update by naming it, which also checks that a named time is written and an unnamed one is left alone. The fixture interface is public API of the `test` module, and the change is free before the first tag.
- **Every hook is required.** The existing "may skip" allowance on the fault hooks is removed, and a missing hook fails the run before any case.
  - `t.Skip` is green in CI, and the implementations most likely to get a rule wrong are the ones most likely to leave its hook out.
  - A fault hook needs no backend support: a fixture wraps its store and returns the error from the port call.
- **One database per run:** cases use names unique to the case, so a factory may hand every case a fixture over one shared database. They keep running in parallel.
- **Out of scope:** context cancellation. The ports say nothing about it.
- **Concurrency:** the suite runs a concurrent double-submit case. Its passing form holds for every interleaving, so it never fails spuriously.
- **Adapter-only interleaving tests:** these force the interleaving, holding one transaction at a blocking statement confirmed through `pg_stat_activity`, and pin insert atomicity and update serialisation. They live with the adapters, because forcing an interleaving needs backend access the ports do not give.
- **Self-test:** the existing broken-store self-test gains one deliberate defect per new entry in the spec's "known defects are caught" scenario, and asserts the suite fails against each.
- **Compatibility:** the fixture is public API of the `test` module. Adding a required hook is a breaking change under the release policy.

### 11. Departures from the established design, and why

Each item below is the only place scrty differs from the established store design. The letters give the justification: (a) a settled product decision requires it, (b) a demonstrated defect, or a project rule where stated.

1. **Grant order is an explicit `position` column, not identifier order.** (a) The established design orders grants by identifier and relies on that order: the duplicate-collapse rule keeps the first stored grant, and its query comment calls the ordering load-bearing. Identifiers there came from one time-ordered source. scrty's identifier generator is replaceable by settled decision, and a consumer generator need not sort in creation order. Without a position column, a consumer's generator could decide which duplicate grant survives, promoting a later duplicate's super role. The "first stored duplicate under a consumer generator" scenario pins this.
2. **Error messages never contain the username.** (b, UNREPRODUCED: the claim rests on the established design's own record of the defect, and no failing test in a disposable export has confirmed it; the scenario that becomes its first failing test is "Collision error text" in this change's spec) The established design's own record of its concurrency defect names the harm: the raw error embedded the username, which on the just-in-time path is the user's email address, and that error is handed to a logger. Its fix restored the sentinel but still formatted the username into the wrapped message, so the same text still reaches logs. scrty wraps sentinels without the username and strips driver text: the returned text is fixed library text naming the operation, plus the SQLSTATE read through the driver error's `SQLState()` method (both `pgconn.PgError` and `lib/pq`'s `Error` provide it), and the driver's error value is left out of the chain, because its detail fields (a unique key, or a failing row with its username and hash) stay reachable through `errors.As` otherwise. This differs from the security-state stores, which keep the driver error in the chain; their rows hold no username or password hash. A consumer who needs the SQLSTATE reads it from the text; the conditions they act on have sentinels. The driver's primary message is not kept, although the spec permits it: some PostgreSQL primary messages quote a value (`invalid input syntax for type …: "…"`), and the project's diagnostic-redaction rule (`internal/diag`) keeps a dependency's text out of every error the library returns. This was settled during implementation, when the lint gate flagged the text pass-through; the one exception is a `database/sql` scan failure, whose text is parsed in its fixed format for the column index and the library's own column name only.
3. **A malformed user reference to the MFA lookup is user-not-found.** (a) The user reference is an opaque string by settled decision, while the established design took a typed integer identifier that could not be malformed. Parsing happens only inside this store, which minted the value. A reference names a user only when it is the canonical lowercase text the store returned: an upper-case spelling of the same UUID is user-not-found, and a malformed reference to the password-history read is an error. The rule is byte-exact, so every adapter compares the same way. Organization references follow the same rule, because they are stored in a `uuid` column: a reference that is not canonical UUID text is refused before anything is written, with fixed text that does not echo it. The driver would otherwise report `invalid input syntax for type uuid` with the value. This is a stated limit (library-design rule 4): a consumer with non-UUID organization keys implements the ports over their own tables.
4. **Identifiers are `uuid`, and user identifiers are exposed as canonical strings.** (a) `users.id` is a native `uuid` holding a UUIDv7 from `pkg/id`, and library-owned records use `pkg/id`. The other identity tables follow, so every identifier the store mints comes from one replaceable generator.
5. **Separate migration set and version table.** (a) Settled.
6. **Seeding hooks replace raw SQL seeding in the loader, role loader and lookup suites.** (a) The established loader suites seeded through SQL against their own table layout, which a consumer with different tables cannot run. The settled decision makes the suite usable against consumers' own implementations.
7. **Construction-time configuration errors.** Project rule (library-design rule 6). The established constructors accepted a nil handle, which failed at first use.
8. **The password-changed-at time is a named field that a port call writes when the caller names it, and the library's local-change path names it by default.** (a) The user's decision, made in this change. The established design had no port write the time, which left a deployment populated through the ports with no way to record a local rotation short of writing to the store's tables, and password-age policy inert for its users. `WithUserPasswordChange`, the reuse guard's `changedAt` and `ProvisionerWrite` make recording the default for a local change. A password write alone still never moves the time, so the mirrored-password exemption the established design guarded against stays closed (Decision 5).

Password history (Decision 12) has no counterpart in the established design. It is an addition, not a departure, so nothing here overrides a prior behaviour.

Everything else follows the established design, including:
- no foreign keys, and dangling references loading as absent;
- the primary-role column;
- delete-and-reinsert grant rebuilds;
- unfiltered grants;
- no port writing the MFA flag, and no password write moving the password time on its own;
- a separate MFA lookup;
- email discarded;
- required hooks;
- no context-cancellation cases.

### 12. Optional password history, enforced at the local change point

A consumer can refuse a new password that matches one of the user's last N passwords. It is off by default: nothing checks or records history until the consumer constructs a reuse guard and calls it from their own change function.

**Enforcement point: a guard the consumer calls from their change function, not the store and not the resolve endpoint.**
- **Not the store's update.** Decision 5 already establishes that the store cannot tell a local change from a provider-mirrored password written on every federated login. Checking there could refuse a mirror, and a login would fail because the provider's password matched history. Recording there would add a row on every federated sign-in and push real history out.
- **Not the resolve endpoint itself.** The library never sees the new plaintext. `WithChangePasswordEndpoint` hands the whole exchange to the consumer's `ChangePasswordFunc`, which parses the request, owns the response, and returns an error that becomes the refusal unchanged. The library ships no rule about where a new password travels in a request. Parsing a body for it would add that rule, and it would cover only the gate's endpoint, not the change route a consumer runs outside the gate (a settings page, an admin reset).
- **Chosen:** a reuse guard in the core `password` package. The consumer calls it inside their `ChangePasswordFunc` or their own route, with the plaintext they already hold. It reaches the endpoint's refusal path unchanged: the guard's error is returned by the function, the gate refuses with it, and the pending password-change marker stays set, because the gate clears it only when the function succeeds (`http-security-chain`).

**Port and guard (sketch).**

```go
package password

// History keeps the hashes a user's password had before its current one.
type History interface {
    // RecentPasswords returns up to n of the user's retired hashes, newest first.
    // A user with none returns an empty slice and no error.
    RecentPasswords(ctx context.Context, user identity.UserID, n int) ([][]byte, error)
    // RetirePassword records hash as the user's newest retired hash, then keeps only
    // the newest keep entries. Recording the same bytes as the current newest entry
    // adds nothing. keep == 0 records nothing and removes every entry.
    RetirePassword(ctx context.Context, user identity.UserID, hash []byte, keep int) error
    // ForgetPasswords removes every retired hash of the user.
    ForgetPasswords(ctx context.Context, user identity.UserID) error
}

var (
    ErrPasswordReused      = errors.New("password: matches a recent password")
    ErrHistoryUnavailable  = errors.New("password: password history could not be read or written")
    ErrConfig              = errors.New("password: invalid configuration")
)

func NewReuseGuard(h History, enc Encoder, depth int, opts ...ReuseOption) (*ReuseGuard, error)
func WithReuseMatchers(encs ...Encoder) ReuseOption
func WithReuseClock(now func() time.Time) ReuseOption // default time.Now

// WriteFunc stores user's new password hash and the time it changed.
type WriteFunc func(ctx context.Context, user *identity.Details, hash []byte, changedAt time.Time) error

// ProvisionerWrite writes through p.Update, naming the hash and the time with
// identity.WithUserPasswordChange.
func ProvisionerWrite(p identity.UserProvisioner) (WriteFunc, error)

// Check refuses candidate with ErrPasswordReused when it matches user.Password or
// one of the depth-1 most recent retired hashes of user.ID.
func (g *ReuseGuard) Check(ctx context.Context, user *identity.Details, candidate string) error

// Change checks, retires user.Password, encodes candidate and calls write with the
// new hash and the guard clock's time, in that order, stopping at the first failure.
func (g *ReuseGuard) Change(ctx context.Context, user *identity.Details, candidate string, write WriteFunc) error
```

The port lives with the encoder because the check is password verification, and `password` gains only `identity` as a new import. `identity` imports no scrty package, so there is no cycle. `ProvisionerWrite` lives here too, for the same reason: `identity` cannot import `WriteFunc` without importing `password`. The four identity ports are unchanged.

**What N counts: the current password is one of the N.** With depth N, the guard compares the candidate against the current hash, `user.Password`, and the N−1 most recent retired hashes. So N = 1 refuses only "changing" to the same password, and N = 3 refuses the current and the two before it.
- **Why the current counts:** "the last N passwords" in common policy wording includes the one in use. A guard that let a user "change" to the same password would satisfy a password-age challenge without changing anything.
- **Why history holds retired hashes, not every hash set:** the current hash is already stored with the user. A user provisioned with a password, or one whose hash was last written by a mirror, has never been through the guard. Checking against `user.Password` covers them, and history never needs seeding.
- **An absent current hash** (nil or empty, for a user with no local password yet) matches nothing. This is not an error.

**Comparison: verification, never re-hashing.** Each stored hash is checked with an encoder's `Match`, which reads the algorithm and parameters from the stored hash. Encoding the candidate again and comparing bytes would never match, because every hash carries a fresh salt. `Match` reports no match for another algorithm's hash, so the guard tries a set of matchers:
- **Default:** the guard's own encoder, plus the library's Argon2id, bcrypt and scrypt encoders at their defaults, used only to match. A default built-in matcher of the same algorithm as the guard's own encoder is left out, because a built-in `Match` reads every parameter from the hash, so the two would answer alike and cost a second derivation. Each reads its parameters from the hash, so any hash a built-in encoder ever wrote matches, whatever its cost. A matcher given another algorithm's hash returns without deriving a key, so the cost stays at about one derivation per stored hash.
- **Override:** `WithReuseMatchers` replaces the extra matchers, for a consumer who stored hashes with their own encoder. The guard's own encoder is always included.
- **Why include retired algorithms by default:** more matchers can only refuse more reuse. A guard that silently stops seeing history after an algorithm migration fails open.

**Ordering, and failing closed.** `Change` runs these steps and stops at the first failure:
1. **Read history.** At depth 1 there is no retired hash to compare, so the read is skipped. Otherwise a read error refuses the change with `ErrHistoryUnavailable`, wrapping the port's error with fixed text, and writes nothing. It never falls back to "no history".
2. **Match.** A match refuses with `ErrPasswordReused`, and `write` is not called.
3. **Retire the current hash.** An absent current hash retires nothing. Otherwise a record error refuses the change with `ErrHistoryUnavailable`, and the password is unchanged.
4. **Encode the candidate** with the guard's encoder. An encoder error, such as bcrypt's too-long input, is returned as is.
5. **Call `write`** with the user, the new hash and the time from the guard's clock. Its error is returned unchanged. The retired entry from step 3 stays, and it holds the hash that is still current. Retiring the same bytes again adds nothing, so a retry does not double-count it and push an older entry out early.

- **Why retire before writing:** a record that fails after the password changed would leave a changed password with no history. Worse, the change function would fail, the gate would keep the marker, and the user's retry with the same new password would be refused as reused. Recording first means every failure before step 5 leaves the password untouched.
- **Atomicity:** with the default identity store backing both the user and the history, the consumer runs `Change` with `ProvisionerWrite(store)` (Decision 5) inside one transaction attached with `WithTx` (Decision 6). The history methods resolve the same handle, so the retire, the password write and the prune commit or roll back together. Without a transaction, the ordering above keeps every partial failure on the safe side.
- **Concurrency limit, stated:** the guard does not serialise two changes of one user. If a user submits two changes at the same instant, the last write wins, and the losing new password is never retired. Only that user can exploit this, and only to reuse a password they chose moments earlier.

**Storage in the default identity store.** One more table in the identity migration set:

```
password_history    (id uuid PK, user_id uuid NOT NULL, password bytea NOT NULL,
                     seq bigint GENERATED ALWAYS AS IDENTITY, retired_at timestamptz NOT NULL)
                     INDEX (user_id, seq DESC)
```

- **Order by `seq`, not by `id` or `retired_at`:** the identifier generator is replaceable (Decision 11.1), and two timestamps can tie. Pruning must know the newest entries exactly.
- **Pruning:** `RetirePassword` inserts the row, unless the user's newest row holds the same bytes, and then deletes every row of the user beyond the newest `keep`. It does both in one statement group, in a savepoint inside an ambient transaction, and atomically otherwise (Decision 6). A user therefore holds at most N−1 rows after any retire that did not overlap another retire of the same user. Two overlapping retires of one user can each miss the other's uncommitted row, and leave one row more until the user's next change prunes it. That is part of the concurrency limit stated under Ordering: the guard does not serialise two changes of one user. Lowering N prunes at the user's next change. Raising N lets history grow back, and never restores pruned rows.
- **Credential material:** `password bytea NOT NULL`, the same type and handling as `users.password`. It is never logged, never in error text, and never returned except through `RecentPasswords`. An old password is often a close variant of the current one, so it deserves the same care.
- **Deleted with the user:** there are no foreign keys, so nothing cascades. `ForgetPasswords` removes a user's rows, and the godoc tells the consumer's user deletion to call it in the same transaction that deletes the user and their grants. Rolling back the identity set drops the table.
- **User reference:** parsed as in Decision 7. A malformed reference fails `RecentPasswords` with an error, so the guard refuses. It is never read as "no history". A well-formed reference with no rows returns an empty slice.
- **The store's update still records nothing.** Decision 5 holds: a password written through the provisioner's update adds no history row, whatever its source.
- **Always created, used only when enabled:** the table is part of the single initial migration before any tag. An unused empty table costs nothing, and making it conditional would need a second migration set for one table.
- **Each adapter implements the port on its store value.** The `database/sql`, `pgx` and `gorm` stores each implement `password.History` alongside the four identity ports.

**Errors and logs.** `ErrPasswordReused` has fixed text and carries no hash, password or user reference. `ErrHistoryUnavailable` wraps the port's error with fixed text, as `diagnostic-redaction` requires, with the port's error reachable by `errors.Is`/`errors.As`. The guard writes no log record, and it never keeps the candidate after `Change` returns.

**Status.** `StatusForError` maps `ErrPasswordReused` to **422 Unprocessable Content**.
- **Not 400:** 400 means a malformed request in the mapping table (malformed login, invalid logout token). Here the request is well formed and the value is refused, so a client can show a field-level message.
- **Not 401 or 403:** 401 reads as an authentication failure and invites a re-login. 403 is the password-change challenge itself, so a client could not tell "you still owe a change" from "that password was used recently".
- **Today's behaviour:** the resolve endpoint returns whatever the consumer's function returns, and a consumer's own "weak password" error is unrecognised and maps to 500. 422 is the first library status for a refused new password. A consumer's error handler can still refine it.
- `ErrHistoryUnavailable` maps to 500, like any dependency failure.

**Default, override and construction errors.**
- **Default:** off. No guard, no check, no history rows. The table exists but stays empty.
- **Enabling:** `NewReuseGuard(history, encoder, depth)`. N is required, and there is no default depth. Published guidance ranges from none at all (current NIST guidance does not ask for history) to 4 or 24, and a library default would present one of them as the right answer.
- **Construction errors (`ErrConfig`, naming the mistake):** a nil or typed-nil history port, a nil encoder, depth ≤ 0, a nil matcher passed to `WithReuseMatchers`, and a nil clock passed to `WithReuseClock`. None of these surfaces first at a change. `ProvisionerWrite` refuses a nil or typed-nil provisioner with `ErrConfig` when it is built, at wiring time. A nil user passed to `Check` or `Change`, or a nil write passed to `Change`, is an error wrapping `ErrConfig`, and nothing is read or written. So is a nil user passed straight to the write `ProvisionerWrite` built.
- **Overrides:** the consumer's own `History` implementation over their own tables; extra matchers; or calling `Check` and composing their own ordering, which gives up the ordering guarantees above.
- **No upper bound on N:** a large N is a cost the consumer chooses, not a contradiction. See Risks.

**Alternatives rejected.**
- **Check and record in the store's update:** it cannot tell a mirror from a local change (Decision 5).
- **An option on `WithChangePasswordEndpoint` that reads the new password from the request:** the library would have to own the request format, and the check would not cover change routes outside the gate.
- **History stores every hash set, including the current one:** users who never went through the guard would need seeding, and every mirror write would have to be excluded again.
- **Write the new password, then record:** a record failure would leave a changed password with no history, and a stuck retry (see Ordering).
- **Compare by re-encoding:** never matches with salted hashes.
- **A default depth:** see above.
- **A conformance case in the identity suite:** history is not an identity port. It gets its own `RunPasswordHistory` entry with its own harness, so a consumer who does not enable history supplies no extra hooks.

**Conformance.** `test/identity` exports `RunPasswordHistory(t, h)` over any `password.History` implementation. It covers newest-first order, the `n` bound, pruning to `keep`, the same-bytes rule, `keep == 0`, `ForgetPasswords`, the per-user boundary, and the ambient-transaction rollback. The three adapters run it.

## Risks / Trade-offs

- [A consumer's migration tool records identity migrations in the security-state version table] → Distinct default names, a scenario applying each set alone, and README guidance showing both runner calls.
- [The flag lookup errors whenever the identity set is missing, and security policy then fails closed on every non-exempt login] → Intended direction. The godoc and migration guide say: apply the identity set before deploying a version wired to this store, and do not roll it back while that version runs.
- [A consumer's own change route, outside the guard, writes the password with `WithUserPassword` alone, so password-age policy never challenges that user] → The guard's path with `ProvisionerWrite` records the time by default, and `WithUserPasswordChange` is the one-option spelling elsewhere. The godoc on `WithUserPassword` and `WriteFunc` states what skipping the time gives up (Decision 5).
- [Without foreign keys, deleting an organization or user leaves dangling references and orphaned grants] → Dangling organizations load as absent. The consumer's user management deletes a user's grants with the user, and the godoc says so.
- [Required hooks make the suite unusable for an implementation that cannot write those fields out of band] → Stated limit. If such an implementation appears, revisit this rather than making hooks optional.
- [The row lock serialises concurrent updates of one user] → Short, rare, and different users are unaffected.
- [Password history multiplies the cost of a change by up to N key derivations; with Argon2id at 64 MiB and N = 24 a change can take over a second] → Derivations run one after another, so peak memory stays at one derivation. The cost falls on a rare, authenticated action, not on login. The godoc states the cost per unit of N, and there is no cap (Decision 12).
- [A bcrypt matcher refuses input over 72 bytes, so a long candidate never matches a bcrypt history entry] → Such a candidate could never have produced that bcrypt hash, so nothing is missed. The bcrypt encoder refused it when it was set.
- [A consumer who calls `Change` without a transaction and whose write fails leaves the still-current hash as a retired entry] → Harmless: that hash is refused as the current one anyway, and retiring the same bytes again adds nothing.
- [Two simultaneous changes by one user can leave one new password out of history] → Stated limit (Decision 12). Only the user can cause it, and only to reuse their own recent choice.
- [A consumer deletes a user and forgets `ForgetPasswords`, leaving hashes behind] → No foreign keys means no cascade, as with grants. The godoc on user deletion names both, and the risk is the same as orphaned grants.

## Migration Plan

Not applicable: a new library with no consumers and no tags. For deployers, apply the identity migration set before, or together with, the first release that wires this store.

## Open Questions

None open. Two questions were decided by the user during this change:
- Whether the local change point records the password-changed-at time: it records it by default, in three layers, and the store never stamps it (Decision 5).
- What the MFA requirement lookup answers for an unknown user: user-not-found, never "not required" (Decision 7).

## References

Two kinds of source are listed. Those under **Researched** were consulted on 2026-09-28 while settling this change's decisions. Those under **Primary documentation** are the standard references for mechanisms the design relies on. They are cited as such, and were not re-checked link by link on that date.

Decisions 5 (the password-changed-at time) and 7 (an unknown user is user-not-found) were reasoned from scrty's own settled specs (`identity-model`, `security-policy`) and project rule (`library-design`). They cite no external source beyond those below.

### Researched

**Password history (Decision 12): what "the last N passwords" means in published guidance, and why there is no default depth**
- [NIST SP 800-63B-4: Authenticators, section 3.1.1.2 (password verifiers)](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/): verifiers "SHALL NOT require subscribers to change passwords periodically", and must check a new password against a blocklist of commonly used or compromised passwords. There is no requirement to keep or check a user's previous passwords, which is the "none at all" end of the range.
- PCI DSS v4.0 requirement 8.3.7: a new password must not match any of the last four. The primary standard is in the [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/), which needs registration. The requirement is summarised in [Compass IT Compliance](https://www.compassitc.com/blog/pci-dss-4.0-password-requirements-a-guide-to-compliance), which states the last-four rule. Two other summaries found in the search do not state it, and are not cited. This is the "4" in the design.
- [Enforce password history, Windows security policy setting (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/enforce-password-history): 24, the maximum, is recommended. The same page warns that forced unique changes push users towards incremental passwords. This is the "24" in the design.
- [CIS benchmark item "Ensure 'Enforce password history' is set to '24 or more'" (Tenable audit)](https://www.tenable.com/audits/items/CIS_Microsoft_Windows_Server_2019_STIG_v1.0.1_L1_MS.audit:a01ae92c73f8d7795108312916cbc4ec)

### Primary documentation

**Provisioning and update (Decision 3), and concurrent retires (Decision 12, Risks)**
- [PostgreSQL: INSERT … ON CONFLICT](https://www.postgresql.org/docs/current/sql-insert.html#SQL-ON-CONFLICT): the insert decides a username collision, and `DO NOTHING` leaves the existing row untouched
- [PostgreSQL: SELECT … FOR UPDATE](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE) and [explicit locking](https://www.postgresql.org/docs/current/explicit-locking.html): the parent-row lock that serialises updates of one user
- [PostgreSQL: transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html): under READ COMMITTED, two overlapping retires of one user can each miss the other's uncommitted row, which is the stated limit on the history bound

**Ambient transactions (Decision 6)**
- [PostgreSQL: transactions tutorial](https://www.postgresql.org/docs/current/tutorial-transactions.html): a failed statement aborts the whole transaction, so the store guards its own writes with savepoints
- [PostgreSQL: SAVEPOINT](https://www.postgresql.org/docs/current/sql-savepoint.html), [ROLLBACK TO SAVEPOINT](https://www.postgresql.org/docs/current/sql-rollback-to.html) and [RELEASE SAVEPOINT](https://www.postgresql.org/docs/current/sql-release-savepoint.html)

**Schema and identifiers (Decisions 2, 11 and 12)**
- [RFC 9562: Universally Unique IDentifiers (UUIDs)](https://www.rfc-editor.org/rfc/rfc9562): UUIDv7, the default generator for `users.id`
- [PostgreSQL: UUID type](https://www.postgresql.org/docs/current/datatype-uuid.html)
- [PostgreSQL: CREATE TABLE, identity columns](https://www.postgresql.org/docs/current/sql-createtable.html): `password_history.seq GENERATED ALWAYS AS IDENTITY` orders history independently of the ID generator and of clock ties

**Migrations (Decision 9)**
- [pressly/goose](https://github.com/pressly/goose): the annotated SQL migration format the identity set uses, and its version table

**The conformance suite's forced interleavings (Decision 10)**
- [PostgreSQL: the pg_stat_activity view](https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-ACTIVITY-VIEW): confirming that a transaction is waiting on a lock before the test releases the other one

**The reuse guard's matching and cost (Decision 12)**
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106) and the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): the Argon2id parameters behind the cost of each derivation
- [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt): the 72-byte input limit, and why a longer candidate can never match a bcrypt history entry

**The reuse refusal's status (Decision 12, Status)**
- [RFC 9110: HTTP Semantics, section 15.5.21 (422 Unprocessable Content)](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.21): a well-formed request whose content is refused
