## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **What other changes provide:**
  - `identity-model` (identity-and-tokens) defines the four ports, user details, the opaque `identity.UserID` string, the sentinel errors (user-not-found, user-already-exists, privileges-not-found) and the provisioning options, with an accessor reporting which fields a caller named;
  - `security-state-stores` and `schema-migrations` (durable-persistence) define the `WithTx(ctx, tx)` context default, the transaction resolver option, the embedded-SQL migration runner and its version-table mechanics;
  - `id-generation` (project-foundation) provides `pkg/id`;
  - `password-encoding` (identity-and-tokens) provides the encoder whose matching the optional password history uses, and `http-security-chain` / `http-error-propagation` (http-security) provide the password-change resolve endpoint and the status table.
  This change uses all of these and restates none of them.
- **Product decisions already made:**
  - the store is optional and included by the default wiring;
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
- An administration API. The consumer's own user management writes organizations, groups, the role catalogue, privileges, `password_changed_at` and `mfa_required`.
- Password rules other than reuse: strength, length or breached-password checks stay in the consumer's own change function. Password history (Decision 12) is the only password rule this change adds, and it is off unless the consumer constructs it.
- An in-memory identity implementation. If one exists, `identity-model` owns it, and it may run the same suite.
- Deciding what the active flag, validity windows, super roles or the MFA-required flag mean. Authentication, authorization and security policy own that.
- Backends other than PostgreSQL, and configurable table names.

## Decisions

### 1. Package placement

- **Core module:**
  - `identitystore`: the `database/sql` store;
  - `identitystore/migrations`: the embedded SQL and the migration set;
  - `internal/identitysql`: the query text shared by `database/sql` and `pgx`, whose only difference is row scanning.
- **Nested modules:** `pgx/identitystore` and `gorm/identitystore`.
- **Test module:** `test/identityconformance` holds the suite, and `test/identitystore` holds the `database/sql` integration tests.

These names follow whatever durable-persistence settles for security-state stores.

- **Default:** one store value per adapter, implementing all four identity ports and the optional password-history port (Decision 12).
- **Override:** skip the store and implement the ports; or wire any subset of the store's ports alongside the consumer's own.

### 2. Schema

```
groups              (id uuid PK, name varchar NOT NULL, internal boolean NOT NULL DEFAULT false, created_at, updated_at)
organizations       (id uuid PK, name varchar NOT NULL, group_id uuid NULL, created_at, updated_at)
roles               (id uuid PK, name varchar NOT NULL UNIQUE, super_role boolean NOT NULL DEFAULT false, created_at, updated_at)
users               (id uuid PK, name varchar NOT NULL DEFAULT '', username varchar NOT NULL UNIQUE,
                     password bytea NOT NULL, active boolean NOT NULL DEFAULT true,
                     role varchar NOT NULL DEFAULT '', organization_id uuid NULL,
                     password_changed_at timestamptz NULL,
                     mfa_required boolean NOT NULL DEFAULT false, created_at, updated_at)
assigned_roles      (id uuid PK, user_id uuid NOT NULL, role_name varchar NOT NULL, position integer NOT NULL,
                     is_primary boolean NOT NULL DEFAULT false, super_role boolean NOT NULL DEFAULT false,
                     start_date timestamptz NULL, valid_until timestamptz NULL, created_at, updated_at)
                     INDEX (user_id)
resource_privileges (id uuid PK, role_name varchar NOT NULL, resource_group varchar NOT NULL,
                     resource varchar NOT NULL, privilege varchar NOT NULL,
                     granted boolean NOT NULL DEFAULT false, created_at, updated_at)
                     INDEX (role_name)
```

Choices a later tidy-up could undo, recorded so it does not:
- **`mfa_required` on `users`, `NOT NULL DEFAULT false`:**
  - losing an enrolment row must not clear the requirement;
  - a NULL would scan as "not required" and fail open;
  - the default lets the column be added to a populated table.
- **`password bytea NOT NULL` with no default:** a user without a credential stores an empty hash, never NULL.
- **`users.role`** holds the primary role name. It is written by provisioning and by a role rebuild, never independently of the grants.
- **No foreign keys anywhere:** an organization reference that resolves to nothing loads as no organization, and a missing group loads as an organization without one. Drop order in Down is still kept meaningful, so adding a key later cannot produce a Down that fails.
- **Role names are not constrained to `roles`:** just-in-time provisioning assigns claim-derived names that may not be in the catalogue.
- **No unique index on `(user_id, role_name)`:** provisioning permits duplicate grants, and update collapses them. A unique index would turn a rule into a constraint error.

- **Default:** fixed table names in the schema selected by the connection's `search_path`.
- **Override:** a different `search_path`; or, for a different layout, the consumer's own port implementations.

### 3. Provisioning: the insert is the check, and an update locks the parent row

- **Provision** inserts the user with `ON CONFLICT (username) DO NOTHING`:
  - zero rows affected is the collision, returned as user-already-exists;
  - there is no `SELECT` beforehand, because a check the write does not honour only makes the race look handled;
  - `DO NOTHING` never touches the existing row;
  - one grant is inserted per occurrence of a role name;
  - `password_changed_at` is written as NULL.
- **gorm:** reaches the same statement through its on-conflict clause and the affected-row count.
- **Update** selects the user row `FOR UPDATE`, then:
  - builds a partial `UPDATE users SET …` from the fields the caller named, using the identity model's field-was-set accessor, never field values;
  - rebuilds grants by deleting the user's grants and re-inserting the surviving ones with their original identifiers and attributes;
  - re-selects the complete record.
- **Why lock the parent row:** row locks on existing grants cannot serialise against another writer's inserts. Lock order is users then grants, matching provisioning, so no deadlock cycle appears.
- **Password writes:** `password_changed_at` is never in the update's column list.
- **Atomicity:** each verb runs in its own transaction, or in a savepoint inside an ambient transaction (Decision 6).
- **Default and override:** none. These are correctness properties of the port contract. A consumer wanting upsert semantics composes the two verbs and owns the account-takeover risk.

### 4. Loading

- **User load:** one query for the user row, one for grants (primary first, then stored order), one for the organization and one for its group, all through the same resolved handle. Any failure returns an error and no partial record.
- **Organization or group that resolves to nothing:** loads as absent, with no error.
- **Role privileges:** one query ordered by resource group and resource, grouped in Go. Denied entries are kept.
- **Grants and the active flag:** returned as stored. Validity windows are not filtered; authorization interprets them.

### 5. The password-changed-at time and the MFA-required flag are consumer-owned

No port call writes either column:
- **Why no port writes the password time:** a provider-mirrored password is written through update on every federated login, so stamping the time on a password write would keep it permanently fresh and exempt that user from password-age policy. The store cannot tell a local change from a mirrored one.
- **Why no port writes the MFA flag:** it is account policy for the consumer's own user management.
- **Consequence, stated in godoc:** a deployment populated only through the ports has a zero password time for every user. Password-age policy then treats the user as `security-policy` documents for a zero time, and the conformance suite has to seed the value through a hook.
- **Default:** never written by the store.
- **Override:** the consumer's tooling writes the columns, and the store returns what it finds.

### 6. Ambient transactions

Each adapter uses its module's `WithTx` and resolver option exactly as `security-state-stores` defines.
- **Loaders and the lookup** read through the resolved handle.
- **Provision and update** use a savepoint inside an ambient transaction:
  - PostgreSQL aborts the whole transaction on the first failed statement, so an unguarded failure would turn the caller's commit into a rollback of work the store never knew about;
  - `database/sql` issues `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` / `RELEASE` with names derived from an internal counter, never from input;
  - `pgx` nests through `Tx.Begin`;
  - `gorm` nests through its savepoint support.
- **Default:** the context's `WithTx` value, otherwise the pool.
- **Override:** the resolver option.

### 7. MFA requirement stays a separate lookup

The lookup reads `users.mfa_required` fresh on every call, and user details do not carry the flag.
- **Why:** details are populated when a credential is proved. A flag on details travels with the authentication event, so a path that authenticates from a session or token without reloading details would evaluate a stale copy. A separate lookup has one place to be wrong: its query.
- **Cost, accepted:** one primary-key read per evaluation, with no cache. A cache would be per replica and would delay a flag change by its TTL.
- **Default:** the store's lookup.
- **Override:** a consumer lookup, for example one backed by a directory.
- **Dependency:** identity-and-tokens is considering putting the flag on details. If it does, the store's loader returns the column as well, with no schema change. The lookup stays until that change removes the port.

### 8. Email is passed through, not stored

The provisioning options carry an email so a consumer's own provisioner can store it in their table. This store has no email column and discards it, and it is never a lookup key: matching external identities by email is an account-takeover vector.
- **Default:** discarded.
- **Override:** a consumer provisioner that stores it.

### 9. Migrations

- **Files:** plain SQL under `identitystore/migrations`, embedded with `embed.FS`, in the same goose-compatible format as the security-state set (`schema-migrations`), so goose or the consumer's own tool can run them.
- **Version table:** the default is `goose_identity`, named in the same pattern as the security-state set's `goose_security_state`, and replaceable by the consumer.
- **History:** one consolidated initial migration before any tag. After the first tag, changes are additive files.
- **Down:** drops the seven tables (the six identity tables and `password_history`, Decision 12) in reverse creation order with `IF EXISTS`, and never touches another set's tables.
- **Default:** nothing applies migrations automatically. Neither the stores nor the wiring (`di-wiring`) applies or checks them. The consumer applies the identity set, alongside the security-state set, before deploying a release that wires this store.
- **Override:** apply only the security-state set and bring your own identity ports, or run the embedded files with the consumer's own tool.

### 10. The conformance suite

`test/identityconformance` exports a harness of the four port implementations plus seeding hooks: user, password-changed-at, super role (first stored grant of the name), organization with group, privilege and MFA flag. It also has an ambient-transaction harness with `Begin` and a hook that makes a grant write fail.
- **Run:** `Run(t, h)` and `RunAmbientTx(t, h)`. Cases are named per rule and run sequentially, each with a unique username and role name.
- **Reading state back:** the provisioner cases read state through an update that names nothing, so they also check the complete-record obligation in every case.
- **Every hook is required,** and a missing one fails the run before any case.
  - `t.Skip` is green in CI, and the implementations most likely to get the password time wrong are the ones most likely to leave its hook out.
  - Writing the hook makes the implementer notice the column their update must not touch.
- **Out of scope:** context cancellation. The ports say nothing about it.
- **Concurrency:** the suite runs a concurrent double-submit case. Its passing form holds for every interleaving, so it never fails spuriously.
- **Adapter-only interleaving tests:** these force the interleaving, holding one transaction at a blocking statement confirmed through `pg_stat_activity`, and pin insert atomicity and update serialisation. They live with the adapters, because forcing an interleaving needs backend access the ports do not give.
- **Self-test:** the `test` module holds one defective in-memory implementation per defect in the spec's "known defects are caught" scenario, and asserts the suite fails against each.
- **Compatibility:** the harness is public API of the `test` module. Adding a required hook is a breaking change under the release policy.

### 11. Departures from the established design, and why

Each item below is the only place scrty differs from the established store design. The letters give the justification: (a) a settled product decision requires it, (b) a demonstrated defect, or a project rule where stated.

1. **Grant order is an explicit `position` column, not identifier order.** (a) The established design orders grants by identifier and relies on that order: the duplicate-collapse rule keeps the first stored grant, and its query comment calls the ordering load-bearing. Identifiers there came from one time-ordered source. scrty's identifier generator is replaceable by settled decision, and a consumer generator need not sort in creation order. Without a position column, a consumer's generator could decide which duplicate grant survives, promoting a later duplicate's super role. The "first stored duplicate under a consumer generator" scenario pins this.
2. **Error messages never contain the username.** (b) The established design's own record of its concurrency defect names the harm: the raw error embedded the username, which on the just-in-time path is the user's email address, and that error is handed to a logger. Its fix restored the sentinel but still formatted the username into the wrapped message, so the same text still reaches logs. scrty wraps sentinels without the username and strips driver detail text.
3. **A malformed user reference to the MFA lookup is user-not-found.** (a) The user reference is an opaque string by settled decision, while the established design took a typed integer identifier that could not be malformed. Parsing happens only inside this store, which minted the value.
4. **Identifiers are `uuid`, and user identifiers are exposed as canonical strings.** (a) `users.id` is a native `uuid` holding a UUIDv7 from `pkg/id`, and library-owned records use `pkg/id`. The other identity tables follow, so every identifier the store mints comes from one replaceable generator.
5. **Separate migration set and version table.** (a) Settled.
6. **Seeding hooks replace raw SQL seeding in the loader, role loader and lookup suites.** (a) The established loader suites seeded through SQL against their own table layout, which a consumer with different tables cannot run. The settled decision makes the suite usable against consumers' own implementations.
7. **Construction-time configuration errors.** Project rule (library-design rule 6). The established constructors accepted a nil handle, which failed at first use.

Password history (Decision 12) has no counterpart in the established design. It is an addition, not a departure, so nothing here overrides a prior behaviour.

Everything else follows the established design, including:
- no foreign keys, and dangling references loading as absent;
- the primary-role column;
- delete-and-reinsert grant rebuilds;
- unfiltered grants;
- no port writing the password time or MFA flag;
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

// Check refuses candidate with ErrPasswordReused when it matches current or one of
// the depth-1 most recent retired hashes.
func (g *ReuseGuard) Check(ctx context.Context, user identity.UserID, candidate string, current []byte) error

// Change checks, retires current, encodes candidate and calls write with the new
// hash, in that order, stopping at the first failure.
func (g *ReuseGuard) Change(ctx context.Context, user identity.UserID, candidate string,
    current []byte, write func(ctx context.Context, hash []byte) error) error
```

The port lives with the encoder because the check is password verification, and `password` gains only `identity` (context, errors, time) as a new import. The four identity ports are unchanged.

**What N counts: the current password is one of the N.** With depth N, the guard compares the candidate against the current hash the caller passes and the N−1 most recent retired hashes. So N = 1 refuses only "changing" to the same password, and N = 3 refuses the current and the two before it.
- **Why the current counts:** "the last N passwords" in common policy wording includes the one in use. A guard that let a user "change" to the same password would satisfy a password-age challenge without changing anything.
- **Why history holds retired hashes, not every hash set:** the current hash is already stored with the user. A user provisioned with a password, or one whose hash was last written by a mirror, has never been through the guard. Checking against the current hash the caller passes covers them, and history never needs seeding.
- **An absent current hash** (nil or empty, for a user with no local password yet) matches nothing. This is not an error.

**Comparison: verification, never re-hashing.** Each stored hash is checked with an encoder's `Match`, which reads the algorithm and parameters from the stored hash. Encoding the candidate again and comparing bytes would never match, because every hash carries a fresh salt. `Match` reports no match for another algorithm's hash, so the guard tries a set of matchers:
- **Default:** the guard's own encoder, plus the library's Argon2id, bcrypt and scrypt encoders at their defaults, used only to match. Each reads its parameters from the hash, so any hash a built-in encoder ever wrote matches, whatever its cost. A matcher given another algorithm's hash returns without deriving a key, so the cost stays at about one derivation per stored hash.
- **Override:** `WithReuseMatchers` replaces the extra matchers, for a consumer who stored hashes with their own encoder. The guard's own encoder is always included.
- **Why include retired algorithms by default:** more matchers can only refuse more reuse. A guard that silently stops seeing history after an algorithm migration fails open.

**Ordering, and failing closed.** `Change` runs these steps and stops at the first failure:
1. **Read history.** A read error refuses the change with `ErrHistoryUnavailable`, wrapping the port's error with fixed text, and writes nothing. It never falls back to "no history".
2. **Match.** A match refuses with `ErrPasswordReused`, and `write` is not called.
3. **Retire the current hash.** A record error refuses the change with `ErrHistoryUnavailable`, and the password is unchanged.
4. **Encode the candidate** with the guard's encoder. An encoder error, such as bcrypt's too-long input, is returned as is.
5. **Call `write`** with the new hash. Its error is returned unchanged. The retired entry from step 3 stays, and it holds the hash that is still current. Retiring the same bytes again adds nothing, so a retry does not double-count it and push an older entry out early.

- **Why retire before writing:** a record that fails after the password changed would leave a changed password with no history. Worse, the change function would fail, the gate would keep the marker, and the user's retry with the same new password would be refused as reused. Recording first means every failure before step 5 leaves the password untouched.
- **Atomicity:** with the default identity store backing both the user and the history, the consumer runs `Change`, with `write` calling the store's update, inside one transaction attached with `WithTx` (Decision 6). The history methods resolve the same handle, so the retire, the password write and the prune commit or roll back together. Without a transaction, the ordering above keeps every partial failure on the safe side.
- **Concurrency limit, stated:** the guard does not serialise two changes of one user. If a user submits two changes at the same instant, the last write wins, and the losing new password is never retired. Only that user can exploit this, and only to reuse a password they chose moments earlier.

**Storage in the default identity store.** One more table in the identity migration set:

```
password_history    (id uuid PK, user_id uuid NOT NULL, password bytea NOT NULL,
                     seq bigint GENERATED ALWAYS AS IDENTITY, retired_at timestamptz NOT NULL)
                     INDEX (user_id, seq DESC)
```

- **Order by `seq`, not by `id` or `retired_at`:** the identifier generator is replaceable (Decision 11.1), and two timestamps can tie. Pruning must know the newest entries exactly.
- **Pruning:** `RetirePassword` inserts the row, unless the user's newest row holds the same bytes, and then deletes every row of the user beyond the newest `keep`. It does both in one statement group, in a savepoint inside an ambient transaction, and atomically otherwise (Decision 6). A user therefore holds at most N−1 rows. Lowering N prunes at the user's next change. Raising N lets history grow back, and never restores pruned rows.
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
- **Construction errors (`ErrConfig`, naming the mistake):** a nil or typed-nil history port, a nil encoder, depth ≤ 0, and a nil matcher passed to `WithReuseMatchers`. None of these surfaces first at a change.
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

**Conformance.** `test/identityconformance` exports `RunPasswordHistory(t, h)` over any `password.History` implementation. It covers newest-first order, the `n` bound, pruning to `keep`, the same-bytes rule, `keep == 0`, `ForgetPasswords`, the per-user boundary, and the ambient-transaction rollback. The three adapters run it.

## Risks / Trade-offs

- [A consumer's migration tool records identity migrations in the security-state version table] → Distinct default names, a scenario applying each set alone, and README guidance showing both runner calls.
- [The flag lookup errors whenever the identity set is missing, and security policy then fails closed on every non-exempt login] → Intended direction. The godoc and migration guide say: apply the identity set before deploying a version wired to this store, and do not roll it back while that version runs.
- [A deployment populated only through the ports never has a password-changed-at time, so password-age policy never challenges] → Stated in godoc (Decision 5). Whether scrty should offer an explicit way to record a local rotation is an open question for the user.
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

- **Should the local change point write `password_changed_at`?** `ReuseGuard.Change` is the first seam that knows a password write is a local change rather than a mirror, which is exactly what Decision 5 says the store cannot know. The guard could take a hook, or the store could offer a local-change write that stamps the time, so that password-age policy works for deployments populated through the ports. This change leaves the column consumer-owned (Decision 5): the consumer's `write` callback may stamp it. Whether the library should do so is for the user to decide. It would also resolve the existing open question in Risks about recording a local rotation.
