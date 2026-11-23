# Design

## Context

See `proposal.md` for why. The current state that shapes the approach:

- **Privilege checks load on every call.** `PrivilegeAuthorizer.Authorize` calls
  `RoleLoader.LoadPrivileges` each time. A request that checks a route and nine actions makes ten
  identical loads.
- **Requirements compose only one way.** `authorize.AnyOf` exists; there is no all-of. The adapter
  guards (`httpsec`, `ginsec`, `fibersec`) take one group and resource through `ResourcePrivileges`,
  never an arbitrary `Requirement`.
- **Grants are keyed by role name.** `scrty_resource_privileges.role_name` and
  `scrty_assigned_roles.role_name` are text, and `scrty_users.role` holds the primary role's name.
  The just-in-time provisioner assigns role names that need not exist in `scrty_roles`.
- **Assignment dates are carried, never enforced.** `identity.AssignedRole` has `StartDate` and
  `ValidUntil`. The store does not filter by them, by spec, and nothing else reads them:
  `identity.PrincipalFromDetails` makes the first primary grant active whatever its dates. This is a gap in
  behaviour, not a reproduced defect; task 6.1 is its first failing test.
- **The principal is rebuilt on every request.** The chain reloads the session's user by reference
  and refuses a user who is gone or inactive (`httpsec/resolve.go`). A change to a user, role or grant
  therefore applies on the next request without any cache to invalidate.
- **Email is discarded.** `identity.WithUserEmail` exists, the OIDC broker passes the provider's email
  through it, and the default store drops it. `scrty_users` has no email column.
- **Lockout runs before the password check, on the submitted identifier.** The chain's login and
  basic endpoints evaluate `policy.PreAuthentication` with the identifier as typed, then call the
  provider, which loads by username.
- **Events carry no actor and no target.** `event.Event` names the user an outcome concerns, and its
  sink is synchronous and must never receive a secret.
- **Three store implementations.** `sqlstore`, `pgxstore` and `gormstore` each implement every
  identity port, and the `test` module's conformance suites prove them.
- **The established design has none of this.** It has no administration services, no grant scopes,
  no per-request memo and no login by email. Every decision below is new rather than a departure,
  except where D4 and D12 say otherwise.

## Goals / Non-Goals

**Goals:**
- Every feature works with no configuration beyond the store, and every default can be replaced
  through an option or a port (`library-design.md`).
- No new dependency. No change to an existing exported signature: everything is added beside what
  exists. **Two exceptions, found by the API report during implementation (decided 2026-11-23,
  during implementation; a compatibility decision under the project's pre-1.0 policy, recorded in
  the CHANGELOG as breaking):** `event.Event` is no longer comparable, because D19's `Changed` field
  is a slice, and a slice is the natural shape for a list of field names; and `test/identity.Fixture`
  gains `SeedEmail` and `SoftDelete`, which the email-loader and soft-deletion conformance cases need.
  **Alternative:** a comparable `Changed` (a joined string, or a fixed array). Rejected: it would
  push parsing onto every sink to keep a property no scrty code relies on.
- One identity migration and one security-state migration, each with a Down section.

**Non-Goals:**
- Authorization inside the administration services. The application guards its own routes; the
  services trust the caller (D3).
- Scopes other than `all` and `own`, and consumer-defined scopes (D4).
- Email delivery, email verification flows, and login by email for magic link and recovery.
- Caching privileges across requests. The memo lives and dies with one request (D5).
- Restoring a soft-deleted user.

## Decisions

### D1. One release, one pull request (decided by the user 2026-11-23)

Everything ships in v0.3.0, with the table prefix and the device grant already on `main`. The whole
change lands in a single pull request, opened after the final gate, which leaves `main` green. Commits
inside it follow the task groups. No tag is made until it has merged.

**Alternative:** separate releases after each part, as the brief asked. Rejected by the user: one
upgrade for consumers, together with the rename. **Alternative:** one pull request per task group,
the first plan. Rejected by the user on 2026-11-23 in favour of one pull request for the change.

**The release preparation is part of this change (decided by the user 2026-11-23, during
implementation).** RELEASING.md steps 1 and 2 for v0.3.0 (the dated changelog entry, the supported
versions in SECURITY.md and README, the `go get` lines, and every nested module requiring v0.3.0) land
in this pull request as task 13.3, before the final gate, so merging it merges the release
preparation. Steps 3 to 9 (the release gate on the merged commit, the tags, the published release)
stay the maintainer's, as RELEASING.md requires. **Alternative:** a separate release pull request
after the merge, as for v0.2.1. Not chosen: one pull request carries the whole release.

### D2. A new `admin` package of services over ports; scrty's identity stores are the default

Package `github.com/kartaladev/scrty/admin` holds the services `Users`, `Importer`, `Roles`,
`Grants` and `Assignments`, the ports `UserStore`, `ImportStore`, `RoleStore`, `GrantStore` and
`AssignmentStore`, and the administration errors. The `IdentityStore` of each of `sqlstore`,
`pgxstore` and `gormstore` implements every port. A service built with only a store works; nothing
else is required except the catalogue for `Grants` (D9).

- **Default:** the services over the identity store the consumer already builds.
- **Override:** any implementation of the ports. The rules a service enforces before reaching the
  store (input bounds, catalogue, actor, events, audit) stay with the service, so a consumer store
  inherits them. The rules only a store can enforce (versions, serialisation, uniqueness) are pinned
  by the administration conformance suite (task group 9).
- **Alternative:** methods on the identity stores only, no services. Rejected: every consumer would
  re-implement the actor, catalogue, event and audit rules, which is the duplication this change
  removes.
- **Alternative:** `identity/admin`. Rejected: core packages group by concept, `identity` ships no
  implementation by spec, and the services are an implementation.

### D3. The actor comes from the context; the services do not authorize

Each write reads the principal from the context. A caller with no principal, such as a sync job,
attaches a named system actor with `admin.WithSystemActor(ctx, name)`. With neither, the call fails
with `admin.ErrNoActor` before any write.

- **Why refuse:** every change emits an event naming its actor. A write with no actor would produce
  an audit record nobody can attribute, and the safe outcome is to refuse.
- **Why no authorization:** the application already guards its routes with scrty's requirements, and
  the rules for who may administer whom (an administrator of one partner managing only its users)
  are the application's. A service that also checked would check something the application did not
  ask for. The godoc says so on every service.
- **Override:** none needed. The system actor is the escape hatch for jobs.

### D4. A grant carries a scope; an own-only grant fails a plain check (decided by the user 2026-11-23)

`identity.Privilege` gains `Scope identity.Scope`, a string type. `identity.ScopeAll` is `"all"`,
`identity.ScopeOwn` is `"own"`. The empty scope reads as `all`, so every existing grant, and every
consumer loader that knows nothing of scopes, keeps its meaning.

Three checks read the scope:

| Check | Allows when | Use |
|---|---|---|
| `HasPrivilege` (unchanged signature) | granted with `all` | route guards, as today |
| `HasPrivilegeAnyScope` | granted with a defined scope; reports the strongest held | list endpoints that filter to own records |
| `HasPrivilegeFor(..., OwnershipAttributes)` | `all`, or `own` and the ownership check passes | one record |

`PrivilegeAttributes` gains an `Accept` field listing the scopes a check accepts; empty means
`all` only. A scope the authorizer does not define covers nothing.

- **Why own-only fails the plain check:** an application that guards a route with `HasPrivilege`
  and forgets the ownership check in its handler would otherwise let a caller with an own-only grant
  read every partner's records. Failing closed makes the safe reading the default.
- **Why the strongest scope is reported:** a list endpoint filters to own records only when the
  caller holds no `all` grant. Reporting `own` to a caller who also holds `all` would hide records
  they may see, which is safe but wrong.
- **Override:** none for the meaning of `all` and `own`. Adding a scope means giving scrty a record
  check it runs for that scope, a contract this change does not define. The type and the column are
  open text, so a later change can add scopes, such as `organization`, without a migration.
- **Alternative:** a boolean `OwnOnly`. Rejected: the brief asks for room for more scopes, and a
  boolean would need a migration to grow.

### D5. A per-request privilege memo in the context, installed by the chain

`authorize.WithRequestMemo(ctx) context.Context` attaches a memo. The privilege authorizer and the
bulk check use it whenever the context carries one, and load directly otherwise. The memo maps a role
name to its loaded privileges, guarded by a mutex with one in-flight load per role, so concurrent
checks of one role wait for one load. A successful load and `ErrPrivilegesNotFound` are remembered.
Any other error is not, so a later check in the same request tries again. The memo holds at most 32
roles; past that it loads without remembering, which bounds memory against a request that checks
many role names.

The chain attaches a fresh memo to every request it runs, at chain entry, before any interceptor, so
every authentication path is covered; an anonymous request pays one small allocation. A context
detached from the request with `context.WithoutCancel` keeps the memo; work that outlives the request
must not make privilege checks on it, or must attach a memo of its own. `httpsec.WithoutPrivilegeMemo()`
turns that off. A consumer outside the chain calls `authorize.WithRequestMemo` itself.

- **Why the context and not the authorizer:** the authorizer is shared by every request. A memo on
  it would need eviction and would let a privilege change outlive the request that saw it.
- **Why on by default:** it changes no outcome, only the number of loads, and a memo created per
  request cannot serve stale data to a later request.
- **Alternative:** a TTL cache in the authorizer. Rejected: it delays revocation by the TTL, which
  the brief rules out.

The memo assumes a role's privileges depend only on the role name: a consumer loader that also reads
the context, such as a tenant, must not share one memo across contexts that differ in it (F46).
Nothing a check returns after its own context ended is remembered, not even a success or a
not-found, since a loader interrupted mid-way may return partial data; live checks waiting on it
load again; after eight such rounds a check loads for itself, without the memo.
The memo is keyed by the authorizer and the exact role name, so two authorizers sharing one memo,
such as two members of a `FirstOf` over different loaders, never see each other's results. In-flight
loads count toward the bound.

### D6. `AllOf` and a guard for any requirement

`authorize.AllOf(requirements...)` evaluates in order and returns the first failure unchanged,
denying when empty or when a member is absent. Each adapter's `Guards` gains `Require(authorize.Requirement)`.
It refuses an absent requirement when the guard is built and maps outcomes as the existing guards do.
`AllOf` returns the first failure unchanged, unlike `AnyOf`, which chooses between refusals. The
first failing member is the reason the request cannot proceed, and an outage stays an outage.

### D7. The bulk check

`authorize.HeldPrivileges(ctx, group, resource string, names ...string) (Holdings, error)` uses the
authorizer in the context. When that authorizer, or a member of a `FirstOf`, implements
`authorize.PrivilegeInspector`, it loads the active role's privileges once, through the memo, and
reports each name as held or not, with the strongest scope. `PrivilegeAuthorizer` implements the
inspector.

- With no subject or no active role, it reports nothing held and no error. "Allowed actions" for a
  caller with no role is an empty list, not a failure of the response.
- An authorizer that does not implement the inspector gives `authorize.ErrInspectionUnsupported`.
  Guessing by calling `Authorize` N times would hide the memo and the scope.
- Through `FirstOf`, members are asked in order: an inspector answers; one that answers
  `ErrUnsupportedAttributes` declines and the next is asked; the ownership authorizer is passed over;
  any other member that is not an inspector stops the walk with `ErrInspectionUnsupported`, because it
  might judge privileges itself and the bulk answer would then disagree with `Authorize`. A consumer
  authorizer joins by implementing the inspector, even only to decline.
- An inspector's answer has one holding per name asked, the names exactly as asked and in order,
  held only with `all` or `own`, and no scope when not held. `HeldPrivileges` refuses any other
  answer with `ErrConfig` and returns the caller its own copy (F47).

### D8. One sentinel per denial reason, each still matching `ErrAccessDenied`

`authorize.ErrNoSubject`, `ErrNoActiveRole`, `ErrNotGranted`, `ErrWrongScope` and `ErrNotOwner`. Every
denial wraps both `ErrAccessDenied` and exactly one reason, so existing `errors.Is(err,
ErrAccessDenied)` callers are unaffected and an application can render a problem type per reason.

- `ErrNotGranted` is the general reason: a role or privilege not held, an empty or absent `AllOf`
  member, `DenyAll`, a `FirstOf` whose members all decline, and a rule set with no match.
- `ErrWrongScope` covers a grant held only with a scope the check does not accept, including a scope
  the authorizer does not define.
- `ErrNoActiveRole` also covers an active role with a blank name.
- The reasons are bare sentinels and leave `authorize` only wrapped with `ErrAccessDenied`, so the
  chain's status mapping answers them 403 through it and does not map them itself.

**The scope a check allowed travels with its attributes (decided 2026-11-23, during
implementation).** `CheckAnyScope` and `HasPrivilegeFor` need the scope the authorizer allowed. The
privilege authorizer writes it into an unexported field of the `PrivilegeAttributes` value it was
given, not into the context, so a nested check sharing the context cannot overwrite it. An
authorizer that allows without reporting a scope, such as a consumer's own, makes those two calls
fail with an error matching `ErrConfig` rather than guess a scope; `HasPrivilegeAnyScope`, which needs
only a yes or no, accepts its allow. With several privileges in one check, all-of reports the weakest
scope among them and any-of the strongest held.

### D9. A resource catalogue declared in code; `Grants` requires it

`authorize.NewCatalogue(resources ...CatalogueResource) (*Catalogue, error)` copies its input and
refuses blank names, duplicates under the default name comparison, and privileges with an undefined
scope. A privilege declared without scopes allows `all` and `own`. The catalogue answers
`Allows(group, resource, privilege, scope)` and lists its resources for a grant matrix.

`admin.NewGrants` requires a catalogue and checks every grant against it before writing.

- **Why required:** without a catalogue, grant administration would store any typo as a privilege
  nobody checks, a silent failure. Failing at construction is the safe default (`library-design.md`
  rule 6).
- **Why the store does not hold it:** the catalogue is code, versioned with the application, and the
  runtime authorizer does not need it. A privilege the catalogue no longer lists still loads, and the
  next grant edit for its resource removes it.
- An empty replacement for a resource the catalogue no longer lists is allowed, so its stored
  grants can be cleared.
- **Override:** the consumer's own catalogue is the only input. A consumer that wants no restriction
  declares every resource it uses, which is the point.

### D10. The role name is an immutable key; "rename" changes the display name (decided by the user 2026-11-23)

Roles gain `display_name`, `description`, `labels` (a text array) and `version`. The name cannot be
updated.

- **Why:** the name is the join key of grants, assignments and `scrty_users.role`. A true rename would
  update three tables in one transaction while logins read them. Sessions are unaffected, since they
  reload, but every consumer cache, token or log that recorded the name would silently point at
  nothing.
- **Alternative:** move every reference to the role id. Rejected: it changes the loaders' contract and
  every adapter's schema for a feature a display name already gives.

### D11. Versions refuse stale writes; row locks serialise writes to one role or one user

`scrty_users.version` and `scrty_roles.version` (bigint, default 1) increase on every
administrative write to the row, including grant and assignment writes, which change the role's or
the user's version respectively. Each write runs in one transaction:

1. `SELECT ... FOR UPDATE` on the role or user row, which serialises writers to that row;
2. compare the version the caller named, and return `admin.ErrStaleUpdate` on a mismatch, or
   `admin.ErrNotFound` when there is no live row;
3. write, and increase the version.

The identity ports' own `Update` keeps its current contract and does not check versions. It does
increase the version, so an administrator's read becomes stale after a login-time update. Only
administrative writes compare versions.

- **Alternative:** `updated_at` as the version. Rejected: two writes inside one clock tick would
  compare equal, and an imported `updated_at` is the source system's time.
- **With an audit sink, the service refuses early (decided 2026-11-23, during implementation; F77).**
  The service reads the record for the audit's before value, and refuses with `ErrStaleUpdate`,
  writing and reporting nothing, when the version it read is not the one the caller named. The
  store's conditional write stays the authority; the early refusal only ensures a before record is
  never reported for a version the write did not replace. Without a sink nothing is read early.

### D12. Email is a column, unique among live users, and only the administration services set it (decided by the user 2026-11-23)

`scrty_users` gains `email text NULL`, `email_verified_at timestamptz NULL` and
`deleted_at timestamptz NULL`. A unique index covers `lower(email)` where `deleted_at IS NULL AND
email IS NOT NULL`.

- **The identity ports still discard email.** The OIDC broker passes the provider's email to
  `Provision` on every just-in-time login. Storing it would make a federated first login fail on any
  collision. The administration services and import set it; an application that wants a federated
  user's email stored sets it through them.
- **A username never equals another live user's email,** ignoring case, in both directions. A
  constraint cannot span two columns of two rows, so every write that sets a username or an email
  takes `pg_advisory_xact_lock` on a hash of each lower-cased value in the same transaction, then
  checks. A hash collision only serialises two unrelated writes. `Provision` takes the same lock,
  which is the one new refusal on the identity ports (proposal, **BREAKING (behaviour)**).
- **Departure from the established design:** it does not store email, as scrty did not. The user
  asked for email as a column.

### D13. Soft deletion keeps the username (decided by the user 2026-11-23)

`Delete` sets `deleted_at`, clears `active`, keeps the row and its username, sets the email to NULL,
and removes the user's profile attributes and password history in the same transaction. Every loader
filters `deleted_at IS NULL`. The username stays held by the unchanged unique constraint.

- **Why the email is cleared:** to release it for a new user, as the unique index already allows,
  and to keep a personal address out of a deleted record.
- **Why the history is removed:** the existing requirement treats password history as credential
  material removed with the user.
- **Override:** none. Reuse of a deleted username was considered and refused by the user.
- **The password hash stays in the row (decided 2026-11-23, during implementation).** `Delete` keeps
  `scrty_users.password`, as it keeps the username; no loader returns a deleted user, so nothing
  reads it. The history is what is removed, and a password change racing the delete must not write
  history back for a deleted user (F76).

**Store rules fixed while writing the administration conformance suite (decided 2026-11-23).**
- A user's first assignment is primary whatever the request says, so a user with grants always has
  a primary role. Each new assignment takes the next position.
- A forced role delete increases the version of every user whose assignment it removes (D11). A
  role assigned only to deleted users may be deleted without force; its rows go with it.
- Importing the identifier of a soft-deleted user is refused with `AlreadyExistsError` naming the
  field `id`: a deleted user is never restored (D13).
- Concurrent imports of identical payloads give one `ImportCreated` and `ImportUnchanged` for the
  rest.
- A store may accept an `AfterID` or `Organization.ID` it can hold, and then honours it; one it
  cannot hold is `ErrInvalidInput`.
  An `Organization.ID` it can hold but that names no organization is `ErrInvalidInput` too; the
  schema has no foreign key, so the store checks the organization under a key-share lock in the
  write's transaction.

**A role's super-role flag reaches its holders (decided 2026-11-23, during implementation).** The flag
is copied onto each grant when the role is assigned, and the authorizer reads it from the grant. A role
update that changes the flag therefore copies it onto every holder's grants in the same transaction,
locking the role and then the holders in identifier order, and bumps each holder's version. Turning
the flag off takes the bypass away from every holder on their next request.

**Imports of one identifier queue first.** Every import first takes a transaction-scoped advisory lock
on the user identifier, before any role or identifier lock, so two imports of one new user never wait
on each other in opposite orders.

### D14. Import matches by identifier only and writes nothing when nothing changed

`admin.Importer.Import(ctx, ImportedUser) (ImportOutcome, error)`. In one transaction it locks the
row by identifier, or creates it, compares every given field with the stored one, and writes only
when one differs. The outcome is `Created`, `Updated` or `Unchanged`.

- `UpdatedAt` before `CreatedAt` is refused as invalid input; a zero `CreatedAt` takes the service
  clock.
- The identifier's form is the store's to judge (decided 2026-11-23, during implementation, moving the
  check out of the service): scrty's stores require a canonical UUID, the users table's type, other
  than the nil UUID, and refuse any other text with `ErrInvalidInput`, so the identifier they return is the one given. The
  service does not parse it, because `identity.UserID` is an opaque, consumer-owned string; a
  consumer's own import store accepts whatever identifiers it holds. The password hash is stored
  as given and must be recognised by the configured encoder's recogniser, so a hash scrty could
  never verify is refused rather than locking a user out silently.
- A username or email held by a different identifier fails with `ErrAlreadyExists`, so import can
  never take over an account.
- The password policy is not applied: import stores a hash it is given and cannot judge the password.
- **Why a separate port:** `Provision` is create-only on purpose, by spec, against takeover. An
  upsert there would undo that.

### D15. Profile attributes are rows, not a JSON column

`scrty_user_attributes(user_id, name, value)` with a primary key on `(user_id, name)` and an index on
`(name, value)`. An update that names attributes replaces the whole set. Bounds: names 1 to 64 bytes,
values up to 1024 bytes, at most 64 per user.

- **Why rows:** exact-match search is an indexed equality on all three stores, including gorm, without
  JSON operators.
- **Override:** the bounds are options on `admin.NewUsers`. scrty never reads the values.

### D16. Paging by an opaque cursor

`List` orders by `(lower(username), id)` and returns a cursor that encodes the last pair and a
format version. It is not signed: a changed cursor can only move the starting point of a list the
caller may already read in full, and a signing key would have to be shared by every replica. Decoding
is strict, and a cursor that does not decode is refused as invalid input. Search
uses `ILIKE` with `%`, `_` and `\` escaped, so the search text is literal.

- **Default page size:** 50. **Maximum:** 500. Both are options.
- **Why a cursor:** offset paging skips or repeats users when the list changes between pages.
- **Accepted:** a search by substring scans the users table. That is acceptable for an administration
  screen, and the index on `lower(username)` serves the order.

### D16b. Password reuse and list folding (decided during implementation)

**The current hash is checked too (decided 2026-11-23, during implementation).** The reuse guard
compares a new password with the user's current hash as well as their history, as the login-side
password change does. `UserStore` therefore has `CurrentPasswordHash(ctx, id)`, which returns the
stored hash or none. The service hands it to the policy only; it never reaches a `User` record, an
event or the audit port.

**Password history follows the policy (decided 2026-11-23, during implementation).** The service sets
a password through `password.Policy.Change`, whose reuse rule retires the old hash through the
consumer's history port and prunes it to the rule's depth. The store's `SetPassword` writes only the
new hash and the change time. With no reuse rule, nothing is recorded, as everywhere else in scrty.
Retire and write are two calls; a failed write leaves a retired copy of the still-current hash, which
the next retry does not count twice (the policy's documented behaviour).

**A changed email is unverified until said otherwise (decided 2026-11-23, during implementation).** An
update that sets or clears the email without naming a verification time clears the stored one, so a
new address never inherits the old one's verification and so never becomes usable for login by email
unverified. **Amended after the code review (2026-11-23):** an email equal to the stored one ignoring
case, the uniqueness rule's comparison, is not a new address, so re-sending it keeps the verification
(F79). The store makes that comparison under the row lock it already takes for the version check,
so a concurrent email change cannot slip between the read and the write; the user store port states
the contract. A verification time for a user with no email is refused (F80).

**Grant names reach the store as the catalogue declares them (decided 2026-11-23, during
implementation).** The grant service compares names with the catalogue's folding, then rewrites
each listed name to the catalogue's declared spelling before the store call, so replacing `CRM/Lead`
replaces the stored `crm/lead`. When a store replaces a resource's grants, it matches the existing
rows by group and resource as the authorizer reads them, surrounding space trimmed and ASCII case
ignored, so clearing a resource the catalogue no longer lists removes every row the authorizer would
still load; the rows it inserts carry the names as given. Key names (usernames, role names,
labels) with leading or trailing whitespace are refused, and role names are exact.

**On import, every field is a value, except the two times.** A zero `EmailVerifiedAt` clears the stored
verification, so an imported email change never stays verified; only `CreatedAt` and `UpdatedAt`
read zero as not given.

**List order is folded in the store only.** The cursor carries the last username as stored and its
identifier; the store compares `(lower(username), id)` with `(lower($after), $id)` in SQL, so the
order and the cursor fold case the same way for every script.

### D17. Assignment dates are enforced when the chain builds the principal

`identity.PrincipalFromDetailsAt(details, at time.Time)` keeps only grants valid at `at`: start not after it,
end after it. The chain calls it with its clock on every request. If the primary grant is not valid,
the principal has no active role rather than another grant. Choosing a different grant would hand the
user privileges nobody chose.

- **Why not in the store:** the store contract says it does not filter, and other consumers of the
  loader rely on seeing every grant.
- **Why not in the authorizer:** `HasAnyRole` and every consumer reading `ActiveRole` would still see
  the expired role.
- `identity.PrincipalFromDetails` without a time is unchanged, for consumers outside the chain.

### D18. Login by email (decided by the user 2026-11-23)

`authenticate.WithEmailLogin()` on the password provider. The user loader must also implement
`identity.EmailLoader`, or construction fails. The provider exposes the identifier resolution as a
step the chain's login and basic endpoints run before the pre-authentication phase:

1. load by username; on found, the account is that user;
2. on not found, load by email (verified, live, ignoring case); on found, the account is that user;
3. if step 1 found a user whose username, lower-cased, also matches a different live user's verified
   email, refuse uniformly and emit `scrty_identifier_conflict`. The write-side lock of D12 makes this
   unreachable through scrty's stores, but a consumer's store may allow it.

The pre-authentication phase then sees the resolved account's username, or the identifier as typed
when nothing resolved, and the provider authenticates the details resolved in step 1 or 2 without
loading again.

- **Only identifiers with `@` reach the email lookup (decided 2026-11-23, during
  implementation).** Every stored email has one, so an identifier without it is never an email: it
  costs one lookup, as today. An identifier with `@` that names a user by username also gets the
  email lookup of step 3, the only way the conflict can be seen.
- **The resolved details travel only from the provider that made them.** A resolution carrier is
  honoured only by the provider that produced it; a hand-built or foreign carrier is ignored and
  the provider loads again. An honoured carrier presented with credentials for another identifier
  is refused, because ignoring it would let lockout judge one account while another is
  authenticated.
- **Resolution is reachable through composition (decided 2026-11-23, during implementation).**
  `authenticate.IdentifierResolver` is the exported port for the resolution step. `FirstOf`
  forwards it, through nesting, to its single member with email login on; more than one is
  `ErrConfig` when the `FirstOf` is built. The chain finds the resolver with
  `authenticate.ResolverOf` and resolves before pre-authentication whenever one reports email login
  on. A consumer's own wrapper around the provider must forward `ResolveIdentifier` and
  `EmailLogin`; one that hides them cannot be detected, and lockout then keys on the identifier as
  typed (F51).
- **A refused email match is recorded twice, on purpose:** the email mismatch is a warning about the
  consumer's loader, and the unknown-user refusal that follows is the attempt's own record.
- **The typed record is written without lockout reporting (decided 2026-11-23, during
  implementation; F70).** `policy.UnreportedAttemptRecorder` is an optional port of an attempt store:
  it records and clears failures that `FailureCount` still counts, but that no observer, security
  event or failure streak sees. The lockout's view implements it, and the chain writes the identifier
  as typed through it, so one account gives one report. **Default:** used whenever the chain's store
  implements it. **Override:** a consumer store implements the port, or does not and receives plain
  writes.
- **An account with no username is refused (decided 2026-11-23, during implementation; F72; scope
  confirmed by the user the same day, choosing by security practice).** A loader that returns one, by
  username or by email, is answered as for an unknown user, with email login on or off: an account
  the library cannot name would yield a principal, session, events and audit records with a blank
  identity, and a lockout keyed on whatever was typed. It fails closed, and has no override, because
  allowing it would weaken that guarantee. `identity.UserLoader` states the requirement. **Departure
  from main:** such an account logged in before; it is a breaking behaviour change, listed in the
  CHANGELOG. **Alternative:** refuse it only on the email path, keeping main's behaviour with email
  login off. Rejected: it keeps the blank-identity principal for every username-only deployment.
- **The email loader is checked, not trusted:** a user it returns unverified, or whose email does
  not match the input ignoring case, counts as not found.
- **Default:** off. Username-only login is unchanged.
- **Why username first:** existing logins keep their exact path and cost. The email lookup is paid
  only by identifiers that are not usernames.
- **Timing:** an unknown identifier makes two lookups where a username makes one. The password work
  is the same, and the decoy hash dominates the response time.

### D19. Administration events and the audit port

`event.Event` gains `Actor string`, `Target string` and `Changed []string`. The names follow the OWASP
Logging Vocabulary (spec `security-events`). Events are emitted after the transaction commits.

`admin.WithAudit(AuditSink)` delivers `admin.Change{Actor, Action, Target, Before, After}` for each
committed change, where `Before` and `After` are the administration records with the password hash
removed by construction: the audit record type has no hash field. A sink error is logged with the
action and target only.

- **Default:** events only, when the consumer gave a sink; no audit.
- **Accepted:** a crash between commit and delivery loses that event and audit record. Making delivery
  transactional would need an outbox table in the identity set. The consumer can put one behind the
  audit port.

### D20. Switching the active role (decided by the user 2026-11-23: build it as a convenience)

Sessions gain `SelectedRole string`, stored in a nullable `scrty_sessions.selected_role`. The chain
gains `httpsec.WithSwitchableRoles()` (named by the user 2026-11-23) and `Chain.SwitchActiveRole(ctx, role)`. That call reloads
the user, checks they hold a grant of that name valid now, writes only the selected-role field of the
current session, and emits `scrty_active_role_switched`. On every request, D17's mapping then makes
the selected grant active when it is still held and valid, and the primary grant otherwise.

- **Why the session and not a token claim:** every request already rebuilds the principal from the
  session's user. A claim would need re-issuing tokens and would outlive a revoked grant.
- **Default:** off. A selection stored while switching was on is ignored once it is off.
- **Recording the selection (decided 2026-11-23, during implementation):** `session.RoleSelector` is an
  optional store interface, implemented by every shipped store. It writes only to a live head: a
  missing session is `ErrNotFound`, a superseded one `ErrSuperseded`, one past either deadline
  `ErrExpired`. `Save` and a strict rotation keep the stored selection, so a stale copy cannot undo
  it. The empty role clears it, and durable stores store NULL. A role the database cannot hold is
  refused without echoing it.
  A supersession gives the successor the selection read from the locked old row, whatever the
  caller's copy says, so a switch that commits while a rotation is in flight is kept. The session
  manager exposes `SelectsRoles` and `SelectRole` so the chain reaches the store's selector without
  holding the store.
- **The lineage table gains the column too (decided 2026-11-23, during implementation):** the
  refresh-token lineage table runs every session statement with only the table name rewritten, and
  its columns are pinned identical to the sessions table's. Adding `selected_role` to
  `scrty_sessions` alone would break those statements as soon as they read or carry the column. The
  migration therefore adds it to both tables; it stays NULL on the lineage table. **Alternative:**
  a second set of session statements for the lineage table. Rejected: it duplicates every statement
  to save one nullable column.
- **The switch event carries the administration fields (decided 2026-11-23, during implementation):**
  `scrty_active_role_switched` names the user as `Actor`, the role now active as `Target` (empty when a
  cleared selection leaves no primary grant), and `active_role` in `Changed`, though the chain is not an administration component, because a user changing their own
  session is the actor of that change. The security-events spec states it as the one exception.

## Failure modes

| # | Failure | State | Outcome a caller sees |
|---|---|---|---|
| F1 | Two administrators edit one user or role from the same read | Handled, tested | Second write: `ErrStaleUpdate`, nothing written |
| F2 | Two grant replacements for one role race | Handled, tested (barrier) | One applied, the other `ErrStaleUpdate` |
| F3 | Store fails mid grant replacement | Handled, tested | Transaction rolled back; grants as before |
| F4 | Concurrent create with one username or email | Handled, tested | One created, others `ErrAlreadyExists` |
| F5 | Username and another user's email race to coincide | Handled (advisory lock), tested | At most one write succeeds |
| F6 | Consumer store holds a username equal to another user's email | Handled, tested | Uniform login failure and conflict event |
| F7 | Import replays an old payload over newer data | Accepted | Import writes the payload's values; the caller owns ordering. It reports `Updated` |
| F8 | Import with a hash no encoder recognises | Handled, tested | `ErrInvalidInput`, nothing written |
| F9 | Import of a username held by another id | Handled, tested | `ErrAlreadyExists`, both users unchanged |
| F10 | Deleted user's live session | Handled, tested | Next request refused as unauthenticated |
| F11 | Grant naming an unknown privilege or scope | Handled, tested | `ErrUnknownPrivilege`, nothing written |
| F12 | Undefined scope in stored data | Handled, tested | Covers nothing; denied |
| F13 | Own-only grant behind a plain route guard | Handled, tested | Denied, `ErrWrongScope` |
| F14 | Role loader outage under the memo | Handled, tested | Error not remembered; dependency failure, not denial |
| F15 | Concurrent checks under one memo | Handled, tested (race detector) | One load, same result |
| F16 | Memo reused across requests | Handled by construction, tested | A fresh memo per request; the next request sees changes |
| F17 | Request checks many role names | Handled (bound 32), tested | Loads beyond the bound are not remembered |
| F18 | Expired or future primary grant | Handled, tested | No active role; privilege guards deny |
| F19 | Selected role revoked after selection | Handled, tested | Primary grant active on next request |
| F20 | Lockout bypass through the email | Handled, tested | One budget per account |
| F21 | Email lookup outage | Handled, tested | Unavailable error, same password work |
| F22 | Migration on a consumer-added `email` column | Handled, tested | Migration fails atomically, changes nothing |
| F23 | Oversized page, attributes or search | Handled, tested | `ErrInvalidInput` |
| F24 | Malformed cursor | Handled, tested | `ErrInvalidInput`, not a storage error |
| F25 | Write with no actor | Handled, tested | `ErrNoActor`, nothing written |
| F26 | Audit sink fails or panics | Handled, tested | Change stays committed; failure logged without values |
| F27 | Crash between commit and event or audit delivery | Accepted (D19) | Record lost; consumer may add an outbox |
| F28 | Forced role delete, or removing a primary assignment, leaves a user without a primary grant | Handled, tested | The remaining grant with the lowest position, the one assigned first since an assignment always takes the next position, becomes primary; none left means no role. Each affected user's version increases |
| F29 | Error text leaks a username, email or hash | Handled, tested | Text carries none; reason is a sentinel |
| F30 | Grant service built without a catalogue, or a contradictory catalogue | Handled, tested | Configuration error at construction |
| F31 | Federated first login whose username is a local email | Handled, tested | Provision refused; login fails as a provisioning refusal |
| F32 | Bulk check against an authorizer without the inspector | Handled, tested | `ErrInspectionUnsupported` |
| F33 | Context cancelled during an administration write | Handled, tested | Transaction rolled back; the context's error returned |
| F34 | Identity migration rolled back on a database in use | Accepted (Migration Plan, step 4) | Emails, attributes, scopes, versions, labels and deletion marks are dropped; the Down section's comment says so |
| F35 | A consumer authorizer allows a scoped check without reporting the scope | Handled, tested | `CheckAnyScope` and `HasPrivilegeFor` fail with `ErrConfig`; no scope is guessed |
| F36 | A nested check overwrites the scope an outer check reported | Handled by construction | The scope travels with the check's own attributes, not the context |
| F37 | A member of `AnyOf` fails with an outage while no member allows | Accepted (spec authorization, `AnyOf` otherwise denies) | Denied with `ErrNotGranted`; the outage is not surfaced. Use `AllOf` or a single requirement where an outage must stay an outage |
| F38 | `Provision` or an identifier write runs inside a consumer's long transaction | Accepted (godoc) | The identifier locks are held until that transaction ends; a savepoint rollback does not release them. Other writes of the same identifiers wait |
| F39 | `Provision` runs inside a consumer's REPEATABLE READ or SERIALIZABLE transaction | Accepted (godoc) | The username-is-an-email check reads the caller's snapshot and can miss an email committed after it; the default READ COMMITTED path sees it |
| F40 | The plaintext password lingers in memory | Accepted | The policy and encoder take a string, so one immutable copy lives until garbage collection; the caller's bytes are neither kept nor changed |
| F41 | Identifiers differ only by case outside ASCII, or by Unicode normalisation | Accepted (store godoc) | Case is folded by the database's `lower()`; on a C or POSIX ctype it folds ASCII only, and composed and decomposed forms count as different identifiers, and an invisible format character such as a zero-width space at the edge of a name is kept. The lock, the check and the unique index fold alike, so no race opens; a consumer wanting stricter matching normalises identifiers before calling scrty |
| F42 | The role loader panics under the memo | Handled, tested | The entry is removed, waiters wake with an error and the panic continues in the loading check; a later check loads again |
| F43 | The check that is loading is cancelled while others wait | Handled, tested | Its result, whatever it is, is not remembered; a waiter whose own context is live loads again; one whose context ended returns its context's error; a loader panic takes precedence and reaches waiters as an error (F42) |
| F44 | A username containing `@` logs in with email login on | Accepted | One extra lookup for the conflict check; usernames without `@` cost the same as before |
| F45 | A caller mutates the role or organization data of a resolved identifier | Accepted (godoc: read-only) | The data is shared with the loaded record; the password hash is removed from the copy |
| F46 | A consumer role loader answers differently by something in the context other than the role name | Accepted (godoc of `WithRequestMemo`) | Within one memo, the first answer for a role is reused; such a loader installs a memo per tenant or none |
| F47 | A consumer privilege inspector returns an answer that breaks its contract | Handled, tested | `HeldPrivileges` refuses it with `ErrConfig` and no holdings |
| F48 | A resolution is kept and presented after its attempt | Accepted (godoc: one attempt) | It authenticates against the details loaded when it was made; only the caller's own code can hold one |
| F49 | A user changes between reading the row and reading its grants in `List` or `Get` | Accepted | The record may combine two moments; any write through it is checked against the version, so nothing stale is written |
| F50 | An import changes a user's roles | Accepted | The grants are rebuilt from the payload in its order, the first primary, overriding a primary chosen through the assignment service; import is a full sync from the source system |
| F51 | A consumer's wrapper hides the password provider's resolver | Accepted (godoc of `ResolverOf`) | Email login still works, but lockout keys on the identifier as typed, so an account's username and email have separate budgets |
| F52 | A password handler that does not resolve sits ahead of the email-login member in a `FirstOf` | Handled for scrty's providers, accepted for a consumer's own | `NewFirstOf` refuses one of scrty's password providers placed before the email-login member with `ErrConfig`; a consumer authenticator in that position can authenticate its own account while lockout was keyed on the resolved one (godoc) |
| F53 | Many cancelled checks keep taking over one role's load while a live check waits | Handled, tested | After eight rounds the live check loads for itself without the memo, so it never takes another check's cancelled result |
| F54 | An old session is renewed again after its successor recorded a selection | Accepted | The new successor is built from the old session, which never had the selection, so the primary role applies until the user switches again |
| F55 | An import changes a user while an audit port is set | Accepted (spec) | The audit record carries the imported values as After and no Before; the import port does not return the previous record |
| F56 | A write that changes nothing but the version, such as setting an already-primary grant primary or an update with equal values | Accepted | It is versioned and reported like any change; only `SetActive` and import detect a no-op |
| F57 | An administration write waits on a row lock held by a slow writer | Accepted | The wait is bounded by the caller's context deadline, as for every store call; the consumer sets it |
| F58 | An attacker alternates a user's username and email at the login | Handled, tested | Lockout keys on the resolved account, so both count against one budget. A failure is also recorded under the identifier as typed when it differs, so the automation challenge treats a registered email exactly as an unknown one and reveals nothing |
| F59 | The login itself builds its principal | Accepted | The password provider and magic links have no clock option and read the wall clock; every later request is built with the chain's clock. They differ only under a fake or skewed clock |
| F60 | A role is assigned to a user who already holds it | Accepted | A second grant is added; two grants of one role may carry different date windows, and only grants valid now apply |
| F61 | A consumer's identifier resolver fails | Handled, tested | The login is refused with the sanitized failure, an outage staying an outage, after the same decoy work; it is logged. Lockout never judges one key while another account is authenticated. A consumer authenticator that offers no decoy spends no password work on that refusal; the chain warns about such an authenticator at construction |
| F62 | Lock disclosure is turned on with email login | Accepted (godoc of `WithLockDisclosure`) | Locking an account through its username, then presenting a candidate email, shows whether the email belongs to it; disclosure is the consumer's opt-in |
| F63 | A role selection commits while a rotation of the same session is in flight | Handled, tested (`RotationTakesSelectionMadeDuringStep`, `SupersedeTakesSelectedRoleFromLockedRow`) | The successor takes the selection from the locked old row, so the switch is kept, up or down. A consumer store that skips this read-back fails the session conformance suite; if run anyway, the selection is lost and the primary role applies |
| F64 | The identity ports provision or update a grant while a forced role delete or a super-role flag change runs | Accepted | Those ports write grants without the role's lock, as before this change, so such a grant can survive the delete, or carry the old flag, until the next administrative write to that role or user; the administration ports are serialised against it. A non-forced delete is affected too: a grant an identity port commits between the delete's holder check and its removal of assignments is removed without `ErrStillAssigned`, and the user's role column may still name the deleted role until the next administrative write |
| F65 | An import runs inside a caller's long transaction | Accepted (godoc) | The import's identifier lock is held until that transaction ends, as in F38; other imports of that identifier wait. Two identifiers whose lock hashes collide only queue behind each other |
| F66 | `SwitchActiveRole` is called on a session a consumer's own interceptor published | Handled, tested | Refused with an error matching `ErrConfig`: only a session this chain resolved can be switched, through the loader and manager that resolved it |
| F67 | A switch is made during a request | Accepted (godoc) | That request keeps the role it was authenticated with; the switch applies from the next request. A role name over 256 bytes, or one no store could hold, is refused as not held |
| F68 | A session is renewed through the renewal endpoint after a switch | Accepted | That one renewal response carries the primary role; the next request applies the selection again |
| F69 | A failed login by email | Accepted | The failure is recorded under the resolved account and under the email as typed, so the attempt store holds rows keyed by typed emails, as it already does for unknown ones; a resolver outage with scrty's provider is logged by the provider and by the chain |
| F70 | A lock is reached by email | Handled, tested (`TestLogin_EmailReportedOnceUnderAccount`, form and Basic; `TestLockoutViewUnreported`) | The failure is recorded under the account through the lockout's view, and under the email as typed through `policy.UnreportedAttemptRecorder`, which lockout's view implements by writing to its store with no observer report, no security event and no streak. A lock, hold or clear is reported once, under the account. A consumer store without the port gets plain writes (`TestLogin_EmailCountedUnderBothWithPlainStore`); a failed typed write or reset is logged and changes no response (`TestLogin_EmailTypedRecordThroughConsumerPort`) |
| F71 | A consumer attempt store folds case, and a user logs in with a case variant of their username through a case-insensitive loader | Accepted (godoc of `policy.AttemptStore`; decided by the user 2026-11-23, during implementation) | Identifiers match exactly by contract, and a folding store is outside it: such a failure is counted twice, so the store locks sooner than configured. Skipping the typed record on a case-only match was rejected: the automation challenge runs before the identifier is resolved, so it reads only the typed text, and an exact-match store with a case-insensitive loader would then never show the challenge for `ADA` while an unknown identifier does, a challenge bypass and an enumeration signal. Moving the challenge after resolution was rejected too, as it would read the account on requests the challenge refuses |
| F72 | A consumer's user loader returns an account with an empty username, by username or by email | Handled, tested (`TestPassword_ResolveRefusesAccountWithoutUsername`; reproduced: before the fix such an account authenticated outright, and lockout keyed on the identifier as typed) | The account is refused as an unknown user would be: `ErrAuthenticationFailed` after the same decoy password work, and a warning with reason `user-without-username` that names no identifier. This holds with email login on or off |
| F73 | A failed login by a registered email, timed against one by an unknown email | Accepted | The registered email makes one more attempt-store write on the response path (the account's record and the typed one, where an unknown email makes one). The decoy password hash, run either way, dominates the response time; the typed write does none of the lockout view's reads (F70). Moving it off the response path would detach a write the request no longer waits for, and was not chosen |
| F74 | A consumer's wrapper around the lockout view hides `policy.UnreportedAttemptRecorder` | Accepted (godoc of `UnreportedAttemptRecorder`) | The typed record arrives as a plain write, which the view reports, so the identifier as typed is reported a second time, as before F70. A capped policy refuses such a wrapper at construction already; an uncapped one accepts it. Mirrors F51 |
| F75 | An email held while it named no account is later verified for one, and its owner logs in by email | Accepted (godoc of the lockout view's `ResetUnreported`) | The success clears that hold through the unreported reset, so the earlier `ReportHeld` is never followed by `ReportReleased`. Nothing is locked or held silently |
| F76 | A password change races a soft delete of the same user | Handled, tested (`Users/RetireAfterDeletion` in the shared suite; `RetireRacesDelete`, both interleavings, per store) | `RetirePassword` takes the user row `FOR UPDATE` (F78) before writing history, and `DeleteUser` takes it `FOR UPDATE` before removing it, so the two serialise: a retire after the delete is refused with not-found (matching `identity.ErrUserNotFound` and `admin.ErrNotFound`) and writes nothing, and a delete after the retire removes what it wrote. A reference with no user row still records history, as before: the tables declare no foreign key, and the password-history port serves such references (accepted) |
| F77 | With an audit sink, the record read for the before value is at another version than the caller named | Handled, tested (`TestAudit_BeforeIsTheVersionTheWriteReplaced`, nine writes) | `ErrStaleUpdate` before anything is written or reported (D11) |
| F78 | Two password changes for one user run concurrently inside callers' transactions | Handled, tested (`RetireThenSetPassword`, per store; task 15.3; was Accepted before the code review) | `RetirePassword` locks the user row FOR UPDATE, not FOR SHARE, so the second change waits for the first instead of deadlocking on a lock upgrade |
| F79 | An administrator re-sends a user's current email, as an edit form does | Handled, tested (`Users/UpdateEmailVerification`, with toy-store guard defects; task 15.2) | The verification is kept when the email equals the stored one ignoring case, compared under the row lock; only a different address is unverified |
| F80 | An update names a verification time for a user with no email | Handled (task 15.4) | `ErrInvalidInput`, nothing written |
| F81 | An update names an email, and the event's changed fields are computed | Accepted (task 15.2's review) | The stores do not report which fields a write changed, so the service lists `email` whenever it is named, as for every other field, and `email_verified_at` whenever a named email may have left the user unverified, including one already unverified. A re-sent equal email with a kept verification lists `email` only. The list may name a field whose value did not change; it never omits one that did |

## Risks / Trade-offs

- [Part C triples the store work across three adapters] → one shared statement set in
  `internal/pgschema` for the two SQL adapters, gorm in its own task group, and one conformance suite
  that proves all three.
- [A consumer added their own `email` column to `scrty_users`] → the migration fails atomically
  on `ADD COLUMN`, and the CHANGELOG says to rename or drop that column first.
- [Provisioning gains a refusal] → the refusal only applies when a username equals another live
  user's email, which is the confusion login by email must prevent. It is listed as a behaviour change.
- [Applications that ignored assignment dates may lose access] → listed as a behaviour change; dates
  set in the past are exactly the grants that should no longer apply.
- [Substring search scans the users table] → bounded page size; documented. An application with very
  many users filters by attribute or role first.
- [The advisory lock serialises unrelated writes on a hash collision] → 64-bit hash; contention is
  negligible for administration traffic.

## Migration Plan

1. Before upgrading, check that `scrty_users` has no `email` column of the consumer's own. scrty
   never created one, so only a consumer's addition can be there.
2. Apply the security-state set (adds `scrty_sessions.selected_role`) and, if the default identity
   store is used, the identity set (adds the administration columns, the attribute table and the
   unique index). Both run after `20261124000000_scrty_prefix`.
3. Deploy. Nothing turns on by itself except the per-request memo and assignment-date enforcement.
4. **Rollback:** roll the identity set back by one, then the security-state set by one. Emails,
   attributes, scopes, versions, deletion marks and selected roles are lost. A soft-deleted user
   becomes a live, inactive user again. Grants read as before.

## References

All accessed 2026-11-23.

### D12, D18: email uniqueness and login by email

**Researched:**
- [Keycloak forum, Non-Unique Email](https://forum.keycloak.org/t/non-unique-email/860): "Login with
  email" and "Duplicate emails" are mutually exclusive in the admin UI, with a report of logging into
  the wrong account when both were on.
- [Red Hat, RH-SSO import fails with "email already exists"](https://access.redhat.com/solutions/3075701):
  unique emails are required while login with email is on, which is the default.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html):
  an email may be used as a username when it is verified, and a non-email username should remain
  possible. The case-insensitivity advice for user IDs was read only through mirrors and an archived
  wiki, and is unverified at the current page.

### D19: administration events

**Researched:**
- [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html):
  `user_created`, `user_updated`, `user_archived`, `user_deleted`, `authz_change`, `authz_admin` and
  `privilege_permissions_changed`, with the fields each carries. The page's own example line spells
  the last as `permissions_changed`; scrty uses the heading name.

### D2 to D11, D13 to D17, D20: reasoned from scrty's own settled specs and the established design

No external source. They follow `authorization`, `identity-model`, `default-identity-store`,
`http-security-chain`, `sessions` and `security-events` as they stand, and the decisions the user
made on 2026-11-23.
