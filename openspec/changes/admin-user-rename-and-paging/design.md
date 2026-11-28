# Design

## Context

See proposal.md for why. D1 to D3 were proposed with the draft. D4 to D7 were decided with the user on 2026-11-28,
after research and after rebasing onto current `main`. A re-audit on the same day corrected D5's
description of lockout holds, settled when D6's revocation runs, and added D8. Offset paging and
counting (D9 to D14) were decided with the user the same day and folded into this change, which was
renamed from `admin-username-change`. Later the same day, during implementation, the user waived
compatibility for consumer implementations of scrty's ports (the only consumer is the user's own
application): D7, D8, D12 and D14 were revised so renames, offsets and counts are part of
`UserStore` itself, and D15 folds every other compatibility-only optional port in the library into
its base interface.

What the code already gives a rename:

- **The update path.** `Users.Update` takes the actor, checks the identifier and version, validates
  the change, reads the audit "before" record conditional on the version, calls
  `UserStore.UpdateUser`, and reports `event.UserUpdated` with the names of the changed fields
  (`changedUserFields`). The store compares the version under the user's row lock.
- **The administrative update statement.** The SQL stores build it with
  `pgschema.UpdateAdminUserQuery`, which writes only the columns on its whitelist and panics on any
  other. The username is not on it yet. (`storekit.UpdateUserQuery` is the identity port's update
  and never writes a username; this change does not touch it.)
- **The identifier guards.** Every scrty store write that sets a username or an email takes one
  transaction-scoped advisory lock per distinct value, keyed by `lower(value)` and taken in
  ascending key order (`IdentifierLockKeys`, `LockIdentifierKey`). Two values equal ignoring case
  take one lock. It then checks the queries that exclude the user being written: `UsernameTaken`
  (exact, deleted users included), `EmailHeldByLiveUser` and `UsernameHeldByLiveUser` (both
  ignoring case, live users only). Each SQL store's `checkIdentifiers` already runs all four checks
  for a username and an email. Import already changes usernames this way (`SetImportedUsername`),
  so the store already does the locking and checks a rename needs.
- **The unique-violation fallback.** Each store's `UpdateUser` maps a unique violation from the
  update statement to `FieldEmail`, because the email is today the only unique value that statement
  sets. Import, which can change both, writes a changed username alone first
  (`SetImportedUsername`), so a violation there is the username and one in the following statement
  is the email. The stores cannot read a violated constraint's name portably: `sqlstore` sees only
  the driver error's SQLSTATE, so the constraint's name (`scrty_users_username_key`) is out of its
  reach.
- **The username's reach.** Sessions and refresh families record the user identifier, not the
  username (`session.Session.UserID`); refresh families are kept in the session store, so
  `Sessions.DeleteByUser` removes them with the sessions. The OIDC provider's `sub` is always the
  identifier. The token subject is the identifier by default. Only the username-subject modes
  (`token.WithUsernameSubject`, `httpsec.WithBearerUsernameSubject`,
  `authenticate.WithJWTUsernameSubject`) put the username in a token. They differ after a rename:
  the `httpsec` bearer loads the user the token names and refuses a session whose recorded user
  differs (`ownsSession`), so an old-username token stops working there; the standalone
  `authenticate.JWTAuthenticator` builds the principal from the token's subject without loading
  any user (`principal`), so an old-username token keeps authenticating, under the name it carries,
  until it expires. Lockout failure counts and holds are keyed by the username
  (`policy/lockout`), and login by email keys them on the resolved account's username too.

What the code gives the listing:

- **The listing.** `Users.List(ctx, UserFilter)` validates the filter into a `UserQuery`, calls
  `UserStore.ListUsers`, and returns `UserPage{Users, Next}`. `Next` encodes the last
  `(username, id)` of a full page. The order is `(lower(username), id)`, served by the
  `lower(username)` index. Page size defaults to 50, at most 500 (`WithPageSize`).
- **The statement.** `pgschema.ListAdminUsers` holds the filters (literal `ILIKE` search, active,
  role, attribute), the cursor comparison and `LIMIT`. All three SQL stores run it.
- **The settled decision.** D16 of the archived `security-administration` design chose cursor
  paging because offset paging skips or repeats users when the list changes between pages. The
  established design has no user listing to compare with.

Shared by both:

- **The public conformance suite.** `admintest.RunConformanceSuite` and `RunUserSuite` call the
  store's ports directly, and consumers run them against their own stores.
  `TestAdminSuiteIsLoadBearing` proves each case fails against a toy store carrying a named defect.

## Goals / Non-Goals

**Goals:**

- A username and an email change in one call, one version check and one write.
- A rename is refused for exactly the reasons a creation is.
- The event and the audit record report a rename as an update with the field `username`.
- Importing users keeps working unchanged.
- A caller can fetch any page of users by number and know how many users match.
- Cursor listing keeps working exactly as it does, and stays the default.
- One way to do each thing: no optional port exists only so that an older consumer implementation
  keeps compiling (D15).

**Non-Goals:**

- Changing how usernames are compared anywhere else.
- Moving or keying any security state (sessions, lockout, MFA, passkeys) by something other than
  what keys it today.
- A dedicated rename endpoint or page. Administration stays a set of services.
- Consistent paging across pages in offset mode, a previous-page cursor, or a total inside
  `UserPage`.
- Changing the list order, the filters or the page-size bounds.
- Keeping consumer implementations of scrty's ports compiling across this change (D15).
- Sharing the three SQL stores' duplicated logic; that is a separate change.

## Decisions

### D1: A field on `UserChange`, not a `Users.Rename` operation

`UserChange` gains `Username *string`. A nil username is unchanged, like every other field. A
change naming only the username is a change: the "names no field" refusal counts it.

- **Why:** a consumer whose usernames are emails must change both in one write. A
  `Rename(ctx, id, version, username)` can change only the username, so the email would need a
  second write and a second version check. That brings back the half-applied state this change
  removes.
- **Alternative:** `Rename` that also takes an optional email. It duplicates `Update`'s email rules
  and leaves two ways to change an email.
- **Default / override:** no configuration. A consumer who wants renames to be a separate
  operation in their application gates the field at their own route.

### D2: A rename is validated and checked as a creation is

- The service validates a username with `exactName`, as `Create` does: it refuses a blank
  username, one with leading or trailing white space, one longer than `MaxTextBytes`, and one that
  is not valid UTF-8 or holds a control character (NUL included), with `ErrInvalidInput`.
- The store refuses, as an `AlreadyExistsError` with `FieldUsername`, a username another user
  holds, deleted or not, compared exactly, and a username equal to another live user's email,
  ignoring case. Both checks exclude the user being renamed. A user may therefore:
  - change only the case of their username;
  - take a username equal to their own email, including an email the same change sets, in any case.
- Comparison is byte for byte. Two spellings that differ only in Unicode normalisation (NFC and
  NFD) are different usernames; the rename succeeds and stores the bytes as given.
- A change naming both a username and an email locks both values before checking either, in key
  order, with one `checkIdentifiers` call, so a racing creation or update cannot slip a clashing
  pair between the checks.
- **The write is two statements, as import's is.** First a new statement,
  `pgschema.RenameAdminUser` (`UPDATE scrty_users SET username = $2 WHERE id = $1 AND username <> $2`),
  writes the username alone. One row affected means the stored username differed: the user was
  renamed. A unique violation here is `FieldUsername`. Then the existing
  `UpdateAdminUserQuery` writes the other fields, `updated_at` and the version; a unique violation
  there is `FieldEmail`. Both run in the one transaction under the row lock, so either both apply
  or neither does. Neither error carries the value.
- Renaming to the current username, byte for byte, is still a write: the version increases and the
  field is reported, as `Update` treats every other field it is given. It is not a rename: the
  store reports it as unchanged, and D6 revokes nothing for it.
- **Override:** none. Uniqueness is a guarantee the stores make, not a policy.

### D3: The event and audit name `username`

`changedUserFields` adds `"username"` when the change names it, first in the list, ahead of
`name`. As today, `email_verified_at` also appears when a named email leaves the user unverified. The audit "before" and "after" records already carry `Username`. Error text never contains
the username (the `security-administration` error requirement).

- **Default / override:** none; the event's field names are a contract every caller relies on.

### D4: Usernames are compared exactly on rename, as on creation

- **Decision:** a rename uses `Create`'s rule. Usernames are compared exactly, deleted users
  included. The cross-check against other live users' emails ignores case.
- **Why not case-insensitive here:**
  - a rule for rename alone would make the outcome depend on which call wrote the username;
  - a case-insensitive rule for every write is a compatibility change, because existing data may
    already hold `Ada` and `ada`.
- **Known gap:** a deleted user's username stays taken exactly, so `D@x` can be given while `d@x`
  belongs to a deleted user. Login by username is exact, so this creates no ambiguity at sign-in.
- **Follow-up:** `username-case-folding`, which adopts case-insensitive uniqueness for every write,
  with a check for clashing existing data. RFC 8265 §3.2 prefers case-mapped usernames to avoid
  false accepts, and Keycloak always lowercases usernames.
- **Override:** none. Uniqueness is a guarantee the stores make.

### D5: Lockout state stays under the old username (accepted)

Failure counts and holds are keyed by the username, so they do not follow a rename:

- the renamed account starts with no failures and no hold under its new username;
- the old username becomes free, and whoever later takes it inherits what is recorded under it:
  - failure counts below the streak limit age out of the window, and a count below the streak
    limit expires after the streak retention (30 days of inactivity by default);
  - **a hold never expires.** When the consumer has enabled a failure-streak limit and the old
    username is held, the next holder of that username is refused before their password is
    checked, until the failures are cleared by a password change through the chain or by the
    lockout policy's `Reset`.
- **Remedy, documented, not automated:** an administrator who renames a user calls the lockout
  policy's `Reset(ctx, oldUsername)` to release what the old username carries. The godoc of
  `UserChange.Username` names this.

This is accepted and documented in the godoc of `UserChange.Username` and in the failure modes.

Moving or clearing the state automatically would need a consumer-wired hook. The project allows no
store transaction across the security-state and identity table groups, and the hook would make
`admin` depend on something beyond its store. The underlying issue is the key: NIST SP 800-63B and
OWASP describe failure limits per account, not per name.

- **Follow-up:** `lockout-by-user-id`, which re-keys lockout state by user identifier.

### D6: An opt-in option ends the user's sessions after a rename

- **Default:** a rename ends no session and revokes no refresh family. Sessions are keyed by the
  user identifier. Username-subject tokens naming the old username fail closed at the `httpsec`
  bearer, and keep authenticating at the standalone `JWTAuthenticator` until they expire (Context).
- **Override:** `WithSessionRevocation(r SessionRevoker)` on `NewUsers`, where:

  ```go
  type SessionRevoker interface {
      DeleteByUser(ctx context.Context, user identity.UserID) error
  }
  ```

  `*session.Sessions` satisfies it as it is, so `admin` does not import `session` and needs no
  adapter. Its `DeleteByUser` removes refresh families too, because they live in the session store.
- **When it runs:** only after an update that **changed** the username has committed, as the store
  reports it (D7: `UpdateUser`'s `renamed` result, decided under the row lock by the
  conditional username write of D2). A case-only change is a change. It revokes every session of
  the user. An update that names no username, names the current one byte for byte, or fails or is
  refused, revokes nothing.
  - **Why "changed", not "names":** profile forms commonly send every field on each save. Revoking
    whenever the username is named would sign a user out everywhere on every such save, including
    an administrator editing their own profile. The store already holds the stored row under lock,
    so it can tell without an extra read.
- **When revocation fails:** the update stays committed and its event is emitted. `Update` returns
  the updated user **together with** an error matching `ErrSessionsNotRevoked` that wraps the
  cause, so the caller can retry the revocation. A context cancelled after the store commits gives
  the same outcome: the revoker's error wraps the context's error, never a silent success. Rolling
  back is impossible, because the two writes are in different table groups.
- **Settled requirements this modifies:** "Every administrative change emits an event" says a
  failed call emits none, and "Administration errors carry one reason each" lists a closed set of
  reasons. Both are modified in this change's spec delta: a committed change whose follow-up
  revocation fails still emits its event, and sessions-not-revoked is a reason of its own.
- **Accepted, caller's transaction:** a scrty store joins a transaction the caller already holds
  (under a savepoint). Then `UpdateUser` returns before anything commits, the revoker runs,
  and a later rollback by the caller leaves the sessions ended for a rename that never happened.
  The `WithSessionRevocation` godoc says so: a caller that wraps updates in its own transaction
  revokes sessions itself, after its commit, instead of using the option.
- **Error wrapping, not cancellation-proofing:** the revoker runs on the caller's context. A context
  cancelled after the store commits makes the revoker fail, which is reported as any revoker
  failure (`ErrSessionsNotRevoked` wrapping the context's error). Running it detached from
  cancellation would need its own bound; not done, because the caller can retry with the returned
  error.
- **Wiring:** a nil revoker, typed-nil included, fails `NewUsers` with an error matching
  `ErrConfig`. Every `UserStore` renames (D7), so no store makes the option meaningless.
- **Not covered:** grants the OpenID Provider issued are not revoked by this option. They are keyed
  by the user identifier and are unaffected by a rename.
- **Sources:** none of the sources read says a rename must end sessions. Auth0's user update treats
  the username as an editable field separate from the stable `user_id`, and says nothing of
  sessions. This is therefore the consumer's policy, offered as an option.

### D7: A rename goes through `UserStore.UpdateUser`, which reports the change

- **The port:** `UserStore.UpdateUser` takes a change that may name a username and also reports
  whether the stored username changed:

  ```go
  // UpdateUser applies change under the version check, in one write. When
  // change names a username it is written under the rules of creation, and
  // renamed reports whether the stored username differed from the named one,
  // byte for byte, decided under the row lock. A change naming no username
  // reports renamed false.
  UpdateUser(ctx context.Context, id identity.UserID, version int64,
      change UserChange) (updated User, renamed bool, err error)
  ```

- **Why one method:** a second, optional rename method existed only so that a consumer store written
  before this change kept compiling. The owner waived that compatibility (D15), so there is one
  update path, one implementation per store, and no call-time refusal. The `renamed` result is what
  D6 needs; the store holds the row under lock and can tell without an extra read.
- **Superseded draft:** an optional `UsernameUpdater` port with `UpdateUserRenaming`, detected in
  `NewUsers`, refusing a rename with `ErrConfig` on a store without it. Dropped on 2026-11-28 with
  D15. It also carried an embedding hazard (a store overriding `UpdateUser` alone left renames on the
  embedded method), which one method removes.
- **Order of refusals:** input validation first (`ErrInvalidInput`), then the store.
- **Default / override:** none. Uniqueness and the `renamed` report are guarantees every store makes.

### D8: The public conformance suite runs the rename cases against every store

- **Decision:** the rename cases in `admintest.RunUserSuite`, and "Import after a rename" in
  `RunImportSuite`, run for every store. There is no skip.
- **Load-bearing proof:** `TestAdminSuiteIsLoadBearing` carries defects (an `UpdateUser` that ignores
  the username; one that skips the username clash checks; one that always reports `renamed` as
  false), each caught by a named case.
- **Store-only races stay out of the public suite:** the barrier race and the unique-index
  collision live in `test/internal/adminfix`, which runs only against scrty's SQL stores.
- **Superseded draft:** the cases ran only for stores implementing the optional rename port and were
  skipped, with a message, otherwise. Dropped with D7.
- **Default / override:** none; the suite is the contract every store is held to.

### D9: Offset paging beside the cursor, which stays the default

`UserFilter` gains `Offset int`. A caller jumping to page `p` (from 1) with page size `n` passes
`Offset: (p-1)*n`.

- **Departure from D16 of the archived design**, decided with the user on 2026-11-28 and recorded
  here as a decision: D16's reason still holds, so the cursor stays the default. Offset paging is added because a consumer needs numbered
  pages, which a forward cursor cannot give. Its trade-off is stated, not hidden (failure modes).
- **Offset, not a page number:** an offset does not depend on the page size, so a caller that changes
  the page size keeps its place. A page number is one multiplication away.
- **Rules:** an offset below zero is `ErrInvalidInput`. A non-zero offset with a cursor is
  `ErrInvalidInput`. An offset past the last match is an empty page.
- **Offset zero is "no offset":** `Offset` is an `int`, so zero cannot be told apart from a field
  left unset. Offset zero is therefore the first page of the default listing: it goes through
  `ListUsers` on every store, and a full page carries a `Next` cursor as today. A caller paging by
  offset ignores `Next`. (A pointer or a separate mode flag would make "offset zero" expressible, at
  the cost of a clumsier filter for every caller; the first page is the same users either way.)
- **No cursor from a non-zero offset:** a page listed from a non-zero offset has an empty `Next`.
  A cursor made by offset mode would mean something different from one made by cursor mode. The
  caller computes the next offset. The godoc of `List` and of `UserPage.Next`, which today say a
  full page always carries `Next`, are updated to say so.
- **Default / override:** the default listing is the cursor. A consumer opts into offset paging per
  call by setting `Offset`.

### D10: A separate `Count`, not a total in every page

```go
func (u *Users) Count(ctx context.Context, filter UserFilter) (int64, error)
```

- It counts live users matching `Search`, `Active`, `Role` and `Attribute`, by the same rules and
  validation as `List`. `PageSize`, `Offset` and `Cursor` are ignored, so the filter used for a page
  can be counted unchanged. The same bounds still apply to the fields it does read.
- **Why separate:** a total costs a second query. Putting it in every page makes every caller pay,
  including cursor callers who never show it. Keycloak's admin API takes the same shape
  (`/users/count` beside the paged list).
- **Not one snapshot:** the count and the page are two reads. A write between them can make
  "10 of 999" off by the writes in between. Accepted: an administration screen tolerates it, and a
  shared snapshot would need a transaction spanning two service calls.
- **Default / override:** no configuration. A caller that does not need the count does not call it.

### D11: The offset is bounded, by default to 10 000

- **Default:** an offset above `DefaultMaxListOffset` (10 000) is `ErrInvalidInput`, before the
  store is called. The bound is inclusive. With the default maximum page size of 500, the last
  reachable user is number 10 500.
- **Why:** PostgreSQL computes and discards every row an `OFFSET` skips, so a deep offset is a scan
  proportional to its depth, on every request. Auth0 bounds the same cost by making only the first
  1 000 results reachable.
- **Override:** `WithMaxListOffset(n int)` on `NewUsers`. `n` below zero fails `NewUsers` with
  `ErrConfig`. `n` of zero allows only the first page.
- A consumer whose list is larger narrows it with filters, or uses the cursor, which has no depth
  cost.

### D12: Offset and count are part of the user store

```go
type UserQuery struct {
    // ... existing filters, Limit, AfterUsername, AfterID ...
    Offset int // users to skip, in list order; never set together with the After fields
}

// UserStore gains:
// CountUsers returns the number of live users matching query's filters.
// query.Limit, query.Offset and the After fields are ignored.
CountUsers(ctx context.Context, query UserQuery) (int64, error)
```

- `ListUsers` serves both listings: with `Offset` zero it is the cursor listing as today; with a
  non-zero `Offset` it skips that many users, in the same order, and the service sets no cursor.
- **The service does not trust the store's results blindly:** a result longer than the page size is
  truncated, as it already is, and a negative count is an error.
- **The store validates what it is given:** a negative offset, or a non-zero offset together with a
  cursor, is refused by the store with `ErrInvalidInput`, as the earlier offset method did, so a
  direct caller never reaches the database with them.
- **Why in `UserStore`:** an optional port existed only so that a consumer store written before this
  change kept compiling (D15). One listing method also removes the hazard of a store overriding
  `ListUsers` while an embedded offset method bypassed the override.
- **Superseded draft:** an optional `UserPager` port (`ListUsersFrom`, `CountUsers`), with offset and
  count refused as `ErrConfig` on a store without it. Dropped on 2026-11-28 with D15.
- **Accepted, embedding:** a consumer store that embeds a scrty store and overrides `ListUsers` (for
  example to scope users by tenant) inherits `CountUsers` unchanged, so counts skip the override. The
  godoc of `CountUsers` tells such consumers to override both.
- **Override:** none needed.

### D13: The SQL stores share one listing filter fragment

- `pgschema` splits `ListAdminUsers`'s `WHERE` filters into one fragment that two statements use:
  the listing (the cursor comparison as today, plus `OFFSET`, which is zero for a cursor listing) and
  the count (`SELECT count(*)`). One listing statement serves both modes, so their order cannot
  drift.
- **Why:** three copies of the filters would drift, and a count that disagrees with its list is the
  failure this part of the change can least afford.
- **Accepted:** the count scans the matching rows. A substring search already scans the users table
  for the listing (D16 of the archived design accepted that); the count costs the same. The caller's
  context deadline bounds it.
- **Default / override:** none; the statements are internal to scrty's stores.

### D14: The public conformance suite runs the offset and count cases against every store

- The offset and count cases in `admintest.RunUserSuite` run for every store. There is no skip.
- **Load-bearing proof:** `TestAdminSuiteIsLoadBearing` carries defects: an offset applied twice, a
  count that includes deleted users, and an offset listing in a different order from the cursor
  listing.
- **Default / override:** none; the suite is the contract every store is held to.

### D15: Every compatibility-only optional port folds into its base interface

- **Decision**, taken with the user on 2026-11-28: an optional port detected by a type assertion,
  which every scrty implementation provides and which exists only so that a consumer's own
  implementation keeps compiling, is folded into its base interface. Ports that some implementations
  genuinely cannot provide stay optional.
- **Why:** each such port is a second way to do one thing. It costs a type assertion, a fallback or a
  call-time refusal, wrappers that must forward it (or variant wrapper types), conformance gates that
  skip, and tests for the "absent" branch. The library's only consumer is the owner's application,
  so the compatibility these ports bought is not needed.
- **Folded:**

  | Port | Into | What goes away |
  |---|---|---|
  | `admin.UsernameUpdater`, `admin.UserPager` | `admin.UserStore` (D7, D12) | call-time `ErrConfig`, two `NewUsers` checks, conformance skips |
  | `session.FamilyReader`, `session.RoleSelector` | `session.Store` | the listing fallback, `roleSelectingEncryptedStore`, `Sessions.SelectsRoles` and its refusals |
  | `oidc.LinkLister`, `oidc.LinkRemover` | `oidc.LinkStore` | the broker's construction refusal, the freshness-check skip, conformance skips |
  | `mfa.DeviceProofStore` | `mfa.EnrolmentStore` | the seal variant `provingEnrolmentStore` (its sealing moves onto the one sealed store), the proof-store refusal |
  | `mfa.EnrolmentRemover` | `mfa.Method` | the recovery kind's construction refusal; `ResetDeps.Enrolments` takes `[]mfa.Method`; the kind re-reads enrolments after removing |
  | `ratelimit.RecentFailureReporter`, `ratelimit.PolicyReporter` | `ratelimit.Limiter` | the "cannot report" answers, the chain's warning and refusal for a limiter without a policy |
  | `password.Recognizer`, `password.Upgrader` | `password.Encoder` (embedded) | "an encoder that cannot report recognises everything" and "never upgrades" |
  | `lockout.FailureStreakStore` | a new `lockout.Store`, which embeds `policy.AttemptStore` and is what `lockout.New` takes | the cap's construction refusal; `policy.AttemptStore` and the chain's attempt view are unchanged |
  | `oidcprovider.PendingRequestCounter` | `oidcprovider.PendingRequestStore` | the ceiling's construction refusal and the "cannot count" refusal |
  | `recovery.UsableLister` | `recovery.AuthenticatorKind` | the fallback that counts every held authenticator as usable |

- **Kept optional (genuine capabilities), among them:** `authenticate.DecoyVerifier` and the
  `OffersDecoy` marker, `IdentifierResolver`, `password.InputLimiter`, `mfa.Enroller`,
  `mfa.ChallengeMethod`, the enrolment-path marker `SupportsEnrolmentPath` (below),
  `oidc.UpstreamBroker` and the relying party's provider-scoped, role-syncing and link-backed markers,
  `authorize.PrivilegeInspector`, `policy.UnreportedAttemptRecorder`, the policy engine's marker
  interfaces, `lockout.AttemptReaper` and `onetime.Reaper` (purging may be left to a database job),
  `identity.EmailLoader`, `logsample.Flusher`, `signingkey.LifetimeReporter`,
  `token.ConfirmingGenerator` and a verifier that also generates, `notify.NonBlocking`,
  `clock.Timed`. Each is either implemented by only some of scrty's own types, or describes a choice
  a consumer may legitimately not make.
- **How each non-mechanical point is settled:**
  - The streak methods fold into a new `lockout.Store`, which embeds `policy.AttemptStore` and adds
    `AddStreakFailure`, `FailureStreak` and `DeleteStreaksBefore`; `lockout.New` takes it.
    `policy.AttemptStore`, the attempt view `Policy.Attempts()` hands the chain, and
    `lockout.FailureStreak` stay where they are, so no holder of the view can advance or purge a
    streak behind the observer. Every store `lockout.New` is given carries the streak methods, even
    when its consumer never sets a cap. The policy still calls them only when a cap is set: the
    "cap is set" gate is the cap option, not the store's type. Decided with the user on 2026-11-28.
    Streak purging is part of the cap's retention contract and so required; attempt purging stays
    the optional `AttemptReaper`.
  - `mfa.Method` gains `RemoveEnrolment`, so every method, a consumer's email-code method included,
    implements it, and `mfa.ResetDeps.Enrolments` takes `[]mfa.Method`. Because a method that
    reports success without removing would leave an attacker's second factor in place, the recovery
    kind reads the user's enrolments again after removing and fails the reset when the method still
    holds one. Decided with the user on 2026-11-28.
  - `password.Recognizer` and `password.Upgrader` stay as named interfaces that `password.Encoder`
    embeds, so `admin.NewImporter` still asks only for recognition. They are no longer optional.
  - `internal/unavailable.Wrap` gains the limit and window it was built for as two fields and answers
    `Policy()` from them, also while its backend is down; its backend type stays narrow and
    internal.
  - `Sessions.SelectsRoles` would always answer true, so it is removed, with the refusals that
    consulted it.
  - `SupportsEnrolmentPath` stays. `policy` cannot import `authenticate/mfa` and matches it
    structurally, and the passkey MFA method reports it without being an `mfa.Enroller`. Only its
    dependence on the device-proof port goes: TOTP reports true whatever its store.
  - Folding into a wrapper keeps the wrapper's treatment: the encrypted session store's `SelectRole`
    keeps its fixed error text and sanitised cause, its `ListByFamily` opens rows, and the sealed MFA
    store seals the emailed code a device proof records.
  - Test-module helpers that exist only for an optional port (`storetest.RequireDeviceProof`,
    `RunDeviceProofSuite`, `DeviceProofEnrolmentStore`, and the `optionalCase` uses for device
    proofs, family reads and role selection) fold into the base suites, whose cases then always run.
    `optionalCase` stays for the reapers.
- **Behaviour changes a consumer sees:**
  - a consumer implementation of any folded base fails to compile until it adds the methods;
  - just-in-time provisioning always runs the link freshness check;
  - an encoder always answers recognition; a consumer encoder is no longer trusted with every
    non-empty hash;
  - a consumer encoder's upgrade report now drives a rehash at login, where it never upgraded before;
  - a flow given a consumer limiter now gets the default IPv6 aggregate from the policy that limiter
    reports, where it got none and a warning before;
  - the automation challenge trusts a consumer limiter's recent-failures answer, where such a limiter
    always counted as having failures before; an answer that fails still counts as failures;
  - a recovery reset fails when an MFA method reports a removal that did not happen.
- **Scenario names:** OpenSpec keeps a modified requirement's scenarios by name, so scenarios that
  described the case without the port ("Store cannot count", "Link store that cannot list", "Method
  without a remover", "Store that cannot record a device proof", "Store without consecutive counts",
  "A store that can only list", "Consumer limiter that reports no policy", "Explicit aggregate over a
  limiter that reports no policy") keep their names and now state how a consumer's implementation is
  served.
- **Compatibility:** these ports were released in v0.6.0, so this is a breaking change to released
  API (`library-design.md` rule 7). The owner accepted it; the CHANGELOG carries a BREAKING section
  naming each folded port and its migration.
- **Override:** none. The consumer implements the base interface.

## Failure modes

### Rename

| Failure | State | What the caller sees |
|---|---|---|
| Stale version | Handled, tested | `ErrStaleUpdate`, nothing written |
| Change naming only a username | Handled, tested | Accepted as a change, not "names no field" |
| Username blank, padded, too long, invalid UTF-8 or holding a control character (NUL included) | Handled, tested | `ErrInvalidInput`, store not called |
| Username held by another user, live or deleted | Handled, tested | `AlreadyExistsError{FieldUsername}`, no value in text |
| Username equals another live user's email, any case | Handled, tested | `AlreadyExistsError{FieldUsername}` |
| Update statement hits a unique violation despite the checks | Handled, tested (D2 two-statement write) | `AlreadyExistsError` naming the field that collided |
| Username and email set together, racing another writer | Handled, tested (barrier test, SQL stores) | At most one write succeeds |
| Rename to own email in the same change | Handled, tested | Succeeds |
| Username and email of one user equal ignoring case in the same change | Handled, tested | Succeeds, one lock taken |
| Case-only rename | Handled, tested | Succeeds, stored as given |
| Rename between Unicode normalisation forms | Handled, tested | Succeeds, bytes stored as given |
| Rename racing a deactivation | Handled, tested | The later write is `ErrStaleUpdate`; the deactivation stays |
| No actor | Handled, tested (existing `Update` tests; the rename takes the same path) | `ErrNoActor`, store not called |
| Store outage | Handled, tested (existing `Update` tests; the rename takes the same path) | Error matching no administration reason |
| A store's `UpdateUser` ignores the username or misreports `renamed` | Handled, tested (D8) | Its conformance run fails a named case |
| The commit fails after the store decided `renamed`, its outcome unknown | Accepted | The caller gets the store error and no revocation runs, though the rename may have committed; the caller reads the user again |
| A consumer store written before this change | Accepted (D15) | It fails to compile until `UpdateUser` takes the username and reports `renamed` |
| Lockout counts left under the old username | Accepted (D5) | The renamed account starts clean. The next holder of the old name inherits its counts until they age out |
| Lockout hold left under the old username | Accepted (D5) | The next holder of the old name is refused until a password change through the chain or the lockout `Reset`; the godoc tells administrators to call `Reset` on the old username |
| Session revocation fails after the rename committed | Handled, tested (D6) | The renamed user and `ErrSessionsNotRevoked` wrapping the cause; update committed, event emitted |
| Context cancelled after the store commits, before revocation | Handled, tested (D6) | `ErrSessionsNotRevoked` wrapping the context's error; update committed |
| Refused rename with a revoker configured | Handled, tested (D6) | Nothing revoked |
| Nil session revoker | Handled, tested (D6) | `NewUsers` fails with `ErrConfig` |
| A sign-in races the revocation | Accepted (D6) | A session created after the revocation was made with the new username and survives; one created before is deleted |
| Revocation enabled and the update names no username | Handled, tested (D6) | Nothing revoked |
| Revocation enabled and the update re-sends the current username | Handled, tested (D6) | The store reports no rename; nothing revoked |
| The update runs inside the caller's own transaction, which later rolls back | Accepted (D6) | The revoker ran when the store returned, so sessions are ended for a rename that was rolled back; the godoc tells such callers to revoke after their own commit |
| A re-sent current username clashes with another live user's email in data that already breaks the rule | Accepted (D2) | The no-op save is refused with `AlreadyExistsError{FieldUsername}`, as any write of that username would be |
| Old-username tokens at the `httpsec` bearer (username-subject mode) | Accepted | The next request with them is refused as unauthenticated; the user signs in again |
| Old-username tokens at the standalone `JWTAuthenticator` (username-subject mode) | Accepted | They keep authenticating under the old name until they expire; once another user takes that name, the principal's username names that other user. The godoc of `UserChange.Username` warns consumers of this mode to keep token lifetimes short or not to reuse released usernames |
| ID tokens already issued carry the old `preferred_username` | Accepted | Stale until the client next receives an ID token; `sub` is unchanged |
| Password context words include the old username | Accepted | The current password is not checked again; the new username applies from the next password change |
| Event or audit delivery lost after commit | Accepted (existing) | As for every administrative write (`admin` package documentation) |
| The session revoker panics | Accepted (D6) | The panic reaches the caller after the update committed and its event was emitted, as a panicking store does; the revoker is consumer code and is not recovered |
| The revoker's error itself wraps an administration reason (for example `ErrNotFound`) | Accepted (D6) | The error matches `ErrSessionsNotRevoked` and, through the wrapped cause, that reason too; the spec requires the cause to stay matchable, so `ErrSessionsNotRevoked` is checked first |
| The revoker's error text names the user | Accepted (D6) | The cause's text is passed through unchanged, as a store's error is; scrty adds no identifier, and the consumer's revoker owns its own text |

### Offset paging and counting

| Failure | State | What the caller sees |
|---|---|---|
| Negative offset | Handled, tested | `ErrInvalidInput`, store not called |
| Negative offset, or offset with a cursor, sent to a store directly | Handled, tested (D12) | The store refuses with `ErrInvalidInput`; the database is not queried |
| Non-zero offset with a cursor | Handled, tested | `ErrInvalidInput`, store not called |
| Offset above the maximum | Handled, tested | `ErrInvalidInput`, store not called; exactly the maximum is accepted |
| Offset past the last match | Handled, tested | Empty page, no error |
| Negative maximum offset | Handled, tested | `NewUsers` fails with `ErrConfig` |
| Consumer store embeds a scrty store and overrides `ListUsers` but not `CountUsers` | Accepted (D12) | Counts run the embedded method, bypassing the override; the godoc says to override both |
| A consumer store written before this change | Accepted (D15) | It fails to compile until it adds `CountUsers` and honours `UserQuery.Offset` |
| Store's offset order differs from its cursor order | Handled, tested (D14) | Its conformance run fails |
| Store counts deleted users | Handled, tested (D14) | Its conformance run fails |
| Store returns more rows than the page size from an offset listing | Handled, tested (D12) | Truncated to the page size, as for a cursor listing |
| Store returns a negative count | Handled, tested (D12) | Error matching no administration reason, never a negative total |
| Invalid search, role or attribute in a count | Handled, tested | `ErrInvalidInput`, as for `List` |
| Users added, removed or renamed between two offset pages | Accepted (D9) | A user may be listed twice or skipped across pages; no error. Cursor listing avoids it |
| Count and page read at different moments | Accepted (D10) | The count may differ from the page by the writes in between |
| Deep offset or broad count is slow | Handled (D11 bound) / Accepted (D13 count scan) | Offset bounded by the maximum; a count runs until the caller's deadline |
| Store outage during offset listing or count | Handled, tested | Error matching no administration reason |
| No actor | Not applicable | Listing and counting are reads; they need no actor, as `List` today |

### Folding the optional ports (D15)

| Failure | State | What the caller sees |
|---|---|---|
| A consumer implementation of a folded base interface | Accepted (D15) | Compile error naming the missing method; the BREAKING changelog entry gives the migration |
| A wrapper that embeds a folded base interface (for example `oidcprovider`'s session wrappers) | Handled, tested | The folded methods are promoted and forwarded; a wrapper no longer hides a family read or role selection |
| A wrapper that overrides one method of a folded base and inherits the folded one | Accepted (D15) | The inherited method bypasses the override, as for any embedding; godoc on each folded method names its siblings |
| A consumer implementation that stubs a folded method with zero values or no effect | Accepted (D15) | The library trusts it, as it trusts scrty's own; the effect per port is in the rows below. The public conformance suites catch it for a consumer who runs them |
| A consumer session store whose family read is wrong | Accepted (D15) | Sign-in state reads answer wrongly; the session store suite's family-read cases, which now always run, fail on such a store |
| A consumer session store whose `SelectRole` does nothing | Accepted (D15) | A role switch reports success and the session keeps its role; the role cases of the session suite fail on such a store |
| A consumer link store that cannot really list or remove | Accepted (D15) | The one-link rule and the freshness check act on what it reports; the link store suite, which now always runs its list and remove cases, fails on such a store |
| A consumer encoder that reports it recognises nothing | Handled, tested | Every stored hash is unusable; each login costs one reference verification and fails, as for an unknown user |
| A consumer encoder whose upgrade report is always true | Accepted (D15) | The password is re-encoded at every successful login, with the write cost that implies |
| A consumer limiter that reports an unusable policy | Handled, tested (existing) | Construction fails naming the flow |
| A consumer limiter whose reported policy differs from what it counts | Accepted (D15) | The aggregate is sized from the reported policy |
| A consumer limiter that answers "no recent failures" when it has some | Accepted (D15) | The verifier is not asked for those requests, as with a scrty limiter that loses its records |
| A limiter whose recent-failures answer fails | Handled, tested | The verifier is told the source has recent failures |
| The shared limiter's backend is down when its policy is asked | Handled, tested | It reports the limit and window it was built with |
| A consumer attempt store whose streak methods do nothing, with a cap set | Accepted (D15) | The cap never holds; the streak suite, which now always runs, fails on such a store. A policy without a cap never calls the streak methods |
| A consumer pending-request store that miscounts | Accepted (D15) | The ceiling trusts the count, as for scrty's stores; a negative count is already refused as a dependency failure |
| A consumer MFA method whose `RemoveEnrolment` fails | Handled, tested (existing) | The recovery reset returns the error |
| A consumer MFA method whose `RemoveEnrolment` reports success without removing | Handled, tested | The kind's re-read finds the enrolment and the reset returns an error |
| A consumer recovery kind that reports held authenticators as usable | Accepted (D15) | The "another way back in" check trusts the kind, as for scrty's kinds |
| A wrapper that seals or sanitises loses that treatment on a newly forwarded method | Handled, tested | The encrypted store's `SelectRole` keeps fixed error text, its `ListByFamily` opens rows, and the sealed MFA store seals the emailed code |

## Risks / Trade-offs

- [The old username is released and may be taken by another person] → The same as an import that
  changes a username today. The `httpsec` bearer refuses a token whose username now names a
  different user. The remaining exposure is lockout state (D5), including a hold that never
  expires, old-username tokens at the standalone `JWTAuthenticator` until they expire, and the
  consumer's own records keyed by username, which the godoc must call out.
- [Every consumer implementation of a folded port breaks] → Accepted by the owner (D15); the only
  consumer is their own application. The CHANGELOG's BREAKING section names each port and the
  methods to add.
- [The fold touches many packages at once] → It is split by area into lanes that each keep their
  package's tests green, and the conformance suites that now always run catch a store that does
  not honour a folded method.
- [Three SQL stores and the toy store must agree] → The store conformance suite in `test/admin`
  runs the rename, offset and count cases against every store, and `adminfix` gains the race and
  the unique-index collision.
- [Duplicated logic across the three SQL stores] → Not addressed here; a separate change explores
  sharing it.
- [Consumers may pick offset where the cursor would serve them better] → The godoc of
  `UserFilter.Offset` states the skip-or-repeat trade-off and names the cursor as the consistent
  choice.
- [A count on a very large table is slow] → Bounded only by the caller's context; stated in godoc.

## Migration Plan

No schema migration. `scrty_users.username` is already unique and writable, and the list order is
served by the existing index. Consumers replace any rename done by re-importing with `Users.Update`,
passing the version they read. Consumers who want numbered pages set `UserFilter.Offset` and call
`Users.Count`. Consumer implementations of every folded port (D15) add the folded methods; the
CHANGELOG's BREAKING section lists them.

## References

**Researched** (accessed 2026-11-28; read through a summarising fetch or search tool):

- D4:
  - [RFC 8265, PRECIS usernames](https://www.rfc-editor.org/rfc/rfc8265): §3.2 prefers the
    UsernameCaseMapped profile to avoid false accepts, and allows case preservation for backward
    compatibility.
  - [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/):
    "usernames in the server are always in lower-case".
  - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html):
    a user ID uniquely identifies a user. No case rule was found.
- D5:
  - [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html): failed attempts are limited
    per subscriber account. The wording comes from a tool summary and is unverified verbatim.
  - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html):
    the failure counter is associated with the account. The wording comes from a tool summary and
    is unverified verbatim.
- D6:
  - [Auth0 Management API, update a user](https://auth0.com/docs/api/management/v2/users/patch-users-by-id):
    the username is editable and separate from the stable `user_id`, with nothing on sessions.
- D9, D10, D11 (how established services page users):
  - [Keycloak `UsersResource` javadoc](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/services/resources/admin/UsersResource.html):
    offset paging by `first` and `max`, with a separate count endpoint over the same filters.
  - [Keycloak forum: paged reading of users gets progressively slower](https://forum.keycloak.org/t/paged-reading-of-users-via-get-realm-users-gets-progressively-slower/7447):
    a user report of deep pages slowing down; unverified, supports the D11 bound.
  - [Auth0: view search results by page](https://auth0.com/docs/manage-users/user-search/view-search-results-by-page):
    page-number paging with at most 1 000 results reachable.
  - [Auth0 Management API: get users](https://auth0.com/docs/api/management/v2/users/get-users):
    `page`, `per_page` and `include_totals`.
  - [Okta dev forum: paging and the next link](https://devforum.okta.com/t/okta-paging-and-the-next-link/3391):
    cursor-only paging with no total, the shape scrty has today.

**Primary documentation:**

- D11, D13: [PostgreSQL, LIMIT and OFFSET](https://www.postgresql.org/docs/current/queries-limit.html):
  the rows an `OFFSET` skips are still computed, so a large offset is inefficient.

D15, and the revised D7, D8, D12 and D14, are reasoned from scrty's own settled specs and code: a
survey of every optional port, its implementations and its fallbacks, taken on 2026-11-28.

D1 to D3, and D5's description of holds and `Reset`, are reasoned from scrty's
own settled specs (`security-administration`, `sessions`, `authentication`), the archived
`security-administration` design, its code (the `policy/lockout` package documentation, the
`admintest` suite), and the project's library-design and defensive-coding rules. The established
design has neither a username rename nor a user listing. The consumer's brief requested both
changes and set out the rename's risks.
