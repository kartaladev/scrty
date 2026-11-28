# Design

## Context

See proposal.md for why. D1 to D3 were proposed with the draft. D4 to D7 were decided with the user on 2026-11-28,
after research and after rebasing onto current `main`. A re-audit on the same day corrected D5's
description of lockout holds, settled when D6's revocation runs, and added D8. Offset paging and
counting (D9 to D14) were decided with the user the same day and folded into this change, which was
renamed from `admin-username-change`.

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
- Consumer stores keep compiling and keep passing the conformance suite.

**Non-Goals:**

- Changing how usernames are compared anywhere else.
- Moving or keying any security state (sessions, lockout, MFA, passkeys) by something other than
  what keys it today.
- A dedicated rename endpoint or page. Administration stays a set of services.
- Consistent paging across pages in offset mode, a previous-page cursor, or a total inside
  `UserPage`.
- Changing the list order, the filters or the page-size bounds.

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
  reports it (D7: `UpdateUserRenaming`'s `renamed` result, decided under the row lock by the
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
  (under a savepoint). Then `UpdateUserRenaming` returns before anything commits, the revoker runs,
  and a later rollback by the caller leaves the sessions ended for a rename that never happened.
  The `WithSessionRevocation` godoc says so: a caller that wraps updates in its own transaction
  revokes sessions itself, after its commit, instead of using the option.
- **Error wrapping, not cancellation-proofing:** the revoker runs on the caller's context. A context
  cancelled after the store commits makes the revoker fail, which is reported as any revoker
  failure (`ErrSessionsNotRevoked` wrapping the context's error). Running it detached from
  cancellation would need its own bound; not done, because the caller can retry with the returned
  error.
- **Wiring:** a nil revoker, typed-nil included, fails `NewUsers` with an error matching
  `ErrConfig`. So does a revoker given with a store that does not implement `UsernameUpdater`
  (D7): that store can never rename, so the option could never take effect
  (`library-design.md` rule 6).
- **Not covered:** grants the OpenID Provider issued are not revoked by this option. They are keyed
  by the user identifier and are unaffected by a rename.
- **Sources:** none of the sources read says a rename must end sessions. Auth0's user update treats
  the username as an editable field separate from the stable `user_id`, and says nothing of
  sessions. This is therefore the consumer's policy, offered as an option.

### D7: Renames go through an optional store method that also reports the change

A `UserStore` written before this change still compiles. Handing it a `UserChange` with a username
through `UpdateUser` would let it ignore the field and report success. So a rename never reaches
`UpdateUser`.

- **The port:**

  ```go
  type UsernameUpdater interface {
      // UpdateUserRenaming applies change, which names a username, as
      // UpdateUser applies its other fields, in one write under the same
      // version check, and also writes the username under the rules of
      // creation. renamed reports whether the stored username differed
      // from the named one, byte for byte, decided under the row lock.
      UpdateUserRenaming(ctx context.Context, id identity.UserID, version int64,
          change UserChange) (updated User, renamed bool, err error)
  }
  ```

  `NewUsers` records whether the store implements it. `Update` sends a change naming a username to
  `UpdateUserRenaming`, and every other change to `UpdateUser`, as today. When the store does not
  implement it, `Update` refuses a change naming a username with an error matching `ErrConfig`,
  before calling the store (the audit read included), so nothing is written. Every store scrty
  ships (`sqlstore`, `pgxstore`, `gormstore`) implements it, and so do the test-only toy store and
  the package example's store.
- **`UpdateUser`'s contract does not change.** It never receives a username, so a consumer store
  that never renames needs no change at all. This is an addition, not a breaking change: no call
  that worked before fails now, and a rename is a new call.
- **Why a method, not a marker:** a marker only promises that `UpdateUser` reads the field, and the
  service cannot check the promise. A method either exists or does not, and it carries the
  `renamed` result D6 needs, which `UpdateUser`'s signature cannot carry without breaking every
  consumer store.
- **Why this option:**
  - Checking after the write reports an inconsistency only once the other fields are committed.
  - A changelog entry alone leaves the guarantee resting on documentation.
  - Refusing at construction would break every consumer store, including those that never rename.
  - So the refusal happens at the first update that names a username, documented in godoc and the
    CHANGELOG.
- **Departure from "wiring mistakes fail at construction"** (`library-design.md` rule 6): a store
  without the method is not a wiring mistake until it is asked to rename, so the refusal comes at
  call time. Options that could never take effect on such a store are still refused at construction
  (D6, D11). `ErrConfig`'s godoc, which today says only constructors return it, is updated to name
  the call-time cases (this one and D12's), and the settled error-reasons requirement is modified to
  list them.
- **Order of refusals:** input validation first (`ErrInvalidInput`), then the store capability
  (`ErrConfig`), as everywhere in `admin`.
- **Accepted, embedding:** a consumer store that embeds a scrty store and overrides `UpdateUser`
  (for example to add its own checks) inherits `UpdateUserRenaming` unchanged, so renames bypass the
  override. The godoc of `UsernameUpdater` and the CHANGELOG tell such consumers to override
  `UpdateUserRenaming` too.
- **Override:** a consumer store opts in by implementing `UpdateUserRenaming`.

### D8: The public conformance suite runs rename cases only for stores that support renames

- **Decision:** the rename cases in `admintest.RunUserSuite`, and "Import after a rename" in
  `RunImportSuite`, run only when the fixture's user store implements `UsernameUpdater`. For a store
  that does not, they are skipped with a message naming the port, and the rest of the suite runs as
  before.
- **Why:** consumers run the suite against their own stores. Making the cases mandatory would turn
  every consumer suite red on upgrade, including stores whose owners never rename, which D7 was
  designed to leave working.
- **Implementing the method is not proof:** a store that implements it runs every rename case, so a
  store whose method ignores the username, or misreports `renamed`, fails a named case.
- **Load-bearing proof:** `TestAdminSuiteIsLoadBearing` gains a variant (a store without the method
  passes, with the rename cases skipped) and defects (a method that ignores the username; one that
  skips the username clash checks; one that always reports `renamed` as false), each caught by a
  named case.
- **Store-only races stay out of the public suite:** the barrier race and the unique-index
  collision live in `test/internal/adminfix`, which runs only against scrty's SQL stores.
- **Override:** none needed; a consumer opts in by implementing the method.

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
  `ErrConfig`. `n` of zero allows only the first page. Given with a store that does not implement
  `UserPager` (D12), it fails `NewUsers` with `ErrConfig`: the option could never take effect
  (`library-design.md` rule 6).
- A consumer whose list is larger narrows it with filters, or uses the cursor, which has no depth
  cost.

### D12: Offset and count are an optional store capability

```go
type UserPager interface {
    // ListUsersFrom returns up to query.Limit users matching query, in the
    // order of ListUsers, after skipping offset of them. query names no
    // cursor. An offset past the last match is an empty result.
    ListUsersFrom(ctx context.Context, query UserQuery, offset int) ([]User, error)

    // CountUsers returns the number of live users matching query's
    // filters. query.Limit and the cursor fields are ignored.
    CountUsers(ctx context.Context, query UserQuery) (int64, error)
}
```

- `NewUsers` records whether the store implements it. A listing with a non-zero offset, and every
  `Count`, is refused with an error matching `ErrConfig` before the store is called when it does not.
  Every store scrty ships implements it.
- **The service does not trust the port's results blindly:** a `ListUsersFrom` result longer than the
  page size is truncated, as `ListUsers` results already are, and a negative count is an error.
- **Why methods, not a field on `UserQuery`:** a consumer store written before this change would
  ignore a new `Offset` field and return the first page as if it were page 7: a silent wrong answer.
  New methods cannot be ignored: a store either has them or it does not. Counting is a new operation
  anyway.
- **Why not on `UserStore`:** adding methods to `UserStore` breaks every consumer store at compile
  time, including those that never page by offset.
- **Call-time `ErrConfig`:** the same departure from "wiring mistakes fail at construction" as D7,
  for the same reason, with the same order: input validation first (`ErrInvalidInput`), then the
  capability (`ErrConfig`). An offset above the maximum on a store without `UserPager` is therefore
  `ErrInvalidInput`.
- **Accepted, embedding:** a consumer store that embeds a scrty store and overrides `ListUsers` (for
  example to scope users by tenant) inherits `ListUsersFrom` and `CountUsers` unchanged, so offset
  pages and counts skip the override. The godoc of `UserPager` and the CHANGELOG tell such consumers
  to override both methods too.
- **Override:** a consumer store opts in by implementing `UserPager`.

### D13: The SQL stores share one listing filter fragment

- `pgschema` splits `ListAdminUsers`'s `WHERE` filters into one fragment that three statements use:
  the cursor listing (unchanged in effect), the offset listing (same order, `LIMIT` and `OFFSET`, no
  cursor comparison), and the count (`SELECT count(*)`).
- **Why:** three copies of the filters would drift, and a count that disagrees with its list is the
  failure this part of the change can least afford.
- **Accepted:** the count scans the matching rows. A substring search already scans the users table
  for the listing (D16 of the archived design accepted that); the count costs the same. The caller's
  context deadline bounds it.

### D14: The public conformance suite runs offset and count cases only for stores that support them

- The offset and count cases in `admintest.RunUserSuite` run when the fixture's store implements
  `UserPager`, and are skipped with a message naming it otherwise, as D8 does for renames.
- **Load-bearing proof:** `TestAdminSuiteIsLoadBearing` gains a variant without `UserPager` (passes,
  cases skipped) and defects: an offset applied twice, a count that includes deleted users, and an
  offset listing in a different order from the cursor listing.

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
| Consumer store without `UsernameUpdater` is asked to rename | Handled, tested (D7) | `ErrConfig` before the store is called, nothing written |
| Consumer store's `UpdateUserRenaming` ignores the username or misreports `renamed` | Handled, tested (D8) | Its conformance run fails a named case |
| Consumer store without `UsernameUpdater` runs the public suite | Handled, tested (D8) | Rename cases and "Import after a rename" skipped with a message; the rest passes |
| Consumer store embeds a scrty store and overrides `UpdateUser` only | Accepted (D7) | Renames run the embedded `UpdateUserRenaming`, bypassing the override; godoc and CHANGELOG say to override it too |
| Session revoker given with a store without `UsernameUpdater` | Handled, tested (D6) | `NewUsers` fails with `ErrConfig` |
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
| A consumer store without `UsernameUpdater` gets a profile save that re-sends the current username | Accepted (D7) | `ErrConfig`, though the username is unchanged; the godoc tells callers on such stores to leave `Username` nil unless it changed |
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
| Non-zero offset with a cursor | Handled, tested | `ErrInvalidInput`, store not called |
| Offset above the maximum | Handled, tested | `ErrInvalidInput`, store not called; exactly the maximum is accepted |
| Offset past the last match | Handled, tested | Empty page, no error |
| Negative maximum offset | Handled, tested | `NewUsers` fails with `ErrConfig` |
| Consumer store without `UserPager`, offset or count asked | Handled, tested (D12) | `ErrConfig`, store not called |
| Consumer store without `UserPager`, cursor listing or offset zero | Handled, tested | Unchanged |
| `WithMaxListOffset` given with a store without `UserPager` | Handled, tested (D11) | `NewUsers` fails with `ErrConfig` |
| Offset above the maximum on a store without `UserPager` | Handled, tested (D12) | `ErrInvalidInput` (validation before capability) |
| Consumer store embeds a scrty store and overrides `ListUsers` only | Accepted (D12) | Offset pages and counts run the embedded methods, bypassing the override; godoc and CHANGELOG say to override them too |
| Consumer store without `UserPager` runs the public suite | Handled, tested (D14) | Offset and count cases skipped with a message |
| Store's offset order differs from its cursor order | Handled, tested (D14) | Its conformance run fails |
| Store counts deleted users | Handled, tested (D14) | Its conformance run fails |
| Store returns more rows than the page size from `ListUsersFrom` | Handled, tested (D12) | Truncated to the page size, as for `ListUsers` |
| Store returns a negative count | Handled, tested (D12) | Error matching no administration reason, never a negative total |
| Invalid search, role or attribute in a count | Handled, tested | `ErrInvalidInput`, as for `List` |
| Users added, removed or renamed between two offset pages | Accepted (D9) | A user may be listed twice or skipped across pages; no error. Cursor listing avoids it |
| Count and page read at different moments | Accepted (D10) | The count may differ from the page by the writes in between |
| Deep offset or broad count is slow | Handled (D11 bound) / Accepted (D13 count scan) | Offset bounded by the maximum; a count runs until the caller's deadline |
| Store outage during offset listing or count | Handled, tested | Error matching no administration reason |
| No actor | Not applicable | Listing and counting are reads; they need no actor, as `List` today |

## Risks / Trade-offs

- [The old username is released and may be taken by another person] → The same as an import that
  changes a username today. The `httpsec` bearer refuses a token whose username now names a
  different user. The remaining exposure is lockout state (D5), including a hold that never
  expires, old-username tokens at the standalone `JWTAuthenticator` until they expire, and the
  consumer's own records keyed by username, which the godoc must call out.
- [Consumer stores gain nothing until they opt in] → `UserStore` itself is unchanged; renames,
  offsets and counts need the optional ports, are refused with `ErrConfig` without them, and D8 and
  D14 keep consumers' conformance runs green.
- [Three SQL stores and the toy store must agree] → The store conformance suite in `test/admin`
  gains rename, offset and count cases that every store implementing the matching port runs, and `adminfix` gains the
  race and the unique-index collision.
- [A call-time `ErrConfig`] → Departs from construction-time wiring errors; stated in D7 and D12 and
  in the modified error-reasons requirement.
- [Consumers may pick offset where the cursor would serve them better] → The godoc of
  `UserFilter.Offset` states the skip-or-repeat trade-off and names the cursor as the consistent
  choice.
- [A count on a very large table is slow] → Bounded only by the caller's context; stated in godoc.

## Migration Plan

No schema migration. `scrty_users.username` is already unique and writable, and the list order is
served by the existing index. Consumers replace any rename done by re-importing with `Users.Update`,
passing the version they read. Consumers who want numbered pages set `UserFilter.Offset` and call
`Users.Count`. Consumer stores implement `UsernameUpdater` and `UserPager` to support them.

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

D1 to D3, D7, D8, D12 and D14, and D5's description of holds and `Reset`, are reasoned from scrty's
own settled specs (`security-administration`, `sessions`, `authentication`), the archived
`security-administration` design, its code (the `policy/lockout` package documentation, the
`admintest` suite), and the project's library-design and defensive-coding rules. The established
design has neither a username rename nor a user listing. The consumer's brief requested both
changes and set out the rename's risks.
