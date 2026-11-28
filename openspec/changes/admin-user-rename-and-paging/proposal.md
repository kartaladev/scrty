# Proposal

## Why

Two gaps in `admin.Users` block a consumer's user administration screens, and closing them showed a
third problem across the library.

**A username cannot be changed.** `UserChange` names the display name, email, verification time,
attributes and organization, but not the username, so the only scrty write that sets one is
`admin.Importer.Import`, which is meant for syncing users from another system.

A consumer whose usernames are email addresses has to change the username whenever the email
changes: on a profile edit, an administrator's edit, or an email-change confirmation. Its only route
today is to read the user and re-import the whole record. That write:

- compares no version, so it overwrites a change made between the read and the import, including
  a deactivation, which it can undo;
- is reported as `UserImported`, not `UserUpdated`, so the audit trail shows a sync run and no
  changed fields;
- skips the checks an update makes, and relies on the caller passing back the password hash and
  role order unchanged, so a caller's mistake corrupts the user instead of being refused.

These risks follow from the import contract. They have not been reproduced against the consumer's
code (UNREPRODUCED: the code is outside this repository).

**The user list cannot be paged by number.** `Users.List` pages only by an opaque cursor. A caller
can move to the next page and nothing else: it cannot jump to page 7, and it cannot learn how many
users match. The consumer's screen needs "10 of 999 records shown" and a link to any page.

The cursor was chosen on purpose (decision D16 of the archived `security-administration` design):
offset paging skips or repeats users when the list changes between pages. That remains true, and a
rename now makes the list change more often. So the cursor stays the default, and offset paging and
a count are added beside it for consumers who accept that trade-off.

**Optional ports duplicate the library's contracts.** About a dozen ports are optional only so that a
consumer's own implementation keeps compiling, although every scrty implementation provides them:
renames and paging would have added two more. Each costs a type assertion, a fallback or a call-time
refusal, wrappers that must forward it, and conformance gates that skip. The library's only consumer
is the owner's own application, so the owner waived that compatibility on 2026-11-28: one thing is
maintained in one place.

## What Changes

**Rename through `Users.Update`:**

- `admin.UserChange` gains `Username *string`. `UserStore.UpdateUser` applies it with the other
  fields under one version check, so a username and an email change together in one call and one
  write, and now also reports whether the stored username actually changed.
- A new username is validated as `Users.Create` validates one (`exactName`).
- A new username is refused with the already-exists error naming the username when another user
  holds it, deleted or not, compared exactly, or when it equals another live user's email ignoring
  case. These are the rules Create already applies. A user may take a username equal to their own
  email, including the email named in the same change.
- The user-updated event and the audit record list `username` among the changed fields. Error text
  never contains the username.
- A rename leaves the old username free for another user to take, as an import that changes a
  username already does. Sessions, refresh families and OIDC `sub` are keyed by the user identifier
  and are not touched. In username-subject token mode, the standalone JWT authenticator keeps
  accepting old-username tokens until they expire; this is accepted and documented.
- **Opt-in session revocation:** `WithSessionRevocation` ends every session of the user after an
  update that changed the username commits; re-sending the current username revokes nothing. It is
  off by default. A failed revocation returns the renamed user with `ErrSessionsNotRevoked`; the
  rename stays committed and its event is emitted.
- Lockout state stays under the old username. This is accepted and documented, with re-keying by
  user identifier left as a follow-up. A hold on the old username never expires, so the godoc tells
  administrators to call the lockout policy's `Reset` on the old username after a rename.

**Offset paging and counting:**

- `admin.UserFilter` gains `Offset int`: skip that many users, in the list's order, before the page
  starts. A non-zero offset cannot be combined with `Cursor`. A negative offset, or one above the maximum, is
  refused with `ErrInvalidInput`. An offset past the last user gives an empty page.
- `admin.Users` gains `Count(ctx, filter) (int64, error)`: the number of live users matching the
  filter's search, active, role and attribute criteria. Its paging fields are ignored, so the filter
  a page was listed with can be counted as it is.
- The maximum offset defaults to `DefaultMaxListOffset` (10 000) and is set with
  `WithMaxListOffset`. It bounds the cost of a deep offset scan.
- An offset of zero is the first page of the default listing and carries its cursor as today; a
  page from a non-zero offset carries none.
- `UserQuery` gains `Offset`, which `UserStore.ListUsers` honours, and `UserStore` gains
  `CountUsers`.
- The cursor listing, its order and its page-size bounds do not change.

**Optional ports fold into their base interfaces (BREAKING for consumer implementations):**

- `session.FamilyReader` and `session.RoleSelector` into `session.Store`; `oidc.LinkLister` and
  `oidc.LinkRemover` into `oidc.LinkStore`; `mfa.DeviceProofStore` into `mfa.EnrolmentStore`;
  `mfa.EnrolmentRemover` into `mfa.Method`; `ratelimit.RecentFailureReporter` and
  `ratelimit.PolicyReporter` into `ratelimit.Limiter`; `password.Recognizer` and `password.Upgrader`
  into `password.Encoder`; `lockout.FailureStreakStore` into `policy.AttemptStore`;
  `oidcprovider.PendingRequestCounter` into `oidcprovider.PendingRequestStore`;
  `recovery.UsableLister` into `recovery.AuthenticatorKind`.
- Their fallbacks, construction refusals, forwarding wrappers and conformance skips go, and so do
  `Sessions.SelectsRoles` and `mfa.Enroller.SupportsEnrolmentPath`, which would always answer true.
- Ports some implementations genuinely cannot provide stay optional (design D15 lists them).

Not in this change:

- a separate `Users.Rename` operation: it could not change the email in the same write;
- case-insensitive username uniqueness: usernames stay compared exactly, as everywhere else. It is a
  follow-up (`username-case-folding`);
- moving or clearing lockout state on rename. It is a follow-up (`lockout-by-user-id`);
- a previous-page cursor, a total inside `UserPage`, or consistent (snapshot) paging across pages in
  offset mode;
- sharing the logic the three SQL stores each write out; a separate change explores it.

Decided on 2026-11-28: D4 to D15 in `design.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-administration`:
  - updates may change the username, under the version check and the uniqueness rules of creation;
    the update event names the username field;
  - listing users may page by offset as well as by cursor, and matching users can be counted;
  - the error-reasons requirement gains the configuration reason (rename or offset asked of a store
    without support) and the sessions-not-revoked reason;
  - the event requirement says a committed change keeps its event when a follow-up step fails.
- `sessions`, `identity-linking`, `multi-factor-auth`, `account-recovery`, `http-security-chain`,
  `authentication`, `password-encoding`, `security-policy`, `oidc-provider-authorization`: what used
  to be optional for a store, limiter, encoder, method or kind becomes required, and the refusals and
  fallbacks for implementations without it are removed.

## Impact

- `admin`: `UserChange`, `UserFilter`, `UserQuery.Offset`, `UserPage.Next`'s godoc, `Users.Update`,
  `Users.List`, the new `Users.Count`, `validateChange`, `changedUserFields`, `UserStore`
  (`UpdateUser` reports `renamed`; `CountUsers`), `WithSessionRevocation` with its `SessionRevoker`
  port and `ErrSessionsNotRevoked`, `WithMaxListOffset` and `DefaultMaxListOffset`, and package
  documentation. `*session.Sessions` satisfies the revoker port as it is.
- `internal/pgschema`: a new `RenameAdminUser` statement that writes the username alone and reports
  whether it changed; the listing filters become one fragment shared by the listing (cursor or
  offset) and a new count.
- `store/pgxstore`, `store/gormstore`, `store/sqlstore`: `UpdateUser` takes the identifier locks for a
  new username, checks it with the queries the import path already uses, and writes it alone before
  the other fields, so a unique violation names the field that collided; `ListUsers` honours the
  offset; `CountUsers` is new. Each store also gains the folded methods it already had as optional
  ports, now required.
- `session`, `authenticate/oidc`, `authenticate/mfa`, `authenticate/passkey`, `ratelimit` (and
  `ratelimit/redisstore`, `internal/unavailable`, `internal/pglimiter`), `authenticate/password`,
  `authenticate`, `policy`, `policy/lockout`, `oidcprovider`, `recovery`, `store/seal`, `httpsec`:
  the folds of D15, their removed fallbacks and wrappers, and regenerated mocks.
- `test` module: the rename, offset and count cases run against every store, with load-bearing
  defects; the conformance suites of the folded ports drop their skips and optional cases;
  `test/internal/adminfix` gains the barrier race and the unique-index collision.
- No schema migration: `scrty_users.username` is already unique and writable, and the list order is
  served by the existing `lower(username)` index.
- `CHANGELOG.md` and `README.md`: the additions, and a BREAKING section naming each folded port and
  the methods a consumer implementation adds.
- Consumers: a rename becomes `Users.Update` with `Username` (and `Email`), conditional on the
  version they read. A numbered page is `List` with `Offset`, beside `Count` for the total. Their own
  implementations of every folded port add the folded methods.
