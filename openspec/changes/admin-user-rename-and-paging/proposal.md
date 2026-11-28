# Proposal

## Why

Two gaps in `admin.Users` block a consumer's user administration screens.

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

## What Changes

**Rename through `Users.Update`:**

- `admin.UserChange` gains `Username *string`. `Users.Update` sends a change naming it to a new
  optional store method, `UsernameUpdater.UpdateUserRenaming`, which applies it with the other
  fields under one version check, so a username and an email change together in one call and one
  write. It also reports whether the stored username actually changed. `UserStore.UpdateUser` is
  unchanged and never receives a username.
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
  rename stays committed and its event is emitted. Given with a store that cannot rename, the
  option fails construction.
- **Consumer stores:** nothing that works today stops working. A consumer store without
  `UsernameUpdater` has a rename refused with `ErrConfig` before anything is written; its other
  updates are unaffected, and the public store conformance suite skips its rename cases.
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
  `WithMaxListOffset`. It bounds the cost of a deep offset scan. Given with a store without offset
  support, the option fails construction.
- An offset of zero is the first page of the default listing and carries its cursor as today; a
  page from a non-zero offset carries none.
- Offset and count are an optional store capability, `admin.UserPager`. Every store scrty ships
  implements it. On a consumer store that does not, a listing with a non-zero offset and every count
  are refused with `ErrConfig` before the store is called; cursor listing is unaffected, and the
  conformance suite skips the offset and count cases.
- The cursor listing, its order and its page-size bounds do not change.

Not in this change:

- a separate `Users.Rename` operation: it could not change the email in the same write;
- case-insensitive username uniqueness: usernames stay compared exactly, as everywhere else. It is a
  follow-up (`username-case-folding`);
- moving or clearing lockout state on rename. It is a follow-up (`lockout-by-user-id`);
- a previous-page cursor, a total inside `UserPage`, or consistent (snapshot) paging across pages in
  offset mode.

Decided on 2026-11-28: D4 to D14 in `design.md`.

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

## Impact

- `admin`: `UserChange`, `UserFilter`, `UserPage.Next`'s godoc, `Users.Update`, `Users.List`, the
  new `Users.Count`, `validateChange`, `changedUserFields`, the `UsernameUpdater` and `UserPager`
  ports, `WithSessionRevocation` with its `SessionRevoker` port and `ErrSessionsNotRevoked`,
  `WithMaxListOffset` and `DefaultMaxListOffset`, `ErrConfig`'s godoc, and package documentation.
  `*session.Sessions` satisfies the revoker port as it is.
- `internal/pgschema`: a new `RenameAdminUser` statement that writes the username alone and reports
  whether it changed; the listing filters become one fragment shared by the cursor listing, a new
  offset listing and a new count.
- `store/pgxstore`, `store/gormstore`, `store/sqlstore`: each store implements `UsernameUpdater` and
  `UserPager`. `UpdateUserRenaming` takes the identifier locks for the new username, checks it with
  the queries the import path already uses (`UsernameTaken`, `EmailHeldByLiveUser`,
  `UsernameHeldByLiveUser`), and writes it alone before the other fields, as import does, so a
  unique violation names the field that collided.
- `test/admin` public conformance suite and its toy store: rename, offset and count cases for every
  store that implements the matching port, skipped for one that does not, with load-bearing
  defects. `test/internal/adminfix`: the barrier race and the unique-index collision on the SQL
  stores.
- No schema migration: `scrty_users.username` is already unique and writable, and the list order is
  served by the existing `lower(username)` index.
- `CHANGELOG.md`: the additions, with a warning for consumer stores that embed a scrty store.
- Consumers: a rename becomes `Users.Update` with `Username` (and `Email`), conditional on the
  version they read; a conflict is the stale-update error instead of a silent overwrite. A numbered
  page is `List` with `Offset`, beside `Count` for the total.
