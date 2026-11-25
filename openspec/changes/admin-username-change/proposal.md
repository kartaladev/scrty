# Proposal

## Why

`admin.Users` cannot change a username. `UserChange` names the display name, email, verification
time, attributes and organization, but not the username, so the only scrty write that sets one is
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

## What Changes

- `admin.UserChange` gains `Username *string`. `Users.Update` and `UserStore.UpdateUser` apply it
  under the same version check as every other field, so a username and an email change together in
  one call and one write.
- A new username is validated as `Users.Create` validates one: no surrounding white space, the
  `MaxTextBytes` bound.
- A new username is refused with the already-exists error naming the username when another user
  holds it, deleted or not, compared exactly, or when it equals another live user's email ignoring
  case. These are the rules Create already applies. A user may take a username equal to their own
  email, including the email named in the same change.
- The user-updated event and the audit record list `username` among the changed fields. Error text
  never contains the username.
- A rename leaves the old username free for another user to take, as an import that changes a
  username already does. Sessions, refresh families and OIDC `sub` are keyed by the user identifier
  and are not touched.
- **BREAKING** for consumers who implement `admin.UserStore` themselves: `UpdateUser` must apply
  the new field. A store that ignores it would report a rename that did not happen; how scrty
  guards against that is an open decision in `design.md`.

Not in this change:

- a separate `Users.Rename` operation: it could not change the email in the same write;
- case-insensitive username uniqueness: usernames stay compared exactly, as everywhere else;
- ending a user's sessions on rename inside `admin`: the services are built from their store alone.

Open decisions (see `design.md`): the username comparison rule, what happens to lockout state keyed
by the old username, the default for sessions after a rename, and the guard against a consumer store
that ignores the field.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-administration`: updates may change the username, under the version check and the
  uniqueness rules of creation; the update event names the username field.

## Impact

- `admin`: `UserChange`, `Users.Update`, `validateChange`, `changedUserFields`, the `UserStore`
  contract and package documentation.
- `store/pgxstore`, `store/gormstore`, `store/sqlstore`, `internal/pgschema`: `UpdateUser` takes the
  identifier locks for the new username and checks it with the queries the import path already
  uses (`UsernameTaken`, `EmailHeldByLiveUser`, `UsernameHeldByLiveUser`).
- `test/admin` conformance suites and the in-memory store in `test/`: rename cases for every store.
- No schema migration: `scrty_users.username` is already unique and writable.
- `CHANGELOG.md`: the `UserStore` contract change.
- Consumers: a rename becomes `Users.Update` with `Username` (and `Email`), conditional on the
  version they read. A conflict is the stale-update error instead of a silent overwrite.
