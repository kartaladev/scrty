# Design

## Context

See proposal.md for why. This change is a draft: decisions D1 to D3 are proposed, and D4 to D7 are
**pending**, to be discussed again with the user before `tasks.md` is written. Nothing here has been
accepted yet.

What the code already gives a rename:

- **The update path.** `Users.Update` takes the actor, checks the identifier and version, validates
  the change, reads the audit "before" record conditional on the version, calls
  `UserStore.UpdateUser`, and reports `event.UserUpdated` with the names of the changed fields
  (`changedUserFields`). The store compares the version under the user's row lock.
- **The identifier guards.** Every scrty store write that sets a username or an email takes one
  transaction-scoped advisory lock per distinct value, keyed by `lower(value)` and taken in
  ascending key order (`IdentifierLockKeys`, `LockIdentifierKey`). It then checks the queries that
  exclude the user being written: `UsernameTaken` (exact, deleted users included),
  `EmailHeldByLiveUser` and `UsernameHeldByLiveUser` (both ignoring case, live users only). Import
  already changes usernames this way (`SetImportedUsername`), so the store already does the
  locking and checks a rename needs.
- **The username's reach.** Sessions and refresh families record the user identifier, not the
  username (`session.Session.UserID`). The OIDC provider's `sub` is always the identifier. The token
  subject is the identifier by default. Only the username-subject modes
  (`token.WithUsernameSubject`, `httpsec.WithBearerUsernameSubject`,
  `authenticate.WithJWTUsernameSubject`) put the username in a token. In those modes a token naming
  an old username no longer loads, and a session whose recorded user differs from the user its
  token names is refused (`ownsSession`). Lockout failure counts and holds are keyed by the username
  (`policy/lockout`), and login by email keys them on the resolved account's username too.

## Goals / Non-Goals

**Goals:**

- A username and an email change in one call, one version check and one write.
- A rename is refused for exactly the reasons a creation is.
- The event and the audit record report a rename as an update with the field `username`.
- Importing users keeps working unchanged.

**Non-Goals:**

- Changing how usernames are compared anywhere else.
- Moving or keying any security state (sessions, lockout, MFA, passkeys) by something other than
  what keys it today.
- A dedicated rename endpoint or page. Administration stays a set of services.

## Decisions

### D1 (proposed): A field on `UserChange`, not a `Users.Rename` operation

`UserChange` gains `Username *string`. A nil username is unchanged, like every other field.

- **Why:** a consumer whose usernames are emails must change both in one write. A
  `Rename(ctx, id, version, username)` can change only the username, so the email would need a
  second write and a second version check. That brings back the half-applied state this change
  removes.
- **Alternative:** `Rename` that also takes an optional email. It duplicates `Update`'s email rules
  and leaves two ways to change an email.
- **Default / override:** no configuration. A consumer who wants renames to be a separate
  operation in their application gates the field at their own route.

### D2 (proposed): A rename is validated and checked as a creation is

- The service refuses a username with surrounding white space or longer than `MaxTextBytes`
  (`exactName`), as `Create` does, with `ErrInvalidInput`.
- The store refuses, as an `AlreadyExistsError` with `FieldUsername`, a username another user
  holds, deleted or not, compared exactly, and a username equal to another live user's email,
  ignoring case. Both checks exclude the user being renamed. A user may therefore:
  - change only the case of their username;
  - take a username equal to their own email, including an email the same change sets.
- A change naming both a username and an email locks both values before checking either, in key
  order, so a racing creation or update cannot slip a clashing pair between the checks.
- Renaming to the current username, byte for byte, is still a write: the version increases and the
  field is reported. This matches how `Update` treats every other field it is given.
- **Override:** none. Uniqueness is a guarantee the stores make, not a policy.

### D3 (proposed): The event and audit name `username`

`changedUserFields` adds `"username"` when the change names it. The audit "before" and "after"
records already carry `Username`. Error text never contains the username (the
`security-administration` error requirement).

### D4 (pending): How usernames are compared on rename

- **Proposed:** keep the existing rule. Usernames are compared exactly, with the cross-checks
  against live users' emails ignoring case.
- **Asked for by the consumer:** case-insensitive comparison of usernames.
- **Why the proposal keeps the existing rule:** a rule for rename that differs from the rule for
  creation makes the outcome depend on which call wrote the username. A case-insensitive rule for
  every write is a compatibility change: existing data may already hold `Ada` and `ada`. For a
  consumer whose usernames equal their emails, the cross-check already refuses `ADA@x` when `ada@x`
  is another live user's email.
- **Still to decide:** whether that is enough for the consumer. A deleted user's username stays
  taken exactly, so `D@x` can be given while `d@x` belongs to a deleted user. Login by username is
  exact, so this creates no ambiguity at sign-in.

### D5 (pending): Lockout state keyed by the old username

Failure counts and holds are keyed by the username, so they do not follow a rename:

- the renamed account starts with no failures and no hold;
- the old username becomes free, and a user who later takes it inherits its failures and any hold.

Options:

1. **Accept and document** (cheapest). The consequence is a temporary lockout of whoever takes the
   old name, bounded by the lockout's retention.
2. **Move the state with the rename.** Lockout lives in the security-state tables, and the
   administration stores live in the identity tables. The project rule allows no joins or foreign
   keys across the two groups, so this needs a hook or port the consumer wires, not a store
   transaction.
3. **Clear the old username's state** on rename, through the same kind of hook. A held account is
   then released by renaming it.

Not decided. Options 2 and 3 make `admin` depend on something beyond its store.

### D6 (pending): Sessions after a rename

- **Proposed default:** a rename ends no session and revokes no refresh family, and this is
  documented. Sessions are keyed by the identifier. In the username-subject token modes, tokens
  naming the old username fail closed on their next use.
- **Alternative asked for by the consumer:** an option such as `WithRevokeSessions`. `admin`
  services are built from their store alone, and adding the session manager as a dependency would
  change that. A consumer who wants this policy revokes the user's sessions after a successful
  update.
- **Still to decide:** whether scrty should provide a helper for that, or only document it.

### D7 (pending): A consumer store that ignores `Username`

A `UserStore` written before this change still compiles. It would ignore the field and report
success, and the event would name a rename that did not happen. The project rule is that a guarantee
is never weakened silently. Options:

1. **Check after the write:** the service compares `updated.Username` with the requested value and
   fails with an error when they differ. The other fields have already been committed by then, so
   the outcome is a reported inconsistency, not a refusal.
2. **Separate port:** a new optional interface (`UsernameUpdater`). `NewUsers` records whether the
   store implements it, and `Update` refuses a change naming a username, with an error matching
   `ErrConfig`, when it does not. This refuses before writing, and fails at first use rather than at
   construction.
3. **Changelog only:** document the contract change under the 0.x release policy and rely on the
   consumer store's own tests.

Leaning towards 1 plus 3: it is cheap, and it guards a guarantee that otherwise rests only on
documentation. Not decided.

## Failure modes

| Failure | State | What the caller sees |
|---|---|---|
| Stale version | Handled, tested | `ErrStaleUpdate`, nothing written |
| Username blank, padded, too long or containing NUL | Handled, tested | `ErrInvalidInput`, store not called |
| Username held by another user, live or deleted | Handled, tested | `AlreadyExistsError{FieldUsername}`, no value in text |
| Username equals another live user's email, any case | Handled, tested | `AlreadyExistsError{FieldUsername}` |
| Username and email set together, racing another writer | Handled, tested (barrier test) | At most one write succeeds |
| Rename to own email in the same change | Handled, tested | Succeeds |
| Case-only rename | Handled, tested | Succeeds, stored as given |
| Rename racing a deactivation | Handled, tested | The later write is `ErrStaleUpdate`; the deactivation stays |
| No actor | Handled, tested | `ErrNoActor`, store not called |
| Store outage | Handled, tested | Error matching no administration reason |
| Consumer store ignores the field | Pending (D7) | See D7 |
| Lockout state left under the old username | Pending (D5) | See D5 |
| Tokens naming the old username (username-subject modes) | Accepted | The next request with them is refused as unauthenticated; the user signs in again |
| ID tokens already issued carry the old `preferred_username` | Accepted | Stale until the client next receives an ID token; `sub` is unchanged |
| Password context words include the old username | Accepted | The current password is not checked again; the new username applies from the next password change |
| Event or audit delivery lost after commit | Accepted (existing) | As for every administrative write (`admin` package documentation) |

## Risks / Trade-offs

- [The old username is released and may be taken by another person] → The same as an import that
  changes a username today. Sessions refuse a token whose username now names a different user. The
  remaining exposure is lockout state (D5) and the consumer's own records keyed by username, which
  the godoc must call out.
- [The `UserStore` contract changes for consumer stores] → D7, plus a CHANGELOG entry.
- [Three SQL stores and the in-memory store must agree] → The store conformance suite in `test/admin`
  gains rename cases that every store runs.

## Migration Plan

No schema migration. `scrty_users.username` is already unique and writable. Consumers replace any
rename done by re-importing with `Users.Update`, passing the version they read.

## References

Reasoned from scrty's own settled specs (`security-administration`, `sessions`, `authentication`)
and code. No external standard governs username changes. The consumer's brief requested the change
and set out its risks.
