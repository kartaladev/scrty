# Design

## Context

See proposal.md for why. D1 to D3 were proposed with the draft. D4 to D7 were decided with the user on 2026-11-28,
after research and after rebasing onto current `main`.

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

### D1 : A field on `UserChange`, not a `Users.Rename` operation

`UserChange` gains `Username *string`. A nil username is unchanged, like every other field.

- **Why:** a consumer whose usernames are emails must change both in one write. A
  `Rename(ctx, id, version, username)` can change only the username, so the email would need a
  second write and a second version check. That brings back the half-applied state this change
  removes.
- **Alternative:** `Rename` that also takes an optional email. It duplicates `Update`'s email rules
  and leaves two ways to change an email.
- **Default / override:** no configuration. A consumer who wants renames to be a separate
  operation in their application gates the field at their own route.

### D2 : A rename is validated and checked as a creation is

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

### D3 : The event and audit name `username`

`changedUserFields` adds `"username"` when the change names it. The audit "before" and "after"
records already carry `Username`. Error text never contains the username (the
`security-administration` error requirement).

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

- the renamed account starts with no failures and no hold;
- the old username becomes free, and whoever later takes it inherits its failures and any hold,
  until the lockout's retention ends.

This is accepted and documented in the godoc of `UserChange.Username` and in the failure modes.

Moving or clearing the state would need a consumer-wired hook. The project allows no store
transaction across the security-state and identity table groups, and the hook would make `admin`
depend on something beyond its store. The underlying issue is the key: NIST SP 800-63B and OWASP
describe failure limits per account, not per name.

- **Follow-up:** `lockout-by-user-id`, which re-keys lockout state by user identifier.

### D6: An opt-in option ends the user's sessions after a rename

- **Default:** a rename ends no session and revokes no refresh family. Sessions are keyed by the
  user identifier, and username-subject tokens naming the old username fail closed on their next
  use.
- **Override:** `WithSessionRevocation(r SessionRevoker)` on `NewUsers`, where:

  ```go
  type SessionRevoker interface {
      DeleteByUser(ctx context.Context, user identity.UserID) error
  }
  ```

  `*session.Sessions` satisfies it as it is, so `admin` does not import `session` and needs no
  adapter.
- **When it runs:** only after an update that changed the username has committed. It revokes every
  session of the user. An update that names no username, or that fails, revokes nothing.
- **When revocation fails:** the update stays committed and its event is emitted. `Update` returns
  an error matching `ErrSessionsNotRevoked` that wraps the cause, so the caller can retry the
  revocation. Rolling back is impossible, because the two writes are in different table groups.
- **Wiring:** a nil revoker, typed-nil included, fails `NewUsers` with an error matching
  `ErrConfig`.
- **Not covered:** grants the OpenID Provider issued are not revoked by this option. They are keyed
  by the user identifier and are unaffected by a rename.
- **Sources:** none of the sources read says a rename must end sessions. Auth0's user update treats
  the username as an editable field separate from the stable `user_id`, and says nothing of
  sessions. This is therefore the consumer's policy, offered as an option.

### D7: A store that cannot change usernames refuses a rename before writing

A `UserStore` written before this change still compiles, and would ignore the field and report
success.

- **The guard:** a marker interface.

  ```go
  type UsernameUpdater interface{ UpdatesUsername() }
  ```

  `NewUsers` records whether the store implements it. `Update` refuses a change naming a username
  with an error matching `ErrConfig` when the store does not, before calling the store, so nothing
  is written. Every scrty store, in-memory and durable, implements it.
- **Why this option:**
  - Checking after the write reports an inconsistency only once the other fields are committed.
  - A changelog entry alone leaves the guarantee resting on documentation.
  - Refusing at construction would break every consumer store, including those that never rename.
  - So the refusal happens at the first update that names a username, documented in godoc and the
    CHANGELOG.
- **Override:** a consumer store opts in by implementing `UpdatesUsername` once its `UpdateUser`
  applies the field.

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
| Consumer store ignores the field | Handled, tested (D7) | `ErrConfig` before the store is called, nothing written |
| Lockout state left under the old username | Accepted (D5) | The renamed account starts clean. The next holder of the old name inherits its count or hold until retention ends |
| Session revocation fails after the rename committed | Handled, tested (D6) | `ErrSessionsNotRevoked` wrapping the cause, update committed, event emitted |
| Nil session revoker | Handled, tested (D6) | `NewUsers` fails with `ErrConfig` |
| A sign-in races the revocation | Accepted (D6) | A session created after the revocation was made with the new username and survives; one created before is deleted |
| Revocation enabled and the update names no username | Handled, tested (D6) | Nothing revoked |
| Tokens naming the old username (username-subject modes) | Accepted | The next request with them is refused as unauthenticated; the user signs in again |
| ID tokens already issued carry the old `preferred_username` | Accepted | Stale until the client next receives an ID token; `sub` is unchanged |
| Password context words include the old username | Accepted | The current password is not checked again; the new username applies from the next password change |
| Event or audit delivery lost after commit | Accepted (existing) | As for every administrative write (`admin` package documentation) |

## Risks / Trade-offs

- [The old username is released and may be taken by another person] → The same as an import that
  changes a username today. Sessions refuse a token whose username now names a different user. The
  remaining exposure is lockout state (D5) and the consumer's own records keyed by username, which
  the godoc must call out.
- [The `UserStore` contract changes for consumer stores] → D7 refuses renames on a store without the
  marker, plus a CHANGELOG entry.
- [Three SQL stores and the in-memory store must agree] → The store conformance suite in `test/admin`
  gains rename cases that every store runs.

## Migration Plan

No schema migration. `scrty_users.username` is already unique and writable. Consumers replace any
rename done by re-importing with `Users.Update`, passing the version they read.

## References

**Researched** (accessed 2026-11-28; read through a summarising fetch tool):

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

D1 to D3 and D7 are reasoned from scrty's own settled specs (`security-administration`, `sessions`,
`authentication`), its code, and the project's library-design and defensive-coding rules. The
established design has no username rename. The consumer's brief requested the change and set out
its risks.
