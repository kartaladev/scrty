# Proposal

## Why

Removing a passkey, or suspending one as a suspected clone, leaves every session of the user alive. A thief who signed in with a lost or cloned passkey keeps that session after the user removes the passkey, and at MFA verification the session that presented the clone stays pending and free to try another method. OWASP ASVS 5.0 §7.4.3 asks that users be offered to end their other sessions after a factor is removed, and NIST SP 800-63B-4 treats a duplicated authenticator as compromised. scrty already ends sessions after an account recovery and an MFA reset. The passkey change deferred this to a follow-up.

## What Changes

- **Removal ends the user's other sessions by default.** The session that removes the passkey is kept, and every other session of the user is deleted before the passkey is.
  - The remove endpoint honours an optional posted field, `other_sessions=keep`, so a consumer's interface can offer the user the choice ASVS 7.4.3 describes.
  - `passkey.WithoutSessionRevocationOnRemoval()` makes "keep" the library default. A posted `other_sessions=end` then still ends them.
- **Suspension as a suspected clone ends every session of the user**, including the MFA-pending session in which the clone was presented. The user gets back in with another factor or an account recovery.
  - `passkey.WithoutSessionRevocationOnClone()` keeps the sessions.
  - Signal-only mode and a consumer clone policy that does not suspend end nothing, because nothing is suspended.
  - A failure to end the sessions after a suspension is logged and does not turn the refusal into an acceptance.
- **The session manager can delete a user's sessions except one**, atomically, on every store: in memory, `sqlstore`, `pgx` and `gorm`. The shared session suite covers it.
- **BREAKING (pre-tag):** `passkey.Deps` gains `Sessions`, a port that `*session.Manager` satisfies. It is required unless both revocations are turned off, and construction fails without it.
- **BREAKING (pre-tag):** `session.Store` gains the "delete a user's sessions except one" operation, so a consumer's own store must implement it.
- The default Suspended and Removed notice texts say when other sessions were ended.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `passkey-authentication`:
  - removal ends the user's other sessions by default, with a per-request keep and a library opt-out;
  - suspension as a suspected clone ends every session of the user, with an opt-out;
  - construction fails when a revocation is on and no session port is wired.
- `multi-factor-auth`: a suspected clone at verification ends the pending session along with the user's others when the credential is suspended, instead of leaving the challenge pending.
- `sessions`: the manager deletes every session of a user except one named session.

## Impact

- **Code:**
  - `passkey`: Deps, options, `Remove`, the clone path and notices.
  - `session`: the Store port, the Manager and the in-memory store.
  - The durable session stores in `sqlstore`, `pgx` and `gorm`.
  - `httpsec`: the remove endpoint's field and wiring.
- **Tests:**
  - the shared session suite in the `test` module, run against every backend;
  - passkey and httpsec tests;
  - conformance scenarios on net/http, gin and fiber.
- **Docs:** README passkey section and defaults table; godoc on the new options and port.
- **No schema change:** the deletion runs over existing columns.
- **No new dependency.**
