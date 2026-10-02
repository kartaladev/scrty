# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **Session deletion is effective revocation.** The bearer interceptor loads the session named by the token's `jti` on every request (`http-security-chain` "Bearer tokens authenticate against a live session and a live user"), so a deleted session refuses its token on the next request. No refresh token exists today.
- **The session port has no "all but one".**
  - `session.Store` and `*session.Manager` offer `Delete`, `DeleteByUser`, `DeleteExpired`, `DeleteByExternalSession` and `DeleteByUserAndExternalIssuer`.
  - Durable stores key a session by `id_digest`, a digest of its identifier, in `internal/pgschema/sessions.go`, with implementations in `sqlstore`, `pgx` and `gorm`.
  - `session/memory.go` is the in-memory store, and `session/encrypted.go` decorates any store.
- **Revocation precedent.**
  - Account recovery: `recovery.WithoutSessionRevocation()`.
  - MFA operator reset: `mfa.WithoutSessionRevocation()`, with the narrow port `mfa.SessionRevoker`.
  - Both end every session by default.
- **The passkey core has no session dependency.**
  - `(*passkey.Manager).Remove(ctx, s, cid, rc)` admits, finds the user's credential, deletes it, then queues the Removed notice.
  - Clone handling (`onCounterRefused`, `passkey/clone.go`) suspends with a conditional write, queues the Suspended notice, and returns `ErrCloneSuspected`. It is reached from passwordless `Authenticate`, where no session exists yet, and from the MFA method's `Verify`, where the caller's MFA-pending session is in flight.
  - `httpsec.PasskeyDeps.Sessions` exists, but only the chain uses it.
- **Saving a deleted session never re-creates it** (`sessions` "Saving an existing session never re-creates a deleted one"). An endpoint that saves after the core deleted the session therefore cannot resurrect it.
- **The established design** ended sessions only on OIDC back-channel logout, so nothing here departs from it. Every behaviour below is new.

## Goals / Non-Goals

**Goals:**
- The passkey core decides both revocations, so a direct caller of the manager gets the same rule as the HTTP chain.
- The removal is retryable: a failure leaves the passkey in place.
- The clone refusal never depends on revocation succeeding.

**Non-Goals:**
- **Ending sessions when other factors change** (TOTP removal, password change). That is a separate decision for each factor.
- **Recording which credential created a session.** "Only that passkey's sessions" was rejected (user's decision, 2026-10-02).
- **A user-facing "sign out everywhere" endpoint.** Consumers can call `(*session.Manager).DeleteByUserExcept` themselves.
- **Reactivating a suspended passkey.** It stays terminal, as `passkey-authentication` already states.

## Decisions

### D1. The session manager deletes a user's sessions except one

```go
// session.Store and *session.Manager
DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)
```

- **Behaviour.** One statement removes every session of `user` whose identifier is not `keep`, and returns how many it removed.
  - Durable: `DELETE FROM sessions WHERE user_id = $1 AND id_digest <> $2`, where the store digests `keep` exactly as `Delete` digests an identifier.
  - In memory: under the store's lock.
  - The encrypted decorator passes the call through.
  - It joins an ambient transaction like every other session write.
- **A `keep` belonging to another user, or to no session,** removes all of `user`'s sessions and touches nothing else, which follows from the `WHERE` clause. An empty `keep` behaves the same as no exception.
- **Default and override:** this is a capability, not a policy. A consumer's own `session.Store` must implement it (BREAKING, pre-tag).
- **Alternatives rejected:**
  - Listing the user's sessions and then deleting each one: a session created between the list and the deletes would survive.
  - `DeleteByUser` followed by re-creating the current session: it changes the caller's handle and token for no gain.

### D2. The passkey core takes a session port

```go
package passkey

// SessionRevoker is what the manager needs to end sessions. *session.Manager satisfies it.
type SessionRevoker interface {
    DeleteByUser(ctx context.Context, user identity.UserID) error
    DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error)
}

// Deps gains:
Sessions SessionRevoker
```

- **Required** when either revocation is on, which is the default. A nil value, typed nil included, is `ErrConfig` at `passkey.New`. With both revocations off it may be nil.
- **The consumer wires the same `*session.Manager`** to `passkey.Deps.Sessions` and to `httpsec.PasskeyDeps.Sessions`. The godoc and the README example show it.
- **Alternatives rejected:**
  - Ending sessions in `httpsec` alone. Clone suspension happens inside the core for direct callers too, and the removal order (D3) is a core rule.
  - Reusing `mfa.SessionRevoker`. It lacks "all but one", and it belongs to another subsystem.

### D3. Removal ends the other sessions, before the passkey

The steps of `Remove`, in order:
1. Admission.
2. Find the user's credential.
3. If revocation applies to this request, `DeleteByUserExcept(user, s.ID)`.
4. `credentials.Delete`.
5. If revocation applied, a second `DeleteByUserExcept(user, s.ID)`.
6. The Removed notice.

- **Revocation runs before the delete** so a failure refuses the removal with fixed text and leaves the passkey for a retry. Deleting first would leave nothing to retry, since the retry is refused as not found, with the thief's sessions still alive.
  - Cost: if the delete then fails, the other sessions are already gone while the passkey remains. That fails safe, and the retry removes the passkey.
- **The second pass** catches a session created by a login that finished between the first pass and the delete.
  - A login that records its assertion after the delete is refused, because the conditional counter write finds no row.
  - The second pass is best effort: its failure is logged and the removal stands.
- **The removing session stays as it is, with no rotation.** Removing a factor lowers no privilege of this session. Rotation would also turn the 204 response into a token response for no security gain.
  - This narrows "keeps (and rotates)" in the option text the user chose on 2026-10-02 to "keeps". It is open to the user's review.
- **The per-request choice:**
  - `Remove(ctx, s, cid, rc, opts ...RemoveOption)` with `passkey.KeepOtherSessions()` and `passkey.EndOtherSessions()`. The last option given wins.
  - `httpsec` reads the optional form field `other_sessions` from the same body as `id`, within the existing 4 KiB limit. `keep` maps to `KeepOtherSessions`, `end` to `EndOtherSessions`, and absent to the manager's default.
  - Any other value is refused before any change with a new `httpsec.ErrMalformedRequest`, which maps to 400 and joins `TestStatusForErrorCoversEverySentinel`.
- **Default:** end the other sessions. **Overrides:**
  - `passkey.WithoutSessionRevocationOnRemoval()` makes "keep" the default;
  - per request, the posted field, or the option for a direct caller.
- **Alternative rejected:** keeping by default, as Keycloak 26.3 does. It departs from scrty's "safe default, convenient as an option" rule (user's decision).

### D4. Clone suspension ends every session of the user

- **When:** in `onCounterRefused`, only after `Suspend` reports that it suspended. The manager calls `DeleteByUser(context.WithoutCancel(ctx), user)`, then queues the Suspended notice.
  - A pending session that presented the clone at MFA verify is among those deleted.
  - The verify endpoint returns `ErrCloneSuspected` as today. A later save of that session cannot re-create it (see Context).
- **A failure** is logged at Error through the manager's sampler, under the key `clone|sessions-not-ended`, with `diag.Failure`. The refusal is still `ErrCloneSuspected`. A revocation failure must never become an acceptance, and the credential is already suspended.
- **No suspension, no revocation.** Signal-only mode, and a clone policy returning `Allow` or `Refuse`, suspend nothing and so end nothing. Only `RefuseAndSuspend`, the default response, revokes.
- **Default:** end every session. **Override:** `passkey.WithoutSessionRevocationOnClone()`.
  - There is one option per subsystem, as `config.yaml` requires: removal and clone handling are separate policies, so they get separate options.
- **Why all sessions, not only the clone's:** a counter mismatch cannot tell whether the clone or the original made any earlier session (WebAuthn L3 §6.1.1), and sessions do not record their credential (Non-Goals).

### D5. Notices say what was ended

- **`Notice` gains `SessionsEnded bool`.**
- **The default texts:**
  - Removed adds "Your other sessions were signed out." when it is true.
  - Suspended adds "All your sessions were signed out." when it is true.
- **Override:** `passkey.WithMessages(m)`, as for every text.
- **Why:** ASVS 5.0 §6.3.7 and the MFA cheat sheet expect a notice after a factor change. A user signed out without explanation is more likely to suspect the service than the thief.

### D6. Conformance and stores

- **The shared session suite** gains `DeleteByUserExcept` cases:
  - the except-one count;
  - a kept session belonging to another user;
  - a kept identifier that matches no session;
  - an expired kept session, which is kept but stays expired.
- **The ambient-transaction suite** gains a rolled-back `DeleteByUserExcept` that leaves every session in place.
- **The memory, `sqlstore`, `pgx` and `gorm` stores and the encrypted decorator** all run the suite.
- **No race case:** the operation is a single statement.

## Risks / Trade-offs

- **[A malfunctioning authenticator reports a lower counter and signs its owner out everywhere.]** → The user signs in with another factor or recovers. The Suspended notice explains why. A consumer who distrusts counters chooses signal-only mode, or turns clone revocation off.
- **[Removing a stale passkey signs the user out of their other devices.]** → The consumer's interface offers `other_sessions=keep`, and the default is the safe one.
- **[A session created by a login racing the removal could survive the first pass.]** → The second pass after the delete catches it (D3). A login completing after the second pass must already have recorded its assertion before the delete. That window is a few statements wide, and its session was authenticated by a passkey the user still held at that moment.
- **[A consumer's own session store must add a method.]** → Pre-tag, recorded as BREAKING. The shared suite tells them when it is right.
- **[Consumer-side caches of session state.]** → Out of scope. scrty revokes at its store, and the bearer path checks the store on every request.

## Migration Plan

Code order, each step compiling:
1. `session`: `DeleteByUserExcept` on Store, Manager, the memory store and the encrypted decorator, with the shared suite.
2. The durable stores (`internal/pgschema`, `sqlstore`, `pgx`, `gorm`) and the ambient-transaction case.
3. `passkey`: `SessionRevoker`, `Deps.Sessions`, the options, the `ErrConfig` wiring, `Remove` with `RemoveOption`, clone revocation, and `Notice.SessionsEnded` with the default texts.
4. `httpsec`: `other_sessions`, `ErrMalformedRequest` and its status row, and the wiring in examples.
5. The `test` module: conformance scenarios for removal and clone on net/http, gin and fiber; README and Examples.

There is no schema change. **Rollback:** revert the commits.

## References

### Researched (accessed 2026-10-02)

**D3, D4: whether, and which, sessions end**
- [OWASP ASVS 5.0, V7 Session Management](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x16-V7-Session-Management.md):
  - 7.4.3 (L2): offer to terminate all other active sessions after a factor is changed or removed;
  - 7.4.2: end all sessions when an account is disabled;
  - 7.5.1: re-authenticate before changing MFA settings.
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): compromise includes unauthorised duplication; compromised authenticators SHALL be suspended or invalidated promptly; nothing on sessions.
- [NIST SP 800-63B-4: Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/): timeouts and reauthentication only; nothing ties session termination to an invalidated authenticator.
- [Web Authentication Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/), §6.1.1 and §7.2: a counter mismatch is a signal, not proof, and cannot tell which authenticator made an operation.
- [Yubico: U2F advanced topics](https://developers.yubico.com/U2F/Libraries/Advanced_topics.html): treat a decremented counter as a compromised account and lock it down.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): renew the session identifier on privilege change; reauthenticate after critical changes.
- [Keycloak issue #39975](https://github.com/keycloak/keycloak/issues/39975) and [PR #40234](https://github.com/keycloak/keycloak/pull/40234): a "sign out from other devices" choice on password, passkey and second-factor updates, whose default moved from checked to unchecked in 26.3.0.
- [Okta: session revocation](https://help.okta.com/en-us/content/topics/security/slo/session-revoke.htm): an opt-in sign-out of other devices on a user's password reset.
- [Google Account: password change](https://support.google.com/accounts/answer/41078) and [passkeys](https://support.google.com/accounts/answer/13548313): other devices are signed out on a password change; passkey removal ends no session.
- [GitHub: managing passkeys](https://docs.github.com/en/authentication/authenticating-with-a-passkey/managing-your-passkeys): no session effect documented for removal.
- [Django: password change and sessions](https://docs.djangoproject.com/en/5.2/topics/auth/default/) and [Laravel: logoutOtherDevices](https://laravel.com/docs/12.x/authentication): the current session is kept and the others end.

**D5: notices**
- [OWASP ASVS 5.0, V6 Authentication](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x15-V6-Authentication.md), 6.3.7: notify users after authentication details change.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): out-of-band notice on factor changes.

**D1, D2, D6**
- Reasoned from scrty's own settled specs (`sessions`, `http-security-chain`, `passkey-authentication`, `multi-factor-auth`, `account-recovery`, `store-conformance`) and the established design.
