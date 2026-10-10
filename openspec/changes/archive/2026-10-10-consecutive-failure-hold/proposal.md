## Why

NIST SP 800-63B-4 §3.2.2 requires a verifier to limit consecutive failed attempts on an account to no more than 100, by disabling the authenticator until it is bound again. scrty's ceiling counts failures in a 24-hour window, which age out. It limits the guessing rate to about 24 a day per account, but sets no limit on the total, and nothing ever holds an account until its password is reset. A deployment that must meet §3.2.2 has no way to configure it. `lockout-honest-defaults` stopped the documentation from claiming this guarantee, and deferred the opt-in that provides it to this change.

## What Changes

- **An opt-in cap on consecutive failures.** A consumer can enable a cap, with a named constant of 100 for NIST's limit. It counts the failures recorded for an identifier since its last successful authentication, whatever their age. When the count reaches the cap, the identifier is **held**: every pre-authentication for it is refused, however long ago its last failure was, until the hold is lifted. A cap above 100 is allowed, and the documentation says it is outside NIST's limit. The default policy is unchanged: there is no cap unless one is configured.
- **What lifts a hold.**
  - A successful password change at the chain's resolve endpoint lifts it. That includes a password change that completes a recovery, which a held user can still reach with recovery codes, or with a recovery code and an MFA code.
  - The lockout policy's reset is the explicit unlock, for an administrator or support tool. It clears the hold together with the windowed failures, so an unlocked account is not still refused by the ceiling.
  - No time-based release exists. A successful login cannot lift a hold, because a held identifier is refused before its password is checked.
- **The count below the cap expires after inactivity.** A count whose newest failure is older than a retention period, 30 days by default and replaceable, is no longer counted, and the expiry sweep may delete it. A hold is never expired this way.
- **A held refusal can be told apart by the consumer.** It is the account-locked refusal with no wait, and it is also identifiable as a hold, so a consumer can tell the user to reset their password. The existing concealment is unchanged: by default the client sees an ordinary authentication failure, with the decoy verification spent, and only the consumer's error handling can tell a hold apart.
- **A successful Basic authentication clears failures, as form login does.** Today a successful Basic request clears nothing, although the lockout requirement says failures are cleared after a successful authentication. With a cap enabled, a Basic user's occasional typos would accumulate until the account is held.
- **A cap needs the policy's view.** A chain whose lockout policy has a cap refuses construction when form login or Basic is handed any attempt store other than that policy's view, because only the view advances the count.
- **Unknown identifiers are held exactly like known ones**, with the same refusal and the same observer report.
- **The observer is told when an identifier becomes held**, and when a hold is lifted.
- **Storage.**
  - A new optional store contract keeps the consecutive count and the hold per identifier. Each of the in-memory and three durable attempt stores implements it, and it gets its own conformance suite.
  - The existing attempt-store interface does not change, so a consumer's own attempt store keeps working.
  - Enabling the cap with a store that does not implement the new contract is a configuration error at construction.
  - One table is added to the security-state migration set, folded into the initial file, since nothing is tagged.

Not in this change:
- a time-based release of a hold;
- counting per identifier and source. NIST's limit is per account, and a limit per source gives a distributed attacker 100 guesses per source;
- notifying the user of a hold. A consumer can do this from the observer.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `security-policy`: the consecutive-failure cap, the hold and what lifts it, the inactivity retention of the count, the held refusal, reset as the unlock, the hold reports to the observer, and the store contract the cap requires.
- `http-security-chain`: a successful Basic authentication clears failures; a capped policy requires its view at the password logins; a held identifier is refused like any locked one, and a password change at the resolve endpoint lifts the hold.
- `security-state-stores`: durable stores for the consecutive count and hold, on every supported backend.
- `schema-migrations`: the security-state set creates the new table.
- `expiry-sweeping`: the login-attempt task deletes inactive counts below the cap, and never a hold.

## Impact

- **Changed code:**
  - `policy`: lockout options, the evaluation, the unlock, the observer view, and the new store contract and its in-memory implementation.
  - `httpsec`: a Basic success clears the consecutive count.
  - `sqlstore`, `pgx` and `gorm`: the new contract.
  - `internal/pgschema` and `migrate/securitystate`: the table and its SQL.
  - `test/storetest`: the new suite and its adapters.
- **Changed API:** additive only, with new options, a constant, a new error, new report kinds, a new store interface and an engine query. Nothing is tagged. **Behaviour change:** a successful Basic authentication now clears failures.
- **Depends on:** nothing in flight. `shared-rate-limiting-postgres` also adds a table to the security-state set. Whichever lands second rebases its fold.

## References

**Researched (accessed 2026-10-09):**

*The cap and the hold:*
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: no more than 100 consecutive failed attempts per authenticator; the authenticator is disabled and must be bound again; a success SHOULD disregard earlier failures; recovery per §4.2 when the subscriber cannot authenticate.

*What lifts a hold, and the denial-of-service risk:*
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), Account Lockout: a lock can be used to deny service; the forgotten-password function must work while an account is locked; count per account, not per source.
- [Keycloak brute-force detection](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/threat/brute-force.adoc): permanent lockout until an administrator re-enables the account; the count resets on success.
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout): self-service password reset lifts the lock.
- [Auth0 brute-force protection](https://auth0.com/docs/secure/attack-protection/brute-force-protection): a password change, an administrator or an emailed link unblocks; a block lapses 30 days after the last failure.
- [Okta password policies](https://help.okta.com/en-us/Content/Topics/security/policies/configure-password-policies.htm): a maximum of 100 attempts before a lock.

*Clearing on success:*
- [ASP.NET Core Identity lockout options](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration): a successful authentication resets the failed-attempt count.

*Unknown identifiers and concealment:* reasoned from scrty's own settled specs (`lockout-honest-defaults`, decision 6) and the OWASP cheat sheet above.

**Unverified:**
- NIST SP 800-63B-4 §4.1 and §4.2 (rebinding and account recovery) were not read; only §3.2.2's reference to them was.
- How any product bounds storage for counts kept against unknown identifiers.
