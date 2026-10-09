## Why

A consumer reviewed the account lockout against NIST, OWASP, CIS and PCI DSS. Most of what they asked for already exists. Four things they found, or that checking their review turned up, are wrong today:
- **No fixed lock duration.** CIS and PCI audits look for a minimum lock duration. The option a consumer reaches for, `WithFixedLockout`, is a sliding window: an identifier is refused while the threshold of failures falls inside the window, and the lock lifts as soon as the oldest one ages out. A lock reached by failures spread across the window lasts seconds. Its name promises a fixed lock it does not give. The escalating wait already gives an exact fixed duration when its first and longest waits are equal, but nothing documents or tests that.
- **The godoc overstates NIST conformance.** It calls the ceiling of 100 "NIST SP 800-63B's cap". NIST §3.2.2 caps *consecutive* failures in total, and disables the authenticator until it is bound again. scrty's ceiling counts failures inside the 24-hour window, and they age out. It limits the guessing rate to about 24 a day per account, with no limit on the total. The default stays as it is (the cap NIST describes is the subject of a later, opt-in change). What changes is that the documentation stops claiming a guarantee the code does not give.
- **Setting a new password does not clear the failure count.** Only a successful login clears it. A user who fails several times, recovers and sets a new password still owes the wait their old guesses earned. If the account reached the ceiling, the user is still refused for up to 24 hours. Microsoft Entra, Auth0 and Keycloak all clear the count when the password is reset or the account re-enabled.
- **Nobody can observe lockout.** Reaching the threshold, reaching the ceiling and clearing are not reported anywhere. A consumer has nothing to audit or alert on, and the only log records are those for a broken attempt store.

## What Changes

- **The sliding lock is named for what it does.** `WithFixedLockout` is renamed, and its godoc and the spec describe a sliding window and a rate limiter, not a lock of fixed duration. Nothing is tagged, so the rename is free (it is recorded as a decision).
- **A fixed-duration lock is a documented, tested configuration**, built on the escalating wait with equal first and longest waits. The tests pin the exact duration, including its boundary instant. They also pin where it differs from the CIS model, which clears the count when the lock ends: here the count stays in the window, so each further failure locks again for the full duration. The design decides whether this is also offered as a named preset.
- **The NIST wording in the godoc is corrected** to describe a windowed ceiling. It states what the ceiling does not provide (a total cap, disabling until rebind).
- **A password change through the chain clears the user's failures.** When the consumer's function at the password-change resolve endpoint succeeds, the failures recorded against the user are cleared. A consumer who changes passwords outside the chain is told to call the policy's reset. How the chain gets from the session's user reference to the identifier the failures are keyed on is a design decision.
- **Lockout transitions can be observed.** A consumer can supply a hook that is told when an identifier reaches the threshold, reaches the ceiling, and is cleared. The default reports nothing new. The design states what the hook receives, so that the hook reveals nothing about whether an account exists that the refusal itself does not.
- **Unknown usernames are pinned to lock exactly like real ones.** This already holds. A conformance scenario makes it a tested guarantee: failures for an identifier with no account accumulate and are refused with the same refusal as a known account's.

Not in this change:
- a hold-until-rebind cap on consecutive failures, offered as an opt-in. It needs a port change, all four attempt stores and the schema, and goes to a later change;
- a risk hook that exempts or softens a lock;
- CIS defaults (5 failures / 15 minutes / 15 minutes fixed), which are declined. The progressive default follows NIST's own example of waits growing from 30 seconds to an hour;
- lock state stored as a `locked_until` value, which is declined. The lock is worked out from the failure log, which already gives an exact, testable duration.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-policy`: the sliding lock renamed and described as a sliding window; the fixed-duration configuration as a stated, tested behaviour; the lockout observation hook.
- `http-security-chain`: a successful password change at the resolve endpoint clears the user's lockout failures; failures for an unknown username lock like a known one's.

`account-recovery` is unchanged: a recovered user sets their new password through the resolve endpoint, which this change covers. `store-conformance` is unchanged: the attempt-store contract does not move.

## Impact

- **Changed code:** `policy` (lockout options, godoc, observation hook) and `httpsec` (password-change resolve endpoint, login conformance). No port changes and no migrations.
- **Changed API:** `policy.WithFixedLockout` is renamed. Nothing is tagged, so there are no consumers to migrate.
- **Depends on:** nothing in flight. `shared-rate-limiting-postgres` and `trusted-proxy-client-ip` do not touch lockout.
- **Followed by:** the opt-in hold-until-rebind cap (a separate change, not yet proposed).

## References

**Researched (accessed 2026-10-07):**

*NIST conformance of the ceiling (the godoc correction):*
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: the verifier SHALL limit consecutive failed attempts on one authenticator to at most 100 by disabling it until rebind. It also gives the example of waits growing from 30 seconds to an hour, and says failures SHOULD be disregarded after a successful authentication.

*Fixed versus sliding lock, and the declined CIS defaults:*
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), Account Lockout: threshold, observation window and lockout duration as the standard parameters; exponential lockout; lockout as a denial-of-service risk.
- [Keycloak brute-force detection](https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/threat/brute-force.adoc): temporary lockouts that escalate to a maximum wait, a failure reset time, and permanent lockout as a separate mode, with its denial-of-service downside stated.
- [AWS Cognito lockout behavior](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html#authentication-flow-lockout-behavior): five free attempts, then waits that double up to about 15 minutes, and refused attempts not counted. This shows the progressive default is established practice.
- [ASP.NET Core Identity lockout options](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration): fixed lock duration, and a success clears the count.

*Clearing the count when the password is set:*
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout): a self-service password reset sets the lockout duration to zero.
- [Auth0 brute-force protection](https://auth0.com/docs/secure/attack-protection/brute-force-protection): changing the password unblocks the user.
- Keycloak (above): re-enabling a user resets the count.

**Unverified:**
- PCI DSS v4.0 requirement 8.3.4 (lock after at most 10 invalid attempts, for at least 30 minutes or until identity is confirmed). The wording comes from the consumer's review. The PCI SSC's public summary of changes did not return readable text, and the standard itself is registration-only. The fixed-duration tests must not claim PCI conformance until this is checked.

**Project:**
- `openspec/specs/security-policy` (the lockout requirements) and `openspec/specs/http-security-chain` (the password-change resolve endpoint).
- `openspec/changes/archive/2026-10-04-login-source-throttling` (decision 2: the escalating wait and the windowed ceiling, which this change keeps).
