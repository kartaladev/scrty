## Why

Password login, form and Basic, is bounded only by per-account lockout: five failures per account in fifteen minutes, then a hard lock. That leaves two gaps:
- **Password spraying is unbounded.** One source trying one common password across many accounts never trips a per-account limit, and no per-source limit exists on login.
- **Lockout is a denial-of-service lever.** Anyone who knows a username can lock its owner out for the window, and the response (423, `ErrAccountLocked`) reveals that the account exists and is locked.

OWASP ASVS 5.0 asks that anti-automation controls prevent malicious account lockout. NIST SP 800-63B-4 caps consecutive failures per account at 100, and lists increasing wait periods and risk-based methods as alternatives to locking. OWASP's Authentication cheat sheet advises against revealing lockout status.

## What Changes

- **A per-source guard on form and Basic login**, built from the rate-limiting source guard and the limiter factory. It has a stated default limit, the same unattributable-source refusal as every guarded flow, and its own namespace.
- **An alternative to the hard lock.** Progressive delay or a growing lock period is offered as a policy option. The default is decided in design, with the departure from the current hard lock recorded if it changes.
- **Lockout responses that do not reveal lockout status by default**, with the current explicit status available as an option.
- **Login records failures on a context the caller cannot cancel**, as every other guarded flow does. Today the login failure is recorded on the request context.
  - **Status:** `UNREPRODUCED`. It needs an attempt store that honours cancellation.
  - **First red step:** reproduce it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `authentication`, `security-policy` and `rate-limiting`: the per-source login guard, the lockout alternatives, and the lockout response.
- `http-security-chain`: the login endpoints' refusal mapping.

## Impact

- **Changed code:** `httpsec` login, `policy` lockout, and the status mapping.
- **Depends on:** `shared-rate-limiting` (the limiter factory, so the new guard is shared like the others).
- **Consumers:** none yet. Nothing is tagged. Any change to the lockout default is recorded as a decision.

## References

**Researched (accessed 2026-10-03):**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: at most 100 consecutive failures; increasing waits and risk-based alternatives.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): lockout parameters, lockout denial of service, do not reveal lockout status.
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): password spraying, and the limits of per-IP blocking.
- [OWASP ASVS 5.0, V6 Authentication](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): requirement 6.1.1 on preventing malicious lockout.
