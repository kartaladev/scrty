## Why

Password login, form and Basic, is bounded only by per-account lockout: five failures per account in fifteen minutes, then a hard lock. That leaves two gaps:
- **Password spraying is unbounded.** One source trying one common password across many accounts never trips a per-account limit, and no per-source limit exists on login.
- **Lockout is a denial-of-service lever.** Anyone who knows a username can lock its owner out for the window, and the response (423, `ErrAccountLocked`) reveals that the account exists and is locked.

OWASP ASVS 5.0 asks that anti-automation controls prevent malicious account lockout. NIST SP 800-63B-4 caps consecutive failures per account at 100, and lists increasing wait periods and risk-based methods as alternatives to locking. OWASP's Authentication cheat sheet advises against revealing lockout status.

## What Changes

- **A per-source guard on form and Basic login**, built from the rate-limiting source guard and the limiter factory. It has a stated default limit, the same unattributable-source refusal as every guarded flow, and its own namespace.
- **An alternative to the hard lock.** The default becomes an escalating wait capped by a ceiling (design decision 2), recorded as a departure from the current hard lock, which remains available as an option.
- **Lockout responses that do not reveal lockout status by default**, with explicit disclosure available as an option. A disclosed lock answers 429 instead of 423 (design decision 3).
- **Login records failures on a context the caller cannot cancel**, as every other guarded flow does. Today the login failure is recorded on the request context.
  - **Status:** `REPRODUCED` (design decision 4 records the tests and output).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `security-policy`: the escalating wait that replaces the hard lock by default, the ceiling, the fixed lock as an option, and the wait carried by the refusal.
- `authentication`: a decoy password verification for refusals made before a password is checked.
- `http-security-chain`: the per-source login guard, the undisclosed lock response, and failures recorded on an uncancellable context.
- `http-error-propagation`: the account-locked refusal maps to 429 instead of 423.
- `account-recovery`: a locked account at the password proof is refused like any other refused proof by default.

`rate-limiting` is unchanged: the guard reuses the source guard as specified.

## Impact

- **Changed code:** `httpsec` login and Basic, `policy` lockout, and `authenticate` (decoy verification). The status table's account-locked row moves from 423 to 429.
- **Depends on:** `shared-rate-limiting` (the limiter factory, so the new guard is shared like the others).
- **Consumers:** none yet. Nothing is tagged. Any change to the lockout default is recorded as a decision.

## References

**Researched (accessed 2026-10-03):**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: at most 100 consecutive failures; increasing waits and risk-based alternatives.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): lockout parameters, lockout denial of service, do not reveal lockout status.
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): password spraying, and the limits of per-IP blocking.
- [OWASP ASVS 5.0, V6 Authentication](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): requirement 6.1.1 on preventing malicious lockout.
