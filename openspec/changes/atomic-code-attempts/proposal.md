## Why

Every guard checks the limiter, runs the attempt, then records a failure. A concurrent burst therefore overshoots the limit by its concurrency, and the `rate-limiting` capability documents that bound. On a source key that is acceptable.

It is not acceptable on the user-keyed code flows: TOTP verification (5 per 15 minutes over a 6-digit code) and saved recovery codes. An attacker who already holds the password sends many guesses in parallel per window, so the effective bound becomes the server's concurrency, not 5. Once limits are shared (`shared-rate-limiting`), the overshoot is summed across replicas.

The passkey emailed-code path already closes this with an atomic per-code attempt charge. That is the model.

## What Changes

- **Atomic per-challenge attempt accounting** for second-factor code verification and saved recovery codes. Each attempt is charged against the challenge or account before the code is compared, and the charge is atomic in every store, in memory and durable. Overshoot is then impossible regardless of concurrency or replica count.
- **The per-user rate limit stays** as a second, coarser bound.
- **The established check-then-record order is kept** for source-keyed flows, where the documented overshoot remains acceptable.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `multi-factor-auth` and `account-recovery`: attempt accounting on code verification.
- `security-state-stores` and `store-conformance`: the atomic charge operation and its conformance scenarios.

## Impact

- **Changed code:** `mfa` and `recovery` verification paths, their stores and the durable adapters, and conformance suites in the `test` module.
- **Defect status:** the overshoot is a documented bound, not a defect. The first red step shows N parallel wrong guesses against one challenge being admitted beyond the limit, under the race detector.
- **Depends on:** nothing unbuilt. It may be applied before or after `shared-rate-limiting`.

## References

**Researched (accessed 2026-10-03):**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: at most 100 consecutive failed attempts per account.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): strict attempt limits on one-time codes.
- [OWASP ASVS 5.0, V6 Authentication](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): rate limiting on out-of-band and one-time codes.
- [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2): the TOTP validation window and one-time use. It does not itself set a throttle.

The atomic charge model is reasoned from scrty's own `passkey-authentication` spec.
