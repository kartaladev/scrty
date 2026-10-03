## Why

Every guard checks the limiter, runs the attempt, then records a failure. A concurrent burst therefore overshoots the limit by its concurrency, and the `rate-limiting` capability documents that bound. On a source key that is acceptable.

It is not acceptable on TOTP verification, where 5 failures per 15 minutes guard a 6-digit code checked against three time steps. An attacker who already holds the password sends many guesses in parallel per window, so the effective bound becomes the server's concurrency, not 5. Once limits are shared (`shared-rate-limiting`), the overshoot is summed across replicas.

The enrolment path's emailed code, and the passkey emailed code, already close this with an atomic per-code attempt charge. That is the model.

## What Changes

- **An atomic attempt charge on the TOTP enrolment.** Each TOTP verification is charged against the user's confirmed enrolment before the code is compared, in one conditional store write, in memory and in every durable store. At most 5 codes are compared per 15-minute window, whatever the concurrency or replica count. A verification that succeeds gives its charge back, so success spends nothing. The limit and window are replaceable by an option.
- **The charge sits inside the TOTP method**, so every caller is bounded by it: the verify endpoint, and a recovery's TOTP proof, which is limited today only by recovery's own per-user throttle.
- **The per-user rate limit stays** as a second, sliding bound.
- **The established check-then-record order is kept** for source-keyed flows, where the documented overshoot remains acceptable.
- **Saved recovery codes are not changed.** Each carries 128 bits, so a concurrency overshoot gives an attacker no measurable advantage. See `design.md`.
- **The gorm stores return an error for a caller's handle that already carries one.** Building the charge exposed that a gorm store reading one row panics, instead of returning an error, when the caller's transaction handle already carries a failure (for example a `Begin` that failed). The same pattern sits in the recovery-record, recovery-code and passkey stores. The handle is now checked once where every gorm operation resolves it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `multi-factor-auth`: TOTP verification charges each attempt before comparing it.
- `security-state-stores`: the atomic charge and refund operations on the MFA enrolment store, and a scenario for a caller's transaction handle that already carries a failure.
- `store-conformance`: the suite and race scenarios that prove the charge.

## Impact

- **Changed code:** `mfa` (the enrolment store contract, the in-memory store, TOTP verification and its options), `seal` (the sealing enrolment store passes the operations through), the `sqlstore`, `pgx` and `gorm` enrolment stores, the shared SQL in `internal/pgschema`, the security-state migration, and the enrolment suites in the `test` module. `httpsec` changes only so that a refused charge is not recorded as a failed verification. The `gorm` module's handle resolution (`gorm/tx.go`) refuses a handle that carries an error, for every gorm store.
- **Defect status of the gorm handle:** reproduced by `TestStores_FailedHandleIsAnError`, which panicked in `(*sql.Row).Scan` without the guard for the enrolment charge, the recovery record's latest completion, the recovery-code match, the passkey user for a handle, the passkey credential charge, and a resolver's handle. The passkey handle assignment did not fail, because its insert reports the error first; it stays in the table as a pin and is not claimed.
- **Breaking, before the first tag:** `mfa.EnrolmentStore` gains two methods, so a consumer's own enrolment store must implement them.
- **Defect status:** the overshoot is a documented bound, not a defect. The first red step shows 20 concurrent wrong codes for one user being compared beyond the limit of 5.
- **Depends on:** nothing unbuilt. Implementation starts after `shared-rate-limiting` has committed its edits to `mfa` and `httpsec`, which touch the same files.

## References

**Researched (accessed 2026-10-03):**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: at most 100 consecutive failed attempts per account.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): strict attempt limits on one-time codes.
- [OWASP ASVS 5.0, V6 Authentication](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): rate limiting on out-of-band and one-time codes.
- [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2): the TOTP validation window and one-time use. It does not itself set a throttle.

The atomic charge model is reasoned from scrty's own `multi-factor-auth` and `passkey-authentication` specs. Narrowing the scope to TOTP is reasoned from the `account-recovery` spec's 128-bit saved codes.
