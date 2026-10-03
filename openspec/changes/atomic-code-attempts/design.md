## Context

See proposal.md for why. The current state that shapes the approach:

- **TOTP verification has no challenge record.** `(*TOTP).Verify` reads the enrolment, matches the code against three time steps in constant time, then records the accepted step with `AcceptStep`, a conditional write that makes a code single-use. A wrong code never reaches the store. The only bound on wrong codes is the per-user limiter (`mfa-verify|<user>`, 5 per 15 minutes, sliding), checked before the body is read and recorded after a failed verification in `httpsec/mfaverify.go`. Check and record are separate, so N concurrent wrong codes are all compared.
- **Recovery calls the method directly.** A recovery's TOTP proof calls `mfa.Method.Verify` from `recovery`, bounded only by recovery's own per-user limiter, with the same check-then-record order.
- **The atomic charge already exists twice.** The enrolment path's emailed code (`DeviceProofStore.ChargeEmailCode`, `pgschema.EnrolmentChargeEmailCode`) and the passkey emailed code (`CredentialStore.ChargeEmailAttempt`) are each one conditional `UPDATE … SET attempts = attempts + 1 WHERE … AND attempts < $max RETURNING`, made before the compare. Each has suite cases, a race rule and broken-store variants in the `test` module. This change follows that shape.
- **Every durable adapter uses the shared SQL** in `internal/pgschema`. The security-state schema is one migration file, `migrate/securitystate/20260926000000_security_state.sql`, and nothing is tagged.
- **The established design** had no attempt limit on second-factor codes at all, so nothing here departs from it.
- **`shared-rate-limiting` is editing `mfa/throttle.go`, `mfa/throttleoptions.go` and `httpsec/mfaverify.go`** in the working tree. This change edits `httpsec/mfaverify.go` too, and is implemented after those edits are committed.

## Goals / Non-Goals

**Goals:**
- Bound the codes compared against one TOTP enrolment per window, whatever the concurrency or replica count, in every store.
- Keep "a successful verification spends nothing".
- Bind every caller of the TOTP method, the recovery proof included, with no change to the caller.

**Non-Goals:**
- Making the rate limiter's check and record atomic. That is a port change for every guard, and `shared-rate-limiting` is rebuilding the port.
- Saved recovery codes (decision 7).
- Passkey second-factor challenges, which are already single-use per challenge.
- A sliding-window counter in the store (decision 2).

## Decisions

### 1. The counter lives on the TOTP enrolment

Two columns on `mfa_enrolments`: `verify_attempts integer NOT NULL DEFAULT 0` and `verify_window_until timestamptz NULL`. The `mfa.Enrolment` record gains `VerifyAttempts int` and `VerifyWindowUntil time.Time`. There is one enrolment per user, so every session, request and replica charges the same row.

- **Alternatives considered:**
  - **An atomic reserve on the limiter port.** This fixes every guard, but it changes the interface `shared-rate-limiting` is rebuilding, with Redis scripts and a conformance suite. It would also be a much larger change.
  - **A counter on the pending session.** An attacker who holds the password logs in again for a fresh session and a fresh budget.
- **Default and override:** the counter is always on. Decision 4 makes its limit and window replaceable.

### 2. A fixed window, charged in one conditional write

The charge is one statement. If the window has ended (`verify_window_until IS NULL OR verify_window_until <= $at`), it opens a new window ending at `$at + $window` with a count of 1. Otherwise it adds one while the count is below `$limit`. It acts only on a confirmed enrolment and returns the window's end:

```sql
UPDATE mfa_enrolments SET
  verify_attempts     = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2
                             THEN 1 ELSE verify_attempts + 1 END,
  verify_window_until = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2
                             THEN $3 ELSE verify_window_until END
 WHERE user_id = $1 AND confirmed_at IS NOT NULL
   AND (verify_window_until IS NULL OR verify_window_until <= $2 OR verify_attempts < $4)
RETURNING verify_window_until
```

`$2` is the charge instant, `$3` the new window's end (computed by the caller as `at + window`, so the database's clock is never used), and `$4` the limit. Under PostgreSQL's default isolation, concurrent updates of one row serialise on its row lock and re-evaluate `WHERE` against the committed row, so at most `$4` succeed per window. The in-memory store does the same check and write under its mutex.

- **Why fixed and not sliding:** a sliding window in the store needs a timestamp per attempt, which is a child table or an array column, three adapters' worth of new SQL and a purge. A fixed window is two columns and one statement. Its cost is the burst at a window edge (see Risks). The per-user limiter stays sliding and remains the outer bound.
- **Alternatives considered:** never resetting the counter and clearing it on success. A user who mistypes five times across a week would then be locked out until they succeed, which they cannot do.

### 3. Success gives its own charge back, bound to its window

After the code matches and `AcceptStep` accepts its step, `Verify` gives back the charge with one conditional write:

```sql
UPDATE mfa_enrolments SET verify_attempts = verify_attempts - 1
 WHERE user_id = $1 AND verify_window_until = $2 AND verify_attempts > 0
```

`$2` is the window end the charge returned. A give-back after the window has been replaced matches nothing, so it can never cancel a charge made in a later window.

- **Only after success.** A failed compare or a spent step (replay) keeps its charge.
- **Precision of the match.** A durable store truncates the `until` it is given to the microsecond before comparing, because `timestamptz` holds microseconds. A give-back whose `until` falls in the same microsecond as the stored end therefore still matches, where the in-memory store compares exactly. This is accepted: `until` is always the value the charge returned, which every store already truncates, and the `RefundVerifyAttempt` godoc states it.
- **Context:** the give-back runs under `context.WithoutCancel`. A failure is logged at WARN, with a fixed reason and the error's type but never its text (diagnostic-redaction), and does not refuse the verification, because the user proved the factor. The cost of a lost give-back is one attempt of the user's own budget, which fails safe.
- **Alternatives considered:** resetting the count to zero on success. That hands an attacker racing a legitimate user a fresh budget in mid-window; giving back only one's own charge does not.
- **No override.** Success spending nothing is the settled rule ("Failed verifications are throttled per user").

### 4. Defaults, the option and its limits

- **Default:** 5 attempts per 15 minutes, the same as the per-user limiter. Done one after another, the limiter trips first, so every existing scenario behaves as before.
- **Override:** `mfa.WithVerifyAttempts(limit int, window time.Duration)` on `NewTOTP`, documented with the default it replaces. A limit or window of zero or less returns a configuration error from `NewTOTP`.
- **No off switch.** Switching it off would bring back the unbounded overshoot. The godoc states that a larger limit admits that many compares per window however many requests arrive at once (library-design rule 4).

### 5. The order inside `Verify`, and the errors

The order is:
1. `Get`. A missing or pending enrolment returns `ErrInvalidCode` and charges nothing.
2. Charge at `t.clock.Now()`:
   - a store error returns a package-worded error that wraps it, as `AcceptStep`'s failure does today;
   - a refused charge returns `ErrVerifyAttemptsExhausted`, a new sentinel that matches `ErrVerifyThrottled` through `errors.Is`, without comparing the code.
3. `match`. Every code, malformed or not, has already been charged.
4. `AcceptStep`.
5. Give back.

`ErrVerifyAttemptsExhausted` matching `ErrVerifyThrottled` keeps the status mapping (401) and every consumer branch on the throttled error unchanged.

### 6. A refused charge is not recorded on the limiter

`httpsec/mfaverify.go` already skips `RecordFailure` for `mfa.ErrAuthenticatorRefused`. It also skips it for `ErrVerifyThrottled`: no code was compared, and recording it would only extend the user's lockout. `recovery` needs no change, because a refused recovery is counted per user by its own rule, and this change does not alter that.

### 7. Saved recovery codes stay as they are

Each saved code carries 128 bits (`account-recovery`). However many parallel guesses get past the limiter, the chance of a hit is about N·2⁻¹²⁸. An attempt counter would add a column or table, three adapters and suite cases, with no measurable gain in security. The issued recovery code is a one-time token, also high-entropy. This narrows the proposal as first drafted; the user chose it on 2026-10-03.

### 8. The store contract and where each piece lives

- **`mfa.EnrolmentStore` gains two methods,** rather than a separate optional interface like `DeviceProofStore`. TOTP verification is not optional, so a store without them must not compile. This breaks consumer stores, which is allowed before the first tag and recorded here.

  ```go
  // ChargeVerifyAttempt charges one TOTP verification attempt at the given
  // instant and reports the end of the window it was charged in.
  ChargeVerifyAttempt(ctx context.Context, user identity.UserID, at time.Time,
      limit int, window time.Duration) (until time.Time, ok bool, err error)
  // RefundVerifyAttempt gives back one attempt charged in the window ending at until.
  RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error)
  ```

- **`PutPending`** clears both columns, as it already clears the emailed-code attempts.
- **Where the code changes:**
  - `seal.NewEnrolmentStore` passes both methods through.
  - The SQL lives in `internal/pgschema/mfa.go` as `EnrolmentChargeVerifyAttempt` and `EnrolmentRefundVerifyAttempt`, used by `sqlstore`, `pgx` and `gorm`.
  - The columns are folded into the security-state migration file, before the first tag, as earlier changes did.
- **Precision:** `timestamptz` keeps microseconds. The give-back compares the window end it was given, so each adapter truncates `at + window` to microseconds before writing, and returns what it wrote. The memory store truncates the same way, so all backends agree.

### 9. Test-first, and the first red step

The first red step is a test in `mfa`. It sends 20 concurrent wrong codes for one user through `VerifyThrottle` and `TOTP.Verify`, with a limiter whose `Exceeded` holds every caller at a barrier until all 20 have checked, so the overlap is deterministic. It asserts that at most 5 codes were compared, counted as `ErrInvalidCode` results. On the current code it fails with 20 compared. A second test, at the endpoint in `httpsec`, does the same through the interceptor.

The store suites follow the existing pattern:
- cases in `RunEnrolmentStoreSuite`;
- a charge rule in `race.go` with 20 racers per enrolment against a limit of 5;
- a `storefix` race fixture;
- broken-store variants for an uncapped charge, read-then-write, a window that never ends and a give-back that ignores its window, each shown to be caught by its named case.

They run against memory, `sqlstore`, `pgx` and `gorm`.

### 10. A gorm handle that carries an error is refused where it is resolved

A gorm handle can carry an error, as `Begin` does when it fails. gorm then skips every statement run on it. A builder chain reports that error in its result, but `Raw(...).Row()` returns a nil `*sql.Row`, and `Scan` on it panics. That breaks the settled rule that database failures are errors.

- **Where:** `conn` in `gorm/tx.go` returns the handle's error, before any statement, whenever the resolved handle carries one. It does this for a transaction attached with `WithTx`, one returned by a resolver, and the base handle alike. Every gorm store operation already resolves its handle there and wraps the error with its operation name, as it does for `ErrNilTransaction`.
- **Alternatives considered:** a guard at each `.Row()` site. It fixes today's six sites, but the next store that reads a row repeats the panic. The guard in `ChargeVerifyAttempt`, added in group 1, becomes redundant and is removed.
- **Effect on other operations:** builder-chain operations already returned this error from their result. They now return it before running, wrapped the same way, so their observable outcome is unchanged.
- **Proof:** `TestStores_FailedHandleIsAnError` (`go test -race -run TestStores_FailedHandleIsAnError ./` in `gorm`) panicked with `runtime error: invalid memory address or nil pointer dereference` in `database/sql.(*Row).Scan`, without the guard, for six cases:
  - the enrolment charge;
  - the recovery record's latest completion;
  - the recovery-code match;
  - the passkey user for a handle;
  - the passkey credential charge, through `returning`;
  - a resolver's handle.

  The enrolment give-back, the passkey handle assignment and a builder-chain operation already returned the error. They stay as pins and are not claimed.
- **No override.** Returning an error for a failed handle is the settled contract, not a policy.

## Risks / Trade-offs

- **[Risk] Burst at a window edge.** 5 charges just before a window ends and 5 just after can be compared within seconds, so the hard cap is 2× the limit over any 15-minute span. → This is still independent of concurrency. The sliding per-user limiter refuses the second five when they are not concurrent. The godoc of `WithVerifyAttempts` states the 2× bound.
- **[Risk] A legitimate user locked out by an attacker's guesses.** This is the same exposure the per-user limiter already has, and it lasts at most one window. → The window is replaceable. An operator reset (`Delete`, then a new `PutPending`) clears the count.
- **[Risk] An extra write on every verification**, plus a second write on success. → Both are single-row updates on a unique key. This is the same cost as `AcceptStep`, which already runs on every success.
- **[Risk] A consumer's own `EnrolmentStore` stops compiling.** → It is pre-tag. The conformance suite gives them the cases to implement against.
- **[Trade-off] The charge is per enrolment, not per method.** A user enrolled on TOTP and passkey has the cap only on TOTP. Passkey challenges are already single-use per challenge.

## Migration Plan

Nothing is tagged. The columns are added to the existing security-state migration file, and the `migrate` tests cover the set. There is no data to migrate and no rollback beyond reverting the change.

## References

### Attempt limits on one-time codes (decisions 1–4)

**Researched (accessed 2026-10-03):**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: at most 100 consecutive failed attempts per account. The default here is far stricter.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): strict attempt limits on one-time codes.
- [OWASP ASVS 5.0, V6 Authentication](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): rate limiting on out-of-band and one-time codes.

**Primary documentation:**
- [RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2): the validation window of one step either side and one-time use, which give three valid codes per guess.
- [PostgreSQL: Read Committed isolation](https://www.postgresql.org/docs/current/transaction-iso.html#XACT-READ-COMMITTED): a concurrent `UPDATE` waits for the row lock and re-evaluates its `WHERE` against the updated row (decision 2).

### A gorm handle that carries an error (decision 10)

**Researched (accessed 2026-10-04):**
- [GORM: Error Handling](https://gorm.io/docs/error_handling.html): a `*gorm.DB` carries an `Error` field, set when an error occurs and checked after a chain. The page does not say whether later operations on that handle run. That gorm skips them, and that `Row()` then returns nil, is shown by the reproducing test, not by this page.

Otherwise reasoned from scrty's own settled `security-state-stores` spec ("Database failures are errors, never refusals or absence").

### The charge model and the scope (decisions 5–8)

Reasoned from scrty's own settled specs (`multi-factor-auth`, `passkey-authentication`, `account-recovery`, `security-state-stores`) and the established design.
