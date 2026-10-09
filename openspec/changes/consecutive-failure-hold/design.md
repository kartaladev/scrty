## Context

See `proposal.md` (Why) for the motivation and `specs/` for the requirements. This section gives only the current state that shapes the approach.

- **Failures are a log.** `policy.AttemptStore` has three methods: record a failure at an instant, count the failures strictly after a cutoff, and reset an identifier. Every lock is worked out from the log at evaluation time, and there is no per-identifier lock record (`policy/lockout.go`, "There is no unlock call and no lock record"). The three durable stores (`sqlstore`, `pgx`, `gorm`) keep one `login_attempts` row per failure, and take part in an ambient transaction. The in-memory store keeps a slice of instants per identifier.
- **A consecutive count cannot come from the log.**
  - The log is pruned at the lockout window (24 hours by default) by `LockoutExpiryTask`, and `FailureCount` takes a cutoff.
  - Keeping the log for 30 days instead would make every count scan up to a month of rows per request, and the default window would no longer bound storage.
- **Login records into the store it is handed.** Form login and Basic write to `FormLoginDeps.Attempts` and `BasicAuthDeps.Attempts`. The policy's `Attempts()` view records through to its store and reports to the observer (`lockout-honest-defaults`, decision 5). Only the policy knows its threshold, window, and, after this change, its cap and retention.
- **The chain can ask its engine what is wired.** `policy.Engine` already answers construction-time questions about its registered policies (`CanChallenge`, `UnwiredFederatedAssurance`), without exposing them.
- **A successful Basic authentication clears nothing.** `httpsec/basic.go` records failures but never calls `Reset`, while form login does (`httpsec/login.go:343`). The `security-policy` requirement "Accounts lock after repeated failures" says failures are "cleared after a successful authentication, through the attempt store". UNREPRODUCED: no test yet shows a Basic success leaving failures counted. The first task writes it.
- **A held user can still get back in.** A recovery with two recovery codes, or with a code and an MFA code, never checks the password. The resulting session becomes full only by binding an authenticator, which includes a password change at the resolve endpoint. That change already resets the username's failures through the chain's attempt stores (`httpsec/passwordchange.go`).
- **Nothing is tagged.** Before the first tag the security-state migration is edited in place (archived `oidc-mfa-assurance` and `default-identity-store` designs).

## Goals / Non-Goals

**Goals:**
- A consecutive count that one atomic write advances, so concurrent failures can neither be lost nor double-count past the cap.
- A cap that can only be enabled with wiring that actually advances the count. Any other wiring fails at construction, never at the first attack.
- Every path that ends a hold (a password change, a recovery followed by a password change, the policy's reset) already exists and needs no new consumer wiring.

**Non-Goals:**
- Any change to `policy.AttemptStore`. A consumer's own attempt store keeps compiling and working without a cap.
- Disabling other authenticators. NIST disables the authenticator that failed. Passkeys, MFA methods and API keys are unaffected.
- Holding an identifier for failures recorded outside the policy's view, such as by the consumer's own code writing to the raw store.

## Decisions

### 1. The count lives in a streak record, behind a new optional store contract

A new interface (name provisional: `policy.FailureStreakStore`) keeps one record per identifier: the consecutive failure count, the instant of the newest failure, and the instant the identifier became held (unset while not held). Its operations:
- **add a failure** at an instant, given the retention cutoff and the cap. It advances the count in one atomic write and returns the resulting record.
  - A record whose newest failure is at or before the cutoff, and which is not held, restarts at one.
  - The hold is set by the write that reaches the cap. Once set it is never moved.
- **read** the record, given the retention cutoff. A record that is not held, and whose newest failure is at or before the cutoff, reads as empty.
- **delete inactive records** whose newest failure is strictly before a cutoff and which are not held, for the expiry sweep. A zero cutoff is refused, as for `DeleteAttemptsBefore`.

A store that implements the contract SHALL also clear the identifier's streak, hold included, in its `Reset`, in the same transaction as the log rows. Every existing reset path, whether a successful login, a password change or the policy's `Reset`, then lifts a hold with no new call.

The in-memory store and the three durable stores implement it. A conformance suite in `test/storetest` runs against all four, and includes a race case: N concurrent adds past the cap set the hold exactly once, and the count equals N plus the prior count.

- **Default:** the contract is not used unless a cap is configured.
- **Override:** a consumer can implement the contract on their own store.
- **Alternatives:**
  - Widen `AttemptStore.RecordFailure` with the cap and the cutoff. Rejected: it breaks every consumer's store to serve an opt-in.
  - Derive the count from the log, kept for the retention period. Rejected for the cost and the storage reasons in Context.
  - Store only a count and decide the hold at evaluation, with count at or above the cap meaning held. Rejected: the restart after inactivity must be decided at write time, against the cap. Otherwise a stale 99 plus one fresh failure would hold an account that has failed once in a month.

### 2. The policy's view advances the streak, and the chain refuses a capped policy whose view it was not given

`WithLockoutCap(n)` enables the cap. The policy's `Attempts()` view, which every login endpoint is already told to use, adds the failure to the streak, with the policy's retention cutoff and cap, and then records it in the log. The streak is written first, because it is the record that cannot be rebuilt.
- A failure of either write is returned to the caller.
- The chain already logs a failed record with fixed text, and the windowed lock and the hold each fail closed on a failed read.

At construction:
- `NewAccountLockoutPolicy` refuses a cap when its store does not implement the streak contract.
- The engine gains a construction-time question: the views of its registered policies that must be used. A chain whose engine holds a capped lockout policy refuses construction when form login or Basic is handed any store other than that view, compared as the password-change gate already compares stores. The error names the endpoint's `Attempts` field and the policy's `Attempts()`.

This makes the cap a wiring that cannot be silently disarmed. It is stricter than the observer, where a raw store stays valid wiring that only loses reports (`lockout-honest-defaults`, Risks). Losing a report is visible; losing a hold is not.

- **Default:** no cap.
- **Override:** `WithLockoutCap(n)`. A consumer that does not use the chain's login endpoints records through `AccountLockoutPolicy.RecordFailure`, which goes through the same view.
- **Alternatives:**
  - Let the durable stores advance the streak inside their own `RecordFailure`. Rejected: they would need the cap and the retention as store configuration, a second copy of the policy's settings that can drift from it.
  - Keep a raw store valid and document that it disarms the cap. Rejected: it breaks library-design §4, because the configuration would be accepted and quietly degraded.

### 3. Evaluation refuses a held identifier first, with a refusal the consumer can tell apart

When a cap is configured, pre-authentication reads the streak first. A held identifier is refused with the account-locked refusal, carrying no wait and also identifiable as the hold (provisional: `policy.ErrAccountHeld`). The windowed evaluation is not consulted. When the identifier is not held, the existing threshold, wait and ceiling evaluation runs unchanged. A failed streak read denies with a reason wrapping the store's error, as a failed count does.

The chain's existing concealment needs no change:
- By default a locked refusal is an authentication failure with the decoy spent.
- With disclosure chosen it is answered 429.
- Unknown identifiers are held and refused exactly as known ones are.
- **Default:** the refusal is concealed as an authentication failure, per the existing chain behaviour.
- **Override:** the chain's existing disclose-locks option. A consumer's own error handling may check for the hold, for example to suggest a password reset.
- **Alternatives:** a refusal identical to other locks. Rejected by the user: a consumer could not tell the user to reset instead of waiting.

### 4. The count expires after 30 days of inactivity; a hold never expires

`WithLockoutCapRetention(d)` sets how long a count below the cap lives after its newest failure. The default is 30 days.
- A count whose newest failure is older is no longer counted, and the next failure starts a new count.
- The login-attempt expiry task also deletes such records, with the cutoff derived from the policy's own retention. That is the same rule the policy applies, so a sweep never changes a decision (expiry-sweeping).
- A held record is never deleted by the sweep and never expires.

Under the default escalating waits, the windowed ceiling allows about 24 failures a day, so reaching a cap of 100 takes about four days. The retention bounds guessing to at most the cap per 30 days of an account's inactivity. That is far below the windowed ceiling's roughly 720 a month.

- **Default:** 30 days.
- **Override:** `WithLockoutCapRetention(d)`.
- **Configuration errors:**
  - a retention of zero or less;
  - a retention without a cap, which is meaningless;
  - a retention shorter than the lockout window, because a count would then expire while the windowed lock still counts its failures;
  - a cap of zero or less;
  - a cap not above the threshold, because the first lock would then already be a hold.
- **Alternatives (decided by the user):**
  - Never expire. Rejected: every mistyped identifier keeps a record forever, and the sweep cannot prune them.
  - Expire at the lockout window. Rejected: the cap would almost never trigger under the default waits.

### 5. A cap above 100 is allowed, and documented as outside NIST

NIST's 100 is an upper bound, and lower values are permitted. A cap above 100 is accepted. The godoc of `WithLockoutCap` states that it no longer meets SP 800-63B-4 §3.2.2's limit.

- **Default:** no cap. `WithLockoutCap(n)` takes the cap explicitly, and a named constant (provisional: `policy.NISTLockoutCap`, 100) is the documented value to pass for NIST's limit, following library-design §3's named-constant conventions.
- **Override:** any value above the threshold.
- **Alternatives:** refuse values above 100. Rejected: a consumer with their own risk controls may choose otherwise, and library-design §4 asks for flexibility up to a stated line, not a refusal where nothing breaks.

### 6. A successful Basic authentication resets through the attempt store, as form login does

On success, Basic calls the attempt store's `Reset` for the username, logged with fixed text on failure, exactly as form login does. This brings Basic in line with the existing requirement that failures are cleared after a successful authentication. With a cap configured it is also what clears a Basic user's streak.

- **Default:** on. It is a correction to existing behaviour, not an option.
- **Override:** none. Keeping failures after a proven password protects nothing, and makes a cap hold a user whose credentials are correct.
- **Cost:** one indexed delete per successful Basic request on a durable store. Recorded under Risks.
- **Departure:** the established design also left Basic successes uncleared. scrty departs from it because its own settled requirement already says failures are cleared on success. The departure is pending reproduction: the first task writes the failing test.

### 7. The observer is told of a hold and of its release

The view reports:
- a new kind (provisional: `LockoutHeld`) on the failure that sets the hold. This is the one write the store reports as having set it, so the report is exact even under concurrency, unlike the threshold crossing (`lockout-honest-defaults`, decision 5);
- a release (provisional: `LockoutReleased`) in place of `LockoutCleared` when a reset clears a held identifier.

Further failures that race the hold are reported as before, at or above the ceiling or the threshold. Reports carry the identifier as submitted, so known and unknown identifiers are reported alike.

Two edges are decided here:
- **A hold is reported even when the log write failed.** The streak is written first. When it reports that it set the hold and the log write then fails, the hold is still reported, with both errors returned. No later write sets the hold again, so withholding this report would lose it for good. This is the one exception to "a failure the store could not record is not reported".
- **A reset whose streak cannot be read reports nothing.** The policy cannot then tell a release from a clearing. The reset still happens, and the lost report is logged with fixed text.

A release is reported whatever the window holds, and carries the consecutive count.

The kind of a reset's report is read before the store's reset, in a separate step. A failure that sets the hold between the two is reported as held, and the reset that lifts it is reported as cleared rather than released; two concurrent resets of one held identifier may both report a release. The reset itself is the store's single atomic operation and is never affected. Reports are advisory, so this is accepted and documented rather than closed by widening the store contract to return what `Reset` removed.

- **Default:** no observer, as before.
- **Override:** `WithLockoutObserver`.

## Risks / Trade-offs

- **[An attacker who knows a username holds it on purpose]** → This is the reason the cap is opt-in.
  - Recovery with codes still works while the account is held, and needs no password (OWASP's mitigation).
  - The per-source guard (50 failures per 15 minutes) and the escalating waits slow a single source to about 24 failures a day, so one source needs about four days to reach the cap.
  - The godoc of `WithLockoutCap` states the risk and these mitigations.
- **[Held records for unknown identifiers are never pruned]** → Each one costs an attacker about 100 failures, paced by the waits. A spray grows the table by one row per held name. The godoc states it, and a consumer can clear records with the policy's `Reset`.
- **[Two writes per failure through the view: the streak and the log]** → The streak is written first. If the log write then fails, the windowed lock under-counts by one, which was already the outcome of a failed log write. Both errors are returned.
- **[A Basic success now writes]** → One delete per successful request, on an indexed column. It is a no-op when there is nothing to clear. Consumers with very hot Basic traffic see the cost, and the godoc says so.
- **[The cap counts only failures recorded through the view]** → Enforced at chain construction (Decision 2) for the chain's endpoints. A consumer recording elsewhere is told to record through `AccountLockoutPolicy.RecordFailure`.
- **[Folding into the initial migration conflicts with `shared-rate-limiting-postgres`]** → Both add a table to the same file. Whichever lands second rebases.

## Migration Plan

Nothing is tagged, so the table is folded into `migrate/securitystate/20260926000000_security_state.sql`. A database created from the earlier fold is recreated, as before the first tag. Rollback is a revert. Consumers without a cap see one behaviour change: a successful Basic authentication now clears failures.

## Open Questions

- The final names of the store contract, its record type, the cap constant and options, the hold error and the report kinds. These are deferrable: the spec fixes their behaviour, not their names.

## References

**Researched (accessed 2026-10-09):**

*Decisions 1, 3 and 5: the cap, the hold, and its upper bound:*
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: no more than 100 consecutive failed attempts per authenticator; disabling until rebound; a success SHOULD disregard earlier failures; lower limits MAY be imposed.
- [Okta password policies](https://help.okta.com/en-us/Content/Topics/security/policies/configure-password-policies.htm): a maximum of 100 attempts before a lock.

*Decisions 2 and 3, and Risks: what lifts a hold, and deliberate lockouts of other people's accounts:*
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), Account Lockout: the denial-of-service risk; the forgotten-password function must work while locked; count per account; identical responses for unknown and locked accounts.
- [Keycloak brute-force detection](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/threat/brute-force.adoc): permanent lockout until an administrator re-enables; the count resets on success.
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout): self-service password reset lifts the lock.
- [Auth0 brute-force protection](https://auth0.com/docs/secure/attack-protection/brute-force-protection): unblock by password change, administrator or emailed link.

*Decision 4: retention of the count:*
- [Auth0 brute-force protection](https://auth0.com/docs/secure/attack-protection/brute-force-protection): a block lapses 30 days after the last failure, the precedent for a 30-day inactivity period.

*Decision 6: clearing on success:*
- [ASP.NET Core Identity lockout options](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration): a successful authentication resets the failed-attempt count.
- Otherwise reasoned from scrty's own settled specs (`security-policy`, "Accounts lock after repeated failures") and the established design.

*Decision 7: reporting:* reasoned from scrty's own settled specs (`lockout-honest-defaults`, decision 5); no external source.

**Unverified:**
- NIST SP 800-63B-4 §4.1 and §4.2 (rebinding and account recovery): only §3.2.2's reference to them was read.
- How any product bounds storage for counts kept against unknown identifiers.
