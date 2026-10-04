# Design

## Context

See proposal.md for why. The current state:

- **Lockout policy.** `policy.AccountLockoutPolicy` runs in the pre-authentication phase. It denies once an identifier has 5 failures in 15 minutes, a hard lock, counting them through `AttemptStore.FailureCount(ctx, username, since)`. `Reset` clears them on success.
- **Recording failures.** Form login (`httpsec/login.go`) and Basic (`httpsec/basic.go`) record failures through the same `AttemptStore`, on the request's context.
- **No per-source guard on login.** Every other guessable flow builds one through `resolveSourceGuard` (`httpsec/throttle.go`), from the chain's `LimiterFactory`.
- **Status mapping.** `httpsec/status.go` maps `policy.ErrAccountLocked` to 423. It maps `authenticate.ErrAuthenticationFailed` and `ratelimit.ErrThrottled` to 401, and the authentication-failed row comes first. A joined error carrying both the authentication failure and the lock therefore maps to 401.
- **Decoy work.** The password provider already verifies a reference hash for an unknown user (`authenticate/password.go`). Nothing outside it can ask for that work.
- **The established design** has a hard lock, answers 423, puts no per-source limit on login, and records on the request's context. Decisions 2 and 3 below depart from it, and are recorded as departures. Decision 1 adds behaviour. Decision 4 fixes a claimed defect, pending reproduction.

## Goals / Non-Goals

**Goals:**
- Bound password spraying per source.
- Stop lockout working as a lever an attacker can pull on someone else's account.
- Stop the login response revealing a lock.
- Count every login failure, even from a client that disconnects.

**Non-Goals:**
- **Distributed credential stuffing** from many sources. Per-source limits cannot stop it (OWASP Credential Stuffing cheat sheet). It is a stated limit, and the IPv6 aggregate from `limiter-key-bounds` narrows it.
- **CAPTCHA or bot detection.** NIST names it as one way to protect legitimate users from lockout. It belongs to the consumer's front end, not to a library.
- **Changing the `AttemptStore` port or its schemas.** Decision 2 is built on `FailureCount` as it stands.
- **The `rate-limiting` spec.** The guard reuses the source guard unchanged. The proposal listed it, and is corrected. (`http-error-propagation` does change: decision 3 moves the account-locked row to 429.)

## Decisions

### 1. One per-source guard, flow `password-login`, shared by form login and Basic

The chain builds one source guard for the flow `password-login`, using `resolveSourceGuard` like every other guarded flow, and gives it to both endpoints. A source that sprays across both channels therefore spends one allowance.

**Order of steps:**
1. Read the credentials.
2. Check the source. A throttled or unattributable source is refused before the pre-authentication phase and before any password work.
3. Run pre-authentication.
4. Authenticate.

**What is recorded against the source:**
- Every authentication failure.
- Every account-locked refusal. An attacker hammering a locked account spends its own allowance. A legitimate user retrying a locked account spends theirs too, but 50 is far more than one person retries.
- Successes spend nothing.

**Basic:** a throttled refusal also carries `WWW-Authenticate`. RFC 9110 §15.5.2 requires the header on every 401, and its absence would also single out a throttled response.

**Default:** 50 failures per 15 minutes, built from the chain's factory under namespace `password-login`.
- Fifty bounds one source to 50 accounts sprayed per window.
- It leaves room for an office NAT or carrier-grade NAT, where many users share one address and some mistype.
- When `limiter-key-bounds` lands, its IPv6 aggregate applies to this guard as to every guard `resolveSourceGuard` builds.

**Override:**
- `httpsec.WithLoginLimiter(l)` (a `LoginOption`) gives form login its own limiter.
- `httpsec.WithBasicAuthLimiter(l)` (a `BasicAuthOption`) does the same for Basic.
- An endpoint without one keeps the shared default.
- A nil limiter, typed nil included, is a configuration error naming the option, as for every other flow's limiter option.
- The limit and window are changed by supplying a limiter, as for every other flow.

**Alternatives:**
- *Separate guards per endpoint.* Spraying through both doubles the allowance.
- *20 per 15 minutes.* A shared address could be throttled by its own users' typos.
- *100 per 15 minutes.* Twice the spraying reach.

### 2. Escalating wait replaces the hard lock by default (departure)

The policy's default becomes an escalating wait.

1. Count the failures in the window: `n = FailureCount(now − window)`.
2. If `n` has reached the ceiling, deny.
3. Otherwise, if `n` has reached the threshold, compute `wait = min(firstWait · 2^(n−threshold), longestWait)`, and deny when `FailureCount(now − wait) > 0`, meaning the newest failure is more recent than the wait.

Below the threshold this costs one store query, and two at or above it. The port is unchanged, so every existing adapter (memory, `sqlstore`, `gorm`, `pgx`) works without migration.

**Defaults:**

| Setting | Default | Why |
|---|---|---|
| threshold (free failures) | 5 | unchanged |
| window | 24 hours | NIST counts consecutive failures, and a successful login already clears them. 24 hours bounds what the store holds. |
| first wait | 30 seconds | NIST's example range starts at 30 seconds |
| longest wait | 1 hour | NIST's example range ends at an hour |
| ceiling | 100 | NIST SP 800-63B-4 §3.2.2's cap |

- After the ramp, an attacker gets about one guess an hour per account, roughly 24 a day, which stays below the ceiling. That is per request in flight when a wait lapses: the policy checks and the flow records through the unchanged port, so a concurrent burst gets one guess per request (see Risks).
- The account's owner is never locked out for longer than an hour unless the ceiling is reached, and a correct password after the wait clears everything.
- Attempts refused during a wait are not recorded against the account. Recording them would let an attacker keep the wait running without making a guess. They are recorded against the source (decision 1).

**Override:**
- `WithLockoutThreshold`, `WithLockoutWindow` and `WithLockoutClock` keep their meaning.
- `WithLockoutWait(first, longest)` and `WithLockoutCeiling(n)` are new.
- `WithFixedLockout(threshold int, window time.Duration)` restores the established hard lock, with its own parameters. Combining it with `WithLockoutWait`, `WithLockoutCeiling`, `WithLockoutThreshold` or `WithLockoutWindow` is a configuration error, because each of those would silently mean something different under a fixed lock.

**Construction errors:** a non-positive threshold, window or first wait; a longest wait shorter than the first; a ceiling not above the threshold.

**Compatibility:** `WithLockoutThreshold(n)` with `n` at or above 100, valid before, is now a configuration error unless `WithLockoutCeiling` raises the ceiling above it, or `WithFixedLockout` is used instead. Recorded as a default change before the first tag (library-design rule 7). A ceiling above 100 is allowed, and godoc names it as a departure from NIST.

**Departure from the established design:**
- The hard 5-per-15-minutes lock lets anyone who knows a username keep its owner out indefinitely.
- ASVS 6.1.1 requires controls that "prevent malicious account lockout", and NIST lists escalating waits as the way to reduce lockout of legitimate users.
- The established behaviour stays available as `WithFixedLockout(5, 15*time.Minute)`.

**The refusal:** it is a `*policy.LockoutError{Wait time.Duration}` that `errors.Is` matches to `ErrAccountLocked`.
- `Wait` is the full escalated wait, an upper bound on what remains. With counts alone the store cannot say when the newest failure was.
- `Wait` is zero at the ceiling and under a fixed lock.
- A consumer that discloses locks (decision 3) can render it as `Retry-After`. The library writes no header.

**Alternatives:**
- *Keep the hard lock.* The lockout lever stays.
- *A growing lock period.* It needs a lock history, which means a port change and migrations in every adapter.
- *Sleep server-side instead of refusing.* That holds a connection for every attempt, so an attacker could tie up the server's connections.

**Pinned edge case: the newest failure exactly `wait` ago.** `FailureCount` counts failures strictly after `since`, so a failure exactly `wait` old no longer counts and the attempt is allowed. This matches the window boundary in the rate-limiting spec.

### 3. Locked-account refusals look like a wrong password by default (departure)

When pre-authentication denies with `ErrAccountLocked`, form login, Basic and account recovery's password proof by default:
1. spend a decoy verification on the presented password;
2. return `errors.Join(authenticate.ErrAuthenticationFailed, reason)`;
3. for Basic, set `WWW-Authenticate`.

Account recovery's password proof goes through the same login code (`checkPassword`), so it gets the same concealed refusal. The recovery converts a check error wrapping the authentication failure into its own recovery-refused error. It keeps the check's error underneath, so a concealed lock answers recovery-refused (401), like an unknown user or a wrong code, and a consumer's handler can still identify the lock with `errors.Is`. Without this, recovery answered a locked account with the bare lock while an unknown username answered recovery-refused, which told a holder of a valid recovery code that the account exists and is locked.

The status table maps the joined error to 401, and a consumer's handler can still tell it is a lock with `errors.Is`. This satisfies the error-propagation spec's "Consumer identifies the refusal".

**Decoy:** a new optional interface in `authenticate`.

```go
// DecoyVerifier spends the password work a real verification would, on a
// refusal made before any password was checked. It reports nothing about the
// outcome; handled says only whether creds are of a kind it verifies, so a
// Manager can find the right delegate without calling Authenticate.
type DecoyVerifier interface {
	VerifyDecoy(ctx context.Context, creds identity.Credentials) (handled bool)
}
```

- The password provider implements it against its reference hash, without loading the user. Loading the user would let a slow user store reveal whether the account exists.
- `authenticate.Manager` implements it by offering the credentials to each delegate that implements `DecoyVerifier`, in order, and stopping at the first that reports `handled`. Support cannot be learned from `Authenticator` itself without authenticating, which is why the method reports it.
- The chain type-asserts its authenticator. If the authenticator offers no decoy and locks are not disclosed, `build` writes one WARN: lock refusals may then be told apart by their timing.
- `authenticate.Manager` always implements `DecoyVerifier`, so the assertion alone cannot tell whether a decoy will ever be spent. `Manager.OffersDecoy() bool` reports whether any delegate offers one: a delegate that implements `DecoyVerifier` and, if it also reports `OffersDecoy`, reports true. The chain warns when the authenticator is not a `DecoyVerifier`, or reports `OffersDecoy() == false`. Found in review: a manager over a non-decoy delegate was silent.
- Calling the consumer's authenticator itself was rejected. A directory-backed authenticator could count the attempt against its own lockout, or record it as a guess.

**Default:** undisclosed. **Override:** `httpsec.WithLockDisclosure()`, a chain `Option` that governs the response to a lock at form login, Basic and recovery's password proof, and nothing else. With it, the refusal is the `LockoutError` alone, mapped to 429, and no decoy runs.

**The disclosed status is 429, not 423 (departure).** The status table's account-locked row moves from 423 to 429, joining too-many-sessions.
- RFC 4918 §11.3 defines 423 for a WebDAV resource that is locked. It says nothing about an account.
- RFC 6585 §4 defines 429 for a client that "has sent too many requests in a given amount of time", which is what a lock under decision 2 is, and lets the response carry `Retry-After`. The `LockoutError.Wait` a consumer reads maps onto it directly. The library still writes no header.
- Established practice: Auth0 answers its brute-force block with 429. No major identity product found answers an account lock with 423.
- A 429 is not a 401, so a disclosed Basic lock carries no `WWW-Authenticate`.
- *Alternative, keep 423:* it is the established mapping, but it borrows a WebDAV status for something it does not describe, and offers no standard place for the wait.

**Departure from the established design:** a distinct lock status, and a refusal that returns faster than a password check, both tell an attacker that the identifier is a locked account that exists. The OWASP Authentication cheat sheet lists "The account is locked or disabled." among the incorrect responses, and warns that "the HTTP response code may differ which can leak information about whether the account is valid or not."

**Cost:** one password hash per refused attempt. The per-source guard (decision 1) bounds it, because locked refusals count against the source.

### 4. Failures are recorded on an uncancellable context (pending reproduction)

**Claim, `UNREPRODUCED`:** login records the failed attempt on the request's context. An attempt store that honours cancellation, which SQL drivers do, then drops the failure of a client that disconnects as soon as it has sent its guess. That is a free guess.

- **First red step:** a typed `MockAttemptStore` whose `RecordFailure` returns `ctx.Err()`, and a form login whose context is cancelled before recording. It runs on the unchanged code. Basic gets the same test.
- **Fix:** record on `context.WithoutCancel(ctx)`, as `SourceGuard.RecordFailure` already does. The source-guard failure is uncancellable already.
- **If the test passes on the unchanged code,** the claim is wrong. The decision is removed and nothing changes.
- **No override.** A failure that goes uncounted is a free guess, never a policy choice.

## Risks / Trade-offs

- **[Distributed spraying from many addresses passes the per-source guard]** → Stated as a limit. The escalating wait bounds each account. The IPv6 aggregate (`limiter-key-bounds`) bounds an allocation.
- **[A concurrent burst gets one guess per in-flight request each time a wait lapses]** → Check-then-record through an unchanged port is not atomic, so k simultaneous requests each pass pre-authentication before any records (reproduced at policy level in review). The hard lock had the same race once, at the threshold; the escalating wait reopens it at every lapse. Bounded per source by decision 1, not per account. Closing it needs an atomic count-and-record port, which this decision rejects; it is a stated limit, as for the rate limiter's own burst bound.
- **[A shared address's own users trip the guard]** → The 50 default leaves room. A consumer gives the endpoint its own limiter.
- **[An attacker who guesses steadily can keep an account's owner waiting up to an hour at a time]** → This is NIST's accepted cost of escalating waits, far below the hard lock's indefinite lockout. A correct password after any wait clears it, and the ceiling is unreachable at about 24 guesses a day.
- **[The in-memory attempt store now holds failures for 24 hours, not 15 minutes]** → Memory grows with failing usernames over a longer span. A deployment of more than one replica already needs a durable store, whose purge (`PurgeExpired`) uses the policy's own window.
- **[A concealed lock still answers a little sooner than a wrong password]** → A wrong password costs a user load, a password check and an attempt-store write; a concealed lock costs only the decoy check. The password check dominates, so the gap is one user-store read and one attempt-store write. Recording a failure on a lock is rejected (decision 2: it would let an attacker keep the wait running), and loading the user would let a slow user store reveal existence. Accepted as a stated limit.
- **[A decoy hash per locked refusal costs CPU]** → Bounded per source by decision 1. A consumer that discloses locks skips it.
- **[A consumer's own handler can still render "locked" from the joined error]** → That is the consumer's choice, and the godoc of `WithLockDisclosure` says so.

## Migration Plan

Before the first tag, so these are recorded default changes, not breaking releases. On upgrade:
- the lockout policy waits instead of hard-locking;
- a lock answers 401 instead of 423, and 429 when disclosed;
- login gains a per-source guard, which means one more factory call, namespace `password-login`.

A consumer wanting the old behaviour uses `WithFixedLockout(5, 15*time.Minute)` and `WithLockDisclosure()`; the disclosed status is then 429, not 423, and a consumer who needs 423 maps `policy.ErrAccountLocked` in their own error handler.

## References

**Researched (accessed 2026-10-04):**

*Decision 2, escalating wait and ceiling:*
- [NIST SP 800-63B-4, §3.2.2 Rate Limiting](https://pages.nist.gov/800-63-4/sp800-63b.html):
  - at most 100 consecutive failed attempts per account;
  - waits that grow as the account nears that cap ("30 seconds up to an hour") as a way to avoid locking out the legitimate claimant;
  - previous failures disregarded after a successful authentication.
- [OWASP ASVS 5.0, V6 Authentication, 6.1.1 and 6.3.1](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): controls against brute force must be documented and "prevent malicious account lockout".
- [OWASP Authentication Cheat Sheet, Account Lockout](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): exponential lockout over a fixed duration, and the denial-of-service risk of lockout.

*Decision 3, generic response:*
- [OWASP Authentication Cheat Sheet, Authentication and Error Messages](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): "The account is locked or disabled." is listed as an incorrect response, and a differing HTTP response code "can leak information about whether the account is valid or not" (quotes re-checked 2026-10-04).

*Decision 3, disclosed status:*
- [RFC 4918 §11.3, 423 Locked](https://www.rfc-editor.org/rfc/rfc4918#section-11.3): "The source or destination resource of a method is locked", a WebDAV resource lock.
- [RFC 6585 §4, 429 Too Many Requests](https://www.rfc-editor.org/rfc/rfc6585#section-4): too many requests in a given amount of time; may carry `Retry-After`.
- [Auth0 Brute-Force Protection](https://auth0.com/docs/secure/attack-protection/brute-force-protection): a blocked login answers 429 `too_many_attempts`.

*Decision 1, per-source guard:*
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): password spraying, and the limits of per-IP blocking (carried from the proposal, accessed 2026-10-03).

**Primary documentation:**
- [RFC 9110 §15.5.2, 401 Unauthorized](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2): a 401 response must carry `WWW-Authenticate` (decision 1, Basic throttled refusals).

Decision 4 is reasoned from scrty's own settled specs and the established design.
