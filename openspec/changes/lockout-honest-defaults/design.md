## Context

See `proposal.md` (Why) for the motivation and `specs/` for the requirements. This section gives only the current state that shapes the approach.

- **Login does not go through the policy to record failures.** Form login and Basic write to a `policy.AttemptStore` that the consumer hands to each of them (`FormLoginDeps.Attempts`, `BasicAuthDeps.Attempts`). The godoc of those fields tells the consumer to "supply the same store the account-lockout policy reads". `AccountLockoutPolicy.RecordFailure` and `Reset` exist, but nothing in the chain calls them. A hook that lives only inside the policy would never see a login failure.
- **Failures are keyed by the submitted identifier**, stored and matched exactly as given (`policy/attempts.go`). A session holds only the user reference (`session.Session.UserID`). The bearer step loads the user by the token's subject, which is the username (`LoadByUsername(claims.Subject())`, `httpsec/bearer.go:119`), and puts an `identity.Principal` carrying `Username` in the request context.
- **The password-change resolve endpoint** runs the consumer's `ChangePasswordFunc`, which owns the response. When the function succeeds, the gate clears the pending marker (`httpsec/passwordchange.go`). The gate has no attempt store today.
- **`WithFixedLockout` callers** (gopls references): `policy/lockout_config_test.go`, `policy/lockout_test.go`, `policy/lockout_error_test.go`, `httpsec/chain_login_guard_test.go`, `httpsec/recoverycomplete_test.go`, `test/expirytasks_test.go`. All are tests. No production code outside `policy` calls it.
- **The windowed ceiling** comes from the settled design of `login-source-throttling` (decision 2). This change keeps it, and corrects only how it is described.

## Goals / Non-Goals

**Goals:**
- Every lockout behaviour a consumer can configure has a name and godoc that say what it does, and tests that pin it.
- A password change made through the chain needs no extra wiring to clear the user's failures.
- Lockout reporting is free of races: two concurrent failures cannot cancel each other's report.

**Non-Goals:**
- Any change to the attempt-store port, the four stores or the schema.
- Exactly-once reporting of a threshold crossing. Without a port change it cannot be done (Decision 5).
- Clearing failures recorded under other spellings of a user's identifier (Decision 4).

## Decisions

### 1. `WithFixedLockout` becomes `WithSlidingLockout`

The behaviour, signature and configuration-error rules are unchanged. Only the name and the godoc change. The godoc says the option limits the failure rate within the window, holds no lock of fixed duration, and lifts as soon as enough failures leave the window. It points to Decision 2 for a lock of fixed duration. The validation list in `NewAccountLockoutPolicy` names the new option.

- **Default:** none. This is an opt-in option, and the escalating wait remains the default.
- **Override:** it is itself an override of the default.
- **Alternatives:**
  - Keep the name and fix only the godoc. Rejected: the name is the defect. A consumer reads `WithFixedLockout` and does not read further.
  - `WithRateLimitLockout`. Rejected: "sliding" names the mechanism, and matches the sliding-window wording used elsewhere in rate limiting.
- **Compatibility:** nothing is tagged, so renaming costs nothing (library-design §7). The rename is recorded here as that decision.

### 2. A lock of fixed duration is a documented configuration, not a new option

`WithLockoutWait(d, d)` already produces a lock that lasts exactly `d` from the newest failure. Refused attempts are never recorded, so the lock lasts `d` from the failure that reached the threshold. This change does three things:
- documents this on `WithLockoutWait` and on the package;
- adds a godoc example that configures a fixed 15-minute lock;
- pins the behaviour with the boundary tests the spec states. The lock is still in force at 14:59 and lifted at exactly 15:00, because `FailureCount` counts strictly after its cutoff. That boundary is a reading of the code. The first test must be seen to fail before it counts as evidence.

The godoc also states where this differs from CIS. CIS clears the count when the lock ends. Here the count stays in the window, so each further failure locks again for `d`: one guess per `d` after the first lock, which is stricter than CIS. It makes no claim of PCI DSS conformance (see References: unverified).

- **Default:** unchanged (the escalating wait, 30 seconds to 1 hour).
- **Override:** `WithLockoutWait(d, d)`, together with `WithLockoutThreshold` and `WithLockoutWindow` as needed.
- **Alternatives:**
  - A preset, `WithFixedDurationLockout(d)`. Rejected for now:
    - it would be a second spelling of one behaviour;
    - it would add rows to the configuration-error matrix (preset combined with a wait, preset combined with the sliding lock);
    - it can be added later without breaking anything, if consumers ask for it.

### 3. The godoc describes the ceiling as what it is

The godoc of `defaultLockoutWindow`, `defaultLockoutCeiling`, the type documentation, `WithLockoutCeiling` and `NewAccountLockoutPolicy` currently calls 100 "NIST SP 800-63B's cap". It will say instead:
- the ceiling counts failures in the window, which age out;
- under the default policy, guessing is limited to about 24 a day per account, with no limit on the total;
- it does not disable the authenticator until it is bound again, as NIST §3.2.2 requires;
- the defaults keep NIST's 30-second-to-1-hour wait range, which is NIST's own example.

`WithLockoutCeiling`'s note that a value above 100 "departs from NIST's cap" is reworded to match.

- **Default:** unchanged (ceiling 100, window 24 hours).
- **Override:** unchanged (`WithLockoutCeiling`, `WithLockoutWindow`).
- **Alternatives:** none. A description that claims a guarantee the code does not give cannot stay.

### 4. The resolve endpoint clears the failures of the principal's username, through the chain's own attempt stores

When the consumer's `ChangePasswordFunc` succeeds, the gate clears failures for `Principal.Username`: the identifier the bearer step loaded the user by, and therefore the identifier that user signs in with.
- **Which stores.** At assembly, the chain hands the gate the attempt stores from `FormLoginDeps` and `BasicAuthDeps`. This is the same handover `wirePasswordChange` already does for logout. When both are present and are the same store, it is cleared once. A chain with neither enabled has no password lockout, so the gate clears nothing.
- **When.** Clearing runs as soon as the consumer's function succeeds, before the session is saved, on a context the client cannot cancel (as `recordFailure` does). A failed save does not undo a password that has already changed, and a client that hangs up after changing its password must still be cleared.
- **If it fails.** A failure is logged with fixed text and the store's error type, as `resetFailures` does, and the outcome does not change.
- **Default:** on whenever the gate has a resolve endpoint and the chain has a password login.
- **Override:** none. The resolve endpoint has just changed the password of the session's own user. The failures being cleared were guesses at a password that no longer exists, so they protect nothing. Keeping them only locks out the user who just proved they hold the account. A consumer who wants a stricter rule can still enforce it in their own `ChangePasswordFunc`.
- **Limit (documented):** only the exact username string is cleared. Failures recorded under another spelling (a different case, or an email alias that the consumer's loader also accepts) stay until they leave the window. This matches what a successful login's reset does today.
- **Outside the chain:** the godoc of `ChangePasswordFunc` and of the gate tells a consumer who changes passwords elsewhere to call `AccountLockoutPolicy.Reset`.
- **Alternatives:**
  - Leave it to the consumer's function. Rejected: unsafe by default, and easy to forget.
  - Load the username with `LoadByUserID(session.UserID)`. Rejected: it needs a new user-loader dependency on the gate, and the bearer step has already loaded the user.
  - A new attempt-store field on `EnablePasswordChangeGate`. Rejected: a third place to supply the same store, and a third chance to supply the wrong one.

### 5. Reports come from a recording view the policy hands out, one report per locking failure

The policy gains `WithLockoutObserver(func(context.Context, LockoutReport))` and a method that returns an `AttemptStore` view of its own store (name provisional: `Attempts()`). The consumer hands this view to `FormLoginDeps.Attempts` and `BasicAuthDeps.Attempts`, and those fields' godoc changes to recommend it. The view behaves like this:
- **`RecordFailure`** writes through. With an observer configured, it then reads `FailureCount` over the policy's window and reports when the identifier is now locked. The kind is `Ceiling` at or above the ceiling, and `Locked` at or above the threshold, which also covers the sliding lock.
- **`Reset`**, with an observer configured, reads the count first, and reports `Cleared` after a successful reset only if the count was above zero.
- **`FailureCount`** passes through.
- **Without an observer**, the view passes everything through, at no extra cost.

A report carries the identifier as submitted, the kind, the count and the instant. It never says whether an account exists, which the policy does not know anyway.
- **The observer runs synchronously, after the store write.** It returns nothing. A panic in it is recovered and logged with fixed text, so an observer cannot turn a refusal into a server fault, or change any decision or error. The record goes through `WithLockoutLogger`, a new option whose default is `slog.Default()` and which ignores a nil logger, as `WithMFAPolicyLogger` does.
- **Default:** no observer; nothing new is reported.
- **Override:** `WithLockoutObserver`.

Why one report per locking failure, rather than one per crossing: a crossing can only be detected by comparing the count before and after the failure. Two failures recorded concurrently can both read a count past the threshold, so the crossing goes unreported, and attacks arrive exactly as concurrent bursts. Reporting each failure that leaves the identifier locked never misses one and never reports one twice. The first report is the crossing.

- **Alternatives:**
  - An observer only on `AccountLockoutPolicy.RecordFailure` and `Reset`. Rejected: the chain never calls them (see Context).
  - An observer on the chain. Rejected: the chain does not know the threshold or the ceiling. A second copy of them would drift from the policy's.
  - Exactly-once crossing reports. Rejected: it needs the store to record and count atomically, which is a port change. That belongs with the later opt-in cap change, which changes the port anyway.
  - Reporting through `slog` by default. Rejected: the spec's default reports nothing new, and a log is not an audit API. An observer that logs is one line for the consumer.

### 6. Unknown usernames are pinned in the chain's conformance suite

The scenarios go into `test/httpsecconformance`, so that every framework adapter runs them, not only `net/http`. The policy-level part, where reports for unknown and known identifiers look alike, is a `policy` test. Nothing in production code changes: the behaviour already holds. The tests' red step is to temporarily skip recording failures for a username the loader does not find, and watch the scenario fail.

## Risks / Trade-offs

- [A consumer wires the raw store instead of the policy's view, and the observer stays silent] → The godoc of `FormLoginDeps.Attempts` and `BasicAuthDeps.Attempts` recommends the view. The observer's godoc says it sees only what goes through the view. The chain cannot detect this at construction, because a raw store remains valid wiring. This limit is stated, not hidden (library-design §4).
- [One extra count read per failure, and one per reset, when an observer is set] → Paid only by consumers who opt in. Failures are rare, and a reset happens once per successful login.
- [Cleared reports race with concurrent failures] → The count before a reset may be stale. A failure recorded between the read and the reset can make the report claim a clearing that removed it, or a clearing of zero can go unreported. These are reports, not decisions, so the lockout outcome is unaffected. This is documented.
- [Failures under another spelling of the username outlive a password change] → Documented (Decision 4). It is the same limit a successful login already has.
- [The fixed-duration boundary is a reading of the code] → The first boundary test is a red step. If 15:00 turns out to be refused, the spec scenario is corrected, not the test.
- [PCI DSS 8.3.4 is unverified] → Neither the godoc nor the tests claim PCI conformance (Decision 2).

## Migration Plan

Nothing is tagged, so there are no consumers to migrate. In-tree, the rename touches the six test files listed in Context. Rollback is a revert.

## Open Questions

- The final names of the view method, the report type and its kinds. These are deferrable: the spec fixes their behaviour, not their names.

## References

**Researched (accessed 2026-10-07):**

*Decision 3: what the ceiling is, and what NIST requires:*
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: a SHALL limit of 100 consecutive failures per authenticator, enforced by disabling it until rebind; the example of waits from 30 seconds to an hour.

*Decisions 1 and 2: sliding versus fixed duration:*
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), Account Lockout: threshold, observation window and duration; exponential lockout; the denial-of-service risk.
- [ASP.NET Core Identity lockout options](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration): a fixed lock duration; a success clears the count.
- [AWS Cognito lockout behavior](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication.html#authentication-flow-lockout-behavior): five free attempts, doubling waits, refused attempts not counted. This shows the escalating default is established practice.
- [Keycloak brute-force detection](https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/threat/brute-force.adoc): escalating temporary lockouts, and permanent lockout as a separate mode with its denial-of-service downside stated.

*Decision 4: a password change clears the count:*
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout): a self-service password reset sets the lockout duration to zero.
- [Auth0 brute-force protection](https://auth0.com/docs/secure/attack-protection/brute-force-protection): changing the password unblocks the user.
- Keycloak (above): re-enabling a user resets the count.

*Decision 5: reporting:* reasoned from scrty's own settled specs and code; no external source.

**Unverified:**
- PCI DSS v4.0 requirement 8.3.4 (lock after at most 10 invalid attempts, for at least 30 minutes or until identity is confirmed). The wording comes from a consumer's review. The PCI SSC's public summary returned no readable text, and the standard itself is registration-only.

**Project:**
- `openspec/changes/archive/2026-10-04-login-source-throttling/design.md`, decision 2: the escalating wait and the windowed ceiling this change keeps.
- `policy/attempts.go`, `policy/lockout.go`, `httpsec/options.go` (`FormLoginDeps`, `BasicAuthDeps`), `httpsec/bearer.go:119`, `httpsec/passwordchange.go`.
