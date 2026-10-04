## Why

Every security-state store scrty ships has a delete operation for expired records, and nothing calls it. In a durable deployment:
- sessions, one-time tokens, OIDC flows and handoffs, and login attempts therefore grow without bound;
- some of those rows are planted by unauthenticated strangers, one per login attempt or authorize request.

The obvious cleanup job is also dangerous: a delete keyed on expiry alone removes rows that a rate limiter or account lockout is still counting, and quietly hands the quota back on every run.

## What Changes

- Add a scheduler-agnostic **expiry runner** in the core module:
  - it deletes expired security state by calling the purge operations of the components that own the data;
  - it never supplies a retention window of its own, so a sweep cannot disarm a rate limiter or account lockout;
  - it isolates failures and panics per task;
  - it honours context cancellation and an optional per-run deadline;
  - it starts no goroutine;
  - it can run all tasks once, or one named task, for consumers who schedule it themselves.
- Add **expiry task constructors** in the packages that own each kind of expiring state:
  - sessions;
  - magic-link tokens, plus one-time tokens of any other purpose;
  - login attempts;
  - the in-memory rate limiter;
  - OIDC flows and handoffs;
  - the one-time state the library keeps on its own behalf: passkey ceremony challenges (`passkey.Manager`), and the MFA challenges and account-recovery codes and hold tokens of the components the HTTP chain builds (`httpsec.Chain`).

  Each wraps its owner's purge. None accepts a duration or chooses a cadence.
- Add the nested module **`github.com/kartaladev/scrty/sweep`**, which runs the expiry runner on a schedule with gocron:
  - each task runs on its own interval or the sweeper's default, and the consumer must set one of them;
  - no boot-time sweep unless the consumer asks for one;
  - a slow run skips ticks instead of queueing them;
  - an optional distributed lock;
  - a start and shutdown lifecycle that leaks no goroutine.
- **Container wiring is not part of this change.** The optional `do` module, which composes the runner and the sweeper into a `samber/do` container, is the separate `di-wiring` change.

## Capabilities

### New Capabilities

- `expiry-sweeping`: deleting expired security state through its owners' purge operations. Covers:
  - what is swept and what is never swept;
  - the guarantee that a sweep cannot free rate-limit or lockout quota;
  - failure isolation and cancellation;
  - manual and scheduled runs;
  - result reporting;
  - construction validation and lifecycle.

### Modified Capabilities

None. The owners gain purge entry points where they lacked one (`magiclink.Manager`, `oidc.Manager`, `oidc.HandoffManager`), and the in-memory limiter's prune reports how many keys it removed; each of those is covered by the `expiry-sweeping` requirements rather than by a change to its owner's spec.

## Impact

- **New code, core module:**
  - the `expiry` package (runner, task, result, report), with the standard library only;
  - an expiry task constructor in each owning package: `session`, `onetime`, `magiclink`, `policy`, `ratelimit`, `oidc`, `passkey`, and `httpsec` for the components the chain builds.
- **New module:** `github.com/kartaladev/scrty/sweep`, which depends on gocron v2 and clockwork. It is added to `go.work`, to the dependency guard and to the CI matrix. The core module gains no dependency.
- **Depends on:**
  - the existing purge operations of `sessions`, `one-time-tokens`, `security-policy` and `rate-limiting` (authn-authz-core), `magic-link` (auth-methods) and `oidc-login` (oidc-brokering). No new store operation is needed;
  - `security-state-stores` (durable-persistence);
  - `log-sampling` and `module-layout` (project-foundation).
- **Depended on by:** `di-wiring`, which schedules the sweeper from a container, and `shared-rate-limiting-postgres`, whose limiter is swept by a task built here.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
