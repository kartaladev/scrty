## Why

Every security-state store scrty ships has a delete operation for expired records, and nothing calls it. In a durable deployment:
- sessions, one-time tokens, OIDC flows and handoffs, and login attempts therefore grow without bound;
- some of those rows are planted by unauthenticated strangers, one per login attempt or authorize request.

The obvious cleanup job is also dangerous: a delete keyed on expiry alone removes rows that a rate limiter or account lockout is still counting, and quietly hands the quota back on every run.

Separately, wiring scrty's many components by hand is repetitive and easy to get subtly wrong:
- a durable session store next to an in-memory key store;
- a key manager that is never started;
- a sweeper that is never shut down.

Applications that already use a DI container want one call that composes the plain constructors with safe defaults. They also want it to fail loudly when the composition is contradictory.

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
  - OIDC flows and handoffs.

  Each wraps its owner's purge. None accepts a duration or chooses a cadence.
- Add the nested module **`github.com/kartaladev/scrty/sweep`**, which runs the expiry runner on a schedule with gocron:
  - each task runs on its own interval or the sweeper's default, and the consumer must set one of them;
  - no boot-time sweep unless the consumer asks for one;
  - a slow run skips ticks instead of queueing them;
  - an optional distributed lock;
  - a start and shutdown lifecycle that leaks no goroutine.
- Add the nested, **optional** module **`github.com/kartaladev/scrty/do`**, which registers scrty's components with `samber/do` by calling the plain constructors:
  - by default it wires in-memory security stores;
  - when a database is registered, it wires the durable adapters and the default identity store, unless the consumer registered their own identity ports;
  - any component the consumer registers or overrides replaces the default;
  - contradictory wiring fails at registration or at start, with a message that names the component and the option. Examples are more than one database backend, missing identity ports, and a durable store without a sealer;
  - it does not apply or check migrations. The consumer applies them before deploying;
  - it warns when in-memory security stores, and in particular the in-memory signing-key store, are used where the deployment may run more than one replica;
  - building the container starts nothing. An explicit start runs key rotation and, when an interval is configured, the scheduled sweeper. Container shutdown stops them in reverse order and flushes refusal-log counts.

## Capabilities

### New Capabilities

- `expiry-sweeping`: deleting expired security state through its owners' purge operations. Covers:
  - what is swept and what is never swept;
  - the guarantee that a sweep cannot free rate-limit or lockout quota;
  - failure isolation and cancellation;
  - manual and scheduled runs;
  - result reporting;
  - construction validation and lifecycle.
- `di-wiring`: optional container wiring of scrty's components. Covers:
  - default composition, durable composition and the default identity store;
  - consumer overrides;
  - wiring errors and when they surface;
  - the schema being left to the consumer;
  - in-memory store warnings;
  - start and shutdown of background work.

### Modified Capabilities

None. No specs have been archived yet.

## Impact

- **New code, core module:**
  - the `expiry` package (runner, task, result, report), with the standard library only;
  - an expiry task constructor in each owning package: `session`, `onetime`, `magiclink`, `policy`, `ratelimit`, `oidc`.
- **New modules:**
  - `github.com/kartaladev/scrty/sweep`, which depends on gocron v2 and clockwork;
  - `github.com/kartaladev/scrty/do`, which depends on `samber/do` v2, the `sweep` module, and the core module's `sqlstore` package.

  Both are added to `go.work`, to the dependency guard and to the CI matrix. The core module gains no dependency.
- **Depends on:**
  - the existing purge operations of `sessions`, `one-time-tokens`, `security-policy` and `rate-limiting` (authn-authz-core), `magic-link` (auth-methods) and `oidc-login` (oidc-brokering). No new store operation is needed;
  - `security-state-stores` (durable-persistence) and `default-identity-store`;
  - `log-sampling` and `module-layout` (project-foundation);
  - every constructor that `di-wiring` composes.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
