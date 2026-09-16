## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** Earlier changes provide the following:
  - `project-foundation`: the module layout and its dependency guard, `pkg/id` and `pkg/logsample`;
  - `identity-and-tokens`: the identity ports (with no in-memory default), the password encoder, the token issuer and verifier, and the signing-key manager with `Start`/`Stop` and an in-memory key store default;
  - `authn-authz-core`: the session manager and store, the policies with the lockout attempt store, the rate limiter and source guard, and the one-time token manager. Each component owns a refusal-log sampler and exposes `FlushRefusalLogs()` so that a consumer can report exact counts at shutdown;
  - `durable-persistence`: the `sqlstore`, `pgx` and `gorm` adapters, the `seal.Sealer` port and the embedded migration sets;
  - `default-identity-store`: a PostgreSQL implementation of the identity ports with its own migration set;
  - `http-security`, `auth-methods` and `oidc-brokering`: the HTTP chain, the optional authentication methods, and OIDC brokering with its flow and handoff stores.
- **The purge operations already exist, and each owner derives its own cutoff.**

  | Owner | Operation | Cutoff |
  |---|---|---|
  | session store | `DeleteExpired(ctx)` | now; nothing counts expired sessions |
  | one-time token manager | `PurgeExpired(ctx)` | expired **and** created before now − its own issuance window; its own purpose only |
  | magic-link manager | its purge, over the one-time manager of its purpose | as above |
  | lockout policy | `PurgeExpired(ctx)` | recorded before now − its own window |
  | in-memory rate limiter | `Prune(ctx)` | the newest stamp has left its own window |
  | OIDC flow purger and handoff manager | their purge (oidc-brokering) | expiry |

  An owner whose store cannot purge returns a purge-unsupported error, never zero. The signing-key manager deletes keys past their overlap inside its own loop, which `signing-keys` owns.
- **Settled product decisions:**
  - the core module has no scheduler or DI dependency;
  - the expiry runner is scheduler-agnostic and can be run manually;
  - the scheduler integration is the nested `sweep` module on gocron;
  - DI wiring is the nested, optional `do` module on `samber/do` v2. It includes the default identity store and in-memory stores unless durable adapters are registered, warns about in-memory stores, and starts and stops background work through the container;
  - plain constructors stay the primary API.

## Goals / Non-Goals

**Goals:**
- A sweep that bounds every expiring security-state table and cannot be configured to free rate-limit or lockout quota.
- A runner whose guarantees hold for a manual run, a gocron schedule and a consumer's own job system alike.
- One call that wires scrty into a `samber/do` container with the constructors' defaults, and that surfaces contradictions before traffic.

**Non-Goals:**
- Defining or changing retention rules. Each owning capability defines its own cutoff; this change only calls it.
- Sweeping durable records that do not expire: API keys, OIDC links, MFA enrolments and identity tables. An API key's `expires_at` is optional, and a revoked key's row is its audit trail.
- Sweeping signing keys. The key manager's own loop removes keys past their overlap (`signing-keys`).
- Deleting in batches. Each run calls the owner's purge once; see decision 3.
- Applying or checking migrations from the wiring; see decision 11.
- Retry, run history or per-task metrics. The result observer is the whole reporting surface.
- A concrete distributed lock implementation, health-check endpoints, and other containers (fx, wire, dig).

## Decisions

Departures from established behaviour are labelled (a) when a settled scrty decision requires them, and (b) when they fix a demonstrated defect.

### 1. Where the code lives

| Module | Package | Contents | Dependencies |
|---|---|---|---|
| core | `expiry` | `Task`, `Runner`, `Result`, `Report`, sentinels | standard library only |
| core | `session`, `onetime`, `magiclink`, `policy`, `ratelimit`, `oidc` | expiry task constructors | `expiry` |
| `github.com/kartaladev/scrty/sweep` | `sweep` | `Sweeper`: gocron scheduling of a `Runner` | gocron v2, clockwork, core |
| `github.com/kartaladev/scrty/do` | `scrtydo` | registration, `Start`, lifecycle, warnings | `samber/do` v2, `sweep`, core |

- **`expiry` is a leaf package (departure (a)).** Owning packages return an `expiry.Task`, so they import `expiry`, which has no third-party dependency. If the task type lived in the scheduler package, every owning package would carry gocron in its build graph, which the core module's no-scheduler rule forbids.
- **Why the package name `scrtydo`:** a consumer's file already imports `github.com/samber/do/v2` as `do`. A second package named `do` would force an alias at every call site.
- **Why `do` depends on `sweep`:** the settled lifecycle decision has the container start and stop the sweeper. A consumer who wants no gocron uses the plain constructors and the core runner.

### 2. A task carries a name, a cadence and a purge, never a retention window

```go
type Task struct {
    Name     string                                  // required, unique within a runner
    Interval time.Duration                           // zero: the scheduler's default; ignored by manual runs
    Run      func(ctx context.Context) (removed int, err error) // required
}
```

- **No retention window.** No field and no runner option can express a window. The quota-freeing sweep therefore cannot be written from the wiring layer. A consumer adding a task for their own table supplies their own `Run` and owns its cutoff.
- **No constructor chooses a cadence.** Every built-in constructor leaves `Interval` zero, because a library cannot know a deployment's cadence.

**Built-in constructors** each wrap their owner's purge:

| Constructor | Accepts | Task name |
|---|---|---|
| `session.ExpiryTask(s session.Store)` | the base store contract, which already has expiry deletion | `sessions` |
| `magiclink.ExpiryTask(m *magiclink.Manager)` | the manager, which owns the purpose and window | `magiclink-tokens` |
| `onetime.ExpiryTask(m *onetime.Manager)` | the manager, which owns the purpose and window | `one-time-tokens:<purpose>` |
| `policy.LockoutExpiryTask(p *policy.LockoutPolicy)` | the policy, which owns the window | `login-attempts` |
| `ratelimit.ExpiryTask(l *ratelimit.MemoryLimiter)` | the in-memory limiter | `ratelimit` |
| `oidc.FlowExpiryTask(r oidc.FlowPurger)` | the purge capability, not the flow store port | `oidc-flows` |
| `oidc.HandoffExpiryTask(m *oidc.HandoffManager)` | the handoff owner | `oidc-handoffs` |

- **Why a capability interface for flows:** a constructor that accepted the flow store port would compile against a stateless store with no rows, and reveal the mismatch only on its first run. Accepting the capability makes that a compile error.
- **Why each constructor wraps the owner and not the store:** the owner derives the cutoff. A task that reached past the one-time manager to its store would have to pick a cutoff itself, and the obvious choice, the TTL, frees issuance quota.
- **Names are stable and part of the contract,** because they appear in logs and results and form the distributed lock key. A deployment with two limiters renames one task, for example `ratelimit:apikey`, because duplicate names are refused.
- **The rate-limiter task** is not needed to bound memory under traffic, since the limiter prunes inline. It exists for a limiter that goes quiet, whose last window's keys would otherwise stay allocated.
- **Generic one-time task (departure (b)):** without a generic constructor, a one-time purpose with no dedicated task silently grows without bound. That gap is acknowledged in the package documentation of the established runner. `onetime.ExpiryTask` covers any purpose, and the name carries the purpose so each purpose's window stays separate.
- **Override:** a consumer builds any `Task` for their own state, renames a built-in task, or leaves one out.
- **Alternative rejected: one central package holding every constructor.** It would import nearly every package in the module, and it puts the cutoff rules at arm's length from their owners.

### 3. Each run calls the owner's purge once

A task run calls `Run` once, and the owner's statement deletes everything eligible. The runner has no batch size or per-run cap.

- **Default and override:** there is no batching to configure. A consumer whose table needs bounded deletes supplies their own `Run`, or their own store whose purge bounds itself.
- **The first-run hazard** (a table that has never been swept makes a large first delete) is handled by the scheduler not sweeping at start by default (decision 6). An operator can run the first sweep manually in a maintenance window.
- **Why no batching:** it would need a limit-accepting variant of every owner's purge and every adapter statement. No failing case or stated defect of the single-statement purge justifies that.

### 4. The runner: sequential, on the caller's goroutine, failures isolated

```go
func NewRunner(tasks []Task, opts ...Option) (*Runner, error)
func (r *Runner) RunOnce(ctx context.Context) (Report, error) // every task, in declared order
func (r *Runner) RunTask(ctx context.Context, name string) (Result, error)
func (r *Runner) Tasks() []Task                               // copies, for schedulers

type Result struct {
    Task    string
    Removed int
    Skipped bool          // busy, or ctx done before the task started
    Err     error
    Elapsed time.Duration // measured with the runner's clock
}
type Report struct{ Results []Result }

// WithRunTimeout (default 0: no deadline beyond ctx), WithObserver(func(Result)),
// WithLogger (default slog.Default()), WithClock (default time.Now)
var ErrNoTasks, ErrInvalidTask, ErrDuplicateTask, ErrUnknownTask, ErrTaskBusy,
    ErrTaskPanicked, ErrPurgeUnsupported, ErrInvalidOption error
```

**Construction** refuses:
- no tasks;
- an empty name;
- a nil `Run`;
- duplicate names;
- a negative interval or run timeout;
- nil option values.

Each of these would otherwise produce a runner that appears to run and reclaims nothing.

**Manual runs (departure (a)).** `RunOnce` and `RunTask` exist because the settled decision requires manual runs. `RunOnce` returns the report together with `errors.Join` of the task errors, so a manual caller such as a CronJob's `main` can exit non-zero. The scheduled sweeper discards that error, because a cleanup job must not take down the service it cleans up for.

**No goroutines.** Tasks run one after another on the caller's goroutine, each under `WithRunTimeout` when that is positive. A `goleak` test pins that nothing is left behind.

**Failure isolation.**
- **Errors:** a returned error is logged at ERROR and recorded in the result, and the next task still runs.
- **Panics:** a panic is recovered into `ErrTaskPanicked`, with the panic value kept in the message.
- **Purge-unsupported:** it is a failure, never zero.

**Cancellation.**
- `ctx` is checked before each task. Tasks not reached are reported `Skipped` with `ctx.Err()`.
- **Limit, stated:** a purge that ignores its context is not interrupted. Whether a running `DELETE` stops is up to the driver.

**Overlap (departure (a)).** A task already running in this runner, whether from a scheduled tick or a concurrent manual call, is skipped with `ErrTaskBusy` rather than queued. The scheduler's singleton mode alone does not cover manual runs, which the settled decision adds.

**Reporting.**
- Success is logged at DEBUG with the count, and failure at ERROR.
- The observer runs synchronously, after the log line, and must not block; the godoc gives a non-blocking send example.
- The observer lives on the runner, not the scheduler, so manual runs are reported too.

### 5. Purge-unsupported is recognisable with one sentinel (departure (b))

Owners keep their own purge-unsupported sentinels. Every built-in constructor also joins the owner's error with `expiry.ErrPurgeUnsupported`, so `errors.Is(result.Err, expiry.ErrPurgeUnsupported)` matches any task.

- **Evidence:** the established result type documents that distinct per-package sentinels with the same name make an operator who alerts on one of them miss a misconfigured store behind another owner.
- **Override:** none needed. Owners' own sentinels still match.

### 6. The scheduled sweeper (`sweep` module)

```go
func New(r *expiry.Runner, opts ...Option) (*Sweeper, error)
func (s *Sweeper) Start(ctx context.Context) error
func (s *Sweeper) Shutdown(ctx context.Context) error

// WithDefaultInterval(d), WithRunImmediately(), WithDistributedLocker(gocron.Locker),
// WithClock(clockwork.Clock) (default real clock)
var ErrNoInterval, ErrAlreadyStarted, ErrAlreadyShutdown, ErrInvalidOption error
```

**Jobs.**
- **One job per task:** named `sweep:<task>`, running `runner.RunTask` with the task's interval, or the default interval when the task's is zero.
- **Singleton mode:** each job uses `LimitModeReschedule`. A tick that arrives while a run is still going is dropped, not queued, because queued runs would stack deletes against a table that was already too slow.
- **Why the job name matters:** gocron uses it as the distributed lock key.

**Interval.**
- **Default:** none. A task with no interval, on a sweeper with no default interval, fails construction with `ErrNoInterval`.
- **Override:** the task's `Interval`, or `WithDefaultInterval`.
- **Why no library default:** a cadence the library chose would look like one somebody chose.

**First run.**
- **Default:** the first run waits one interval.
- **Override:** `WithRunImmediately()`.
- **Why:** the first sweep against a table that has never been swept can be a very large delete, and a boot-time sweep fires on every replica during a rollout.

**Replicas.**
- **Default:** no lock, so every replica sweeps. The godoc states it.
- **Override:** `WithDistributedLocker`, passed through to gocron.
- **Limit, stated:** the tests prove the locker is consulted with the job name. They do not prove that two replicas serialise, which depends on the consumer's locker.

**Lifecycle.**
- **Construction:** gocron starts its goroutine when the scheduler is built, so `Shutdown` tears the scheduler down whether or not `Start` ran. A `goleak` test covers the construct-then-discard path.
- **Idempotence and refusal:** `Shutdown` is idempotent. `Start` after `Shutdown` returns `ErrAlreadyShutdown`, and a second `Start` returns `ErrAlreadyStarted`.
- **A partial `Start` is not retryable:** if scheduling fails partway, the sweeper shuts itself down, and a retry gets `ErrAlreadyShutdown` rather than double-registering jobs.
- **`ctx` passed to `Start`:** it bounds each run. The sweeper's lifetime ends with `Shutdown`.

### 7. The `do` wiring: registration calls constructors and nothing else

```go
func Register(i do.Injector, opts ...Option) error  // validates options, then registers lazy providers
func Start(ctx context.Context, i do.Injector) error // builds every component, checks, starts background work
// The container's own ShutdownWithContext stops background work (decision 10).
```

**Registration.**
- **What `Register` does:** it registers one lazy provider per component. Each provider resolves its dependencies and calls the plain constructor with the options given through `scrtydo` options named after the component, for example `WithSessionOptions(session.Option...)`.
- **What it does not do:** it adds no behaviour a constructor does not have. A table test compares container-built components with constructor-built ones.
- **Validation first:** options that can be validated without a database (OIDC provider configuration, durations, the TOTP issuer) are checked in `Register`, before anything is registered.

**Consumer registration wins (departure (b)).**
- **Before `Register`:** a service type the consumer already provided is not registered again.
  - **Evidence:** registering a default after an existing provider makes `samber/do` panic with "already declared". The established wiring works around this with an ordering constraint documented in a comment, so correctness depends on call order.
- **After `Register`:** `do.Override` replaces a registration, provided it runs before the first invocation.
- **Limit, stated:** an override after a dependent has been built does not rebuild the dependent. `Start` builds everything, so overrides belong before `Start`.

**Optional features** (magic link, MFA, API keys, OIDC) are registered only when their options are given. The core components are always registered.

**Best-effort dependencies (departure (b)).**
- **Absent:** a dependency that is genuinely not registered, for example the role loader behind the privilege authorizer, makes the dependent omit that feature, and the omission is logged at INFO at `Start`.
- **Registered but failing:** a dependency that is registered but fails to build is an error, returned with the provider's message.
  - **Evidence:** the established wiring documents that reducing a provider error to "not registered" discards the message that names the broken option, which is why it validates some options eagerly as a workaround.

### 8. Stores: in-memory by default, durable when a backend is registered

**Default.** With no backend registered:
- every security-state store is the owning package's in-memory default;
- the identity ports have no default.

**Durable backend.** A backend is either:
- a `*sql.DB` registered in the container, which gets the core `sqlstore` adapters and the core default identity store; or
- a `scrtydo.SecurityStateStores` value the consumer registers, built with the `pgx` or `gorm` adapter constructors.

Either way, every security-state store is taken from the backend.

- **Departure (a), no probing for pgx or gorm handles:** probing `*pgxpool.Pool` or `*gorm.DB` would make the `do` module require both driver modules. The module layout keeps drivers out of consumers' module graphs unless they choose them.
- **More than one backend is an error at `Start`, naming both (departure (b)).**
  - **Evidence:** the established wiring lets the last probed backend win and logs that this is a wiring smell, not a supported configuration. It silently selects stores the consumer may not have meant.
- **Sealer:** a durable backend requires a `seal.Sealer`, given through `WithSealer` or registered in the container. The check runs when the backend is resolved, not inside a lazy provider, so a missing sealer fails `Start` rather than the first request. There is no plaintext path.

**Identity ports.**
- **Default identity store (departure (a)):** it is wired when a `*sql.DB` backend is registered and the consumer registered none of the identity ports. It fills the user loader, role loader, user provisioner and MFA requirement lookup.
- **Override:** the consumer registers their own identity ports.
- **Partial registration:** registering some identity ports but not others, while the default store would fill the rest, is an error at `Start`. Two sources of users in one deployment is never intended.
- **No identity ports at all:** with no identity ports and no `*sql.DB`, building the authentication manager fails with an error naming the missing user loader and both ways to supply it.

**Per-store override.** The consumer registers or overrides any single store, and that override is honoured. It is reported only by the warning in decision 9.

### 9. In-memory warnings (departure (a))

At `Start`, the wiring lists every security-state store that is an in-memory implementation.

**The warning.**
- **Durable backend registered:** the deployment is presumed to have more than one replica, and each store still in memory gets a WARN naming it and what breaks across replicas.
- **No durable backend:** one WARN lists the in-memory stores and says they are per process.
- **Always:** the in-memory signing-key store gets its own WARN in both cases, because tokens signed by one replica are rejected by every other replica and after a restart.
- **The rate limiter:** it is in-memory until a shared limiter exists, so it gets an INFO stating that behind N replicas the effective limit is N times higher.

**Overrides.**
- `WithSingleProcess()` downgrades these records to DEBUG.
- `WithLogger` replaces the logger (default `slog.Default()`).

**Alternatives rejected.**
- **Reading environment variables:** a library must not change behaviour based on ambient environment the consumer did not pass it.
- **Refusing in-memory stores next to a durable backend:** that would contradict the settled rule that consumer overrides replace any component.

### 10. Lifecycle: build starts nothing; `Start` checks, then starts; shutdown reverses (departure (a))

**Building starts nothing.** `Register` and every lazy provider start no goroutine. The established wiring also never starts the key manager or background work; it leaves `Start` to the caller. The settled decision moves that into the container, through an explicit call.

**`Start(ctx, i)`** runs these steps in order:
1. Invoke every registered component, so every constructor error surfaces now.
2. Run the backend and identity checks (decision 8).
3. Write the warnings (decision 9).
4. Call the signing-key manager's `Start`.
5. Call the sweeper's `Start`, when a sweeper is configured (decision 12).

If any step fails, everything started so far is stopped in reverse order, and the error is returned wrapped with the step name. A second `Start` returns `ErrAlreadyStarted`.

**Shutdown.** `Start` resolves a `*scrtydo.Lifecycle` service that implements samber/do's `Shutdown(ctx) error`, which the container's `ShutdownWithContext` reaches. It runs these steps in order:
1. Sweeper `Shutdown`.
2. Key manager `Stop`.
3. Every component's `FlushRefusalLogs`.

- **Why the flush:** the components expose that operation so pending suppressed counts are reported exactly at shutdown, and the container's shutdown is that moment. There is no flush after sweep runs.
- **Idempotence:** shutdown is idempotent, and shutting down without `Start` stops nothing and flushes.
- **Why one lifecycle service:** samber/do shuts down in reverse invocation order, which depends on who invoked what first. One service makes the order a stated contract.

### 11. The wiring does not touch the schema

`Register` and `Start` neither apply nor check migrations. The consumer applies the security-state set, and the identity set when the default identity store is wired, before deploying the release, with scrty's migration runner or their own tool.

- **This adopts established behaviour.** The established wiring only resolves database handles and registers adapters, and its godoc states the deploy order: apply the migration before deploying, and do not roll it back while that version runs.
- **Override:** none within the wiring. A consumer who wants migrations at startup calls the migration runner before `Start`.
- **Consequence, stated:** a missing table first surfaces as a store error on the first request that reaches it. Identity lookups that fail make security policy fail closed. The godoc and README state the deploy order.
- **Alignment needed:** the `default-identity-store` design says the default wiring applies both sets. It should instead say that the wiring applies no migrations, and that the consumer applies both sets before deploying.

### 12. The sweeper in the container is scheduled only with a configured interval

When `Start` runs, the container's expiry runner holds one task for each wired component whose store supports purging.

**Store without purge support.** A wired store that cannot purge, for example a consumer's store with native TTL, is left out, and `Start` logs INFO naming it. A task that fails every interval would turn a legitimate store choice into recurring ERROR logs.

**Scheduling.**
- **With an interval:** `WithSweepInterval(d)`, passed to the sweeper as its default interval, schedules the sweeper, and `Start` starts it.
- **Without one:** no sweeper is scheduled, because the sweeper has no default interval (decision 6). `Start` logs one WARN listing the tables that will grow until an interval is configured or the runner is scheduled elsewhere. The runner stays registered for manual runs.

**Other overrides.**
- `WithSweeperOptions(sweep.Option...)` and `WithExpiryRunnerOptions(expiry.Option...)` tune the sweep.
- `WithExtraExpiryTasks(expiry.Task...)` adds the consumer's own tasks.

### 13. Test-first throughout

- **`expiry` runner:** table tests in the `assert` closure form, driven by fake tasks, covering:
  - construction refusals;
  - error and panic isolation, with the panic value kept;
  - cancellation between tasks;
  - `ErrTaskBusy` under a concurrent `RunTask`, using `testing/synctest`;
  - the observer receiving counts;
  - the joined error from `RunOnce`;
  - `goleak` after runs.
- **Task constructors:** for each owner, a test that the owner's quota count is unchanged by a run, against the in-memory default. It is seen to fail against a constructor that uses the TTL or reaches past the owner to the store. There are also tests that the constructor sets no interval, that the name is stable, that the owner's error propagates, and that purge-unsupported matches the shared sentinel.
- **`sweep` module:** clockwork fake clock covering:
  - each task firing on its own interval;
  - the default interval;
  - `ErrNoInterval`;
  - a slow run skipping ticks, asserted after the blocked run is released, where reschedule and wait modes actually differ;
  - run-immediately on and off;
  - the locker being consulted with the job name;
  - lifecycle refusals;
  - `goleak` for both started and never-started shutdown.
- **`do` module:**
  - container-built components compared with constructor-built ones;
  - every `Start` error path (identity ports, sealer, two backends);
  - the warnings, captured through a recording `slog` handler;
  - start rollback;
  - shutdown order with recording fakes;
  - `goleak` after container shutdown.

Each group ends with a `/simplify` pass and a re-run.

## Risks / Trade-offs

- [A single-statement purge on a long-unswept table is a large delete] → No boot-time sweep by default. The godoc recommends a first manual run in a maintenance window, and a consumer can supply a bounded `Run`.
- [A purge that ignores its context runs past its deadline] → Stated in godoc. Durable adapters pass the context to the driver.
- [N replicas without a lock each sweep] → Deletes are idempotent, and a lock is one option away. The godoc says what the lock tests do not prove.
- [A container started without a sweep interval sweeps nothing] → One WARN at `Start` lists the tables that will grow. The runner remains available for any scheduler.
- [Pending migrations surface at the first request, not at `Start`] → The deploy order is documented, and identity lookups fail closed.
- [The `do` module pulls gocron into every consumer of container wiring] → The module is optional. Constructors and the core runner need no scheduler.
- [An override registered after `Start` does not reach components already built] → Stated in godoc. `Start` builds everything, which makes the moment explicit.
- [The multi-replica presumption is a heuristic] → It only chooses a log level, and `WithSingleProcess()` makes it explicit.

## Migration Plan

Not applicable: this is a new library with no consumers and no tags. For deployers, apply the migration sets before the first release that wires a database.
