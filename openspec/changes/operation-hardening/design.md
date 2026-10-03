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
  - plain constructors stay the primary API.

## Goals / Non-Goals

**Goals:**
- A sweep that bounds every expiring security-state table and cannot be configured to free rate-limit or lockout quota.
- A runner whose guarantees hold for a manual run, a gocron schedule and a consumer's own job system alike.

**Non-Goals:**
- Defining or changing retention rules. Each owning capability defines its own cutoff; this change only calls it.
- Sweeping durable records that do not expire: API keys, OIDC links, MFA enrolments and identity tables. An API key's `expires_at` is optional, and a revoked key's row is its audit trail.
- Sweeping signing keys. The key manager's own loop removes keys past their overlap (`signing-keys`).
- Deleting in batches. Each run calls the owner's purge once; see decision 3.
- Container wiring. The optional `do` module, including how a container schedules the sweeper, is the separate `di-wiring` change.
- Retry, run history or per-task metrics. The result observer is the whole reporting surface.
- A concrete distributed lock implementation, and health-check endpoints.

## Decisions

Departures from established behaviour are labelled (a) when a settled scrty decision requires them, and (b) when they fix a demonstrated defect.

### 1. Where the code lives

| Module | Package | Contents | Dependencies |
|---|---|---|---|
| core | `expiry` | `Task`, `Runner`, `Result`, `Report`, sentinels | standard library only |
| core | `session`, `onetime`, `magiclink`, `policy`, `ratelimit`, `oidc` | expiry task constructors | `expiry` |
| `github.com/kartaladev/scrty/sweep` | `sweep` | `Sweeper`: gocron scheduling of a `Runner` | gocron v2, clockwork, core |

- **`expiry` is a leaf package (departure (a)).** Owning packages return an `expiry.Task`, so they import `expiry`, which has no third-party dependency. If the task type lived in the scheduler package, every owning package would carry gocron in its build graph, which the core module's no-scheduler rule forbids.

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
// WithLogger (default slog.Default()), WithClock(clock.Clock) (default clock.System())
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

**The one clockwork type in a scrty API.** scrty's own components take the standard-library-typed
`clock.Clock` or `clock.Timed` (the `clock-seam` change). `sweep` is the exception: its `WithClock`
takes `clockwork.Clock`, because gocron v2's own `WithClock` requires exactly that type and `sweep`
hands the clock straight to gocron. Widening a `clock.Timed` into gocron's eight-method interface
would make scrty invent the behaviour of six methods it never reads. `sweep` is a nested module whose
consumers already depend on clockwork through gocron, so the core module still gains no clockwork
dependency.

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

### 7. Test-first throughout

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

Each group ends with a `/simplify` pass and a re-run.

## Risks / Trade-offs

- [A single-statement purge on a long-unswept table is a large delete] → No boot-time sweep by default. The godoc recommends a first manual run in a maintenance window, and a consumer can supply a bounded `Run`.
- [A purge that ignores its context runs past its deadline] → Stated in godoc. Durable adapters pass the context to the driver.
- [N replicas without a lock each sweep] → Deletes are idempotent, and a lock is one option away. The godoc says what the lock tests do not prove.

## Migration Plan

Not applicable: this is a new library with no consumers and no tags. For deployers, apply the migration sets before the first release that wires a database.
