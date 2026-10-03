## Context

See proposal.md for why this change exists. This change was split out of `operation-hardening`, which keeps the expiry runner and the `sweep` module; the decisions below were drafted there and are carried over unchanged except where noted. The constraints that shape the approach:

- **Starting point.** Earlier changes provide the following:
  - `project-foundation`: the module layout and its dependency guard, `pkg/id` and `pkg/logsample`;
  - `identity-and-tokens`: the identity ports (with no in-memory default), the password encoder, the token issuer and verifier, and the signing-key manager with `Start`/`Stop` and an in-memory key store default;
  - `authn-authz-core`: the session manager and store, the policies with the lockout attempt store, the rate limiter and source guard, and the one-time token manager. Each component owns a refusal-log sampler and exposes `FlushRefusalLogs()` so that a consumer can report exact counts at shutdown;
  - `durable-persistence`: the `sqlstore`, `pgx` and `gorm` adapters, the `seal.Sealer` port and the embedded migration sets;
  - `default-identity-store`: a PostgreSQL implementation of the identity ports with its own migration set;
  - `http-security`, `auth-methods` and `oidc-brokering`: the HTTP chain, the optional authentication methods, and OIDC brokering with its flow and handoff stores.
- **From `operation-hardening` (a prerequisite):** the core `expiry` runner and task constructors, and the `sweep` module. The container composes them; it does not define them.
- **From `shared-rate-limiting`:** the `ratelimit.LimiterFactory` port. The container selects a factory (decision 8); the port and its implementations are defined there.
- **Settled product decisions:**
  - the core module has no scheduler or DI dependency;
  - DI wiring is the nested, optional `do` module on `samber/do` v2. It includes the default identity store and in-memory stores unless durable adapters are registered, warns about in-memory stores, and starts and stops background work through the container;
  - plain constructors stay the primary API.
- **Not scheduled.** This change is proposed and designed so that other changes can name its seams. It is not to be applied until the consumer asks for it.

## Goals / Non-Goals

**Goals:**
- One call that wires scrty into a `samber/do` container with the constructors' defaults, and that surfaces contradictions before traffic.

**Non-Goals:**
- Applying or checking migrations from the wiring; see decision 6.
- Other containers (fx, wire, dig), and health-check endpoints.
- Defining expiry tasks, the sweeper or limiter implementations. They belong to `operation-hardening` and `shared-rate-limiting`.

## Decisions

Departures from established behaviour are labelled (a) when a settled scrty decision requires them, and (b) when they fix a demonstrated defect.

### 1. Where the code lives

| Module | Package | Contents | Dependencies |
|---|---|---|---|
| `github.com/kartaladev/scrty/do` | `scrtydo` | registration, `Start`, lifecycle, warnings | `samber/do` v2, `sweep`, core |

- **Why the package name `scrtydo`:** a consumer's file already imports `github.com/samber/do/v2` as `do`. A second package named `do` would force an alias at every call site.
- **Why `do` depends on `sweep`:** the settled lifecycle decision has the container start and stop the sweeper. A consumer who wants no gocron uses the plain constructors and the core runner.

### 2. The `do` wiring: registration calls constructors and nothing else

```go
func Register(i do.Injector, opts ...Option) error  // validates options, then registers lazy providers
func Start(ctx context.Context, i do.Injector) error // builds every component, checks, starts background work
// The container's own ShutdownWithContext stops background work (decision 5).
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

### 3. Stores: in-memory by default, durable when a backend is registered

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

### 4. In-memory warnings (departure (a))

At `Start`, the wiring lists every security-state store that is an in-memory implementation.

**The warning.**
- **Durable backend registered:** the deployment is presumed to have more than one replica, and each store still in memory gets a WARN naming it and what breaks across replicas.
- **No durable backend:** one WARN lists the in-memory stores and says they are per process.
- **Always:** the in-memory signing-key store gets its own WARN in both cases, because tokens signed by one replica are rejected by every other replica and after a restart.
- **The rate limiter:** unless a shared limiter factory is registered (decision 8), it gets an INFO stating that behind N replicas the effective limit is N times higher.

**Overrides.**
- `WithSingleProcess()` downgrades these records to DEBUG.
- `WithLogger` replaces the logger (default `slog.Default()`).

**Alternatives rejected.**
- **Reading environment variables:** a library must not change behaviour based on ambient environment the consumer did not pass it.
- **Refusing in-memory stores next to a durable backend:** that would contradict the settled rule that consumer overrides replace any component.

### 5. Lifecycle: build starts nothing; `Start` checks, then starts; shutdown reverses (departure (a))

**Building starts nothing.** `Register` and every lazy provider start no goroutine. The established wiring also never starts the key manager or background work; it leaves `Start` to the caller. The settled decision moves that into the container, through an explicit call.

**`Start(ctx, i)`** runs these steps in order:
1. Invoke every registered component, so every constructor error surfaces now.
2. Run the backend and identity checks (decision 3).
3. Write the warnings (decision 4).
4. Call the signing-key manager's `Start`.
5. Call the sweeper's `Start`, when a sweeper is configured (decision 7).

If any step fails, everything started so far is stopped in reverse order, and the error is returned wrapped with the step name. A second `Start` returns `ErrAlreadyStarted`.

**Shutdown.** `Start` resolves a `*scrtydo.Lifecycle` service that implements samber/do's `Shutdown(ctx) error`, which the container's `ShutdownWithContext` reaches. It runs these steps in order:
1. Sweeper `Shutdown`.
2. Key manager `Stop`.
3. Every component's `FlushRefusalLogs`.

- **Why the flush:** the components expose that operation so pending suppressed counts are reported exactly at shutdown, and the container's shutdown is that moment. There is no flush after sweep runs.
- **Idempotence:** shutdown is idempotent, and shutting down without `Start` stops nothing and flushes.
- **Why one lifecycle service:** samber/do shuts down in reverse invocation order, which depends on who invoked what first. One service makes the order a stated contract.

### 6. The wiring does not touch the schema

`Register` and `Start` neither apply nor check migrations. The consumer applies the security-state set, and the identity set when the default identity store is wired, before deploying the release, with scrty's migration runner or their own tool.

- **This adopts established behaviour.** The established wiring only resolves database handles and registers adapters, and its godoc states the deploy order: apply the migration before deploying, and do not roll it back while that version runs.
- **Override:** none within the wiring. A consumer who wants migrations at startup calls the migration runner before `Start`.
- **Consequence, stated:** a missing table first surfaces as a store error on the first request that reaches it. Identity lookups that fail make security policy fail closed. The godoc and README state the deploy order.
- **Alignment needed:** the `default-identity-store` design says the default wiring applies both sets. It should instead say that the wiring applies no migrations, and that the consumer applies both sets before deploying.

### 7. The sweeper in the container is scheduled only with a configured interval

When `Start` runs, the container's expiry runner holds one task for each wired component whose store supports purging.

**Store without purge support.** A wired store that cannot purge, for example a consumer's store with native TTL, is left out, and `Start` logs INFO naming it. A task that fails every interval would turn a legitimate store choice into recurring ERROR logs.

**Scheduling.**
- **With an interval:** `WithSweepInterval(d)`, passed to the sweeper as its default interval, schedules the sweeper, and `Start` starts it.
- **Without one:** no sweeper is scheduled, because the sweeper has no default interval (`operation-hardening` decision 6). `Start` logs one WARN listing the tables that will grow until an interval is configured or the runner is scheduled elsewhere. The runner stays registered for manual runs.

**Other overrides.**
- `WithSweeperOptions(sweep.Option...)` and `WithExpiryRunnerOptions(expiry.Option...)` tune the sweep.
- `WithExtraExpiryTasks(expiry.Task...)` adds the consumer's own tasks.
### 8. Shared rate limiting is selected explicitly

**Default:** every flow builds its in-memory limiter, and decision 4's INFO is written. Registering a `*sql.DB` or `SecurityStateStores` does **not** switch rate limiting to a shared backend, because that would change the default for a consumer who asked only for durable stores.

**Override:** a `ratelimit.LimiterFactory` the consumer registers, for example from the `redis` module. The container passes it to every flow that accepts a factory. The `do` module never imports the `redis` module, for the same reason it does not probe pgx or gorm handles.

- **At `Start`:** the wiring calls `Verify(ctx)` on a registered factory that implements it, and a failure fails `Start`. With a shared factory registered, decision 4's rate-limiter INFO is not written.
- **Error at `Start`:** `WithSingleProcess()` together with a registered shared factory, naming both. The two statements contradict each other.
- **Deferred:** a `WithSharedRateLimiting()` option that builds a PostgreSQL factory from the registered backend waits on `shared-rate-limiting-postgres`.

### 9. Test-first throughout

- **`do` module:**
  - container-built components compared with constructor-built ones;
  - every `Start` error path (identity ports, sealer, two backends);
  - the warnings, captured through a recording `slog` handler;
  - start rollback;
  - shutdown order with recording fakes;
  - `goleak` after container shutdown.

- **Shared limiter selection:** a registered factory reaches every flow; the INFO is absent with it and present without it; the `WithSingleProcess()` contradiction; a `Verify` failure fails `Start`.

Each group ends with a `/simplify` pass and a re-run.

## Risks / Trade-offs

- [A container started without a sweep interval sweeps nothing] → One WARN at `Start` lists the tables that will grow. The runner remains available for any scheduler.
- [Pending migrations surface at the first request, not at `Start`] → The deploy order is documented, and identity lookups fail closed.
- [The `do` module pulls gocron into every consumer of container wiring] → The module is optional. Constructors and the core runner need no scheduler.
- [An override registered after `Start` does not reach components already built] → Stated in godoc. `Start` builds everything, which makes the moment explicit.
- [The multi-replica presumption is a heuristic] → It only chooses a log level, and `WithSingleProcess()` makes it explicit.

## Migration Plan

Not applicable: this is a new library with no consumers and no tags. For deployers, apply the migration sets before the first release that wires a database.
