## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** The `rate-limiting` capability, from `authn-authz-core`, defines:
  - `ratelimit.Limiter`, with `Exceeded(ctx, key) (bool, error)` and `RecordFailure(ctx, key) error`. An error from `Exceeded` means the limiter could not decide, and callers treat it as exceeded. `RecordFailure` may receive a context without cancellation, so an implementation doing I/O bounds its own;
  - the in-memory limiter:
    - a sliding window, where a failure counts while strictly after `now - window`;
    - at most `limit` newest stamps per key;
    - exceeded at `count >= limit`;
    - inline pruning at most once per window, removing a key only when its newest stamp has expired;
    - `Prune` accepting no window;
    - one per-replica WARN;
    - non-positive limit or window refused;
  - the source keyer and source guard: canonical keys, IPv6 grouping by prefix (default /64), unattributable sources refused rather than pooled, check and record on the same key, and a record step on `context.WithoutCancel` whose errors are logged.
- **Capabilities used by name and not restated:**
  - `security-state-stores` and `schema-migrations`: the `sqlstore`, `pgx` and `gorm` adapters, and the embedded security-state migration set;
  - `store-conformance`: suites in `github.com/kartaladev/scrty/test`, each seen to fail against a deliberately broken variant;
  - `expiry-sweeping`: `ratelimit.ExpiryTask(ratelimit.Pruner)`, `PruneBatch(ctx, limit)`, and the rule that no task accepts a cutoff and no run changes a count a limiter uses;
  - `di-wiring`: `scrtydo.Register` and `Start`, consumer registration wins, and the per-replica INFO for the in-memory limiter;
  - `http-security`, `api-keys`, `magic-link`, `oidc-login` and `multi-factor-auth`: the flows that build a default in-memory limiter and accept a replacement.
- **Settled rules:**
  - rate limiting is in-memory by default;
  - the core module has no driver dependency;
  - wiring mistakes fail at construction;
  - options are named after what they govern;
  - the library never interprets consumer-owned data, including a user reference used as a limiter key.
- **Established behaviour** has no shared limiter. It states the per-replica limit and relies on the port for replacement. Every limiter decision above is kept. This change adds implementations and wiring; it departs from no existing decision (see decision 12).

## Goals / Non-Goals

**Goals:**
- A limit that holds across replicas, with the existing semantics unchanged and proven by one conformance suite that every limiter runs.
- A backend outage that refuses by default and never degrades silently.
- A single-process consumer who sees no difference.

**Non-Goals:**
- **Changing the default.** The in-memory limiter stays the default for every flow, constructor and wiring path.
- **Closing the check-then-record overshoot.** A concurrent burst can still exceed the limit by its concurrency. This remains the capability's documented bound (decision 3 explains why it is not closed here).
- **Sharing account lockout.** It counts through the attempt store, which the durable adapters already share.
- **Sharing one-time-token issuance counts, MFA replay protection or sessions.** These are store contracts owned elsewhere.
- **Databases other than PostgreSQL, and key-value stores other than Redis.** A consumer implements the port and runs the conformance suite.
- **Pseudonymising source keys at rest** (see Risks).

## Decisions

### 1. Backend options

Both candidates implement `ratelimit.Limiter` unchanged. The comparison:

| | PostgreSQL | Redis | Both |
|---|---|---|---|
| **New infrastructure** | none: durable mode already requires PostgreSQL | a Redis deployment the consumer may not run | consumer's choice |
| **New dependency** | none: `database/sql` in core, pgx in the existing `pgx` module | `github.com/redis/go-redis/v9` in a new nested module | both |
| **Atomicity** | one `INSERT … ON CONFLICT DO UPDATE` per record, serialized by the row lock | one Lua script per call, single key, so it is cluster-slot safe | as each |
| **Expiry** | the limiter's own prune through `expiry-sweeping` (`Pruner`) | TTL on the key, with no sweep | as each |
| **Read cost on the hot path** | one indexed primary-key lookup per `Exceeded` | one script call, typically sub-millisecond | as each |
| **Write cost under attack** | one row update per failure: dead tuples, vacuum and WAL on the same database that serves logins and sessions | one in-memory update, isolated from the security-state database | as each |
| **Clock** | `clock_timestamp()` | `TIME` inside the script (Redis 7.0 or later) | as each |
| **Operational pitfalls** | connection-pool contention with the stores during an attack | an evicting `maxmemory-policy` can drop live keys | both sets |
| **Work** | `sqlstore` and `pgx` limiters plus a migration. gorm consumers pass the `*sql.DB` from `db.DB()` to `sqlstore`, so no gorm-native limiter is needed | one module, one script pair, a testcontainers helper | the sum |

Writes happen only on failures, so legitimate traffic writes nothing. `Exceeded` runs on every guarded request, including every request that presents an API key.

**Recommendation: both, PostgreSQL first.**
- PostgreSQL closes the gap for every durable deployment with no new infrastructure. Its failure-only write pattern is acceptable at the default limits: an attacker is refused after 20 failures per source per minute, and each refused request is a read, not a write.
- Redis is the answer for deployments that already run it, or that cannot accept attacker-driven write load on the security-state database.
- The shared pieces (factory, unavailable modes, conformance suite, wiring) are backend-neutral and land once.

**The final choice is open** (Open Questions). The tasks breakdown waits on it. Choosing one backend removes that backend's decisions below; it changes nothing else.

- **Default:** no shared limiter. The in-memory limiter is still what every flow builds.
- **Override:** the consumer constructs a shared limiter, or selects one in the `do` wiring (decision 9).

### 2. Algorithm fidelity: the same sliding-window log, stored remotely

The shared limiters store the same data as the in-memory one: per key, at most `limit` failure timestamps, the newest ones. They answer the same two questions the same way.

- **`Exceeded`:** count the stamps strictly after `now - window`, and report `count >= limit`. It performs no write.
- **`RecordFailure`:**
  1. drop the stamps at or before `now - window`;
  2. append `now`;
  3. keep the newest `limit`;
  4. extend the key's lifetime to `now + window`.
- **Cancelled context:** both methods return an error when `ctx` has already ended, before any I/O, as the in-memory limiter does.

**Alternatives rejected:**
- **A fixed-window counter**, `INCR` with `EXPIRE` or an integer column. It is cheaper, but it fails the "straddling a boundary" scenario: failures at 12:00:50 and 12:01:10 land in different windows, allowing a 2x burst at every boundary. That is a change to specified behaviour, not an implementation detail.
- **A token bucket or GCRA.** These rate requests rather than counting failures in a window, and cannot express "the newest failure keeps the key alive".
- **A row per failure, like login attempts.** It needs a separate trim statement to hold the per-key bound, and two statements are not atomic without a transaction.

**Precision:** stamps are stored at microsecond precision in both backends. The in-memory limiter uses nanoseconds. The conformance suite steps time by at least one microsecond, and the godoc states the precision.

### 3. Atomicity per backend

**PostgreSQL.** Table `rate_limit_buckets` has these columns:
- `namespace text`;
- `key text`;
- `stamps timestamptz[] NOT NULL`;
- `newest_at timestamptz NOT NULL`;
- `retain interval NOT NULL`.

The primary key is `(namespace, key)`, with an index on `(namespace, newest_at)`.
- **`RecordFailure`** is one statement. A CTE takes `clock_timestamp()` once. `INSERT … ON CONFLICT (namespace, key) DO UPDATE` sets:
  - `stamps` to the live stamps plus `now`, ordered newest first and limited to `limit`;
  - `newest_at` to `now`;
  - `retain` to `greatest(retain, window)`.

  The conflicting row's lock serializes concurrent records for one key. Stamps are re-sorted on every write, because two transactions can read the clock in one order and commit in the other.
- **`Exceeded`** is one read-only `SELECT count(*)` over `unnest(stamps)`, filtered by `> clock_timestamp() - window`. It takes no lock.
- **Ambient transactions are ignored on purpose.** The limiter always runs on its own handle, never on a `WithTx` transaction or a resolver's.
  - **Why:** a failure recorded inside the request's transaction rolls back with the failed request, handing the attacker their budget back.
  - **Override:** none, because it would break the guarantee. The godoc states it.

**Redis.** One sorted set per key. Each score is a microsecond timestamp, and each member is that timestamp plus a random suffix, so equal stamps never collapse into one member.
- **`RecordFailure` script**, one `EVALSHA`:
  1. `ZREMRANGEBYSCORE key -inf cutoff`;
  2. `ZADD key now member`;
  3. `ZREMRANGEBYRANK key 0 -(limit+1)`;
  4. `PEXPIRE key window GT`, falling back to a plain `PEXPIRE` when the key has no TTL.
- **`Exceeded` script**, read-only (`EVALSHA_RO`): `ZCOUNT key (cutoff +inf`.
- **Why scripts:** they run atomically on the server, and each touches exactly one key, so they are valid on Redis Cluster without hash tags.
- **Why not `MULTI`:** a transaction cannot branch on the time it reads.

**Why check-then-record stays non-atomic.** A combined "check and reserve" operation would close the concurrency overshoot. It would also change the port and every flow's ordering, and it would count attempts that later succeed. The port is unchanged, and the overshoot stays the documented bound.

### 4. Expiry and pruning never disarm a limit

The rule carries over unchanged: nothing may remove a key whose newest stamp is still inside the window.

- **Redis:** the TTL is `newest stamp + window`, set only by `RecordFailure`, and only ever extended (`GT`). A key therefore expires exactly when the in-memory limiter would prune it. `Exceeded` never touches the TTL.
- **PostgreSQL:**
  - the limiter implements `ratelimit.Pruner`;
  - `Prune(ctx)` and `PruneBatch(ctx, limit)` delete rows in the limiter's own namespace where `newest_at <= clock_timestamp() - greatest(retain, window)`;
  - batch deletes use the `FOR UPDATE SKIP LOCKED` pattern from `expiry-sweeping`;
  - neither method accepts a window or cutoff.
- **Mixed configuration during a rollout:** both backends keep the longest window any replica recorded with (`retain`, and `PEXPIRE … GT`). A replica configured with a shorter window cannot reap a failure that a longer-window replica still counts.
- **Inline pruning:** neither shared limiter prunes inside `Exceeded` or `RecordFailure`. Redis needs no pruning, and a PostgreSQL delete on the request path would put attacker-driven deletes on the hot path.
  - **Default:** the `expiry-sweeping` task named `rate-limiter`.
  - **Limit, stated:** without the sweep, rows stay in the table. Stale rows are never counted, because every read filters by the window.
- **Eviction pitfall (Redis):** an evicting `maxmemory-policy` (`allkeys-*`, `volatile-*`) can drop a live key, which disarms that source's limit. Only `noeviction` is safe: under memory pressure writes then fail, and failures refuse.
  - `Verify(ctx)` reads the policy.
  - **An evicting policy:** a configuration error.
  - **An unreadable policy** (managed services often block `CONFIG`): one WARN naming the requirement.
  - **Override:** `WithEvictionPolicyCheck(false)`, for a consumer who has verified the policy out of band. The godoc names what that gives up.

### 5. Backend unavailable: fail closed by default

A backend error is already an error under the port contract, and the guard already refuses on it. This change keeps that default and adds overrides that make degradation an explicit decision.

```go
type UnavailableMode int // UnavailableRefuse (default), UnavailableFallBackToLocal, UnavailableAllow
func WithOnUnavailable(m UnavailableMode) Option     // on every shared limiter constructor
func WithOperationTimeout(d time.Duration) Option    // default 250ms; bounds each call, including records on WithoutCancel
func WithUnavailableProbeInterval(d time.Duration) Option // default 1s; applies to the fallback and allow modes only
```

**What counts as unavailable:** any backend error, a timeout or an exhausted pool while the caller's context is still live. A call whose caller context has ended always returns an error, refuses, and is logged at DEBUG by the guard, whatever the mode.

**The modes:**
- **`UnavailableRefuse` (default):**
  - `Exceeded` returns the error, so the guard refuses as throttled;
  - `RecordFailure` returns the error, and the guard logs it.
  - **Cost, stated:** while the backend is down, every guarded flow refuses. That includes API-key requests, magic-link and handoff redemption, and second-factor verification, so users who need a second factor cannot complete sign-in. Password login without a second factor is unaffected.
  - **Why this is the default:** a limiter that fails open under load is one an attacker disables by causing load, and the capability already requires failing closed.
- **`UnavailableFallBackToLocal`:**
  - on a backend error, both calls go to an in-memory limiter with the same limit and window, built by the constructor;
  - the backend is retried at most once per probe interval, so an outage does not add a timeout to every request.
  - **Stated limit:** during the outage the effective limit is N times, the documented default's limit.
  - **Logging:** each transition, to local and back, is logged at ERROR and WARN. Refusals keep their sampled records.
- **`UnavailableAllow`:**
  - on a backend error, `Exceeded` returns `false, nil`, and `RecordFailure` drops the failure;
  - an ERROR is logged, sampled per namespace.
  - **Stated limit:** no limit at all during the outage. The godoc says it is for flows whose consumer has another bound in front, such as an edge rate limiter.

**Why the modes live on the shared limiter, not the guard:** the guard cannot tell a backend outage from an in-memory limiter bug, and the in-memory default has no outage to tolerate. The mode is implemented once, as an internal decorator in core `ratelimit`, and applied by each backend constructor.

**Construction errors:**
- an unknown mode;
- a non-positive timeout or probe interval.

### 6. Clock: the backend's by default

- **Default:** time is read inside the backend operation: `clock_timestamp()` in PostgreSQL, `TIME` in Redis.
  - **Why:** with the application clock, a replica running 30 seconds fast writes stamps that other replicas count for 30 seconds longer. A replica running slow computes a cutoff that counts expired failures. With the backend clock, one clock orders every stamp.
  - **Why `clock_timestamp()` and not `now()`:** `now()` is the transaction start, which differs from the call time on a pooled connection inside a longer transaction.
- **Override:** `WithAppClock(clock.Clock)` passes the time as an argument instead. It takes scrty's `clock.Clock` seam (the `clock-seam` change), so a clockwork fake or a consumer's own clock is accepted directly; a nil clock, typed nil included, is a configuration error. This serves tests and deployments that trust their clock discipline more than the backend's.
  - **Stated limit:** replica clocks must agree to well within the window.
  - **Construction error:** a nil function.
- **Redis version:** `TIME` inside a script requires effect replication, the default in Redis 7. `Verify(ctx)` refuses an older server with a configuration error.

### 7. Namespaces and keys

Every stored key is scoped by a namespace.
- **Redis key:** `<prefix><namespace>:<key>`.
- **PostgreSQL:** the `namespace` column.

**Namespace:**
- **Default:** none. The namespace is a required constructor argument, and an empty namespace is a configuration error.
- **Why no default:** the capability requires that guards built with separate limiters do not share buckets. Two shared limiters with the same default namespace would share buckets across flows, silently, which is exactly what the requirement forbids.
- **Built by the factory** (decision 8): the namespace is the guard's flow name, so a consumer using the factory never types one.
- **Duplicates in one process:** a factory refuses to create a second limiter for a namespace it already created, with a configuration error. A consumer who wants two flows to share buckets passes the same limiter instance, as the capability documents.
- **Limit, stated:** duplicates across processes with different limits or windows cannot be detected. The godoc requires every replica to use one configuration per namespace, and decision 4 keeps a mismatch from disarming a limit.

**Prefix (Redis only):**
- **Default:** `scrty:ratelimit:`, a documented constant.
- **Override:** `WithKeyPrefix(p)`. An empty prefix is a configuration error, because it would put scrty keys in the consumer's own keyspace unmarked.

**Keys:**
- Keys are stored exactly as given. The limiter does not parse them, and a user reference used as a key is consumer-owned.
- Keys longer than 512 bytes are stored as `sha256:` followed by the hex digest. This is deterministic on every replica and keeps the PostgreSQL primary key inside btree limits.
- **Override:** none needed. The mapping is invisible to callers.

### 8. The limiter factory

```go
// in core ratelimit
type LimiterFactory interface {
    NewLimiter(namespace string, limit int, window time.Duration) (Limiter, error)
}
func MemoryLimiterFactory(opts ...MemoryOption) LimiterFactory // default
```

Each backend provides its own factory:
- `sqlstore.NewRateLimiterFactory(db *sql.DB, opts...)`;
- `pgx.NewRateLimiterFactory(pool, opts...)`;
- `scrtyredis.NewLimiterFactory(client redis.UniversalClient, opts...)`.

Each backend also keeps its plain constructor, for example `scrtyredis.NewLimiter(client, namespace, limit, window, opts...)`.

- **Why a factory:** each flow owns its limit and window (API key 20 per minute, magic link 10 per 15 minutes, handoff 10 per 5 minutes, second-factor verification 5 per 15 minutes). A consumer building shared limiters by hand would restate those numbers and drift from them. With a factory, each flow keeps its own defaults and only the storage changes.
- **Precedence:** a flow uses its explicit limiter option first, then the configured factory, then `MemoryLimiterFactory()`.
- **The per-replica warning** stays on the in-memory limiter, so it is written exactly when an in-memory limiter is in use.
- **Dependency on other capabilities:** the seam that passes a factory to flows belongs to `http-security` (a chain-level option naming what it governs, for example `WithRateLimiterFactory`) and to the flow options in `auth-methods` and `oidc-brokering`. This change's delta specifies the factory contract in `rate-limiting`. The seam must be added in those capabilities.
- **Construction errors:** a nil `*sql.DB`, pool or client, including a typed nil.

### 9. Wiring

**Plain constructors** are primary. A consumer builds a factory from their backend and passes it to the chain or to each flow. Nothing is probed or selected implicitly.

**`do` wiring:**
- **Default:** in-memory limiters, with the existing INFO. Registering a `*sql.DB` or `SecurityStateStores` does **not** switch rate limiting to PostgreSQL, because that would change the default for a consumer who asked only for durable stores.
- **Override:** either of these:
  - `scrtydo.WithSharedRateLimiting()`, which uses the registered durable backend. With a `*sql.DB` it builds the `sqlstore` factory. With `SecurityStateStores`, the consumer's value supplies it through a `RateLimiterFactory` field, filled in by the `pgx` or `gorm` constructors;
  - a `ratelimit.LimiterFactory` the consumer registers, for example from `scrtyredis`. The `do` module never imports the `redis` module, for the same reason it does not probe pgx or gorm.
- **At `Start`:** the wiring calls `Verify(ctx)` on factories that implement it. That checks for a missing table or migration, an old Redis server and an evicting policy. When a shared factory is in use, the per-replica INFO is not written.

**Errors at `Start`, each naming both sides:**
- `WithSharedRateLimiting()` with no durable backend registered;
- `WithSharedRateLimiting()` together with a registered `LimiterFactory`, which is two sources for one decision;
- `WithSingleProcess()` together with a shared factory. This is contradictory, and the INFO it downgrades is not written anyway;
- a `Verify` failure.

**Errors at construction:** everything in decisions 5 to 8.

**Migration:**
- `rate_limit_buckets` is added to the security-state migration set, so every durable deployment has the table whether or not it uses it. An unused empty table is cheaper than a second migration set and version table.
- **Squashing:** before the first tag, the migration folds into the initial set.

### 10. Conformance suite

`github.com/kartaladev/scrty/test/ratelimittest` exposes `Run(t *testing.T, h Harness)`, where:
- **`Harness.New(t, namespace, limit, window)`** returns a limiter, and **`Harness.Advance(d)`** moves its clock. Shared limiters run it in app-clock mode with a fake clock.
- **`Harness.SecondInstance`** is non-nil for shared limiters. It builds another instance over the same backend, standing in for another replica.

The scenarios mirror the `rate-limiting` requirements:
- no failures is not exceeded; `limit - 1` is not; `limit` is;
- another key's failures do not count;
- a failure one microsecond inside the window counts, and one exactly a window old does not;
- failures straddling a boundary count together;
- excess failures keep the newest stamps;
- a cancelled context makes `Exceeded` return an error, and `RecordFailure` records nothing;
- separate namespaces do not share buckets;
- prune, where supported, keeps a key whose oldest stamp expired but whose newest did not, and never changes the count;
- concurrent checks and records produce no data race, and every key ends exceeded;
- **shared only:** failures recorded through one instance are exceeded through the other;
- **shared only:** a shorter-window instance never removes a failure that a longer-window instance counts.

Runs and fault tests:
- **Who runs it:** all runs live in the `test` module, because no other module may import it (module-layout). That covers the in-memory limiter, the `sqlstore` and `pgx` limiters through `RunTestPostgres`, and the Redis limiter through a new `RunTestRedis` helper.
- **Server-clock mode:** it gets a separate short-window real-time test, because a fake clock cannot drive the backend's clock.
- **Unavailable modes:** tested by stopping the container mid-test. One test per mode shows refuse, fall back and recover, and allow.
- **Seen to fail:** as in `store-conformance`, each scenario is first run against broken variants kept in the tests, and must fail against each:
  - a fixed-window counter;
  - a prune by oldest stamp;
  - a TTL reset on `Exceeded`;
  - a fail-open error path.

### 11. Test-first

- **The suite is written first**, and run against the in-memory limiter before any backend exists. That confirms the suite encodes today's behaviour.
- **Each backend, construction check and wiring error** gets a failing table test in the project's `assert` closure form before its implementation.

### 12. Departures

None. Established behaviour is only the in-memory limiter and the port, and every decision recorded for them is kept:
- failures, not requests;
- the sliding window with strictly-after counting;
- the newest-`limit` cap;
- prunes that take no cutoff and never disarm;
- fail closed on error;
- records that survive client cancellation.

The shared limiters, the unavailable modes and the factory are new behaviour behind existing seams, not changes to recorded decisions.

## Risks / Trade-offs

- **[Fail closed turns a backend outage into refusals on every guarded flow, including second-factor completion]** → It is the documented default, with two explicit overrides. `Verify` at `Start` catches misconfiguration before traffic. The operation timeout keeps an outage from hanging requests.
- **[PostgreSQL write amplification under a distributed attack slows logins that share the database]** → Writes happen only on failures, and a throttled source stops writing. A consumer can pass a separate `*sql.DB` pool. Redis is the alternative.
- **[An evicting Redis policy silently disarms limits]** → `Verify` refuses a known evicting policy and warns when the policy cannot be read.
- **[Replicas with different limits or windows for one namespace]** → The longest window is retained. The godoc requires one configuration per namespace. In-process duplicates are refused.
- **[Source keys (IP addresses and prefixes) and user references are stored at rest in a shared backend]** → They are stored as given, with the same TTL or prune bound as the in-memory map. Hashing would not pseudonymise an IPv4 key, since the space can be enumerated. A consumer who needs it wraps the limiter.
- **[Clock precision differs from the in-memory limiter]** → Microseconds, documented, and the suite steps in microseconds.
- **[Check-then-record still overshoots under concurrency, now across replicas as well]** → The bound is unchanged in kind: the burst's concurrency, now summed across replicas. It is documented.
- **[`WithSharedRateLimiting` depends on adapters that expose a factory]** → Those constructors are added in this change. A consumer with their own stores registers a factory instead.
- **[Inherited from `auth-methods`: `httpsec.WithRateLimiter` and `WithIPv6SourcePrefix` currently reach nothing]** → `config.ipv6Prefix` and `config.limiter` are copied onto `Chain` and read by no production code; each throttled flow builds its own limiter with the default source keyer. Two documented override points therefore do nothing, silently, which is a `library-design` rule 2 and 4 problem rather than a defect of behaviour — nothing computes a wrong answer, the configuration is simply ignored. It reached this change because the limiter factory is what would make a chain-level limiter meaningful: without deciding whether a flow takes the chain's limiter or its own, a shared limiter can be wired and still not be used. The decision is not obvious either way — per-flow limiters are what keep one flow's exhaustion from spending another's allowance — so it needs stating, not defaulting. `auth-methods` labelled it `UNREPRODUCED` deliberately: there is no failing behaviour to reproduce, only configuration that goes nowhere.

## Migration Plan

No consumers and no tags. The default is unchanged, so no deployment behaves differently until it opts in. A deployment that opts in adds the migration (applied with the security-state set), deploys, and can roll back by removing the factory. Counts then restart per replica, which is the documented default's limit.

## Open Questions

- **Backend choice:** PostgreSQL only, Redis only, or both? The recommendation is both, PostgreSQL first (decision 1). It decides which adapter and module tasks exist.
- **Fail-mode default:** is `UnavailableRefuse` right for every flow? Or should second-factor verification, where a refusal blocks sign-in for users who must present a second factor, default to `UnavailableFallBackToLocal`? The recommendation is refuse everywhere, with the override documented per flow.
- **PostgreSQL on the hot path:** is one extra indexed read per API-key request, plus failure writes on the security-state database, acceptable to the teams expected to adopt scrty? Or must shared limiting require Redis for high-volume API-key traffic?
