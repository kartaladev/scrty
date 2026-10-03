## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** The `rate-limiting` capability defines:
  - `ratelimit.Limiter`, with `Exceeded(ctx, key) (bool, error)` and `RecordFailure(ctx, key) error`. An error from `Exceeded` means the limiter could not decide, and callers treat it as exceeded. `RecordFailure` may receive a context stripped of cancellation, so an implementation doing I/O bounds its own;
  - the in-memory limiter, `NewMemoryLimiter(limit, window, ...MemoryOption)` with `WithMemoryLimiterClock(clock.Clock)` and `WithMemoryLimiterLogger`:
    - a sliding window, where a failure counts while strictly after `now - window`;
    - at most `limit` newest stamps per key;
    - exceeded at `count >= limit`;
    - `Exceeded` on an ended context returns `true` with the error; `RecordFailure` ignores cancellation and always records;
    - inline pruning at most once per window, removing a key only when its newest stamp has expired;
    - `Prune()` accepting no window;
    - one per-replica WARN on first use;
    - non-positive limit or window refused with `ErrConfig`;
  - the source keyer and source guard: canonical keys, IPv6 grouping by prefix (default /64), unattributable sources refused rather than pooled, check and record on the same key (`flow:source`), and a record step on `context.WithoutCancel` whose errors are logged.
- **Every place that builds a default limiter today** (13 sites, each with its own replacement option):

  | Site | Key | Records | Default |
  |---|---|---|---|
  | `httpsec` API key guard (`api-key`) | source | failures | 20 / 1m |
  | `httpsec` magic-link redeem guard (`magic-link-redeem`) | source | failures, refused valid redemptions | 10 / 15m |
  | `httpsec` OIDC handoff guard (`oidc.handoff`) | source | failures, refused redemptions | 10 / 5m |
  | `httpsec` passwordless passkey begin guard (`passkey-login`) | source | **every begin** | 30 / 15m |
  | `httpsec` recovery complete guard (`account-recovery`) | source | failures | 10 / 15m |
  | `httpsec` recovery start guard (`account-recovery-start`) | source | **every start** | 10 / 1h |
  | `httpsec` MFA enrolment begin | user reference | **every begin** | 5 / 1h |
  | `httpsec` MFA enrolment confirm | user reference | failures | 5 / 15m |
  | `mfa` verify throttle | user reference | failures | 5 / 15m |
  | `recovery.Recoverer` per-user limiter | user reference | refusals | 5 / 15m |
  | `recovery.Codes` saved-code limiter | user reference | failures | 5 / 15m |
  | `passkey` emailed-code confirm limiter | user reference | failures | 5 / 15m |
  | `httpsec` chain-level `WithRateLimiter` | — | read by nothing (F1) | 5 / 15m |

  The source-keyed sites go through `ratelimit.SourceGuard`. The user-keyed sites call the limiter directly, with `context.WithoutCancel` at the call site.
- **Defects found in these sites** (proven by failing tests, kept as the first red steps of this change):
  - **F1:** `httpsec.WithRateLimiter` and `httpsec.WithIPv6SourcePrefix` are copied onto the chain and read by no production code, contrary to the `http-security-chain` rule that every public option takes effect or is refused at construction. Tests: `TestChainIPv6SourcePrefixReachesSourceGuards`, `TestChainRateLimiterOptionIsConsulted` (names provisional).
  - **F2:** `httpsec`'s throttle record is sampled per raw client address rather than per canonical source, and duplicates the guard's own sampled record. Fifty addresses inside one throttled IPv6 /64 write fifty records instead of one.
  - **F7:** the `mfa` verify throttle's default limiter writes its per-replica warning through `slog.Default()`, not the configured logger. `recovery.Codes` and `recovery.Recoverer` have the same construction (unreproduced there).
- **Capabilities used by name and not restated:** `security-state-stores` (only to state what this change does not touch), `store-conformance` (the seen-to-fail pattern for suites in `github.com/kartaladev/scrty/test`), `module-layout` (nested modules and the dependency guard), `http-security-chain`, `api-keys`, `magic-link`, `oidc-login`, `multi-factor-auth`, `account-recovery` and `passkey-authentication` (the flows above).
- **Not yet built, so not depended on:** `expiry-sweeping` and the `sweep` module (change `operation-hardening`) and `di-wiring` (change `di-wiring`, not scheduled). Phase 1 needs neither: the Redis backend expires keys by TTL, and wiring is by plain constructors.
- **Settled rules:**
  - rate limiting is in-memory by default;
  - the core module has no driver dependency;
  - wiring mistakes fail at construction;
  - options are named after what they govern;
  - the library never interprets consumer-owned data, including a user reference used as a limiter key.
- **Established behaviour** has no shared limiter, no factory and no unavailable-mode handling. It states the per-replica limit and relies on the port for replacement. Every limiter decision it records is kept (decision 13).

## Goals / Non-Goals

**Goals:**
- A limit that holds across replicas, with the existing semantics unchanged and proven by one conformance suite that every limiter runs.
- One seam, the limiter factory, that reaches every built-in throttled flow.
- A backend outage that refuses by default, refuses fast, and never degrades silently.
- The chain-level limiter settings either take effect or no longer exist (F1), and the throttle-record and logger defects (F2, F7) fixed.
- A single-process consumer who sees no difference.

**Non-Goals:**
- **Changing the default.** The in-memory limiter stays the default for every flow and constructor.
- **A PostgreSQL limiter.** It is change `shared-rate-limiting-postgres`, which depends on `operation-hardening` for its sweep.
- **Container wiring.** Selecting a factory from a `samber/do` container is change `di-wiring`.
- **Closing the check-then-record overshoot.** A concurrent burst can still exceed the limit by its concurrency, now summed across replicas. Per-code attempt accounting for the user-keyed code flows is change `atomic-code-attempts`.
- **Per-source limiting of password login** (`login-source-throttling`), **a bound on the number of keys** (`limiter-key-bounds`) and **a trusted-proxy client-address seam** (`trusted-proxy-client-ip`).
- **Sharing account lockout**, one-time-token issuance counts, MFA replay protection or sessions. These are store contracts owned elsewhere.
- **Key-value stores other than Redis and Valkey.** A consumer implements the port and runs the conformance suite.
- **`RateLimit` / `RateLimit-Policy` response headers.** The IETF draft is not final, and the port does not report a reset time.
- **Pseudonymising source keys at rest** (see Risks).

## Decisions

### 1. Backend: Redis and Valkey in this change; PostgreSQL follows

| | PostgreSQL | Redis / Valkey |
|---|---|---|
| **New infrastructure** | none for durable deployments | a server the consumer may not run |
| **New dependency** | none in core | `github.com/redis/go-redis/v9` in a new nested module |
| **Expiry** | needs a prune task, which needs `operation-hardening` | TTL on the key, no sweep |
| **Write load** | every recorded failure **and every begin** of the passkey, recovery-start and enrolment-begin flows rewrites a row; the row's index on `newest_at` would also make every update non-HOT | in memory, isolated from the security-state database |
| **Reads on the hot path** | one indexed lookup per guarded request, on the pool that serves logins | one script call |

**Decision: Redis and Valkey first, PostgreSQL in `shared-rate-limiting-postgres`.**
- The backend-neutral pieces (factory, seams, unavailable modes, conformance suite, F1/F2/F7) land once, here.
- Redis needs no sweep and no migration, so this change does not wait on `operation-hardening`.
- The original premise for PostgreSQL, that "legitimate traffic writes nothing", is false: three flows record every begin. PostgreSQL's write cost therefore needs the benchmark its own change will carry.

- **Default:** no shared limiter. Every flow builds its in-memory limiter.
- **Override:** the consumer builds a Redis factory and passes it to the chain or to each flow (decision 9).

### 2. Algorithm fidelity: the same sliding-window log, stored remotely

The shared limiter stores the same data as the in-memory one: per key, at most `limit` stamps, the newest ones.

- **`Exceeded`:** count the stamps strictly after `now - window`, and report `count >= limit`. It performs no write.
- **`RecordFailure`:**
  1. drop the stamps at or before `now - window`;
  2. append `now`;
  3. keep the newest `limit`;
  4. extend the key's lifetime to at least `now + window`.
- **Ended context, matching the in-memory limiter:**
  - `Exceeded` with an ended context returns `true` and the error, before any I/O;
  - `RecordFailure` ignores cancellation, as the port allows, and is bounded by the limiter's own operation timeout (decision 5).
- **What is recorded** is the caller's business: most flows record failures, and the begin and start flows record every call. The limiter counts whatever it is given.

**Alternatives rejected:**
- **A fixed-window counter** (`INCR` with `EXPIRE`). It fails the specified "straddling a boundary" scenario, allowing a 2x burst at every boundary.
- **A sliding-window counter approximation** (two fixed windows, weighted). It is the right trade for counting every request at high volume, where a log would be large. Here at most `limit` stamps per key are stored, so the log's cost is bounded and its answer is exact.
- **A token bucket or GCRA** (for example `go-redis/redis_rate`). These keep one theoretical-arrival value per key and rate requests. They cannot answer "how many failures lie strictly inside the window, capped at the newest `limit`", which is the specified behaviour.

**Precision:** stamps are stored in microseconds. The in-memory limiter uses nanoseconds. The conformance suite steps time by at least one microsecond, and the godoc states the precision.

### 3. Redis atomicity, scripts and server floor

One sorted set per key. Each score is a microsecond timestamp. Each member is that timestamp plus a random suffix, so equal stamps never collapse.

- **`RecordFailure` script**, run with go-redis `Script.Run` (`EVALSHA`, falling back to `EVAL` on `NOSCRIPT`):
  1. read `TIME`;
  2. `ZREMRANGEBYSCORE key -inf cutoff`;
  3. `ZADD key now member`;
  4. `ZREMRANGEBYRANK key 0 -(limit+1)`;
  5. set the TTL to the larger of the current `PTTL` and `window`. `PEXPIRE … GT` alone is not enough: on a key with no TTL, `GT` treats the TTL as infinite and does nothing. A test pins the no-TTL path.
- **`Exceeded` script**, read-only, run with `Script.RunRO` (`EVALSHA_RO`, falling back to `EVAL_RO`): `ZCOUNT key (cutoff +inf`.
- **Single declared key.** Each script touches exactly the one key it declares in `KEYS`, so it is valid on Redis Cluster without hash tags, and on servers that enforce declared keys.
- **Why scripts and not `MULTI`:** a transaction cannot branch on the time it reads.
- **Why not Redis Functions:** functions persist, but on a cluster an operator must load them onto every primary. An embedded library cannot assume that. Eval scripts reload themselves on `NOSCRIPT` after a restart, failover or `SCRIPT FLUSH`.
- **Server floor: Redis 7.0 or Valkey 7.2.** This is required by `PEXPIRE` options and `EVALSHA_RO`. (`TIME` before writes has been allowed since effects replication became the default in Redis 5.) `Verify` refuses an older server with a configuration error.
- **Primary only.** Both scripts must run on the primary: a lagging replica undercounts. The godoc requires a client that does not route reads to replicas (`ReadOnly`, `RouteByLatency` and `RouteRandomly` off). A cluster client with replica reads enabled is refused at construction where go-redis exposes the setting, and documented where it does not.
- **Client type:** the constructors take `redis.UniversalClient`, which covers a single node, Sentinel failover and Cluster.
  - **Why not the narrower `redis.Scripter`:** `Verify` also needs `INFO` and `CONFIG GET`.
  - **Override:** a consumer on another client implements `ratelimit.Limiter` and runs the conformance suite.
- **Minimum go-redis:** v9.7.3, the first v9 line free of GO-2025-3540.

**Why check-then-record stays non-atomic.** A combined "check and reserve" would close the overshoot, but it changes the port and every flow's ordering. It would also count attempts that later succeed. The port is unchanged. Per-code accounting for the user-keyed code flows, where the overshoot matters most, is `atomic-code-attempts`.

### 4. Expiry and eviction never disarm a limit

The rule carries over unchanged: nothing may remove a key whose newest stamp is still inside the window.

- **TTL:** at least `newest stamp + window`. It is set only by `RecordFailure` and only ever extended. `Exceeded` never touches it.
- **Mixed windows during a rollout:** because the TTL is only extended, a replica configured with a shorter window cannot expire a failure that a longer-window replica still counts. Each replica still counts with its own window. The godoc requires one configuration per namespace.
- **Eviction:** an evicting `maxmemory-policy` (`allkeys-*`, or `volatile-*`, since every limiter key has a TTL) can drop a live key, which disarms that source's limit. Only `noeviction` is safe.
  - `Verify(ctx)` reads the policy with `CONFIG GET`.
  - **An evicting policy:** a configuration error.
  - **An unreadable policy** (managed services may block `CONFIG`): one WARN naming the requirement.
  - **Override:** `WithEvictionPolicyCheck(false)`, for a consumer who has verified the policy out of band. The godoc names what that gives up.
- **Out of memory under `noeviction`:** writes fail while reads still succeed. A naive limiter would therefore stop counting while still answering "not exceeded". Decision 5's record-error rule closes this.
  - **Status:** `UNREPRODUCED` (no code yet).
  - **First red step:** a Redis container with a tiny `maxmemory` and `noeviction`, where a source keeps failing past its limit and is never refused.

### 5. Backend unavailable: fail closed by default, and fast

A backend error is already an error under the port, and the guard already refuses on it. This change keeps that default, makes refusal fast during an outage, closes the write-fails-read-succeeds gap, and adds explicit overrides.

```go
type UnavailableMode int // UnavailableRefuse (default), UnavailableFallBackToLocal, UnavailableAllow
func WithOnUnavailable(m UnavailableMode) Option
func WithOperationTimeout(d time.Duration) Option      // default 250ms; bounds each call, records included
func WithUnavailableProbeInterval(d time.Duration) Option // default 1s; every mode
```

**What counts as unavailable:** any backend error, a timeout, or an exhausted pool while the caller's context is still live. A check whose caller context has ended always returns `true` and the error, whatever the mode, and the guard logs it at DEBUG.

**Circuit breaker, in every mode.** After an unavailable error, the limiter treats the backend as down for the probe interval and answers from its mode without calling the backend. After the interval, one call goes through as a probe. Success closes the breaker; failure reopens it.
- **Why also in refuse mode:** without the breaker, every guarded request waits the full operation timeout during an outage and can exhaust the connection pool. Refusing should cost nothing.

**Record errors close the read-succeeds gap.** When `RecordFailure` fails for key `k`:
- the breaker opens, as for any unavailable error;
- in **refuse** mode, `k` is held locally as refused for one window, so `Exceeded(k)` on this replica refuses even after the breaker closes and reads succeed again. The local hold set is bounded and pruned like the in-memory limiter;
- in **fall-back** mode, the failure is recorded in the local limiter, and `Exceeded(k)` is exceeded when either the shared count or the local count is;
- in **allow** mode, the failure is dropped.

**The modes:**
- **`UnavailableRefuse` (default):**
  - `Exceeded` returns `true` and the error, so the guard refuses as throttled;
  - `RecordFailure` returns the error, and the caller logs it.
  - **Cost, stated:** while the backend is down, every guarded flow refuses. That includes API-key requests, magic-link and handoff redemption, recovery, passwordless begin, and second-factor verification, so users who need a second factor cannot complete sign-in.
  - **Why this is the default:** a limiter that fails open under load is one an attacker disables by causing load, and the capability already requires failing closed. Gateways commonly fail open for general traffic (Kong `fault_tolerant`, Stripe). A guard against credential guessing is a different case.
- **`UnavailableFallBackToLocal`:**
  - while the breaker is open, both calls go to an in-memory limiter with the same limit and window, built by the constructor;
  - **stated limit:** during the outage the effective limit is N times, as for the documented default;
  - **logging:** each transition, to local and back, is logged at ERROR and WARN.
  - **Recommended for second-factor flows:** they still get a bound per replica, well inside NIST SP 800-63B's 100-failure ceiling, and users are not locked out of sign-in by an outage. The godoc of each user-keyed flow says so.
- **`UnavailableAllow`:**
  - while the breaker is open, `Exceeded` returns `false, nil`, and `RecordFailure` drops the failure;
  - an ERROR is logged, sampled per namespace;
  - **stated limit:** no limit during the outage. The godoc says it is for flows whose consumer has another bound in front, such as an edge limiter.

**Where the modes live:** `ratelimit.UnavailableMode` is public. The decorator is in `internal/unavailable`, which every scrty backend module can import, and each backend constructor applies it through its own options. The guard cannot tell a backend outage from a bug, and the in-memory default has no outage.

**Construction errors:** an unknown mode, or a non-positive timeout or probe interval.

### 6. Clock: the backend's by default

- **Default:** time is read inside the script with `TIME`.
  - **Why:** with the application clock, a replica running 30 seconds fast writes stamps that other replicas count for 30 seconds longer. A replica running slow computes a cutoff that counts expired failures. With the server clock, one clock orders every stamp. `go-redis/redis_rate` does the same.
- **Override:** `WithLimiterClock(clock.Clock)`, taking scrty's `pkg/clock` seam, passes the time as a script argument instead. It serves tests, and deployments that trust their own clock discipline more than the server's.
  - **Stated limit:** replica clocks must agree to well within the window.
  - **Construction error:** a nil clock, typed nil included.

### 7. Namespaces and keys

Every stored key is scoped by a namespace: `<prefix><namespace>:<key>`.

**Namespace:**
- **Default:** none. The namespace is a required constructor argument, and an empty namespace is a configuration error.
  - **Why:** two shared limiters with the same default namespace would share buckets across flows, silently, which the capability forbids.
- **Built by a factory:** each flow passes its own namespace (decision 8), so a consumer using the factory never types one.
- **The same namespace twice in one process:** a factory returns a limiter over the same buckets, exactly as another replica would. This covers two chains built from one factory, or a flow constructed twice.
  - Asking for the same namespace with a **different limit or window** is a configuration error, because one bucket cannot hold two policies.
  - **Departure from the earlier draft**, which refused every duplicate. Refusing would break a consumer who builds two chains from one factory.
  - **Across processes,** a mismatch cannot be detected. The godoc requires one configuration per namespace, and decision 4 keeps a mismatch from disarming a limit.

**Prefix:**
- **Default:** `scrty:ratelimit:`, a documented constant.
- **Override:** `WithKeyPrefix(p)`. An empty prefix is a configuration error, because it would put scrty keys in the consumer's keyspace unmarked.

**Keys:**
- Keys are stored exactly as given. The limiter does not parse them, and a user reference used as a key is consumer-owned.
- Keys longer than 512 bytes are stored as `sha256:` followed by the hex digest. This is deterministic on every replica.
- **Override:** none needed. The mapping is invisible to callers.
- **ACL, documented:** the limiter needs `EVAL`, `EVALSHA`, `EVAL_RO`, `EVALSHA_RO` and `SCRIPT LOAD` on keys under its prefix. `Verify` additionally needs `INFO` and `CONFIG GET`.

### 8. The limiter factory

```go
// in core ratelimit
type LimiterFactory interface {
    NewLimiter(namespace string, limit int, window time.Duration) (Limiter, error)
}
func MemoryLimiterFactory(opts ...MemoryOption) LimiterFactory // the default

type Verifier interface { Verify(ctx context.Context) error } // optional, implemented by shared factories
```

- **Redis:** `scrtyredis.NewLimiterFactory(client redis.UniversalClient, opts ...Option)` and the plain `scrtyredis.NewLimiter(client, namespace, limit, window, opts...)`, in the nested module `github.com/kartaladev/scrty/redis`.
- **Why a factory:** each flow owns its limit and window. A consumer building shared limiters by hand would restate the 12 defaults above and drift from them. With a factory, each flow keeps its defaults and only the storage changes.
- **The in-memory factory** returns a new limiter with separate buckets on every call, as each flow builds one today. A component that builds its default from it passes its own logger and clock (fixing F7). A consumer-supplied factory owns its own logging.
- **Namespaces:** each source-keyed guard uses its flow name. Each user-keyed site uses a fixed, documented namespace: `mfa-verify`, `mfa-enrol-begin`, `mfa-enrol-confirm`, `recovery-user`, `recovery-codes` and `passkey-email-confirm`. The keys themselves are unchanged.
- **Precedence at every site:**
  1. the site's explicit limiter option;
  2. the configured factory;
  3. `MemoryLimiterFactory()` with the component's logger and clock.
- **Where the factory option lives:**
  - `httpsec.WithRateLimiterFactory(f)` reaches every limiter the chain builds, including the MFA, recovery and passkey components the chain constructs;
  - `mfa`, `recovery` and `passkey` each gain a component option, for consumers who build them without the chain;
  - each option is named after what it governs.
- **The per-replica warning** stays on the in-memory limiter, so it is written exactly when an in-memory limiter is in use.
- **Construction errors:** a nil factory or client, typed nil included. A factory's own `NewLimiter` error fails the component's constructor, wrapped with the namespace.

### 9. Chain-level settings (F1)

`httpsec.WithRateLimiter(l)` gives one limiter, with one limit and window, for flows whose defaults differ by an order of magnitude. And `WithIPv6SourcePrefix` reaches no guard.

- **`WithRateLimiter` is removed** and replaced by `WithRateLimiterFactory`.
  - **Why:** a single limiter for every flow would either impose one policy on all of them, or need a precedence rule nobody can predict.
  - Nothing is tagged, so removal is free (library-design rule 7), and it is recorded here.
  - A consumer who really wants every flow to share one limiter passes it to each flow's option, as the capability documents.
- **`WithIPv6SourcePrefix(bits)` takes effect.** Every source guard the chain builds uses a keyer with that prefix. A flow-level keyer is out of scope; see `limiter-key-bounds`, which may add an aggregate prefix.
- **The `http-security-chain` rule holds again:** every public option takes effect or is refused at construction. A nil factory is a configuration error, replacing the chain's "absent rate limiter" error.

### 10. Throttle records sampled per canonical source (F2)

The `httpsec` throttle record keyed on `flow|clientAddr` is removed. The guard already writes a record sampled per flow and canonical source.

- **Default:** one record per flow and canonical source per sampling window.
- **Override:** the guard's existing log-interval option.

### 11. Wiring

- **Plain constructors only.** A consumer builds a factory from their client and passes it to the chain or to each component. Nothing is probed or selected implicitly.
- **`Verify(ctx)`** checks the server version, the eviction policy and that both scripts load. It is never called by a constructor, because constructors do no I/O.
  - The consumer calls it at startup, before traffic.
  - The godoc and the example show where.
  - `di-wiring` calls it at container start when that change is applied.
- **New module:** `github.com/kartaladev/scrty/redis`, package `scrtyredis`, on go-redis v9.7.3 or later. It is added to `go.work`, to the dependency guard and to CI. The core module gains no dependency.

### 12. Conformance suite

`github.com/kartaladev/scrty/test/ratelimittest` exposes `Run(t *testing.T, h Harness)`, where:
- **`Harness.New(t, namespace, limit, window)`** returns a limiter, and **`Harness.Advance(d)`** moves its clock. The Redis limiter runs it in app-clock mode with a fake clock.
- **`Harness.SecondInstance`** is non-nil for shared limiters. It builds another instance over the same backend, standing in for another replica.

The scenarios mirror the `rate-limiting` requirements:
- no failures is not exceeded; `limit - 1` is not; `limit` is;
- another key's failures do not count;
- a failure one microsecond inside the window counts, and one exactly a window old does not;
- failures straddling a boundary count together;
- excess failures keep the newest stamps;
- `Exceeded` with an ended context returns `true` and an error;
- `RecordFailure` with an ended context still records;
- separate namespaces do not share buckets;
- concurrent checks and records produce no data race, and every key ends exceeded;
- **shared only:** failures recorded through one instance are exceeded through the other;
- **shared only:** a shorter-window instance never expires a failure that a longer-window instance counts.

Runs and fault tests:
- **Who runs it:** all runs live in the `test` module, because no other module may import it (module-layout). That covers the in-memory limiter, and the Redis limiter through a new `RunTestRedis` helper.
- **Server matrix:** Redis 7.x, Redis 8.x and Valkey 8.x. The helper defaults to the newest Redis.
- **Server-clock mode:** a separate short-window real-time test, because a fake clock cannot drive `TIME`.
- **Unavailable modes and the breaker:** tested by stopping the helper's own container mid-test. The container is never one shared across tests, because `testcontainers-optimize` shares the PostgreSQL server per process and the same pattern is expected for Redis. There is one test per mode, plus one that the breaker refuses without waiting for the timeout.
- **Out of memory:** the decision 4 red step.
- **No-TTL path:** a key without a TTL gets one on the next record.
- **Seen to fail:** as in `store-conformance`, each scenario is first run against broken variants kept in the tests, and must fail against each:
  - a fixed-window counter;
  - a TTL reset on `Exceeded`;
  - `PEXPIRE … GT` without the no-TTL fallback;
  - a fail-open error path.

### 13. Departures

None from established behaviour. Established behaviour is only the in-memory limiter and the port, and every decision recorded for them is kept:
- failures, not requests;
- the sliding window with strictly-after counting;
- the newest-`limit` cap;
- prunes that take no cutoff and never disarm;
- fail closed on error;
- records that survive client cancellation.

**Departures from scrty's own settled specs**, each through a delta in this change:
- `http-security-chain`: `WithRateLimiter` is removed, and `WithRateLimiterFactory` and the working `WithIPv6SourcePrefix` are added (decision 9).
- `rate-limiting`: `UnavailableAllow` and `UnavailableFallBackToLocal` are explicit overrides of "limiter errors fail closed". The fail-closed default is unchanged.

### 14. Test-first

- **F1, F2 and F7 first.** Each fix starts from its reproducing test, rewritten in the project's `assert` closure form.
- **The suite next,** run against the in-memory limiter before any backend exists, to confirm it encodes today's behaviour.
- **Each Redis behaviour, construction check and breaker transition** gets a failing table test before its implementation.

## Risks / Trade-offs

- **[Fail closed turns a Redis outage into refusals on every guarded flow, including second-factor completion]** → It is the documented default. The breaker makes refusal immediate. Fall-back is documented as the recommended second-factor override. `Verify` at startup catches misconfiguration.
- **[An evicting Redis policy silently disarms limits]** → `Verify` refuses a known evicting policy and warns when it cannot read one.
- **[Writes fail while reads succeed (OOM)]** → Record errors hold the key locally as refused (refuse mode) or count it locally (fall-back mode). This stays `UNREPRODUCED` until its red step.
- **[A replica-routed read undercounts]** → Primary-only is required, refused where detectable, and documented.
- **[Replicas with different limits or windows for one namespace]** → The TTL only extends, the godoc requires one configuration, and in-process mismatches are refused.
- **[Source keys (IP addresses and prefixes) and user references are stored at rest in a shared backend]** → They are stored as given, bounded by the TTL. Hashing would not pseudonymise an IPv4 key, since the space can be enumerated. A consumer who needs it wraps the limiter.
- **[Clock precision differs from the in-memory limiter]** → Microseconds, documented, and the suite steps in microseconds.
- **[Check-then-record overshoots, now summed across replicas]** → The bound is documented. Per-code accounting is `atomic-code-attempts`.
- **[Removing `httpsec.WithRateLimiter` breaks any consumer using it]** → None exist and nothing is tagged. The option did nothing anyway.

## Migration Plan

No consumers and no tags. The default is unchanged, so no deployment behaves differently until it opts in. A deployment that opts in deploys a Redis or Valkey server with `noeviction`, calls `Verify` at startup, and passes the factory. It can roll back by removing the factory; counts then restart per replica, which is the documented default's limit. No schema migration.

## Open Questions

None. Resolved 2026-10-03:
- **Backend:** Redis and Valkey here; PostgreSQL in `shared-rate-limiting-postgres` (decision 1).
- **Fail-mode default:** refuse everywhere, with fall-back documented as the recommended second-factor override (decision 5).
- **PostgreSQL on the hot path:** deferred to `shared-rate-limiting-postgres`, which will benchmark it.

## References

### Decision 1: backend
**Researched (accessed 2026-10-03):**
- [PostgreSQL: Heap-Only Tuples](https://www.postgresql.org/docs/current/storage-hot.html): an update that changes an indexed column is never HOT.
- [Keycloak caching guide](https://raw.githubusercontent.com/keycloak/keycloak/main/docs/guides/server/caching.adoc), [Authelia regulation](https://www.authelia.com/configuration/security/regulation/) and [Django-axes configuration](https://django-axes.readthedocs.io/en/latest/4_configuration.html): established auth servers keep brute-force state in a database or a shared cache.

### Decision 2: algorithm
**Researched (accessed 2026-10-03):**
- [Cloudflare: counting things, a lot of different things](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/): the sliding-window counter trade-off, and why a log is costly when every request is counted.
- [go-redis/redis_rate `lua.go`](https://raw.githubusercontent.com/go-redis/redis_rate/v10/lua.go): GCRA keeps one value per key and rates requests.

### Decision 3: scripts and server floor
**Researched (accessed 2026-10-03):**
- [Redis PEXPIRE](https://redis.io/docs/latest/commands/pexpire/) and [Valkey PEXPIRE](https://valkey.io/commands/pexpire/): `GT` treats a key with no TTL as infinite; options from 7.0.
- [Redis: scripting with Lua](https://redis.io/docs/latest/develop/programmability/eval-intro/): script cache loss and `NOSCRIPT`, effects replication as the default since 5.0, declared keys.
- [Redis Functions](https://redis.io/docs/latest/develop/programmability/functions-intro/): functions must be loaded onto every cluster primary.
- [go-redis `script.go`](https://raw.githubusercontent.com/redis/go-redis/master/script.go) and `go doc github.com/redis/go-redis/v9 Script.RunRO`: `Run`/`RunRO` fall back from `EVALSHA` to `EVAL`.
- [OSV query for `github.com/redis/go-redis/v9`](https://api.osv.dev/v1/query): GO-2025-3540, fixed in 9.5.5, 9.6.3 and 9.7.3.
- [PostgreSQL: hot standby](https://www.postgresql.org/docs/current/hot-standby.html): replicas are eventually consistent. The same reasoning motivates primary-only Redis reads; that a Redis replica can undercount is reasoned, not documented.
- Live figures (read 2026-10-03; they drift): `redis/go-redis` v9.22.0 (2026-08-03), 22,258 stars; `valkey-io/valkey-go` v1.0.78 (2026-09-15).
- [Redis AGPLv3 announcement](https://redis.io/blog/agplv3/): licence history, and why Valkey is supported alongside Redis.

### Decision 4: expiry and eviction
**Researched (accessed 2026-10-03):**
- [Redis key eviction](https://redis.io/docs/latest/develop/reference/eviction/): eviction policies, and `noeviction` rejecting writes.
- [Amazon ElastiCache parameter groups](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ParameterGroups.html): managed services set the policy through parameter groups. That `CONFIG` is blocked there is unverified.

### Decision 5: unavailable modes
**Researched (accessed 2026-10-03):**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.1.1.2 and §3.2.2: rate limiting against online guessing, at most 100 consecutive failures per account.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and [Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): neither states a fail mode.
- [Kong rate limiting](https://developer.konghq.com/plugins/rate-limiting/reference/), [Envoy rate limit filter](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ratelimit/v3/rate_limit.proto) and [Stripe: scaling your API with rate limiters](https://stripe.com/blog/rate-limiters): gateways fail open for general traffic.

### Decision 6: clock
**Researched (accessed 2026-10-03):**
- [go-redis/redis_rate `lua.go`](https://raw.githubusercontent.com/go-redis/redis_rate/v10/lua.go): a shared limiter reading the server's `TIME`.

### Decisions 7–13
Reasoned from scrty's own settled specs (`rate-limiting`, `http-security-chain`, `module-layout`, `store-conformance`), the failing tests behind F1, F2 and F7, and the established design.

### Non-goals
**Researched (accessed 2026-10-03):**
- [draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/): revision -11 of 2026-05-23, still an Internet-Draft. Its status drifts.

**Primary documentation:**
- [RFC 9110 §10.2.3, Retry-After](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3).
