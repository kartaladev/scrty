## Why

The `rate-limiting` capability ships one limiter, in memory, and states its limit: each process counts only the failures it saw, so behind N replicas every per-source limit is effectively N times higher. For a deployment with more than one replica, the API-key, magic-link and handoff guards therefore bound guessing far less than their configured numbers suggest, and an attacker who spreads attempts across replicas through the load balancer gets the multiplication for free. This change gives such deployments a limiter whose count is shared by every replica, without changing what a single-process consumer gets by default.

## What Changes

- Add **shared limiter implementations** behind the existing limiter port. They count failures in a backend every replica reads, so a limit means the same thing at one replica and at twenty. The backend (PostgreSQL, Redis, or both) is an open question in design.md.
- **Preserve the limiter semantics exactly:**
  - failures, not requests, are counted, per canonical source key;
  - the window slides, and a failure counts while strictly newer than now minus the window;
  - at most the limit's number of newest failures is kept per key;
  - no expiry, TTL or pruning path can remove a key whose newest failure is still inside the window.

  Canonical source keys, including IPv6 prefix grouping and the refusal of unattributable sources, stay in the source guard and are unchanged.
- **Keep failing closed when the backend is unavailable.** A check that cannot reach the backend refuses the attempt, as the capability already requires of any limiter. Add an explicit, documented consumer override: fall back to a per-replica in-memory count, or, as a deliberate choice, allow.
- **Take time from the backend's clock by default**, so replicas with skewed clocks cannot expire or extend each other's failures. The application clock is an override.
- **Namespace keys per flow**, so separate limiters never share buckets by accident, and bound backend storage with the limiter's own window.
- Add a **limiter factory** port, so every throttled flow can build its default limiter from one shared backend while keeping its own limit and window.
- Add a **rate-limiting conformance suite** to the `test` module. The in-memory limiter and every shared limiter must pass it, and shared limiters must also pass a cross-instance scenario.
- **Wiring:** plain constructors for each backend, and optional selection in the `do` wiring. Contradictory configuration fails at construction or at `Start`.
- **Unchanged:** the in-memory limiter remains the default everywhere, with its per-replica warning.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rate-limiting`: adds requirements for limiters whose count is shared across replicas:
  - counts are shared across instances;
  - the fail-closed default holds under backend unavailability, and the fallback and allow overrides are explicit;
  - the backend clock is the default;
  - namespacing keeps flows separate;
  - expiry by TTL or pruning never disarms a limit;
  - every limiter passes the conformance suite.

  The capability is still being introduced by `authn-authz-core` and is not yet a main spec. This change's delta spec is written as a MODIFIED delta once `authn-authz-core` is archived. Until then this change carries only proposal.md and design.md.

## Impact

- **New code:**
  - core `ratelimit`: the limiter factory port, the backend-unavailable modes and the decorator that applies them;
  - a PostgreSQL limiter in the `sqlstore` and `pgx` adapters, plus one migration in the security-state set, if PostgreSQL is chosen;
  - a new nested module `github.com/kartaladev/scrty/redis` on `github.com/redis/go-redis/v9`, if Redis is chosen;
  - `test/ratelimittest`: the conformance suite, with a Redis testcontainers helper if Redis is chosen.
- **Dependencies:** none added to the core module. go-redis enters only the graph of consumers who require the `redis` module.
- **Flows that benefit** (each already accepts a replacement limiter):
  - API-key verification, 20 failures per source per minute by default;
  - magic-link redemption, including refused redemptions of a valid link, 10 per 15 minutes;
  - OIDC handoff redemption, including refused redemptions, 10 per 5 minutes;
  - second-factor code verification, counted per user reference;
  - any per-source guard a consumer adds to their own login or other endpoints through the source guard.

  Account lockout on password login is not affected. It counts through the attempt store, which the durable adapters already share.
- **Depends on:**
  - `authn-authz-core` (`rate-limiting`, which this change modifies);
  - `durable-persistence` (adapters, migration set and `test` module layout);
  - `expiry-sweeping` and `di-wiring` (the prune task and container wiring);
  - `http-security`, `auth-methods` and `oidc-brokering` (the flows that build default limiters).
- **Consumers:** none yet. Nothing is tagged, and the default behaviour does not change.
