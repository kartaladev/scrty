## Why

The `rate-limiting` capability ships one limiter, in memory, and states its limit: each process counts only the failures it saw, so behind N replicas every per-source limit is effectively N times higher. That affects every guard built on it:
- API-key verification;
- magic-link, handoff and recovery redemption;
- passwordless begin;
- second-factor verification and enrolment;
- recovery-code checks.

An attacker who spreads attempts across replicas through the load balancer gets the multiplication for free. This change gives multi-replica deployments a limiter whose count is shared by every replica, without changing what a single-process consumer gets by default.

Evaluating the existing components for this change found three defects in the seams a shared limiter must pass through, each reproduced by a failing test:
- **F1:** `httpsec.WithRateLimiter` and `httpsec.WithIPv6SourcePrefix` take effect nowhere, which breaks the `http-security-chain` rule that every option takes effect or is refused.
- **F2:** throttle records are sampled per raw address instead of per canonical source, and duplicated.
- **F7:** the MFA verify throttle's default limiter ignores the configured logger.

A shared limiter that the flows cannot receive would be worse than none, so these are fixed here.

## What Changes

- **A limiter factory port** in core `ratelimit`, with an in-memory default, that reaches every built-in throttled flow. There are 12 limiter sites across `httpsec`, `mfa`, `recovery` and `passkey`, each keeping its own limit and window. Precedence: the site's own limiter option, then the configured factory, then the in-memory default built with the component's logger and clock.
- **A shared limiter on Redis and Valkey** in a new nested module, `github.com/kartaladev/scrty/redis`, on go-redis v9. It preserves the limiter semantics exactly:
  - failures, not requests, per key;
  - a sliding window where a failure counts while strictly newer than now minus the window;
  - at most the limit's number of newest failures kept;
  - no expiry or eviction path that removes a key whose newest failure is still inside the window.
- **Fail closed when the backend is unavailable, and fail fast.** A circuit breaker answers from the configured mode during an outage, without waiting on timeouts. A failed record cannot leave a source unthrottled while reads still succeed. The explicit overrides are fall back to a per-replica count, or, deliberately, allow.
- **The backend's clock by default**, with the application clock as an override.
- **Per-flow namespaces.**
- **Startup verification** of the server version, the eviction policy and the scripts.
- **A rate-limiting conformance suite** in the `test` module, which the in-memory limiter and every shared limiter must pass. Shared limiters also pass cross-instance scenarios.
- **Chain-level settings (F1):**
  - `httpsec.WithRateLimiter` is replaced by `httpsec.WithRateLimiterFactory`;
  - `httpsec.WithIPv6SourcePrefix` reaches every source guard the chain builds.
- **Throttle records (F2):** one record per flow and canonical source per sampling window.
- **Default-limiter logging (F7):** default limiters log through the component's configured logger.
- **Unchanged:** the in-memory limiter remains the default everywhere, with its per-replica warning.
- **Not in this change:**
  - a PostgreSQL limiter (`shared-rate-limiting-postgres`);
  - container wiring (`di-wiring`);
  - per-code attempt accounting (`atomic-code-attempts`);
  - per-source limiting of password login (`login-source-throttling`);
  - a bound on the number of keys (`limiter-key-bounds`);
  - a trusted-proxy client-address seam (`trusted-proxy-client-ip`).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rate-limiting`:
  - shared limiters count across instances;
  - the fail-closed default holds under backend unavailability, refusal is immediate, and the fall-back and allow overrides are explicit;
  - a failed record never leaves a source unthrottled;
  - the backend clock is the default;
  - namespaces keep flows separate;
  - expiry and eviction never disarm a limit;
  - a limiter factory reaches every built-in throttled flow;
  - every limiter passes the conformance suite.
- `http-security-chain`:
  - the chain-level limiter option becomes a factory option;
  - the IPv6 source prefix takes effect on every source guard the chain builds.
  - throttle records are sampled per flow and canonical source, and the consumer's refusal-log reporter still receives the guards' summaries.

## Impact

- **New code:**
  - core `ratelimit`: the factory port and in-memory factory, the `Verifier` port, the unavailable modes, and the breaker decorator;
  - factory options in `httpsec`, `mfa`, `recovery` and `passkey`;
  - the nested module `github.com/kartaladev/scrty/redis` (package `scrtyredis`);
  - `test/ratelimittest`, the conformance suite, and a `RunTestRedis` testcontainers helper.
- **Changed code:**
  - `httpsec`: `WithRateLimiter` is removed, `WithIPv6SourcePrefix` is wired, and the duplicate throttle record is removed;
  - `mfa` and `recovery`: their default limiters receive the component's logger and clock.
- **Dependencies:** none added to the core module. go-redis v9.7.3 or later enters only the graph of consumers who require the `redis` module. The `test` module gains the testcontainers Redis module.
- **Depends on:** `rate-limiting`, `http-security-chain`, `module-layout`, `store-conformance`, and the flows' capabilities (`api-keys`, `magic-link`, `oidc-login`, `multi-factor-auth`, `account-recovery`, `passkey-authentication`). It does not depend on `operation-hardening` or `di-wiring`.
- **Sequencing:** the Redis helper follows the per-process sharing pattern `testcontainers-optimize` sets for PostgreSQL. Outage tests always use their own container.
- **Consumers:** none yet. Nothing is tagged. Removing `httpsec.WithRateLimiter` breaks no one, and the default behaviour does not change.
