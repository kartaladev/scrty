# Tasks

Phase 1 of shared rate limiting: the backend-neutral core, the factory seam through every flow, the
F1/F2/F7 fixes, and the Redis/Valkey module. PostgreSQL is `shared-rate-limiting-postgres`;
container wiring is `di-wiring`. Neither is a prerequisite.

Every task is test-first: write the failing test, run it and see it fail for the intended reason (a
compile error is not a red step), make it pass, then refactor. Tables follow the project's
`table-test` skill. Each task names how it is verified. A signature change owns every caller of the
changed API across the workspace (`_test.go` files, `httpsec`, the `test` module), so the workspace
compiles and passes at the end of every task group. Names in parentheses are the spec requirements
and design decisions the task covers.

After group 1, groups 2, 3 and 4 touch disjoint files and may run in parallel. Group 5 needs 3 and 4.

## 1. Factory port and default-limiter logging (decision 8; rate-limiting "A limiter factory builds every built-in flow's limiter")

- [x] 1.1 Red step for F7: `TestVerifyThrottle_DefaultLimiterWarnsThroughConfiguredLogger` in `mfa`, failing on the unchanged code because the per-replica warning goes to `slog.Default()`. Record the failing output. Verify with `go test -run TestVerifyThrottle_DefaultLimiterWarnsThroughConfiguredLogger -count=1 ./mfa/`
- [x] 1.2 `ratelimit.LimiterFactory`, `ratelimit.MemoryLimiterFactory(opts ...MemoryOption)` (a new limiter with separate buckets on each call; non-positive limit or window refused with `ErrConfig`), and the optional `ratelimit.Verifier` port, each with godoc naming the default. Verify with `go test -race ./ratelimit/...` and `go doc ./ratelimit LimiterFactory`
- [x] 1.3 Default limiters in `mfa` (verify throttle), `recovery` (`Recoverer`, `Codes`) and `passkey` are built through `MemoryLimiterFactory` with the component's logger and, where the component has one, its clock. This turns 1.1 green, and adds the same test for `recovery.Codes` and `recovery.Recoverer`. Update the `recovery.Codes` godoc that says its default limiter keeps its own clock. Verify with `go test -race ./mfa/... ./recovery/... ./passkey/...`

## 2. Factory seam through every flow, and the chain fixes (decisions 8–10; rate-limiting "A limiter factory builds every built-in flow's limiter"; http-security-chain "Chain-level rate-limit settings reach every guard the chain builds", MODIFIED "Wiring mistakes fail at construction", MODIFIED "Chain refusal logs are sampled and summarised")

- [x] 2.1 Red steps for F1 and F2 in `httpsec`, failing on the unchanged code and recorded:
  - `TestChain_IPv6SourcePrefixReachesSourceGuards`, scenario "Chain prefix groups a wider allocation";
  - `TestChain_RateLimiterFactoryReachesFlows`, scenario "Chain factory reaches a flow", red until `WithRateLimiterFactory` exists. The red step is the old option's test showing that the chain limiter is never consulted;
  - `TestChain_ThrottleRecordSampledPerCanonicalSource`, scenario "Rotating within one IPv6 source", expecting 1 record and seeing 50.

  Verify with `go test -run 'TestChain_' -count=1 ./httpsec/`
- [x] 2.2 Component factory options in `mfa`, `recovery` and `passkey`, each named after what it governs and documenting the default, with the precedence of decision 8. Each site uses its fixed namespace: `mfa-verify`, `recovery-user`, `recovery-codes`, `passkey-email-confirm`. A nil factory, typed nil included, is `ErrConfig`, and a factory error fails the constructor wrapped with the namespace. Covers scenario "Flow option wins over the factory" at the component level. Verify with `go test -race ./mfa/... ./recovery/... ./passkey/...`
- [x] 2.3 `httpsec.WithRateLimiterFactory` replaces `httpsec.WithRateLimiter`, which is removed together with `Chain.limiter` and its dead per-replica WARN. The chain builds every guard and every limiter it constructs from the factory, including enrolment begin and confirm under `mfa-enrol-begin` and `mfa-enrol-confirm`, and the factory reaches the MFA, recovery and passkey components it constructs. A nil factory is a construction error naming it. Covers scenarios "Default unchanged", "Consumer factory reaches every flow", "Flow option wins over the factory" and "Absent factory". Update every caller and test of the removed option across the workspace. Verify with `go test -race ./httpsec/... ./ginsec/... ./fibersec/...` (each module) and `go build ./...` in `test`
- [x] 2.4 `httpsec.WithIPv6SourcePrefix` builds the keyer every chain-built source guard uses; `Chain.ipv6Prefix` is then read in production. Covers scenarios "Chain prefix groups a wider allocation" and "Default prefix". Verify by 2.1's prefix test passing, and `go test -race ./httpsec/...`
- [x] 2.5 Remove the `httpsec` throttle record keyed on the raw address. The guard's record, sampled per flow and canonical source, is the only one. Covers scenarios "Rotating within one IPv6 source" and "Flood from one source". Verify by 2.1's sampling test passing, and `go test -race ./httpsec/... ./ratelimit/...`
- [x] 2.6 Godoc: `WithRateLimiterFactory`, `WithIPv6SourcePrefix` and each component factory option state their defaults, the precedence and the namespaces; the `httpsec` package documentation lists the limiter sites. Verify with `go doc ./httpsec WithRateLimiterFactory` and `go vet ./...`

## 3. Conformance suite (decision 12; rate-limiting "Every limiter passes the conformance suite")

- [x] 3.1 `test/ratelimittest` with `Harness` (`New`, `Advance`, optional `SecondInstance`) and `Run`, holding every single-instance scenario of decision 12. Written first and run against the in-memory limiter, including "Exceeded with an ended context returns true and an error" and "RecordFailure with an ended context still records". Verify with `go test -race -run TestRateLimitConformance_Memory ./...` in `test`
- [x] 3.2 Broken variants kept in the suite's tests: a fixed-window counter, a TTL reset on `Exceeded`, and a fail-open error path. Each scenario is seen to fail against at least one variant, run in child processes as in `store-conformance`. Covers scenario "Suite rejects a fixed window". Verify with `go test -race -run 'TestRateLimitConformance_Broken' ./...` in `test`
- [x] 3.3 Cross-instance scenarios: "Two replicas, one limit", "Shorter-window instance" and "Separate namespaces". They are skipped when `SecondInstance` is nil, and seen to fail against a broken shared double that keeps per-instance state. Verify with `go test -race ./ratelimittest/...` in `test`

## 4. Unavailable modes and the breaker (decision 5; rate-limiting "Shared limiters fail closed and fast when the backend is unavailable", "A failed record never leaves a source unthrottled", "Degrading during an outage is an explicit consumer choice", MODIFIED "Limiter errors fail closed")

- [x] 4.1 The public `ratelimit.UnavailableMode` (refuse by default, fall back, allow) and `ratelimit.ErrBackendUnavailable`, and the decorator in `internal/unavailable` over a backend `Limiter`, configured with the mode, the operation timeout (250ms default; it also bounds records on an uncancellable context) and the probe interval (1s default, every mode). Backends expose these as `WithOnUnavailable`, `WithOperationTimeout` and `WithUnavailableProbeInterval` (group 5). An unknown mode and non-positive durations are `ErrConfig`. A check on an ended caller context returns `true` and the error in every mode. Driven by a mock backend from `use-mockgen` and the `pkg/clock` fake. Verify with `go test -race ./ratelimit/... ./internal/unavailable/...`
- [x] 4.2 The breaker: an unavailable error opens it; while open, every mode answers without calling the backend; after the interval exactly one call probes; success closes it and failure reopens it. Concurrent callers during half-open send one probe, shown with `testing/synctest`. Covers scenarios "Backend down", "Refusal does not wait during an outage" and "Recovery after the outage". Verify with `go test -race -run 'TestUnavailable' ./ratelimit/... ./internal/unavailable/...`
- [x] 4.3 Record errors: in refuse mode a failed record holds the key as refused locally for one window, bounded and pruned like the in-memory limiter; in fall-back mode the failure is counted locally and either count exceeds; in allow mode it is dropped. Covers scenario "Writes fail while reads succeed" against a backend double whose writes fail and reads succeed. Verify with `go test -race ./ratelimit/... ./internal/unavailable/...`
- [x] 4.4 Fall-back and allow modes, with their transition logs (ERROR into degraded, WARN out of it; allow sampled per namespace) captured through a recording `slog` handler. Covers scenarios "Fall back to a local count", "Allow during an outage" and "Consumer chose to allow". Verify with `go test -race ./ratelimit/... ./internal/unavailable/...`, then `goleak` showing no goroutine left behind

## 5. Redis and Valkey module (decisions 1–4, 6, 7, 11; rate-limiting "A shared limiter counts across instances", "Shared limiter namespaces keep flows apart", "Shared limiters take time from the backend by default", "Expiry and eviction never disarm a shared limit", "Shared limiters are verified before traffic, not at construction")

- [x] 5.1 Scaffold `github.com/kartaladev/scrty/redis` (package `scrtyredis`, go-redis v9.7.3 or later), add it to `go.work`, the dependency guard (`layout_guard_test.go`) and the CI matrix. Add `RunTestRedis(t, opts ...TestOption) RedisConn` to `test/testutils.go`, defaulting to the newest Redis, with options for the server image (Redis 7.x, 8.x, Valkey 8.x), for an own container, and for server arguments on an own container (`WithTestRedisServerArgs`). `RedisConn` holds a client that resolves the server's address on every dial, and `Stop`/`Start` for an own container. Verify with `go build ./...` in each module, `go test -run 'TestModuleLayout|TestCoreDependencies|TestConsumerModuleGraph|TestRedisClientStaysInItsModules' .` at the root, and a `RunTestRedis` smoke test in `test`
- [x] 5.2 `NewLimiter(client, namespace, limit, window, opts...)`: the `RecordFailure` and `Exceeded` scripts of decision 3, run through `Script.Run` and `Script.RunRO` on one declared key, stamps in microseconds with unique members, server `TIME`, wrapped by the decorator from group 4 and configured by `WithOnUnavailable`, `WithOperationTimeout`, `WithUnavailableProbeInterval` and `WithUnavailableLogInterval`. It does no I/O at construction. It refuses an empty namespace, a nil or typed-nil client, a client that routes reads to replicas where the client exposes that setting, a client whose options leave `ContextTimeoutEnabled` off, a non-positive limit or window, and an empty prefix. Keys over 512 bytes are hashed. Covers scenarios "Empty namespace" and "Typed nil client". Verify with unit tests for construction and key mapping, and `go test -race ./...` in `redis`
- [x] 5.3 Conformance runs in `test`: the suite from group 3 against the Redis limiter in app-clock mode (`WithLimiterClock`) with `SecondInstance` over the same server, across the server matrix. Covers scenarios "Two replicas, one limit", "Window semantics preserved", "Shorter-window instance" and "Consumer clock". Verify with `go test -race -run TestRateLimitConformance_Redis ./...` in `test`
- [x] 5.4 Server-clock and TTL tests against a real server:
  - "Skewed replica", with a short real window;
  - a key with no TTL gains one on the next record, first seen to fail against a `PEXPIRE … GT`-only script;
  - `Exceeded` leaves the TTL unchanged;
  - a shorter-window record made late in a longer window keeps the key for the longer window, first seen to fail against a script that sets the TTL from its own window only.

  Verify with `go test -race -run 'TestRedisLimiter_(ServerClock|TTL)' ./...` in `test`
- [x] 5.5 `NewLimiterFactory(client, opts...)`: the same namespace with the same policy returns a limiter over the same buckets; a conflicting policy is `ErrConfig`; a client that routes reads to replicas is refused as in 5.2. Covers scenario "Conflicting policy for one namespace". Verify with `go test -race ./...` in `redis` and `test`
- [x] 5.6 `Verify(ctx)` on the factory and the limiter:
  - the server version floor (Redis 7.0, Valkey 7.2);
  - an evicting `maxmemory-policy` is `ErrConfig`;
  - an unreadable policy writes one WARN;
  - `WithEvictionPolicyCheck(false)`;
  - both scripts load and run once on a probe key, so a missing ACL permission is caught before traffic.

  Covers scenarios "Evicting backend", "Consumer disables the eviction check" and "Unsupported server". Verify with `go test -race -run TestRedisVerify ./...` in `test`, using a server configured per case
- [x] 5.7 Fault tests on the helper's own container:
  - the red step for decision 4's out-of-memory claim, a tiny `maxmemory` with `noeviction` and a source failing past its limit, recorded as failing before 4.3 is wired and passing after; if it never fails, the claim is removed from design.md;
  - stopping the container mid-test for each mode;
  - the breaker refusing without waiting for the timeout.

  Covers scenarios "Writes fail while reads succeed", "Backend down", "Refusal does not wait during an outage", "Recovery after the outage", "Fall back to a local count" and "Allow during an outage". Verify with `go test -race -run TestRedisLimiter_Fault ./...` in `test`
- [x] 5.8 Godoc and a runnable example (`Example_sharedLimiter`): the primary-only requirement, `noeviction`, the ACL commands, microsecond precision, one configuration per namespace, the fall-back recommendation for second-factor flows, and calling `Verify` before traffic. Verify with `go test -run Example ./...` in `redis` and `go doc ./ NewLimiterFactory` in `redis`

## 6. Integration

- [x] 6.1 Whole-branch review against every requirement in this change's two spec deltas, by a fresh reviewer who did not write the code. Each finding is reproduced by a failing test or labelled `UNREPRODUCED`. Verify by the review report, with every finding resolved or recorded
- [x] 6.2 Final gate across every module in `go.work`: `go test -race ./...`, `go vet ./...`, `gofmt -l .` empty, `golangci-lint run`, and `openspec validate shared-rate-limiting --strict`. Verify by the recorded output of each command
