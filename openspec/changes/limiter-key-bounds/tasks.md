# Tasks

Every task is test-first: write the failing test, run it and see it fail for the intended reason (a
compile error is not a red step), make it pass, then refactor. Tables follow the project's
`table-test` skill, and test doubles come from `use-mockgen`. Each task says how it is verified. A
signature change owns every caller of the changed API across the workspace (`_test.go` files,
`httpsec`, the `test` module), so the workspace compiles and passes at the end of every group. Names
in parentheses are the spec requirements and design decisions the task covers.

Groups 1–4 change the in-memory limiter (`ratelimit/memory.go` and its tests). Group 5 changes the
source keyer and guard (`ratelimit/keyer.go`, `ratelimit/guard.go`). Group 6 changes `httpsec`.
Group 5 needs 4.2 (the full-limiter sentinel) only for task 5.5. Group 6 needs group 5.

## 1. Baseline benchmark (design "Context"; rate-limiting "Inline pruning never stalls the whole limiter")

- [x] 1.1 Add `ratelimit/memory_bench_test.go`, with the measurement tests opt-in through `SCRTY_MEASURE=1` and skipped under `-short`. Run it on the unchanged limiter. It measures, over distinct /64 keys with limit 10, window 15 min and one failure per key:
  - the heap per key at 100,000 and 1,000,000 keys;
  - the worst check that triggers inline pruning with 1,000,000 expired keys, and the worst latency of eight concurrent readers of other keys during it;
  - a single-lock reference: one scan of a plain map holding the same keys under one mutex, which is the denominator of the spec's one-thirtieth ratio;
  - the heap after every key is swept and the GC runs;
  - mixed 90/10 check/record throughput with `-cpu 1,8`.

  Verify with `SCRTY_MEASURE=1 go test -run 'TestMemoryLimiterMeasure' -count=1 -v ./ratelimit/` and `go test -run '^$' -bench 'BenchmarkMemoryLimiter' -benchmem -count 6 -cpu 1,8 ./ratelimit/`. Report the figures, so the main session can confirm or correct design.md's baseline table.

## 2. A clock stepped backwards (decision 4; rate-limiting MODIFIED "The in-memory limiter bounds its own memory without disarming limits", scenario "Clock stepped backwards")

- [x] 2.1 Red step for the `UNREPRODUCED` claim: `TestMemoryLimiter_SweepResumesAfterClockSteppedBack`, on the unchanged limiter, driven by the `pkg/clock` fake. It follows the spec scenario. Record the failing output, or report that it passes. Verify with `go test -run TestMemoryLimiter_SweepResumesAfterClockSteppedBack -count=1 ./ratelimit/`
- [x] 2.2 Only if 2.1 failed: re-arm the sweep pacing when `sweptAt` is later than now, so sweeping resumes one window after the step back. If 2.1 passed, report it, and the main session removes decision 4 and this task. Verify with 2.1 passing and `go test -race ./ratelimit/...`

## 3. Sharding and compaction (decision 3; rate-limiting "Inline pruning never stalls the whole limiter", MODIFIED "The in-memory limiter bounds its own memory without disarming limits")

- [x] 3.1 Red step for "Memory is returned after a flood": `TestMemoryLimiter_ReturnsMemoryAfterFlood`, skipped under `-short`. It fails on the unchanged limiter because the swept map keeps its buckets. Record the failing output. Verify with `go test -run TestMemoryLimiter_ReturnsMemoryAfterFlood -count=1 ./ratelimit/`
- [x] 3.2 Split `MemoryLimiter` into 64 shards, each with its own mutex, map, `sweptAt` and high-water mark, selected by `hash/maphash` with a seed drawn per limiter.
  - `Exceeded` and `RecordFailure` lock and sweep only their key's shard.
  - `Prune` sweeps the shards one at a time.
  - `StampsFor` reads one shard.
  - Behaviour is otherwise unchanged. Every existing `ratelimit` test and the in-memory conformance run stay green unedited, except the inline-pruning test, which now checks every key as its scenario says.
  - Covers scenarios "Inline pruning under traffic", "Oldest expired, newest live" and "Clock stepped backwards", and the concurrent-use requirement under `-race`.

  Verify with `go test -race -count=1 ./ratelimit/...` and `go test -race -run TestRateLimitConformance_Memory ./...` in `test`
- [x] 3.3 Compaction: after a sweep, a shard whose map has fallen below a quarter of its high-water mark, with a mark of at least 1,024 keys, copies its survivors into a fresh map and resets the mark. This turns 3.1 green. Add a test that a compacted shard still holds and counts every live key. Verify with `go test -race -count=1 ./ratelimit/...` and 3.1 passing
- [x] 3.4 Re-run 1.1's measurements against the sharded limiter, covering scenario "One million expired keys". The worst pruning-triggering check must be at most one-thirtieth of the single-lock reference. Godoc on `MemoryLimiter` states the shard count, why it has no option, and the stall bound. Verify with 1.1's commands, the ratio reported with both figures, and `go doc ./ratelimit MemoryLimiter`

## 4. Key cap (decisions 1, 2; rate-limiting "The in-memory limiter caps the keys it holds", "A full in-memory limiter refuses new keys and keeps counting held ones", "A full in-memory limiter says so")

- [ ] 4.1 `ratelimit.DefaultMemoryLimiterMaxKeys` (250,000) and `ratelimit.WithMemoryLimiterMaxKeys(n)`. `n <= 0` is `ErrConfig`. Godoc names the default, the cost per key, `math.MaxInt` for a consumer who accepts no bound, and that `MemoryLimiterFactory` applies it to every limiter it builds. Covers scenarios "Default cap", "Consumer cap" (held keys only, without the refusal yet) and "Zero cap". Verify with `go test -race -run 'TestNewMemoryLimiter|TestMemoryLimiter_MaxKeys' -count=1 ./ratelimit/`
- [ ] 4.2 `ratelimit.ErrLimiterFull`, and refusal at the cap, through an `atomic.Int64` count reserved with `Add(1)` before a new key is inserted and given back on overflow or when pruning removes a key.
  - `Exceeded` of an unheld key returns `true` and an error wrapping `ErrLimiterFull`.
  - `RecordFailure` of an unheld key stores nothing and returns that error.
  - Held keys behave as below the cap.
  - Covers scenarios "Consumer cap", "New source at the cap", "Held source at the cap", "Room after pruning" and "Live keys are never evicted".
  - Add a `-race` test: 64 goroutines insert distinct keys into a limiter with a cap of 100, and the limiter never holds more than 100.

  Verify with `go test -race -run 'TestMemoryLimiter_(Full|Cap)' -count=1 ./ratelimit/`
- [ ] 4.3 The full-limiter warning through the limiter's logger: written when the limiter first finds itself full, and at most once per window after that, naming the maximum. Checked with a recording `slog` handler and the fake clock. Covers scenario "Flood at the cap". Verify with `go test -race -run TestMemoryLimiter_FullWarning -count=1 ./ratelimit/`

## 5. Aggregate prefix in the guard (decision 5; rate-limiting "IPv6 sources can also be counted by an aggregate prefix", "Aggregate refusals are logged per aggregate", "Guards report a full limiter as its own refusal")

- [x] 5.1 `SourceKeyer.IPv6Prefix()`, and keying of an IPv6 source's enclosing aggregate prefix (zone dropped, mapped IPv4 unmapped first; IPv4 has no aggregate). Verify with `go test -race -run 'TestSourceKeyer' -count=1 ./ratelimit/`
- [x] 5.2 `ratelimit.WithSourceGuardIPv6Aggregate(bits int, limiter Limiter)`. Construction refuses with `ErrConfig`:
  - an absent limiter, typed nil included;
  - `bits` outside 1..127;
  - `bits` not strictly less than the keyer's prefix, including a consumer-supplied keyer.

  Godoc states the default is off at this level and why. Covers scenario "Aggregate no wider than the source". Verify with `go test -race -run 'TestNewSourceGuard' -count=1 ./ratelimit/`
- [x] 5.3 Check and record with an aggregate. `Source` carries both keys. Check consults the source and then the aggregate; either one exceeded, or either limiter's error, refuses with `ErrThrottled`. Record counts against both, and logs each recording error independently. Uses mockgen `Limiter` doubles and the in-memory limiter. Covers scenarios "Rotating /64s inside one aggregate", "Another aggregate is unaffected" and "IPv4 unaffected". Verify with `go test -race -run 'TestSourceGuard_Aggregate' -count=1 ./ratelimit/`
- [x] 5.4 Aggregate refusal records: an `aggregate` field, sampled under `throttled:<flow>:<aggregate prefix>`. Covers scenario "Rotation inside a throttled aggregate". Verify with `go test -race -run 'TestSourceGuard_AggregateLog' -count=1 ./ratelimit/`
- [ ] 5.5 Full-limiter refusals in the guard: a check failing with `ErrLimiterFull` refuses with `ErrThrottled` and writes its own "limiter full" record, sampled under `full:<flow>:`, apart from the limiter-unavailable record. Update `WithSourceGuardLogReporter`'s godoc with the new key family. Covers scenario "Full limiter behind a guard". Verify with `go test -race -run 'TestSourceGuard_Full' -count=1 ./ratelimit/` and `go doc ./ratelimit WithSourceGuardLogReporter`

## 6. Chain default aggregate (decision 6; http-security-chain "Chain source guards count an IPv6 aggregate by default", "Contradictory aggregate settings fail at construction", MODIFIED "Chain-level rate-limit settings reach every guard the chain builds"; rate-limiting MODIFIED "A limiter factory builds every built-in flow's limiter")

- [x] 6.1 `httpsec.WithIPv6Aggregate(bits, multiplier int)` and `httpsec.WithoutIPv6Aggregate()`, validated at `build`, since options may come in any order. Refused with a configuration error naming the option:
  - an explicit aggregate not wider than the source prefix;
  - `bits` outside 1..127;
  - a multiplier below 1;
  - both options given.

  The default aggregate is skipped when the source prefix is /56 or wider. Covers scenarios "Aggregate no wider than the source", "Zero multiplier" and "Wide source prefix skips the default aggregate". Verify with `go test -race -run 'TestChain_IPv6Aggregate' -count=1 ./httpsec/`
- [x] 6.2 `resolveSourceGuard` asks the chain's factory for `NewLimiter(flow+"-ipv6-aggregate", limit*multiplier, window)` and passes it with `WithSourceGuardIPv6Aggregate`, including for a flow given its own limiter. Update `TestChain_RateLimiterFactoryReachesFlows` for the extra calls. Covers scenarios "Default aggregate", "Consumer aggregate", "Aggregate turned off", "Default prefix", "Consumer factory reaches every flow" and "Flow option wins over the factory". Verify with `go test -race -count=1 ./httpsec/...`, and `go test -race ./...` in `ginsec` and `fibersec`
- [x] 6.3 Godoc: both options state the default (/56 at 4×), the aggregate namespace, the per-replica note for an in-memory aggregate behind a shared flow limiter, and the /48 remainder. `WithIPv6SourcePrefix` mentions the interaction. The `httpsec` package documentation lists the aggregate. Verify with `go doc ./httpsec WithIPv6Aggregate` and `go vet ./...`

## 7. Integration

- [ ] 7.1 Whole-workspace gate. Verify with:
  - `go build ./...`, `go vet ./...` and `go test -race -count=1 ./...` in every module of `go.work`, including `test`, with Docker for the Redis conformance;
  - `gofmt -l .` empty;
  - `golangci-lint run ./...` clean.
- [ ] 7.2 Whole-branch review against every requirement in this change's spec deltas, with design.md's baseline table updated to the in-tree figures from 1.1 and 3.4. Verify by the review reporting no open finding.
