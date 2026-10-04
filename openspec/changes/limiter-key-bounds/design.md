# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- `ratelimit.MemoryLimiter` keeps one `map[string][]time.Time` behind one `sync.Mutex`. Each key holds at most `limit` stamps. An inline sweep scans every key under that lock, at most once per window, from inside `Exceeded` and `RecordFailure`.
- Every source guard in `httpsec` is built by `config.resolveSourceGuard` (`httpsec/throttle.go`). Six guards are built there: API key, magic link, OIDC handoff, passwordless begin, recovery, and recovery start. Each is built from the chain's one `SourceKeyer` and from a limiter. That limiter is the flow's own if the consumer gave one, otherwise one the chain's `LimiterFactory` built with the flow's limit and window.
- The memory limiter is also used without a guard, by limiters keyed per user (second factor, recovery, passkey). The key cap applies to those too.
- The established design has none of this: no key cap, no aggregate prefix, and a single lock with a full sweep once per window. Every decision below adds behaviour; none departs from the established design.

**Baseline, re-measured as this change's first benchmark** (exploratory harness on 2026-10-04; Go 1.27.1, Apple M4 Pro, 14 cores; limit 10, window 15 min, one failure per distinct /64 key):

| | Value |
|---|---|
| Heap at 1,000,000 keys | 149.4 MiB, 156.6 B/key |
| Heap at 100,000 keys | 11.4 MiB, 119 B/key |
| Sweep of 1,000,000 expired keys, worst call | 100.6 ms |
| Same, 1% expired | 35.3 ms |
| Mixed check/record throughput, 8 cores | 284 ns/op, against 114 ns/op on 1 core |
| Heap after sweeping every key, then GC | 96 MiB. The map keeps its buckets. |

Task 1 turns this harness into the benchmark that stays in the tree.

## Goals / Non-Goals

**Goals:**
- Bound what an attacker who rotates sources can make one in-memory limiter hold, and fail closed at that bound.
- Stop rotation of /64s inside one allocation from multiplying a flow's allowance.
- Make one check wait for at most a sixty-fourth of the sweep work, and return a flood's memory once its keys expire.

**Non-Goals:**
- **An IPv4 aggregate** (per /24, say). Carrier-grade NAT already pools many users behind one IPv4 address, so a /24 aggregate would pool whole ISPs' worth of users. Not done here.
- **Bounding the shared Redis limiter's key count.** Its memory is bounded by the server's `maxmemory` and `noeviction`, which `Verify` already enforces, and a full server already fails closed.
- **Least-recently-used eviction**, of the kind nginx and HAProxy use by default. Evicting a key whose failures are still inside the window resets its count, which the rate-limiting spec forbids.
- **A configurable shard count.** See decision 3.

## Decisions

### 1. The key cap is on by default at 250,000 keys per limiter, and refuses new keys when full

The memory limiter counts the keys it holds. When it holds the maximum:
- `Exceeded` on a key it does not hold returns `true` with an error wrapping a new sentinel, `ratelimit.ErrLimiterFull`.
- `RecordFailure` on a key it does not hold stores nothing and returns the same error.
- Held keys are checked and recorded as normal, so a source that is already failing goes on being counted.
- A key leaves the count only when pruning removes it. Nothing is evicted to make room.

The count is one `atomic.Int64` across all shards. A new key reserves its place first with `Add(1)` and, if that goes past the maximum, gives it back with `Add(-1)`. The cap is therefore exact, with no check-then-insert race between shards, and the measured overhead was within noise (decision 3).

- **Default:** 250,000 keys, exported as `ratelimit.DefaultMemoryLimiterMaxKeys`.
  - A full limiter holds about 37 MiB at the measured cost per key (at most 157 B).
  - With roughly ten memory limiters in a fully enabled chain, the worst case if all of them are flooded is about 0.4 GiB, against an unbounded amount today.
  - 250,000 distinct sources failing inside one window is far beyond one replica's normal traffic. That includes passwordless begin, which records every begin, not only failures (250,000 in 15 minutes is about 280 new sources a second). A deployment that large belongs on the shared limiter.
- **Override:** `ratelimit.WithMemoryLimiterMaxKeys(n)`, a `MemoryOption`. A `MemoryLimiterFactory` passes it to every limiter it builds, so the chain's factory sets the cap for every flow.
  - `n <= 0` is a configuration error wrapping `ErrConfig`.
  - There is no "unbounded" mode, because unbounded memory is the defect this change fixes. A consumer who accepts that cost passes `math.MaxInt`, which godoc states.
- **Alternatives:**
  - *Evict the least-recently-used key* (the nginx and HAProxy default). It resets a live count, so it was rejected (see Non-Goals).
  - *Off by default.* It keeps memory exhaustion as the default exposure, and the library-design rule puts the safe behaviour in the default.
  - *100,000.* A busy site's passwordless begin could reach it with normal traffic.
  - *1,000,000.* About 150 MiB per limiter, which is too much across ten flows.

**Visibility:**
- The limiter writes a WARN record through its own logger when it first finds itself full, and at most one per window after that. The record names the maximum and says new sources are being refused. This is what an operator sees for the per-user limiters, which have no guard.
- A guard that gets `ErrLimiterFull` refuses with `ErrThrottled`, as for any limiter error. Its record is a separate message, "limiter full", sampled under its own key family, `full:<flow>:`. A flood at the cap therefore cannot hide an outage record, and an outage cannot hide the flood.
- `WithSourceGuardLogReporter`'s godoc gains the new key family.

### 2. Expired keys hold their places until their shard's next sweep

Each shard keeps today's once-per-window pacing. A key whose newest stamp expired at time t therefore holds its place until that shard next sweeps, which is no later than t plus one window. A flood at the cap keeps refusing new sources for at most one window after its last failure has left the window.

- **Alternative: sweep a full shard on demand when the cap is hit.** An attacker at the cap would then trigger a scan with every request, buying CPU instead of memory. Rejected.
- **No override.** The pacing is what keeps sweep cost proportional to time rather than to the request rate an attacker chooses, as it already does today.

### 3. Shard the memory limiter 64 ways, and compact a shard after a sweep that empties it

The limiter becomes 64 shards. Each shard has its own mutex, map, `sweptAt` and high-water mark.

- A key's shard is chosen by `hash/maphash` with a seed drawn per limiter, so an attacker cannot aim keys at one shard.
- `Exceeded` and `RecordFailure` lock only their key's shard, and sweep only that shard when its window is due.
- `Prune` sweeps the shards one after another, locking each only while sweeping it.
- `StampsFor` reads one shard.

Measured in the exploratory harness, against the single-lock baseline:

| 1,000,000 expired keys | Baseline | 16 shards | 64 shards | 256 shards | Two generations |
|---|---|---|---|---|---|
| Worst sweep call | 100.6 ms | 7.3 ms | 1.96 ms | 0.52 ms | 8 µs (rotation) |
| p99 of 8 concurrent readers during the sweep | 22.5 µs | 480 ns | 224 ns | 224 ns | 28.7 µs |
| Mixed throughput, 8 cores (ns/op) | 284 | — | 32.3 | — | 280 |

- **Why 64:** it cuts the worst stall 51-fold and gives a 9-fold gain on 8 cores. 256 shards adds little and costs more fixed memory per limiter. The number is a constant, not an option. It changes no observable behaviour except latency, and an option for it would be a tuning knob with no policy behind it. The spec pins a floor (at least 64 parts) and a ratio to the single-lock sweep (at most one-thirtieth), not the number itself.
- **Compaction:** sweeping leaves a Go map's buckets allocated. Emptying a 1,000,000-key map left 96 MiB held. After a sweep, a shard whose map has fallen below a quarter of its high-water mark, with a high-water mark of at least 1,024 keys, copies its survivors into a fresh map and resets the mark. The copy costs time proportional to the survivors: under a quarter of the most keys the shard has held, and never more than the sweep just scanned, so a compacting call takes at most about twice one shard's sweep. Below 1,024 keys the retained memory is not worth a copy.
- **Alternatives:**
  - *Two generations* (`cur` and `prev` maps, with `prev` dropped once a window). The drop is O(1) and frees memory. But it keeps the single lock, so 8-core throughput stays at today's 280 ns/op, and expired keys hold cap places for up to two windows instead of one.
  - *Shards with two generations each.* It combines both and keeps the two-window hold, for more complexity than the measured stall justifies.

### 4. A clock stepped backwards must not stop sweeping (reproduced)

**`REPRODUCED`** by `TestMemoryLimiter_SweepResumesAfterClockSteppedBack` (`go test -run TestMemoryLimiter_SweepResumesAfterClockSteppedBack -count=1 ./ratelimit/`), which on the unchanged limiter failed with `Should be zero, but was 1 … still held after its window passed`, and passes with the fix. The defect: pacing compares `now.Sub(sweptAt) < window`. If the clock steps back after a sweep, that difference is negative until the clock catches up again. Sweeping stops in the meantime. With a cap, a stalled sweep would keep refusing new sources for as long as the clock was set back.

- **Planned test:** the spec scenario "Clock stepped backwards". It is task 2.1's red step.
- **If it fails:** a shard whose `sweptAt` is later than `now` sets `sweptAt = now`, so sweeping resumes one window later. Pruning judges keys by their newest stamp, so sweeping sooner never removes a live key.
- **If it passes:** the hypothesis was wrong. Task 2.2 is dropped and this decision is removed.
- **No override:** this is a fix, not a policy.

### 5. The aggregate prefix is a guard option with a limiter of its own

`ratelimit.WithSourceGuardIPv6Aggregate(bits int, limiter Limiter)` is a `GuardOption`.

**Keys:**
- With it set, the keyer also produces the IPv6 source's enclosing `/bits` prefix.
- The aggregate is counted in its own limiter under `<flow>:<prefix>`, for example `api-key:2001:db8:1::/56`.
- `Source` carries both keys, unexported, so the keys a check read and the keys a record writes cannot drift apart.
- IPv4 sources produce no aggregate key.

**Check:** the source key is consulted first, then the aggregate.
- Either one exceeded refuses with `ErrThrottled`.
- Either limiter's error refuses as today (fail closed).
- An aggregate refusal is logged with an `aggregate` field and sampled under `throttled:<flow>:<aggregate prefix>`. Rotation inside one aggregate therefore produces one record per window, not one per /64.

**Record:** counts against both keys. Each recording error is logged independently, and one failing does not skip the other.

**Why a limiter of its own:**
- The aggregate needs its own limit, which a `Limiter` cannot vary per key.
- A shared limiter (Redis) works unchanged, under its own namespace.
- The aggregate takes a place in the key cap like any other key, so it is bounded by decision 1.

**Validation at construction:**
- An absent limiter (including typed nil) is refused.
- `bits` outside 1..127 is refused.
- `bits` not strictly less than the keyer's prefix is refused: an aggregate no wider than the source counts nothing new.
- `SourceKeyer` gains an exported `IPv6Prefix() int` so the guard can check this against a keyer the consumer supplied.

**Default at the `ratelimit` level:** off. `NewSourceGuard` cannot invent a limit for a limiter it was not given. The default the spec requires is applied where limits are known, in decision 6.

### 6. The chain builds every source guard with a /56 aggregate at 4× the flow's limit

- **Building it:** `resolveSourceGuard` asks the chain's factory for a second limiter, `NewLimiter(flow+"-ipv6-aggregate", limit*multiplier, window)`, and passes it to the guard with `WithSourceGuardIPv6Aggregate`.
  - The aggregate is built this way even when the flow was given its own limiter. The flow's `limit` and `window` are always known at that call.
  - If the flow's own limiter is shared and the factory is the in-memory default, the aggregate counts per replica, which godoc states.
- **Default:** a /56 prefix with a multiplier of 4.
  - A /56 is the usual residential end site (RFC 6177, RIPE-738), so it rarely groups unrelated users.
  - Rotating /64s inside one site gives 4× a flow's allowance instead of 256×.
  - A holder of a /48 still gets 256 /56s × 4, so 1,024× the allowance instead of 65,536×. That remainder is stated in godoc and in Risks.
  - With the API-key default (20 per minute), one /56 gets 80 failures per minute.
- **Override:**
  - `httpsec.WithIPv6Aggregate(bits, multiplier int)` sets the prefix and the multiplier.
  - `httpsec.WithoutIPv6Aggregate()` turns the aggregate off.
  - Each option names what it governs, and neither touches the source prefix.
- **Interaction with `WithIPv6SourcePrefix`:** the options may be applied in any order, so the check runs at `build`.
  - The default aggregate is skipped when the source prefix is /56 or wider (≤ 56). The source key already covers the aggregate, so skipping it relaxes nothing.
  - An explicit aggregate not wider than the source prefix is a configuration error.
  - So are giving both `WithIPv6Aggregate` and `WithoutIPv6Aggregate`, a multiplier below 1, and `bits` outside 1..127.
- **Alternatives:**
  - */48 at 8×.* Stronger, but whether a /48 holds unrelated subscribers depends on each ISP's assignment policy: RIPE-738 leaves end-site size to the ISP. That makes it a lockout risk the library should not take by default. A consumer can opt in with `WithIPv6Aggregate(48, 8)`.
  - *Off by default.* It leaves the allowance multiplier in place, which is what the proposal set out to remove.

## Risks / Trade-offs

- **[An attacker who can fill the cap refuses new sources to that flow for up to one window after the flood stops]**
  - This is the stated cost of failing closed.
  - Mitigations: it is bounded per flow, held sources keep working, the limiter warns, and the guard logs "limiter full" as its own record.
  - A deployment that cannot accept it raises the cap or uses the shared limiter.
- **[A per-user memory limiter (recovery, second factor) can be filled by enumerating usernames]**
  - Recovery for unheld users is then refused for up to a window.
  - Same mitigations. Its godoc names the case.
- **[The /56 aggregate pools a household]**
  - Every device in one site shares 4× a flow's limit.
  - Failures are rare for legitimate users, so 4× leaves room. The multiplier is an option.
- **[A /48 holder still gets 1,024× the allowance]**
  - The key cap still bounds memory.
  - A consumer facing such attackers sets `WithIPv6Aggregate(48, n)`.
- **[Peak memory after a flood stays until each shard next sweeps]**
  - Bounded by the cap (about 37 MiB per limiter), and returned by compaction.
- **[The latency bound is measured on a developer machine]**
  - The spec states it as a ratio to the single-lock sweep on the same machine, so it does not depend on hardware.
  - The benchmark is not a CI gate: CI runs under the race detector and on shared runners, where timing measures the scheduler. The measurement tests are opt-in (`SCRTY_MEASURE=1`) and skipped by a plain `go test`. Under `-race` the ratio is logged, not asserted. Otherwise the measurement takes the best of five trials against the median of three reference scans, since preemption and GC only ever add time. Tasks 1.1 and 3.4 record its numbers in this design.

## Migration Plan

Before the first tag, so no compatibility policy applies yet. Each new default is recorded here, as `library-design.md` requires.

What a consumer sees on upgrade:
- the 250,000-key cap;
- the /56 aggregate on every chain source guard;
- one more factory call per source-guarded flow, under namespace `<flow>-ipv6-aggregate`.

A consumer with a Redis factory gets those namespaces created on first use. Each replica must configure them the same way, as the Redis limiter already requires.

To roll back the behaviour, a consumer uses `WithoutIPv6Aggregate()` and `WithMemoryLimiterMaxKeys(math.MaxInt)`.

## References

**Researched (accessed 2026-10-04):**

*Decision 1, full-table behaviour:*
- [nginx `ngx_http_limit_req_module`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html): when the zone is exhausted, the least recently used state is removed, and only if that fails is the request refused. A state takes 128 bytes on 64-bit platforms.
- [HAProxy configuration manual, `stick-table` `size` and `nopurge`](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt): purges the oldest entries when full by default. `nopurge` refuses new entries instead, for when "we prefer not to offer access to new clients than to reject the ones already connected".
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html): bound the server-side state each client can create.

*Decisions 5 and 6, aggregate prefix:*
- [RFC 6177](https://www.rfc-editor.org/rfc/rfc6177): end sites get at least a /64 and in most cases significantly more. One assignment size no longer fits every site.
- [RIPE-738, IPv6 Address Allocation and Assignment Policy](https://www.ripe.net/publications/docs/ripe-738/): end-site assignment size is the ISP's decision, in multiples of /64. Assignments larger than a /48 need justification.
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): attackers rotate addresses through proxy networks (carried from the proposal, accessed 2026-10-03).

*Decisions 1 to 3, measurements:*
- Exploratory benchmark run on 2026-10-04, figures above. Hardware-specific; task 1 re-measures them in the tree.

**Primary documentation:**
- [`hash/maphash`](https://pkg.go.dev/hash/maphash): the per-limiter seeded hash used for shard selection (decision 3).
- [`sync/atomic.Int64`](https://pkg.go.dev/sync/atomic#Int64): the exact cap reservation (decision 1).

Decisions 2 and 4 are reasoned from scrty's own settled specs and the established design.
