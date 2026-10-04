# Limiter Key Bounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code (`.claude/rules/subagent-delegation.md`). Every task below is carried out by a dispatched subagent, and the main session verifies and reviews it.

**Goal:** Bound the keys the in-memory limiter holds, stop IPv6 /64 rotation from multiplying a flow's allowance, and stop the inline sweep from stalling every check.

**Architecture:**
- `ratelimit.MemoryLimiter` becomes 64 independently locked shards. Each shard sweeps only itself, and compacts its map once a sweep leaves it far below its high-water mark.
- One atomic key count, reserved before a new key is inserted, caps the limiter exactly at 250,000 keys by default. A key that is not already held is refused with `ErrLimiterFull`.
- `SourceGuard` gains an optional IPv6 aggregate: a wider prefix counted in a limiter of its own.
- The `httpsec` chain builds that aggregate for every source guard, by default a /56 at four times the flow's limit.

**Tech Stack:** Go 1.27. Standard library `hash/maphash`, `sync`, `sync/atomic` and `net/netip`. testify, `go.uber.org/mock` (typed mocks), and the `jonboulle/clockwork` fake clock in tests.

**Spec:** `openspec/changes/limiter-key-bounds/` — `proposal.md`, `design.md` (decisions 1–6), `specs/rate-limiting/spec.md`, `specs/http-security-chain/spec.md` and `tasks.md`. Task numbers below (1.1, 3.2, …) are `tasks.md`'s.

## Global Constraints

- Test-first for every task: write the failing test, run it, and confirm it fails **for the intended reason**. A compile error is not a red step. Then implement, then refactor (`.claude/rules/golang-tdd.md`).
- Tables follow the `table-test` skill: an `assert` closure per case, not `want`/`wantErr` fields, and `t.Context()`, never `context.Background()`, in tests.
- Mocks come from `use-mockgen` (`//go:generate mockgen ... -typed`). `ratelimit/mocks_test.go` already holds `MockLimiter`.
- Library design: every default is named in godoc, together with the option that replaces it. Wiring mistakes fail at construction with an error wrapping `ratelimit.ErrConfig`, or with an `httpsec` configuration error naming the option.
- Defect claims: decision 4 (clock stepped back) is `UNREPRODUCED` until 2.1 fails. If 2.1 passes, 2.2 is not done.
- Exact values from the spec:
  - default key cap `250000`;
  - shard count `64`;
  - compaction threshold: below a quarter of the high-water mark, with a mark of at least `1024`;
  - default aggregate `/56`, multiplier `4`;
  - aggregate namespace `<flow>-ipv6-aggregate`;
  - sampler key families `full:<flow>:` and `throttled:<flow>:<aggregate prefix>`;
  - stall ratio: at most one-thirtieth of the single-lock reference.
- No code, comment or godoc may cite or copy the predecessor (`.claude/rules/legacy-reference.md`).
- No git command that discards work (`checkout --`, `restore`, `reset --hard`, `stash`, `clean`). Subagents do not commit. The main session commits after each verified, reviewed dispatch.
- Verification for every task includes `gofmt -l ./ratelimit ./httpsec` empty and `go vet ./...`.

## Review Focus

1. **Key count drift.** Inline sweep, `Prune` and compaction must each change the count exactly once per removed key, and never for a survivor. After a full cap, a prune of everything and a refill, the limiter must again admit exactly `max` keys. The test is in Task 4.2, step 1, case "refill after full prune".
2. **Mapped IPv4 and zones in the aggregate.** `::ffff:203.0.113.7` gets no aggregate key. `fe80::1%eth0` aggregates as `fe80::/56`. The test is in Task 5.1, step 1.
3. **A full aggregate limiter.** When the aggregate limiter, not the source limiter, returns `ErrLimiterFull`, the attempt is refused with a "limiter full" record, not a limiter-unavailable one. The test is in Task 5.5, step 1, case "aggregate limiter full".
4. **One recording failure must not skip the other.** If recording on the source limiter errors, the aggregate is still recorded, and the other way round. The test is in Task 5.3, step 1, cases "source record fails" and "aggregate record fails".
5. **A clock stepped back must be handled per shard.** After sharding, a step back must re-arm every shard that gets touched, not one global timestamp. 2.1's test is re-run unchanged in Task 3.2.

---

## Execution: lanes, dispatches and models

The main session sets each dispatch's model, as `subagent-delegation.md` requires. A dispatch that touches a concurrency or security-refusal path is on Opus's list.

| Dispatch | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| A1 | 1.1, 2.1, 2.2 | `ratelimit/memory_bench_test.go` (new), `ratelimit/memory.go`, `ratelimit/memory_test.go` | everything else | Sonnet | Measurement harness to a stated design, plus a one-line pacing fix the test dictates |
| A2 | 3.1–3.4 | `ratelimit/memory.go`, `ratelimit/memory_shard.go` (new), `ratelimit/memory_test.go`, `ratelimit/memory_bench_test.go` | `options.go`, `guard.go`, `keyer.go` | Opus | A refactor that must keep behaviour under concurrency |
| B1 | 5.1–5.4 | `ratelimit/keyer.go`, `ratelimit/keyer_test.go`, `ratelimit/export_test.go` (new), `ratelimit/guard.go`, `ratelimit/guard_test.go`, `ratelimit/guard_aggregate_test.go` (new), `ratelimit/options.go` | `memory*.go` | Opus | First-time refusal logic in a security guard |
| A3 | 4.1–4.3 | `ratelimit/memory*.go`, `ratelimit/memory_cap_test.go` (new), `ratelimit/options.go`, `ratelimit/factory.go` (godoc only) | `guard*.go`, `keyer*.go` | Opus | Exact cap under concurrent shards (reserve and rollback) |
| B2 | 5.5 | `ratelimit/guard.go`, `ratelimit/guard_test.go`, `ratelimit/options.go` (godoc) | `memory*.go` | Sonnet | Known pattern: a new sampled record family |
| C1 | 6.1–6.3 | `httpsec/options.go`, `httpsec/throttle.go`, `httpsec/doc.go`, `httpsec/chain_ratelimit_test.go`, `httpsec/chain_aggregate_test.go` (new) | `ratelimit/` | Sonnet | Option plumbing and validation over an API B1 fixed |
| D1 | 6.4–6.6 | `ratelimit/policy.go` (new), `ratelimit/memory.go`, `ratelimit/memory_cap_test.go`, `ratelimit/guard_test.go`, `redis/limiter.go`, `redis/limiter_test.go` (or a new `redis/policy_test.go`), `httpsec/throttle.go`, `httpsec/options.go`, `httpsec/oidc_options.go`, `httpsec/recoveryoptions.go`, `httpsec/passkeylogin.go` (godoc only in the last four), `httpsec/chain_aggregate_test.go`, `internal/unavailable/wrap.go` (comment only) | `openspec/` | Opus | An interface other packages compile against, across ratelimit, redis and httpsec, and a sizing rule whose mistake passes tests (decision 6) |

**Order:**
- A1 and B1 start together.
- A2 starts after A1 is verified and reviewed.
- A3 starts after **both** A2 and B1, because both write `options.go`.
- B2 starts after A3, because it needs `ErrLimiterFull`.
- C1 starts after B1. It may run beside A3 and B2, since it touches only `httpsec/`.
- D1 runs after the whole-branch review of the other lanes, which found that the default aggregate silently tightened a consumer's own limiter (design decision 6).
- 7.1 and 7.2 belong to the main session, after every lane.

A2, A3 and B1 get Opus reviewers. A1, B2 and C1 get Sonnet reviewers.

---

### Task 1.1: Baseline benchmark

**Files:**
- Create: `ratelimit/memory_bench_test.go` (package `ratelimit_test`)

**Interfaces:**
- Consumes: `ratelimit.NewMemoryLimiter(limit int, window time.Duration, opts ...MemoryOption)`, `ratelimit.WithMemoryLimiterClock`, `clockwork.NewFakeClockAt`.
- Produces: helpers `slash64Keys(n int) []string` and `newMeasuredLimiter(t testing.TB, clk clockwork.FakeClock) *ratelimit.MemoryLimiter`. Task 3.4 reuses them.

- [ ] **Step 1: Write the measurement tests and benchmarks**

```go
package ratelimit_test

// slash64Keys returns n distinct /64 keys in the shape SourceGuard composes.
func slash64Keys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("api-key:2001:db8:%x:%x::/64", i>>16, i&0xffff)
	}
	return keys
}

func heapAlloc() uint64 {
	runtime.GC(); runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func TestMemoryLimiterMeasure_Heap(t *testing.T) {
	if testing.Short() { t.Skip("measurement") }
	for _, n := range []int{100_000, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			keys := slash64Keys(n)
			clk := clockwork.NewFakeClockAt(epoch)
			before := heapAlloc()
			l := newMeasuredLimiter(t, clk)
			for _, k := range keys { _ = l.RecordFailure(t.Context(), strings.Clone(k)) }
			after := heapAlloc()
			t.Logf("keys=%d heap=%.1fMiB perKey=%.1fB", n,
				float64(after-before)/(1<<20), float64(after-before)/float64(n))
			runtime.KeepAlive(l)
		})
	}
}
```

Also add:
- `TestMemoryLimiterMeasure_SweepStall`: 1,000,000 keys. Advance the clock by `window + time.Second`. Eight goroutines call `Exceeded` on 4,096 hot keys, recording max and p99 latency. Then time the first `Exceeded` that triggers the sweep. Log every figure.
- `TestMemoryLimiterMeasure_SingleLockReference`: the same keys in a plain `map[string][]time.Time` behind one `sync.Mutex`. Time one full scan that deletes every entry. Log it as `reference=`.
- `TestMemoryLimiterMeasure_HeapAfterSweep`: the heap after every key is swept and `heapAlloc()` runs.
- `BenchmarkMemoryLimiter_Mixed`: `b.RunParallel` over 100,000 prefilled keys, 90% `Exceeded` and 10% `RecordFailure`, picking keys with a per-goroutine `rand.New(rand.NewPCG(seed, 0))`.

Each measurement test starts with `skipUnlessMeasuring(t)`, which skips it under `-short` and unless `SCRTY_MEASURE` is set: wall-clock timing on a loaded machine or a shared CI runner measures the scheduler, so these run on demand on a quiet machine (design.md, Risks). Task 3.4's assertion takes the best of five trials against the median of three reference scans, and is logged rather than asserted under `-race`.

- [ ] **Step 2: Run and capture**

Run: `SCRTY_MEASURE=1 go test -run 'TestMemoryLimiterMeasure' -count=1 -v ./ratelimit/`
Run: `go test -run '^$' -bench 'BenchmarkMemoryLimiter' -benchmem -count 6 -cpu 1,8 ./ratelimit/ | tee /tmp/bench-baseline.txt`
Expected, on the unchanged code: heap about 149 MiB at 1M keys, a sweep of about 100 ms, and a heap after the sweep of about 96 MiB (figures vary by machine). Report all of them.

- [ ] **Step 3: Confirm `go test -short ./ratelimit/` skips them and stays fast**

Run: `go test -short -count=1 ./ratelimit/`
Expected: PASS in seconds.

### Task 2.1: Red step for a clock stepped back (`UNREPRODUCED`)

**Files:**
- Modify: `ratelimit/memory_test.go`, adding a case to `TestTheLimiterBoundsItsMemoryWithoutDisarmingLimits` or a new top-level test named below.

**Interfaces:** consumes `MemoryLimiter.Prune`, `MemoryLimiter.StampsFor` and `clockwork.FakeClock`. Stepping back uses a consumer clock type that the test can set to any instant. clockwork's fake clock only advances, so add `settableClock` in the test file: a `sync.Mutex` and a `time.Time`, with `Now()` and `Set(time.Time)`.

- [ ] **Step 1: Write the failing test**

```go
func TestMemoryLimiter_SweepResumesAfterClockSteppedBack(t *testing.T) {
	clk := &settableClock{now: epoch} // 12:00:00
	l, err := ratelimit.NewMemoryLimiter(testLimit, time.Minute, ratelimit.WithMemoryLimiterClock(clk))
	require.NoError(t, err)

	l.Prune() // sweptAt = 12:00:00
	clk.Set(epoch.Add(-time.Hour)) // 11:00:00

	keys := slash64Keys(1000)
	for _, k := range keys {
		require.NoError(t, l.RecordFailure(t.Context(), k))
	}

	clk.Set(epoch.Add(-time.Hour + 2*time.Minute)) // 11:02:00
	for _, k := range keys {
		_, err := l.Exceeded(t.Context(), k)
		require.NoError(t, err)
	}

	for _, k := range keys {
		assert.Zero(t, l.StampsFor(k), "key %s should have been swept", k)
	}
}
```

- [ ] **Step 2: Run it**

Run: `go test -run TestMemoryLimiter_SweepResumesAfterClockSteppedBack -count=1 ./ratelimit/`
Expected, if the claim holds: FAIL, with `StampsFor` = 1 for the keys, because `now.Sub(sweptAt)` is negative and no sweep runs. Report the output. If it PASSES, report that. The claim is then refuted: skip 2.2, and the main session removes decision 4.

### Task 2.2: Re-arm the pacing (only if 2.1 failed)

**Files:** Modify `ratelimit/memory.go`, `sweepLocked`.

- [ ] **Step 1: Minimal fix**

```go
func (l *MemoryLimiter) sweepLocked(now time.Time) {
	// A clock stepped backwards leaves sweptAt in the future, and pacing on a
	// negative interval would stop sweeping until the clock caught up again.
	// Re-arming from now resumes it one window later; sweeping sooner never
	// removes a live key, because keys are judged by their newest stamp.
	if now.Before(l.sweptAt) {
		l.sweptAt = now
		return
	}
	if now.Sub(l.sweptAt) < l.window {
		return
	}
	l.pruneLocked(now)
}
```

- [ ] **Step 2: Verify**

Run: `go test -run TestMemoryLimiter_SweepResumesAfterClockSteppedBack -count=1 ./ratelimit/` (PASS), then `go test -race -count=1 ./ratelimit/...` (PASS).

### Task 3.1: Red step for memory returned after a flood

**Files:** Modify `ratelimit/memory_test.go`.

- [ ] **Step 1: Write the failing test**

```go
func TestMemoryLimiter_ReturnsMemoryAfterFlood(t *testing.T) {
	if testing.Short() { t.Skip("allocates 1M keys") }
	clk := clockwork.NewFakeClockAt(epoch)
	keys := slash64Keys(1_000_000)
	base := heapAlloc()
	l, err := ratelimit.NewMemoryLimiter(testLimit, time.Minute,
		ratelimit.WithMemoryLimiterClock(clk))
	require.NoError(t, err)
	for _, k := range keys { require.NoError(t, l.RecordFailure(t.Context(), k)) }
	peak := heapAlloc() - base

	clk.Advance(2*time.Minute + time.Second)
	for _, k := range keys { _, _ = l.Exceeded(t.Context(), k) }
	after := heapAlloc() - base
	runtime.KeepAlive(l)

	assert.Less(t, after, peak/10, "peak=%d after=%d", peak, after)
}
```

`slash64Keys` and `heapAlloc` live in `memory_bench_test.go` (Task 1.1), in the same package `ratelimit_test`. `keys` is kept alive in both measurements, so it cancels out.

- [ ] **Step 2: Run it**

Run: `go test -run TestMemoryLimiter_ReturnsMemoryAfterFlood -count=1 ./ratelimit/`
Expected: FAIL with `after` at about 64% of `peak`, because the map keeps its buckets. Report the output.

### Task 3.2: Shard the limiter

**Files:**
- Create: `ratelimit/memory_shard.go`, holding the shard type and its locked operations.
- Modify: `ratelimit/memory.go`, so that `MemoryLimiter` holds the shards and routes to them.
- Modify: `ratelimit/memory_test.go`, so the inline-pruning case checks every key ("each of them is checked").

**Interfaces:**
- Produces, unexported: `const shardCount = 64`, `type memoryShard struct`, `(*MemoryLimiter).shardFor(key string) *memoryShard`, and `(*memoryShard).pruneLocked(now time.Time, cutoff time.Time) (removed int)`, which returns how many keys it removed, for Task 4.2's count.
- The public API is unchanged: `Exceeded`, `RecordFailure`, `Prune` and `StampsFor` keep their signatures.

- [ ] **Step 1: Write the sharded structure**

```go
// memory_shard.go
package ratelimit

// shardCount is how many independently locked parts a MemoryLimiter divides
// its keys into. A sweep holds one shard's lock, so a check waits for at most a
// sixty-fourth of the sweep work, and checks of keys in other shards do not
// wait at all. It is not an option: it changes latency, not what is limited.
const shardCount = 64

type memoryShard struct {
	mu        sync.Mutex
	keys      map[string][]time.Time
	sweptAt   time.Time
	highWater int
	_         [64]byte // keeps neighbouring shards' mutexes off one cache line
}
```

In `MemoryLimiter`:
- replace `mu`, `keys` and `sweptAt` with `shards [shardCount]memoryShard` and `seed maphash.Seed`;
- in `NewMemoryLimiter`, set `seed = maphash.MakeSeed()` and give each shard `keys = map[string][]time.Time{}` and `sweptAt = l.clock.Now()`.

```go
func (l *MemoryLimiter) shardFor(key string) *memoryShard {
	return &l.shards[maphash.String(l.seed, key)%shardCount]
}
```

Move `countLocked`, `sweepLocked` (with 2.2's re-arm, if it landed) and `pruneLocked` onto `*memoryShard`, taking `window` as a parameter. `Exceeded` and `RecordFailure` lock `s := l.shardFor(key)` only. `Prune` loops over the shards, locking each in turn.

- [ ] **Step 2: Run the whole existing suite unedited, except the inline-pruning case**

Run: `go test -race -count=1 ./ratelimit/...`
Expected: PASS, including 2.1's test.
Run, in `test/`: `go test -race -run TestRateLimitConformance_Memory -count=1 ./...`
Expected: PASS.

- [ ] **Step 3: Refactor, then consider `/simplify` on `memory.go` and `memory_shard.go`. Re-run step 2.**

### Task 3.3: Compaction

**Files:** Modify `ratelimit/memory_shard.go` and `ratelimit/memory_test.go`.

- [ ] **Step 1: Write the test that a compacted shard keeps live keys**

```go
func TestMemoryLimiter_CompactionKeepsLiveKeys(t *testing.T) {
	clk := clockwork.NewFakeClockAt(epoch)
	l, err := ratelimit.NewMemoryLimiter(testLimit, time.Minute, ratelimit.WithMemoryLimiterClock(clk))
	require.NoError(t, err)
	keys := slash64Keys(200_000) // ~3,000 per shard, above the 1,024 mark
	for _, k := range keys { require.NoError(t, l.RecordFailure(t.Context(), k)) }
	clk.Advance(50 * time.Second)
	live := keys[:1000] // a few per shard: well under a quarter
	for _, k := range live { require.NoError(t, l.RecordFailure(t.Context(), k)) }
	clk.Advance(20 * time.Second) // the first stamps have expired; the live keys' second stamps have not
	l.Prune()
	for _, k := range live {
		assert.Equal(t, 2, l.StampsFor(k))
		exceeded, err := l.Exceeded(t.Context(), k)
		require.NoError(t, err)
		assert.False(t, exceeded)
	}
	assert.Zero(t, l.StampsFor(keys[len(keys)-1]))
}
```

This passes before compaction too. It guards the copy. The red step for compaction is 3.1.

- [ ] **Step 2: Implement**

```go
// compactLocked replaces a shard's map once a sweep has left it under a
// quarter of its high-water mark. Go maps keep their buckets after deletes,
// so without this a flood's memory stays held after its keys have gone.
func (s *memoryShard) compactLocked() {
	n := len(s.keys)
	if n > s.highWater { s.highWater = n }
	if s.highWater < 1024 || n >= s.highWater/4 { return }
	fresh := make(map[string][]time.Time, n)
	maps.Copy(fresh, s.keys)
	s.keys, s.highWater = fresh, n
}
```

Update `highWater` on insert in `RecordFailure`, and call `compactLocked` at the end of `pruneLocked`.

- [ ] **Step 3: Verify**

Run: `go test -run 'TestMemoryLimiter_(ReturnsMemoryAfterFlood|CompactionKeepsLiveKeys)' -count=1 ./ratelimit/` (PASS), then `go test -race -count=1 ./ratelimit/...` (PASS).

### Task 3.4: Re-measure, and godoc

**Files:** Modify `ratelimit/memory_bench_test.go` and the `MemoryLimiter` godoc in `ratelimit/memory.go`.

- [ ] **Step 1: Add the ratio assertion to `TestMemoryLimiterMeasure_SweepStall`**

Measure the reference (Task 1.1) and the worst sharded call in the same test run, then:

```go
assert.LessOrEqual(t, worst*30, reference, "worst=%s reference=%s", worst, reference)
```

- [ ] **Step 2: Run**

Run: the two commands from 1.1. Expected: PASS. Report the heap, the worst call, the reference, the reader max and p99, and throughput at `-cpu 1,8`, next to the 1.1 figures.

- [ ] **Step 3: Godoc.** Replace the sweep paragraph of `MemoryLimiter`'s godoc. It must state:
- 64 shards;
- that a check waits only for its own shard's sweep;
- the compaction rule;
- why the shard count has no option.

Run `go doc ./ratelimit MemoryLimiter`.

### Task 4.1: Cap option and default

**Files:** Modify `ratelimit/options.go`, `ratelimit/memory.go` and `ratelimit/memory_test.go` (table `TestNewMemoryLimiterRefusesALimiterThatCannotWork`). Create `ratelimit/memory_cap_test.go`.

**Interfaces:**
- Produces: `const DefaultMemoryLimiterMaxKeys = 250_000`, `func WithMemoryLimiterMaxKeys(n int) MemoryOption`, and the field `maxKeys int`.

- [ ] **Step 1: Failing tests.** Add a "zero max keys" case (`WithMemoryLimiterMaxKeys(0)` and `-1`, each asserting `errors.Is(err, ratelimit.ErrConfig)`) to the constructor table. Add a test that `ratelimit.DefaultMemoryLimiterMaxKeys == 250_000`. Add `TestMemoryLimiter_MaxKeysHoldsOnlyThatMany`, which uses `WithMemoryLimiterMaxKeys(3)`, records `a`, `b`, `c`, `d`, and asserts that `StampsFor("d") == 0` and the others are 1. That last one is red until 4.2. In 4.1 make the option and constant exist and the constructor check pass; the holding assertion turns green in 4.2.
- [ ] **Step 2: Run.** `go test -run 'TestNewMemoryLimiter|TestMemoryLimiter_MaxKeys' -count=1 ./ratelimit/`. Expected: the constructor cases FAIL with "undefined: WithMemoryLimiterMaxKeys" — **that is a compile error, so not the red step.** First add the option as a stub that sets nothing, re-run, and see the zero case FAIL because construction succeeds.
- [ ] **Step 3: Implement**

```go
// WithMemoryLimiterMaxKeys sets how many keys the limiter holds at most.
// Default: DefaultMemoryLimiterMaxKeys (250,000), about 37 MiB at the measured
// ~157 bytes per key. At the maximum, a key the limiter does not already hold
// is refused with ErrLimiterFull and held keys are counted as before; nothing
// is evicted to make room. A value of zero or less fails construction with
// ErrConfig. There is no unbounded mode: a consumer who accepts unbounded
// memory passes math.MaxInt. MemoryLimiterFactory applies it to every limiter
// it builds.
func WithMemoryLimiterMaxKeys(n int) MemoryOption {
	return func(l *MemoryLimiter) { l.maxKeys = n }
}
```

The constructor default is `maxKeys: DefaultMemoryLimiterMaxKeys`. Validate it with `if l.maxKeys <= 0 { return nil, fmt.Errorf("%w: a maximum of %d keys holds no source at all", ErrConfig, l.maxKeys) }`.

- [ ] **Step 4: Verify.** The constructor cases PASS. `go test -race -count=1 ./ratelimit/...` PASS, apart from the holding assertion, which is red until 4.2.

### Task 4.2: Refusal at the cap

**Files:** Modify `ratelimit/memory.go`, `ratelimit/memory_shard.go` and `ratelimit/memory_cap_test.go`.

**Interfaces:**
- Produces: `var ErrLimiterFull = errors.New("ratelimit: the limiter is holding its maximum number of keys")`, and the field `held atomic.Int64`.

- [ ] **Step 1: Failing table test `TestMemoryLimiter_Full`.** Each case builds a limiter with a small cap, applies a setup, then asserts:
- "new source at the cap": `max=2`, holds `a` and `b`. `Exceeded(c)` returns `true` and `errors.Is(err, ErrLimiterFull)`.
- "record for new source at the cap": `RecordFailure(c)` returns `ErrLimiterFull`, and `StampsFor(c) == 0`.
- "held source at the cap": limit 3, `max=2`, `a` has 1 failure, `b` is held. Two more failures on `a`, then `Exceeded(a)` returns `true` with a nil error.
- "room after pruning": `max=2`, `a` and `b` failed at 12:00:00. At 12:02:30 `c` records, and `c` is held while `a` and `b` are not.
- "live keys never evicted": `max=2`, `a` and `b` live. 1,000 other keys are checked and recorded, then `a` and `b` still have their stamps.
- "refill after full prune" (Review Focus 1): `max=100`. Fill 100 keys, advance past two windows, `Prune()`, then fill another 100 distinct keys with no error, and the 101st returns `ErrLimiterFull`.

Also `TestMemoryLimiter_CapHoldsUnderConcurrency`: 64 goroutines, each recording 50 distinct keys into `max=100` under `-race`. Then count the keys with `StampsFor > 0` over all 3,200 keys, and assert it is exactly 100.

- [ ] **Step 2: Run.** `go test -race -run 'TestMemoryLimiter_(Full|Cap)' -count=1 ./ratelimit/`. Expected: FAIL. `c` is held and no error is returned.
- [ ] **Step 3: Implement**

```go
// In Exceeded, under the shard lock:
stamps, held := s.keys[key]
if !held && l.held.Load() >= int64(l.maxKeys) {
	l.warnFull(now)
	return true, fmt.Errorf("ratelimit: check %q: %w", key, ErrLimiterFull)
}

// In RecordFailure, under the shard lock, before inserting a new key:
if _, held := s.keys[key]; !held {
	if l.held.Add(1) > int64(l.maxKeys) {
		l.held.Add(-1)
		l.warnFull(now)
		return fmt.Errorf("ratelimit: record %q: %w", key, ErrLimiterFull)
	}
}

// In memoryShard.pruneLocked: return removed; the caller does l.held.Add(-int64(removed)).
```

Compaction moves keys without changing `held`. Leave `warnFull` as a no-op stub, which Task 4.3 fills in.

- [ ] **Step 4: Verify.** Step 2's command PASSES, 4.1's holding assertion PASSES, and `go test -race -count=1 ./ratelimit/...` PASSES. Then, in `test/`, `go test -race -run TestRateLimitConformance_Memory ./...` PASSES.

### Task 4.3: The full-limiter warning

**Files:** Modify `ratelimit/memory.go` and `ratelimit/memory_cap_test.go`.

- [ ] **Step 1: Failing test `TestMemoryLimiter_FullWarning`.** It uses a recording `slog` handler (reuse the handler `TestThePerReplicaWarningIsWrittenOnce` captures records with, or add one beside it), a 1-minute window and `max=10`. Fill the limiter, check 500 new keys within one minute, and assert exactly one record whose message contains "maximum number of keys", with an attribute `max_keys=10`. Advance one window, check again, and assert a second record.
- [ ] **Step 2: Run.** `go test -run TestMemoryLimiter_FullWarning -count=1 ./ratelimit/`. Expected: FAIL, with 0 records.
- [ ] **Step 3: Implement**

```go
const fullWarning = "ratelimit: the in-memory limiter is holding its maximum number of keys, " +
	"so attempts from sources it does not already hold are refused"

// warnFull writes fullWarning at most once per window. warnedAt is an
// atomic.Int64 of UnixNano, swapped by CompareAndSwap so concurrent shards
// write one record.
func (l *MemoryLimiter) warnFull(now time.Time) {
	last := l.warnedFullAt.Load()
	if last != 0 && now.UnixNano()-last < int64(l.window) { return }
	if !l.warnedFullAt.CompareAndSwap(last, now.UnixNano()) { return }
	l.logger.Warn(fullWarning, slog.Int("max_keys", l.maxKeys), slog.Duration("window", l.window))
}
```

- [ ] **Step 4: Verify.** Step 2's command PASSES, and `go test -race -count=1 ./ratelimit/...` PASSES.

### Task 5.1: Keyer prefix accessor and aggregate keys

**Files:** Modify `ratelimit/keyer.go` and `ratelimit/keyer_test.go`. Create `ratelimit/export_test.go` (package `ratelimit`), which exposes `keys` to the external test package.

**Interfaces:**
- Produces:
  - `func (k *SourceKeyer) IPv6Prefix() int`;
  - unexported `func (k *SourceKeyer) keys(clientAddr string, aggregateBits int) (source, aggregate string, err error)`. `aggregate` is `""` for IPv4 or when `aggregateBits == 0`.
- `Key` keeps its signature and delegates to `keys(addr, 0)`.

- [ ] **Step 1: Failing table test `TestSourceKeyer_Aggregate`** (Review Focus 2):

| input | bits | source | aggregate |
|---|---|---|---|
| `2001:db8:1:2::1` | 56 | `2001:db8:1:2::/64` | `2001:db8:1::/56` |
| `2001:db8:1:100::1` | 56 | `2001:db8:1:100::/64` | `2001:db8:1:100::/56` |
| `fe80::1%eth0` | 56 | `fe80::/64` | `fe80::/56` |
| `::ffff:203.0.113.7` | 56 | `203.0.113.7` | `""` |
| `203.0.113.7` | 56 | `203.0.113.7` | `""` |

Also assert that `IPv6Prefix()` is 64 by default and 56 with `WithIPv6SourcePrefix(56)`. The test is in package `ratelimit_test`, so it reaches `keys` through the guard in 5.3. Here it covers `IPv6Prefix` plus an `export_test.go` shim, `var SourceKeys = (*SourceKeyer).keys`.

- [ ] **Step 2: Run.** `go test -run TestSourceKeyer -count=1 ./ratelimit/`. Expected: FAIL, after a stub `keys` that returns `"", "", nil` (avoiding the compile-error non-red).
- [ ] **Step 3: Implement.** Compute the source as today. If `addr.Is6()` (after `Unmap`) and `aggregateBits > 0`, then `p, _ := addr.WithZone("").Prefix(aggregateBits)` and `aggregate = p.String()`.
- [ ] **Step 4: Verify.** Step 2's command PASSES, and `go test -race -count=1 ./ratelimit/...` PASSES.

### Task 5.2: The aggregate guard option and its validation

**Files:** Modify `ratelimit/options.go`, `ratelimit/guard.go` and `ratelimit/guard_test.go` (table `TestNewSourceGuardRefusesAGuardThatCannotCount`).

**Interfaces:**
- Produces: `func WithSourceGuardIPv6Aggregate(bits int, limiter Limiter) GuardOption`, and the fields `aggregateBits int` and `aggregate Limiter` on `SourceGuard`.

- [ ] **Step 1: Failing cases** in the constructor table, each asserting `errors.Is(err, ErrConfig)`:
- a nil limiter;
- a typed nil (`(*ratelimit.MemoryLimiter)(nil)`);
- `bits` 0 and 128;
- `bits` 64 with the default keyer (/64);
- `bits` 56 with `WithSourceGuardKeyer` at a /56 keyer.

Plus one valid case: `bits` 56 with the default keyer, which succeeds.
- [ ] **Step 2: Run.** `go test -run TestNewSourceGuard -count=1 ./ratelimit/`, after stubbing the option. Expected: FAIL, because the invalid cases construct successfully.
- [ ] **Step 3: Implement.** The option sets a flag `aggregateSet = true`, plus `bits` and `limiter`. In `NewSourceGuard`, when `aggregateSet`:
  - `nilcheck.IsNil(limiter)` → `"%w: the IPv6 aggregate for flow %q was given no limiter"`;
  - `bits < 1 || bits > 127` → refused;
  - `bits >= g.keyer.IPv6Prefix()` → `"%w: an IPv6 aggregate of /%d is no wider than the /%d source prefix, so it would count nothing the source does not"`.

  Godoc states that the default is off at this level, because a guard cannot invent a limit for a limiter it was not given, and that `httpsec` turns it on.
- [ ] **Step 4: Verify.** Step 2's command PASSES, and `go test -race -count=1 ./ratelimit/...` PASSES.

### Task 5.3: Check and record with an aggregate

**Files:** Modify `ratelimit/guard.go`. Create `ratelimit/guard_aggregate_test.go`.

**Interfaces:**
- `Source` gains the unexported `aggregateKey string` and `aggregateAddr string`.
- `Source.Key()` and `Source.Addr()` are unchanged: they still name the source, not the aggregate.

- [ ] **Step 1: Failing table test `TestSourceGuard_Aggregate`.**
  - Cases with real in-memory limiters (source limit 5, aggregate limit 4, 1-minute window, `bits` 56):
    - "rotating /64s": record one failure each from `2001:db8:1:1::1` through `2001:db8:1:4::1`. Then `Check("2001:db8:1:5::1")` returns `ErrThrottled`.
    - "another aggregate unaffected": the same setup, then `Check("2001:db8:1:100::1")` succeeds.
    - "IPv4 unaffected": a `MockLimiter` aggregate with no expectations. `Check("203.0.113.7")` succeeds, and the mock fails the test if it is called.
  - Cases with `MockLimiter` for both limiters:
    - "aggregate error fails closed": the source answers false and nil, and the aggregate returns an error. Result: `ErrThrottled`.
    - "source record fails" (Review Focus 4): the source `RecordFailure` errors, and the aggregate `RecordFailure` is still called once.
    - "aggregate record fails": the reverse.
- [ ] **Step 2: Run.** `go test -race -run TestSourceGuard_Aggregate -count=1 ./ratelimit/`. Expected: FAIL. The rotating case is admitted, and the mocks are not called.
- [ ] **Step 3: Implement.**
  - `Check` uses `g.keyer.keys(clientAddr, g.aggregateBits)` and sets `src.aggregateKey = g.flow + keySeparator + aggregate`, only when `aggregate != ""`.
  - After the source check passes, if `src.aggregateKey != ""` it calls `g.aggregate.Exceeded(ctx, src.aggregateKey)`. Errors take the same path as the source limiter's. When exceeded, it goes to the 5.4 record and returns `ErrThrottled`.
  - `RecordFailure` records the source, then, if `s.aggregateKey != ""`, records the aggregate. Each error is reported through the existing not-recorded path on its own.
- [ ] **Step 4: Verify.** Step 2's command PASSES, and `go test -race -count=1 ./ratelimit/...` PASSES.

### Task 5.4: Aggregate refusal records

**Files:** Modify `ratelimit/guard.go` and `ratelimit/guard_aggregate_test.go`.

- [ ] **Step 1: Failing test `TestSourceGuard_AggregateLog`.** Use a recording handler and the fake clock. The aggregate `2001:db8:1::/56` is exceeded, and 50 checks come from 50 distinct /64s inside it within one minute. Assert exactly one WARN record with `aggregate=2001:db8:1::/56`. Assert that `Flush` reports `suppressed=49` under key `throttled:<flow>:2001:db8:1::/56`.
- [ ] **Step 2: Run.** Expected: FAIL. Either there are 50 records keyed per /64, or none.
- [ ] **Step 3: Implement.** On an aggregate refusal:

```go
g.sampled(ctx, slog.LevelWarn, msgThrottledAggregate,
	sampleKey(sampleThrottled, g.flow, src.aggregateAddr),
	slog.String("source", src.addr), slog.String("aggregate", src.aggregateAddr))
```

with `msgThrottledAggregate = "ratelimit: refusing an attempt from an IPv6 aggregate over its limit"`.
- [ ] **Step 4: Verify.** `go test -race -run TestSourceGuard_AggregateLog -count=1 ./ratelimit/` PASSES, and the full `./ratelimit/...` run PASSES.

### Task 5.5: Full-limiter refusals in the guard

**Files:** Modify `ratelimit/guard.go`, `ratelimit/guard_test.go` and `ratelimit/options.go` (godoc of `WithSourceGuardLogReporter`).

- [ ] **Step 1: Failing table test `TestSourceGuard_Full`.** Each case uses `MockLimiter`:
- "source limiter full": the source `Exceeded` returns `true` and `fmt.Errorf("x: %w", ratelimit.ErrLimiterFull)`. The check returns `ErrThrottled`, and one WARN record carries the message "ratelimit: refusing an attempt because the limiter is full" and `reason=limiter-full`. No limiter-unavailable record is written.
- "aggregate limiter full" (Review Focus 3): the source answers false and nil, and the aggregate returns `ErrLimiterFull`. Same assertions.
- "sampling": 20 full refusals within a minute give one record, and `Flush` reports `suppressed=19` under key `full:<flow>:`.
- [ ] **Step 2: Run.** `go test -race -run TestSourceGuard_Full -count=1 ./ratelimit/`. Expected: FAIL, because the record is the limiter-unavailable one.
- [ ] **Step 3: Implement.** In `reportUnconsultableLimiter`, before the outage branch:

```go
if errors.Is(err, ErrLimiterFull) {
	g.sampled(ctx, slog.LevelWarn, msgLimiterFull, sampleKey(sampleLimiterFull, g.flow, ""),
		slog.String("source", s.addr), slog.String("reason", "limiter-full"))
	return
}
```

with `sampleLimiterFull = "full"`. Update the `WithSourceGuardLogReporter` godoc: the key is also `"full:<flow>:"` for a full limiter.
- [ ] **Step 4: Verify.** Step 2's command PASSES, `go test -race -count=1 ./ratelimit/...` PASSES, and `go doc ./ratelimit WithSourceGuardLogReporter` shows the new family.

### Task 6.1: Chain aggregate options and validation

**Files:** Modify `httpsec/options.go`. Create `httpsec/chain_aggregate_test.go`.

**Interfaces:**
- Produces:
  - `func WithIPv6Aggregate(bits, multiplier int) Option`;
  - `func WithoutIPv6Aggregate() Option`;
  - config fields `aggregateBits int` (default 56), `aggregateMultiplier int` (default 4), `aggregateExplicit bool` and `aggregateOff bool`;
  - consts `defaultIPv6AggregatePrefix = 56` and `defaultIPv6AggregateMultiplier = 4`.

- [ ] **Step 1: Failing table test `TestChain_IPv6Aggregate_Construction`.** Each case calls `httpsec.New(...)`, with API key enabled the way existing chain tests enable it:
- "aggregate no wider than the source": `WithIPv6SourcePrefix(48), WithIPv6Aggregate(56, 4)` → error mentioning `WithIPv6Aggregate`;
- "zero multiplier": `WithIPv6Aggregate(56, 0)` → error;
- "bits 0" and "bits 128" → error;
- "both": `WithIPv6Aggregate(56, 4), WithoutIPv6Aggregate()` → error;
- "wide source skips the default": `WithIPv6SourcePrefix(48)` alone → no error;
- "order independent": `WithIPv6Aggregate(48, 2), WithIPv6SourcePrefix(64)` → no error.
- [ ] **Step 2: Run** after stubbing both options as no-ops. `go test -run TestChain_IPv6Aggregate -count=1 ./httpsec/`. Expected: FAIL, because the error cases construct.
- [ ] **Step 3: Implement.** The options only record what was asked. `validate()` (or `build()`, before the keyer) checks:
  - `aggregateExplicit && aggregateOff`;
  - an explicit multiplier `< 1`;
  - explicit `bits` outside 1..127;
  - explicit `bits >= ipv6Prefix`.

  The resulting aggregate is off when `aggregateOff`, or when it is not explicit and `ipv6Prefix <= 56`. Errors come from `newConfigError("WithIPv6Aggregate ...")`.
- [ ] **Step 4: Verify.** Step 2's command PASSES, and `go test -race -count=1 ./httpsec/...` PASSES.

### Task 6.2: Build the aggregate limiter for every source guard

**Files:** Modify `httpsec/throttle.go` (`resolveSourceGuard`), `httpsec/chain_ratelimit_test.go` (`TestChain_RateLimiterFactoryReachesFlows`) and `httpsec/chain_aggregate_test.go`.

- [ ] **Step 1: Failing tests**, through `httptest` requests in the style of the existing chain rate-limit tests:
- "default aggregate": the API key is enabled with the default 20/min. Make 20 failed attempts from each of `2001:db8:1:1::1` through `2001:db8:1:4::1`. The attempt from `2001:db8:1:5::1` gets 429 (or the chain's throttled status mapping).
- "consumer aggregate": `WithIPv6Aggregate(48, 2)`, 20 failures from each of `2001:db8:1:1::1` and `2001:db8:1:200::1`, then `2001:db8:1:300::1` is throttled.
- "aggregate turned off": `WithoutIPv6Aggregate()`, with the "default aggregate" setup. The fifth /64 is not throttled.
- "default prefix": the existing scenario is still not throttled.
- Update `TestChain_RateLimiterFactoryReachesFlows`: the recording factory also sees `api-key-ipv6-aggregate` with `limit*4` and the same window, and the same for each source-guarded flow (magic link, OIDC handoff, passwordless, recovery, recovery start). Second factor gets no aggregate.
- "flow option wins": the factory is asked for `api-key-ipv6-aggregate` but not for `api-key`.
- [ ] **Step 2: Run.** `go test -race -run 'TestChain_(IPv6Aggregate|RateLimiterFactoryReachesFlows)' -count=1 ./httpsec/`. Expected: FAIL, because the fifth /64 is admitted and the factory receives no aggregate call.
- [ ] **Step 3: Implement**

```go
opts := []ratelimit.GuardOption{ /* existing four */ }
if c.aggregateOn() {
	agg, err := c.rateLimiterFactory().NewLimiter(flow+"-ipv6-aggregate", limit*c.aggregateMultiplier, window)
	if err != nil {
		return nil, newConfigError("%s could not build its IPv6 aggregate limiter for namespace %q: %s",
			option, flow+"-ipv6-aggregate", err)
	}
	opts = append(opts, ratelimit.WithSourceGuardIPv6Aggregate(c.aggregateBits, agg))
}
```

- [ ] **Step 4: Verify.** Step 2's command PASSES. Then `go test -race -count=1 ./httpsec/...`, and `go test -race ./...` inside `ginsec/` and `fibersec/`, all PASS.

### Task 6.3: Godoc

**Files:** Modify `httpsec/options.go` and `httpsec/doc.go`.

- [ ] **Step 1:** The godoc of `WithIPv6Aggregate` and `WithoutIPv6Aggregate` states:
  - the default (/56 at 4× the flow's limit, over the flow's window);
  - the namespace `<flow>-ipv6-aggregate`;
  - that the aggregate is built from the chain's factory even when a flow has its own limiter, and counts per replica if that factory is the in-memory default;
  - that a /48 holder still gets 256 × 4 times a flow's allowance, and `WithIPv6Aggregate(48, n)` closes that;
  - that the default is skipped when the source prefix is /56 or wider.

  `WithIPv6SourcePrefix` mentions the interaction. The `doc.go` rate-limit section lists the aggregate.
- [ ] **Step 2:** `go doc ./httpsec WithIPv6Aggregate`, `go doc ./httpsec WithoutIPv6Aggregate`, and `go vet ./...`, all clean.

### Task 6.4: `ratelimit.PolicyReporter`

**Files:**
- Create: `ratelimit/policy.go`.
- Modify: `ratelimit/memory.go`, `redis/limiter.go`.
- Test: `ratelimit/memory_cap_test.go` (or a new `ratelimit/policy_test.go`), and `redis/limiter_test.go` or a new `redis/policy_test.go`.

**Interfaces — produces:**

```go
// PolicyReporter is implemented by a Limiter that can say the limit and window
// it counts with. It is optional: a component that needs a limiter's policy,
// such as the httpsec chain sizing an IPv6 aggregate, asks for it with a type
// assertion and treats a limiter without it as one whose policy is unknown.
type PolicyReporter interface {
	Policy() (limit int, window time.Duration)
}

func (l *MemoryLimiter) Policy() (int, time.Duration) // the limit and window it was built with
func (l *Limiter) Policy() (int, time.Duration)       // package scrtyredis
var _ ratelimit.PolicyReporter = (*MemoryLimiter)(nil)
```

The Redis `Limiter` currently keeps only the wrapped limiter and the server check. Add `limit int` and `window time.Duration` fields, set in `NewLimiter` from its arguments.

- [ ] **Step 1: Failing tests.**
  - `TestMemoryLimiter_Policy`: `NewMemoryLimiter(20, time.Minute)`, then `var r ratelimit.PolicyReporter = l` and `r.Policy()` returns `(20, time.Minute)`.
  - `TestLimiter_Policy` in `redis`: `NewLimiter(client, "ns", 10, 15*time.Minute)` with an unreachable client (construction does no I/O), and `Policy()` returns `(10, 15*time.Minute)`.
  - Stub both methods to return zero values first, so the red step is the assertion and not a compile error.
- [ ] **Step 2: Run.** `go test -race -run TestMemoryLimiter_Policy -count=1 ./ratelimit/`, and `go test -race -run TestLimiter_Policy -count=1 ./...` in `redis`. Expected: FAIL with `expected: 20 actual: 0`, and `expected: 10 actual: 0`.
- [ ] **Step 3: Implement** the methods and fields. Godoc names what each reports, and that the policy is fixed at construction.
- [ ] **Step 4: Verify.** Both commands pass, and `go test -race -count=1 ./ratelimit/...` and `go test -race -count=1 ./...` in `redis` pass.

### Task 6.5: Size the aggregate from a consumer's limiter

**Files:** Modify `httpsec/throttle.go` (`resolveSourceGuard`), `httpsec/options.go` (`WithIPv6Aggregate`, `WithAPIKeyLimiter` and `WithMagicLinkLimiter` godoc), `httpsec/oidc_options.go` (`WithHandoffLimiter` godoc), `httpsec/recoveryoptions.go` (`WithRecoveryLimiter` and `WithRecoveryStartLimiter` godoc), `httpsec/passkeylogin.go` (`PasswordlessLimiter` godoc), and `httpsec/chain_aggregate_test.go`.

**Interfaces:**
- Consumes: `ratelimit.PolicyReporter` (6.4).
- `resolveSourceGuard(option, flow string, limiter ratelimit.Limiter, limit int, window time.Duration, logInterval time.Duration)` keeps its signature. `limiter` is non-nil exactly when the flow was given its own limiter.

- [ ] **Step 1: Failing table cases** in `chain_aggregate_test.go`:
  - "aggregate follows a consumer limiter": `WithAPIKeyLimiter(memLimiter(200, time.Minute))`. 200 failed API-key attempts from one /64 are all refused only by the wrong key, never throttled. The factory receives `NewLimiter("api-key-ipv6-aggregate", 800, time.Minute)`.
  - "consumer limiter reports a longer window": `memLimiter(30, time.Hour)`. The factory receives `("api-key-ipv6-aggregate", 120, time.Hour)`.
  - "consumer limiter that reports no policy": a typed `MockLimiter` (no `Policy` method), with a recording logger. `httpsec.New` succeeds, the factory receives no `api-key-ipv6-aggregate` call, and exactly one WARN names `api-key`.
  - "explicit aggregate over a limiter that reports no policy": `WithIPv6Aggregate(48, 4)` plus that mock. `httpsec.New` fails with a configuration error naming `WithIPv6Aggregate` and `api-key`.
  - "default flow unchanged": no flow limiter. The factory still receives `("api-key-ipv6-aggregate", 80, time.Minute)`.
- [ ] **Step 2: Run** `go test -race -run 'TestChain_IPv6Aggregate' -count=1 ./httpsec/`. Expected: FAIL. The first case is throttled at attempt 81, and the factory receives `(…, 80, 1m0s)` instead of `(…, 800, 1m0s)`.
- [ ] **Step 3: Implement**

```go
// The aggregate is sized from the flow's own limiter when it was given one,
// because that limiter's limit is the consumer's and the flow's default is not.
// A limiter that cannot say its policy gets no default aggregate: building one
// from the default would quietly tighten a limit the consumer chose.
aggLimit, aggWindow := limit, window
if own != nil { // own is the limiter argument as passed in, before the factory fills a nil one
	r, ok := own.(ratelimit.PolicyReporter)
	if !ok {
		if c.aggregateExplicit {
			return nil, newConfigError("%s: WithIPv6Aggregate cannot size the %s aggregate: "+
				"its limiter does not report its limit and window (ratelimit.PolicyReporter)", option, flow)
		}
		c.logger.Warn("httpsec: no IPv6 aggregate for a flow whose limiter does not report its limit and window",
			slog.String("flow", flow), slog.String("option", option))
		// fall through with the aggregate off for this flow
	} else {
		aggLimit, aggWindow = r.Policy()
	}
}
```

Keep the existing overflow check, applied to `aggLimit`. Build the aggregate with `NewLimiter(flow+"-ipv6-aggregate", aggLimit*c.aggregateMultiplier, aggWindow)`.

- [ ] **Step 4: Godoc.**
  - `WithIPv6Aggregate`: the aggregate is four times (the multiplier times) the flow's limit over the flow's window, read from the flow's own limiter when one was given. A limiter that does not implement `ratelimit.PolicyReporter` gets no default aggregate and one warning, and is a configuration error under an explicit `WithIPv6Aggregate`.
  - Each per-flow limiter option listed above: the same sentence about the aggregate, plus "a limiter handed to several flows shares its key cap among them, so a flood on one refuses new sources on all".
- [ ] **Step 5: Verify.** Step 2's command passes. `go test -race -count=1 ./httpsec/... ./ratelimit/...` passes, as does `go test -race ./...` in `ginsec`, `fibersec` and `redis`. `go vet ./...` is clean.

### Task 6.6: Close the review's small gaps

**Files:** Modify `ratelimit/guard_test.go` (`TestSourceGuard_Full`) and `internal/unavailable/wrap.go` (comment only).

- [ ] **Step 1:** Add the row "aggregate limiter full at record time". Both mocks answer `Exceeded` with false and nil. The source's `RecordFailure` returns nil, and the aggregate's returns `fmt.Errorf("x: %w", ratelimit.ErrLimiterFull)`. Assert one record, "ratelimit: a failed attempt was not counted because the limiter is full", with `aggregate=2001:db8:1::/56` and `reason=limiter-full`, sampled under `full:<flow>:`.
  - If it passes at once, temporarily drop the `aggregate` attribute on that path and see it fail, then restore.
- [ ] **Step 2:** Re-wrap the `degradedExceeded` doc comment in `internal/unavailable/wrap.go` so no line runs past the file's usual width, keeping its wording.
- [ ] **Step 3: Verify.** `go test -race -run TestSourceGuard_Full -count=1 ./ratelimit/` passes, `gofmt -l ./internal ./ratelimit` is empty, and `go vet ./...` is clean.

### Task 7.1: Whole-workspace gate (main session)

- [ ] For every module in `go.work` (`.`, `fibersec`, `ginsec`, `gorm`, `passkey/webauthn`, `pgx`, `redis` and `test`), run `go build ./... && go vet ./... && go test -race -count=1 ./...` with Docker running.
- [ ] `gofmt -l .` is empty, and `golangci-lint run ./...` is clean.

### Task 7.2: Whole-branch review (main session dispatches an Opus reviewer)

- [ ] The reviewer reads both spec deltas and design decisions 1–6, and checks the full diff against every requirement and scenario. It reports findings with failing tests, or labels them `UNREPRODUCED`, and edits nothing.
- [ ] The main session updates design.md's baseline table and decision 3's table with the in-tree figures from 1.1 and 3.4, removes decision 4 if 2.1 passed, and ticks the tasks.
