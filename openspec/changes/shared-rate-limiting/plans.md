# Shared Rate Limiting (phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository, code is written only by subagents (`.claude/rules/subagent-delegation.md`); the main session dispatches, verifies, reviews and commits.

**Goal:** Give every built-in throttled flow one factory seam for its limiter, fix the three seam defects (F1, F2, F7), and ship a Redis/Valkey limiter that keeps the in-memory limiter's exact semantics, fails closed and fast, and passes one conformance suite.

**Architecture:** A `ratelimit.LimiterFactory` port in core builds each flow's limiter from the flow's own namespace, limit and window. An internal decorator (`internal/unavailable`, importable by the nested `redis` module because Go's internal rule is path-based) adds the operation timeout, the circuit breaker, the record-error hold and the unavailable modes to any backend limiter. The nested module `github.com/kartaladev/scrty/redis` implements the backend with two single-key Lua scripts and wraps it in that decorator. The conformance suite lives in the `test` module and runs against both limiters.

**Tech Stack:** Go 1.27, `github.com/redis/go-redis/v9` (v9.7.3 or later), testcontainers-go v0.44.0 (adding its Redis module), `pkg/clock` with clockwork fakes, uber-go/mock (`--typed`), testify.

**Spec:** `openspec/changes/shared-rate-limiting/` holds `proposal.md`, `design.md` (decisions 1–14), `specs/rate-limiting/spec.md`, `specs/http-security-chain/spec.md` and `tasks.md`. Executors read the design decision and spec requirement named in each task.

## Global Constraints

- The core module gains no dependency. go-redis appears only in `redis/go.mod` and `test/go.mod`.
- The minimum go-redis version is `v9.7.3`. The supported servers are Redis ≥ 7.0 and Valkey ≥ 7.2.
- No module imports `github.com/kartaladev/scrty/test`, not even from `_test.go` files.
- Every wiring mistake is an error wrapping `ratelimit.ErrConfig` (or the chain's config error in `httpsec`), returned from the constructor.
- No constructor performs I/O. `Verify(ctx)` is the only probe.
- `ratelimit.Limiter` is unchanged.
- Defaults:
  - operation timeout 250ms;
  - probe interval 1s;
  - key prefix `scrty:ratelimit:`;
  - keys longer than 512 bytes are stored as `sha256:<hex>`;
  - stamps are kept in microseconds.
- Namespaces:
  - source guards use their existing flow names (`api-key`, `magic-link-redeem`, `oidc.handoff`, `passkey-login`, `account-recovery`, `account-recovery-start`);
  - user-keyed sites use `mfa-verify`, `mfa-enrol-begin`, `mfa-enrol-confirm`, `recovery-user`, `recovery-codes` and `passkey-email-confirm`.
- Precedence at every site: the explicit limiter option, then the configured factory, then `MemoryLimiterFactory` with the component's logger and clock.
- Tests:
  - table form with `assert` closures (`.claude/skills/table-test`);
  - `t.Context()`;
  - mocks via `.claude/skills/use-mockgen`;
  - containers via `.claude/skills/use-testcontainers`;
  - red before green, and a compile error is not a red step.
- Never cite or copy the legacy reference (`.claude/rules/legacy-reference.md`).
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.

## Review Focus

1. **Typed-nil factories and clients.** An interface holding a nil `*redis.Client`, or a nil factory pointer, must fail construction, never panic at first request. Pinned in Task 2.2, 2.3 and 5.2.
2. **Two chains from one factory.** A consumer building an admin chain and a public chain from one Redis factory must not get an error, and both must count into the same buckets. Pinned in Task 5.5 ("same namespace, same policy").
3. **The breaker under concurrency.** Many goroutines arriving while half-open must produce exactly one probe. A probe that times out must reopen the breaker, not hang. Pinned in Task 4.2.
4. **A key at exactly 512 bytes and at 513.** The first is stored raw, the second hashed. Two different 600-byte keys must not collide into one bucket. Pinned in Task 5.2.
5. **A consumer-supplied flow limiter plus a chain factory.** The explicit limiter wins, and the factory is never asked for that namespace. Asking anyway would also trip the conflicting-policy check if defaults differ. Pinned in Task 2.3.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `ratelimit/factory.go` | `LimiterFactory`, `MemoryLimiterFactory`, `Verifier` | 1.2 |
| `ratelimit/factory_test.go` | factory tests | 1.2 |
| `ratelimit/unavailable.go` | the public `UnavailableMode` type and constants, `ErrBackendUnavailable` | 4.1 |
| `internal/unavailable/{wrap.go,breaker.go,hold.go}` | the decorator, breaker and record-error hold | 4.1–4.4 |
| `internal/unavailable/*_test.go`, `internal/unavailable/limiter_mock_test.go` | decorator tests, generated mock of `ratelimit.Limiter` | 4.x |
| `mfa/throttle.go`, `mfa/options.go` | default via factory (1.3), `WithVerifyLimiterFactory` (2.2) | 1.3, 2.2 |
| `recovery/recoverer.go`, `recovery/codes.go`, `recovery/*options.go` | same | 1.3, 2.2 |
| `passkey/manager.go`, `passkey/options.go` | same | 1.3, 2.2 |
| `httpsec/options.go`, `httpsec/chain.go`, `httpsec/throttle.go`, `httpsec/mfaenrol.go`, `httpsec/mfaenroloptions.go` | factory option, keyer, removal of `WithRateLimiter`, F2 | 2.x |
| `test/ratelimittest/{doc.go,harness.go,suite.go,shared.go}` | conformance suite | 3.x |
| `test/ratelimittest/{memory_test.go,broken_test.go}` | in-memory run, broken variants | 3.x |
| `redis/{go.mod,doc.go,limiter.go,scripts.go,factory.go,verify.go,options.go,example_test.go,*_test.go}` | Redis module | 5.x |
| `test/testutils.go` (`RunTestRedis`), `test/redis_ratelimit_test.go` | helper, integration and fault tests | 5.1, 5.3–5.7 |
| `go.work`, `layout_guard_test.go`, `.github/workflows/*` | module registration | 5.1 |

Dispatch lanes (`subagent-delegation.md`):

| Lane | Tasks | Model | Why that model |
|---|---|---|---|
| A | 1.1–1.3 | Sonnet | a known pattern |
| B | 2.1–2.6 | Opus | touches several packages and the interface other lanes compile against |
| C | 3.1–3.3 | Sonnet | a conformance suite in an existing pattern |
| D | 4.1–4.4 | Opus | concurrency and refusal logic |
| E | 5.1–5.8 | Opus for 5.2–5.7, Sonnet for 5.1 and 5.8 | |

Lane A runs first. Lanes B, C and D then run in parallel, because their files are disjoint. Lane E runs after C and D. Lanes longer than six tasks (E) are dispatched in two parts: 5.1–5.4, then 5.5–5.8.

---

### Task 1.1–1.3: Factory port and default-limiter logging (F7)

**Files:**
- Create: `ratelimit/factory.go`, `ratelimit/factory_test.go`
- Modify: `mfa/throttle.go:110-125`, `recovery/codes.go:137`, `recovery/recoverer.go:606`, `passkey/manager.go:250`
- Test: `mfa/throttle_test.go`, `recovery/codes_test.go`, `recovery/recoverer_test.go`

**Interfaces:**
- Consumes: `ratelimit.NewMemoryLimiter`, `WithMemoryLimiterLogger`, `WithMemoryLimiterClock`.
- Produces:
  ```go
  type LimiterFactory interface {
      NewLimiter(namespace string, limit int, window time.Duration) (Limiter, error)
  }
  func MemoryLimiterFactory(opts ...MemoryOption) LimiterFactory
  type Verifier interface{ Verify(ctx context.Context) error }
  ```

- [ ] **Step 1 (task 1.1): Write the F7 red test** in `mfa/throttle_test.go`

```go
func TestVerifyThrottle_DefaultLimiterLogsThroughConfiguredLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	th, err := mfa.NewVerifyThrottle(mfa.WithVerifyThrottleLogger(logger))
	require.NoError(t, err)

	_, _ = th.Exceeded(t.Context(), "user-1") // first use writes the per-replica warning

	assert.Contains(t, buf.String(), "counts only this replica",
		"the default limiter's per-replica warning must reach the configured logger")
}
```

Use the throttle's actual constructor and logger option names (`go doc ./mfa VerifyThrottle`).

- [ ] **Step 2: Run it and see it fail**

Run: `go test -run TestVerifyThrottle_DefaultLimiterLogsThroughConfiguredLogger -count=1 ./mfa/`
Expected: FAIL. The message says the warning must reach the configured logger, and the buffer is empty. Record the output in the dispatch report.

- [ ] **Step 3 (task 1.2): Write the factory table test** in `ratelimit/factory_test.go`

```go
func TestMemoryLimiterFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, f ratelimit.LimiterFactory, l ratelimit.Limiter, err error)
	}

	cases := []testCase{
		{
			name: "builds a working limiter", limit: 2, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				exceeded, err := l.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "each call has its own buckets", limit: 1, window: time.Minute,
			assert: func(t *testing.T, f ratelimit.LimiterFactory, l ratelimit.Limiter, err error) {
				require.NoError(t, err)
				require.NoError(t, l.RecordFailure(t.Context(), "k"))
				other, err := f.NewLimiter("ns", 1, time.Minute)
				require.NoError(t, err)
				exceeded, err := other.Exceeded(t.Context(), "k")
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "zero limit refused", limit: 0, window: time.Minute,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
		{
			name: "zero window refused", limit: 1, window: 0,
			assert: func(t *testing.T, _ ratelimit.LimiterFactory, _ ratelimit.Limiter, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := ratelimit.MemoryLimiterFactory(
				ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
			l, err := f.NewLimiter("ns", tc.limit, tc.window)
			tc.assert(t, f, l, err)
		})
	}
}
```

- [ ] **Step 4: Run it and see it fail**

Run: `go test -run TestMemoryLimiterFactory -count=1 ./ratelimit/`
Expected: compile error (undefined `MemoryLimiterFactory`). That is not a red step. Add only an empty factory body that returns `nil, nil`, then rerun.
Expected: FAIL in "builds a working limiter", with a nil limiter.

- [ ] **Step 5: Implement** `ratelimit/factory.go`

```go
// LimiterFactory builds the limiter a flow counts its failures through.
//
// Each built-in flow asks for its own namespace, limit and window, so a
// consumer who replaces the storage keeps every flow's own policy. Default:
// MemoryLimiterFactory, which gives each call a limiter of its own in this
// process.
type LimiterFactory interface {
	NewLimiter(namespace string, limit int, window time.Duration) (Limiter, error)
}

// Verifier is implemented by factories and limiters whose backend can be
// checked before traffic. Constructors never perform I/O; a consumer calls
// Verify at startup.
type Verifier interface {
	Verify(ctx context.Context) error
}

// MemoryLimiterFactory returns a factory of in-memory limiters. Every call
// builds a new MemoryLimiter with separate buckets; the namespace is not
// needed to keep them apart and is ignored. opts apply to every limiter built.
func MemoryLimiterFactory(opts ...MemoryOption) LimiterFactory {
	return memoryFactory{opts: slices.Clone(opts)}
}

type memoryFactory struct{ opts []MemoryOption }

func (f memoryFactory) NewLimiter(_ string, limit int, window time.Duration) (Limiter, error) {
	return NewMemoryLimiter(limit, window, f.opts...)
}
```

- [ ] **Step 6: Run the tests and see them pass**

Run: `go test -race ./ratelimit/...`
Expected: PASS.

- [ ] **Step 7 (task 1.3): Route the default limiters through the factory.**
  - `mfa/throttle.go`:

    ```go
    l, err := ratelimit.MemoryLimiterFactory(
        ratelimit.WithMemoryLimiterLogger(t.logger),
    ).NewLimiter(namespaceVerify, defaultVerifyLimit, defaultVerifyWindow)
    ```

    `resolveLimiter` must run after `t.logger` is validated, so move it below the nil-logger check. Add `const namespaceVerify = "mfa-verify"`.
  - `recovery/codes.go:137`: pass the logger and clock with `WithMemoryLimiterClock(c.clock)`.
  - `recovery/recoverer.go:606` and `passkey/manager.go:250`: pass the logger and clock in the same way.
  - Add the same logger test, in table form, to `recovery` for both `Codes` and `Recoverer`.
  - Change the `recovery.Codes` godoc sentence "The default limiter keeps its own clock" to say that it uses the component's clock.

- [ ] **Step 8: Run**

Run: `go test -race ./mfa/... ./recovery/... ./passkey/... ./ratelimit/...`
Expected: PASS, including Step 1's test.

- [ ] **Step 9: Commit**

```bash
git add ratelimit/factory.go ratelimit/factory_test.go mfa recovery passkey
git commit -m "feat(ratelimit): add LimiterFactory and route default limiters through the component logger"
```

---

### Task 2.1–2.6: Factory seam through every flow, and the chain fixes (F1, F2)

**Files:**
- Modify:
  - `httpsec/options.go` (remove `WithRateLimiter`, `config.limiter`, `resolveLimiter`, `defaultFailureLimit` and `defaultFailureWindow` if they become unused; add `WithRateLimiterFactory` and `config.limiterFactory`);
  - `httpsec/chain.go:40,56` (drop `limiter`; keep `ipv6Prefix` only if read);
  - `httpsec/throttle.go:64-87` (`resolveSourceGuard` takes the factory and keyer);
  - `httpsec/throttle.go` (the throttled-source record, F2);
  - `httpsec/mfaenrol.go:408`;
  - every call site that builds `mfa`, `recovery` or `passkey` components inside the chain;
  - `mfa`, `recovery` and `passkey` options files;
  - every test and example in the workspace using `WithRateLimiter`. Find them with gopls references.
- Test: `httpsec/chain_ratelimit_test.go` (new), plus the component option tests.

**Interfaces:**
- Consumes: `ratelimit.LimiterFactory` and `ratelimit.MemoryLimiterFactory` (Task 1).
- Produces:
  ```go
  // httpsec
  func WithRateLimiterFactory(f ratelimit.LimiterFactory) Option
  // mfa
  func WithVerifyLimiterFactory(f ratelimit.LimiterFactory) VerifyThrottleOption
  // recovery
  func WithUserLimiterFactory(f ratelimit.LimiterFactory) Option       // Recoverer
  func WithCodeLimiterFactory(f ratelimit.LimiterFactory) CodesOption  // Codes
  // passkey
  func WithConfirmLimiterFactory(f ratelimit.LimiterFactory) Option
  ```
  Each option type above is the package's existing one. Check it with `go doc` and keep the existing name pattern.

- [ ] **Step 1 (task 2.1): Write the F1 and F2 red tests** in `httpsec/chain_ratelimit_test.go`

```go
func TestChain_SourceRateLimitSettings(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		first  string // client address that is throttled first
		second string // client address of the follow-up attempt
		assert func(t *testing.T, refused bool, logs *recordingHandler)
	}

	cases := []testCase{
		{
			name:   "chain prefix groups a wider allocation",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48)},
			first:  "2001:db8:1:1::1",
			second: "2001:db8:1:2::1",
			assert: func(t *testing.T, refused bool, _ *recordingHandler) {
				assert.True(t, refused, "a /64 inside the throttled /48 is the same source")
			},
		},
		{
			name:   "default prefix keeps /64s apart",
			first:  "2001:db8:1:1::1",
			second: "2001:db8:1:2::1",
			assert: func(t *testing.T, refused bool, _ *recordingHandler) {
				assert.False(t, refused)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logs := &recordingHandler{}
			h := newAPIKeyChain(t, slog.New(logs), tc.opts...)  // 1 failure per minute
			exhaustAPIKey(t, h, tc.first)
			tc.assert(t, attemptAPIKey(t, h, tc.second) == http.StatusUnauthorized && logs.throttled() > 0, logs)
		})
	}
}

func TestChain_ThrottleRecordSampledPerCanonicalSource(t *testing.T) {
	t.Parallel()

	logs := &recordingHandler{}
	h := newAPIKeyChain(t, slog.New(logs))
	exhaustAPIKey(t, h, "2001:db8:1:1::1")
	for i := range 50 {
		attemptAPIKey(t, h, fmt.Sprintf("2001:db8:1:1::%x", i+2))
	}

	assert.Equal(t, 1, logs.throttled(), "one record per flow and canonical source per window")
}
```

Write `newAPIKeyChain`, `exhaustAPIKey`, `attemptAPIKey` and `recordingHandler` in the same file. Reuse existing helpers in `httpsec`'s tests where they exist (search with gopls `workspace_symbol`). The API-key flow gets an explicit in-memory limiter of 1 per minute through `WithAPIKeyLimiter`, so one wrong key throttles the source. For the factory case, write `TestChain_RateLimiterFactoryReachesFlows` with a recording factory:

```go
type recordingFactory struct {
	mu    sync.Mutex
	asked map[string][2]any // namespace -> {limit, window}
	inner ratelimit.LimiterFactory
}

func (f *recordingFactory) NewLimiter(ns string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	f.mu.Lock()
	f.asked[ns] = [2]any{limit, window}
	f.mu.Unlock()
	return f.inner.NewLimiter(ns, limit, window)
}
```

It asserts that `asked` holds every namespace of the enabled flows with their documented defaults (`api-key`: 20, `time.Minute`; `magic-link-redeem`: 10, `15*time.Minute`; …), and that with `WithAPIKeyLimiter(l)` set, `api-key` is absent.

- [ ] **Step 2: Run and see them fail**

Run: `go test -run 'TestChain_' -count=1 ./httpsec/`
Expected:
- the prefix case fails, "a /64 inside the throttled /48 is the same source";
- the sampling test fails, `expected: 1 actual: 50` (or 51 with the guard's duplicate);
- the factory test does not compile until `WithRateLimiterFactory` exists. Add the option as a no-op stub storing the factory, rerun, and see it fail on the empty `asked`.

Record all three outputs.

- [ ] **Step 3 (task 2.2): Component factory options.** For each of `mfa`, `recovery` (two components) and `passkey`:
  - add the option, storing the factory and refusing nil or typed nil with `nilcheck.IsNil`;
  - resolve with the precedence: explicit limiter, then factory, then memory factory;
  - wrap a factory error as `fmt.Errorf("%s: limiter for namespace %q: %w", pkg, ns, err)`.

  Table test per component, with cases:
  - "default builds in-memory";
  - "factory asked with namespace, limit, window";
  - "explicit limiter wins and factory not asked";
  - "nil factory refused";
  - "factory error fails construction".

  Run `go test -race ./mfa/... ./recovery/... ./passkey/...` and see each new case fail before implementing it, then pass.

- [ ] **Step 4 (task 2.3): The chain factory.**
  - `WithRateLimiterFactory(f)` uses `requireDep("WithRateLimiterFactory", "factory", f)` for the nil and typed-nil refusal.
  - `config.limiterFactory` defaults to `ratelimit.MemoryLimiterFactory(ratelimit.WithMemoryLimiterLogger(c.logger))`, resolved after options are applied.
  - `resolveSourceGuard(option, flow string, limiter ratelimit.Limiter, limit int, window time.Duration)` becomes:

```go
if limiter == nil {
	built, err := c.limiterFactory.NewLimiter(flow, limit, window)
	if err != nil {
		return nil, newConfigError("%s could not build its limiter: %s", option, err)
	}
	limiter = built
}
guard, err := ratelimit.NewSourceGuard(flow, limiter,
	ratelimit.WithSourceGuardLogger(c.logger),
	ratelimit.WithSourceGuardKeyer(c.keyer))
```

  - `httpsec/mfaenrol.go:408` uses `c.limiterFactory.NewLimiter("mfa-enrol-begin"|"mfa-enrol-confirm", …)`.
  - Every `mfa`, `recovery` and `passkey` component the chain constructs receives the factory option unless the consumer passed that component's explicit limiter.
  - Delete `WithRateLimiter`, `config.limiter`, `Chain.limiter` and `resolveLimiter`.
  - Fix every caller found by gopls references, including `ginsec`, `fibersec` and the `test` module.
  - Add the "Absent factory" case to the chain construction-error table.

- [ ] **Step 5 (task 2.4): The keyer.** In `config.build`, after options:

```go
keyer, err := ratelimit.NewSourceKeyer(ratelimit.WithIPv6SourcePrefix(c.ipv6Prefix))
if err != nil {
	return nil, newConfigError("WithIPv6SourcePrefix: %s", err)
}
c.keyer = keyer
```

  Remove `Chain.ipv6Prefix` if nothing else reads it.

- [ ] **Step 6 (task 2.5): F2.** Remove the chain's own throttled-source record keyed on `flow|clientAddr`. The guard's record, keyed on flow and canonical source, stays. Keep the limiter-failure and unattributable-address records unchanged. Confirm the existing "Flood from one source" and "Sources do not suppress each other" tests still pass.

- [ ] **Step 7: Run**

Run: `go test -race ./httpsec/... ./ratelimit/... ./mfa/... ./recovery/... ./passkey/...`, then `go test -race ./...` in `ginsec`, `fibersec` and `test`.
Expected: PASS, with Step 1's tests green.

- [ ] **Step 8 (task 2.6): Godoc.**
  - `WithRateLimiterFactory`: the default (in-memory, per flow, its own limits), the precedence, the namespaces, and that the flows' own limiter options still win.
  - `WithIPv6SourcePrefix`: now true as written; also state that it applies to every source guard the chain builds.
  - Each component option names its default.
  - Run `go doc ./httpsec WithRateLimiterFactory` and `go vet ./...`.

- [ ] **Step 9: Commit**

```bash
git commit -m "fix(httpsec): make chain rate-limit settings reach every flow and sample throttles per source

WithRateLimiter is replaced by WithRateLimiterFactory; WithIPv6SourcePrefix now
keys every chain-built guard; one throttle record per canonical source."
```

---

### Task 3.1–3.3: Conformance suite

**Files:**
- Create: `test/ratelimittest/doc.go`, `harness.go`, `suite.go`, `shared.go`, `memory_test.go`, `broken_test.go`

**Interfaces:**
- Consumes: `ratelimit.Limiter`, `ratelimit.NewMemoryLimiter`, `clockwork.FakeClock`, `test/internal/storefix.{BrokenVariant,RunBrokenChild,CatchBrokenVariants}`.
- Produces:
  ```go
  type Harness struct {
      // New builds a limiter over a fresh, isolated backend scope.
      New func(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter
      // Advance moves the clock every limiter from New reads.
      Advance func(d time.Duration)
      // SecondInstance, when set, builds another instance over the same backend
      // scope as the last New for that namespace, standing in for another replica.
      SecondInstance func(t *testing.T, namespace string, limit int, window time.Duration) ratelimit.Limiter
  }
  func Run(t *testing.T, h Harness)
  ```

- [ ] **Step 1 (task 3.1): Write the suite** (`suite.go`) as one table over the limiter. Each case's `assert` receives `(t, h, l)`:

```go
func Run(t *testing.T, h Harness) {
	t.Helper()

	type testCase struct {
		name   string
		limit  int
		window time.Duration
		assert func(t *testing.T, h Harness, l ratelimit.Limiter)
	}

	cases := []testCase{
		{name: "no failures is not exceeded", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) { requireExceeded(t, l, "k", false) }},
		{name: "limit minus one is not exceeded", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				record(t, l, "k", 2)
				requireExceeded(t, l, "k", false)
			}},
		{name: "limit is exceeded", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				record(t, l, "k", 3)
				requireExceeded(t, l, "k", true)
			}},
		{name: "other keys do not count", limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				record(t, l, "a", 1)
				requireExceeded(t, l, "b", false)
			}},
		{name: "one microsecond inside the window counts", limit: 1, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				record(t, l, "k", 1)
				h.Advance(time.Minute - time.Microsecond)
				requireExceeded(t, l, "k", true)
			}},
		{name: "exactly one window old does not count", limit: 1, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				record(t, l, "k", 1)
				h.Advance(time.Minute)
				requireExceeded(t, l, "k", false)
			}},
		{name: "failures straddling a boundary count together", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				h.Advance(50 * time.Second)
				record(t, l, "k", 1)
				h.Advance(20 * time.Second)
				record(t, l, "k", 1)
				h.Advance(10 * time.Second)
				requireExceeded(t, l, "k", true)
			}},
		{name: "excess failures keep the newest stamps", limit: 2, window: time.Minute,
			assert: func(t *testing.T, h Harness, l ratelimit.Limiter) {
				record(t, l, "k", 1)
				h.Advance(40 * time.Second)
				record(t, l, "k", 2) // three recorded, cap 2: the oldest is dropped
				h.Advance(30 * time.Second)
				requireExceeded(t, l, "k", true) // both kept stamps are 30s old
			}},
		{name: "ended context: Exceeded returns true and an error", limit: 3, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				exceeded, err := l.Exceeded(ctx, "k")
				require.Error(t, err)
				assert.True(t, exceeded)
			}},
		{name: "ended context: RecordFailure still records", limit: 1, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_ = l.RecordFailure(context.WithoutCancel(ctx), "k")
				requireExceeded(t, l, "k", true)
			}},
		{name: "concurrent use ends exceeded without a race", limit: 5, window: time.Minute,
			assert: func(t *testing.T, _ Harness, l ratelimit.Limiter) {
				var wg sync.WaitGroup
				for i := range 64 {
					wg.Go(func() {
						key := fmt.Sprintf("k%d", i%4)
						_, _ = l.Exceeded(t.Context(), key)
						_ = l.RecordFailure(t.Context(), key)
					})
				}
				wg.Wait()
				for i := range 4 {
					requireExceeded(t, l, fmt.Sprintf("k%d", i), true)
				}
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := h.New(t, "conformance", tc.limit, tc.window)
			tc.assert(t, h, l)
		})
	}

	runShared(t, h) // shared.go; skips when h.SecondInstance is nil
}
```

  Cases run sequentially, because `Advance` moves a clock shared by the harness. `record(t, l, key, n)` and `requireExceeded(t, l, key, want)` are unexported helpers in `suite.go`.

- [ ] **Step 2: The memory run** (`memory_test.go`):

```go
func TestRateLimitConformance_Memory(t *testing.T) {
	t.Parallel()
	clk := clockwork.NewFakeClock()
	ratelimittest.Run(t, ratelimittest.Harness{
		New: func(t *testing.T, _ string, limit int, window time.Duration) ratelimit.Limiter {
			l, err := ratelimit.NewMemoryLimiter(limit, window,
				ratelimit.WithMemoryLimiterClock(clk),
				ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
			require.NoError(t, err)
			return l
		},
		Advance: clk.Advance,
	})
}
```

  Run: `go test -race -run TestRateLimitConformance_Memory -count=1 ./ratelimittest/` (in `test`).
  Expected: PASS. The suite encodes today's behaviour.
  **Red check:** temporarily change `requireExceeded`'s comparison to the inverse, see the run fail, and restore it. Report both outputs.

- [ ] **Step 3 (task 3.2): Broken variants** (`broken_test.go`) using `storefix.BrokenVariant`, `RunBrokenChild` and `CatchBrokenVariants`:

| Variant | Limiter | `FailsCase` |
|---|---|---|
| `fixed-window` | counts in buckets `now.Truncate(window)` | `failures straddling a boundary count together` |
| `ttl-reset-on-check` | `Exceeded` extends the key to `now + window` (stamps re-written as now) | `exactly one window old does not count` |
| `fail-open` | `Exceeded` returns `false, ctx.Err()` | `ended context: Exceeded returns true and an error` |
| `prune-by-oldest` | drops a key when its oldest stamp expires | `excess failures keep the newest stamps` |

  Write each broken limiter as a small type in `broken_test.go`.

  Run: `go test -race -run 'TestRateLimitConformance_Broken|TestRateLimitSuiteCatchesBrokenLimiters' -count=1 ./ratelimittest/`
  Expected: PASS. Every variant fails in its child at its named case.

- [ ] **Step 4 (task 3.3): Shared scenarios** (`shared.go`), skipped when `h.SecondInstance == nil`:
  - "two replicas, one limit": limit 3; two failures through the first instance and one through the second exceed through both;
  - "shorter-window instance": a 15-minute instance records; a 1-minute instance on the same namespace records 30s later; advance 10 minutes; the 15-minute instance still counts 2;
  - "separate namespaces": an exhausted `api-key` namespace does not exceed `magic-link-redeem`.

  Add a `per-instance-state` broken shared double (two memory limiters, no sharing) that must fail "two replicas, one limit".

  Run the same command as Step 3.
  Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git commit -m "test(ratelimittest): add rate-limiter conformance suite, seen to fail against broken limiters"
```

---

### Task 4.1–4.4: Unavailable modes and the breaker

**Files:**
- Create: `ratelimit/unavailable.go` (public mode type), `internal/unavailable/wrap.go`, `breaker.go`, `hold.go`, `wrap_test.go`, and a `//go:generate mockgen ... -typed github.com/kartaladev/scrty/ratelimit Limiter` producing `limiter_mock_test.go` (per `use-mockgen`)

**Interfaces:**
- Consumes: `ratelimit.Limiter`, `NewMemoryLimiter`, `pkg/clock.Clock`.
- Produces:
  ```go
  // public, core ratelimit
  type UnavailableMode int
  const (
      UnavailableRefuse UnavailableMode = iota // default
      UnavailableFallBackToLocal
      UnavailableAllow
  )
  var ErrBackendUnavailable = errors.New("ratelimit: backend unavailable")

  // internal/unavailable (used by backend modules only; consumers configure it
  // through each backend's own options, design decision 5)
  type Config struct {
      Mode          ratelimit.UnavailableMode // default UnavailableRefuse
      Timeout       time.Duration             // default 250ms
      ProbeInterval time.Duration             // default 1s
      Clock         clock.Clock               // default clock.System()
      Logger        *slog.Logger              // default slog.Default()
  }
  func DefaultConfig() Config
  func Wrap(backend ratelimit.Limiter, namespace string, limit int, window time.Duration, cfg Config) (ratelimit.Limiter, error)
  ```

- [ ] **Step 1 (task 4.1): Write the construction and pass-through table test** (`TestWrap_Construction`). Cases:
  - unknown mode `UnavailableMode(9)` gives `ErrConfig`;
  - a zero timeout gives `ErrConfig`;
  - a negative probe interval gives `ErrConfig`;
  - a nil backend, including typed nil, gives `ErrConfig`;
  - an empty namespace gives `ErrConfig`;
  - defaults are accepted.

  Then `TestWrap_PassThrough` with the typed mock:
  - backend `Exceeded` returning `(true, nil)` passes through;
  - `RecordFailure` returning nil passes through;
  - an ended caller context returns `(true, err)` without calling the backend (`EXPECT().Exceeded(...).Times(0)`), in all three modes.

  Run: `go test -run 'TestWrap' -count=1 ./internal/unavailable/`
  Expected: compile error, so add `Wrap` returning `backend, nil` and rerun.
  Expected: FAIL on every refusal case.

- [ ] **Step 2: Implement construction and the timeout.** Each backend call runs under `context.WithTimeout(ctx, cfg.timeout)`. For `RecordFailure`, the parent is `context.WithoutCancel(ctx)`, so the timeout is the only bound. Unavailable is any error while `ctx.Err() == nil`. A caller-ended context is never unavailable.

- [ ] **Step 3 (task 4.2): Breaker tests** (`TestWrap_Breaker`), with the fake clock and a mock backend:
  - "opens on error": the first `Exceeded` gets a backend error and returns `(true, err)`; a second within 1s returns `(true, ErrBackendUnavailable)` with the backend not called.
  - "probes after the interval": advance 1s; exactly one backend call; on success the breaker closes.
  - "failed probe reopens".
  - "one probe under concurrency": inside `synctest.Test`, 50 goroutines call `Exceeded` after the interval, and the backend mock expects `Times(1)`.
  - "probe that times out reopens": the backend blocks until ctx is done; the call returns within the timeout, and the next call is short-circuited.

  Every short-circuited refusal wraps `ratelimit.ErrBackendUnavailable`.
  Expected: FAIL before `breaker.go` exists.

- [ ] **Step 4: Implement** `breaker.go`:

```go
type breaker struct {
	mu       sync.Mutex
	clock    clock.Clock
	interval time.Duration
	openedAt time.Time
	open     bool
	probing  bool
}

// allow reports whether a call may reach the backend now, and whether it is the probe.
func (b *breaker) allow() (pass, probe bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true, false
	}
	if b.probing || b.clock.Now().Sub(b.openedAt) < b.interval {
		return false, false
	}
	b.probing = true
	return true, true
}

func (b *breaker) success() { b.mu.Lock(); b.open, b.probing = false, false; b.mu.Unlock() }

func (b *breaker) failure() {
	b.mu.Lock()
	b.open, b.probing, b.openedAt = true, false, b.clock.Now()
	b.mu.Unlock()
}
```

  Return whether a transition happened from `success` and `failure`, so the log in 4.4 is written once per transition.

- [ ] **Step 5 (task 4.3): Record-error tests** (`TestWrap_RecordErrors`), against a mock whose `RecordFailure` errors and `Exceeded` returns `(false, nil)`:
  - refuse mode: after one failed record for `k`, and with the breaker closed again (advance 1s, probe succeeds), `Exceeded(k)` is still `(true, err)` until one window passes; `Exceeded(other)` is `(false, nil)`.
  - fall-back mode with limit 2: two failed records for `k` lead to `Exceeded(k)` true, from the local count.
  - allow mode: a failed record is dropped, and `Exceeded(k)` follows the backend.
  - the hold set is pruned: after one window the held key is gone (an unexported `heldLen()` through `export_test.go`).

  Expected: FAIL before `hold.go`.

- [ ] **Step 6: Implement** `hold.go` as a `map[string]time.Time` (key to release time) under a mutex, swept at most once per window, the same way `MemoryLimiter.sweepLocked` paces its sweep. The fall-back local limiter is a `MemoryLimiter` built in `Wrap` with the same limit, window and clock, whose per-replica warning is suppressed by a discard logger. The transition logs (4.4) carry the meaning instead.

- [ ] **Step 7 (task 4.4): Mode and log tests**, with a recording `slog` handler:
  - fall-back: backend down, then three local failures with limit 3 give exceeded; one ERROR `"ratelimit: backend unavailable, counting locally"` with the namespace; on recovery one WARN `"ratelimit: backend available again"`.
  - allow: backend down gives `Exceeded` `(false, nil)` and one ERROR per namespace per sampling window (use `pkg/logsample`).
  - "consumer chose to allow": a `SourceGuard` over the wrapped limiter admits the attempt.
  - end with `goleak.VerifyNone(t)`.

- [ ] **Step 8: Run**

Run: `go test -race ./ratelimit/... ./internal/unavailable/...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git commit -m "feat(ratelimit): fail closed and fast on backend outages, with explicit fall-back and allow modes"
```

---

### Task 5.1–5.8: Redis and Valkey module

**Files:**
- Create:
  - `redis/go.mod` (`module github.com/kartaladev/scrty/redis`, `go 1.27`, `require github.com/redis/go-redis/v9 v9.22.0` or the newest at dispatch time, never below v9.7.3);
  - `redis/doc.go`, `redis/options.go`, `redis/scripts.go`, `redis/limiter.go`, `redis/factory.go`, `redis/verify.go`;
  - `redis/limiter_test.go`, `redis/example_test.go`;
  - `test/redis_ratelimit_test.go`.
- Modify: `go.work` (add `./redis`), `layout_guard_test.go` (allow go-redis only in `redis` and `test`), the CI workflow matrix, and `test/testutils.go` and `test/go.mod` (testcontainers Redis module v0.44.0, and a `replace`/workspace entry for `redis`).

**Interfaces:**
- Consumes:
  - `ratelimit.Limiter`, `LimiterFactory`, `Verifier`, `UnavailableMode`, `ErrConfig`, and `internal/unavailable.Wrap`/`Config`;
  - `pkg/clock.Clock`;
  - `ratelimittest.Harness`/`Run`.
- Produces:
  ```go
  package scrtyredis
  const DefaultKeyPrefix = "scrty:ratelimit:"
  type Option func(*config)
  func WithKeyPrefix(p string) Option
  func WithLimiterClock(clk clock.Clock) Option
  func WithEvictionPolicyCheck(enabled bool) Option // default true
  func WithOnUnavailable(m ratelimit.UnavailableMode) Option       // default UnavailableRefuse
  func WithOperationTimeout(d time.Duration) Option                // default 250ms
  func WithUnavailableProbeInterval(d time.Duration) Option         // default 1s
  func WithLogger(l *slog.Logger) Option
  func NewLimiter(client redis.UniversalClient, namespace string, limit int, window time.Duration, opts ...Option) (*Limiter, error)
  func (l *Limiter) Exceeded(ctx context.Context, key string) (bool, error)
  func (l *Limiter) RecordFailure(ctx context.Context, key string) error
  func (l *Limiter) Verify(ctx context.Context) error
  func NewLimiterFactory(client redis.UniversalClient, opts ...Option) (*Factory, error)
  func (f *Factory) NewLimiter(namespace string, limit int, window time.Duration) (ratelimit.Limiter, error)
  func (f *Factory) Verify(ctx context.Context) error
  // test module
  func RunTestRedis(t *testing.T, opts ...TestOption) *redis.Client
  func WithTestRedisImage(ref string) TestOption
  func WithTestRedisOwnContainer() TestOption
  ```

- [ ] **Step 1 (task 5.1): Scaffold.** Create the module with `doc.go` only. Add it to `go.work`, the layout guard and CI. Write `RunTestRedis` per `use-testcontainers`:
  - default image `redis:8`;
  - each call gets a fresh logical database (`SELECT n`) on a per-process shared container, unless `WithTestRedisOwnContainer()` is set;
  - `t.Cleanup` flushes the database.

  Smoke test `TestRunTestRedis_Ping`.
  Run: `go build ./...` in each module; `go test -run TestLayout -count=1 .` at the root; `go test -run TestRunTestRedis -count=1 .` in `test`.
  Expected: PASS. The layout guard is seen to fail first, before the allowance is added.

- [ ] **Step 2 (task 5.2): Construction and key-mapping table tests** in `redis/limiter_test.go` (no server). Cases:
  - nil client;
  - typed-nil `*redis.Client` in a `UniversalClient`;
  - empty namespace;
  - limit 0;
  - window 0;
  - empty prefix;
  - nil clock;
  - defaults accepted.

  All refusals `errors.Is(err, ratelimit.ErrConfig)`. Plus `TestStorageKey`:
  - 512-byte key stored raw under `scrty:ratelimit:ns:` + key;
  - 513-byte key stored as `scrty:ratelimit:ns:sha256:<64 hex>`;
  - two distinct 600-byte keys give distinct storage keys.

  Expected: FAIL first. Then implement `options.go`, the constructor and `storageKey`:

```go
func storageKey(prefix, namespace, key string) string {
	if len(key) > maxRawKeyLen { // 512
		sum := sha256.Sum256([]byte(key))
		key = "sha256:" + hex.EncodeToString(sum[:])
	}
	return prefix + namespace + ":" + key
}
```

- [ ] **Step 3: The scripts** (`scripts.go`). Times are microseconds. `ARGV[1]` is the app-clock "now" in microseconds, or empty to use the server clock.

```go
var recordScript = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
local window_us = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = tostring(now) .. ':' .. ARGV[4]
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window_us)
redis.call('ZADD', KEYS[1], now, member)
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -(limit + 1))
local ttl_ms = math.ceil(window_us / 1000)
local current = redis.call('PTTL', KEYS[1])
if current < ttl_ms then
  redis.call('PEXPIRE', KEYS[1], ttl_ms)
end
return 1
`)

var exceededScript = redis.NewScript(`
local now
if ARGV[1] == '' then
  local t = redis.call('TIME')
  now = tonumber(t[1]) * 1000000 + tonumber(t[2])
else
  now = tonumber(ARGV[1])
end
return redis.call('ZCOUNT', KEYS[1], '(' .. (now - tonumber(ARGV[2])), '+inf')
`)
```

  `PTTL` returns -1 for a key with no TTL, which is less than `ttl_ms`, so the no-TTL path sets one. This is decision 3's fix for `GT`. `ARGV[4]` is 8 random bytes in hex from `crypto/rand`.
  - `ZREMRANGEBYSCORE … now - window_us` is inclusive, so stamps at or before the cutoff are dropped.
  - `ZCOUNT` with `(` is exclusive, so only stamps strictly after the cutoff count.

- [ ] **Step 4: The limiter** (`limiter.go`). The backend type `backend` implements `ratelimit.Limiter`:
  - `Exceeded` is `exceededScript.RunRO(ctx, client, []string{k}, nowArg, windowUS).Int()`, then `count >= limit`;
  - `RecordFailure` is `recordScript.Run(...)`.

  `NewLimiter` wraps the backend with `unavailable.Wrap(backend, namespace, limit, window, cfg.unavailable)`, where `cfg.unavailable` starts from `unavailable.DefaultConfig()` and is set by `WithOnUnavailable`, `WithOperationTimeout`, `WithUnavailableProbeInterval`, `WithLimiterClock` and `WithLogger`. Construction cases for an unknown mode and non-positive durations are added to Step 2's table. It keeps the backend for `Verify`.
  Run: `go test -race ./...` in `redis`.
  Expected: PASS.

- [ ] **Step 5 (task 5.3): Conformance runs** in `test/redis_ratelimit_test.go`, as a table over images `redis:7.4`, `redis:8` and `valkey/valkey:8`:

```go
func TestRateLimitConformance_Redis(t *testing.T) {
	for _, image := range []string{"redis:7.4", "redis:8", "valkey/valkey:8"} {
		t.Run(image, func(t *testing.T) {
			client := RunTestRedis(t, WithTestRedisImage(image))
			clk := clockwork.NewFakeClockAt(time.Unix(1_700_000_000, 0))
			build := func(t *testing.T, ns string, limit int, window time.Duration) ratelimit.Limiter {
				l, err := scrtyredis.NewLimiter(client, ns, limit, window,
					scrtyredis.WithLimiterClock(clk),
					scrtyredis.WithLogger(slog.New(slog.DiscardHandler)))
				require.NoError(t, err)
				return l
			}
			ratelimittest.Run(t, ratelimittest.Harness{New: build, Advance: clk.Advance, SecondInstance: build})
		})
	}
}
```

  Each `New` must start from an empty namespace. Use `t.Name()`-derived namespaces inside the suite, or flush in `New`. Pick one and state it in the harness godoc.
  Run: `go test -race -run TestRateLimitConformance_Redis -count=1 .` in `test`.
  Expected: PASS for all three images.

- [ ] **Step 6 (task 5.4): Server-clock and TTL tests** (`TestRedisLimiter_ServerClockAndTTL`, a table):
  - "server clock window": limit 1, window 2s, no app clock; record; exceeded; after a real 2.1s wait, not exceeded.
  - "skewed replica": in server-clock mode the host clock is never read. A unit test in `redis` builds the limiter without `WithLimiterClock` and asserts the scripts receive an empty `ARGV[1]`. A server test runs two server-clock instances: one records, the other sees it exceeded, and both see it expire after the real window.
  - "no-TTL key gains a TTL": `ZADD` a stamp directly with no TTL, `RecordFailure`, and `PTTL > 0`. **Red:** first run it against a variant script using `PEXPIRE … GT` (kept as `recordScriptGTOnly` in the test file) and see `PTTL == -1`.
  - "Exceeded leaves TTL unchanged": the `PTTL` before and after are equal within 5ms.

- [ ] **Step 7 (task 5.5): Factory** (`factory.go`):

```go
type Factory struct {
	client redis.UniversalClient
	opts   []Option
	mu     sync.Mutex
	built  map[string]policy
}
type policy struct{ limit int; window time.Duration }

func (f *Factory) NewLimiter(ns string, limit int, window time.Duration) (ratelimit.Limiter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.built[ns]; ok && (p.limit != limit || p.window != window) {
		return nil, fmt.Errorf("%w: namespace %q already built with %d per %s, asked for %d per %s",
			ratelimit.ErrConfig, ns, p.limit, p.window, limit, window)
	}
	l, err := NewLimiter(f.client, ns, limit, window, f.opts...)
	if err != nil {
		return nil, err
	}
	f.built[ns] = policy{limit, window}
	return l, nil
}
```

  Table test, written first, with cases:
  - same namespace and policy, where both limiters see each other's failures (server test);
  - conflicting policy gives `ErrConfig`;
  - nil client refused;
  - typed nil refused.

- [ ] **Step 8 (task 5.6): `Verify`** (`verify.go`). Server table test `TestRedisVerify`, written first:
  - `redis:6.2` image gives an `ErrConfig` naming 7.0;
  - `redis:8` with `--maxmemory-policy allkeys-lru` gives an `ErrConfig` naming `maxmemory-policy`;
  - `--maxmemory-policy noeviction` gives nil;
  - `CONFIG` renamed away (`--rename-command CONFIG ""`) gives nil and one WARN;
  - the same with `WithEvictionPolicyCheck(false)` gives nil and no WARN;
  - a cluster client with `ReadOnly: true` gives `ErrConfig` at construction.

  Implementation:
  - parse `INFO server` for `redis_version`, or `valkey_version` when present;
  - read `CONFIG GET maxmemory-policy`;
  - run `ScriptLoad` for both scripts.

- [ ] **Step 9 (task 5.7): Fault tests** (`TestRedisLimiter_Fault`, a table, each case with `WithTestRedisOwnContainer()`):
  - "writes fail, reads succeed" (decision 4 red step): `CONFIG SET maxmemory 1mb`, `noeviction`, fill memory with filler keys until `OOM` errors, then fail one source 10 times through a `SourceGuard` with limit 3, and assert it is refused. **Red:** run it with the wrapper's record-error hold disabled (a test-only option through `export_test.go` in `ratelimit`, or a wrapper built with `UnavailableAllow` for the red run) and record that the source is never refused. If even that run refuses, the claim is false: remove it from design.md (main session) and drop the hold.
  - "refuse while stopped": stop the container; `Exceeded` gives `(true, err)`; the second call returns in under 50ms (breaker).
  - "fall back and recover": `UnavailableFallBackToLocal`; stop; three local failures exceed; start again; after the probe interval reads come from Redis.
  - "allow while stopped": `(false, nil)`.

- [ ] **Step 10 (task 5.8): Godoc and example.** `doc.go` states:
  - primary only (no replica reads);
  - `noeviction` required;
  - the ACL commands;
  - microsecond precision;
  - one configuration per namespace;
  - fall-back recommended for second-factor flows;
  - call `Verify` before traffic.

  `example_test.go`:

```go
func Example_sharedLimiter() {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	factory, err := scrtyredis.NewLimiterFactory(client)
	if err != nil {
		panic(err)
	}
	// At startup, before traffic: factory.Verify(ctx)
	_, err = httpsec.New( /* ... */ httpsec.WithRateLimiterFactory(factory))
	fmt.Println(err == nil)
	// Output: true
}
```

  If `httpsec.New` needs required options, use the minimal set the `httpsec` examples use. Verify that no I/O happens without `Verify`, because the example has no server.
  Run: `go test -run Example -count=1 ./...` in `redis`; `go doc . NewLimiterFactory` in `redis`.

- [ ] **Step 11: Run and commit**

Run: `go test -race ./...` in `redis` and in `test`.

```bash
git commit -m "feat(redis): add Redis/Valkey shared rate limiter passing the conformance suite"
```

---

### Task 6.1–6.2: Integration

- [ ] **Step 1 (task 6.1):** Dispatch a fresh Opus reviewer that did not write the code. It gets:
  - the diff `git diff main...HEAD`;
  - both spec deltas;
  - design decisions 1–14.

  It reports, per requirement and scenario, the test that pins it. Each finding comes with a failing test or the label `UNREPRODUCED`. It edits nothing.
- [ ] **Step 2 (task 6.2):** In each module of `go.work`, run:
  - `go test -race ./...`
  - `go vet ./...`
  - `gofmt -l .`
  - `golangci-lint run`

  Then run `openspec validate shared-rate-limiting --strict`. Record every output. The main session runs these and judges them.

---

## Self-review

- **Spec coverage:** every ADDED and MODIFIED requirement in both deltas maps to a task.

  | Requirement | Task |
  |---|---|
  | factory | 1, 2 |
  | counts across instances | 3.3, 5.3 |
  | namespaces | 3.3, 5.5 |
  | fail closed and fast | 4.1, 4.2, 5.7 |
  | failed record | 4.3, 5.7 |
  | explicit degrade | 4.4, 5.7 |
  | backend clock | 5.4 |
  | expiry and eviction | 5.4, 5.6 |
  | verification | 5.6 |
  | conformance | 3, 5.3 |
  | MODIFIED fail-closed | 4.4 |
  | chain settings | 2.4, 2.3 |
  | MODIFIED wiring errors | 2.3 |
  | MODIFIED sampling | 2.5 |

- **Placeholders:** the helper names in 2.1 (`newAPIKeyChain` and the others) are defined in that task's step. The component option type names are confirmed with `go doc` at dispatch, because they are existing types.
- **Type consistency:**
  - `unavailable.Wrap`/`Config` and `ratelimit.UnavailableMode` in Task 4 are consumed unchanged by Task 5. The redis options map one-to-one onto `Config` fields;
  - `Harness` in Task 3 is consumed unchanged in 5.3;
  - `LimiterFactory` in Task 1 is consumed in 2 and 5.
