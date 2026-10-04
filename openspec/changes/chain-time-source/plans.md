# Chain Time Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code (`.claude/rules/subagent-delegation.md`): every task is carried out by a dispatched subagent, and the main session verifies, reviews and commits.

**Goal:** Give the HTTP security chain one replaceable time source, `httpsec.WithClock(clock.Clock)`, that every built-in interceptor and every time-keeping component the chain builds reads; and record in the spec that a second account recovery is refused.

**Architecture:**
- `config` gains `clock clock.Clock`, defaulting to `clock.System()` in `New`.
- Interceptors take `now: c.now`, a method value reading `c.clock` at call time, so a `WithClock` given after an `Enable...` option still applies.
- The components the chain builds get the chain's clock through their existing options, placed **before** any consumer-supplied options, so a consumer's own clock option wins.

**Tech Stack:** Go 1.27; `pkg/clock`; `internal/nilcheck`; testify; `clockwork` fakes in tests.

**Spec:** `openspec/changes/chain-time-source/`: `proposal.md`, `design.md` (decisions 1–6), `specs/http-security-chain/spec.md`, and `tasks.md`. Task numbers below (1.1, 2.3, …) are `tasks.md`'s.

## Global Constraints

- **Test-first for every task** (`.claude/rules/golang-tdd.md`): write the failing test, run it, confirm it fails **for the intended reason** (stub new identifiers first; a compile error is not a red step), implement, refactor.
- **Tables** follow the `table-test` skill (assert closures, `t.Context()`); **mocks** follow `use-mockgen`.
- **Option type** is `clock.Clock`, never `clock.Timed`: the chain only reads the time.
- **Nil or typed-nil clock** is `ErrConfig` naming `WithClock`, never a fallback to the system clock.
- **No new dependency in the core module.** `clockwork` appears only in tests; the core `go.mod` already requires it for tests.
- **A consumer-built dependency** (session manager, token issuer, a factory given with `WithRateLimiterFactory`, a store given with `WithMFAChallengeStore`, a recovery core with its own `recovery.WithClock`) keeps its own clock; the chain never replaces it.
- **No direct `time.Now`** remains in non-test `httpsec` code except `clock.System()` as the default.
- **Predecessor:** never read into or cite it (`.claude/rules/legacy-reference.md`).
- **Git:** subagents run no git commands; the main session commits after each verified, reviewed dispatch.
- **Every task's verification also includes** `gofmt -l httpsec` empty, `go vet ./httpsec/...` and `golangci-lint run ./httpsec/...`.

## Review Focus

1. **`WithClock` given after the `Enable...` options.** It must still reach every interceptor and every built component. Test: Task 1.2, row "WithClock after EnableMFA still drives MFA".
2. **A clock far behind the system clock.** Nothing may treat live state as expired because some part still reads the system clock (a challenge begun 1 minute ago on a clock a year in the past must still verify). Test: Task 2.1, row "a clock behind the system clock keeps a live challenge".
3. **The consumer's `WithRateLimiterFactory` together with `WithClock`.** The consumer's factory must not be re-clocked; only the chain's default factory follows the chain clock. Test: Task 2.2, row "a consumer's factory keeps its own clock".
4. **`recovery.WithClock` inside `WithRecoveryCore` together with `WithClock`.** The consumer's recovery clock wins. Test: Task 2.3, row "a recovery core with its own clock keeps it".
5. **A chain with only a `WithClock` and no interceptors.** It builds, and the option is not refused as unused, because it governs the chain as a whole. Test: Task 1.1, row "WithClock alone builds".

---

## Execution: lanes, dispatches and models

| Dispatch | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| H1 | 1.1–1.2 | `httpsec/options.go` (config, New, the interceptors' `now`), `httpsec/oidc_options.go`, `httpsec/mfaenroloptions.go`, `httpsec/passkeylogin.go`, `httpsec/recoveryoptions.go`, `httpsec/recoverycooldown.go`, new `httpsec/clock.go` and `httpsec/clock_test.go` | everything outside `httpsec/` | Sonnet | Option plumbing on a stated contract |
| H2 | 2.1–2.3 | `httpsec/mfabegin.go`, `httpsec/throttle.go`, `httpsec/recoverycomplete.go`, `httpsec/clock_test.go` | everything outside `httpsec/` | Opus | Several components and a precedence rule that would pass naive tests and still be wrong |
| H3 | 3.1–3.2 | `httpsec/export_test.go`, `httpsec/*_test.go` | non-test code | Sonnet | Test conversion with mutant checks |

**Order:** H1, then H2, then H3: one package, one lane. Each dispatch is verified, then reviewed: Sonnet reviewers for H1 and H3, an Opus reviewer for H2. 4.1 and 4.2 are the main session's.

---

### Task 1.1: The `WithClock` option

**Files:**
- Create: `httpsec/clock.go` (the option and `config.now`)
- Modify: `httpsec/options.go` (`config` gains `clock clock.Clock`; `New` defaults it to `clock.System()`, ~line 306)
- Test: `httpsec/clock_test.go`

**Interfaces:**
- Produces:

```go
// WithClock sets the time source the chain and the components it builds read.
// Default: clock.System(). Dependencies the consumer builds and hands to the
// chain keep their own clocks.
func WithClock(c clock.Clock) Option

func (c *config) now() time.Time // c.clock.Now()
```

- [ ] **Step 1: Write the failing table `TestWithClock`** (assert closures, `t.Context()`):
  - "nil clock": `httpsec.New(httpsec.WithClock(nil))` → `errors.Is(err, httpsec.ErrConfig)` and the message contains `WithClock`.
  - "typed nil clock": `var fc *clockwork.FakeClock; httpsec.New(httpsec.WithClock(fc))` → the same.
  - "WithClock alone builds" (Review Focus 5): `httpsec.New(httpsec.WithClock(clockwork.NewFakeClock()))` → no error.
  - "System clock by default": build a chain with MFA over a challenge method (reuse the MFA begin test harness in `httpsec/mfabegin_test.go`) and no `WithClock`; begin a challenge; assert the stored challenge's expiry is within a second of `time.Now().Add(<challenge TTL>)`.
- [ ] **Step 2: Run** `go test -race -run 'TestWithClock' -count=1 ./httpsec/` with `WithClock` stubbed as `func WithClock(clock.Clock) Option { return func(*config) error { return nil } }`. Expected: FAIL on the two refusal rows ("An error is expected but got nil").
- [ ] **Step 3: Implement.**

```go
func WithClock(c clock.Clock) Option {
	return func(cfg *config) error {
		if nilcheck.IsNil(c) {
			return newConfigError("WithClock was given no clock; omit the option to use the system clock")
		}
		cfg.clock = c

		return nil
	}
}

func (c *config) now() time.Time { return c.clock.Now() }
```

  In `New`, set `clock: clock.System()` in the `config` literal.
- [ ] **Step 4: Run** Step 2's command → PASS.

### Task 1.2: Every interceptor reads the chain's clock

**Files:**
- Modify: every `now: time.Now` in non-test `httpsec`: `options.go:953` (form login), `:1174` (Basic), `:1318` (bearer), `:1515` (MFA), `:1716` (API keys), `:1832` (magic link); `oidc_options.go:97`; `mfaenroloptions.go:206`; `passkeylogin.go:300`; `recoveryoptions.go:238`; `recoverycooldown.go:74`
- Test: `httpsec/clock_test.go`

**Interfaces:**
- Consumes: `config.now` (Task 1.1).

- [ ] **Step 1: Write the failing table `TestChain_Clock`**, one row per interceptor. Each row builds a chain with `WithClock(fc)`, where `fc := clockwork.NewFakeClockAt(time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))`, far from the system clock. It then drives a path whose outcome depends on the time:
  - **form login:** a refusal log sampled with the controlled time. Assert the sampled record's time attribute, or the guard's window, reads 2040.
  - **bearer:** a session validated against the controlled time. Use a session manager on the same `fc`, so only the chain's reading differs from before.
  - **MFA begin:** the sweep throttle's due time uses 2040.
  - **API key, magic link, OIDC login (flow cookie MaxAge computed from a 2040 expiry), enrolment (email-code window), passwordless, recovery regeneration freshness, recovery cool-down:** one row each.

  Where an existing test already drives that path, reuse its harness. Add a row "WithClock after EnableMFA still drives MFA" (Review Focus 1), giving `WithClock` last.
- [ ] **Step 2: Run** `go test -race -run 'TestChain_Clock' -count=1 ./httpsec/`. Expected: FAIL on every row, because the interceptors still read `time.Now`, so the observed times are around the present day rather than 2040.
- [ ] **Step 3: Implement.** Replace each `now: time.Now` with `now: c.now`. The method value captures `c` and reads `c.clock` when called, so the order of options does not matter.
- [ ] **Step 4: Add a guard test** `TestNoDirectTimeNow`. It reads the non-test `.go` files in `httpsec` with `os.ReadDir` and `os.ReadFile`, and fails on any `time.Now` other than inside `clock.System`. Prove it bites by temporarily reintroducing one `now: time.Now`, then restore.
- [ ] **Step 5: Run** `go test -race -count=1 ./httpsec/...` → PASS.

### Task 2.1: MFA challenges on the chain's clock

**Files:**
- Modify: `httpsec/mfabegin.go` (`wireChallenges`, ~line 234: the default store and the per-method managers)
- Test: `httpsec/clock_test.go`

**Interfaces:**
- Consumes: `config.clock`.

- [ ] **Step 1: Write the failing table `TestChain_ClockMFA`:**
  - "a challenge expires on the chain's clock": `fc` at 2040; begin a challenge as a signed-in user; `fc.Advance(<TTL> + time.Second)`; answering is refused as expired. No `synctest`.
  - "the expiry task purges on the chain's clock": then `fc.Advance(<issuance window>)`; run `mfa-challenges:<method>` from `chain.ExpiryTasks()` → `Removed == 1`.
  - "a clock behind the system clock keeps a live challenge" (Review Focus 2): `fc` at 2000-01-01; begin; `fc.Advance(time.Minute)`; answering is not refused as expired, and the expiry task removes 0.
  - "a consumer's challenge store keeps its own clock": `WithMFAChallengeStore(onetime.NewMemoryStore())` (the system clock) with `fc` at 2040; after the TTL and window, the task removes 0, so the consumer's store was not re-clocked.
- [ ] **Step 2: Run** `go test -race -run 'TestChain_ClockMFA' -count=1 ./httpsec/`. Expected: FAIL on the first three rows (the store and managers read the system clock).
- [ ] **Step 3: Implement** in `wireChallenges`:

```go
store := i.challengeStore
if store == nil {
	store = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(c.clock))
}
// and each manager:
onetime.NewManager(purpose, onetime.WithStore(store), onetime.WithClock(c.clock), /* existing options */)
```

- [ ] **Step 4: Run** Step 2's command → PASS.

### Task 2.2: Source guards and the default factory on the chain's clock

**Files:**
- Modify: `httpsec/throttle.go` (`rateLimiterFactory` ~57, `resolveSourceGuard` ~113)
- Test: `httpsec/clock_test.go`

- [ ] **Step 1: Write the failing table `TestChain_ClockThrottle`:**
  - "a throttle window follows the chain's clock": `fc` at 2040, form login with the default factory. Drive failures from one source until it is refused for throttling; `fc.Advance(<password-login window> + time.Second)`; the next login from that source is not refused for throttling.
  - "a consumer's factory keeps its own clock" (Review Focus 3): `WithRateLimiterFactory(ratelimit.MemoryLimiterFactory())` (the system clock) plus `WithClock(fc)`. After the same advance, the source is still refused, because the consumer's factory was not re-clocked.
- [ ] **Step 2: Run** `go test -race -run 'TestChain_ClockThrottle' -count=1 ./httpsec/`. Expected: FAIL on the first row.
- [ ] **Step 3: Implement.** The default factory becomes `ratelimit.MemoryLimiterFactory(ratelimit.WithMemoryLimiterLogger(c.logger), ratelimit.WithMemoryLimiterClock(c.clock))`. Every guard gets `ratelimit.WithSourceGuardClock(c.clock)` in `resolveSourceGuard`'s options. A guard reads the time for its own sampling even over a consumer's limiter, so this does not re-clock the consumer's limiter.
- [ ] **Step 4: Run** Step 2's command → PASS.

### Task 2.3: The recoverer on the chain's clock, the consumer's winning

**Files:**
- Modify: `httpsec/recoverycomplete.go` (~line 230, the `opts` slice)
- Test: `httpsec/clock_test.go`

- [ ] **Step 1: Write the failing table `TestChain_ClockRecovery`:**
  - "recovery codes expire on the chain's clock": `fc` at 2040, account recovery with issued codes and no `recovery.WithClock`. Start a recovery (the issued code is stored); `fc.Advance(<issued TTL> + <window>)`; the `recovery-issued-codes` task from `chain.ExpiryTasks()` → `Removed == 1`.
  - "a recovery core with its own clock keeps it" (Review Focus 4): `WithRecoveryCore(recovery.WithClock(other))` with `other := clockwork.NewFakeClockAt(2050-01-01)` and the chain on `fc` at 2040. Advance `fc` past the TTL and window but not `other` → `Removed == 0`. Advance `other` → `Removed == 1`.
- [ ] **Step 2: Run** `go test -race -run 'TestChain_ClockRecovery' -count=1 ./httpsec/`. Expected: FAIL on the first row.
- [ ] **Step 3: Implement.** Put the chain's clock first in the `opts` slice, before `i.coreOpts`:

```go
opts = append(opts, recovery.WithLogger(c.logger), recovery.WithClock(c.clock))
```

  Update the comment above it to say the chain's clock goes first so the consumer's `recovery.WithClock` replaces it.
- [ ] **Step 4: Run** Step 2's command, then `go test -race -count=1 ./httpsec/...` → PASS.

### Task 3.1: Retire the test workarounds

**Files:**
- Modify: `httpsec/export_test.go` (remove `WithRecoveryClockForTest`, ~line 115), `httpsec/recoverycodes_test.go:36`, `httpsec/mfabegin_test.go` (the `synctest` bubbles described at ~729), `httpsec/expiry_test.go` (the MFA row's bubble), and any other test whose comment says it uses `synctest` because the chain has no clock option (`grep -n "no clock option" httpsec/*_test.go`)

- [ ] **Step 1:** Replace `httpsec.WithRecoveryClockForTest(h.clock.Now)` with `httpsec.WithClock(h.clock)` in the harness, then delete the seam. Run `go test -race -count=1 ./httpsec/...` → PASS.
- [ ] **Step 2:** For each `synctest` bubble that exists only for the missing clock, rewrite the test on a `clockwork` fake given through `WithClock`, replacing `time.Sleep` with `fc.Advance`. Leave a bubble that also proves something else (for example that no goroutine outlives the request), and say why.
- [ ] **Step 3: Prove each converted test bites.** Temporarily revert the component's clock wiring from Task 2.1 (or 1.2), run the converted test, see it fail, restore. Record the failing lines.
- [ ] **Step 4: Run** `go test -race -count=3 ./httpsec/...` → PASS.

### Task 3.2: The account-recovery refusal pins the spec scenario

**Files:**
- Test: `httpsec/recoveryoptions_test.go` (`TestEnableAccountRecovery_Config`, row "enabled twice", ~line 186)

- [ ] **Step 1:** Read the row's assertion. If it already checks `errors.Is(err, httpsec.ErrConfig)` and that the message names account recovery (the code's message is "EnableAccountRecovery was given twice; one chain has one account recovery"), record that and stop.
- [ ] **Step 2:** Otherwise tighten it: assert `ErrConfig` and `assert.Contains(t, err.Error(), "EnableAccountRecovery")`. Temporarily change the message in `httpsec/recoveryoptions.go:263` to drop the option name, see the row fail, restore.
- [ ] **Step 3: Run** `go test -race -run 'TestEnableAccountRecovery' -count=1 ./httpsec/` → PASS.

### Task 4.1: Whole-workspace gate (main session)

- [ ] For every module in `go list -m` (root, `fibersec`, `ginsec`, `gorm`, `passkey/webauthn`, `pgx`, `redis`, `sweep`, `test`), with Docker up: `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`. Then `gofmt -l` empty over the tracked Go files, and `openspec validate chain-time-source --strict`.

### Task 4.2: Whole-branch review (main session dispatches an Opus reviewer)

- [ ] Review `git diff main...HEAD` against every requirement and scenario of `specs/http-security-chain/spec.md` and design decisions 1–6, producing a requirement → test map, with findings labelled REPRODUCED or UNREPRODUCED. No open finding.
