# clock-seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace scrty's three time seams (`func() time.Time` options, per-package `Clock`
interfaces, signingkey's `TickerClock`/`Ticker`) with one standard-library-typed `pkg/clock` seam
that a clockwork clock satisfies directly, and pace every background loop through it.

**Architecture:** A new `pkg/clock` declares `Clock` (`Now`) and `Timed` (`Clock` + `After`), plus
`System()`. Read-only components take `clock.Clock`; the two loop components (signing-key manager,
in-memory session store) take `clock.Timed` and wait on `After` (fixed-delay). clockwork is the
test fake everywhere and is barred from production builds by the layout guard.

**Tech Stack:** Go 1.27, `github.com/jonboulle/clockwork` v0.5.0 (tests only), testify, gopls,
testcontainers (the `test` module).

**Spec:** `openspec/changes/clock-seam/` — `proposal.md`, `design.md` (D1–D7), `specs/time-source`,
`specs/signing-keys`, `specs/sessions`, `specs/module-layout`, and `tasks.md`. Task numbers below
(`1.1`, `3.4`, …) are `tasks.md`'s; no step here exists without a task there.

## Global Constraints

- The core module's production build imports nothing outside the standard library for time: `pkg/clock` imports only `time`.
- `clock.Clock` is exactly `Now() time.Time`; `clock.Timed` is `Clock` plus exactly `After(d time.Duration) <-chan time.Time` (signatures identical to `clockwork.Clock`'s).
- clockwork appears only in `_test.go` files of the core, `pgx` and `gorm` modules, and in the `test` module. Never in a non-test file of the core module.
- Option **names** do not change; only their parameter type (D2).
- Nil handling (D2): every option whose constructor returns an error refuses nil **and typed nil** with the package's configuration error, judged by `internal/nilcheck.IsNil` (replace any `== nil` check on a clock). The four exceptions keep the system clock on nil and typed nil: `session.WithMemoryStoreClock`, `onetime.WithMemoryStoreClock`, `id.WithClock`, `mfa.WithResetClock`; their godoc says so.
- No interval, lifetime, TTL, leeway or default duration changes.
- Loops are fixed-delay: the next run starts one interval after the previous run finishes (D3).
- Test-first for every task (`.claude/rules/golang-tdd.md`): failing test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, green, refactor.
- Table tests follow the `table-test` skill: `assert` closure, `ctx` modifier where context matters, `t.Context()`.
- A test that needs all of package `time` faked (net/http timeouts, `context.WithTimeout`) stays on `testing/synctest`. Never mix synctest and a clockwork fake in one test (D7).
- Godoc on every changed option names the default it replaces (`clock.System()`), per `library-design.md`.
- No git command that discards work (`checkout --`, `restore`, `reset --hard`, `stash`, `clean`).
- No edit to any file under `openspec/`.

## Review Focus

1. **Stale `After` waiters on a clockwork fake after Stop/restart.** A cancelled loop leaves its pending `After` registered on the fake, so after a restart `BlockUntilContext(ctx, 3)` returns before the new loops park. Expected: restart tests wait for the stale plus new count (6 for signingkey, 2 for the session store), stated in a comment. Pinned in 4.2 and 3.4.
2. **A consumer `Timed` whose `After` returns a nil channel.** Expected: the loop never runs, and Stop still returns promptly, with no goroutine left. Pinned in 4.2.
3. **Typed-nil clock to an option that used `== nil`** (oidc, policy, password, drivers, TOTP). Expected: construction refused, not a panic on first use. Pinned in each lane's nil table rows.
4. **One fake shared by a manager (`clock.Clock`) and its in-memory store (`clock.Timed`).** Expected: both read the same instant, and expiry means the same on both sides. Pinned in 3.4.
5. **The default system clock still paces loops in real time.** The only path consumers ship with. Expected: with `clock.System()` and a short interval, a loop runs. Pinned in 4.1 (the `ticker_test.go` replacement) and 3.4.

---

## Dispatch map

The split follows the call graph (`gopls references` on every clock option, 2026-09-30):

- `seal.WithClock` is called in production by `sqlstore/mfa.go`, `pgx/mfa.go` and `gorm/mfa.go`, so `seal` goes with the drivers.
- `session.WithClock`, `session.WithMemoryStoreClock`, `mfa.WithClock` and `oidc.WithClock` are all called from `httpsec` test files, some from the same file (`mfaenrollifetime_test.go`, `mfaenrolupgrade_test.go`), and `onetime`'s options from `magiclink/helpers_test.go`. They form one lane: `httpsec`'s test package compiles only when all of them have landed.
- Every conformance suite, the cross-backend tests and the driver tests live in the `test` module, which calls options from every lane. It is one dispatch, after all the others.

| Order | Dispatch | Tasks | Owns | Model | Why this model |
|---|---|---|---|---|---|
| 1 | Seam | 1.1, 1.2 | `pkg/clock/**`, `go.mod`, `go.sum`, `layout_test.go`, `layout_guard_test.go`, `testdata/layout/prodclockwork/**` | Sonnet | Signatures and tests fully given here |
| 2 (parallel) | Lane B | 2.1–2.3 | `token/**`, `ratelimit/**`, `pkg/id/**`, `password/**`, `policy/**`, `apikey/**` | Sonnet | Mechanical option type change, nil rows |
| 2 (parallel) | Lane C | 3.1–3.4 | `onetime/**`, `magiclink/**` (tests only), `oidc/**`, `session/**`, `mfa/**`, `httpsec/*_test.go` | Opus | Four packages plus a loop under `-race`, and shared test files |
| 2 (parallel) | Lane S | 4.1–4.2 | `signingkey/**` | Opus | Loop ordering, stop/restart races, goroutine lifetime |
| 2 (parallel) | Lane F | 5.1 | `seal/**`, `sqlstore/**`, `pgx/**` (not `pgx/go.mod`), `gorm/**` (not `gorm/go.mod`) | Sonnet | Option plumbing across three drivers |
| 3 | Suites | 5.2 | `test/**` | Sonnet | Mechanical factory change across one module |
| 4 | Main session | 6.1–6.3 | `openspec/**`, verification | — | — |

Between dispatches 2 and 3 the `test` module does not compile: it calls options every lane changes,
and dispatch 3 owns all of it. Each dispatch-2 lane verifies its own packages. The `pgx` and `gorm`
modules verify in Lane F.

---

### Task 1.1: `pkg/clock`

**Files:**
- Create: `pkg/clock/clock.go`, `pkg/clock/clock_test.go`
- Modify: `go.mod`, `go.sum` (clockwork arrives through the test import)

**Interfaces:**
- Produces: `package clock` — `type Clock interface{ Now() time.Time }`, `type Timed interface{ Clock; After(d time.Duration) <-chan time.Time }`, `func System() Timed`. Every later task uses these names.

- [ ] **Step 1: Write the failing test**

```go
package clock_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/clock"
)

// clockwork's clocks satisfy both interfaces with no adapter (D1).
var (
	_ clock.Timed = clockwork.NewFakeClock()
	_ clock.Timed = clockwork.NewRealClock()
	_ clock.Clock = clockwork.NewFakeClock()
)

func TestSystem(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, c clock.Timed)
	}

	cases := []testCase{
		{
			name: "Now reads the system time",
			assert: func(t *testing.T, c clock.Timed) {
				before := time.Now()
				got := c.Now()
				after := time.Now()
				assert.False(t, got.Before(before))
				assert.False(t, got.After(after))
			},
		},
		{
			name: "After fires once the duration has passed",
			assert: func(t *testing.T, c clock.Timed) {
				start := time.Now()
				select {
				case fired := <-c.After(10 * time.Millisecond):
					assert.GreaterOrEqual(t, fired.Sub(start), 10*time.Millisecond)
				case <-time.After(5 * time.Second):
					require.FailNow(t, "After never fired")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, clock.System())
		})
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go get github.com/jonboulle/clockwork@v0.5.0 && go test -run TestSystem -count=1 ./pkg/clock/`
Expected: a build failure, because the package does not exist yet. That is a compile error and does **not** count as red. Add `clock.go` with `System()` returning a `system{}` whose `Now` returns `time.Time{}` and whose `After` returns `make(chan time.Time)`, then run it again. Expected: FAIL on "Now reads the system time" (the zero time is before `before`) and on "After never fired" (after 5s). That is the red step.

- [ ] **Step 3: Implement**

```go
// Package clock is the time source every scrty component reads and waits on.
//
// A component that only reads the time takes a Clock; one that runs background
// loops takes a Timed, and waits between runs on its After, so advancing a
// controlled clock runs those loops without real waiting. Both default to
// System.
//
// The method signatures match github.com/jonboulle/clockwork's Clock exactly,
// so a clockwork fake or real clock, or any type of the consumer's with these
// methods, satisfies both interfaces with no adapter. scrty itself never
// imports clockwork outside its tests.
package clock

import "time"

// Clock is the time source of a component that only reads the time.
type Clock interface {
	Now() time.Time
}

// Timed is the time source of a component that also waits.
//
// After must deliver once Now has advanced by at least d, whether Now is the
// system time or a controlled one; a Timed whose After runs on real time while
// its Now is controlled would fire the component's loops at the wrong moments.
// clockwork's fake clock is a conforming implementation.
type Timed interface {
	Clock
	After(d time.Duration) <-chan time.Time
}

// System returns the clock backed by package time. It is every component's
// default.
func System() Timed { return system{} }

type system struct{}

func (system) Now() time.Time { return time.Now() }

func (system) After(d time.Duration) <-chan time.Time { return time.After(d) }
```

- [ ] **Step 4: Run it to see it pass**

Run: `go test -count=1 ./pkg/clock/ && go mod tidy && git diff --stat go.mod`
Expected: PASS, and `go.mod` requires `github.com/jonboulle/clockwork v0.5.0`.

### Task 1.2: The layout guard forbids clockwork in production

**Files:**
- Create: `testdata/layout/prodclockwork/go.mod`, `testdata/layout/prodclockwork/app/app.go`, `testdata/layout/prodclockwork/stub/clockwork/go.mod`, `testdata/layout/prodclockwork/stub/clockwork/clockwork.go`
- Modify: `layout_test.go` (the `TestModuleLayout` table), `layout_guard_test.go:30-34` (`forbiddenProduction`)

**Interfaces:**
- Consumes: the existing `hasViolation(where, what string)` helper and fixture layout (copy `testdata/layout/prodtestify`).

- [ ] **Step 1: Write the fixture and the failing case**

`testdata/layout/prodclockwork/go.mod`:
```
module example.com/fixture

go 1.26

require github.com/jonboulle/clockwork v0.0.0

replace github.com/jonboulle/clockwork => ./stub/clockwork
```
`stub/clockwork/go.mod`: `module github.com/jonboulle/clockwork` and `go 1.26`. `stub/clockwork/clockwork.go`: `package clockwork` with `func NewFakeClock() any { return nil }`. `app/app.go`: `package app`, importing `github.com/jonboulle/clockwork` and using `var _ = clockwork.NewFakeClock()`.

Add a row to `TestModuleLayout`:
```go
{
	name:    "production file imports clockwork",
	fixture: "testdata/layout/prodclockwork",
	assert:  hasViolation("example.com/fixture/app", "github.com/jonboulle/clockwork"),
},
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test -run 'TestModuleLayout' -count=1 ./`
Expected: FAIL on "production file imports clockwork", because no violation names `github.com/jonboulle/clockwork`.

- [ ] **Step 3: Implement**

In `forbiddenProduction`, add `"github.com/jonboulle/clockwork",` after testcontainers.

- [ ] **Step 4: Run it to see it pass**

Run: `go test -run 'TestModuleLayout' -count=1 ./ && go mod tidy && git diff --exit-code go.mod go.sum`
Expected: PASS. The "real tree has no violations" row stays green, and tidy leaves no diff.

---

## Lane B: self-contained read-only components (tasks 2.1–2.3)

The pattern is the same in every package below. It is repeated in full for each one, because a
reader may start at any task.

**The option change:**
```go
// Before
func WithLockoutClock(now func() time.Time) LockoutOption { return func(p *AccountLockoutPolicy) { p.now = now } }
// After
// WithLockoutClock replaces the policy's time source. Default: clock.System().
// A nil clock, typed nil included, is a configuration error.
func WithLockoutClock(clk clock.Clock) LockoutOption { return func(p *AccountLockoutPolicy) { p.clock = clk } }
```
The field becomes `clock clock.Clock`, defaulted to `clock.System()`, and each `x.now()` becomes
`x.clock.Now()`. The constructor's nil check becomes `if nilcheck.IsNil(x.clock) { return …ErrConfig… }`,
replacing any `x.now == nil`.

**The nil table:** one table per package, in its options test file, following the `table-test` skill:
```go
type nilClock struct{} // a consumer clock type; (*nilClock)(nil) is the typed nil
func (*nilClock) Now() time.Time { return time.Time{} }

type fixedClock struct{ at time.Time } // a consumer's own clock with only Now
func (c fixedClock) Now() time.Time { return c.at }

cases := []testCase{
	{name: "default clock", opts: nil, assert: func(t *testing.T, err error) { require.NoError(t, err) }},
	// A Now-only consumer type: `time-source` "Read-only source for a read-only component".
	{name: "consumer clock", opts: []Opt{WithXClock(fixedClock{at: t0})}, assert: func(t *testing.T, err error) { require.NoError(t, err) }},
	{name: "nil clock", opts: []Opt{WithXClock(nil)}, assert: func(t *testing.T, err error) { require.ErrorIs(t, err, ErrConfig) }},
	{name: "typed-nil clock", opts: []Opt{WithXClock((*nilClock)(nil))}, assert: func(t *testing.T, err error) { require.ErrorIs(t, err, ErrConfig) }},
}
```
Where a nil row already exists, keep it and add the typed-nil row. The typed-nil row is the red step
wherever the current check is `== nil`, or wherever there is no check at all. `token` may have none:
the red run shows it either way.

**The test migration:** each closure clock (`func() time.Time { return t0 }`) or hand-rolled fake
becomes `clk := clockwork.NewFakeClockAt(t0)`, passed as `clk`. Each "move time" step becomes
`clk.Advance(d)`, or `clk.Advance(target.Sub(clk.Now()))` where a test sets an absolute time.

### Task 2.1: `token` and `ratelimit`

**Files:** Modify `token/options.go` (delete `Clock` and `systemClock` at lines 32-38; `setClock`, `WithClock`, `VerifyWithClock` take `clock.Clock`; the `jwt.WithClock(jwt.ClockFunc(c.clock.Now))` line is unchanged), `token/generator.go`, `token/verifier.go` (nil check), `token/generator_test.go`, `token/verifier_test.go`, `ratelimit/options.go` (delete `Clock` and `systemClock`; `WithMemoryLimiterClock` and `WithSourceGuardClock` take `clock.Clock`), `ratelimit/memory.go`, `ratelimit/guard.go` (fields become `clock.Clock`, defaults `clock.System()`; `nilcheck.IsNil` already used), `ratelimit/memory_test.go`, `ratelimit/guard_test.go`.

**Interfaces:** Consumes `clock.Clock`, `clock.System()` (1.1).

- [ ] **Step 1:** Add the nil tables (nil and typed-nil rows) for `NewGenerator` + `WithClock`, `NewVerifier` + `VerifyWithClock`, `NewMemoryLimiter` + `WithMemoryLimiterClock`, `NewSourceGuard` + `WithSourceGuardClock`, and move the existing clock tests to `clockwork.NewFakeClockAt`.
- [ ] **Step 2:** Run `go test -count=1 ./token/... ./ratelimit/...`. First expected: build failure, because the tests pass a `*clockwork.FakeClock` where token's own `Clock` is expected. That is structurally fine, since `FakeClock` has `Now`, so it may actually compile. Record which rows fail. Expected red: token's nil and typed-nil rows fail (construction succeeds) if token has no nil check. If every row passes on the old code, say so in the report: the red step for this task is then the type change itself, shown by a compile-only diff, and the report must state that plainly.
- [ ] **Step 3:** Delete the package `Clock` types, switch to `clock.Clock`, and add `nilcheck.IsNil` checks where missing (token: in the config validation both constructors share; return the package's configuration error).
- [ ] **Step 4:** Run `go test -race -count=1 ./token/... ./ratelimit/...` and `gopls references` on the old `token.Clock`/`ratelimit.Clock` positions, confirming no reference remains. Expected: PASS.

### Task 2.2: `pkg/id` and `password`

**Files:** Modify `pkg/id/generator.go:31-47` (`now` field → `clock clock.Clock`; `WithClock(clk clock.Clock)` keeps `clock.System()` when `nilcheck.IsNil(clk)`; godoc says a nil clock, typed nil included, keeps the system clock), `pkg/id/generator_test.go`, `pkg/id/generator_internal_test.go`, `password/reuse.go:43-52,103,153` (`WithReuseClock(clk clock.Clock)`; the check at line 103 becomes `nilcheck.IsNil(cfg.clock)`), `password/reuse_test.go`, `password/provisionerwrite_test.go`.

Do **not** touch `test/*/identity_reuse_test.go`; that is 5.2's.

- [ ] **Step 1:** Tests. For `pkg/id`, a table: a default row, a fake-clock row (the UUIDv7 timestamp prefix equals the fake's millisecond instant), and nil and typed-nil rows that both **succeed** and use the system clock (the generated ID's timestamp lies between `time.Now()` before and after). For `password`, the nil table on `NewReuseGuard` (or whatever constructor applies `ReuseOption`s; find it with `gopls references` on `WithReuseClock`), with nil and typed nil refused.
- [ ] **Step 2:** Run `go test -count=1 ./pkg/id/... ./password/...`. Expected red: `pkg/id`'s typed-nil row panics on a nil pointer dereference (the current `now != nil` accepts the typed nil); `password`'s typed-nil row succeeds where refusal is expected.
- [ ] **Step 3:** Implement as above.
- [ ] **Step 4:** Run `go test -race -count=1 ./pkg/id/... ./password/...`. Expected: PASS.

### Task 2.3: `policy` and `apikey`

**Files:** Modify `policy/mfa.go:211-223,284`, `policy/mfarequirement.go:124,156,265`, `policy/lockout.go:64,108,154`, `policy/mfa_test.go`, `policy/mfasampling_test.go`, `policy/mfarequirement_test.go`, `policy/enrolmentpath_test.go`, `policy/lockout_test.go`, `policy/lockout_config_test.go`, `apikey/options.go:100`, `apikey/manager.go:38,92`, and apikey's tests (`failure_records_test.go`, `options_test.go`, `overrides_test.go`, `rotate_test.go`, `verify_test.go`).

- [ ] **Step 1:** Add the nil tables for `WithMFAPolicyClock`, `WithMFARequirementClock`, `WithLockoutClock` and apikey's `WithClock`, and move the existing tests to clockwork fakes.
- [ ] **Step 2:** Run `go test -count=1 ./policy/... ./apikey/...`. Expected red: the typed-nil rows for `WithMFAPolicyClock` and `WithMFARequirementClock` pass construction, because their checks are `p.now == nil`.
- [ ] **Step 3:** Implement, using `nilcheck.IsNil` in all four.
- [ ] **Step 4:** Run `go test -race -count=1 ./policy/... ./apikey/...`. Expected: PASS.

---

## Lane C: components whose callers share `httpsec` tests (tasks 3.1–3.4)

This lane owns `httpsec/*_test.go` (only the test files; no `httpsec` production file changes) and
`magiclink/helpers_test.go`. `httpsec`'s test package compiles again only after 3.3. Run the
narrower packages at each red step, and `./httpsec/...` from 3.3 on.

The option pattern, nil table and test migration are exactly as in Lane B's preamble, repeated here:
the option takes `clk clock.Clock`, the field is `clock clock.Clock` defaulting to `clock.System()`,
`x.now()` becomes `x.clock.Now()`, and nil and typed nil are judged by `nilcheck.IsNil`. Tests use
`clockwork.NewFakeClockAt(t0)` and `Advance`.

### Task 3.1: `onetime`

**Files:** Modify `onetime/options.go:80`, `onetime/manager.go:42,103`, `onetime/memory.go:26,41-47` (`WithMemoryStoreClock(clk clock.Clock)` keeps `clock.System()` when `nilcheck.IsNil(clk)`; godoc updated), `onetime/check_test.go`, `onetime/consume_test.go`, `onetime/failure_records_test.go`, `onetime/manager_test.go`, `onetime/memory_test.go`, `magiclink/helpers_test.go`.

- [ ] **Step 1:** Tests.
  - `time-source` "Consumer time source": a manager and memory store sharing `clockwork.NewFakeClockAt(2030-01-01T12:00Z)` issue a token with a 5-minute lifetime; its expiry is 12:05; after `Advance(6*time.Minute)` redemption is refused as expired.
  - "Absent source on a constructor that cannot fail": `NewMemoryStore(WithMemoryStoreClock((*nilClock)(nil)))` stores a token whose expiry is computed from system time, and does not panic.
  - The manager's nil table (nil and typed nil refused).
- [ ] **Step 2:** Run `go test -count=1 ./onetime/...`. Expected red: the typed-nil memory-store row panics (the current `now != nil` accepts it), which shows the missing typed-nil guard.
- [ ] **Step 3:** Implement. Update `magiclink/helpers_test.go` to pass a clockwork fake.
- [ ] **Step 4:** Run `go test -race -count=1 ./onetime/... ./magiclink/...`. Expected: PASS.

### Task 3.2: `oidc`

**Files:** Modify `oidc/options_manager.go:58-64`, `oidc/options_broker.go:43-49`, `oidc/options_handoff.go:41-47`, `oidc/flowstore_memory.go:52,77-83`, `oidc/manager.go:32,123` (including its own `WithMemoryFlowStoreClock` call, which now passes the manager's `clock.Clock`), `oidc/broker.go:33,107`, `oidc/handoff.go:64,110`, their tests (`authorize_test.go`, `callback_consumerbroker_test.go`, `callback_test.go`, `flush_test.go`, `logouttoken_test.go`, `manager_test.go`, `verify_test.go`, `broker_test.go`, `password_changed_at_test.go`, `passwordclaim_test.go`, `provision_test.go`, `handoff_issue_test.go`, `handoff_redeem_test.go`, `flowstore_memory_test.go`), and `httpsec/oidc_authorize_test.go`, `httpsec/oidc_backchannel_test.go`.

- [ ] **Step 1:** Add typed-nil rows beside the existing nil rows for all four options (each option returns `ErrConfig` from inside the option func; keep that shape and replace `now == nil` with `nilcheck.IsNil(clk)`).
- [ ] **Step 2:** Run `go test -count=1 ./oidc/...`. Expected red: all four typed-nil rows construct successfully.
- [ ] **Step 3:** Implement, and migrate the listed tests.
- [ ] **Step 4:** Run `go test -race -count=1 ./oidc/...`. Expected: PASS.

### Task 3.3: `session` manager and `mfa`

**Files:** Modify `session/options.go:71-76` (`WithClock(clk clock.Clock)`), `session/manager.go:42,157`, `session/helpers_test.go:29-50` (delete `testClock`; callers use `clockwork.NewFakeClockAt`; `Set(at)` becomes `Advance(at.Sub(clk.Now()))`), `session/enrolment_test.go`, `session/manager_test.go`, `session/returned_errors_test.go`, `mfa/totpoptions.go:49`, `mfa/totp.go:43,111`, `mfa/reset.go:64,106-115` (`WithResetClock(clk clock.Clock)` keeps `clock.System()` when `nilcheck.IsNil(clk)`), `mfa/throttle.go:64` (its internal field becomes `clock.Clock`, fed from TOTP's), and mfa's tests (`enroller_test.go`, `failclosed_test.go`, `memory_test.go`, `returned_errors_test.go`, `throttle_test.go`, `totp_test.go`, `totpenrolment_test.go`, `totpoptions_test.go`, `totpreplay_test.go`, `reset_test.go`), plus `httpsec/bearer_test.go`, `httpsec/logincomplete_test.go`, `httpsec/mfaenrollifetime_test.go`, `httpsec/mfaenrolupgrade_test.go`, `httpsec/authmethods_integration_test.go`, `httpsec/mfaenrolconfirm_test.go`, `httpsec/mfaenrole2e_test.go`, `httpsec/mfaenrolharness_test.go`, `httpsec/mfaenrolleak_test.go`, `httpsec/mfaenrollogs_test.go`, `httpsec/mfaenroloptions_test.go`.

- [ ] **Step 1:** Tests.
  - `time-source` "Nil time source": `session.NewManager(session.WithClock(nil))` returns a configuration error, and a typed-nil row does too.
  - TOTP's nil table (nil and typed nil refused).
  - `WithResetClock` rows: nil and typed nil keep the system clock, so the notification's instant lies between `time.Now()` before and after.
- [ ] **Step 2:** Run `go test -count=1 ./session/... ./mfa/...`. Expected red: TOTP's typed-nil row constructs (the check is `t.now == nil`), and `WithResetClock`'s typed-nil row panics.
- [ ] **Step 3:** Implement, and migrate the listed tests.
- [ ] **Step 4:** Run `go test -race -count=1 ./session/... ./mfa/...`. Expected: PASS. Update the listed `httpsec` test files' calls to `session.WithClock` and `mfa.WithClock` now, but `httpsec`'s test package compiles again only in 3.4, after `session.WithMemoryStoreClock` changes too. So `./httpsec/...` is first verified there.

### Task 3.4: `session` in-memory store loop

**Files:** Modify `session/memory.go:38-64,143-163` and `session/options.go:152-167`, and the tests `session/memory_test.go`, `session/encrypted_test.go`, `session/helpers_test.go`, `httpsec/bearer_test.go`, `httpsec/mfaenrollifetime_test.go`, `httpsec/mfaenrolupgrade_test.go`.

**Interfaces:**
- Produces: `func WithMemoryStoreClock(clk clock.Timed) MemoryStoreOption` (nil and typed nil keep `clock.System()`).

- [ ] **Step 1: Write the failing test** (in `session/memory_test.go`, as rows of the store's housekeeping table, or as a new table if none exists)

```go
{
	name: "housekeeping on a controlled time source",
	assert: func(t *testing.T) {
		ctx := t.Context()
		clk := clockwork.NewFakeClockAt(t0)
		s := session.NewMemoryStore(
			session.WithMemoryStoreClock(clk),
			session.WithHousekeepingInterval(10*time.Second),
		)
		require.NoError(t, s.Create(ctx, expiringAt(t0.Add(5*time.Second))))
		require.NoError(t, s.Start(ctx))
		t.Cleanup(func() { _ = s.Stop() })

		require.NoError(t, clk.BlockUntilContext(ctx, 1)) // the loop is parked on After
		clk.Advance(10 * time.Second)
		require.NoError(t, clk.BlockUntilContext(ctx, 1)) // the sweep ran and the loop re-parked

		assert.Zero(t, heldCount(s))
	},
},
{
	name: "a manager and its store share one fake",
	assert: func(t *testing.T) {
		// Review Focus 4: session.WithClock(clk) and session.WithMemoryStoreClock(clk)
		// with the same *clockwork.FakeClock; after Advance past the idle expiry,
		// the manager refuses the session and a sweep removes it.
	},
},
{
	name: "restart counts the stale waiter",
	assert: func(t *testing.T) {
		// Review Focus 1: Start, BlockUntilContext(1), Stop, Start again. The
		// cancelled loop's After stays registered on the fake, so wait for 2
		// before Advance, and assert exactly one sweep ran.
	},
},
{
	name: "default system clock still sweeps",
	assert: func(t *testing.T) {
		// Review Focus 5: no clock option, a 10ms interval, and a session already
		// expired; require.Eventually(heldCount == 0, 2s, 5ms).
	},
},
```

`expiringAt` and `heldCount` are local helpers in the test file: the first builds a `*Session` with
that absolute expiry, and the second counts records through `DeleteExpired` on a copy, or through an
existing test hook. Use whatever `memory_test.go` already uses to count held records, and do not
add a production accessor.

- [ ] **Step 2: Run it to see it fail**

Run: `go test -run 'TestMemoryStore' -count=1 ./session/`
Expected: before the signature change this does not compile, because `WithMemoryStoreClock` wants a func. That is not red. First change only the option's type to `clock.Timed` and keep `time.NewTicker` in `housekeep`. Run again. Expected: FAIL: `BlockUntilContext(ctx, 1)` times out (the test's context ends) because the loop waits on a real ticker and never registers with the fake. That is the red step.

- [ ] **Step 3: Implement**

```go
// WithMemoryStoreClock replaces the store's time source. Default: clock.System().
//
// The store reads expiry from it and waits on it between housekeeping sweeps,
// so a controlled clock runs housekeeping without real waiting. A test that
// moves a manager's clock gives the store the same one. A nil clock, typed nil
// included, keeps the default, since this constructor cannot fail and a store
// with no clock could not judge expiry at all.
func WithMemoryStoreClock(clk clock.Timed) MemoryStoreOption {
	return func(s *MemoryStore) {
		if !nilcheck.IsNil(clk) {
			s.clock = clk
		}
	}
}
```

```go
// housekeep sweeps expired sessions one interval after the previous sweep
// finished, until ctx ends.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for.
func (s *MemoryStore) housekeep(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(s.interval):
			_, _ = s.DeleteExpired(ctx)
		}
	}
}
```

The field `now func() time.Time` becomes `clock clock.Timed`, defaulting to `clock.System()`, and
each `s.now()` becomes `s.clock.Now()`. Update the stop/start godoc from "ticker" to "housekeeping".

- [ ] **Step 4: Run it to see it pass**

Run: `go test -race -count=3 ./session/... ./httpsec/...`
Expected: PASS, including "Double start and stop" (no housekeeping left running; goleak where the file already uses it).

---

## Lane S: signing-key loops (tasks 4.1–4.2)

### Task 4.1: `signingkey` takes `clock.Timed` and waits on `After`

**Files:**
- Modify: `signingkey/options.go:20-69,127-135` (delete `Clock`, `Ticker`, `TickerClock`, `systemClock`, `realTicker`; `WithClock(clk clock.Timed)`; the default is `clock.System()`; the nil check becomes `nilcheck.IsNil`, replacing `isNilPort` only for the clock, and keep `isNilPort` for the other ports unless it becomes unused), `signingkey/lifecycle.go:36-157` (delete the ticker preallocation and `newTicker`; each loop calls `After`), `signingkey/manager.go` (field type).
- Test: `signingkey/lifecycle_test.go` (delete `fakeClock` and `fakeTicker`; use `clockwork.NewFakeClockAt`), `signingkey/ticker_test.go` (becomes the real-clock test), `signingkey/restart_test.go` (the `panickyClock` NewTicker cases no longer apply, so replace them per Step 1), `signingkey/replica_test.go`, `signingkey/housekeep_test.go`, `signingkey/hook_test.go`, `signingkey/rotate_test.go`, `signingkey/stop_test.go`, and every other file `gopls references` lists for `signingkey.WithClock`: `algs_test.go`, `boundary_test.go`, `failure_records_test.go`, `keyringlock_test.go`, `manager_test.go`, `options_test.go`, `sample_test.go`.

**Interfaces:**
- Consumes: `clock.Timed`, `clock.System()` (1.1).
- Produces: `func WithClock(clk clock.Timed) Option`.

- [ ] **Step 1: Write the failing tests** (in `lifecycle_test.go`, one table over the loop scenarios)

```go
{
	name: "one interval runs rotation, reload and housekeeping once each",
	assert: func(t *testing.T, ctx context.Context, clk *clockwork.FakeClock, km *signingkey.KeyManager, store *countingStore) {
		require.NoError(t, km.Start(ctx))
		require.NoError(t, clk.BlockUntilContext(ctx, 3))
		clk.Advance(time.Hour) // rotate 1h, reload 1m, housekeep 1h: each fires once
		require.NoError(t, clk.BlockUntilContext(ctx, 3))
		assert.Equal(t, 1, store.stores(), "one rotation for the one configured algorithm")
		assert.Equal(t, 1, store.loads(), "a long jump fires reload once, not 60 times")
	},
},
{
	name: "the interval is measured from the end of a run",
	assert: func(t *testing.T, ctx context.Context, clk *clockwork.FakeClock, km *signingkey.KeyManager, store *countingStore) {
		store.blockNextLoad() // the next LoadAll parks until released
		require.NoError(t, km.Start(ctx))
		require.NoError(t, clk.BlockUntilContext(ctx, 3))
		clk.Advance(time.Minute)            // reload starts at +1m
		store.awaitLoadStarted(t)
		clk.Advance(3 * time.Second)        // reload is still running at +1m3s
		store.releaseLoad()
		require.NoError(t, clk.BlockUntilContext(ctx, 3))
		clk.Advance(time.Minute - time.Nanosecond) // +2m3s minus 1ns: not yet
		assert.Equal(t, 1, store.loads())
		clk.Advance(time.Nanosecond)               // +2m3s: next reload
		require.NoError(t, clk.BlockUntilContext(ctx, 3))
		assert.Equal(t, 2, store.loads())
	},
},
```

`countingStore` wraps the in-memory key store from `signingkey.NewInMemoryKeyStore()`, counts
`Store` and `LoadAll` calls under a mutex, and can park the next `LoadAll` on a channel. Build the
manager with `WithKeyStore(store)`, `WithClock(clk)`, `WithRotateInterval(time.Hour)`,
`WithReloadInterval(time.Minute)`, `WithHousekeepingInterval(time.Hour)`, and RS256 only. If
`NewKeyManager` loads or rotates once at construction, subtract those baseline counts, taken before
`Start`.

Rewrite `replica_test.go`'s shared-store test as the `signing-keys` scenario "Controlled reload":
two managers on one store and one fake, where A rotates `k2`, then `BlockUntilContext(ctx, 6)` (three
loops per replica), `Advance(time.Minute)`, `BlockUntilContext(ctx, 6)`, and B publishes `k2`.
Replace every `require.Eventually` in the loop tests with a `BlockUntilContext` wait.

Rewrite `ticker_test.go` as `realclock_test.go`: `TestSystemClockDrivesTheLoops` builds a manager
with no clock option, a reload interval of 20ms (and a rotation interval and lifetime long enough
to pass validation), starts it over a store that already holds a key written by another manager, and
`require.Eventually` sees it published within 2s. This is Review Focus 5. It keeps the
non-parallel/goleak note from the old file.

Delete `restart_test.go`'s `panickyClock` type and the rows that use it: `Start` no longer calls
into the clock, so the state they guarded (tickers taken, then a panic partway) cannot arise. The
nil-channel row in 4.2 covers a misbehaving consumer clock instead. Move `restart_test.go`'s other
rows to the clockwork fake.

- [ ] **Step 2: Run them to see them fail**

First change only `WithClock`'s parameter to `clock.Timed` and delete `TickerClock`/`Ticker`, keeping
`newTicker` falling back to the system ticker, so the package compiles. Run:
`go test -run 'TestLifecycle|TestReplica' -count=1 ./signingkey/`
Expected: FAIL: `BlockUntilContext(ctx, 3)` never returns before the test's deadline, because the
loops sit on real tickers and never register a waiter with the fake. That is the red step.

- [ ] **Step 3: Implement**

```go
// Start: after reapLocked and building loops, no ticker is taken.
loopCtx, cancel := context.WithCancel(ctx)
km.cancel = cancel
km.runDone = loopCtx.Done()

km.wg.Add(len(loops))
for _, loop := range loops {
	go km.loop(loopCtx, loop.every, loop.step)
}
return nil
```

```go
// loop runs step one interval after the previous step finished, until the
// context ends. Waiting on the clock's After, rather than a ticker, is what
// lets a controlled clock drive the loop and makes the cadence fixed-delay.
//
// It ends with return, never with break: a break inside the select would leave
// the select but not the for.
func (km *KeyManager) loop(ctx context.Context, every time.Duration, step func(context.Context)) {
	defer km.wg.Done()
	defer km.sampler.Flush()

	for {
		select {
		case <-ctx.Done():
			return
		case <-km.clock.After(every):
			step(ctx)
		}
	}
}
```

Remove the comments in `Start` about taking tickers up front and about a panicking `TickerClock`,
which no longer apply. Update `WithClock`'s godoc: default `clock.System()`; the clock stamps
creation times and paces rotation, reload and housekeeping, each one interval after the previous run
finished; a nil clock, typed nil included, is a configuration error.

- [ ] **Step 4: Run them to see them pass**

Run: `go test -race -count=1 ./signingkey/...`
Expected: PASS, including `apisurface_guard_test.go` and `options_test.go`'s "a nil clock" row. Add a
typed-nil row beside it.

### Task 4.2: Long jumps, nil channels and restarts

**Files:** Test `signingkey/lifecycle_test.go`, `signingkey/restart_test.go`, `signingkey/stop_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `time-source` "A long jump runs once": `Advance(5*time.Hour)` in one call gives exactly one rotation and one housekeeping; a further `Advance(time.Hour - time.Nanosecond)` gives none; `Advance(time.Nanosecond)` gives the next.
  - Review Focus 2: a consumer `Timed` whose `After` returns `nil` (a nil channel). `Start`, then `Stop`, returns within 2s and goleak finds no goroutine; nothing was stored.
  - Review Focus 1: Start, `BlockUntilContext(ctx, 3)`, cancel the start context and `Start` again under a fresh one. The three cancelled `After` waiters stay on the fake, so `BlockUntilContext(ctx, 6)` before `Advance(time.Hour)`, then exactly one rotation happens (not two). Comment why the count is 6.
- [ ] **Step 2: Run them to see them fail**

Run: `go test -run 'LongJump|NilAfter|Restart' -count=1 ./signingkey/`
These pin behaviour 4.1 already produces, so they may pass at once. Then invert the implementation
temporarily, per `golang-tdd.md`, to show that each test notices:
  - replace the `After` loop with `for range every/…` catch-up firing, and the long-jump test must fail;
  - drop the `ctx.Done()` case, and the nil-channel test must hang, then fail on its 2s bound.

Record each failure in the report, then restore the code by editing it back (no git revert).

- [ ] **Step 3: Implement**

No production change is expected. If a test fails for real, fix the loop and say so.

- [ ] **Step 4: Run them to see them pass**

Run: `go test -race -count=3 ./signingkey/...`
Expected: PASS, three times.

---

## Lane F: sealing and driver adapters (task 5.1)

### Task 5.1: `seal`, `sqlstore`, `pgx`, `gorm`

**Files:** Modify `seal/options.go:11-16,57,84-88` (`WithClock(clk clock.Clock)`; `nilClock` becomes `nilcheck.IsNil(clk)`), `seal/mfa_test.go`, `seal/signingkey_test.go`, `sqlstore/options.go:30,128-138`, `sqlstore/mfa.go`, `sqlstore/options_test.go`, `pgx/options.go:31,129-139`, `pgx/mfa.go`, `pgx/options_test.go`, `gorm/options.go:31,130-140`, `gorm/mfa.go`, `gorm/options_test.go`, and each driver's other files that read `c.now` (`gopls references` on the `now` field in each `config`).

**Interfaces:**
- Consumes: `clock.Clock`.
- Produces: `sqlstore.WithClock(clk clock.Clock) Option`, `pgx.WithClock(clk clock.Clock) Option`, `gorm.WithClock(clk clock.Clock) Option`, `seal.WithClock(clk clock.Clock) Option`. Each driver's `mfa.go` passes its `clock.Clock` straight to `seal.WithClock`. 5.2 relies on these.

- [ ] **Step 1:** Each `options_test.go` already has a nil-clock row (`c.refuse("the clock is nil")`); add a typed-nil row to each, and to seal's options table. Move the rows that pass a closure to `clockwork.NewFakeClockAt`.
- [ ] **Step 2:** Run `go test -count=1 ./seal/... ./sqlstore/...` (core) and `go test -count=1 ./...` in `pgx/` and `gorm/`. Expected red: the typed-nil rows are accepted, because the checks are `now == nil`.
- [ ] **Step 3:** Implement, keeping each driver's `c.applies(optClock, "WithClock")` duplicate-option guard unchanged.
- [ ] **Step 4:** Run `go test -race -count=1 ./seal/... ./sqlstore/...`, then `go test -race -count=1 ./...` in `pgx/` and `gorm/`, then `go mod tidy` in each and confirm no diff. Expected: PASS. clockwork is used only by the `_test.go` files of `pgx` and `gorm`, if at all. If they import it, tidy adds the requirement, and that `go.mod` edit is this task's to make; report it.

---

## Dispatch 3: the `test` module (task 5.2)

### Task 5.2: Suite factories take `clock.Clock`

**Files:** Modify `test/go.mod`, `test/go.sum`; `test/storetest/suite.go:30-104` (delete `fakeClock`; `suiteCase.assert` receives `*clockwork.FakeClock`; `runSuite` and `withoutClock` take `func(t *testing.T, clk clock.Clock) S`); `test/storetest/session_suite.go`, `test/storetest/onetime_suite.go` and every other suite that calls `clock.Set` (it becomes `clk.Advance(at.Sub(clk.Now()))`); `test/oidc/flowstore_suite.go:122-126`, `test/oidc/handoffstore_suite.go:106-110,284`; plus every caller `gopls references` lists across `test/` for the changed options and suite runners: `test/storetest/broken_test.go`, `test/storetest/memory_test.go`, `test/oidc/flowstore_suite_test.go`, `test/crossbackend/*.go`, `test/sqlstore/*`, `test/pgxstore/*`, `test/gormstore/*` (including `identity_reuse_test.go`), and `test/httpsecconformance/enrolment_scenarios.go`.

**Interfaces:**
- Consumes: every option from dispatches 1–2, and `clock.Clock`/`clock.Timed`.
- Produces: `RunSessionStoreSuite(t, func(t *testing.T, clk clock.Clock) session.Store)`, and the same `clk clock.Clock` factory parameter for `RunOneTimeStoreSuite` (whatever its exact name is at `onetime_suite.go:105`), `oidctest.RunFlowStoreSuite` and `oidctest.RunHandoffStoreSuite`.

- [ ] **Step 1:** Change the suite runner signatures first, and add one suite case asserting that the factory's clock is the one the suite advances: a store built on the given `clk`, where a record expiring at `suiteStart+1m` loads before `clk.Advance(2*time.Minute)` and is refused after. Place it in the session suite, whose cases already take the clock.
- [ ] **Step 2:** Run `go test -count=1 -run 'TestMemory' ./storetest/` inside `test/`. The in-memory stores need no Docker. Expected red: the new case fails against a deliberately wrong adapter in the test (a factory that ignores `clk` and builds the store on `clock.System()`), which shows that the case detects a store not wired to the suite's clock. Keep that adapter only for the red run, then point the factory at `clk`.
- [ ] **Step 3:** Update every listed caller to pass `clk`, or `clockwork.NewFakeClockAt(...)` where it built closures. Then run `go get github.com/jonboulle/clockwork@v0.5.0` and `go mod tidy` in `test/`.
- [ ] **Step 4:** Run `go vet ./...` and `go test -race -count=1 ./...` inside `test/`. This needs Docker; if Docker is unavailable, say so and report only the non-container packages. Expected: PASS.

---

## Main session: close out (tasks 6.1–6.3)

These are the main session's, never an agent's.

- [ ] **6.1** From the repository root: `rg -n 'func\(\) time\.Time' --glob '*.go' --glob '!*_test.go' --glob '!.claude/.legacy'`. Expected: only unexported internals whose values come from a `clock.Clock` (for example, `httpsec`'s interceptor fields, which are a design non-goal), and no exported option. Then run the gopls workspace-symbol search for `Clock`. Expected: `clock.Clock` and `clock.Timed` are the only interface types named `Clock`/`Timed`.
- [ ] **6.2** Edit `openspec/changes/shared-rate-limiting/design.md` (`WithAppClock(clock.Clock)`) and `openspec/changes/operations/design.md` (record the `sweep` exception, D6). Run `openspec validate shared-rate-limiting --strict` and `openspec validate operations --strict`.
- [ ] **6.3** For every module in `go.work`: `go build ./...`, `go vet ./...`, `gofmt -l .` (empty), `go test -race ./...`. Then `openspec validate clock-seam --strict`. Then dispatch one fresh reviewer against every requirement in the four spec deltas and the Review Focus list. Its findings go back to a fresh dispatch of the owning lane.
