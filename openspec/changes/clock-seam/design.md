# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **Three seam shapes.**
  - About 25 options take `func() time.Time`. This is the convention the authn-authz-core design set
    as a shared rule.
  - token and ratelimit each declare their own `Clock interface{ Now() time.Time }`.
  - signingkey declares `Clock`, plus an optional `TickerClock` and `Ticker`. A clock that does not
    implement `TickerClock` leaves the loops on `time.NewTicker`, so a fake `Now` runs alongside
    real waits.
- **Two background loops.**
  - The signing-key manager runs rotation, reload and housekeeping.
  - The in-memory session store runs housekeeping on a raw `time.NewTicker` that no option reaches.
- **Two ways tests control time.**
  - 12 test files use `testing/synctest`. It fakes all of package `time` inside a bubble, but does
    not support external I/O.
  - The rest pass frozen closures or hand-rolled fakes. The store conformance suites run against
    real PostgreSQL through testcontainers, so they cannot use synctest and must inject a clock.
- **Go's interface rule.** A type implements an interface only when every method signature matches
  exactly, including named result types. clockwork's `NewTicker` returns `clockwork.Ticker`, so no
  scrty-declared ticker method can be satisfied by a clockwork clock without importing clockwork.
  `Now() time.Time` and `After(time.Duration) <-chan time.Time` use only standard-library types.
- **The established design** injected `clockwork.Clock` directly into its public options: token,
  key manager, rate limiter, session stores and the conformance suite factory. It paced its loops
  with `clock.NewTicker`, so a controlled clock always drove them.

## Goals / Non-Goals

**Goals:**
- One seam shape for every component that reads time, owned by scrty, and satisfied by a clockwork
  clock with no adapter.
- A controlled clock drives every background loop, so no loop test waits on real time.
- No new production dependency in the core module.

**Non-Goals:**
- Migrating existing `testing/synctest` tests to clockwork. synctest stays the tool for concurrency
  tests that need all of package `time` faked. Both tools remain, and D7 says when to use which.
- Changing any interval, lifetime, TTL, leeway or default duration.
- The `sweep` module's clock, which the `operations` change owns (D6).

## Decisions

### D1. `pkg/clock`: a scrty-owned subset of clockwork's `Clock`, split in two

```go
package clock

// Clock is the time source of a component that only reads the time.
type Clock interface {
    Now() time.Time
}

// Timed is the time source of a component that also waits: its background loops
// wait on After, so advancing a controlled clock runs them without real waiting.
type Timed interface {
    Clock
    After(d time.Duration) <-chan time.Time
}

// System returns the clock backed by package time. It is every component's default.
func System() Timed
```

- **Signatures match clockwork exactly.** Every method has the same signature as the method of the
  same name on `clockwork.Clock`. So `clockwork.NewFakeClock()`, `clockwork.NewRealClock()`, and any
  consumer type with those methods satisfy both interfaces with no adapter.
- **The package lives under `pkg/`,** beside `pkg/id` and `pkg/logsample`: it is a non-security
  helper with no dependency beyond the standard library.
- **The split** keeps what a component asks for to what it reads. A consumer's own clock for a
  component that only reads time implements one method, not two.
- **Default:** `clock.System()`, used whenever no clock option is given.
- **Override:** the component's clock option (D2, D3).
- **Alternatives rejected:**
  - *`clockwork.Clock` in scrty signatures* (the established design). It puts a v0 library in
    scrty's public API, so a breaking change there becomes a breaking change in scrty. It also makes
    a consumer's own clock implement eight methods where scrty reads one or two. Rejected as a
    departure from the established design, recorded under D3's departure note.
  - *One shared `Clock{Now, After}`.* It is simpler to name, but every Now-only component would then
    demand `After` from a consumer's own clock.
  - *Keep a per-package `Clock` interface* (token's current reasoning). Go's structural typing makes
    them interchangeable, but three copies of the same one-method interface, plus 25 function
    options, is the inconsistency this change removes. With `After` in place of a ticker, token's
    concern about exposing ticker vocabulary to packages with no loop no longer applies: those
    packages take `clock.Clock`, which has none.
  - *Keep `func() time.Time`.* clockwork users can already pass `fc.Now`, but the loops need a
    method set anyway. Two shapes for one concept is the problem being fixed.

### D2. Every clock option takes `clock.Clock`, and a nil clock is still refused

- **The type changes, the name does not.** Every `func() time.Time` option, and token's and
  ratelimit's `Clock`-typed options, take a `clock.Clock` instead. `WithClock`, `WithReuseClock`,
  `VerifyWithClock` and the rest keep their names, because an option is named after what it
  governs, and that has not changed.
- **Nil is still a configuration error.** A nil clock, including a typed nil, fails construction
  with the package's configuration error, through the existing nil-detection helper. This keeps the
  authn-authz-core rule.
- **Default:** `clock.System()`.
- **Override:** pass any `clock.Clock` (a clockwork fake, or the consumer's own type) to the
  option.
- **Amends** the authn-authz-core shared convention `WithClock(func() time.Time)`, default
  `time.Now`. Nothing is tagged, so this is free under the compatibility rule, and it is recorded
  here.

### D3. The loops wait on `After`, and the loop components require `clock.Timed`

```go
for {
    select {
    case <-ctx.Done():
        return
    case <-km.clock.After(km.rotateEvery):
        km.rotate(ctx)
    }
}
```

- **What changes.** signingkey's `WithClock` and the in-memory session store's
  `WithMemoryStoreClock` take a `clock.Timed`. `TickerClock`, `Ticker` and `realTicker` are
  removed. Each loop waits a full interval after each run finishes: this is fixed-delay, where
  before it was fixed-rate.
- **Required, not optional.** Today `TickerClock` is optional, and a Now-only clock silently leaves
  the loops on real time. That mix, where fake creation times sit beside real waits, is the
  surprise `library-design.md` warns against. Requiring `Timed` makes a controlled clock control
  everything the component does with time, as the established design's required clock did.
- **Default:** `clock.System()`, whose `After` is `time.After`.
- **Override:** a clockwork fake or real clock, or the consumer's own `Timed`. A consumer
  coordinating the loops with their own scheduler implements `After`; this is the use the removed
  `TickerClock` documented.
- **Why fixed-delay is acceptable here.**
  - **Worst-case latency does not change.** A key rotated in just after a reload begins is seen by
    the end of the next reload under both models: one interval plus one reload's duration later.
  - **Only the start-to-start period changes.** It grows by one run's duration, a store load or a
    sweep. Against the defaults (1m reload, 1h rotation and housekeeping) that is noise.
  - **The reload-shorter-than-rotation guarantee still holds** whenever one reload finishes well
    within the gap between the two intervals. That already has to be true for the guarantee to mean
    anything.
  - **A long jump fires once, as a ticker does.** Advancing a controlled clock past several
    intervals fires the pending `After` once, then waits again.
- **Timer lifetime.** A `time.After` channel that nobody holds is collected even when
  `ctx.Done()` wins the select (Go 1.23 and later), so the loop leaks no timer.
- **Alternatives rejected:**
  - *Keep a scrty `Ticker` shaped like clockwork's* (`Chan`, `Reset`, `Stop`). `NewTicker` would
    still return scrty's type, not `clockwork.Ticker`, so clockwork would still need an adapter.
    That is the problem this change exists to remove.
  - *Import clockwork in signingkey and session only.* Every consumer would then build against
    clockwork, because `session` is imported by almost all of them, and scrty's API would be tied
    to a v0 type.
  - *Accept `clock.Clock` and type-assert to `Timed` with a `time.After` fallback.* This keeps
    today's silent mix of fake time and real waits.
- **Departure from the established design.** The established design passed `clockwork.Clock`
  through its public options and paced its loops at a fixed rate with `clock.NewTicker`. scrty
  keeps clockwork out of its public API (D1), continuing the settled authn-authz-core choice of a
  minimal, standard-library-typed seam. A ticker cannot be declared in that API compatibly with
  clockwork without importing it, so the loops wait on `After`, and the fixed-delay trade-off above
  is the cost. No defect in the established design is claimed.

### D4. The conformance suites' store factories receive a `clock.Clock`

`newStore func(t *testing.T, now func() time.Time) S` becomes
`newStore func(t *testing.T, clk clock.Clock) S`. This covers the session, one-time, flow and
handoff suites.

- **What the suites pass.** Each suite passes a clockwork fake and advances it. The
  store-conformance rule "drive time through the store's clock, not by waiting" is met with fake
  time against a real database, which synctest cannot provide.
- **Default:** not applicable: the suites are test helpers, not runtime behaviour.
- **Override:** a store under test wires the clock it receives into its own clock option.

### D5. clockwork is the test fake and the recommended consumer fake, never a core production import

- **Where it is required.** `github.com/jonboulle/clockwork` becomes a requirement of the core
  module (for `_test.go` files) and of the `test` module, next to testify. It has no requirements of
  its own. Graph pruning keeps a dependency's test-only imports out of a consumer's build.
- **What it replaces.** The hand-rolled fakes: session's `testClock`, signingkey's ticker-counting
  clock, and the frozen closures. They become `clockwork.NewFakeClockAt(t0)` with `Advance`.
  Loop tests use `BlockUntilContext` to wait for loops to park, instead of `Eventually`.
- **How it is enforced.** The layout guard, which already fails a production file that imports
  testify, adds clockwork to the same list, so the rule is checked rather than remembered.
- **Consumers.** Godoc for `pkg/clock` names clockwork as a fake that satisfies both interfaces.
  Consumers are not required to use it.
- **Default:** not applicable: this is test tooling, not runtime behaviour.
- **Override:** none needed. Consumers may use any type with the right methods.

### D6. `sweep` is the one place a clockwork type crosses a scrty API

The `operations` change's `sweep` module takes `WithClock(clockwork.Clock)`, because gocron v2's
own `WithClock` requires exactly that type, and `sweep` hands the clock straight to gocron.

- **Why it is allowed.** A `clock.Timed` cannot be widened into gocron's eight-method interface
  without scrty inventing six methods' behaviour. `sweep` is a nested module whose consumers
  already depend on clockwork through gocron.
- **Scope of this change.** It adds nothing to `sweep`. The `operations` design records this
  exception when it is next updated.

### D7. When a test uses clockwork, and when synctest

- **clockwork fake:**
  - a component whose time arrives through its clock option;
  - every conformance suite, because real I/O rules synctest out;
  - loop tests, where `BlockUntilContext` plus `Advance` replaces polling.
- **synctest:** code that uses package `time` directly (timeouts inside `net/http` or `httptest`,
  `context.WithTimeout`, backoff sleeps), and concurrency tests that need `synctest.Wait` for "every
  goroutine is idle".
- **Never both in one test.** A clockwork fake inside a bubble does not advance bubble time, and
  bubble time does not advance the fake. Mixing them makes it unclear which clock a component read.

## Risks / Trade-offs

- **[A consumer's own `Timed` implements `After` inconsistently with its `Now`,** for example a
  fake `Now` with a real `time.After`.] → Godoc on `Timed` states that `After` must fire when `Now`
  has advanced by `d`, and names clockwork's fake as a conforming implementation.
- **[Fixed-delay shifts loop timing by one run's duration per cycle.]** → The analysis is in D3.
  The signing-keys and sessions delta specs state the cadence as "an interval after the previous
  run", so the behaviour is specified, not incidental.
- **[clockwork is v0, and could break its fake clock's API.]** → Only test code imports it, so a
  break costs test edits, never a consumer build. The version is pinned in `go.mod`.
- **[Loop tests on a clockwork fake can race `Advance` against a loop that has not yet called
  `After`.]** → Tests call `BlockUntilContext(ctx, n)` before every `Advance`, with n equal to the
  number of loops that must be parked. D7 and the test plan make this the required pattern.
- **[The change touches about 20 packages and three modules at once.]** → Signature changes are
  mechanical, and the existing tests already cover the behaviour. The migration plan orders the
  work so the tree compiles at each step.

## Migration Plan

This change starts only after `default-identity-store` is archived. That change lands
`password.WithReuseClock(func() time.Time)` under the old convention, and this change migrates it
with every other option in step 2.

1. **Add `pkg/clock`, test-first.** `System()` satisfies both interfaces, and clockwork's real and
   fake clocks satisfy both at compile time. Add clockwork to the layout guard's production-import
   list.
2. **Core packages, grouped by owner.** Switch each option to `clock.Clock`. Move each package's
   tests to clockwork fakes, and keep the nil-refusal cases. Callers of a changed option belong to
   the same unit of work, per the delegation rule.
3. **The two loops.** Move signingkey and the session memory store to `clock.Timed` and `After`,
   test-first: a controlled clock advanced by an interval runs the loop once, with no real waiting.
4. **Driver modules and the `test` module.** Update the `sqlstore`, `pgx` and `gorm` options, the
   suite factories, and the driver tests that call them.
5. **Align the in-flight changes.** Amend the `shared-rate-limiting` and `operations` designs as
   described in the proposal.

**Rollback:** revert the change's commits. Nothing is tagged, and no stored data or schema depends
on the clock's shape.

## References

### Researched (accessed 2026-09-28)

**D1, D3: seam shape, and why the loops use `After`**
- [jonboulle/clockwork `clockwork.go`](https://github.com/jonboulle/clockwork/blob/master/clockwork.go):
  the `Clock` interface. `Now` and `After` have standard-library-only signatures, and
  `NewTicker`, `NewTimer` and `AfterFunc` return clockwork's own types.
- [jonboulle/clockwork `ticker.go`](https://github.com/jonboulle/clockwork/blob/master/ticker.go):
  `Ticker` is `Chan`, `Reset` and `Stop`, which differs from signingkey's current `C` and `Stop`.
- [jonboulle/clockwork repository metadata](https://api.github.com/repos/jonboulle/clockwork):
  Apache-2.0, 729 stars, latest release v0.5.0 on 2025-01-02, and a `go.mod` with no requirements.
  Live figures, read on this date; they drift.

**D5: clockwork as the test fake**
- [jonboulle/clockwork](https://github.com/jonboulle/clockwork): `NewFakeClockAt`, `Advance` and
  `BlockUntilContext` on the fake clock.

**D6: the `sweep` exception**
- [go-co-op/gocron v2 `scheduler.go`](https://github.com/go-co-op/gocron/blob/v2/scheduler.go):
  `WithClock(clock clockwork.Clock)`, and gocron's own `go.mod` requires clockwork v0.5.0.

**D2, D3: amending the convention, and the departure**
- Reasoned from scrty's own settled specs and the established design: the authn-authz-core shared
  clock convention, the signing-keys and sessions specs, and store-conformance's "drive time through
  the store's clock" rule.

### Primary documentation

- [The Go Programming Language Specification: method sets](https://go.dev/ref/spec#Method_sets):
  implementing an interface requires exactly matching method signatures (D1, D3).
- [Go Modules Reference: module graph pruning](https://go.dev/ref/mod#graph-pruning):
  a dependency's test-only imports stay out of a consumer's build (D5).
- [`time.After`](https://pkg.go.dev/time#After): since Go 1.23, unreferenced timers are collected
  even when not stopped (D3).
- [`testing/synctest`](https://pkg.go.dev/testing/synctest): bubble-scoped fake time, with no
  support for external I/O (Context, D4, D7).
