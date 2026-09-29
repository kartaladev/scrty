# Proposal

## Why

Time reaches scrty's components through three different shapes:

- about 25 `func() time.Time` options;
- three per-package `Clock interface{ Now() time.Time }` types (token, ratelimit, signingkey);
- a `TickerClock` with its own `Ticker` for the signing-key loops.

The in-memory session store's housekeeping loop cannot be driven by any of them.

Tests therefore each hand-roll their own fake: frozen closures, a mutex-guarded `testClock`, and a
ticker-counting clock. The signing-key tests wait on real time with `Eventually`.

A consumer who already uses the widely adopted `github.com/jonboulle/clockwork` fake clock cannot
pass it to the loops without an adapter.

One scrty-owned seam fixes this, and needs no production dependency. Its methods are the subset of
clockwork's `Clock` that scrty reads, with identical signatures, so a clockwork clock satisfies it
directly. Nothing is tagged yet, so the API can change without a compatibility cost.

## What Changes

- **New `pkg/clock` package**, with no dependencies beyond the standard library:
  - `Clock` (`Now`), for components that only read the time;
  - `Timed` (`Clock` plus `After`), for components that run background loops;
  - the system clock as the shared default.
- **BREAKING:** every `func() time.Time` clock option takes a `clock.Clock` instead. This covers
  `WithClock`, `With<Component>Clock` and `WithMemoryStoreClock` across session, onetime, apikey,
  mfa, policy, oidc, password, seal and pkg/id, and the sqlstore, pgx and gorm adapters.
- **BREAKING:** the per-package `Clock` interfaces in token and ratelimit are replaced by `clock.Clock`.
- **BREAKING:** signingkey's `Clock`, `TickerClock` and `Ticker` are removed. Its `WithClock` takes a
  `clock.Timed`, and the rotation, reload and housekeeping loops wait on `After`, which makes them
  fixed-delay instead of fixed-rate.
- **The in-memory session store's housekeeping** is paced by its time source, which becomes a
  `clock.Timed`. Advancing a controlled clock runs housekeeping without real waiting.
- **BREAKING:** the conformance suites' store factories receive a `clock.Clock` instead of a
  `func() time.Time`.
- **clockwork becomes the project's fake clock** in tests, replacing the hand-rolled fakes. It is
  the documented choice for consumers. Core production code never imports it. The layout guard
  enforces this as it does for testify.
- **Amends the clock convention** that the authn-authz-core design established
  (`WithClock(func() time.Time)`, default `time.Now`). The nil-clock-is-a-configuration-error rule
  stays.

## Capabilities

### New Capabilities

- `time-source`: the cross-cutting contract for how scrty components read and wait on time:
  - one replaceable time source per component, defaulting to the system clock;
  - a nil source is a configuration error;
  - background loops are paced by the same source, so a controlled clock drives them without real
    waiting.

### Modified Capabilities

- `signing-keys`: the time source also paces reload, as it already paces rotation and housekeeping,
  and it is always used to pace them (today that is optional). Loops wait a full interval after each
  run instead of ticking at a fixed rate.
- `sessions`: the in-memory store's housekeeping is paced by the store's time source rather than a
  real ticker.
- `module-layout`: the dependency check that keeps test tooling out of the core module's production
  build also forbids clockwork.

## Impact

- **Code:**
  - production: every package listed above, and the `test` module's `storetest` and `oidc` suites;
  - tests: roughly 25 test files that build clock closures or hand-rolled fake clocks.
- **API:** breaking signature changes to every clock option, to signingkey's clock types and to the
  suite factories. Nothing is tagged yet.
- **Dependencies:**
  - `github.com/jonboulle/clockwork` becomes a test-only requirement of the core module and the
    `test` module, alongside testify. It has no dependencies of its own.
  - Production builds are unchanged.
  - The `sweep` module in the `operations` change already takes `clockwork.Clock`, because gocron v2
    requires it.
- **Active changes to align:**
  - `default-identity-store` is completed first, under the old convention. Its
    `WithReuseClock(func() time.Time)` is migrated here with every other option;
  - `shared-rate-limiting` designs `WithAppClock(func() time.Time)`;
  - `operations` needs its `sweep` clock recorded as the one place a clockwork type crosses a scrty
    API.

## References

### Researched (accessed 2026-09-28)

**Seam shape: scrty-owned subset satisfied by clockwork**
- [jonboulle/clockwork `clockwork.go`](https://github.com/jonboulle/clockwork/blob/master/clockwork.go):
  the 8-method `Clock` interface. `Now` and `After` use only standard-library types, so a subset
  interface is satisfied structurally.
- [jonboulle/clockwork `ticker.go`](https://github.com/jonboulle/clockwork/blob/master/ticker.go):
  `NewTicker` returns clockwork's own `Ticker` (`Chan`, `Reset`, `Stop`). No scrty-declared ticker
  method can match it without importing clockwork, which is why the loops wait on `After`.
- [jonboulle/clockwork repository metadata](https://api.github.com/repos/jonboulle/clockwork):
  Apache-2.0, 729 stars, latest release v0.5.0 on 2025-01-02, and a `go.mod` with no requirements.
  Live figures, read on this date; they drift.

**Operations exception: `sweep` takes `clockwork.Clock`**
- [go-co-op/gocron v2 `scheduler.go`](https://github.com/go-co-op/gocron/blob/v2/scheduler.go):
  `WithClock(clock clockwork.Clock)`, and gocron's own `go.mod` requires clockwork v0.5.0.

### Primary documentation

- [The Go Programming Language Specification: method sets and interface implementation](https://go.dev/ref/spec#Method_sets):
  a type implements an interface only when its method signatures match exactly, including named
  result types.
- [Go Modules Reference: module graph pruning](https://go.dev/ref/mod#graph-pruning):
  a dependency's test-only imports are not built into a consumer's program.
- [`testing/synctest`](https://pkg.go.dev/testing/synctest): fake time inside a bubble, with no
  support for external I/O. That limit is why store conformance suites need an injected clock.
