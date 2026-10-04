## Context

See proposal.md for why. The current state:

- **The chain reads the wall clock directly.** Each built-in interceptor sets `now: time.Now` at construction: form login, Basic, bearer, MFA, API keys, magic link, OIDC login, MFA enrolment, passwordless login, account recovery and its cool-down. Sampled refusal logs take the same `now()` reading.
- **The chain builds components on the system clock.**
  - The MFA interceptor builds one one-time manager per challenge method, all over one default store (`wireChallenges`). It passes no clock, so the managers and the store read the system clock.
  - `EnableAccountRecovery` builds the `recovery.Recoverer` from the consumer's `WithRecoveryCore` options and adds no clock.
  - The source guards and, when the consumer gives no factory, the limiters behind them come from the chain's default rate-limit factory, which is built without a clock.
- **Every one of those components already takes `clock.Clock`:** `onetime.WithClock`, `onetime.WithMemoryStoreClock`, `recovery.WithClock`, `ratelimit.WithSourceGuardClock`, `ratelimit.WithMemoryLimiterClock`. No signature outside `httpsec` changes.
- **Workarounds in the tests:** a test-only `WithRecoveryClockForTest` seam (`httpsec/export_test.go`), and `testing/synctest` bubbles in the MFA begin, verify and expiry tests, whose comments say they exist because the chain has no clock option.
- **`time-source` rules this change must meet:**
  - one source per component, defaulting to the system clock;
  - an absent or typed-nil source is a configuration error;
  - a default dependency the component builds for itself reads the same source;
  - a component that only reads the time does not require a source that can wait.
- **The established design's chain had no time-source option either.** This change adds one because `time-source` now requires built-in defaults to follow their owner's clock (operation-hardening, decision 8), which the chain cannot do without a clock of its own.

## Goals / Non-Goals

**Goals:**
- A consumer can drive everything the chain itself does with time from one controlled source, with no real waiting.
- Nothing changes for a consumer who sets no clock.

**Non-Goals:**
- Reaching into dependencies the consumer builds. Their clocks are the consumer's wiring; the chain neither replaces nor checks them.
- Pacing background work. The chain runs no loop of its own, so it needs no source that can wait.
- Changing any `time-source` requirement. Once the chain offers the option, the existing requirements apply to it as written.

## Decisions

### 1. One chain option, `WithClock(clock.Clock)`

```go
// WithClock sets the time source the chain and the components it builds
// read. Default: clock.System().
func WithClock(c clock.Clock) Option
```

- **Default:** `clock.System()`.
- **Override:** `WithClock` with the consumer's source; any `clockwork` clock satisfies `clock.Clock` with no adapter.
- **Type:** `clock.Clock`, not `clock.Timed`, because the chain only reads the time (`time-source`: a component that only reads the time SHALL NOT require a source that can wait).
- **Refusal:** nil or typed-nil (checked with `internal/nilcheck`) is a configuration error naming `WithClock`, as `time-source` requires. It never falls back to the system clock.
- **Name:** the chain's options are named for what they govern. This one governs the chain's time, so it is `WithClock`, matching the other components' option of the same name.
- **Alternative rejected: one clock option per interceptor.** Twelve options for one concern, and a consumer who forgot one would run two clocks in one chain without noticing.

### 2. Interceptors read the chain's clock at assembly

Each built-in interceptor's `now` is set from the chain's clock when the chain is assembled, after every option has run. That way `WithClock` given after an `Enable...` option still takes effect, honouring "every public option SHALL either take effect or be refused at construction".

- **Alternative rejected: reading the clock when each `Enable...` option runs.** It would make the result depend on option order, so a `WithClock` placed last would silently not apply to interceptors enabled before it.

### 3. The chain's clock goes first; a consumer's own clock wins

Where the chain builds a component from options the consumer can also supply, it puts its own clock option **first**, before the consumer's:

- the recoverer: `recovery.WithClock(chainClock)` is placed before the `WithRecoveryCore` options, so a consumer's `recovery.WithClock` (applied later) overrides it;
- the MFA challenge managers and their default store: built with the chain's clock. A store given with `WithMFAChallengeStore` keeps its own;
- the default rate-limit factory and the source guards: the guards and the limiters that factory builds get the chain's clock. A factory given with the chain's rate-limiter factory option keeps its own.

- **Default:** every component the chain builds reads the chain's clock.
- **Override:** the component's own clock option, or a consumer-built store or factory.
- **Why option order rather than detection:** scrty's functional options apply in order, and a later option wins. Prepending the chain's clock gives the consumer's explicit choice precedence with no need to inspect option values.
- **Stated limit:** a chain clock that differs from the clock of a dependency the consumer built (session manager, token issuer, a consumer factory or store, a recovery core with its own clock) is allowed and documented on `WithClock`. The chain cannot see those clocks, and refusing a mismatch would need every dependency to expose its clock.

### 4. Tests drive the chain with the option

- `WithRecoveryClockForTest` is removed. Its users move to `WithClock`.
- The `synctest` bubbles whose comments say they exist because the chain has no clock option move to a `clockwork` fake given through `WithClock`. A bubble that serves another purpose, such as asserting no goroutine outlives a request, stays.

### 5. The spec records the recovery refusal

A second `EnableAccountRecovery` is already refused (`httpsec/recoveryoptions.go`, pinned by the "enabled twice" row of `recoveryoptions_test.go`). The `http-security-chain` wiring list gains the line and a scenario. No code changes for this part.

### 6. Test-first

- **The default:** a chain built without `WithClock` measures challenge expiry from the system time.
- **The override, per area:**
  - MFA challenge expiry on a controlled clock;
  - the MFA expiry task purging after the source passes the issuance window;
  - a password-login throttle window resetting when the source passes it;
  - recovery codes expiring on the chain's clock;
  - a recovery core with its own clock keeping it.
- **Order independence:** `WithClock` given last still reaches interceptors enabled before it.
- **Refusals:** nil and typed-nil.
- **Removed workaround:** each converted `synctest` test is shown to fail with the clock wiring removed.

## Risks / Trade-offs

- [A consumer sets a chain clock but forgets their session manager's] → Documented on `WithClock`. Mismatched clocks are a test-wiring mistake, never a production one, because production runs both on the system clock.
- [An interceptor added later reads `time.Now` directly] → A test sweeps the chain: with a controlled clock far from the system clock, it drives each built-in interceptor through a time-dependent path. In code review, a direct `time.Now` in `httpsec` non-test code is a finding.
- [Prepending the clock relies on later options winning] → That is the documented behaviour of every scrty option set involved. The test "a recovery core with its own clock keeps it" pins it.

## Migration Plan

Not applicable: the option is new, its default is today's behaviour, and nothing is tagged.

## References

Reasoned from scrty's own settled specs (`time-source`, `http-security-chain`, `account-recovery`, `rate-limiting`) and the established design, whose chain likewise had no time-source option.
