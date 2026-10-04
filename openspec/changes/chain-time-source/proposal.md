## Why

The HTTP security chain is the one scrty component with no time-source option. Its interceptors read the wall clock directly, and so do the components it builds for itself: the MFA challenge managers and their default store, the source guards' limiters, and the recoverer. A consumer whose session manager, token issuer or one-time stores run on a controlled clock cannot drive the chain with the same clock. Its own tests work around that with `testing/synctest` bubbles and a test-only recovery clock seam. `time-source` now requires that a component's built-in defaults read its own source, and the chain cannot meet that until it has one.

Separately, the chain already refuses a second account recovery at construction, but the `http-security-chain` spec's list of wiring mistakes does not name it, unlike a second form login, Basic or MFA.

## What Changes

- Add a chain time-source option, `httpsec.WithClock(clock.Clock)`. It defaults to the system clock and is refused when absent or typed-nil.
  - Every chain interceptor reads the time from it: form login, Basic, bearer, MFA begin and verify, API keys, magic link, OIDC login, MFA enrolment, passwordless login, account recovery and its cool-down.
  - Every time-keeping component the chain builds for itself receives it: the MFA challenge managers and their default store, the MFA verification throttle, the source guards and the limiters the chain's default factory builds, and the recoverer.
  - Dependencies the consumer builds and hands to the chain keep their own clocks (session manager, token issuer, a consumer's limiter factory or challenge store, a recovery core given its own `recovery.WithClock`). The option's documentation says so, because a chain clock that differs from those is the consumer's wiring choice.
- Remove the test-only `WithRecoveryClockForTest` seam and the `synctest` workarounds that exist only because the chain had no clock. Tests drive the chain with the new option.
- Record in `http-security-chain` that enabling account recovery more than once is a construction error. The code and its test already do this; only the spec is missing it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-security-chain`:
  - a new requirement: the chain reads time from one replaceable time source, and passes it to the time-keeping components it builds;
  - "Wiring mistakes fail at construction" gains "account recovery enabled more than once".

## Impact

- **Code, core module:** `httpsec` (a new option, its plumbing to every interceptor's `now` and to the components the chain builds, and tests). `mfa` gains one additive option, `mfa.WithVerifyClock`, because the verification throttle had no way to be given a clock. `ratelimit`, `onetime` and `recovery` are only called with their existing clock options.
- **API:** two new public options, `httpsec.WithClock` and `mfa.WithVerifyClock`. A test-only seam is removed. No breaking change: the default is the system clock, as today.
- **Depends on:** `time-source` (the clock contract and its rule for built-in defaults), `http-security-chain`, `multi-factor-auth`, `account-recovery`, `rate-limiting`.
- **Consumers:** none yet; nothing is tagged.
