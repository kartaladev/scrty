# Tasks

Every task is test-first: write the failing test, run it and see it fail for the intended reason (a
compile error is not a red step), make it pass, then refactor (consider `/simplify`). Tables follow
the project's `table-test` skill. Clocks in tests are `clockwork` fakes given through the new option.
Names in parentheses are the spec requirements and design decisions covered.

All work is in `httpsec/`, so the groups run in order in one lane. Groups 1–2 and group 3 are
separate dispatches.

## 1. The option and the interceptors (decisions 1, 2; "The chain reads time from one replaceable time source", scenarios "System clock by default", "Absent time source")

- [x] 1.1 `httpsec.WithClock(clock.Clock)`, default `clock.System()`. Nil and typed-nil fail construction with `ErrConfig` naming `WithClock`. Godoc names the default, says the components the chain builds read it, and says dependencies the consumer builds keep their own clocks. Tests: a refusal table (nil, typed nil, valid); "System clock by default" (a challenge begun without the option expires relative to the system time). Verify with `go test -race -run 'TestWithClock' -count=1 ./httpsec/`
- [x] 1.2 Every built-in interceptor's `now` comes from the chain's clock, set at assembly after all options ran: form login, Basic, bearer, MFA, API keys, magic link, OIDC login, MFA enrolment, passwordless login, recovery and its cool-down. Tests: a table with one row per interceptor, each driving a time-dependent path under a controlled clock far from the system clock; a row giving `WithClock` after the `Enable...` option, proving order independence. A grep in the test (or a vet-style check) shows no `time.Now` remains in non-test `httpsec` code outside the default. Verify with `go test -race -run 'TestChain_Clock' -count=1 ./httpsec/`

## 2. The components the chain builds (decision 3; scenarios "Consumer time source drives the chain's own state", "A throttle window follows the chain's source", "A consumer's dependency keeps its own source")

- [x] 2.1 The MFA challenge managers and their default store read the chain's clock; a store given with `WithMFAChallengeStore` keeps its own. Tests: a challenge begun on a controlled clock is refused as expired after the source passes its lifetime, with no `synctest`; the `mfa-challenges:<method>` expiry task removes it after the source passes the issuance window. Verify with `go test -race -run 'TestChain_ClockMFA' -count=1 ./httpsec/`
- [x] 2.2 The source guards, and the limiters the chain's default factory builds, read the chain's clock; a factory given with `WithRateLimiterFactory` keeps its own. Test: with a controlled clock and the default factory, a source refused for password-login failures is no longer refused after the source passes the window. Verify with `go test -race -run 'TestChain_ClockThrottle' -count=1 ./httpsec/`
- [x] 2.3 The recoverer receives `recovery.WithClock(chainClock)` ahead of the `WithRecoveryCore` options, so a consumer's own `recovery.WithClock` wins. Tests: recovery codes issued through the chain expire on the chain's clock; with a different `recovery.WithClock` in `WithRecoveryCore`, they expire on that one instead. Verify with `go test -race -run 'TestChain_ClockRecovery' -count=1 ./httpsec/`

- [x] 2.4 `mfa.WithVerifyClock(clock.Clock)` (default `clock.System()`, nil and typed-nil refused) sets the clock the verification throttle's default limiter and refusal-log sampling read; the chain passes `mfa.WithVerifyClock(chainClock)` ahead of the consumer's throttle options. Tests in `mfa`: a refusal table and a throttle window that follows the given clock. Tests in `httpsec`: with no `WithMFAVerifyLimiter`, a user throttled for wrong codes may answer again after the chain's clock passes the window (scenario "The second-factor verification throttle follows the chain's source"); the throttle's refusal log is sampled on the chain's clock. Verify with `go test -race -run 'TestVerifyThrottle|TestWithVerifyClock' -count=1 ./mfa/` and `go test -race -run 'TestChain_ClockMFAVerify' -count=1 ./httpsec/`
- [x] 2.5 `httpsec.WithClock`'s godoc names what follows the chain's clock (interceptors and their log sampling, MFA challenge managers and default store, the verification throttle, source guards, the default factory's limiters including the IPv6 aggregate and enrolment limiters, the recovery core unless its own `recovery.WithClock` is given) and what keeps its own (session manager, token issuer, a consumer's challenge store, limiter factory or limiters, and the managers the consumer builds), and says mismatched clocks are allowed and not checked. `TestChain_ClockRecovery` gains a row showing recovery hold tokens expire on the chain's clock, and keep a recovery core's own clock. Verify with `go doc ./httpsec WithClock` and `go test -race -run 'TestChain_ClockRecovery' -count=1 ./httpsec/`

## 3. Retire the workarounds and record the refusal (decisions 4, 5; "Wiring mistakes fail at construction", scenario "Account recovery enabled twice")

- [x] 3.1 Remove `WithRecoveryClockForTest` from `httpsec/export_test.go` and move its users to `WithClock`. Convert the `synctest` bubbles whose comments say they exist because the chain has no clock option (`mfabegin_test.go`, `expiry_test.go`, and any other found) to a `clockwork` fake given through `WithClock`. Keep any bubble serving another purpose, and say why. For each converted test, show it fails when the chain's clock wiring for that component is removed. Verify with `go test -race -count=3 ./httpsec/...`
- [x] 3.2 Confirm the existing "enabled twice" row in `httpsec/recoveryoptions_test.go` pins the spec scenario "Account recovery enabled twice": the error is `ErrConfig` and names account recovery. Tighten the assertion if it checks less, test-first: an assertion on the message must be seen to fail against a changed message first. Verify with `go test -race -run 'TestEnableAccountRecovery' -count=1 ./httpsec/`

## 4. Integration

- [x] 4.1 Whole-workspace gate: `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module of `go.work` (Docker running), and `gofmt -l` empty. Verify by every command's output.
- [x] 4.2 Whole-branch review against every requirement and scenario of `specs/http-security-chain/spec.md` and design decisions 1–7. Verify by the review reporting no open finding.
