# Tasks

Every task is test-first: write the failing test, run it and see it fail for the intended reason
(a compile error is not a red step), make it pass, then refactor. Each task names how it is
verified. A signature change owns every caller of the changed option, including `_test.go` files
and callers in the driver and `test` modules (D2, migration plan step 2).

## 1. The seam

- [x] 1.1 Add `pkg/clock` with `Clock`, `Timed` and `System()` (D1): tests assert `System()` reads the current time, that its `After` fires after the duration, and compile-time assertions that `clockwork.NewFakeClock()` and `clockwork.NewRealClock()` satisfy both interfaces; godoc names the default and states that `After` must fire once `Now` has advanced by `d`. Verify with `go test ./pkg/clock/...`
- [x] 1.2 Add `github.com/jonboulle/clockwork` to the layout guard's forbidden production imports (`module-layout` delta, D5): first a guard case with a fixture whose production file imports clockwork, seen failing, then the list entry. The core module's requirement arrives with 1.1's test import; the `test` module's arrives in 5.2, the first task there that imports it, since `go mod tidy` drops an unused requirement. Verify with `go test -run 'TestModuleLayout' ./` and `go mod tidy` leaving no diff

## 2. Self-contained read-only components take `clock.Clock` (D2)

These packages have no caller of their clock options outside their own tests, except `password`,
whose `test`-module callers are updated in 5.2.

- [ ] 2.1 `token` and `ratelimit`: replace each package's `Clock` interface with `clock.Clock` in `WithClock`, `VerifyWithClock`, `WithMemoryLimiterClock` and `WithSourceGuardClock`; move their tests to clockwork fakes; keep or add nil and typed-nil refusal cases (`time-source`: absent source). Verify with `go test ./token/... ./ratelimit/...`
- [ ] 2.2 `pkg/id` and `password`: `id.WithClock` and `WithReuseClock` take `clock.Clock`; tests use clockwork fakes, with the default and one consumer-source case per option; nil and typed-nil are refused by `WithReuseClock` and ignored by `id.WithClock`, keeping the system clock (D2). Verify with `go test ./pkg/id/... ./password/...`
- [ ] 2.3 `policy` and `apikey`: `WithMFAPolicyClock`, `WithMFARequirementClock`, `WithLockoutClock` and apikey's `WithClock` take `clock.Clock`; tests move to clockwork fakes and keep nil and typed-nil refusal. Verify with `go test ./policy/... ./apikey/...`

## 3. Components whose callers share `httpsec` tests (D2, D3)

These options are called from the same `httpsec` and `magiclink` test files, so they change together,
with those callers.

- [ ] 3.1 `onetime`: the manager's `WithClock` and `WithMemoryStoreClock` take `clock.Clock`, with `magiclink`'s test callers; tests cover the `time-source` scenarios "Consumer time source" and "Absent source on a constructor that cannot fail" on the in-memory store, and nil and typed-nil refusal by the manager. Verify with `go test ./onetime/... ./magiclink/...`
- [ ] 3.2 `oidc`: `WithClock`, `WithBrokerClock`, `WithHandoffClock` and `WithMemoryFlowStoreClock` take `clock.Clock`, with their `httpsec` test callers; tests move to clockwork fakes and keep nil and typed-nil refusal. Verify with `go test ./oidc/...`
- [ ] 3.3 `session` manager and `mfa`: session's `WithClock`, TOTP's `WithClock` and `WithResetClock` (and the throttle's internal clock, fed from them) take `clock.Clock`, with their `httpsec` test callers; nil and typed-nil are refused except by `WithResetClock`, which keeps the system clock (D2), covering the `time-source` scenario "Nil time source"; session's hand-rolled `testClock` is replaced by a clockwork fake. Verify with `go test ./session/... ./mfa/...` (`httpsec`'s tests compile again after 3.4)
- [ ] 3.4 `session` in-memory store: `WithMemoryStoreClock` takes `clock.Timed`, still keeping the system clock for nil and typed nil (D2), and housekeeping waits on its `After` instead of `time.NewTicker`. Red first: `sessions` scenario "Housekeeping on a controlled time source"; keep "Double start and stop" with no housekeeping left running. Verify with `go test -race ./session/... ./httpsec/...`

## 4. The signing-key loops take `clock.Timed` and wait on `After` (D3)

- [ ] 4.1 `signingkey`: `WithClock` takes `clock.Timed`; remove `Clock`, `TickerClock`, `Ticker` and `realTicker`. Red first: with a clockwork fake, `BlockUntilContext` then `Advance` by one interval runs rotation, reload and housekeeping each once with no real waiting (`signing-keys` scenarios "Controlled time" and "Controlled reload"), and a run's next start is one interval after it finishes ("Interval measured from the end of a run"). Replace the `Eventually` waits in the loop tests. Verify with `go test -race ./signingkey/...`
- [ ] 4.2 `signingkey`: a jump of several intervals runs each task once and then waits a full interval (`time-source` "A long jump runs once"); start, stop and double-start still leave no goroutine. Verify with `go test -race -count=3 ./signingkey/...`

## 5. Sealing, driver adapters and conformance suites (D2, D4)

- [ ] 5.1 `seal`, `sqlstore`, `pgx` and `gorm`: seal's `WithClock` and each driver's `WithClock` take `clock.Clock`, with nil and typed-nil refusal, and the drivers' `mfa.go` hand their clock to seal unchanged; the packages' own tests move to clockwork fakes. Verify with `go test ./seal/... ./sqlstore/...` in the core module and `go test ./...` in `pgx` and `gorm`
- [ ] 5.2 `test` module: clockwork becomes a requirement of the module; the session, one-time, flow and handoff suite factories receive `clock.Clock`, and each suite passes a clockwork fake and advances it instead of building closures (`store-conformance`: time driven through the store's clock); update every caller in the module, including the identity-reuse, cross-backend and driver tests. Verify with `go test ./...` in the `test` module (needs Docker)

## 6. Close out

- [ ] 6.1 No `func() time.Time` clock option and no per-package `Clock` interface remains in production code across all modules: verify by a gopls workspace-symbol search for `Clock` and an `rg -n 'func\(\) time\.Time' --glob '!*_test.go' --glob '!.claude/.legacy'` returning only unexported internals that are fed from a `clock.Clock`
- [ ] 6.2 Align the in-flight changes (migration plan step 5): amend the `shared-rate-limiting` design's `WithAppClock` to take `clock.Clock`, and record in the `operations` design that `sweep`'s `WithClock(clockwork.Clock)` is the one place a clockwork type crosses a scrty API (D6). Verify with `openspec validate shared-rate-limiting --strict` and `openspec validate operations --strict`
- [ ] 6.3 Final gate across every module in `go.work`: `go build ./...`, `go vet ./...`, `gofmt -l .` empty, `go test -race ./...` green, and `openspec validate clock-seam --strict`; then one whole-branch review against every requirement in this change's four spec deltas
