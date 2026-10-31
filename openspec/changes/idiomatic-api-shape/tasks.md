# Tasks

The behaviour changes (D3–D6) are test-first. Each spec scenario is written as a failing test, seen to fail for the intended reason, and only then implemented.

The signature-only decisions (D1, D2, D7, D8) change no observable behaviour. Under the old signatures the only possible red step is a compile error, which does not count as one. They are therefore verified like a refactor: the existing tests of the behaviour must pass unchanged, a compile-time check must hold for each port, and the godoc must be updated. Every group updates every caller of what it changes, in every module (production code, tests, examples and `README.md`), and its own godoc.

Some scenarios pin behaviour the code already has ("Keys served after shutdown", "Store serves after shutdown", "Purge outlasts the stop timeout"). They cannot fail first on the current code. Each is written, seen to pass, and then shown to test something by temporarily breaking the behaviour and watching it fail (`golang-tdd.md`).

## 1. Preconditions

- [x] 1.1 Confirm that `restructure-layout` is merged into `main` and archived, and start the branch from that `main`. Verify: `openspec list` no longer shows `restructure-layout`, `go list ./...` shows the post-restructure paths, and `make check` passes (everything but the Docker suites).

## 2. Concrete constructor types and the shared flush interface (D1, D2)

- [x] 2.1 Add `logsample.Flusher`. Replace `authenticate.RefusalLogFlusher`, `policy.RefusalLogFlusher` and `oidc`'s anonymous interface with it in all three probes (`policy.Engine`, `httpsec`, `oidc.RelyingParty`). Verify: the existing flush tests in `policy`, `authenticate`, `httpsec` and `oidc` pass unchanged, and `rg 'RefusalLogFlusher'` finds no declaration.
- [x] 2.2 Make the aggregators join errors (D2):
  - first change `policy.Engine.FlushRefusalLogs` and `httpsec.Chain.FlushRefusalLogs` to return `error`, returning nil, so that the tests compile;
  - red: a registered policy, and a consumer authenticator given to the chain, whose flush returns an error. Assert that the engine and the chain return an error matching it, and that every other flusher was still called. Run and confirm the error assertions fail because nil is returned;
  - implement `errors.Join`, and update every caller, which now handles or explicitly discards the error.

  Verify: the new tests pass, the existing flush tests pass, and `golangci-lint` reports no unchecked flush error.
- [x] 2.3 Return `*UsernamePasswordAuthenticator` and `*JWTAuthenticator` from `authenticate`, and `*MFA` and `*MFARequirement` from `policy`. Each gets a compile-time port check, and its godoc loses the type-assertion advice. `README.md`'s `requirement.(policy.LoginAdmission)` becomes a direct method call. Verify: `go test ./authenticate/... ./policy/... ./httpsec/...` passes, and the tests that type-asserted now call `FlushRefusalLogs` directly.
- [x] 2.4 Return `*BcryptEncoder`, `*ScryptEncoder` and `*Argon2idEncoder` from `password`; `*JWTGenerator` and `*JWTVerifier` from `token`; `*StaticKeyring` and `*AEADCipher` from `seal`; and `*MemoryKeyStore` from `signingkey`. Each gets a compile-time port check. Every type renamed in 2.3 and 2.4 gets godoc saying its zero value is not usable and naming its constructor. No method is unexported, because D1's table shows each is reachable through a port or optional interface already. Verify: `go test ./...` passes in every module, and the exported method set of each type matches D1's table.
- [x] 2.5 Make `authenticate.FirstOf` a `logsample.Flusher` (D2). Red:
  - form login wired with a `FirstOf` around the password authenticator, whose sampler holds suppressed refusals; assert that `Chain.FlushRefusalLogs` writes their summary;
  - a `FirstOf` whose first delegate's flush fails; assert the error is returned and that later delegates are still flushed. This case asserts through `logsample.Flusher`, so it fails on the assertion, not on compiling.

  Run them and confirm they fail because `FirstOf` does not flush. Then add the method, joining errors in delegate order, with a compile-time check. Verify: the new tests pass, and so do `go test ./authenticate/... ./httpsec/...`.

## 3. Memory stores refuse bad options (D3)

- [x] 3.1 Red: write the `one-time-tokens` scenarios "Nil time source" and "Consumer time source", run them, and confirm "Nil time source" fails because a store is returned. Include a typed-nil time source. Then make `onetime.NewMemoryStore` return `(*MemoryStore, error)`, and pass its error up through the four places that build it as a default: `onetime.New`, `passkey.New`, the recovery hold store (`recovery/hold.go`) and `httpsec`'s `EnableMFA` set-up (`httpsec/mfa_begin.go`). Verify: both scenarios pass, and so do the existing suites of `onetime`, `passkey`, `recovery` and `httpsec`.
- [x] 3.2 Red: write the `sessions` scenario "Invalid housekeeping configuration" (interval zero, a nil clock and a typed-nil clock), run it, and confirm it fails because a store is returned. Then make `session.NewMemoryStore` return `(*MemoryStore, error)`, and pass its error up through `session.New`. Verify: the scenario passes, and so do the existing housekeeping scenarios.
- [x] 3.3 Red: write the `security-policy` scenario "Capacity of zero", run it, and confirm it fails with a panic. Then make `lockout.NewMemoryAttemptStore` return `(*MemoryAttemptStore, error)` without panicking, with an error wrapping `policy.ErrConfig`, and pass its error up through `lockout.New`. Verify: the scenario and "Consumer capacity" pass.

## 4. One lifecycle (D4)

- [x] 4.1 Red: write the `signing-keys` scenarios:
  - "Double start" (the second start fails);
  - "Cancelled start context";
  - "Start after shutdown";
  - "Consumer bounds the shutdown";
  - "Shutdown twice";
  - "Stop before start";
  - a shutdown whose context is already done, on a manager whose work has ended, returns nil (design D4, completion wins).

  Run them and confirm each fails for the scenario's reason. Pin "Keys served after shutdown" as the header describes. Then replace `Keys.Stop()` with `Shutdown(ctx)`, detach the work's context, and add `ErrAlreadyStarted` and `ErrAlreadyShutdown`. The godoc of `Start` loses the restart paragraph, and the godoc of `Shutdown` warns against calling it from an error hook. Verify: every `signing-keys` lifecycle scenario passes under `-race`, and `goleak` finds no goroutine left behind.
- [x] 4.2 Red: write the `sessions` scenarios "Cancelled start context", "Double start and stop" and "Start after shutdown", and a shutdown bounded by its context during a slow sweep, followed by a later shutdown that waits again. Run them and confirm they fail. Pin "Store serves after shutdown". Then apply the same lifecycle to `session.MemoryStore`, and remove the restart paragraph from its godoc. Verify: as in 4.1.
- [x] 4.3 Red: write the `expiry-sweeping` scenarios "Cancelled start context", "Shutdown cancels a running purge" and "Consumer bounds the shutdown". Run them and confirm "Cancelled start context" fails. Pin "Purge outlasts the stop timeout". Then detach `Sweeper`'s run context, keeping `WithStopTimeout` and the shared shutdown result. Verify: every "starts and stops cleanly" scenario passes under `-race`.
- [x] 4.4 Red: write the `email-notification` scenarios "Close drains" (with the shut-down error), "Shutdown bounded by its context", "Shutdown twice" and "Sends racing shutdown" (under `-race`). Run them and confirm they fail; a racing case that passes on the current code is pinned as the header describes. Then replace `QueuedSender.Close` with `Shutdown`, and `ErrSenderClosed` with `ErrAlreadyShutdown`. `notify` declares no `ErrAlreadyStarted`. Verify: every queued-sender scenario passes.
- [x] 4.5 Red: write a test that `Start` with a nil context returns the configuration error and starts nothing, for `Keys` and `session.MemoryStore`, and that `Shutdown` with a nil context returns the configuration error and changes nothing, for `Keys`, `session.MemoryStore` and `QueuedSender`. Run them and confirm they fail. Then implement the refusal. `Sweeper` already refuses both, and its existing tests stay as they are. Verify: the tests pass.

## 5. Guards declare their authorizer (D5)

- [x] 5.1 Red: write the `http-security-chain` scenarios "Guards built with no authorizer" (a plain nil and a typed nil), "Consumer relies on the chain's authorizer", "Typed-nil authorizer beside the declared reliance" and "Declared reliance with no chain authorizer". Run them and confirm the first fails because construction succeeds. Then make `httpsec.NewGuards` return `(*Guards, error)`, add `WithChainAuthorizer()`, detect a typed nil with `internal/nilcheck`, and store a typed nil as no fallback. Rewrite the godoc that says there is nothing to misconfigure. Verify: the three scenarios and the existing guard tests pass.
- [x] 5.2 Red: write the `framework-adapters` scenarios "fiber guards built with no authorizer", "gin guards rely on the chain" and "fiber guard refusal reaches the consumer's error handler". Run them and confirm the first fails. Then apply the same construction rule to `ginsec.NewGuards` and `fibersec.NewGuards`, adding `fibersec.GuardOption`. Verify: the scenarios pass in both adapter modules.

## 6. Nil contexts (D6)

- [x] 6.1 Red: write tests that `httpsec.NewExchange(nil, …)` and `Exchange.SetContext(nil)` panic with messages naming the function. Run them and confirm they fail, because today the first substitutes and the second ignores. Then implement the panics, and remove the `contextcheck` exemption. Verify: the tests pass, and every adapter test still passes.

## 7. Required dependencies and default scopes (D7, D8)

- [x] 7.1 Introduce `OIDCDeps` and change `EnableOIDCLogin` to take it. Its rules move with the fields unchanged: a nil `RelyingParty` is refused, and `Handoff` is required unless `WithOIDCCallbackSuccess` is given, and must then be nil. These checks already exist, so this is a signature refactor with no red step. `EnableRecoveryCooldown` is unchanged (design D7). Verify: the existing OIDC tests pass on the new signature, including those for a missing handoff, for `WithOIDCCallbackSuccess` with a nil handoff, and for one given with a handoff.
- [x] 7.2 Replace `var DefaultScopes` with `func DefaultScopes() []string`, which returns a new slice. Verify: the existing registry tests pass, and a new test that changes the returned slice shows the next call unaffected.

## 8. Final integration

- [x] 8.1 Sweep the godoc, examples and README for the old signatures and names, excluding `openspec/` and `.claude/.legacy`:
  - `Stop()`, `Close(ctx)`, `ErrSenderClosed`, `RefusalLogFlusher`, and `DefaultScopes` as a variable;
  - type assertions onto the twelve ports or the optional interfaces (for example `.(policy.LoginAdmission)`);
  - prose that still says stop, close, restart or idempotent start for the four lifecycle owners (for example `token/signingkey/doc.go`);
  - the claim that guards have nothing to misconfigure.

  Verify: a search for each finds no stale use.
- [ ] 8.2 Run the whole-branch review against the eight deltas and D1–D8. Then run `make check`, push, and confirm CI is green, including the Docker suites, and `openspec validate idiomatic-api-shape --strict`. Verify: a clean review, a green CI run on the final head, and a valid change.

## 9. Review follow-ups

The pull request's code review found these, and the user chose on 2026-10-31 to fold all but one into this change. The declined one is recorded in design D5. Task 8.2 closes only after this group lands, with a fresh review of it and green CI.

- [x] 9.1 Red: a `QueuedSender` whose logger blocks while a `Send` to a full queue logs the drop; `Shutdown` with a short context returns that context's error within its bound. Run it and confirm it fails because `Shutdown` waits for the lock. Then make `Send` decide under the lock and log after releasing it. Verify: the test passes under `-race`, and so do the queued-sender scenarios.
- [x] 9.2 Move D4's shutdown wait (completion wins a tie, then wait under the context) into one internal helper that the four `Shutdown` methods share. Each keeps its current result: `sweep` still wraps the context's error, and the other three return it as it is. The struct fields named `lifecycle` become `lifecycleMu`, so they do not read as the new package. This is a refactor with no red step. The sweeper's tests gain the completion-wins case and the wrapping assertion that the other three already had. Verify: every existing lifecycle test passes unchanged under `-race`.
- [x] 9.3 Move D5's construction rule and the authorizer resolution of guards into one internal helper that `httpsec`, `ginsec` and `fibersec` share. Each package keeps its error text and the request-time typed-nil check. This is a refactor with no red step. Verify: every existing guard test passes unchanged in the three modules.
- [x] 9.4 Small fixes:
  - `EnableOIDCLogin`'s errors name the `OIDCDeps` fields (`RelyingParty`, `Handoff`) instead of "an OIDC manager" and "a handoff manager";
  - the godoc of `notify.ErrConfig`, `signingkey.ErrConfig` and `session.ErrConfig` includes the lifecycle methods that now return them;
  - a table test for `internal/must`, seen to fail against a broken `Must`;
  - `FirstOf.FlushRefusalLogs` collects only non-nil errors, as the other aggregators do;
  - the default scopes are copied once, not twice, when a registry is built.

  Verify: the affected suites pass.

## Workflow follow-up

- Archive with `/opsx:archive` after merge, which syncs the eight deltas into the main specs.
- Explore `key-port-context` next.
- Open the pull request only when the user asks for it.
