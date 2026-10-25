# Tasks

The behaviour changes (D3–D6) are test-first. Each spec scenario is written as a failing test, seen to fail for the intended reason, and only then implemented.

The signature-only decisions (D1, D2, D7, D8) change no observable behaviour. Under the old signatures the only possible red step is a compile error, which does not count as one. They are therefore verified like a refactor: the existing tests of the behaviour must pass unchanged, a compile-time check must hold for each port, and the godoc must be updated. Every group updates its own callers in the test module, and its own godoc and examples.

## 1. Preconditions

- [ ] 1.1 Confirm that `restructure-layout` is merged into `main` and archived, and start the branch from that `main`. Verify: `openspec list` no longer shows `restructure-layout`, `go list ./...` shows the post-restructure paths, and `make check` passes (everything but the Docker suites).

## 2. Concrete constructor types and the shared flush interface (D1, D2)

- [ ] 2.1 Add `logsample.Flusher`. Replace `authenticate.RefusalLogFlusher`, `policy.RefusalLogFlusher` and `oidc`'s anonymous interface with it in all three probes (`policy.Engine`, `httpsec`, `oidc.RelyingParty`). Verify: the existing flush tests in `policy`, `authenticate`, `httpsec` and `oidc` pass unchanged, and `rg 'RefusalLogFlusher'` finds no declaration.
- [ ] 2.2 Return `*UsernamePasswordAuthenticator` and `*JWTAuthenticator` from `authenticate`, and `*MFA` and `*MFARequirement` from `policy`. Each gets a compile-time port check, and its godoc loses the type-assertion advice. Verify: `go test ./authenticate/... ./policy/... ./httpsec/...` passes, and the tests that type-asserted now call `FlushRefusalLogs` directly.
- [ ] 2.3 Return `*BcryptEncoder`, `*ScryptEncoder` and `*Argon2idEncoder` from `password`; `*JWTGenerator` and `*JWTVerifier` from `token`; `*StaticKeyring` and `*AEADCipher` from `seal`; and `*MemoryKeyStore` from `signingkey`. Each gets a compile-time port check. Verify: `go test ./...` passes in every module, and the review of each newly exported method set (design D1, risk) is recorded in the task report.

## 3. Memory stores refuse bad options (D3)

- [ ] 3.1 Red: write the `one-time-tokens` scenarios "Nil time source" and "Consumer time source", run them, and confirm "Nil time source" fails because a store is returned. Then make `onetime.NewMemoryStore` return `(*MemoryStore, error)`, and pass its error up through `onetime.New`. Verify: both scenarios pass.
- [ ] 3.2 Red: write the `sessions` scenario "Invalid housekeeping configuration" (interval zero, nil clock), run it, and confirm it fails because a store is returned. Then make `session.NewMemoryStore` return `(*MemoryStore, error)`, and pass its error up through `session.New`. Verify: the scenario passes, and so do the existing housekeeping scenarios.
- [ ] 3.3 Red: write the `security-policy` scenario "Capacity of zero", run it, and confirm it fails with a panic. Then make `lockout.NewMemoryAttemptStore` return `(*MemoryAttemptStore, error)` without panicking, and pass its error up through `lockout.New`. Verify: the scenario and "Consumer capacity" pass.

## 4. One lifecycle (D4)

- [ ] 4.1 Red: write the `signing-keys` scenarios:
  - "Double start" (the second start fails);
  - "Cancelled start context";
  - "Start after shutdown";
  - "Consumer bounds the shutdown";
  - "Shutdown twice";
  - "Stop before start".

  Run them and confirm each fails for the scenario's reason. Then replace `Keys.Stop()` with `Shutdown(ctx)`, detach the work's context, and add `ErrAlreadyStarted` and `ErrAlreadyShutdown`. Verify: every `signing-keys` lifecycle scenario passes under `-race`, and `goleak` finds no goroutine left behind.
- [ ] 4.2 Red: write the `sessions` scenarios "Cancelled start context", "Double start and stop" and "Start after shutdown". Run them and confirm they fail. Then apply the same lifecycle to `session.MemoryStore`. Verify: as in 4.1.
- [ ] 4.3 Red: write the `expiry-sweeping` scenarios "Cancelled start context", "Shutdown cancels a running purge" and "Consumer bounds the shutdown". Run them and confirm "Cancelled start context" fails. Then detach `Sweeper`'s run context, keeping `WithStopTimeout`. Verify: every "starts and stops cleanly" scenario passes under `-race`.
- [ ] 4.4 Red: write the `email-notification` scenarios "Close drains" (with the shut-down error), "Shutdown bounded by its context" and "Shutdown twice". Run them and confirm they fail. Then replace `QueuedSender.Close` with `Shutdown`, and `ErrSenderClosed` with `ErrAlreadyShutdown`. Verify: every queued-sender scenario passes.
- [ ] 4.5 Red: for each of the four components, write a test that `Start` with a nil context returns its configuration error, and that `Shutdown` with a nil context does the same. Run the tests and confirm they fail where the component does not refuse today. Then implement the refusal. Verify: the tests pass.

## 5. Guards declare their authorizer (D5)

- [ ] 5.1 Red: write the `http-security-chain` scenarios "Guards built with no authorizer", "Consumer relies on the chain's authorizer" and "Declared reliance with no chain authorizer". Run them and confirm the first fails because construction succeeds. Then make `httpsec.NewGuards` return `(*Guards, error)` and add `WithChainAuthorizer()`. Verify: the three scenarios and the existing guard tests pass.
- [ ] 5.2 Red: write the `framework-adapters` scenarios "fiber guards built with no authorizer", "gin guards rely on the chain" and "fiber guard refusal reaches the consumer's error handler". Run them and confirm the first fails. Then apply the same construction rule to `ginsec.NewGuards` and `fibersec.NewGuards`, adding `fibersec.GuardOption`. Verify: the scenarios pass in both adapter modules.

## 6. Nil contexts (D6)

- [ ] 6.1 Red: write tests that `httpsec.NewExchange(nil, …)` and `Exchange.SetContext(nil)` panic with messages naming the function. Run them and confirm they fail, because today the first substitutes and the second ignores. Then implement the panics, and remove the `contextcheck` exemption. Verify: the tests pass, and every adapter test still passes.

## 7. Required dependencies and default scopes (D7, D8)

- [ ] 7.1 Introduce `OIDCDeps` and `RecoveryCooldownDeps`. Change `EnableOIDCLogin` and `EnableRecoveryCooldown` to take them, with each nil field refused at chain construction. Verify: the existing OIDC and cooldown tests pass on the new signatures, and a new table case shows each nil field refused with `httpsec.ErrConfig`. That case is red first: it fails to build a refusal until the check exists.
- [ ] 7.2 Replace `var DefaultScopes` with `func DefaultScopes() []string`, which returns a new slice. Verify: the existing registry tests pass, and a new test that changes the returned slice shows the next call unaffected.

## 8. Final integration

- [ ] 8.1 Sweep the godoc, examples and README for the old signatures and names (`Stop()`, `Close(ctx)`, `ErrSenderClosed`, `RefusalLogFlusher`, `DefaultScopes` as a variable, the interface returns), excluding `openspec/` and `.claude/.legacy`. Verify: a search for each finds no stale use.
- [ ] 8.2 Run the whole-branch review against the eight deltas and D1–D8. Then run `make check`, push, and confirm CI is green, including the Docker suites, and `openspec validate idiomatic-api-shape --strict`. Verify: a clean review, a green CI run on the final head, and a valid change.

## Workflow follow-up

- Archive with `/opsx:archive` after merge, which syncs the eight deltas into the main specs.
- Explore `key-port-context` next.
- Open the pull request only when the user asks for it.
