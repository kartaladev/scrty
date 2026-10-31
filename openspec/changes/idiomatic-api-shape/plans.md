# idiomatic-api-shape Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make scrty's constructors, flush interface, lifecycle, guards and context handling idiomatic Go before `v0.1.0`, as the eight spec deltas and design decisions D1–D8 require.

**Architecture:**
- Behaviour changes (D2's error joining, and D3–D6) are driven test-first from the delta scenarios.
- Signature-only changes (D1, D2's interface, D7, D8) are verified as refactors by the existing tests.
- Scenarios that pin behaviour the code already has are seen to pass, then shown to bite by temporarily breaking the behaviour.
- The lanes are split by file ownership along the call graph. The lane that changes a signature owns every caller of it, in every module.

**Tech Stack:** Go 1.27 workspace, testify, `go.uber.org/goleak`, mockgen v0.6 (`--typed`), clockwork (tests only), gocron v2 in `expiry/sweep`.

**Spec:** `openspec/changes/idiomatic-api-shape/`: `proposal.md`, `design.md` (D1–D8), `specs/*/spec.md` and `tasks.md`. Step numbers below cite `tasks.md`.

## Global Constraints

- **Post-restructure paths everywhere:** `session`, `token/signingkey`, `token/onetime`, `policy/lockout`, `expiry/sweep`, `notify`, `httpsec/ginsec`, `httpsec/fibersec`, `store/seal`, `authenticate/password`, `authenticate/oidc`, `authenticate/passkey`, `recovery`.
- **Configuration errors wrap the package's own sentinel:** `ErrConfig`; `sweep` keeps `ErrInvalidOption`; `lockout` wraps `policy.ErrConfig`; adapter guard errors wrap `httpsec.ErrConfig`.
- **Lifecycle sentinels:** `signingkey` and `session` declare `ErrAlreadyStarted` and `ErrAlreadyShutdown`, with the messages `"<package>: already started"` and `"<package>: already shut down"`. `notify` declares only `ErrAlreadyShutdown`.
- **Terminal means the background work only.** After `Shutdown`, `Keys` still serves its keys, and `session.MemoryStore` still serves sessions. Only `QueuedSender` refuses new messages.
- **A nil context is never replaced with `context.Background`.**
- **Typed-nil detection** uses `internal/nilcheck.IsNil(v any) bool`.
- **Table tests** follow `.claude/skills/table-test`. Test doubles come from `use-mockgen`. The Docker suites use `use-testcontainers` helpers.
- **Never run** `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.
- **`.claude/.legacy` is never read, copied or cited.** Agents never edit `openspec/`.
- **A defect found while working** is reported `REPRODUCED` with its failing test (`defect-claims.md`), and is not fixed in passing.

## Review Focus

1. **Shutdown racing Start** on every lifecycle owner. Expected: no race report and no goroutine left. Tests in 4.1, 4.2, 4.3 and 4.4.
2. **Start with a context that is already cancelled.** Expected: the work still launches, because its context is detached. Tests in 4.1 and 4.2.
3. **Shutdown called from inside the component's own work:** a sweep purge, a `Keys` error hook, or a wrapped sender. Expected: it returns its context's error within the bound and never deadlocks. Tests in 4.1 (error hook) and 4.3 (purge).
4. **A consumer flusher that fails beside ones that succeed.** Expected: the aggregate returns the error, and every other flusher is still called. Test in 2.2.
5. **A typed-nil value where a port is expected:** an authorizer, or a memory store's clock. Expected: a configuration error at construction, or no fallback, never a nil-method panic at request time. Table cases in 3.1, 3.2, 5.1 and 5.2.

---

## Dispatches and models

| Dispatch | Tasks | Owns | Model, reason | Reviewer |
|---|---|---|---|---|
| main session | 1.1 | | verification | none |
| A | 2.1–2.4 | `pkg/logsample`, `authenticate` (root), `authenticate/password`, `policy` (root), `token`, `store/seal`, `token/signingkey/record.go`, `httpsec/chain.go`, `httpsec/login.go`, `httpsec/basic.go`, `authenticate/oidc/relying_party.go`, `README.md`, and every caller of these constructors and flush methods in every module | Opus: it changes interfaces every other lane compiles against | Opus |
| B | 3.1–3.3 | `token/onetime`, `session/store_memory.go`, `session/sessions.go`, `policy/lockout`, `authenticate/passkey/passkey.go`, `recovery/hold.go`, `httpsec/mfa_begin.go`, and every caller of the three memory-store constructors in every module | Sonnet: a known construction-error pattern; its callers share test helpers, so it is one lane | Sonnet |
| C1 | 4.1 | `token/signingkey` lifecycle files (`keys_lifecycle.go`, `doc.go`, their tests) | Opus: concurrency and ordering | Opus |
| C2 | 4.2 | `session/store_memory.go` lifecycle, and its tests | Opus: concurrency | Opus |
| C3 | 4.3 | `expiry/sweep`, and the sweeper callers in `test/` | Opus: concurrency | Opus |
| C4 | 4.4 | `notify`, and the `Close` callers of `QueuedSender` | Opus: concurrency | Opus |
| D | 4.5 | the lifecycle methods of `Keys`, `session.MemoryStore` and `QueuedSender` | Sonnet: nil checks on the shape C1–C4 settled | Sonnet |
| E | 5.1–5.2 | `httpsec/guards.go`, `httpsec/ginsec/guards.go`, `httpsec/fibersec/guards.go`, and every `NewGuards` caller | Opus: security refusal logic written for the first time | Opus |
| F | 6.1, 7.1, 7.2, 8.1 | `httpsec/exchange.go`, `httpsec/oidc_options.go` and `EnableOIDCLogin`'s callers, `authenticate/oidc/registry.go`, and the final stale-name sweep | Sonnet: signatures and panics fixed by the design | Sonnet |
| main session + Opus reviewer | 8.2 | whole branch | | Opus |

**Order:**
- A runs first, because every later lane compiles against its types.
- B runs after A. Its three constructors are called from the same test helpers, including `httpsec/helpers_test.go`, `httpsec/integration_test.go`, `test/storetest/memory_test.go` and `test/httpsecconformance/scenarios.go`. One lane avoids two writers on them.
- C1, C2, C3 and C4 then run in parallel. Their files and callers do not overlap. C2 comes after B, which owns `session/store_memory.go`'s constructor.
- D runs after all of C, E after D, and F after E. E and F stay sequential so that the `httpsec` test files never have two writers.

---

### Task 1: Preconditions (task 1.1, main session)

- [ ] **Step 1:** `openspec list --json` does not list `restructure-layout`, and `go list ./...` includes `github.com/kartaladev/scrty/authenticate/oidc`.
- [ ] **Step 2:** `git fetch origin main && git checkout -B refactor/idiomatic-api-shape origin/main`, then `make check`. Expected: PASS.

### Task 2: Flush interface, aggregators and concrete types (tasks 2.1–2.4, dispatch A)

**Files:**
- Modify: `pkg/logsample/logsample.go` (add `Flusher`); `policy/engine.go`, `httpsec/chain.go` (aggregators); `httpsec/login.go`, `httpsec/basic.go`, `authenticate/oidc/relying_party.go` (probes)
- Remove: `RefusalLogFlusher` from `authenticate/password.go` and `policy/mfa.go`
- Modify (exported types): `authenticate/password.go`, `authenticate/jwt.go`, `policy/mfa.go`, `policy/mfa_requirement.go`, `policy/federated.go`, `authenticate/password/{bcrypt,scrypt,argon2id}.go`, `token/generator.go`, `token/verifier.go`, `store/seal/keyring.go`, `store/seal/cipher.go`, `token/signingkey/record.go`, `README.md`

**Interfaces:**
- Produces:
  - `type logsample.Flusher interface{ FlushRefusalLogs() error }`
  - `func (e *policy.Engine) FlushRefusalLogs() error`, `func (c *httpsec.Chain) FlushRefusalLogs() error`
  - `authenticate.NewUsernamePasswordAuthenticator(users identity.UserLoader, opts ...PasswordOption) (*UsernamePasswordAuthenticator, error)`
  - `authenticate.NewJWTAuthenticator(opts ...JWTOption) (*JWTAuthenticator, error)`
  - `policy.NewMFA(methods []MFAMethodLookup, opts ...MFAOption) (*MFA, error)`
  - `policy.NewMFARequirement(required identity.MFARequirementLookup, methods []MFAMethodLookup, …) (*MFARequirement, error)`
  - `password.NewBcryptEncoder(...) (*BcryptEncoder, error)`, and Scrypt and Argon2id alike
  - `token.NewGenerator(keys signingkey.KeySource, opts ...Option) (*JWTGenerator, error)`
  - `token.NewVerifier(opts ...VerifyOption) (*JWTVerifier, error)`
  - `seal.NewKeyring(opts ...KeyringOption) (*StaticKeyring, error)`
  - `seal.NewAEADCipher(kr Keyring) (*AEADCipher, error)`
  - `signingkey.NewMemoryKeyStore() *MemoryKeyStore`

- [ ] **Step 1 (2.1):** Declare `logsample.Flusher`, switch the three probes to it, and delete both `RefusalLogFlusher` declarations. Run `go build ./...` in every module, then `go test -count=1 ./pkg/... ./policy/... ./authenticate/... ./httpsec/...`. Expected: PASS with no assertion changed. `rg -n 'type RefusalLogFlusher'` finds nothing.
- [ ] **Step 2 (2.2, compile first):** Change both aggregators to return `error`, returning nil. Build every module. Expected: it builds.
- [ ] **Step 3 (2.2, red):** Add tests:
  - `TestEngine_FlushRefusalLogs_JoinsErrors` in `policy`: two registered policies whose flush returns `errA` and nil. Assert `require.ErrorIs(t, err, errA)` and that both were called.
  - `TestChain_FlushRefusalLogs_JoinsErrors` in `httpsec`: a consumer authenticator given to `EnableFormLogin` whose flush returns `errA`, and a policy engine whose policy returns `errB`. Assert `ErrorIs` for both, and that the chain's own sampler still flushed.

  Run `go test -run 'FlushRefusalLogs_JoinsErrors' -count=1 ./policy/ ./httpsec/`. Expected: FAIL, "expected error … got nil".
- [ ] **Step 4 (2.2, green):** Collect each flusher's error into `errors.Join`, keeping the documented order and calling every flusher. Update every caller, which handles or explicitly discards the error. Rerun, then run `golangci-lint run ./...`. Expected: PASS, and no unchecked flush error.
- [ ] **Step 5 (2.3):**
  - rename the unexported implementations with gopls (`jwtAuthenticator`→`JWTAuthenticator`, `passwordAuthenticator`→`UsernamePasswordAuthenticator`, `mfaPolicy`→`MFA`, `mfaRequirementPolicy`→`MFARequirement`);
  - change the constructor results, and add `var _ Authenticator = (*UsernamePasswordAuthenticator)(nil)` and the same for each type;
  - replace the type-assertion paragraphs in the godoc with "build it with New…; the zero value is not usable";
  - rewrite the tests that type-asserted (`authenticate/password_test.go`, `policy/mfa_requirement_test.go`, `policy/integration_test.go`) to call methods directly;
  - `README.md:227` becomes `deps.Admits = requirement.AdmitsWithoutLocalSecondFactor`.

  Run `go test ./authenticate/... ./policy/... ./httpsec/...`. Expected: PASS.
- [ ] **Step 6 (2.4):** The same for `bcryptEncoder`, `scryptEncoder`, `argon2idEncoder`, `generator`→`JWTGenerator`, `verifier`→`JWTVerifier`, `keyring`→`StaticKeyring`, `aeadCipher`→`AEADCipher` and `inMemoryKeyStore`→`MemoryKeyStore`. Unexport nothing: every method is in D1's table. Run `go test -count=1 ./...` in every module and `go vet ./...`. Expected: PASS. In the report, list each type's exported methods against D1's table.
- [ ] **Step 7:** Commit: `refactor!: return concrete types and share one flush interface`.

### Task 3: Memory stores refuse bad options (tasks 3.1–3.3, dispatch B)

**Files:**
- Modify: `token/onetime/store_memory.go`, `token/onetime/tokens.go:240`, `authenticate/passkey/passkey.go:221`, `recovery/hold.go:125`, `httpsec/mfa_begin.go:241`, `session/store_memory.go` (constructor only), `session/sessions.go:234`, `policy/lockout/attempts.go:298`, `policy/lockout/lockout.go`, and every caller in every module (for example `httpsec/helpers_test.go`, `test/storetest/memory_test.go`, `test/httpsecconformance/scenarios.go`, `recovery/helpers_test.go`, `authenticate/passkey/helpers_test.go`)

**Interfaces:**
- Consumes: Task 2's types.
- Produces:
  - `onetime.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)`
  - `session.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)`
  - `lockout.NewMemoryAttemptStore(opts ...MemoryAttemptOption) (*MemoryAttemptStore, error)`

- [ ] **Step 1 (3.1, red):** Write `TestMemoryStore_Construction` in `token/onetime`:
  - `"nil time source"` and `"typed nil time source"`: assert `require.ErrorIs(t, err, onetime.ErrConfig)` and `assert.Nil(t, store)`;
  - `"consumer time source"` (clockwork fake): a record with a 1-minute TTL, an advance of 2 minutes, then `PurgeExpired` removes it.

  Stub the signature to return `(s, nil)` so that it compiles, then run `go test -run TestMemoryStore_Construction -count=1 ./token/onetime/`. Expected: FAIL on both nil cases, "expected an error".
- [ ] **Step 2 (3.1, green):** Refuse with `nilcheck.IsNil`, and pass the error up through the four default sites. Run the test, then `go test ./token/onetime/... ./authenticate/passkey/... ./recovery/... ./httpsec/...`. Expected: PASS.
- [ ] **Step 3 (3.2, red):** Write `TestMemoryStore_InvalidHousekeepingConfiguration` in `session`, with cases interval `0`, interval `-time.Second`, a nil clock and a typed-nil clock. Each asserts `ErrorIs(err, session.ErrConfig)` and a nil store. Run it. Expected: FAIL, because a store is returned.
- [ ] **Step 4 (3.2, green):** Implement, and pass the error up through `session.New`. Run `go test ./session/...`. Expected: PASS.
- [ ] **Step 5 (3.3, red):** Write `TestMemoryAttemptStore_Capacity` in `policy/lockout`:
  - `"capacity of zero"` and `"negative capacity"`: assert `require.NotPanics`, `ErrorIs(err, policy.ErrConfig)` and a nil store;
  - `"consumer capacity"`: 1,000,000 identifiers held.

  Run it. Expected: FAIL with a panic on zero.
- [ ] **Step 6 (3.3, green):** Replace the panic with the error, and pass it up through `lockout.New`. Run `go test ./policy/...`. Expected: PASS.
- [ ] **Step 7:** Run `go test -count=1 ./...` in every module. Expected: PASS. Commit: `refactor!: memory stores refuse bad options at construction`.

### Task 4: Signing keys lifecycle (task 4.1, dispatch C1)

**Interfaces:**
- Produces: `(*Keys).Start(ctx context.Context) error`, `(*Keys).Shutdown(ctx context.Context) error`, `signingkey.ErrAlreadyStarted`, `signingkey.ErrAlreadyShutdown`

- [ ] **Step 1 (red):** Write `TestKeys_Lifecycle`, a table with `goleak.VerifyNone` and a clockwork fake synchronised with `BlockUntilContext(ctx, 3)`. One case per scenario:
  - "Double start" (`ErrorIs(err, ErrAlreadyStarted)`);
  - "Cancelled start context" (a rotation still happens after the interval);
  - `"already-cancelled start context"` (Review Focus 2);
  - "Start after shutdown" (`ErrAlreadyShutdown`);
  - "Consumer bounds the shutdown": a store double blocks `Store`, Shutdown with a 50 ms context returns `context.DeadlineExceeded`, and after the release a second Shutdown returns nil;
  - "Shutdown twice";
  - "Stop before start";
  - `"completion wins"`: on a manager whose work has ended, Shutdown with an already-cancelled context returns nil;
  - `"shutdown from error hook"` (Review Focus 3): a hook calling `Shutdown` with a 100 ms context returns `context.DeadlineExceeded` within 1 s;
  - "Concurrent start and stop", under `-race`.
- [ ] **Step 2:** `go test -race -run TestKeys_Lifecycle -count=1 ./token/signingkey/`. Expected: FAIL on every new case.
- [ ] **Step 3 (pin):** Add `TestKeys_ServedAfterShutdown`: after Shutdown, `Signer` and `VerificationKeys` still return the held key, and advancing the fake past the rotation interval rotates nothing. Run it: PASS. Temporarily clear the keys in `Stop` and watch it fail, then restore.
- [ ] **Step 4 (green):** Replace `Stop()` with `Shutdown(ctx)`:
  - derive the work's context as `context.WithCancel(context.WithoutCancel(ctx))`, and track the work with a `sync.WaitGroup`;
  - in Shutdown, check for completion before the `select` on `ctx.Done()`, and wait for an in-flight store write;
  - rewrite the godoc of `Start` without the restart paragraph, and the godoc of `Shutdown` with the warning against calling it from an error hook;
  - update `doc.go` and every caller of `Stop`.

  Run Steps 2 and 3. Expected: PASS. Commit.

### Task 5: Session memory store lifecycle (task 4.2, dispatch C2)

**Interfaces:**
- Consumes: Task 3's `session.NewMemoryStore(...) (*MemoryStore, error)`.
- Produces: `(*MemoryStore).Start(ctx context.Context) error`, `(*MemoryStore).Shutdown(ctx context.Context) error`, `session.ErrAlreadyStarted`, `session.ErrAlreadyShutdown`

- [ ] **Step 1 (red):** Write `TestMemoryStore_Lifecycle`, a table on a clockwork fake with `goleak.VerifyNone`:
  - "Cancelled start context", and `"already-cancelled start context"`: the expired session is gone after one interval;
  - "Double start and stop": `ErrAlreadyStarted`, and both shutdowns return nil;
  - "Start after shutdown": `ErrAlreadyShutdown`;
  - `"shutdown bounded, then waits again"`: a slow `DeleteExpired`, Shutdown with an expired context returns `context.DeadlineExceeded`, and a later Shutdown with a sufficient context returns nil;
  - `"concurrent start and shutdown"`, under `-race`.
- [ ] **Step 2:** `go test -race -run TestMemoryStore_Lifecycle -count=1 ./session/`. Expected: FAIL on the cancelled-context, double-start, after-shutdown and bounded cases.
- [ ] **Step 3 (pin):** Add `TestMemoryStore_ServesAfterShutdown`: save and load succeed after Shutdown, and no sweep runs. Run it: PASS. Temporarily refuse `Save` after Stop and watch it fail, then restore.
- [ ] **Step 4 (green):** Apply Task 4 Step 4's shape. Remove the restart paragraph from the godoc, and update every caller of `Stop`. Run Steps 2 and 3. Expected: PASS. Commit.

### Task 6: Sweeper lifecycle (task 4.3, dispatch C3)

- [ ] **Step 1 (red):** Write `TestSweeper_DetachedStart`:
  - "Cancelled start context": a purge runs after the start context is cancelled, and its context's `Err()` is nil;
  - "Shutdown cancels a running purge": the purge sees `ctx.Done()`, and Shutdown returns after it does;
  - "Consumer bounds the shutdown": a purge ignoring cancellation, and Shutdown with a 50 ms context, returns `ErrorIs(err, context.DeadlineExceeded)`;
  - `"shutdown from inside a purge"` (Review Focus 3): `Shutdown` with a 100 ms context returns within 1 s, with no deadlock;
  - `"concurrent start and shutdown"`, under `-race`.
- [ ] **Step 2:** `go test -race -run TestSweeper_DetachedStart -count=1 ./...` in `expiry/sweep`. Expected: FAIL on "Cancelled start context".
- [ ] **Step 3 (pin):** Add `TestSweeper_PurgeOutlastsStopTimeout`: `WithStopTimeout(time.Second)`, and a purge ignoring cancellation. Both Shutdown calls return the stop-timeout error (`ErrorIs(err, gocron.ErrStopExecutorTimedOut)` or the sweeper's wrapper of it). Run it: PASS. Temporarily return nil instead and watch it fail, then restore.
- [ ] **Step 4 (green):** Parent the run contexts on `context.WithoutCancel(ctx)` plus an internal cancel that Shutdown triggers. Keep `WithStopTimeout` and the shared result. Run Steps 2 and 3. Expected: PASS. Commit.

### Task 7: Queued sender (task 4.4, dispatch C4)

**Interfaces:**
- Produces: `(*QueuedSender).Shutdown(ctx context.Context) error`, and `notify.ErrAlreadyShutdown`, which replaces `ErrSenderClosed`. There is no `notify.ErrAlreadyStarted`.

- [ ] **Step 1 (red):** Write `TestQueuedSender_Shutdown`:
  - "Close drains": 3 messages and a 10 s context, nil returned; a later Send returns `ErrorIs(err, notify.ErrAlreadyShutdown)`;
  - "Shutdown bounded by its context": a 5 s sender and a 1 s context return `context.DeadlineExceeded` within 1.5 s;
  - "Shutdown twice": nil;
  - "Sends racing shutdown": 100 goroutines send while Shutdown runs, under `-race`. Each Send either returned nil and its message was delivered, or returned `ErrAlreadyShutdown`, and nothing panics.

  To compile, add `Shutdown` as a call to `Close`, and declare `ErrAlreadyShutdown` as a new sentinel. Run. Expected: FAIL on the error identity. A racing case that passes is pinned: temporarily drop accepted messages and watch it fail.
- [ ] **Step 2 (green):** Rename `Close` to `Shutdown` and the sentinel, and guard intake with the existing mutex. Update every caller. Run. Expected: PASS. Commit.

### Task 8: Nil context on lifecycle methods (task 4.5, dispatch D)

- [ ] **Step 1 (red):** Write `Test<Type>_NilContext` in `signingkey` and `session`, with cases `"start"` and `"shutdown"`, and in `notify`, with `"shutdown"` only. Each asserts `ErrorIs(err, <pkg>.ErrConfig)`, that no goroutine started, and that a later call with a real context still works. Run them. Expected: FAIL in all three packages. `sweep` already refuses both, and its existing tests stay.
- [ ] **Step 2 (green):** Add the checks. Run. Expected: PASS. Commit: `refactor!: one Start and Shutdown lifecycle`.

### Task 9: Guards (tasks 5.1–5.2, dispatch E)

**Interfaces:**
- Produces:
  - `httpsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`, `httpsec.WithChainAuthorizer() GuardOption`
  - `ginsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`, `ginsec.WithChainAuthorizer() GuardOption`
  - `type fibersec.GuardOption func(*Guards)`, `fibersec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`, `fibersec.WithChainAuthorizer() GuardOption`

- [ ] **Step 1 (5.1, red):** Write `TestNewGuards_Authorizer` in `httpsec`:
  - `"nil authorizer"` and `"typed-nil authorizer"`: `ErrorIs(err, httpsec.ErrConfig)`, and the guards are nil;
  - `"chain authorizer declared"`: through a chain with `EnableAuthorization` and a privileged principal, 200;
  - `"typed nil beside declared reliance"`: no authorizer in the context, refused with `authorize.ErrAccessDenied` and `require.NotPanics`;
  - `"declared reliance, no chain authorizer"`: `ErrAccessDenied`;
  - `"both given"`: the request's authorizer is preferred.

  Run. Expected: FAIL on the two nil cases.
- [ ] **Step 2 (5.1, green):** Implement with `nilcheck.IsNil`, storing a typed nil as no fallback, and rewrite the "nothing to misconfigure" godoc. Update every `NewGuards` caller. Run. Expected: PASS.
- [ ] **Step 3 (5.2):** The same table in `ginsec` and `fibersec`, plus `"fiber refusal reaches the consumer's error handler"`: an app whose `ErrorHandler` writes `"custom"` receives the guard's refusal. Run. Expected: FAIL on the nil cases. Implement. Run. Expected: PASS. Commit: `feat!: guards declare where their authorizer comes from`.

### Task 10: Nil context in the exchange (task 6.1, dispatch F)

- [ ] **Step 1 (red):** Write `TestExchange_NilContext`:
  - `"new exchange"`: `require.PanicsWithValue(t, "httpsec: NewExchange needs a non-nil context", …)`;
  - `"set context"`: `PanicsWithValue(t, "httpsec: Exchange.SetContext needs a non-nil context", …)`.

  Run. Expected: FAIL, because neither panics.
- [ ] **Step 2 (green):** Implement, and remove the `//nolint:contextcheck` on `NewExchange`. Run it, plus the `ginsec` and `fibersec` suites. Expected: PASS. Commit.

### Task 11: `OIDCDeps` and default scopes (tasks 7.1–7.2, dispatch F)

**Interfaces:**
- Produces:
  - `type httpsec.OIDCDeps struct{ RelyingParty *oidc.RelyingParty; Handoff *oidc.Handoff }`
  - `EnableOIDCLogin(d OIDCDeps, opts ...OIDCOption) Option`
  - `func oidc.DefaultScopes() []string`
- `EnableRecoveryCooldown(records, d, routes...)` is unchanged.

- [ ] **Step 1 (7.1, refactor):** Change the signature and move the existing checks unchanged: a nil `RelyingParty` is refused, and `Handoff` is required unless `WithOIDCCallbackSuccess` is given, when it must be nil. Update every caller, including `README.md` and `authenticate/oidc/doc.go`. Run `go test ./httpsec/... ./authenticate/oidc/...` and the test module's OIDC suites. Expected: PASS, including the existing missing-handoff and callback-success cases.
- [ ] **Step 2 (7.2, red):** Write `TestDefaultScopes_ReturnsACopy`: overwrite element 0 of one result, and assert the next call returns `[]string{"openid", "profile", "email"}`. With the function stubbed to return the shared variable, run it. Expected: FAIL.
- [ ] **Step 3 (7.2, green):** Return `slices.Clone` of an unexported array, and make `resolveProvider` call it. Update `registry_test.go:64`. Run. Expected: PASS. Commit: `refactor!: OIDCDeps; DefaultScopes is a function`.

### Task 12: Final integration (tasks 8.1–8.2)

- [ ] **Step 1 (8.1, dispatch F):** Search, excluding `openspec/` and `.claude/.legacy`:
  - `rg -n 'RefusalLogFlusher|ErrSenderClosed|\.Stop\(\)|\.Close\(ctx|DefaultScopes\b[^(]|RecoveryCooldownDeps'`;
  - `rg -n '\.\((authenticate|policy|token|seal|signingkey|password)\.\w+\)'` for type assertions onto ports or optional interfaces;
  - `rg -n -i 'restart|idempotent|nothing to misconfigure' token/signingkey session expiry/sweep notify httpsec/*guards*.go`, checking each hit by hand.

  Fix each stale use. Expected: none left.
- [ ] **Step 2 (8.2, main session):** Run `make check`, push, and wait for CI to be green, including the Docker suites. Run `openspec validate idiomatic-api-shape --strict`. Dispatch the Opus whole-branch reviewer with the eight deltas, D1–D8 and `git diff origin/main...HEAD`. Expected: green, valid, and a clean review.
