# idiomatic-api-shape Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make scrty's constructors, lifecycle, guards and context handling idiomatic Go before `v0.1.0`, as the eight spec deltas and design decisions D1–D8 require.

**Architecture:** Behaviour changes (D3–D6) are driven test-first from the delta scenarios. Signature-only changes (D1, D2, D7, D8) are verified as refactors by the existing tests. The lanes are split by package ownership. The test module's callers are updated in the lane that owns the changed constructor.

**Tech Stack:** Go 1.27 workspace, testify, `go.uber.org/goleak`, mockgen v0.6 (`--typed`), clockwork (tests only), gocron v2 in `expiry/sweep`.

**Spec:** `openspec/changes/idiomatic-api-shape/`: `proposal.md`, `design.md` (D1–D8), `specs/*/spec.md` and `tasks.md`. Step numbers below cite `tasks.md`.

## Global Constraints

- **Post-restructure names everywhere.** Use `session.Sessions`, `signingkey.Keys`, `policy/lockout`, `expiry/sweep`, `httpsec/ginsec`, `httpsec/fibersec`, `store/seal`, `token/signingkey`.
- **Configuration errors wrap the package's own sentinel:** `ErrConfig` (`sweep` keeps `ErrInvalidOption`). Adapter guard errors wrap `httpsec.ErrConfig`.
- **Lifecycle sentinels:** each lifecycle package declares `ErrAlreadyStarted` and `ErrAlreadyShutdown`, with the message form `"<package>: already started"` and `"<package>: already shut down"`.
- **A nil context is never replaced with `context.Background`.**
- **Table tests** follow `.claude/skills/table-test`. Test doubles come from `use-mockgen`. The Docker suites use `use-testcontainers` helpers.
- **Never run** `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.
- **`.claude/.legacy` is never read, copied or cited.** Agents never edit `openspec/`.
- **A defect found while working** is reported `REPRODUCED` with its failing test (`defect-claims.md`), and is not fixed in passing.

## Review Focus

1. **Shutdown racing Start**, on every lifecycle owner, not only `Keys`. Expected: no race report and no goroutine left. A test is added in each of 4.2, 4.3 and 4.4.
2. **Start with a context that is already cancelled.** Expected: the work still launches, because its context is detached. A test is added in 4.1 and 4.2.
3. **Shutdown called from inside the component's own work** (a sweep purge, or a reuse observer, calling Shutdown). Expected: it returns its context's error within the bound and never deadlocks. A test is added in 4.3.
4. **A typed-nil authorizer** (`(*myAuthorizer)(nil)` in the interface) passed to `NewGuards` without `WithChainAuthorizer()`. Expected: a configuration error, exactly as for a plain nil. Table cases are added in 5.1 and 5.2.
5. **`QueuedSender.Send` concurrent with `Shutdown`.** Expected: each message is either queued and delivered, or refused with `ErrAlreadyShutdown`. It is never silently lost, and there is no send-on-closed-channel panic. A test is added in 4.4.

---

## Dispatches and models

| Dispatch | Tasks | Owns | Model, reason | Reviewer |
|---|---|---|---|---|
| main session | 1.1 | | verification | none |
| A | 2.1–2.3 | `pkg/logsample`, `authenticate`, `policy`, `password`, `token`, `store/seal`, `token/signingkey` (record and memory store files only), and their callers in `httpsec`, `authenticate/oidc` and `test/` | Opus: it changes interfaces every other lane compiles against | Opus |
| B1 | 3.1 | `token/onetime` (+ test-module callers) | Sonnet: a known construction-error pattern | Sonnet |
| B2 | 3.3 | `policy/lockout` memory attempt store (+ callers) | Sonnet: same reason | Sonnet |
| C1 | 4.1 | `token/signingkey` lifecycle files | Opus: concurrency and ordering | Opus |
| C2 | 3.2, then 4.2 | `session` memory store | Opus: concurrency (3.2 rides with it, same file) | Opus |
| C3 | 4.3 | `expiry/sweep` | Opus: concurrency | Opus |
| C4 | 4.4 | `notify` queued sender | Opus: concurrency | Opus |
| D | 4.5 | the four lifecycle owners | Sonnet: nil checks on the shape C1–C4 settled | Sonnet |
| E | 5.1–5.2 | `httpsec` guards, `ginsec`, `fibersec` | Opus: security refusal logic written for the first time | Opus |
| F | 6.1, 7.1, 7.2 | `httpsec` exchange and `Enable…` signatures, `authenticate/oidc` registry | Sonnet: signatures and panics fixed by design | Sonnet |
| main session + Opus reviewer | 8.1–8.2 | whole branch | | Opus |

**Order:**
- A runs first, because later lanes compile against its types.
- B1, B2, C1, C2, C3 and C4 then run in parallel. Their files do not overlap.
- D runs after all of C, E after D, and F after E.
- F could run beside E in principle: `exchange.go` is separate from `guards.go`, but both are in `httpsec`. They stay sequential so that the `httpsec` test files never have two writers.

---

### Task 1: Preconditions (task 1.1, main session)

- [ ] **Step 1:** `openspec list --json` must not list `restructure-layout`, and `go list ./... | grep -c authenticate/oidc` must be at least 1.
- [ ] **Step 2:** `git fetch origin main && git checkout -B <branch> origin/main`, then run `make check` (everything but the Docker suites). Expected: PASS.

### Task 2: Shared flush interface and concrete types (tasks 2.1–2.3, dispatch A)

**Files:**
- Create: the `Flusher` declaration in `pkg/logsample/logsample.go`
- Modify: `policy/engine.go` (probe), `httpsec/login.go` and `httpsec/basic.go` (probes), `authenticate/oidc/relying_party.go` (probe)
- Remove: `RefusalLogFlusher` from `authenticate/password.go` and `policy/mfa.go`
- Modify (exported types): `authenticate/password.go`, `authenticate/jwt.go`, `policy/mfa.go`, `policy/mfa_requirement.go`, the `password` encoder files, the `token` generator and verifier files, `store/seal/keyring.go`, `store/seal/cipher.go`, `token/signingkey/record.go`

**Interfaces:**
- Produces:
  - `type logsample.Flusher interface{ FlushRefusalLogs() error }`
  - `authenticate.NewUsernamePasswordAuthenticator(users identity.UserLoader, opts ...PasswordOption) (*UsernamePasswordAuthenticator, error)`
  - `authenticate.NewJWTAuthenticator(opts ...JWTOption) (*JWTAuthenticator, error)`
  - `policy.NewMFA(methods []MFAMethodLookup, opts ...MFAOption) (*MFA, error)`
  - `policy.NewMFARequirement(required identity.MFARequirementLookup, methods []MFAMethodLookup, …) (*MFARequirement, error)`
  - `password.NewBcryptEncoder(...) (*BcryptEncoder, error)` (Scrypt and Argon2id alike)
  - `token.NewGenerator(keys signingkey.KeySource, opts ...Option) (*JWTGenerator, error)`
  - `token.NewVerifier(opts ...VerifyOption) (*JWTVerifier, error)`
  - `seal.NewKeyring(opts ...KeyringOption) (*StaticKeyring, error)`
  - `seal.NewAEADCipher(kr Keyring) (*AEADCipher, error)`
  - `signingkey.NewMemoryKeyStore() *MemoryKeyStore`

- [ ] **Step 1 (2.1):** Declare `logsample.Flusher`, switch the three probes to it, and delete the two `RefusalLogFlusher` declarations. Run `go build ./...` in every module, then `go test -count=1 ./pkg/... ./policy/... ./authenticate/... ./httpsec/...`. Expected: PASS with no test assertion changed.
- [ ] **Step 2 (2.2):** Rename each unexported implementation to its exported name with gopls. Change the constructor results, add `var _ Authenticator = (*UsernamePasswordAuthenticator)(nil)` (and the same for each type), and remove the type-assertion paragraph from the godoc. Rewrite the tests that type-asserted (`authenticate/password_test.go`, `policy/mfa_requirement_test.go`, `policy/integration_test.go`) to call `FlushRefusalLogs()` directly. Expected: `go test ./authenticate/... ./policy/... ./httpsec/...` passes.
- [ ] **Step 3 (2.3):** The same for the `password`, `token`, `seal` and `signingkey` rows. For each newly exported type, list its exported methods in the dispatch report, and keep any that only serve the library unexported. Expected: `go test -count=1 ./...` passes in every module, and `go vet` is clean.
- [ ] **Step 4:** Commit: `refactor!: return concrete types and share one flush interface`.

### Task 3: One-time token memory store (task 3.1, dispatch B1)

**Interfaces:**
- Produces: `onetime.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)`

- [ ] **Step 1: Failing tests.** `TestMemoryStore_Construction`, a table with cases:
  - `"nil time source"`, with `WithMemoryStoreClock(nil)`, asserting `require.ErrorIs(t, err, onetime.ErrConfig)` and `assert.Nil(t, store)`;
  - `"typed nil time source"`, with `WithMemoryStoreClock((*fakeClock)(nil))`, asserting the same;
  - `"consumer time source"`, with a clockwork fake: issue a record with a 1-minute TTL, advance 2 minutes, call `PurgeExpired`, and assert the record is gone.
- [ ] **Step 2:** `go test -run TestMemoryStore_Construction -count=1 ./token/onetime/`. Expected: FAIL on both nil cases with "expected an error", and with no compile error once the signature is stubbed to return `(s, nil)`.
- [ ] **Step 3:** Implement the refusal, and pass the error up through `onetime.New` (its existing error return).
- [ ] **Step 4:** Rerun. Expected: PASS. Then `go test ./...` in the core and test modules. Commit.

### Task 4: Session memory store construction and lifecycle (tasks 3.2 and 4.2, dispatch C2)

**Interfaces:**
- Produces:
  - `session.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)`
  - `(*MemoryStore).Start(ctx context.Context) error`
  - `(*MemoryStore).Shutdown(ctx context.Context) error`
  - `session.ErrAlreadyStarted`, `session.ErrAlreadyShutdown`

- [ ] **Step 1 (3.2): Failing test.** `TestMemoryStore_InvalidHousekeepingConfiguration`, with cases interval `0`, interval `-time.Second` and a nil clock. Each asserts `ErrorIs(err, session.ErrConfig)` and a nil store. Run it. Expected: FAIL, because a store is returned. Implement, run, PASS. Commit.
- [ ] **Step 2 (4.2): Failing tests.** `TestMemoryStore_Lifecycle`, a table on a clockwork fake with `goleak.VerifyNone` in each case:
  - `"cancelled start context"`: start with a ctx that is then cancelled, expire a session, advance 10 seconds, and assert the session is gone;
  - `"already-cancelled start context"` (Review Focus 2): the same, with the ctx cancelled before Start;
  - `"double start and stop"`: the second Start returns `ErrorIs(err, session.ErrAlreadyStarted)`, and both Shutdowns return nil;
  - `"start after shutdown"`: Start returns `ErrorIs(err, session.ErrAlreadyShutdown)`;
  - `"shutdown bounded"`: Shutdown with an expired ctx during a slow `DeleteExpired` returns `context.DeadlineExceeded`;
  - `"concurrent start and shutdown"` (Review Focus 1), run under `-race`.
- [ ] **Step 3:** `go test -race -run TestMemoryStore_Lifecycle -count=1 ./session/`. Expected: FAIL on the cancelled-context, double-start and after-shutdown cases.
- [ ] **Step 4:** Replace `Stop()` with `Shutdown(ctx)`. Derive the work's context with `context.WithCancel(context.WithoutCancel(ctx))`, track the work with a `sync.WaitGroup`, and select on a done channel against `ctx.Done()`. Update every caller of `Stop`. Run again. Expected: PASS. Commit.

### Task 5: Lockout attempt store (task 3.3, dispatch B2)

**Interfaces:**
- Produces: `lockout.NewMemoryAttemptStore(opts ...MemoryAttemptOption) (*MemoryAttemptStore, error)`

- [ ] **Step 1: Failing test.** `TestMemoryAttemptStore_Capacity`, with cases:
  - `"capacity of zero"`, asserting `require.NotPanics`, `ErrorIs(err, policy.ErrConfig)` and a nil store;
  - `"negative capacity"`, asserting the same;
  - `"consumer capacity"`, holding 1,000,000 identifiers.

  Run it. Expected: FAIL with a panic on zero.
- [ ] **Step 2:** Implement the refusal, and pass the error up through `lockout.New`. Run. Expected: PASS. Commit.

### Task 6: Signing keys lifecycle (task 4.1, dispatch C1)

**Interfaces:**
- Produces:
  - `(*Keys).Start(ctx context.Context) error`
  - `(*Keys).Shutdown(ctx context.Context) error`
  - `signingkey.ErrAlreadyStarted`, `signingkey.ErrAlreadyShutdown`

- [ ] **Step 1: Failing tests.** `TestKeys_Lifecycle`, a table with `goleak.VerifyNone`, using a clockwork fake that is `BlockUntilContext`-synchronised on the three loops. One case per `signing-keys` scenario:
  - "Double start" (`ErrorIs(err, ErrAlreadyStarted)`);
  - "Cancelled start context" (a rotation still happens after the interval);
  - "already-cancelled start context" (Review Focus 2);
  - "Start after shutdown" (`ErrAlreadyShutdown`);
  - "Consumer bounds the shutdown" (a store double blocks `Store` until released; Shutdown with a 50 ms ctx returns `context.DeadlineExceeded`; after the release, a second Shutdown returns nil);
  - "Shutdown twice";
  - "Stop before start".
- [ ] **Step 2:** `go test -race -run TestKeys_Lifecycle -count=1 ./token/signingkey/`. Expected: FAIL on all but "Constructed but not started" and "Clean shutdown".
- [ ] **Step 3:** Implement as in Task 4, Step 4. Keep "no store write after a nil Shutdown" by waiting for the in-flight write. Update every caller of `Stop`. Run. Expected: PASS. Commit.

### Task 7: Sweeper lifecycle (task 4.3, dispatch C3)

- [ ] **Step 1: Failing tests.** `TestSweeper_DetachedStart`, with cases:
  - `"cancelled start context"`: a task's purge runs after the start ctx is cancelled, and its ctx `Err()` is nil;
  - `"shutdown cancels a running purge"`: the purge observes `ctx.Done()`, and Shutdown returns after the purge returns;
  - `"consumer bounds the shutdown"`: a purge ignoring cancellation, with Shutdown on a 50 ms ctx, returns `context.DeadlineExceeded`;
  - `"shutdown from inside a purge"` (Review Focus 3): a purge calls `Shutdown` on a 100 ms ctx, which returns `context.DeadlineExceeded` within 1 second, with no deadlock;
  - `"concurrent start and shutdown"` (Review Focus 1), under `-race`.
- [ ] **Step 2:** `go test -race -run TestSweeper_DetachedStart -count=1 ./...` in `expiry/sweep`. Expected: FAIL on "cancelled start context".
- [ ] **Step 3:** Parent the run contexts on `context.WithoutCancel(ctx)` plus an internal cancel used by Shutdown. Keep `WithStopTimeout` as gocron's bound. Run. Expected: PASS. Commit.

### Task 8: Queued sender (task 4.4, dispatch C4)

**Interfaces:**
- Produces: `(*QueuedSender).Shutdown(ctx context.Context) error`, `notify.ErrAlreadyShutdown` (replaces `ErrSenderClosed`)

- [ ] **Step 1: Failing tests.** `TestQueuedSender_Shutdown`, with cases:
  - "Close drains": 3 messages, a 10 s ctx, nil returned, and a later Send returns `ErrorIs(err, notify.ErrAlreadyShutdown)`;
  - "Shutdown bounded by its context": a 5 s sender with a 1 s ctx returns `context.DeadlineExceeded` within 1.5 s;
  - "Shutdown twice": nil;
  - `"send concurrent with shutdown"` (Review Focus 5): 100 goroutines send while Shutdown runs, under `-race`. Every Send either returns nil and its message is delivered, or returns `ErrAlreadyShutdown`, and nothing panics.
- [ ] **Step 2:** Stub `Shutdown(ctx)` as a call to the existing `Close(ctx)`, and alias `ErrAlreadyShutdown` to a fresh sentinel, so that the tests compile. Run them. Expected: FAIL on the error identity (a later Send still returns `ErrSenderClosed`) and on the concurrent case.
- [ ] **Step 3:** Rename `Close` to `Shutdown` and the sentinel, and guard intake with the existing mutex so that no send reaches a closed channel. Run. Expected: PASS. Commit.

### Task 9: Nil context on lifecycle methods (task 4.5, dispatch D)

- [ ] **Step 1: Failing tests.** One table per package, `Test<Type>_NilContext`, with cases `"start"` and `"shutdown"`. Each asserts `ErrorIs(err, <pkg>.ErrConfig)` (`sweep.ErrInvalidOption` for `sweep`) and that no goroutine was started. Run. Expected: FAIL in `signingkey`, `session` and `notify`; `sweep`'s start case already passes.
- [ ] **Step 2:** Add the checks. Run. Expected: PASS. Commit: `refactor!: one Start and Shutdown lifecycle`.

### Task 10: Guards (tasks 5.1–5.2, dispatch E)

**Interfaces:**
- Produces:
  - `httpsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`
  - `httpsec.WithChainAuthorizer() GuardOption`
  - `ginsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`
  - `ginsec.WithChainAuthorizer() GuardOption`
  - `type fibersec.GuardOption func(*guardConfig)`
  - `fibersec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`
  - `fibersec.WithChainAuthorizer() GuardOption`

- [ ] **Step 1 (5.1): Failing tests.** `TestNewGuards_Authorizer` in `httpsec`, with cases:
  - `"nil authorizer"` and `"typed-nil authorizer"` (Review Focus 4), each asserting `ErrorIs(err, httpsec.ErrConfig)` and nil guards;
  - `"chain authorizer declared"`, where a route through a chain with `EnableAuthorization` and a privileged principal is called (200);
  - `"declared reliance, no chain authorizer"`, refused with `authorize.ErrAccessDenied`;
  - `"both given"`, where the request's authorizer is preferred.

  Run. Expected: FAIL on the two nil cases.
- [ ] **Step 2:** Implement. Update every `NewGuards` caller, including examples and the test module. Run. Expected: PASS.
- [ ] **Step 3 (5.2):** The same table in `ginsec` and `fibersec`, plus `"fiber refusal reaches the consumer's error handler"` (a fiber app whose `ErrorHandler` writes `"custom"` receives the guard's refusal). Run. Expected: FAIL on the nil cases. Implement. Run. Expected: PASS. Commit: `feat!: guards declare where their authorizer comes from`.

### Task 11: Nil context in the exchange (task 6.1, dispatch F)

- [ ] **Step 1: Failing tests.** `TestExchange_NilContext`, with cases:
  - `"new exchange"`: `require.PanicsWithValue(t, "httpsec: NewExchange needs a non-nil context", …)`;
  - `"set context"`: `PanicsWithValue(t, "httpsec: Exchange.SetContext needs a non-nil context", …)`.

  Run. Expected: FAIL, because neither panics.
- [ ] **Step 2:** Implement, and remove the `//nolint:contextcheck` on `NewExchange`. Run it, plus the `ginsec` and `fibersec` suites. Expected: PASS. Commit.

### Task 12: Deps and default scopes (tasks 7.1–7.2, dispatch F)

**Interfaces:**
- Produces:
  - `type httpsec.OIDCDeps struct{ RelyingParty *oidc.RelyingParty; Handoff *oidc.Handoff }`
  - `EnableOIDCLogin(d OIDCDeps, opts ...OIDCOption) Option`
  - `type httpsec.RecoveryCooldownDeps struct{ Records recovery.RecordStore; Cooldown time.Duration }`
  - `EnableRecoveryCooldown(d RecoveryCooldownDeps, routes ...Route) Option`
  - `func oidc.DefaultScopes() []string`

- [ ] **Step 1 (7.1): Failing test.** `TestEnableDeps_Required`, with cases:
  - `"oidc without relying party"` and `"oidc without handoff"`;
  - `"cooldown without records"` and `"cooldown of zero"`.

  Each asserts that `httpsec.New(...)` returns `ErrorIs(err, httpsec.ErrConfig)`. Run it against the new signatures with the checks absent. Expected: FAIL. Implement the checks. Run. Expected: PASS, and the existing OIDC and cooldown tests pass on the new signatures.
- [ ] **Step 2 (7.2):** Replace the variable with the function, using `slices.Clone` of an unexported array. Add `TestDefaultScopes_ReturnsACopy`, which overwrites element 0 of one result and asserts the next call returns `[]string{"openid", "profile", "email"}`. Expected: PASS. Commit: `refactor!: one Deps rule; DefaultScopes is a function`.

### Task 13: Final integration (tasks 8.1–8.2)

- [ ] **Step 1 (8.1, dispatch F):** Search `rg -n --glob '!openspec/**' --glob '!.claude/.legacy/**' 'RefusalLogFlusher|ErrSenderClosed|\.Stop\(\)|\.Close\(ctx|DefaultScopes\b[^(]'`. Fix each stale use in godoc, examples and the README. Expected: no hits.
- [ ] **Step 2 (8.2, main session):** Run `make check`, push, and wait for CI to be green, including the Docker suites. Then run `openspec validate idiomatic-api-shape --strict`, and dispatch the Opus whole-branch reviewer with the eight deltas, D1–D8 and `git diff origin/main...HEAD`. Expected: green, valid, and a clean review.
