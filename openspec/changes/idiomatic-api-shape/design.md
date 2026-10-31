# Design

## Context

See `proposal.md` (Why) for the motivation, and the eight deltas under `specs/` for the requirements. This change lands after `restructure-layout`, and every path and name below is the one that change produces: `session.Sessions`, `signingkey.Keys`, `policy/lockout`, `expiry/sweep`, `httpsec/ginsec`, `httpsec/fibersec`, `store/seal`, `token/signingkey`.

Facts that shape the approach:
- **Twelve constructors return a port interface backed by an unexported type.** The godoc of `authenticate.RefusalLogFlusher` and `policy.RefusalLogFlusher` tells consumers to type-assert, and so does `README.md` (`requirement.(policy.LoginAdmission)`).
- **`FlushRefusalLogs` has ten implementations in two shapes.** Eight return `error`. The two aggregators, `policy.Engine` and `httpsec.Chain`, return nothing, and discard what the flushers they reach return. Three components probe consumer-supplied values for the method: `policy.Engine`, `httpsec` (on authenticators, in `login.go` and `basic.go`), and `oidc.RelyingParty` (on its broker). Every probe discards the error, with a comment that the flush is "documented never to fail". That holds for the library's own implementations, not for a consumer's.
- **The four background components differ** in method names, in what a second `Start` does, in whether stopping is terminal, and in whether the start context ends their work. Only `sweep` already has the sentinels `ErrAlreadyStarted` and `ErrAlreadyShutdown`.
- **`Keys` and `session.MemoryStore` are restartable on purpose today.** Their godoc says a `Start` under a fresh context, after the first one was cancelled, is "the only way" to get the background work back without a new instance. That need exists only because the start context can end the work. D4 removes the cause, so it removes the restart too.
- **`sweep`'s `Shutdown` already shares one result.** The scheduler is shut down once, and every call, concurrent or later, returns that shutdown's result. That is nil, or the error saying a purge outlasted the stop timeout. A call whose own context ends first returns an error wrapping that context's error, and a later call still gets the shared result.
- **The library builds the three option-taking memory stores as defaults in six places:** `onetime.New`, `session.New`, `lockout.New`, `passkey.New` (its challenge store), the recovery hold store, and `httpsec`'s `EnableMFA` set-up (its challenge store). Each enclosing function already returns an error.
- **`sweep`'s `WithStopTimeout`** (default 10 seconds) bounds how long gocron waits for a cancelled purge. It is passed to gocron itself, and is separate from Shutdown's context.
- **`httpsec.NewExchange` returns `*Exchange`** and turns a nil context into `context.Background`. `Exchange.SetContext` ignores nil.
- **The adapters have no configuration sentinel of their own.** Their guards are `httpsec` guards adapted to gin and fiber.
- **Guards already prefer the authorizer the chain publishes on the request,** and fall back to the one they were built with (`http-security-chain`). Their godoc says `NewGuards` "reports no error because there is nothing to misconfigure". D5 reverses that.
- **`EnableOIDCLogin`'s handoff is conditionally required.** It is required unless `WithOIDCCallbackSuccess` conveys the login instead, and must then be nil (`oidc-login`).
- **`EnableRecoveryCooldown` already refuses** a nil store (typed nil included), a cooldown of zero or less, no routes, and a route with an empty method or path.

## Goals / Non-Goals

**Goals:**
- **Every behaviour change is test-first.** Each spec scenario becomes the failing test of its task.
- **Each concrete type keeps satisfying its port,** checked at compile time.

**Non-Goals:**
- **`context.Context` on the key and cipher ports.** That is `key-port-context`.
- **Moving `internal/assurance`'s types, `session.ErrDeleteDidNotSettle`, or any port.** `proposal.md` (Not in this change) gives the reasons.
- **Adding nil-context checks to every function that takes a context** (D6).

## Decisions

### D1. Constructors return concrete types; ports keep their names

| Constructor | New result |
|---|---|
| `authenticate.NewUsernamePasswordAuthenticator` | `*UsernamePasswordAuthenticator` |
| `authenticate.NewJWTAuthenticator` | `*JWTAuthenticator` |
| `policy.NewMFA` | `*MFA` |
| `policy.NewMFARequirement` | `*MFARequirement` |
| `password.NewBcryptEncoder`, `NewScryptEncoder`, `NewArgon2idEncoder` | `*BcryptEncoder`, `*ScryptEncoder`, `*Argon2idEncoder` |
| `token.NewGenerator` | `*JWTGenerator` |
| `token.NewVerifier` | `*JWTVerifier` |
| `seal.NewKeyring` | `*StaticKeyring` |
| `seal.NewAEADCipher` | `*AEADCipher` |
| `signingkey.NewMemoryKeyStore` | `*MemoryKeyStore` |

Each constructor keeps its parameters and its error return. The unexported implementing type is renamed to the exported one. Each file keeps a compile-time check: `var _ Authenticator = (*UsernamePasswordAuthenticator)(nil)`, and the same for every row.

**No new method becomes public.** Every exported method of these types is already reachable through the port, or through an exported optional interface the type satisfies:

| Type | Methods | Already reachable through |
|---|---|---|
| `UsernamePasswordAuthenticator` | `Authenticate`, `FlushRefusalLogs`, `VerifyDecoy` | `Authenticator`, `logsample.Flusher`, `DecoyVerifier` |
| `JWTAuthenticator` | `Authenticate` | `Authenticator` |
| `MFA` | `Name`, `Phases`, `Challenges`, `Evaluate`, `FlushRefusalLogs` | `Policy`, `logsample.Flusher` |
| `MFARequirement` | as `MFA`, plus `NeedsFederatedAssuranceSource`, `AdmitsWithoutLocalSecondFactor` | plus `FederatedAssuranceUser`, `LoginAdmission` |
| the three encoders | `Encode`, `Match`, `Recognizes` | `Encoder` and its optional interface |
| `JWTGenerator`, `JWTVerifier` | `Generate`, `Verify` | `Generator` (which embeds `Verifier`), `Verifier` |
| `StaticKeyring`, `AEADCipher` | `Active`, `ByID`; `Seal`, `Open`, `ActiveKeyID` | `Keyring`, `Cipher` |
| `MemoryKeyStore` | `Store`, `LoadAll` | `KeyStore` |

None of these may be unexported, because the probes that find the optional interfaces need them exported. What this decision does add to the API is the type names and their zero values.

**The zero value is not usable.** A zero `MFA` has no exemption rule and would panic on its first `Evaluate`, and the other types hold configuration only their constructor validates. Each type's godoc says to build it with its constructor. No method guards against the zero value, because a guard would have to choose between failing open and inventing a default. `README.md`'s type assertion becomes a direct method call.

These keep returning their interface, because each one is a wrapper over a port it does not own:
- decorators: `session.NewEncryptedStore`, `seal.NewEnrolmentStore`, `seal.NewSigningKeyStore`, `seal.SessionCipher`, and the backends' sealing `New…Store`;
- small factory values: `clock.System`, `ratelimit.MemoryLimiterFactory`, `recovery.MFAEnrolments`, `passkey.NewRecoveryKind`, and the `webauthn` metadata sources.

**Default and override:** no default changes. A consumer still passes their own implementation of each port wherever one is accepted.

**Alternatives considered:**
- **Keep returning interfaces.** Consumers keep needing type assertions, and every new method is a breaking change to a port.
- **Move ports to their consumers.** That redesigns the extension points (proposal).

### D2. One optional flush interface: `logsample.Flusher`

`pkg/logsample` gains `type Flusher interface { FlushRefusalLogs() error }`.

`authenticate.RefusalLogFlusher` and `policy.RefusalLogFlusher` are removed, and `oidc`'s anonymous interface is replaced. The three probes (`policy.Engine`, `httpsec`, `oidc.RelyingParty`) assert against `logsample.Flusher`. The godoc of the concrete types (D1), of `Engine` and of `Chain` documents `FlushRefusalLogs` as a method, and says nothing about type assertion.

**The aggregators join errors instead of discarding them.** `policy.Engine.FlushRefusalLogs` and `httpsec.Chain.FlushRefusalLogs` change from returning nothing to returning `error`, so both satisfy `logsample.Flusher`:
- each still flushes everything it reaches, in its documented order, even when one flush fails;
- each returns `errors.Join` of the errors it got, or nil;
- `Chain` returns the errors of the components it reaches, the policy engine's joined error included.
- **`authenticate.FirstOf` is an aggregator too.** It implements `logsample.Flusher`: it flushes each delegate that implements it, in delegate order, keeps going after a failure, and returns `errors.Join` of their errors, or nil. Without it, the form-login and basic-auth probes miss every flusher wrapped in a `FirstOf`, the authenticator `FormLoginDeps` suggests. The summary of suppressed refusals is then never written at flush, and a consumer delegate's error is lost. A nested `FirstOf` is reached through the same method. This is `UNREPRODUCED` until task 2.5's red test.

The library's own flushers never fail, so with the defaults nothing changes. A consumer's authenticator, broker or policy whose flush fails is now reported instead of discarded.

**Default and override:** unchanged. A consumer's own authenticator, policy or broker opts in to flushing by having the method, and may now return an error that reaches the caller of `Chain.FlushRefusalLogs`.

**Alternatives considered:**
- **Keep a copy in each probing package.** Two names for one method.
- **Keep both copies.** The structural typing works either way, but the duplication stays.
- **Keep `Engine` and `Chain` returning nothing.** They would be the only flushers that are not a `logsample.Flusher`, and a consumer flusher's error would stay silent (user's choice, 2026-10-31).

### D3. The option-taking memory stores return `(T, error)`

| Constructor | Refuses, with a configuration error |
|---|---|
| `onetime.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)` | a nil clock, typed nil included (`onetime.ErrConfig`) |
| `session.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)` | a housekeeping interval of zero or less; a nil clock, typed nil included (`session.ErrConfig`) |
| `lockout.NewMemoryAttemptStore(opts ...MemoryAttemptOption) (*MemoryAttemptStore, error)` | a capacity of zero or less, replacing the panic (`policy.ErrConfig`, which every `lockout` configuration error already wraps) |

When a consumer configures no store, the library builds these defaults in the six places listed in Context. Each enclosing function already returns an error and passes the store's error on unchanged. Those defaults are built with the enclosing component's own clock, which that component has already validated, so the error cannot occur in practice; passing it on keeps a future mistake visible instead of silent. The nine memory stores that take no options keep returning `*T`.

**Default and override:** the defaults are unchanged (the system clock, one minute, 100,000 identifiers), and each stays replaceable by its option. Only a meaningless value is now refused instead of ignored or panicking.

**Alternative considered:** make every `NewMemory…` return an error. That adds error returns to constructors that cannot fail.

### D4. One lifecycle: detached `Start(ctx)` and terminal `Shutdown(ctx)`

This applies to `signingkey.Keys`, `session.MemoryStore`, `sweep.Sweeper` and `notify.QueuedSender`.
- **`Start(ctx context.Context) error`** derives the work's context as `context.WithCancel(context.WithoutCancel(ctx))`, keeping the cancel function. The work therefore carries the start context's values (trace and log fields), and only Shutdown cancels it. `QueuedSender` keeps starting its workers in `NewQueuedSender`, and has no work context to cancel: each delivery already runs under its caller's context with the cancellation removed, bounded by the send timeout. Its Shutdown closes intake and waits for the drain instead of cancelling anything, because `email-notification` requires the messages already queued to be delivered, and cancelling the workers would abort that drain.
- **A second `Start`** returns `ErrAlreadyStarted`. A `Start` after Shutdown, and a send to a shut-down `QueuedSender`, return `ErrAlreadyShutdown`. `signingkey` and `session` declare both sentinels, following `sweep`'s existing names. `notify` declares only `ErrAlreadyShutdown`, because `QueuedSender` has no `Start`.
- **`Shutdown(ctx context.Context) error`:**
  - marks the component shut down (terminal);
  - cancels the work's context (for `QueuedSender`, closes intake and lets the queue drain);
  - waits for the work's `WaitGroup` inside a `select` on `ctx.Done()`;
  - returns nil once the work has ended, or `ctx.Err()` if the context is done first.

  A later call waits again under its own context, and returns the shutdown's outcome. For `Keys`, `session.MemoryStore` and `QueuedSender`, that outcome is nil once the work has ended. For `Sweeper`, it is the shared result described in Context, which can be the stop-timeout error. Shutting down a component that was never started marks it shut down and returns nil.
- **Completion wins a tie.** When the work has already ended and the context given to Shutdown is already done, Shutdown returns nil. It checks completion before it waits, so the result does not depend on which `select` case Go happens to pick.
- **Terminal means the background work only.** After Shutdown, the work never runs again, and every other method keeps its contract:
  - `Keys` still serves `Signer`, `VerificationKeys` and `JWKS` from the keys it holds, and no longer rotates;
  - `session.MemoryStore` still saves, loads and deletes sessions, and no longer sweeps expired ones on its own;
  - only `QueuedSender` refuses new messages, because accepting a message is a promise its workers will deliver it.

  The OpenTelemetry reference below supports the terminal state, not its "every method becomes a no-op" rule. A session store that stopped saving at shutdown would lose sessions while requests are still being drained.
- **Shutdown from inside the component's own work** cannot wait for itself. A purge, an error hook of `Keys`, or a wrapped sender that calls Shutdown waits until its own context ends, and returns that context's error. Each `Shutdown`'s godoc says so, and says to call it from outside the work.
- **Renames:** `Keys.Stop()`, `MemoryStore.Stop()` and `QueuedSender.Close(ctx)` become `Shutdown(ctx)`. `notify.ErrSenderClosed` becomes `notify.ErrAlreadyShutdown`.
- **`sweep`'s `WithStopTimeout` stays.** It is gocron's own bound on a cancelled purge (default 10 seconds), and Shutdown returns when either that timeout or its own context ends first, as it does today.

**Default and override:** start-up and shutdown need no configuration. The consumer controls how long Shutdown waits through its context, and `sweep` keeps `WithStopTimeout` as the override for gocron's wait.

**Alternatives considered:**
- **Let the start context keep cancelling the work.** A request context passed by mistake stops background work. That is why `Keys` and the session memory store are restartable today, and why their godoc calls restart "the only way" to recover. With the work detached, a request context can no longer stop it, the restart is no longer needed, and the settled `signing-keys` and `sessions` requirements are modified to make Shutdown terminal.
- **Rename the methods but keep each component's semantics.** The three contradicting spec rules stay.

### D5. Guards need an authorizer or `WithChainAuthorizer()`

`httpsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`. `ginsec.NewGuards` and `fibersec.NewGuards` take the same parameters.

A nil or typed-nil `az` fails with an error wrapping `httpsec.ErrConfig`, unless the option `WithChainAuthorizer()` is given. That option records the consumer's declaration that the guards rely on the authorizer the chain publishes on each request. The adapters reuse `httpsec.ErrConfig`, because their guards are `httpsec` guards adapted to a framework. The typed-nil check uses the library's existing `internal/nilcheck`.

**A typed nil is never a fallback.** With `WithChainAuthorizer()`, a typed-nil `az` is stored as no fallback at all. A request with no authorizer in its context is then refused with the access-denied error, as for a plain nil, instead of calling a method on a nil value.

Giving both a non-nil `az` and `WithChainAuthorizer()` is allowed and means what it says: the request's authorizer is preferred, and `az` is the fallback.

`httpsec` and `ginsec` already have a `GuardOption` type, and gain `WithChainAuthorizer()`. `fibersec.NewGuards` takes no options today. It gains a `GuardOption` type of the same shape, `func(*Guards)`, for `WithChainAuthorizer()` alone. Fiber refusals stay rendered by `fiber.Config.ErrorHandler` (`framework-adapters`). The builder methods keep panicking at wiring time on a nil receiver, checker or extractor, as `net/http`'s `ServeMux.Handle` does.

**Default and override:** the default is the safe one. Guards built with nothing refuse to build. The override is to pass an authorizer, or to declare reliance on the chain.

**Alternative considered:** accept nil silently, as today. Wiring that has forgotten the authorizer then looks the same as wiring that relies on the chain, and every guarded route refuses at request time.

### D6. A nil context is refused, never substituted

- **`httpsec.NewExchange`,** which returns no error, panics on a nil context with `"httpsec: NewExchange needs a non-nil context"`, as `http.Request.WithContext` does.
- **`Exchange.SetContext`** panics on nil.
- **The lifecycle methods in D4** return an error wrapping their package's configuration sentinel for a nil context (`ErrInvalidOption` in `sweep`, `ErrConfig` elsewhere), and change nothing. That means `Start` on `Keys`, `session.MemoryStore` and `Sweeper`, and `Shutdown` on all four. `sweep` already does this for both of its methods.

The library adds no nil check to functions that merely pass a context along. Those fail at first use, which is the standard library's convention. The rule bans substitution, not unchecked use.

**Default and override:** this is a programming contract, so there is no option to accept a nil context.

**Alternative considered:** check nil in every function that takes a context. That adds hundreds of checks for a mistake the standard library leaves to the caller.

### D7. One required dependency is positional; two or more go in `Deps`

The rule counts dependencies: components the function calls. A required value that is not a dependency, such as a duration or a list of rules or routes, stays a parameter.

- `EnableOIDCLogin(d OIDCDeps, opts ...OIDCOption) Option`, where `OIDCDeps{RelyingParty *oidc.RelyingParty; Handoff *oidc.Handoff}`.
  - The existing rules move with the fields unchanged:
    - a nil `RelyingParty` fails at chain construction with `httpsec.ErrConfig`;
    - `Handoff` is required unless `WithOIDCCallbackSuccess` is given, and must then be nil.
  - Both checks exist today, so this is a signature change that the existing tests cover.
- `EnableRecoveryCooldown(records, d, routes...)` is unchanged. It has one dependency, the record store; the cooldown and the routes are required values, which it already refuses when absent. It follows the rule, as `EnableAuthorization(az, rules...)` does.

Every other `Enable…` function already follows the rule.

**Default and override:** none changes. These are required dependencies, not defaults.

**Alternative considered:** a `RecoveryCooldownDeps{Records, Cooldown}` struct. It would count a duration as a dependency, contradicting the rule it applies (user's choice, 2026-10-31).

### D8. `oidc.DefaultScopes()` returns a copy

`func DefaultScopes() []string` returns `[]string{"openid", "profile", "email"}` as a new slice on each call. `resolveProvider` calls it.

**Why it matters beyond style:** the registry checks that a non-nil `Provider.Scopes` includes `openid`, but takes nil scopes from the global without checking it. A consumer, or a dependency, that changed `oidc.DefaultScopes` could therefore drop `openid` from every provider left on the defaults, past the check. This is `UNREPRODUCED`: a code reading, pending the copy test of task 7.2.

**Default and override:** the default scopes are unchanged. They are replaced per provider through `Provider.Scopes`, as before. No process-wide override exists any more, and none is needed.

## Risks / Trade-offs

- **Tests that stop background work by cancelling the start context now leak goroutines.** → Those tests are rewritten to call `Shutdown`, and the leak checks (`goleak`) in each package prove no goroutine remains.
- **A consumer who relied on cancelling the start context loses that stop signal.** → Nothing is tagged, so no consumer exists yet. The godoc of each `Start` says that only `Shutdown` stops the work.
- **Exported concrete types widen the API surface.** → They add type names and zero values, not methods (D1's table). Each type's godoc says its zero value is unusable.
- **`Chain.FlushRefusalLogs` returning an error** is flagged by `errcheck` wherever a caller ignores it. → The library's own callers and examples handle or explicitly discard it, in the same task.
- **Changing `NewExchange` to panic on nil** could crash an integration that passed nil. → `ginsec` and `fibersec` always pass the request's context. The panic message names the function.
- **The test module calls every changed constructor.** → It is updated in the same task as each constructor, so the workspace always builds.

## Migration Plan

1. Start from `main` once `restructure-layout` is merged and archived.
2. Implement D1–D8 test-first, one decision per task group: write each spec scenario's failing test, then the change.
3. Update godoc, the examples and the README for every changed signature, in the same group as the change.
4. Run the whole-branch review against the eight deltas and D1–D8. Confirm `make check` and CI are green, including the Docker suites.

**Rollback:** revert the merge. Nothing is tagged.

## References

### D1: concrete return types

**Researched (accessed 2026-10-25):**
- [Go Code Review Comments: Interfaces](https://go.dev/wiki/CodeReviewComments#interfaces): implementers return concrete types, so that new methods can be added without breaking anyone.

### D4: lifecycle

**Researched (accessed 2026-10-25):**
- [net/http `Server.Shutdown`](https://pkg.go.dev/net/http#Server.Shutdown): Shutdown is bounded by its context, and a server "may not be reused" after Shutdown.
- [OpenTelemetry Go SDK `TracerProvider.Shutdown`](https://pkg.go.dev/go.opentelemetry.io/otel/sdk/trace#TracerProvider.Shutdown): "After Shutdown is called, all methods are no-ops."

**Primary documentation:**
- [context `WithoutCancel`](https://pkg.go.dev/context#WithoutCancel): a context that keeps its parent's values but is not cancelled with it.

### D5, D6: guards and nil contexts

**Primary documentation:**
- [context](https://pkg.go.dev/context): "Do not pass a nil Context, even if a function permits it."
- [net/http `Request.WithContext`, `NewRequestWithContext` and `ServeMux.Handle`](https://pkg.go.dev/net/http): panic or error on a nil context, and panic on a nil handler at registration.

### D2: one flush interface, aggregators joining errors

**Primary documentation:**
- [errors `Join`](https://pkg.go.dev/errors#Join): one error wrapping several, nil when all are nil, each still matched by `errors.Is` and `errors.As`.

The aggregators' new return value is the user's choice of 2026-10-31, reasoned from the tree: two of the ten flushers return nothing, and every probe discards a consumer flusher's error.

`FirstOf` forwarding is the user's choice of 2026-10-31, reasoned from the tree: the two login probes assert on the authenticator they were given, and `FirstOf` already forwards the decoy check to its delegates.

### D3, D7, D8

Reasoned from scrty's own settled specs and code: library-design rules 2, 4 and 6, the construction-error pattern of `password`, `sqlstore`, `pgx` and the limiters, the conditional handoff rule of `oidc-login`, and the registry's scope check. Keeping `EnableRecoveryCooldown` positional is the user's choice of 2026-10-31.
