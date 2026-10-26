# Design

## Context

See `proposal.md` (Why) for the motivation, and the eight deltas under `specs/` for the requirements. This change lands after `restructure-layout`, and every path and name below is the one that change produces: `session.Sessions`, `signingkey.Keys`, `policy/lockout`, `expiry/sweep`, `httpsec/ginsec`, `httpsec/fibersec`, `store/seal`, `token/signingkey`.

Facts that shape the approach:
- **Twelve constructors return a port interface backed by an unexported type.** The godoc of `authenticate.RefusalLogFlusher` and `policy.RefusalLogFlusher` tells consumers to type-assert. The same method, `FlushRefusalLogs() error`, has ten implementations. Three components probe consumer-supplied values for it: `policy.Engine`, `httpsec` (on authenticators), and `oidc.RelyingParty` (on its broker).
- **The four background components differ** in method names, in what a second `Start` does, in whether stopping is terminal, and in whether the start context ends their work. Only `sweep` already has the sentinels `ErrAlreadyStarted` and `ErrAlreadyShutdown`.
- **`sweep`'s `WithStopTimeout`** (default 10 seconds) bounds how long gocron waits for a cancelled purge. It is passed to gocron itself, and is separate from Shutdown's context.
- **`httpsec.NewExchange` returns `*Exchange`** and turns a nil context into `context.Background`. `Exchange.SetContext` ignores nil.
- **The adapters have no configuration sentinel of their own.** Their guards are `httpsec` guards adapted to gin and fiber.
- **Guards already prefer the authorizer the chain publishes on the request,** and fall back to the one they were built with (`http-security-chain`).

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

Each constructor keeps its parameters and its error return. The unexported implementing type is renamed to the exported one, and its existing exported methods become callable. Each file keeps a compile-time check: `var _ Authenticator = (*UsernamePasswordAuthenticator)(nil)`, and the same for every row.

These keep returning their interface, because each one is a wrapper over a port it does not own:
- decorators: `session.NewEncryptedStore`, `seal.NewEnrolmentStore`, `seal.NewSigningKeyStore`, `seal.SessionCipher`, and the backends' sealing `New…Store`;
- small factory values: `clock.System`, `ratelimit.MemoryLimiterFactory`, `recovery.MFAEnrolments`, `passkey.NewRecoveryKind`, and the `webauthn` metadata sources.

**Default and override:** no default changes. A consumer still passes their own implementation of each port wherever one is accepted.

**Alternatives considered:**
- **Keep returning interfaces.** Consumers keep needing type assertions, and every new method is a breaking change to a port.
- **Move ports to their consumers.** That redesigns the extension points (proposal).

### D2. One optional flush interface: `logsample.Flusher`

`pkg/logsample` gains `type Flusher interface { FlushRefusalLogs() error }`. Every one of the ten implementers already imports `pkg/logsample`.

`authenticate.RefusalLogFlusher` and `policy.RefusalLogFlusher` are removed, and `oidc`'s anonymous interface is replaced. The three probes (`policy.Engine`, `httpsec`, `oidc.RelyingParty`) assert against `logsample.Flusher`. The godoc of the concrete types (D1) documents `FlushRefusalLogs` as a method, and says nothing about type assertion.

**Default and override:** unchanged. A consumer's own authenticator, policy or broker opts in to flushing by having the method.

**Alternatives considered:**
- **Keep a copy in each probing package.** Two names for one method.
- **Keep both copies.** The structural typing works either way, but the duplication stays.

### D3. The option-taking memory stores return `(T, error)`

| Constructor | Refuses, with its package's `ErrConfig` |
|---|---|
| `onetime.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)` | a nil clock, typed nil included |
| `session.NewMemoryStore(opts ...MemoryStoreOption) (*MemoryStore, error)` | a housekeeping interval of zero or less; a nil clock |
| `lockout.NewMemoryAttemptStore(opts ...MemoryAttemptOption) (*MemoryAttemptStore, error)` | a capacity of zero or less (replaces the panic) |

When a consumer configures no store, the library builds these defaults inside a constructor that already returns an error (`onetime.New`, `session.New`, `lockout.New`), and passes their error on unchanged. The ten memory stores that take no options keep returning `*T`.

**Default and override:** the defaults are unchanged (the system clock, one minute, 100,000 identifiers), and each stays replaceable by its option. Only a meaningless value is now refused instead of ignored or panicking.

**Alternative considered:** make every `NewMemory…` return an error. That adds error returns to constructors that cannot fail.

### D4. One lifecycle: detached `Start(ctx)` and terminal `Shutdown(ctx)`

This applies to `signingkey.Keys`, `session.MemoryStore`, `sweep.Sweeper` and `notify.QueuedSender`.
- **`Start(ctx context.Context) error`** derives the work's context as `context.WithCancel(context.WithoutCancel(ctx))`, keeping the cancel function. The work therefore carries the start context's values (trace and log fields), and only Shutdown cancels it. `QueuedSender` keeps starting its workers in `NewQueuedSender`, and its workers' context is derived the same way from `context.Background()`.
- **A second `Start`** returns `ErrAlreadyStarted`. A `Start` after Shutdown, and a send to a shut-down `QueuedSender`, return `ErrAlreadyShutdown`. Each package declares both sentinels, following `sweep`'s existing names.
- **`Shutdown(ctx context.Context) error`:**
  - marks the component shut down (terminal);
  - cancels the work's context;
  - waits for the work's `WaitGroup` inside a `select` on `ctx.Done()`;
  - returns nil once the work has ended, or `ctx.Err()` if the context is done first.

  A later call waits again under its own context, so a call made after the work has ended returns nil. Shutting down a component that was never started marks it shut down and returns nil.
- **Renames:** `Keys.Stop()`, `MemoryStore.Stop()` and `QueuedSender.Close(ctx)` become `Shutdown(ctx)`. `notify.ErrSenderClosed` becomes `notify.ErrAlreadyShutdown`.
- **`sweep`'s `WithStopTimeout` stays.** It is gocron's own bound on a cancelled purge (default 10 seconds), and Shutdown returns when either that timeout or its own context ends first, as it does today.

**Default and override:** start-up and shutdown need no configuration. The consumer controls how long Shutdown waits through its context, and `sweep` keeps `WithStopTimeout` as the override for gocron's wait.

**Alternatives considered:**
- **Let the start context keep cancelling the work.** A request context passed by mistake stops background work. The session memory store would then have to be restartable, or lose every session it holds.
- **Rename the methods but keep each component's semantics.** The three contradicting spec rules stay.

### D5. Guards need an authorizer or `WithChainAuthorizer()`

`httpsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) (*Guards, error)`. `ginsec.NewGuards` and `fibersec.NewGuards` take the same parameters.

A nil or typed-nil `az` fails with an error wrapping `httpsec.ErrConfig`, unless the option `WithChainAuthorizer()` is given. That option records the consumer's declaration that the guards rely on the authorizer the chain publishes on each request. The adapters reuse `httpsec.ErrConfig`, because their guards are `httpsec` guards adapted to a framework.

Giving both a non-nil `az` and `WithChainAuthorizer()` is allowed and means what it says: the request's authorizer is preferred, and `az` is the fallback.

`fibersec` gains a `GuardOption` type for `WithChainAuthorizer()` alone. Fiber refusals stay rendered by `fiber.Config.ErrorHandler` (`framework-adapters`). The builder methods keep panicking at wiring time on a nil receiver, checker or extractor, as `net/http`'s `ServeMux.Handle` does.

**Default and override:** the default is the safe one. Guards built with nothing refuse to build. The override is to pass an authorizer, or to declare reliance on the chain.

**Alternative considered:** accept nil silently, as today. Wiring that has forgotten the authorizer then looks the same as wiring that relies on the chain, and every guarded route refuses at request time.

### D6. A nil context is refused, never substituted

- **`httpsec.NewExchange`,** which returns no error, panics on a nil context with `"httpsec: NewExchange needs a non-nil context"`, as `http.Request.WithContext` does.
- **`Exchange.SetContext`** panics on nil.
- **The lifecycle methods in D4** return an error wrapping their package's configuration sentinel for a nil context (`ErrInvalidOption` in `sweep`, `ErrConfig` elsewhere). `sweep` already does this.

The library adds no nil check to functions that merely pass a context along. Those fail at first use, which is the standard library's convention. The rule bans substitution, not unchecked use.

**Default and override:** this is a programming contract, so there is no option to accept a nil context.

**Alternative considered:** check nil in every function that takes a context. That adds hundreds of checks for a mistake the standard library leaves to the caller.

### D7. One required dependency is positional; two or more go in `Deps`

- `EnableOIDCLogin(d OIDCDeps, opts ...OIDCOption) Option`, where `OIDCDeps{RelyingParty *oidc.RelyingParty; Handoff *oidc.Handoff}`.
- `EnableRecoveryCooldown(d RecoveryCooldownDeps, routes ...Route) Option`, where `RecoveryCooldownDeps{Records recovery.RecordStore; Cooldown time.Duration}`.

A nil field fails at chain construction with `httpsec.ErrConfig`, as the other `Deps` structs already do. Every other `Enable…` function already follows the rule.

**Default and override:** none changes. These are required dependencies, not defaults.

### D8. `oidc.DefaultScopes()` returns a copy

`func DefaultScopes() []string` returns `[]string{"openid", "profile", "email"}` as a new slice on each call. `resolveProvider` calls it.

**Default and override:** the default scopes are unchanged. They are replaced per provider through `Provider.Scopes`, as before. No process-wide override exists any more, and none is needed.

## Risks / Trade-offs

- **Tests that stop background work by cancelling the start context now leak goroutines.** → Those tests are rewritten to call `Shutdown`, and the leak checks (`goleak`) in each package prove no goroutine remains.
- **A consumer who relied on cancelling the start context loses that stop signal.** → Nothing is tagged, so no consumer exists yet. The godoc of each `Start` says that only `Shutdown` stops the work.
- **Exported concrete types widen the API surface,** and every exported method becomes a compatibility commitment from `v0.1.0`. → Each concrete type is reviewed for methods that should stay unexported before it is exported.
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

### D2, D3, D7, D8

Reasoned from scrty's own settled specs and code: library-design rules 2, 4 and 6, and the construction-error pattern of `password`, `sqlstore`, `pgx` and the limiters.
