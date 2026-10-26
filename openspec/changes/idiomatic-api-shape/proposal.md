# Proposal

## Why

A review of scrty's API found several places where it departs from idiomatic Go or from the library's own design rules:

- **Constructors hide their concrete types.** Twelve constructors return an interface backed by an unexported type, and their godoc tells consumers to reach the rest of the API with a type assertion. That assertion advice is why `RefusalLogFlusher` exists in two packages.
- **The same wiring mistake fails three ways.** For a bad option, one memory store panics, another ignores it silently, and a third falls back to a default because its constructor "cannot fail".
- **Four background components disagree on how they start and stop.** They use different method names. Starting twice is an error for one and a silent no-op for another. A stopped component is terminal for one and restartable for another. A request context cancelled by mistake ends background work for two of them.
- **The remaining inconsistencies:**
  - a nil context is substituted in one place, ignored in another and refused in a third;
  - guards accept a nil authorizer without saying where their authorizer comes from;
  - `fibersec` guards cannot have their error handler replaced;
  - `httpsec` mixes positional arguments and `Deps` structs for required dependencies;
  - `oidc.DefaultScopes` is an exported mutable global.

Every one of these is a public API or behaviour change. Nothing is tagged yet, so this is the last point at which they can be made without breaking anyone. The change lands after `restructure-layout` and uses its names.

## What Changes

**BREAKING** in signatures and in the specified lifecycle behaviour.

- **Constructors return concrete types.**
  - The new return types:
    - `authenticate`: `*UsernamePasswordAuthenticator`, `*JWTAuthenticator`;
    - `policy`: `*MFA`, `*MFARequirement`;
    - `password`: `*BcryptEncoder`, `*ScryptEncoder`, `*Argon2idEncoder`;
    - `token`: `*JWTGenerator`, `*JWTVerifier`;
    - `seal`: `*StaticKeyring`, `*AEADCipher`;
    - `signingkey`: `*MemoryKeyStore`.
  - The ports (`Authenticator`, `Policy`, `Encoder`, `Generator`, `Verifier`, `Keyring`, `Cipher`, `KeyStore`) keep their names and packages.
  - Decorators and small factory values keep returning their interface.
- **One optional flush interface.** `logsample.Flusher` replaces `authenticate.RefusalLogFlusher`, `policy.RefusalLogFlusher` and `oidc`'s anonymous interface. The type-assertion advice goes from the godoc.
- **Memory stores refuse bad options at construction.** The three in-memory stores that take options (`onetime`, `session`, `lockout`) return `(T, error)`. They refuse a nil clock, a housekeeping interval of zero or less, and a capacity of zero or less, each with their package's `ErrConfig`.
- **One lifecycle for background components.** `signingkey.Keys`, `session.MemoryStore`, `sweep.Sweeper` and `notify.QueuedSender` share these rules:
  - `Start(ctx)` passes the context's values to the background work but not its cancellation, so a request context can never stop that work.
  - A second `Start` returns `ErrAlreadyStarted`, and a `Start` after shutdown returns `ErrAlreadyShutdown`.
  - `Shutdown(ctx)` waits no longer than its context allows. It is terminal and idempotent.
  - `Stop()` and `Close(ctx)` are replaced by `Shutdown(ctx)`.
- **Guards state where their authorizer comes from.** `NewGuards` in `httpsec`, `ginsec` and `fibersec` returns `(*Guards, error)`. It refuses a nil authorizer unless the consumer opts in to the chain's authorizer with an explicit option. The builder methods keep panicking at wiring time on a nil receiver, checker or extractor.
- **`fibersec` guards take `GuardOption`,** for the option that declares reliance on the chain's authorizer. Refusal rendering stays with `fiber.Config.ErrorHandler`, the specified override on fiber, so no guard error-handler option is added.
- **A nil context is refused, never substituted.**
  - A function that returns an error refuses a nil context with an invalid-argument error.
  - A function that cannot return an error panics.
  - `httpsec.Exchange` stops substituting `context.Background`, and stops ignoring nil in `SetContext`.
- **Required dependencies follow one rule.** One required dependency is a positional argument; two or more go in a `Deps` struct. `EnableOIDCLogin` takes `OIDCDeps`, and `EnableRecoveryCooldown` takes `RecoveryCooldownDeps`.
- **`oidc.DefaultScopes()` becomes a function** that returns a fresh copy.

### Not in this change

- **`context.Context` on the key and cipher ports** (`seal.Keyring`, `seal.Cipher`, `session.Cipher`, `signingkey.KeySource`). This is the separate change `key-port-context`, which lands next.
- **Moving `internal/assurance`'s types into `policy`.** Keeping them internal is deliberate: only the library can mint a second-factor proof that holds, and the `policy` aliases let consumers name the types without forging them.
- **Moving `session.ErrDeleteDidNotSettle`.** It belongs to the `session.Store` contract that returns it.
- **Moving ports to their consuming packages.** That would be a redesign of the extension points, not an idiom fix.

### Order

`restructure-layout` → this change → `key-port-context` → `trusted-proxy-client-ip` → `release-readiness` (v0.1.0).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `signing-keys`: "Start is idempotent and construction starts nothing" changes to the shared lifecycle: a second Start fails, Start after Shutdown fails, and a cancelled start context does not stop the key manager.
- `sessions`: the in-memory store's housekeeping follows the shared lifecycle. It is no longer stopped by its start context, and Shutdown is terminal. The store refuses a housekeeping interval of zero or less and a nil clock at construction.
- `expiry-sweeping`: "The scheduled sweeper starts and stops cleanly" keeps its errors and idempotent Shutdown. The context given to Start no longer cancels runs; Shutdown does.
- `email-notification`: the queued sender's close becomes Shutdown, with the same drain and deadline behaviour, and is terminal.
- `security-policy`: the default attempt store refuses a capacity of zero or less with a configuration error instead of panicking.
- `one-time-tokens`: the in-memory store refuses a nil clock at construction instead of keeping the default.
- `http-security-chain`: a guard is built with an authorizer, or with an explicit opt-in to the chain's authorizer. Building one with neither is a configuration error.
- `framework-adapters`: gin and fiber guards follow the same construction rule. On fiber, refusals stay rendered by fiber's error handler.

The return types, `logsample.Flusher`, the nil-context rule, the `Deps` rule and `DefaultScopes()` are API shape that no spec requirement states. They are decided in `design.md` and need no spec delta. Each requirement above is confirmed against its full text when the spec deltas are written.

## Impact

- **Code:**
  - the twelve constructors and every caller of them;
  - the four lifecycle owners, and their callers in `httpsec`, `sweep` and the test module;
  - `httpsec`, `httpsec/ginsec` and `httpsec/fibersec` guards;
  - `httpsec.Exchange`, `EnableOIDCLogin` and `EnableRecoveryCooldown`;
  - `oidc`'s registry;
  - `authenticate`, `policy`, `oidc` and `pkg/logsample` for the flush interface.
- **Tests:** test-first for every behaviour change. Existing lifecycle and construction tests whose expectations change are rewritten to the new specification.
- **Dependencies, migrations, stored data:** unchanged.
- **Consumers:** none yet. Nothing is tagged.

## References

### Concrete return types (A)

**Researched (accessed 2026-10-25):**
- [Go Code Review Comments: Interfaces](https://go.dev/wiki/CodeReviewComments#interfaces): implementers "return concrete (usually pointer or struct) types"; interfaces generally belong with the consumer.

### Lifecycle (D)

**Researched (accessed 2026-10-25):**
- [net/http `Server.Shutdown`](https://pkg.go.dev/net/http#Server.Shutdown): Shutdown is bounded by its context, and "Once Shutdown has been called on a server, it may not be reused; future calls to methods such as Serve will return ErrServerClosed."
- [OpenTelemetry Go SDK `TracerProvider.Shutdown`](https://pkg.go.dev/go.opentelemetry.io/otel/sdk/trace#TracerProvider.Shutdown): Shutdown is terminal ("After Shutdown is called, all methods are no-ops").

### Nil context and wiring-time panics (G)

**Primary documentation:**
- [context](https://pkg.go.dev/context): "Do not pass a nil Context, even if a function permits it."
- [net/http `NewRequestWithContext`, `Request.WithContext` and `ServeMux.Handle`](https://pkg.go.dev/net/http): the first refuses a nil context with an error, the second panics on one, and the third panics on a nil handler at registration.

### Memory-store errors, guards, `Deps` and `DefaultScopes` (C, G, E)

Reasoned from scrty's own settled specs and code: library-design rules 2, 4 and 6, and the construction-error pattern already used by `password`, `sqlstore`, `pgx` and the limiters.
