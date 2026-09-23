## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** Port-foundation has landed:
  - the core module and its layout gates;
  - `pkg/id`, a sortable identifier with a replaceable generator;
  - `pkg/logsample`, a per-key per-window sampler with an optional reporter and `Flush`.

  There are no security packages, consumers or tags yet.
- **Capabilities from other changes, used by name and not restated:**
  - `identity-model`: principal, the opaque consumer-owned user reference, user loader, role loader, the MFA requirement lookup port, first-factor kinds with their channels and local-MFA exemptions, and context carriers;
  - `password-encoding`: the password encoder port and its default;
  - `token-issuance`: the token verifier;
  - `secrets-at-rest`: the cipher port;
  - `log-sampling` and `id-generation`.
- **Capabilities of later changes that consume this one:**
  - `http-security` and `http-error-propagation` assemble chains and map these sentinels to statuses;
  - `multi-factor-auth`, `magic-link` and `api-keys` use the policy, rate-limiting and one-time-token contracts;
  - `oidc-login` and `oidc-logout` use federated session attributes;
  - `security-state-stores` implements the store ports durably;
  - `expiry-sweeping` schedules purges and housekeeping.
- **Settled rules that shape departures below:**
  - consumer data is opaque;
  - options are named after what they govern;
  - wiring mistakes fail at construction;
  - refusal logs are sampled with a reporter;
  - library-owned records use `pkg/id`;
  - a same-channel second factor is an explicit decision with a safe default.

## Goals / Non-Goals

**Goals:**
- Behaviour that has been proven in review, written as scrty's own contract, with every departure named and grounded.
- Security decisions that are framework-free and testable without HTTP, a database or a scheduler.

**Non-Goals:**
- **HTTP interceptors, matchers, chain assembly and status mapping.** These belong to `http-security`.
- **Choosing which policies a default chain registers.** Each policy states its own defaults here.
- **Durable stores and conformance suites** (`security-state-stores`), and scheduling purges (`expiry-sweeping`).
- **Specific MFA methods, enrolment, magic-link issuance rules and API-key verification** (`auth-methods`).
- **A shared rate limiter** (`shared-rate-limiting`).
- **OIDC assurance claims** (`oidc-mfa-assurance`).
- **First-factor kinds and channels.** These are owned by `identity-model`.

## Decisions

### 1. Packages

All packages below live in the core module:

| Package | Holds |
|---|---|
| `authenticate` | manager, provider port, password and bearer-token providers, result, context carrier |
| `authorize` | manager, authorizer port, privilege and ownership authorizers, generic rule set, requirements |
| `session` | manager, store port, in-memory store, sealing store |
| `policy` | engine, decision, phases, built-in policies, attempt store port and in-memory store |
| `ratelimit` | limiter port, in-memory limiter, source keyer, source guard |
| `onetime` | manager, token store port, in-memory store |

Shared conventions:
- **Clocks:** `WithClock(func() time.Time)`, defaulting to `time.Now`.
- **Loggers:** `With<Component>Logger(*slog.Logger)`. The default is `slog.Default()`, and a nil logger is ignored.
- **Nil or typed-nil detection:** one internal helper, used by every construction check.

### 2. `authenticate`: a manager over ordered providers

```go
type Authenticator interface {
    Authenticate(ctx context.Context, c identity.Credentials) (*Authentication, error)
}
var ErrUnsupportedCredentials, ErrAuthenticationFailed, ErrNoEligibleAuthenticator error
func NewManager(delegates ...Authenticator) (*Manager, error)
```

Evaluation:
- **`ErrUnsupportedCredentials`:** skip to the next delegate.
- **Any other error:** returned as is.
- **A nil result, or a nil `Principal`:** `ErrAuthenticationFailed`. This is the one choke point that protects every caller that reads the principal after a nil error.
- **Every delegate skipped:** `ErrNoEligibleAuthenticator`.

Construction:
- no delegates is a configuration error;
- a nil or typed-nil delegate is also a configuration error. This departs under (a), wiring mistakes fail at construction: a nil delegate otherwise panics on the first request.

Defaults and overrides:
- **Default:** none. The consumer or `http-security` names the delegates.
- **Override:** any `Authenticator`.

`Authentication` carries:
- `ID id.ID`, from a replaceable `id.Generator`. This departs under (a), library-owned identifiers use `pkg/id`.
- `Credentials`, cleared on success;
- `Principal`;
- `Time`;
- `PasswordChangedAt`.

`WithAuthentication` and `AuthenticationFromContext` carry it with a request.

### 3. The password provider

```go
func NewUsernamePasswordAuthenticator(users identity.UserLoader, opts ...PasswordOption) (Authenticator, error)
func WithPasswordEncoder(enc password.Encoder) PasswordOption          // default: password-encoding's default
func WithPasswordAuthenticatorLogInterval(d time.Duration) PasswordOption // default 1m; ≤0 disables
```

Construction:
- a nil loader is a configuration error;
- a dummy hash is encoded with the configured encoder, and construction fails if that encoding fails.

On `Authenticate`:
1. **Load the user.** On any load error, run `Match` against the dummy hash and return the bare `ErrAuthenticationFailed`.
   - **Not found:** logged at DEBUG.
   - **Any other error:** logged at ERROR.
2. **Match the password.** A mismatch returns the sentinel.
3. **Check `Active`, only now.** An inactive account returns the sentinel, logged at WARN.
4. **On success, clean up the credentials** and return the result.

Why:
- **A dummy hash from the configured encoder:** a literal in another algorithm's format would short-circuit the real encoder and reopen the timing gap.
- **Active checked after the password:** otherwise "disabled account" becomes observable without the password.

**Departure (a): sampled refusal logs.** The logs above go through a `logsample.Sampler` keyed by refusal kind. Its reporter writes a summary record, and the provider exposes `FlushRefusalLogs()`. Records never contain the password. The interval option is named for this provider alone.

### 4. The bearer-token provider

```go
func NewJwtAuthenticator(opts ...JwtOption) (Authenticator, error) // WithJwtVerifier required → else configuration error
```

- **Verification:** delegated to the verifier. An error returns `errors.Join(ErrAuthenticationFailed, err)`.
- **Principal:** built from the verified subject.
- **Result ID:** the token's own identifier.

### 5. `authorize`: manager, privilege authorizer, ownership authorizer

The sentinels are `ErrUnsupportedAttributes`, `ErrInvalidAttributes` and `ErrAccessDenied`. The manager's first non-skipping authorizer decides, and when all skip the result is `ErrAccessDenied`.

Privilege authorizer:
- **Invalid attributes:** `ErrInvalidAttributes`.
- **Nil subject or nil active role:** `ErrAccessDenied`, without calling the loader.
- **Super role:** allow.
- **Privileges not found:** `ErrAccessDenied`.
- **Any other loader error:** wrapped with `%w`.
- **Matching:** only granted privileges count, in any-of or all-of mode. Names match after `TrimSpace` and `EqualFold`.

Ownership authorizer: resolver and check errors are wrapped with `%w`.

Defaults and overrides:
- **Name comparison default:** trimmed and case-insensitive.
- **Override:** `WithPrivilegeNameComparer(func(a, b string) bool)`. This departs under (a), every default is replaceable. It adds an override point without changing the default.
- **Departure (a): construction checks.** A nil or typed-nil authorizer, and a manager with no authorizers, are configuration errors instead of being silently filtered. A filtered nil produces fewer checks than the consumer wrote, which is exactly the wiring mistake rule 6 moves to construction.

### 6. Centralized rules, generic over the request

```go
type Requirement func(ctx context.Context) error
type Rule[R any] struct{ Match func(R) bool; Require Requirement }
func NewRules[R any](rules ...Rule[R]) (*Rules[R], error) // nil Match / Require → configuration error
```

`http-security` instantiates `R` with its request type and supplies path matchers. Evaluation:
- **First match decides.**
- **A non-empty set with no match:** `ErrAccessDenied`.
- **An empty set:** no central decision, so authorization is left to per-endpoint guards.

The requirements are `PermitAll`, `DenyAll`, `Authenticated`, `HasAnyRole`, `HasAnyScope`, `HasAllScopes` (empty denies), `AnyOf` (empty denies; `ErrAuthenticationRequired` only when every member returned it), and `HasPrivilege`, which delegates to the authorizer in context and denies without one.

- **Default:** deny unmatched requests.
- **Override:** a trailing permit-all rule.

### 7. Session identifiers, expiry and the store

```go
type Store interface {
    Create(ctx, *Session) error            // insert
    Save(ctx, *Session) error              // update existing only; ErrSessionNotFound if missing
    Load(ctx, id string) (*Session, error) // ErrSessionNotFound / ErrSessionExpired
    Delete(ctx, id string) error
    DeleteByUser(ctx, user identity.UserID) error
    CountActiveByUser(ctx, user identity.UserID) (int, error)
    DeleteExpired(ctx) (int, error)
    DeleteByExternalSession(ctx, issuer, sessionID string) (int, error)
    DeleteByUserAndExternalIssuer(ctx, user identity.UserID, issuer string) (int, error)
}
func NewManager(opts ...ManagerOption) (*Manager, error) // WithStore (default in-memory), WithIdleTimeout(30m), WithAbsoluteTimeout(12h), WithClock
```

Identifiers and expiry:
- **Identifier:** 32 bytes from `crypto/rand`, encoded base64url.
- **Deadlines:** `Touch` moves the idle deadline to `now + idle`, capped at the absolute deadline.
- **Expiry enforcement:** stores enforce expiry in `Load`.
- **Create options:** `WithFirstFactor` and `WithExternalSession` apply before the single create write, so a crash cannot leave a live session without them.
- **External deletes:** with an empty issuer, or an empty session identifier for the session-scoped delete, they delete nothing and return no error.

**Departure (b): `Create` and `Save` are split, and `Save` never inserts.**
- **The evidence** is a pitfall recorded against the upsert-shaped save. A write that follows a load and races a concurrent delete re-inserts the row, resurrecting a revoked session.
- **The failing case:** load a session, delete it, then `Touch` it. With an upserting `Save`, the session loads again. That is exactly the load-then-save path `Touch` takes.
- **The fix:** keep the whole-record save, but make it update-only.
- **The default and override are unchanged:** any store implementing the contract.

**Departure (a): non-positive idle or absolute timeouts are configuration errors.** A zero idle timeout expires every session on creation, which is a meaningless configuration.

### 8. Library-owned session fields and consumer data

`Session` fields:
- `ID` and `UserID`;
- `CreatedAt`, `LastAccessedAt`, `IdleExpiresAt` and `AbsoluteExpiresAt`;
- `FirstFactor factor.Kind`;
- `MFA MFAState` (none, pending or satisfied);
- `PasswordChangePending bool`;
- `ExternalProvider`, `ExternalIssuer`, `ExternalSessionID` and `ExternalIDToken`;
- `Data map[string]string`.

**Departure (a): opaque consumer data.**
- **Library state moved out of `Data`:** the first factor, the MFA state and the password-change marker are fields. Keeping them under reserved keys in the consumer's map means the library reads and writes consumer-owned data, and a consumer key collision could forge or erase a challenge state.
- **`Data` is `map[string]string`:** a map of arbitrary values does not come back unchanged through a durable store. Numbers return as floats, so "returned unchanged" cannot hold.

There is no default first factor. The empty kind is enforced by policy.

### 9. The in-memory session store

It copies records on write and read, behind a read-write mutex.
- **`Start(ctx)` launches a housekeeping ticker** that calls `DeleteExpired` once per `WithHousekeepingInterval(d)`, which defaults to 1 minute.
- **`Stop()` ends it.** Both are idempotent, and the ticker exits when `ctx` ends.
- **Without `Start`:** expired sessions are never served, because `Load` enforces expiry. They do stay in memory, and the godoc says so.
- **Limit, stated:** the store is per process.

### 10. The sealing store

```go
type Cipher interface { // declared here, in session, not imported
    Seal(plaintext, additionalData []byte) ([]byte, error)
    Open(ciphertext, additionalData []byte) ([]byte, error)
}

func NewEncryptedStore(inner Store, c Cipher) (Store, error) // nil inner or cipher → configuration error
```

**Where the cipher port lives.** The Context lists `secrets-at-rest` as supplying the cipher port, and
that capability belongs to a later change, so there is nothing to import: the package it will live
in does not exist. The port is therefore declared here, in the package that consumes it, which is
where Go puts an interface anyway. Nothing is lost when `secrets-at-rest` arrives — a cipher it
ships satisfies this interface structurally, so neither package imports the other, and a consumer
wires one implementation into every place that seals. A later capability that also needs sealing
declares the narrow port it needs rather than inheriting this one.

- **Sealed field:** only `ExternalIDToken`. The additional authenticated data is `"scrty/session:external-id-token:" + ID`, and the envelope is base64url-encoded.
- **Unsealed:** an empty token. Every other field and method passes through.
- **Copies:** `Create` and `Save` seal a copy, so the caller keeps plaintext.
- **Open failures:** `ErrSessionUnreadable`, distinct from not-found, so a retired-key mistake stays visible.
- **No re-seal on load:** a write on read is the resurrection race from Decision 7.
- **Departure (a):** nil arguments are configuration errors.

### 11. Policy engine

```go
type Phase int // PreAuthentication, PostAuthentication, PerRequest, PostHandler, StatelessAuthentication
type Outcome int // Allow, Deny, Challenge
type Decision struct{ Outcome Outcome; Reason error; Challenge ChallengeKind }
type Policy interface{ Name() string; Phases() []Phase; Evaluate(ctx, *Input) Decision }
func NewEngine(policies ...Policy) (*Engine, error)
func (e *Engine) Add(p Policy) error      // before serving; not safe concurrently with EvaluatePhase
func (e *Engine) EvaluatePhase(ctx, phase Phase, in *Input) Decision
```

- **Precedence:** Deny, then the first held Challenge, then Allow. An empty phase is Allow.
- **`Phase.String()`** returns the constant's name, for logs.
- **`Input` carries:** user, username, principal, session, first factor, password-changed time, the MFA-satisfied flag and now.
- **The phase reaches a policy through the context.** `EvaluatePhase` puts the phase it is
  evaluating into the `ctx` it passes on, and `ContextWithPhase`/`PhaseFromContext` are the
  package's vocabulary for it. The `Input` is passed unchanged; the context is not.
  - **Why it is not an `Input` field:** the field list above is the contract a policy reads, and
    a phase is not a fact about the request — it is which question is being asked of it.
  - **Why a policy cannot do without it:** Decision 16's order gives *opposite* answers for
    post-authentication, per-request and stateless authentication, and nothing else in `Input`
    distinguishes them. A policy left to guess must fail closed, which refuses the very users
    the order says to challenge or allow.
  - **Override:** `WithMFARequirementPhaseSource` replaces how that policy learns the phase; a
    policy evaluated outside an engine, with no phase in the context, fails closed.

Departures:
- **Departure (b): a Deny with a nil reason gets `ErrPolicyDenied`.**
  - **The failing case:** stateless first factors refuse by returning the Deny's reason as their error. A reasonless Deny therefore returns nil, and the request proceeds.
  - **Why the engine fixes it:** substituting a reason in the engine closes this for every caller.
- **Departure (a): nil policies are configuration errors** in `NewEngine` and `Add`.

### 12. First factors: this change uses `identity-model`'s kinds and channels

The first-factor kinds, their channels and their local-MFA exemptions are `identity-model`'s capability, and this change does not restate them. The policies only use them:
- the same-channel rule (Decision 15) compares a method's channel with the login's first-factor channel;
- the MFA requirement (Decision 16) skips exempt kinds and enforces the empty kind.

The MFA policies accept `WithMFAExemption(func(factor.Kind) bool)`, which defaults to `identity-model`'s rule. This departs under (a), every default is replaceable: it adds an override, and the default behaviour is unchanged.

One option value has to be accepted by **both** `NewMFAPolicy` and `NewMFARequirementPolicy`, so a
deployment states its exemption rule once and hands the same value to each. Two distinct named
`func(*T)` option types cannot share a value, and generic inference does not resolve it in an
argument position. So `MFAOption` and `MFARequirementOption` are one-method interfaces with
unexported adapters, and `WithMFAExemption` returns an exported `MFAExemptionOption` implementing
both. A consumer still writes `policy.WithMFAExemption(...)`, and handing an option to the wrong
constructor is still a compile error. The cost is that mocks of those option interfaces are
excluded from generation, since a method taking an unexported type will not compile in the
black-box test package.

### 13. Account lockout

```go
type AttemptStore interface {
    RecordFailure(ctx, username string, at time.Time) error
    Reset(ctx, username string) error
    FailureCount(ctx, username string, since time.Time) (int, error)
}
type AttemptReaper interface{ DeleteAttemptsBefore(ctx, retainSince time.Time) (int, error) } // zero → ErrRetainSinceRequired
func NewAccountLockoutPolicy(opts ...LockoutOption) (*AccountLockoutPolicy, error)
// WithAttemptStore (default in-memory), WithLockoutThreshold(5), WithLockoutWindow(15m), WithLockoutClock
func (p *AccountLockoutPolicy) RecordFailure(ctx, username string) error // stamps the policy's own clock
func (p *AccountLockoutPolicy) Reset(ctx, username string) error         // what a successful authentication does
func (p *AccountLockoutPolicy) PurgeExpired(ctx) (int, error) // cutoff = now - own window; ErrReapUnsupported
```

`RecordFailure` and `Reset` are on the policy rather than left to the consumer's own use of the
store, because the requirement is that failures are recorded and cleared *through the attempt
store*, and `Evaluate` only reads the count. A consumer driving the store directly would also have
to stamp the policy's clock to match the window it is counted against, which is precisely the
detail they would get wrong. What counts as a failure stays the login flow's decision.

Evaluation, in the pre-authentication phase:
- **At or above the threshold:** `ErrAccountLocked`, counting failures strictly after `now - window`.
- **Store error:** deny, wrapping the error.
- **Reaping:** the in-memory store does not implement `AttemptReaper`, so `PurgeExpired` reports `ErrReapUnsupported` rather than a silent zero.
- **The purge takes no caller window**, so no sweep can shorten lockout.

Defaults: threshold 5, window 15 minutes.

**Departure (a) and (b): a non-positive threshold or window is refused at construction, not only at evaluation.**
- **The documented gap:** a zero window counts no failures and silently disables lockout. A zero threshold denies everyone as "locked".
- **The fix:** checking at construction surfaces the mistake before traffic, instead of as an outage at the login page. A constructor for a new type can return an error, so nothing forces the check onto the request path.

### 14. Idle timeout, password age, concurrent sessions

**Idle timeout policy**, `NewIdleTimeoutPolicy(opts...)`, per-request phase:
- **Deny `ErrSessionIdle`** when `now - LastAccessedAt > idle`.
- **A zero `LastAccessedAt` passes.**
- **`Thresholds(createdAt, now)`** supplies deadlines for new sessions.
- **Defaults:** `WithIdlePolicyTimeout(30m)` and `WithIdlePolicyAbsoluteTimeout(12h)`. They are named for this policy, so they are distinct from the session manager's options (settled rule: options are named after what they govern).

**Password age policy**, `NewPasswordAgePolicy(opts...)`, post-authentication phase:
- **Challenge `ChallengePasswordChange`** when the age exceeds `WithMaxPasswordAge`, which defaults to 90 days.
- **A zero change time passes.**
  - **The godoc must state** that the policy enforces nothing for users whose change time is never written. Whoever writes the column (the consumer, or the default identity store) owns the change time.
  - **The godoc must also warn** against refreshing the value from every federated login.
- **Override:** `WithUnknownPasswordAge(ChallengeUnknown)`. This departs under (a), every default is replaceable. It adds an override without changing the default.

**Concurrent session policy**, `NewConcurrentSessionPolicy(counter, max)`, post-authentication phase:
- **Deny `ErrTooManySessions`** when the count is at least `max`.
- **A count error denies.**
- **`max` is a required argument**, with no default. The policy is opt-in.

**Departure (a) for all three:** non-positive durations or `max` are configuration errors. Each makes the policy either always fire or never fire.

### 15. Second-factor challenge and the same-channel rule

```go
type MFAMethodLookup interface {
    Enrolled(ctx, user identity.UserID) (bool, error)
    Channel() factor.Channel
}
func NewMFAPolicy(method MFAMethodLookup, opts ...MFAOption) (Policy, error) // nil → configuration error (a)
func WithSameChannelEnrolment(mode SameChannelMode) MFAOption // default SameChannelRefuse
```

**The enrolment lookup contract, which `multi-factor-auth` implements.**
- **Enrolled:** only when the store holds a confirmed enrolment whose secret opens.
- **Not enrolled:** an unconfirmed enrolment.
- **An error:** a store failure, or a secret that fails to decrypt. It is never reported as not enrolled.

The policies refuse on that error. This matches the established behaviour: the enrolment check returns the store's error, and a sealed secret that cannot be opened surfaces as a decryption error. Losing or corrupting an enrolment therefore cannot downgrade a user.

It runs in the post-authentication phase.
- **Allow:** an MFA-satisfied login, or an exempt first factor.
- **Lookup error:** deny.
- **Enrolled on a different channel:** challenge MFA.
- **Not enrolled:** allow.
- **Enrolled on the same channel:** decided by the same-channel mode below.

**Departure (a): the same-channel case is explicit, and refuses by default.** Settled rule: a same-channel second factor is an explicit, documented decision with a safe default, and nothing is skipped silently.
- **The earlier reasoning:** two factors on one channel are one factor, so the enrolment cannot count. A user who is not required is therefore treated like a user who is not enrolled, and completes on the first factor without a record.
- **Why scrty refuses instead.** That reasoning establishes that the second factor is unusable. It does not establish that completing silently is safe.
  - **The fact is identical for required users**, and for them it is already resolved by refusal: an enrolment on the first factor's channel counts as no usable enrolment.
  - **An enrolled user opted into two factors.** Completing on one quietly lowers their assurance below what they chose.
  - **The user keeps a path in:** any first factor on another channel gets a real challenge.
- **Default: `SameChannelRefuse`.** Deny with `ErrSecondFactorSameChannel`, plus a sampled WARN.
- **Override: `SameChannelCompleteOnFirstFactor`.** Allow, record no satisfied second factor, and still write a sampled WARN.
- **What the override cannot change:** required users are unaffected by it.
- **Logging:** `WithMFAPolicyLogInterval` names the interval, and the policy exposes a reporter and `FlushRefusalLogs`.

### 16. MFA requirement

```go
func NewMFARequirementPolicy(required identity.MFARequirementLookup, method MFAMethodLookup, opts ...MFARequirementOption) (Policy, error)
// WithMFARequiredForAll, WithMFARequirementLogger, WithMFARequirementLogInterval(1m)
// WithMFAExemption, WithMFARequirementClock, WithMFARequirementPhaseSource
```

It runs in the post-authentication, per-request and stateless-authentication phases.

Because its answer differs by phase, it is told which phase it is in — see Decision 11. The default
reads what the engine put in the context; `WithMFARequirementPhaseSource` replaces that for a
consumer whose call path cannot reach it, and a source that cannot identify a phase is treated as
none, which fails closed with `ErrMFARequired`. A nil source is a configuration error.

Construction errors:
- `ErrMFARequirementLookupMissing`: a nil lookup without for-all.
- `ErrMFARequirementUnsatisfiable`: for-all with a nil method. This departs under (a), wiring at construction, instead of at chain assembly only.

Evaluation order:
1. **Exempt first factor:** allow.
2. **Required?** For-all answers yes without a lookup. A lookup error denies with the error:
   - if `ctx.Err() != nil`, it is logged at DEBUG, unsampled;
   - otherwise it is logged at ERROR under the shared key `lookup-failed`.
3. **Not required:** allow.
4. **Stateless phase, or no method:** deny `ErrMFARequired`, with a WARN keyed by user, first factor and phase.
5. **Per-request and satisfied:** allow.
6. **No usable enrolment**, including a same-channel one: deny `ErrMFAEnrollmentRequired`, with a WARN.
7. **Per-request:** challenge.
8. **Post-authentication:** allow, because `NewMFAPolicy` issues the login challenge. The godoc requires both policies to be registered.
9. **Any other phase:** deny `ErrMFARequired`.

The sampler reporter and `FlushRefusalLogs` depart under (a), sampled refusal logs.

### 17. Rate limiting

```go
type Limiter interface {
    Exceeded(ctx, key string) (bool, error)   // error ⇒ treat as exceeded
    RecordFailure(ctx, key string) error      // may get a non-cancelling ctx; bound own I/O
}
func NewMemoryLimiter(limit int, window time.Duration, opts ...MemoryOption) (*MemoryLimiter, error)
func NewSourceKeyer(opts ...KeyerOption) (*SourceKeyer, error) // WithIPv6SourcePrefix(64), 1..128
func NewSourceGuard(flow string, l Limiter, opts ...GuardOption) (*SourceGuard, error)
func (g *SourceGuard) Check(ctx, clientAddr string) (Source, error) // ErrSourceUnattributable, ErrThrottled
func (g *SourceGuard) RecordFailure(ctx, s Source)                  // context.WithoutCancel; errors logged
```

In-memory limiter:
- **Sliding window:** a failure counts while strictly after `now - window`.
- **Stamps kept:** at most `limit` per key.
- **Pruning:** inline, at most once per window. A key is removed only when its newest stamp has expired. `Prune` accepts no window.
- **Per-replica WARN:** once, on first use.
- **Configuration errors:** a non-positive limit or window.

Source keys:
- IPv4 keys per address;
- an IPv4-mapped address is unmapped;
- IPv6 keys by its /64 prefix, with the zone dropped;
- empty, non-single-IP and unspecified addresses are refused under distinct log reasons.

Guard:
- **Limiter errors:** refused.
- **Throttle WARN:** sampled per flow and source.
- **Placement:** the source keyer and guard live in `ratelimit` rather than the HTTP layer, because canonical source keys are part of this capability. `http-security` supplies the client address and maps the errors.
- **Separate log interval:** `WithSourceGuardLogInterval` is per guard. This departs under (a), options are named after what they govern: one refusal-log option must not govern both throttle logs and MFA logs.
- **What the guard exposes:** `Check` and `RecordFailure` only. The refused-redemption counting rule belongs to `magic-link` and `oidc-login`.
- **Limits, stated:** the in-memory limiter is per replica, and concurrent bursts overshoot by their concurrency.

### 18. One-time tokens

```go
type Store interface {
    Insert(ctx, Token) error
    FindByID(ctx, id id.ID) (*Token, error)
    Consume(ctx, id id.ID, at time.Time) error // CAS on consumed_at IS NULL; ErrTokenNotFound otherwise
    CountRecentBySubject(ctx, purpose, subject string, since time.Time) (int, error)
}
type Reaper interface{ DeleteExpiredBefore(ctx, purpose string, retainSince time.Time) (int, error) }
func NewManager(purpose string, opts ...Option) (*Manager, error) // WithStore, WithTTL(15m), WithIssuanceWindow(1h)
func (m *Manager) Issue(ctx, subject string, opts ...IssueOption) (string, Token, error)
func (m *Manager) Check(ctx, token, binding string) (Checked, error)
func (m *Manager) Consume(ctx, c Checked) error
func (m *Manager) Redeem(ctx, token, binding string, checks ...Check) (Token, error)
func (m *Manager) IssuedCount(ctx, subject string) (int, error)
func (m *Manager) PurgeExpired(ctx) (int, error) // cutoff = now - issuance window; ErrReapUnsupported
```

Token format and storage:
- **Format:** `<id>.<base64url(32 random bytes)>`.
- **Stored:** `sha256(secret)` and, when bound, `sha256(binding)`, compared in constant time.

Check:
- **Refusals:** a wrong purpose, a consumed token, an expired token, a binding mismatch and a secret mismatch all return `ErrInvalidToken`.
- **Store errors:** also `ErrInvalidToken`, logged at ERROR.
- **No writes.**

Redeem runs Check, then the caller's checks, then Consume:
- a check error is returned unchanged and nothing is spent;
- a Consume failure returns `ErrInvalidToken`, and no token.

Why this shape:
- **Checks are side-effect free**, because they can run once per racing caller.
- **The purge cutoff comes from the manager's own issuance window**, so a sweep cannot free quota that `IssuedCount` still counts.
- **`Reaper` stays a separate capability**, and a zero cutoff is refused.

Departures:
- **Departure (a):** the record identifier is `pkg/id.ID`.
- **Departure (a):** `Checked` values are obtainable only from `Check`, so consumption cannot precede a check. That makes the settled check-then-consume rule structural.
- **Departure (a):** construction refuses an empty purpose and non-positive durations.

### 19. Test-first throughout

- **Each package:** table tests in the `assert` closure form, with mocks from `use-mockgen`.
- **Concurrency:** covered with `testing/synctest` and the race detector for token consumption, the limiter, housekeeping start and stop, and sampling.
- **Each departure gets a test first seen to fail** against the behaviour it replaces:
  - resurrection by `Save`;
  - a reasonless Deny letting a stateless request through;
  - a nil delegate panicking;
  - the same-channel login completing silently.

### 20. Choices the capability specs left open

Implementation surfaced decisions the specs do not pin. Each is recorded here because a later
reader would otherwise have to re-derive it from the code, and because changing any of them after
the first tag is a compatibility decision.

- **`HasAnyRole` matches the active role only, and matches names exactly.** The spec requires a
  requirement for "any of a set of roles" without saying which of a principal's roles count.
  Matching every assigned role would let a caller acting under a lesser role pass a role guard that
  the privilege authorizer — which counts only the active role — would then refuse, so the two
  halves of the library would disagree about one request. Names are compared exactly because
  `identity-model` states role identifiers are opaque and never case-folded. A principal with no
  active role therefore meets no role requirement, which is the closed failure.
- **The bearer credential type lives in `authenticate`, not `identity`.** `identity-model` requires
  the credential *types* `username-password` and `jwt` to be named, and `identity` names both. It
  does not require a struct for each, and `identity` ships one only for the password. Putting the
  bearer credential beside the provider that consumes it keeps an archived capability closed; a
  consumer who wants it in `identity` is asking for a change to that capability, not this one.
- **A verified token naming no subject is refused.** The spec says the principal is built only from
  the verified claims, and is silent on a token whose subject is empty. Such a principal satisfies
  every "is anyone authenticated?" check while naming nobody, so the provider refuses rather than
  issue it.
- **The privilege requirement names a group and a resource**: `HasPrivilege(group, resource,
  required ...string)`, all-of. The spec's own scenario is "`read` on `billing/invoice`", which a
  single-string form cannot express. Any-of is reached through `AnyOf` over one `HasPrivilege`
  each, or by handing `PrivilegeAttributes{Mode: MatchAnyOf}` to an authorizer directly.
- **`MatchAllOf` is the zero value of `MatchMode`, and an unknown mode is refused.** Attributes
  built without naming a mode demand every privilege listed, so a forgotten field narrows access
  rather than widening it. The mode constants carry the type-name prefix because the requirement
  constructors `AnyOf` and `HasAnyRole` already own the unprefixed names.
- **The in-memory one-time-token store implements purging**, as `one-time-tokens` requires of it.
  `ErrReapUnsupported` is reserved for a consumer's store that cannot, and is never a silent zero,
  which a caller would read as "nothing needed purging".

## Risks / Trade-offs

- **[Password age allows unknown change times, so it enforces nothing against stores that never record them]** → State it in godoc. The challenge mode is one option away. Whether the default identity store stamps the change time is that change's decision.
- **[Same-channel refusal blocks a login a looser rule would complete]** → The refusal names its reason, the override exists and still logs, and another-channel first factor still works.
- **[The MFA requirement allows at post-authentication and relies on the challenge policy being registered]** → Required in godoc. `http-security` registers both together.
- **[An unstarted in-memory session store keeps expired sessions in memory]** → Documented. They are never served. `expiry-sweeping` or `Start` reclaims them.
- **[The in-memory attempt store cannot be purged and grows with submitted identifiers]** → Documented. Durable stores implement the reaper.
- **[Lockout by submitted identifier lets an attacker lock a victim]** → Documented. Pair it with the per-source guard.
- **[The in-memory limiter and stores are per replica]** → WARN and godoc. Shared implementations plug into the same ports.
- **[Refusing unspecified client addresses breaks Unix-socket or in-memory transports without a trusted-proxy setup]** → Distinct log reason. `http-security` documents adapter setup.
- **[Check-then-record overshoots under concurrency]** → Documented bound.

## Migration Plan

Not applicable: a new library with no consumers and no tags.
