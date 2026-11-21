# Changelog

All notable changes to scrty are recorded here, for every published module. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All published modules are released in lockstep: one version number names the same release of each.

While the major version is 0, **no compatibility is promised**: any minor release may break a
published API, and each break is stated in its entry under *Changed*. Security fixes go to the latest
minor release only, as [SECURITY.md](SECURITY.md) states.

## [Unreleased]

### Added

- **`github.com/kartaladev/scrty/httpsec/prblmsec`.** A new module that renders the chain's refusals
  as RFC 9457 problem details through `github.com/kartaladev/prblm`. It is opt-in: nothing changes
  for an application that does not mount it.
- `httpsec.LookupStatus`, which reports the HTTP status the chain maps an error to and whether it
  maps one at all.
- `httpsec.ChallengeError.TokenType`, the token type a challenge names.
- `ginsec.WithRefusalsRendered`, an option that leaves a chain's refusals to the application's error
  middleware, including a 404 for an unrouted path.

### Changed

- **BREAKING** `ginsec.Middleware` takes options after the chain (`...Option`). Every call compiles
  unchanged, but code that stores it as a `func(*httpsec.Chain) gin.HandlerFunc` value no longer
  compiles.
- `httpsec` sets `Cache-Control: no-store` on any response refused with a `*ChallengeError` that
  carries a `Token`. It replaces any cache policy that an outer middleware or an earlier interceptor
  set, so a credential handed out with a challenge is never cacheable. A challenge without a token
  leaves `Cache-Control` as it was. An error handler that sets `Cache-Control` again after the
  refusal overrides this.
- A challenge offered through an `As` method behind a typed-nil `*ChallengeError` is now found, and
  an error chain of more than 1,000 links is unrecognised by `httpsec.LookupStatus` and
  `httpsec.StatusForError` (status 500, not recognised).
- **BREAKING (records).** Where a component writes its records is now decided when each record is
  written. In order: the component's own logger option, else the logger of the `httpsec` chain
  handling the request (`httpsec.WithLogger`), else `slog.Default()` as it is at that moment.
  - A component without a logger option, used inside a chain, now writes to the chain's logger and
    is filtered by its level. A chain logger at Warn drops the Info and Debug records that used to
    reach the default.
  - `slog.SetDefault` called after wiring is honoured. Before, each component kept the default it
    saw at construction.
  - The same component writes to the chain's logger inside a chain and to `slog.Default()` outside
    one. A chain answers its logger to components only when `httpsec.WithLogger` was given.
  - To keep the old destination, pass `slog.Default()` to the component's logger option.
  - The chain-built source guards' suppressed-records summary now reads `ratelimit: refusal records
    suppressed` with a `flow` attribute (it read `httpsec: refusal logs suppressed`). A consumer
    `WithRefusalLogReporter` still receives it.
  - A sampler's suppressed-count summary goes where that key's own records went, so a summary that
    names a user never reaches another chain's log. Before, it went to the last logger the component
    had resolved.
- **BREAKING (configuration).** A nil logger option now fails construction with the component's
  `ErrConfig`, naming the option. These options ignored nil before, which meant "use the default" or
  "do not log": `authenticate.WithPasswordLogger`, `apikey.WithLogger`, `session.WithLogger`,
  `lockout.WithLogger`, `policy.WithMFALogger`, `policy.WithMFARequirementLogger`,
  `magiclink.WithLogger`, `passkey.WithLogger`, `recovery.WithLogger`, `recovery.WithCodesLogger`,
  `onetime.WithLogger`, `notify.WithSMTPLogger` and `notify.WithQueueLogger`. The OpenID Provider's
  `WithLogger` now refuses a typed nil as well. To get the default, leave the option out. The other
  logger options already refused nil, as `redisstore.WithLogger` does.
- **BREAKING (consumer errors).** An error returned by a consumer-supplied port (a store, limiter,
  loader, sender, authenticator, hook, refusal check, write function, key source, signer or the
  `http.Client` behind the outbound calls) is read once where it enters the library. A walkable
  error passes unchanged. An error that cannot be walked (a cycle, a fan-out, a panicking `Unwrap`)
  is replaced by a fixed error, one Error record is written, and the site answers as it does when
  that dependency is down. A store or user loader that answers neither a record nor an error is now
  a dependency failure, never a missing record or user. Before, a hostile error could make a flow
  treat a fault as "not found", "refused" or "unsupported".
- **BREAKING (identifier generators).** An `id.Generator` that answers the nil identifier with no
  error is now a failing dependency at every place the library asks it for an identifier, the
  `sqlstore`, `pgxstore` and `gormstore` backends included. The caller sees that site's own failure
  (the OpenID Provider's `server_error`, a store's failure error, a refused issuance), and nothing
  is stored under the nil identifier. The session family keeps its configuration error.
- A panic in consumer code that the library runs on a goroutine of its own is recovered, with one
  Error record, instead of ending the process. The site then answers its outage and carries on: the
  WebAuthn metadata refresh (`passkey/webauthn`; registration is refused), the OIDC relying party's
  discovery and key-set fetches (`ErrDiscoveryFailed`), the `signingkey` rotation loops, the memory
  `session` store's housekeeping, and the `expiry/sweep` scheduled jobs (locker, observer, clock).
- The `prblmsec` module requires `github.com/kartaladev/prblm` v0.3.0, and the test module requires
  its `ginprblm` and `fiberprblm` adapters at v0.3.0. prblm now bounds its own walks. Its hooks
  receive a note wrapping `prblm.ErrUnwalkableError` instead of `*PanicError` reports, a `WithStatus`
  hint joined beside a sentinel is decided in `errors.Is` order, and typed-nil pointers in a chain
  are skipped.
- Dependencies are updated across the workspace modules: `gofiber/fiber/v3` 3.7.0 (its static
  middleware now confines symlinks by default), `valyala/fasthttp` 1.78.0,
  `klauspost/compress` 1.20.4, `golang.org/x/crypto` 0.59.0, `golang.org/x/sync` 0.25.0,
  `golang.org/x/mod` 0.43.0 (tools), `pressly/goose/v3` 3.30.1, `jackc/pgx/v5` 5.13.0 and
  `go-co-op/gocron/v2` 2.23.1.

### Fixed

- `httpsec.LookupStatus` and `httpsec.StatusForError` no longer hang, crash or panic on a cyclic,
  fanned-out or panicking error chain, or on a typed-nil `*ChallengeError` or
  `*password.RejectedError` in it. They read the chain once, within 1,000 entries, and recover a
  panicking `Unwrap`, `Is` or `As`. An unreadable chain is unrecognised (500) and writes one
  redacted Error record. The `prblmsec` mapper and `fibersec` classify through the same bounded walk.
  Consumer code that calls stdlib `errors.Is` or `errors.As` on the same error is not protected.
- Refusal-path reads of an error (request cancellation causes, a consumer `httpsec.Request`'s body
  read, the outbound client's transport and body errors) use the same bounded walk, so a hostile
  error no longer hangs or crashes the request.
- Hostile consumer-port errors no longer change a security outcome. Each of these used to read a
  cycle or fan-out that claimed "not found", "refused" or "unsupported" as that answer:
  - the authenticator chain `authenticate.FirstOf` skipped a delegate and authenticated through the
    next one, and an `authorize.FirstOf` chain skipped a consumer authorizer, so the next one could grant
    access;
  - the OIDC provider's code exchange issued tokens, a code replay revoked nothing, a refresh revoked
    the grant on a user-loader fault, and revocation and introspection answered as if the token store
    had worked;
  - the OIDC broker provisioned a duplicate user, back-channel logout ended nothing, and a consent
    store fault parked the request at the consent page;
  - passkey sign-in and the passkey second factor answered a credential-store fault as an unknown
    credential, passwordless login answered a user-loader fault as an unknown user, and recovery and
    magic-link flows no longer log or refuse a store fault as an unknown user;
  - step-up verification charged nothing for a refusal, and the sealed MFA store read
    `ErrAlreadyEnrolled` where it had not been returned;
  - magic-link redemption charged the client's source for a hostile consumer check, and MFA
    enrolment answered 500 and charged its limiter twice where a plain outage answers 401.
- The expiry sweeper no longer crashes the process when a consumer error's `Is` method panics on a
  scheduler goroutine, and a lock answered as nil no longer panics `gocron`. A scheduler timer that
  never fires no longer hangs shutdown, and the memory `session` store's housekeeping no longer
  stops silently on a nil timer channel.
- The OpenID Provider no longer stores an authorization code under the nil grant family when the
  identifier generator answers the nil identifier, so one family can no longer span users' grants.
  The code exchange and a replay refuse a stored code that names the nil family, and a store that
  answers neither a pending request nor a browser session no longer causes a nil dereference.
- The store backends no longer write a row under the nil identifier. Before, a nil identifier could
  overwrite an existing signing key or replace a recovery-code set.
- Hostile errors no longer hang their caller where the library handed them back raw: the password
  policy's write and context-words errors, the password authenticator's event-id generator, the
  signing-key manager's store errors, the token generator's key-source and signer errors, and the
  sealed MFA store's cipher errors. A random-source error is no longer rendered eagerly by
  `fmt.Errorf` before it is checked.
- A consumer `slog.Handler` that panics no longer ends the process from the queued notifier's
  workers or the sign-in notice goroutine, and a consumer clock that panics no longer ends it from
  the OpenID Provider's client-key-set fetch, which now answers a dependency failure and no longer
  calls the clock while holding its lock. A panicking handler loses only that record.
- A dependency's error text no longer reaches the returned error of TOTP enrolment, the MFA
  emailed-code draw, one-time token issue, the `session` manager's identifiers and CSRF token, or
  the SMTP sender's connection deadline. Each carries fixed library text, and `errors.Is` still
  finds the cause.
- `notify.NewSMTPSender` refuses a default sender (`WithSMTPFrom`) that contains a carriage return
  or line feed, wrapping `ErrUnsafeHeaderValue`. Such a value was written unchecked into the `From`
  header of every message that named no sender of its own.

## [0.1.1] - 2026-11-11

A patch release that fixes three security defects in `v0.1.0`, and retracts `v0.1.0`. Upgrade every
scrty module to `v0.1.1`.

### Security

All three affect the `httpsec` chain in `github.com/kartaladev/scrty` `v0.1.0`.

- **A fiber application could serve a path its authorization rules never approved.** Fiber removes
  `.` and `..` segments before routing, while the chain's rules read the path as sent. So a
  `/public` rule permitted `GET /public/../admin/users`, and fiber served it from the `/admin/users`
  handler. Encoded spellings (`%2e%2e`, and segments joined by `%2F` when `UnescapePath` is set)
  did the same. The chain now refuses such paths on every adapter (see *Changed*).
- **The recovery cool-down could be bypassed the same way.** On fiber, `/x/../account/delete`
  reached a route the cool-down marks while the cool-down was in force.
- **A consumer authenticator placed after the gates skipped them.** An authenticator registered past
  the recovery, enrolment, second-factor and password-change gates could publish a session those
  gates never judged. A session still owing a second factor, an enrolment or a password change then
  reached the handler with 200. A second chain run inside the first chain's gates, mounted through
  any adapter, could do the same with its own authenticator. `Exchange.PublishSession` now refuses a
  session while a request is inside the chain's gates, or inside another chain's gates that enclose
  this run, unless the publishing chain enables every gate the enclosing chain enables, so that its
  own gates judge what it publishes. The reverse nesting is closed too: a chain with gates mounted
  inside a chain without them never judged the session the outer chain had published, so its
  handler could serve a session still owing a second factor. Its gates and authorization stage now
  judge that session. As defence in depth, the authorization stage refuses a session that
  still owes the challenge of a gate the chain enables, with that gate's own error.

### Changed

- **BREAKING (request handling).** The chain answers `400` (`httpsec.ErrMalformedRequest`) to a
  request whose path holds a `.` or `..` segment, sent as is or percent-encoded, or whose
  percent-encoding does not decode. The check runs after client resolution, whose own refusal wins
  when both apply, and before any interceptor, on every adapter. It has no opt-out, and the 400
  carries the same security headers as any other refusal. Browsers never send such paths.
- **BREAKING (configuration).** `WithLogger`, `WithClock`, `WithPolicyEngine`,
  `WithRateLimiterFactory` and `WithErrorHandler` given more than once now fail `httpsec.New`, where
  the last value used to win silently. `EnableAuthorization` keeps its last-wins authorizer, and now
  refuses a nil authorizer in any of its calls.
- **BREAKING (configuration).** `Exchange.PublishSession` returns an `httpsec.ErrConfig` error, and
  publishes nothing, when a session is published after the chain's gates have begun, or by a chain
  run inside another chain's gates that lacks one of that chain's gates. A handler's in-process
  forward through the same chain, or through a chain with the same gates, still publishes. Register a consumer authenticator at `OrderBearerToken`, no
  later: the recovery cool-down, just after it, judges a request by the session it carries when it
  runs. Mount a second chain outside the first chain's gates, or authenticate in the outer chain.
- One chain mounted twice on a request, such as on a gin engine or fiber application and again on a
  group, now runs once. The second mount lets the request through as the first one judged it, so a
  middleware between the two mounts that changes what a rule reads is not judged again. Two
  different chains still both run.
- An interceptor that keeps `next` and calls it after its run has returned, or a terminal that calls
  `next` of its own run, now gets an `httpsec.ErrConfig` error instead of running the terminal again.
- After the chain's step returns, an exchange's context, `Session` and `Authentication`, and the
  rest of its per-run state, are what they were before the run, including after a recovered
  panic. Code that read them after the step returned used to see the run's state, and an exchange
  run many times grew its context on every run. Read a run's state inside the terminal. An exchange
  refused once and run again now reports its second refusal too.
- The chain builds its interceptor fold once, when it is constructed, instead of on every request.
  With eight interceptors a request now allocates as much as with none.
- Token verification (`token.Verifier`) and the OIDC provider's ID token hint check refuse a token
  whose header names no `alg`. `token.Verifier` accepted one on `v0.1.0`, against its documentation;
  the hint check began accepting one with jwx 4.6.0. The signature was always checked under the
  algorithm recorded on the key, so neither let a token through without the issuer's key.
- Store and service calls that must finish even if the client hangs up now have a deadline where
  they had none: 5 seconds for a write, and 10 seconds for revoking a session, a session family or a
  credential. They still outlive the client's cancellation. When the deadline passes, the call
  fails as a store error from that call already did, and the failure is logged as an outage, not
  as the client leaving. Calls that already had a bound keep it. Rate-limiter calls, session end
  observers, the event sink and notification senders are not bounded by the library: the limiter
  and the sender bound themselves, and an observer or sink bounds its own work. A lockout observer
  shares the 5-second bound of the chain's failed-attempt record or reset that runs it. A consumer-supplied WebAuthn metadata fetch now receives a
  context with a deadline of `outbound.DefaultTimeout` (10 seconds). A fetch that runs past it
  refuses the registration, as any metadata failure does.
- `notify.SMTPSender.Send` returns an error that matches the context's error (`context.Canceled`
  or `context.DeadlineExceeded`) when the caller's context ended during the send. Such a send is
  logged at debug level, as a hang-up, not as a failed delivery. A timeout of the sender's own still
  returns the network error.
- Exported signatures use descriptive parameter names (no API change).
- Dependencies: `github.com/lestrrat-go/jwx/v4` 4.6.0; `github.com/testcontainers/testcontainers-go`
  and its postgres, redis and mailpit modules 0.45.0 (the `test` module only). With jwx 4.6.0 a
  token's negative `nbf` or `iat` parses as a date before 1970 instead of being refused, and a
  malformed string date is refused when the token is parsed.

## [0.1.0] - 2026-11-09

The first release. Nothing was tagged before it, so the items under *Changed* describe what differs
from the earlier, untagged tree that this release replaces. Items marked **BREAKING** change a public
signature, a default, or how stored data behaves.

### Added

**`github.com/kartaladev/scrty` (root module).** Production builds carry no web framework, database driver, scheduler or test tooling; those live in the nested modules.

- Authentication (`authenticate`): a first-of-many authenticator; password sign-in with scrypt,
  bcrypt and Argon2id encoders (`authenticate/password`); API keys (`authenticate/apikey`); magic
  links (`authenticate/magiclink`); passkeys, over a verifier port (`authenticate/passkey`); a
  second factor after the first (`authenticate/mfa`); and sign-in through external OpenID Connect
  providers (`authenticate/oidc`).
- Authorization (`authorize`) and the identity ports a consumer implements to supply users, roles and
  links (`identity`).
- Sessions with rotation, renewal and reuse detection (`session`), and signed tokens
  (`token`), with signing-key management (`token/signingkey`) and single-use credentials
  (`token/onetime`).
- Rules a deployment applies around authentication (`policy`), account lockout (`policy/lockout`),
  and a failure rate-limit port with an in-memory limiter (`ratelimit`).
- Account recovery with two independent proofs (`recovery`), and required second-factor enrolment.
- The security chain in front of any HTTP handler (`httpsec`), with:
  - login, logout, magic-link, passkey, MFA, recovery, session-management and OIDC endpoints;
  - per-route guards, including a recent-authentication guard (`Guards.RequireRecentAuthentication`,
    `RequireAuthenticationWithin`);
  - opt-in security response headers (`EnableSecurityHeaders`), CORS (`EnableCORS`), CSRF protection,
    trusted proxies and API gateways (`EnableTrustedProxies`), DPoP (`EnableDPoP`) and mTLS-bound
    tokens, and an automation-challenge seam before login, magic-link requests and recovery start;
  - opt-in re-authentication endpoints for a signed-in session (`EnableReauthentication`), under
    `/reauth` by default: the user re-proves with an enrolled second factor, or with the password
    when they hold none;
  - an opt-in session-signal stream of server-sent events about the signed-in user's own session
    (`EnableSessionSignals`), with a closed set of library signals, the consumer's own namespaced
    signals, and an in-process signal bus replaceable through a port;
  - `WithBasePath`, which puts every built-in endpoint under one prefix, and `(*Chain).Endpoints()`,
    a read-only inventory of every operation of every enabled endpoint.
- User-facing session management: list a user's live sessions, revoke one or all others, and opt-in
  sign-in metadata with an opt-in notice for a sign-in from an unseen device.
- `password.Policy`: minimum length, a common-password list, context words, an opt-in breach check
  and a no-reuse rule. A stored hash is upgraded on login when its algorithm or parameters are
  outdated.
- `password.Recognizer`, an optional encoder interface. A user whose stored hash is empty or
  unrecognised costs the same work as an unknown user.
- An OpenID Provider a consumer can run for their own applications (`oidcprovider`), built on
  scrty's own primitives with no OpenID Provider library underneath:
  - authorization code flow with PKCE, `prompt`, `max_age` and `iss` in responses; a browser session
    for single sign-on and `prompt=none`; remembered consent; refresh-token rotation with reuse
    detection; ID tokens and JWT access tokens, with DPoP and mTLS binding;
  - client authentication by `client_secret_basic`, `client_secret_post`, `private_key_jwt` and
    `none`; UserInfo, revocation and introspection; OpenID Provider and OAuth authorization server
    metadata;
  - RP-initiated logout and back-channel logout; a static client registry with in-memory and durable
    stores;
  - the OpenID Foundation conformance suite runs in CI against the Basic OP, Config OP,
    RP-initiated logout and back-channel RP-initiated logout plans (`make conformance`), with one
    recorded expected failure, `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, and one
    recorded expected warning, `oidcc-claims-essential` (the optional `claims` request parameter is
    not supported). Official
    certification has not been sought.
- A security-event port that emits OWASP Logging Vocabulary events (`event`), which the lockout and
  reuse observers feed. Removing a passkey notifies the user by default.
- Package `store`, holding the errors every durable store backend shares, and `store/seal`, which
  encrypts long-lived secrets at rest; `store/sqlstore` and `store/migrate` for PostgreSQL through
  `database/sql`.
- Time (`pkg/clock`), identifiers (`pkg/id`), log sampling (`pkg/logsample`), confined outbound HTTP
  (`outbound`), email (`notify`) and expiry (`expiry`).
- Supply chain: CI actions pinned to commit SHAs, automated dependency updates, a vulnerability
  check over every published module, and a CycloneDX SBOM per published module.

**`github.com/kartaladev/scrty/httpsec/fibersec`.** Runs the security chain in front of fiber
handlers, with the same guards, including the recent-authentication guard, and the stream support the
session signals need.

**`github.com/kartaladev/scrty/httpsec/ginsec`.** Runs the security chain in front of gin handlers,
with the same guards, including the recent-authentication guard, and the stream support the session
signals need.

**`github.com/kartaladev/scrty/store/gormstore`.** The security-state stores, and an optional
identity store, over gorm with its PostgreSQL driver.

**`github.com/kartaladev/scrty/authenticate/passkey/webauthn`.** The passkey package's verifier port
over a WebAuthn library, in a module of its own so the core carries no WebAuthn, CBOR or TPM
dependency, and `webauthntest`, a software WebAuthn authenticator for tests.

**`github.com/kartaladev/scrty/store/pgxstore`.** The security-state stores over native pgx v5.

**`github.com/kartaladev/scrty/ratelimit/redisstore`.** A `ratelimit.Limiter` over Redis or Valkey, so
one limit holds across every replica.

**`github.com/kartaladev/scrty/expiry/sweep`.** Runs the tasks of an `expiry.Runner` on a gocron
schedule.

**`github.com/kartaladev/scrty/test`.** Shared test helpers and conformance suites for scrty's ports:
security-state stores, rate limiters, identity ports, the `oidc` package, and the behaviours
every framework integration of the chain must produce identically. It also holds the conformance
OpenID Provider the suite tests. No other scrty module imports it.

### Changed

Items below are stated relative to the earlier, untagged tree.

**Package layout and names** (`restructure-layout`). **BREAKING** for every import path and many
exported identifiers; the moves and renames change no behaviour.

- **BREAKING** The root directories are regrouped by concept. Under `authenticate/`: `factor`,
  `password`, `apikey`, `magiclink`, `oidc`, `passkey` and `mfa`. Under `token/`: `signingkey` and
  `onetime`. The account-lockout group of `policy` becomes `policy/lockout`. `storeerr` becomes the
  parent package `store`, with `sqlstore`, `migrate` and `seal` under it. `identity`, `authorize`,
  `session`, `recovery`, `ratelimit`, `outbound`, `notify`, `pkg/` and `internal/` keep their places.
- **BREAKING** Nested module paths move: `passkey/webauthn` to `authenticate/passkey/webauthn`, `pgx`
  to `store/pgxstore`, `gorm` to `store/gormstore`, `redis` to `ratelimit/redisstore` (package
  `redisstore`, was `scrtyredis`), `sweep` to `expiry/sweep`, `ginsec` to `httpsec/ginsec` and
  `fibersec` to `httpsec/fibersec`.
- **BREAKING** `Manager` leaves every type name: `oidc.Manager` is `RelyingParty`,
  `oidc.HandoffManager` is `Handoff`, `authenticate.Manager` and `authorize.Manager` are `FirstOf`,
  `session.Manager` is `Sessions`, `passkey.Manager` is `Passkeys`, `signingkey.KeyManager` is
  `Keys`, `apikey.Manager` is `Keys`, `onetime.Manager` is `Tokens` and `magiclink.Manager` is
  `Links`. Constructors and option types follow.
- **BREAKING** Sentinel errors drop the package noun (`session.ErrNotFound`, `password.ErrTooLong`,
  `token.ErrInvalid`, `policy.ErrDenied`); policy types drop the `Policy` suffix (`policy.IdleTimeout`,
  `policy.ConcurrentSessions`, `policy.PasswordAge`, `lockout.Policy`); initialisms, getter prefixes
  and spellings are corrected (`JWT…`, `Signer`, `ErrMFAEnrolmentRequired`, `NormalizeName`).
- **BREAKING** Options say what they bound, with one vocabulary: Limit for a count per subject,
  `Max<Entity>` for a container's size, Timeout, Lifetime and TTL by meaning. The lockout family is
  `WithFailureStreakLimit`, `WithFailureStreakRetention`, `WithWaitThreshold`,
  `WithWindowFailureLimit`, `WithFailureWindow` and `WithAttemptStoreMaxIdentifiers`, and about
  twenty more names gained the noun they lacked.
- **BREAKING** `token.NewVerifier` requires an issuer and an audience, or an explicit waiver of each
  (`WithoutVerifyIssuer`, `WithoutVerifyAudience`), so a token minted for one service no longer
  verifies at another that shares its keys.
- **BREAKING** A user-store outage during a password login is its own outcome,
  `authenticate.ErrUnavailable`, answered as a wrong password is. Form login, Basic authentication
  and a recovery's password proof charge it to the source, never to the username, so an outage no
  longer holds real accounts.
- **BREAKING** The `ratelimit` limiter port gains an atomic charge and refund, which every shipped
  limiter implements. Saved recovery codes charge
  before the lookup and refund on success, so the limit holds under concurrent presentations.
- API key authentication can be given a user loader (`httpsec.WithAPIKeyOwners`) and then refuses a
  key whose user is inactive or gone. Without one it looks nothing up, as before.
- The SQL backends build columns only through the shared store helpers, so no caller can put text
  into a SQL statement.

**API shape** (`idiomatic-api-shape`). **BREAKING** in signatures and lifecycle behaviour.

- **BREAKING** Twelve constructors return concrete types, not interfaces: `*UsernamePasswordAuthenticator`
  and `*JWTAuthenticator` (`authenticate`), `*MFA` and `*MFARequirement` (`policy`), `*BcryptEncoder`,
  `*ScryptEncoder` and `*Argon2idEncoder` (`password`), `*JWTGenerator` and `*JWTVerifier` (`token`),
  `*StaticKeyring` and `*AEADCipher` (`seal`), and `*MemoryKeyStore` (`signingkey`). The ports keep
  their names.
- **BREAKING** `logsample.Flusher` replaces `authenticate.RefusalLogFlusher`,
  `policy.RefusalLogFlusher` and `oidc`'s anonymous interface. `policy.Engine.FlushRefusalLogs` and
  `httpsec.Chain.FlushRefusalLogs` return an `error` joining what they flush, and
  `authenticate.FirstOf` forwards the flush to its delegates.
- **BREAKING** The in-memory stores that take options (`onetime`, `session`, `lockout`) return
  `(T, error)`, and refuse a nil clock, a housekeeping interval of zero or less and a capacity of zero
  or less with their package's `ErrConfig`.
- **BREAKING** One lifecycle for `signingkey.Keys`, `session.MemoryStore`, `sweep.Sweeper` and
  `notify.QueuedSender`: `Start(ctx)` takes the context's values but not its cancellation; a second
  `Start` returns `ErrAlreadyStarted` and a `Start` after shutdown `ErrAlreadyShutdown`; `Shutdown(ctx)`
  is bounded by its context, terminal and idempotent. It replaces `Stop()` and `Close(ctx)`.
- **BREAKING** `NewGuards` in `httpsec`, `httpsec/ginsec` and `httpsec/fibersec` returns
  `(*Guards, error)` and refuses a nil authorizer unless the consumer opts in to the chain's
  authorizer explicitly. The `fibersec` guards take `GuardOption`.
- **BREAKING** `httpsec.NewExchange` and `Exchange.SetContext` panic on a nil context instead of
  substituting or ignoring it; the lifecycle methods return their package's configuration error.
- **BREAKING** `EnableOIDCLogin` takes `OIDCDeps`: one required dependency is a positional argument,
  two or more go in a `Deps` struct.
- **BREAKING** `oidc.DefaultScopes()` is a function that returns a fresh copy, not an exported
  mutable global.

**Context on the key and cipher ports** (`key-port-context`). **BREAKING** in five ports.

- **BREAKING** `ctx` is the first parameter of every method of `seal.Keyring` (`Active`, `ByID`),
  `seal.Cipher` (`Seal`, `Open`, `ActiveKeyID`), `session.Cipher` (`Seal`, `Open`),
  `signingkey.KeySource` (`Signer`, `VerificationKeys`) and `httpsec.KeySetProvider` (`JWKS`).
- **BREAKING** `KeySource.Signer` returns an error instead of a boolean:
  `Signer(ctx, alg) (kid, signer, err)`. A source holding no key for the algorithm returns an error
  matching the new `signingkey.ErrNoKey`; any other error is an outage.
- An outage is answered as one. A cipher, session-store or user-store failure that is not a refusal,
  and a key set that cannot be obtained, fail the request as a dependency failure (500 by default),
  are not logged as an undecryptable session and are not charged to the source's throttle. New
  `seal.ErrUnavailable` and `session.ErrCipherUnavailable` carry a remote cipher's retryable failure.
- A credential is issued before anything is stored or spent, so a credential that cannot be issued
  stores, spends, removes and revokes nothing.
- A request whose own context ended is not refused: it fails with the context's error.

**Re-authentication** (`reauthentication`).

- **BREAKING** The MFA begin and verify endpoints refuse a session that owes no second-factor
  challenge, with `ErrNoMFAChallengePending`. Re-proof has its own endpoints.
- **BREAKING** A chain that has the MFA slot and passkeys must enable re-authentication; construction
  fails and names the option. A chain that gave MFA a shared challenge store must give
  re-authentication one too.
- **BREAKING** The sessions table gains one column. A strict rotation that lost a race keeps the old
  session, marked, for its 30-second in-flight window instead of deleting it, so a losing rotation or
  renewal answers 409 on every replica that shares the store, not 401.
- Recovery-code regeneration, passkey registration and removal, and the recency guard judge one
  shared "authentication time", which a re-proof refreshes as a second factor does.
- The default re-proof policy is "strongest factor held"; `RequireSecondFactorForReauthentication()`
  makes it second factor only. Re-proof paths are checked against every endpoint the chain answers.

**Security gaps** (`close-security-gaps`).

- **BREAKING** `httpsec.Request` gains `Host()` and `Secure()`, and every adapter implements them. A
  consumer's own `Request` implementation must add them.
- **BREAKING** `NewReuseGuard` is removed; `password.Policy`'s `NoReuse` rule replaces it.
- **BREAKING** A consumer's own `session.Store` implements the new session-listing and revocation
  methods.

**Pre-release fixes** (`pre-release-api-fixes`).

- **BREAKING** The token subject is the user's identifier by default; an option on the generator, on
  the JWT authenticator and on the chain's bearer keeps the username. Issuing with an empty subject
  fails. The chain reloads a signed bearer's user by the session's user reference and refuses a token
  whose subject is not that reference. This breaks any reader of `sub`, a reader of
  `Principal.Username` behind the standalone `JWTAuthenticator` (empty by default), a consumer's own
  `token.Generator` (it gains a method reporting its subject mode), a `JWTAuthenticator` given a
  generator of the other mode as its verifier, and an authentication provider that returns no user
  identifier. A chain whose generators disagree with its bearer fails to build.
- **BREAKING** A signing key retires when its tokens can have expired, and the key manager deletes it
  from the store one grace later, one key lifetime by default, with options to change the grace or
  keep retired keys. `signingkey.KeyStore` gains a delete method, which a consumer's own key store
  must implement.
- **BREAKING** `passkey.CredentialStore` loses `DeleteAwaitingSavedCodes`, which the library no longer
  calls.
- **BREAKING** `EnrolmentStore.Confirm` refuses an enrolment whose device is proven, decided by its
  one write; a consumer's own store that implements `DeviceProofStore` must do the same.
- `ErrConfig` in `notify` names the SMTP send with no sender address, which it already wrapped.

**Session signals** (`session-signals`).

- **BREAKING** `httpsec.ResponseWriter` gains a required `Stream` method, implemented by the net/http,
  gin and fiber adapters. An adapter of the consumer's own must add it, or report that it cannot
  stream.

**OpenID Provider** (`oidc-provider`).

- **BREAKING** `token` gains a typed issuer, with the claims an access token and an ID token need,
  and enforces `typ`.
- Provider endpoints render the error bodies the protocols require, a departure from the chain's
  bare-status default.
- The provider's tables arrive in a security-state migration, and new conformance suites cover its
  stores.

**Endpoint paths** (`endpoint-inventory-base-path`). **BREAKING** for `httpsec`.

- **BREAKING** The default endpoint paths are regrouped by what each endpoint does:
  `/sign-in/{password,magic-link,passkey}`, `/sign-out`,
  `/sso/{login,callback,handoff,backchannel-logout}/...` for signing in at other providers,
  `/oauth2/*` only for scrty as a provider, `/passkeys`, `/mfa/challenge/{m}` and
  `/reauth/challenge/{m}`. The magic-link confirm page default moves to `/sign-in/magic-link/confirm`.
  Option names do not change.
- **BREAKING** Every path setting must be absolute, not the root, clean, and free of characters that
  need escaping; with `WithBasePath` set, every path setting is relative to it, and a base path that is
  malformed, moves nothing or is repeated in a per-feature path is refused at construction.
- **BREAKING** One collision check covers the whole chain, within and across features. Paths may be
  shared only by declaration, and a collision names both settings, both paths and what it would break.
- **BREAKING** New construction-time refusals, each with a waiver: an OIDC provider's redirect URL path
  must end with the resolved callback path and the provider's name
  (`WithoutOIDCRedirectPathCheck`); under a base path the provider's issuer must cover it
  (`WithoutOIDCIssuerBasePathCheck`); under a base path a consumer route left at an endpoint's
  pre-base path is refused (`WithoutBasePathRouteCheck`).

**Hardening** (`pre-release-hardening`).

- **BREAKING** `onetime.Store` gains `InsertWithin(ctx, tok, since, limit) (bool, error)`, and
  `onetime.Tokens` gains `IssueWithin`, which reports the new `onetime.ErrIssueLimitReached`
  (answered 429). Every consumer-written one-time store must implement it.
- **BREAKING** `passkey.CredentialStore` gains `InsertWithin(ctx, cred, limit) (bool, error)`.
- **BREAKING** The MFA enrolment store's `Confirm` and `AcceptStep` take the enrolment generation and
  write only on it.
- **BREAKING** `apikey.Store.Revoke` returns `(bool, error)`: whether this call revoked the key.
  `apikey.Keys.Rotate` refuses a revoked or expired key with the new `apikey.ErrRotationRefused`
  (answered 409).
- **BREAKING** `seal.MFASecretAAD` takes `(gen id.ID, user identity.UserID)` and binds the enrolment
  generation. TOTP secrets sealed before this release no longer open: affected users enrol their
  authenticator again.
- **BREAKING** Stored password hashes are bounded: scrypt `p ≤ 16`, `(N + p)·128·r ≤ 1 GiB` and a
  power-of-two `N ≥ 2`; bcrypt cost `≤ 16`; Argon2id memory `≤ 1 GiB`, iterations and threads `≤ 16`,
  salt and key `≤ 64` bytes. A hash above them no longer matches, and encoders refuse such parameters
  at construction. bcrypt refuses a password containing NUL. Affected users reset their password. The
  OIDC password-claim cost band tops out at 16.
- **BREAKING** Account recovery refuses an issued code paired with an email-channel MFA proof, and
  the way-back check no longer counts that pairing.
- **BREAKING** The recovery cool-down matches its marked routes ignoring ASCII case and trailing
  slashes, with `HEAD` as `GET`, so on net/http and gin it also holds a differently cased route.
- A refused magic-link redemption answers 401; it answered 500. `apikey.ErrKeyNotFound` answers 404.
- A TOTP period and a token lifetime must be whole seconds, at least one; OIDC clock-skew leeway is
  bounded at 5 minutes and logout-token max age at 1 hour; OIDC redirect allowlist entries and a
  requested `next` are bounded at 2048 bytes; a rate-limit flow name may not contain `:`; magic-link
  and passkey-ceremony cookie TTLs must be whole seconds; the passkey relying-party ID must be a
  lowercase DNS name. Each is refused at construction.
- Ownership and resource guards in `httpsec`, `fibersec` and `ginsec` panic at wiring on a nil
  checker, extractor or `Guards`.
- `fibersec` keeps a route's own error and status, and runs the chain on a context cancelled when the
  request's handling ends (fiber gives no disconnect signal).
- Security-state stores pin READ COMMITTED for every transaction they open; recovery-code replace,
  the streak add and the bounded inserts refuse a caller's stronger transaction with the new
  `store.ErrIsolationTooStrong`. User-wide session deletes stop after 64 passes with
  `session.ErrDeleteDidNotSettle`.
- The default lockout attempt store, the outage hold and the log sampler are bounded and fail closed
  when full (`lockout.WithAttemptStoreMaxIdentifiers`, `logsample.WithMaxKeys`).
- Signing keys: construction, reload and housekeeping share one publishing rule; a future-dated key
  never signs.
- Policies deny a zero `Input.Now` (idle timeout, password age, enrolment path) and
  `Engine.EvaluatePhase` denies a nil input; they allowed before.
- A nested `authenticate.FirstOf` whose delegates skip lets the outer one try its next delegate.
- Default login, magic-link, MFA begin and verify, and passkey login responses carry
  `Cache-Control: no-store`.
- A WebAuthn backed-up state without backup eligibility is refused at registration and assertion.
- SMTP bodies normalise bare CR and bare LF to CRLF.
- New sentinels: `password.ErrContainsNUL`, `lockout.ErrAttemptStoreFull`,
  `onetime.ErrIssueLimitReached`, `apikey.ErrRotationRefused`, `session.ErrDeleteDidNotSettle`,
  `store.ErrIsolationTooStrong`, `signingkey.ErrNoKey`, `seal.ErrUnavailable`,
  `session.ErrCipherUnavailable` and `authenticate.ErrUnavailable`.

### Fixed

- A queued sender whose wrapped sender ends its goroutine (`runtime.Goexit`, as `t.FailNow` does) lost
  that worker, and once every worker was gone it accepted messages it never delivered. The worker is
  now replaced.
- A device proof landing inside the single-call confirm of an MFA enrolment left the enrolment
  confirmed without the emailed code.
- A bearer whose resolution ended in a per-request policy's throttle now records its credential, so
  the session-signal stream's cross-site check judges that request as a bearer, as it judges the same
  request unthrottled.

### Security

- A signed bearer no longer authenticates whoever now holds the session owner's former username; a
  disabled user's sessions are refused.
- One stored scrypt or bcrypt record can no longer exhaust memory or CPU.
- The recovery cool-down can no longer be bypassed on fiber by changing a path's case or adding
  trailing slashes.
- Issuance and passkey limits hold under concurrent requests.
- A token minted for one service no longer verifies at another that shares its keys, because a
  verifier now enforces an issuer and an audience unless each is waived.
- API keys can be refused when their owner is inactive or gone (`httpsec.WithAPIKeyOwners`).
- A user-store outage during a password login no longer places a hold on a real account.
- The limit on saved recovery codes holds when the codes are presented concurrently.

[Unreleased]: https://github.com/kartaladev/scrty/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/kartaladev/scrty/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kartaladev/scrty/releases/tag/v0.1.0
