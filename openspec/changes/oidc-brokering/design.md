## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Earlier contracts this change builds on, and does not restate:**
  - `identity-model`: the opaque user reference, the user loader (by username), the create-only `Provision` whose collision is decided by the write, the `Update` verb that writes only named fields, and the `oidc` first-factor kind with channel `federated`.
  - `sessions`: federated session fields written in the creating write, and deletes by issuer and provider session id and by user and issuer, both refusing empty arguments.
  - `security-policy`: phased evaluation, and the first-factor classification that marks OIDC exempt from local MFA and that a consumer can replace.
  - `rate-limiting`: the per-source guard, with separate check and record steps.
  - `token-issuance` and `signing-keys`: the internal access token minted at redemption.
  - `http-security-chain`, `http-error-propagation` and `outbound-http-confinement` (http-security): interceptor slots, sentinel-to-status mapping, and the outbound client that enforces `https`, confines redirects, bounds bodies and applies timeouts.
- **Persistence split.** This change owns the behaviour of the link, flow and handoff stores and ships in-memory defaults. `durable-persistence` owns the three durable adapters (`security-state-stores`) and the sealing of the provider ID token retained on sessions (`secrets-at-rest`).
- **One JOSE stack.** `github.com/lestrrat-go/jwx/v3` is scrty's only JOSE, JWT and JWK library. Provider ID tokens, logout tokens and provider key sets use it, including its JWKS cache.
- **No cross-store transaction.** A provisioned user and its link are two writes to two ports that may live in different databases.
- **Browser navigation.** The callback arrives as a top-level navigation, not as a request the application's own code made. There is no cookie-borne session or CSRF defence in scrty yet (`bff-resource-server`).

## Goals / Non-Goals

**Goals:**
- A federated login that cannot be steered into another user's account by email, username reuse, a forged callback or a conflicting link.
- A handoff code that no refusal can spend and that a replaying holder cannot use for free.
- Provider metadata fetching that no unauthenticated caller can amplify.
- Back-channel logout that is safe to expose to the internet.
- Every default named, and every override reachable without forking.

**Non-Goals:**
- MFA assurance from the provider (`amr`/`acr`), which is `oidc-mfa-assurance`. The exemption is total in this change, as a stated limit.
- Persisting claim-derived roles. Claim mirroring (decision 8a) covers only the display name and the password hash.
- Front-channel logout, `response_mode=form_post`, the UserInfo endpoint, dynamic client registration and per-request provider configuration.
- Storing or refreshing provider access and refresh tokens. They are discarded after the exchange.
- Account linking initiated by a logged-in user, and a link-management UI.
- Loading provider configuration from a database. The trusted-input decision (2) assumes operator-authored configuration.

## Decisions

### 1. Package layout

| Package | Holds | Imports |
|---|---|---|
| `oidc` | registry, discovery and key cache, authorize/callback manager, flow store port and in-memory store, ID and logout token verification, broker, link store port and in-memory store, handoff manager, handoff store port and in-memory store | `identity`, `session` (types), `pkg/id`, `pkg/logsample`, jwx v3, `golang.org/x/sync/singleflight` |
| `httpsec` (additions) | the authorize, callback, redemption and back-channel logout interceptors, and the end-session hook on local logout | `oidc`, `policy`, `ratelimit`, `session`, `token` |
| `test` module | `RunLinkStoreSuite`, `RunFlowStoreSuite`, `RunHandoffStoreSuite`, an in-process test identity provider, `RunTestKeycloak` | testcontainers-go |

The `oidc` package has no HTTP-framework import, and makes outbound calls only through the client that the `outbound-http-confinement` capability provides.

- **Alternative rejected:** a nested `oidc` module. The core already carries jwx for `token`, and OIDC needs no framework or driver.

### 2. Provider registry: trusted, validated input

```go
type Provider struct {
    Name, Issuer, ClientID, ClientSecret, RedirectURL string
    Scopes      []string         // default: openid, profile, email
    ClientAuth  ClientAuthMethod // default: ClientSecretPost; ClientSecretBasic available
    AuthorizationEndpoint, TokenEndpoint, JWKSURI string // all three or none
    EndSessionEndpoint string    // optional, independent of the pin rule
}
func NewRegistry(providers ...Provider) (*Registry, error)
func WithSigningAlgs(provider string, algs ...string) ManagerOption // default RS256
```

- **Default:** validation at construction, per `oidc-login`. `RedirectURL` is required, and is never derived from the request `Host`, which a client controls.
- **Trusted input.** Beyond `https`, a parsable URL and a host, the destination is not filtered. Loopback and private hosts are accepted, because development IdPs and internal corporate IdPs are real topologies. A pinned token endpoint receives the client secret, so whoever can write provider configuration can direct that secret. This is documented on every URL field and in the README as a limit.
- **`EndSessionEndpoint`** is outside the all-three-or-none rule. Pinning it alone is valid, and an empty value means the provider offers no RP-initiated logout.
- **Symmetric algorithms** (`HS*`) are refused unless listed explicitly for that provider. When listed, the client secret is the key, and that is documented.
- **Override:** everything is plain data. A consumer-built `Registry` from any source is accepted, and the trust statement then applies to that source.
- **Alternative rejected:** default-deny internal destinations. The predicate (private ranges, IPv6 unique-local, DNS names resolving to them, resolution at validation versus request time) is non-trivial and TOCTOU-prone. It is the recommended shape if providers ever load from storage.

### 3. Discovery and key sets on the jwx cache

```go
func WithDiscoveryTTL(d time.Duration) ManagerOption                    // default 15m
func WithEagerDiscovery() ManagerOption                                 // default lazy
func WithDiscoveryFailureBackoff(base, max time.Duration) ManagerOption // default 1s, 30s
func WithDiscoveryStaleWhileError(window time.Duration) ManagerOption   // default 0 (off)
func WithJWKSRefetchCooldown(d time.Duration) ManagerOption             // default 30s
func (m *Manager) Start(ctx context.Context) error
func (m *Manager) Stop(ctx context.Context) error
```

- **Key-set storage and fetching use jwx v3's `jwk.Cache`.** It is built by `jwk.NewCache` on an `httprc.Client` whose HTTP client is the confined outbound client, so every key-set request passes through `outbound-http-confinement`. Each provider's `jwks_uri` is registered on first use (or at `Start` under eager discovery) with `jwk.WithMinInterval` and `jwk.WithMaxInterval` both set to the TTL, and read with `Lookup`.
- **The discovery document** uses a small TTL cache of its own, because `jwk.Cache` holds key sets only.
- **Freshness is scrty's, not the cache's.** A wrapper records the time of every successful fetch it observes, both its own `Refresh` calls and `Lookup` results after a background refresh. A set older than the TTL is refreshed on demand. This matters because `jwk.Cache` keeps its last good copy when a background refresh fails; without the wrapper, a withdrawn key would stay acceptable indefinitely during an outage.
- **Coalescing.** On-demand `Refresh` and document fetches for a resource (`meta:<provider>`, `keys:<provider>`) run through a `singleflight.Group` with `DoChan`. The shared call runs on `context.WithoutCancel(ctx)` with its own timeout, and each caller selects on its own `ctx.Done()`.
- **Unknown `kid`:** a fresh set missing the `kid` triggers one `Refresh`. The cooldown claim is taken inside the flight body, so the goroutine that claims the window is the goroutine that fetches. A refusal inside the cooldown returns an unknown-signing-key error, which verification maps to invalid token, not provider failure.
- **Failure backoff:** doubling windows keyed like the flight. A refusal that never reached the network (cooldown, or a document failure inside a key-set flight) is marked not-attempted, so it neither opens nor widens a window. Each window transition is logged once.
- **Stale-while-error:** off by default. When configured, it serves an expired entry within `TTL + window` after a failed refresh, logging a warning per use. It never serves a fresh entry after a failed unknown-`kid` refresh, and never serves a stale set that lacks the caller's `kid`.
- **Lifecycle:**
  - `Start` creates the cache and, under eager discovery, registers every provider, failing on any error.
  - `Stop` calls `Cache.Shutdown` and is idempotent.
  - `Start` after `Stop` is an error.
- **Stated limits:**
  - state is per process, so N replicas refetch up to N times per window;
  - background refresh and on-demand refresh can each fetch once per TTL;
  - the first failure against a cold cache reaches the network;
  - there is no jitter;
  - a second key rotation inside one cooldown waits for the cooldown to end.

### 4. Authorization request

`Manager.Authorize(ctx, provider, next)` generates the state, nonce and verifier from `crypto/rand` (32 bytes each, base64url). It sends an `S256` challenge, stores the flow, and returns the redirect URL and handle. `next` is stored verbatim and untrusted.

- **Flow cookie:** `oidc_flow`, `HttpOnly; Secure; SameSite=Lax; Path=<callback base>`, with `Max-Age` derived from the flow expiry and clamped to at least 1. The redirect carries `Referrer-Policy: no-referrer`. `SameSite=Lax` is required, not a default: `Strict` drops the cookie on the provider's cross-site redirect.
- **Flow TTL:** 10 minutes by default (`WithFlowTTL`). The cookie name is replaceable (`WithFlowCookieName`).

### 5. Flow store: atomic, bound completion

```go
type FlowStore interface {
    Begin(ctx context.Context, f Flow) (handle string, err error)
    Complete(ctx context.Context, handle, provider, state string) (Flow, error)
    DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
```

- **Binding inside the operation.** Provider and state are arguments to `Complete`, not checks after it. A request that cannot produce the state cannot cause a write, so a forged `?code=` or `?error=` callback riding the victim's `SameSite=Lax` cookie is harmless.
  - There is no `Abort` and no non-consuming `Peek`: one predicate per implementation, nothing to drift.
  - `Manager.AbortFlow` for the error branch is built on `Complete` and returns only a bool.
- **Uniform refusal:** `ErrInvalidState`, with one message.
- **Default:** an in-memory store (see decision 16, departure 1). It checks and writes under one mutex, compares state in constant time, prunes expired flows inline, and refuses `Begin` above `WithMaxFlows` (default 100,000) rather than evicting, because eviction would let an attacker delete victims' flows.
- **Override:** any `FlowStore`. `durable-persistence` completes a durable flow with one conditional `UPDATE` (atomic, not constant-time).
- **Stated limit:** the in-memory store is per process. Behind several replicas without sticky routing, a callback that lands on another replica fails. This is documented on the default.

### 6. Callback, exchange and verification

`Manager.Callback(ctx, provider, code, state, handle)` completes the flow, exchanges the code, verifies the ID token and brokers the identity. It returns `CallbackResult{Principal, Provider, Issuer, SessionID, IDToken, Next}`. It does not create a session.

- **Error branch.** `?error=` goes through `AbortFlow` with the echoed state. The cookie is cleared and the provider's error text logged only when the flow was spent. `Callback` joins `ErrFlowUnspent` at exactly the returns at or before `Complete`, and the interceptor clears the cookie only when that marker is absent. A store fault logs at ERROR and propagates as a server error.
- **Exchange:** a `net/http` form POST through the confined client, with `grant_type`, `code`, `redirect_uri` and `code_verifier`.
  - Client authentication is `client_secret_post` by default. `client_secret_basic` is per provider (decision 16, departure 7).
  - Bodies are bounded, the error body is logged truncated and never returned, and the provider's access and refresh tokens are discarded.
  - `golang.org/x/oauth2` is permitted but not used: the call is one POST, and its token-source and refresh machinery would sit unused.
- **Verification (jwx v3):**
  - `jwt.Parse(raw, jwt.WithKeySet(set, jws.WithRequireKid(true)), jwt.WithIssuer(iss), jwt.WithAudience(clientID), jwt.WithAcceptableSkew(skew), jwt.WithValidate(true))`, with the key set filtered to keys whose algorithm is in the provider's allowlist;
  - then scrty's own checks: `exp` present, `sub` non-empty, `azp` when there are several audiences, and `nonce` in constant time;
  - `WithClockSkew` defaults to 60 s.
  
  One unexported `parseProviderJWT(raw, provider, requireExp bool)` is shared, and the ID-token and logout-token verifiers are siblings rather than one function with a mode flag, because they disagree on `nonce`, `sub`, `events` and `jti`.
- **Errors:**
  - authentication failures: `ErrInvalidState`, `ErrInvalidIDToken`, `ErrNoLinkedAccount` and a wrapped `identity.ErrUserNotFound` from a dangling link;
  - not authentication failures: `ErrExchangeFailed` and `ErrDiscoveryFailed`.

### 7. Broker, links and provisioning

```go
type ExternalIdentity struct {
    Provider, Issuer, Subject, Email string
    EmailVerified bool
    Claims map[string]any // unchanged
}
type IdentityBroker interface {
    Broker(ctx context.Context, ext ExternalIdentity) (identity.Principal, error)
}
type LinkStore interface {
    FindByExternal(ctx context.Context, provider, issuer, subject string) (Link, error) // ErrLinkNotFound
    Insert(ctx context.Context, l Link) error                                          // ErrLinkExists
    DeleteByUser(ctx context.Context, user identity.UserID) (int, error)
}
func NewBroker(links LinkStore, users identity.UserLoader, opts ...BrokerOption) (*Broker, error)
```

- **Link row:** `ID id.ID`, `Provider`, `Issuer`, `Subject`, `UserID identity.UserID`, `Username`, `Email` (not normalized) and `CreatedAt`.
- **Resolution by username, guarded by the user reference.**
  - `identity-model`'s user loader looks up by username, so `Username` is the operational key.
  - A username is a reusable handle. The loaded `Details.ID` must therefore equal `Link.UserID`, or a stale link would authenticate whoever holds the name next.
  - "User not found", nil details, a mismatch and an inactive user all return `ErrNoLinkedAccount`, so a caller cannot learn which usernames were recycled. A dangling or stale link logs at WARN, and an inactive user at DEBUG.
  - A nil link from a non-conforming store is refused, not dereferenced.
  - Loader errors are wrapped after bcrypt-shaped substrings are redacted.
- **The in-memory `LinkStore` is the default.** Under one mutex it refuses a conflicting key, including a byte-identical re-insert, so `nil` always means "I created it".
- **Just-in-time provisioning, per provider:**

  | Option | Default | Effect |
  |---|---|---|
  | `WithJIT(provider)` | off | enables provisioning |
  | `WithJITAllowUnverifiedEmail(provider)` | off | drops the `email_verified` precondition; the allowlist still applies |
  | `WithJITEmailDomains(provider, domains...)` | not configured | exact, case-insensitive domain; configured-empty admits no one |
  | `WithNameClaim(provider, path)` | email | display-name claim path |
  | `WithProvisioner(p)` | none | required when any `WithJIT` is set, checked by `NewBroker` |

  "Configured" and "configured empty" are told apart by a comma-ok read, never by `len`, so a missing configuration value fails closed.
- **Username = email.** It is safe because email verification is required by default, and because the create-only provisioner refuses an existing username instead of adopting it.
- **Sequence on a miss:**
  1. check the gates;
  2. `Provision` (create-only; `identity.ErrUserExists` becomes a refusal, with no adoption);
  3. `Links.Insert`, binding the returned `det.ID` and `det.Username`, not the requested email, so a provisioner that normalizes usernames still yields a resolvable link.

  `Provision` is called as `Provision(ctx, email, WithUserName(name), WithUserEmail(email), WithUserRoles(roles...), [WithUserPassword(hash)])`. Both collisions are decided by writes.
- **Stated limit:** a crash between steps 2 and 3 leaves a user with no link, and every later login of that identity is refused until an operator inserts the link. A consumer whose provisioner and link store share a database can run both inside one transaction, using each adapter's transaction resolver.
- **Override:** `WithBroker(IdentityBroker)` replaces linking and provisioning.

### 8a. Password-hash mapping and claim mirroring

| Option | Default | Effect |
|---|---|---|
| `WithPasswordClaim(provider, path)` | none | maps a claim to the stored password hash |
| `WithPasswordEncoder(enc)` | none | required when any password claim is mapped |
| `WithPasswordClaimCostRange(min, max)` | 10, 15 | accepted bcrypt cost band, within bcrypt's 4 to 31 |
| `WithClaimMirror(provider, bool)` | off | refresh mapped fields on every linked login |

- **One resolution function** (`mappedUserOptions`) produces the name and password options for both provisioning and mirroring, so the two cannot apply different mappings.
- **Password claim acceptance.**
  - The value must match an anchored bcrypt pattern (`$2a$`, `$2b$` or `$2y$`, a two-digit cost, 53 characters).
  - Its cost is parsed with `bcrypt.Cost` and must lie inside the band.
  - Anything else is ignored and logged without the value. The shape and cost reasons are logged separately, the cost message naming the observed cost and the band. Each (provider, reason) pair logs WARN once per process, then DEBUG, so an attacker-controlled malformed claim cannot silence the cost diagnostic.
- **Why bcrypt only, with a bounded cost.**
  - The claim is influenced by the federated user.
  - An unbounded cost is a CPU-exhaustion lever on a pre-authentication path: cost 31 is roughly 2^21 times the default work.
  - An illegal cost fails instantly, which is a timing oracle.
- **Encoder check.** `NewBroker` encodes a probe with `WithPasswordEncoder`'s encoder and requires the output to be a bcrypt hash.
  - Without that, the application's Argon2id authentication would reject the mapped hash instantly: inert, and a timing oracle against users who hold one.
  - This is an honour system across two constructors, so the godoc shows passing the same encoder value to the password authenticator.
- **Construction refusals:**
  - a password claim without an encoder, or with a non-bcrypt encoder;
  - an invalid band;
  - an empty provider key for the name or password claim;
  - a name or role claim path equal to the password claim path, which would publish a hash as a display name or role;
  - mirroring enabled without a provisioner, or without a name or password claim path.
- **Redaction.** Errors from `Provision`, `Update` and `LoadByUsername` are wrapped by a scrubbing error whose `Error()` redacts bcrypt-shaped substrings, while `Unwrap` still reaches the original. It is best effort: `errors.As` into a driver type bypasses it, and that is documented.
- **Mirroring,** on a linked login after the user-id and active checks:
  1. Resolve the mapped options; if none resolve, stop.
  2. Seed a proposal from the loaded details and apply the options.
  3. Compare field by field through one table (`mirroredFields`: name, password) that also drives seeding and copy-back. If nothing differs, stop.
  4. `Update(ctx, det.Username, opts...)` naming only the resolved fields (`identity-model`'s update verb).
  5. On error, or on a nil result: log ERROR (scrubbed) and continue with the loaded details.
  6. On success: copy back only the mirrored fields onto the per-request details, never adopting the returned record wholesale. A non-conforming partial-update adapter could otherwise blank roles for the rest of the login.
- **Why a failed write does not fail the login:** the user authenticated at the provider, and a storage error would make the mirror an availability dependency of the flow it exists to back up.
- **Stated limits:**
  - change detection assumes the provider returns its stored hash; a provider that re-hashes per token writes on every login and should not be mirrored;
  - a mirrored credential is not revoked by disabling the user at the provider;
  - the mapped hash's password-changed time stays unset, so a password-age policy does not challenge it.

### 8. Roles from claims

| Option | Default | Effect |
|---|---|---|
| `WithDefaultRole(role)` | none | single role for a provisioned user when the provider has no claim path |
| `WithRoleClaim(provider, path)` | none | dotted path; the leaf is a string or an array of strings; configured-empty yields no roles and no default fallback |
| `WithRoleMapping(provider, map[string]string)` | pass-through | unmapped values are dropped |
| `WithAllowedRoles(provider, roles...)` | no restriction | applied after the mapping, and also to the default role |
| `WithRoleSync(provider, bool)` | off | re-derive on every login; requires `WithRoleClaim` |

- **One resolution function** serves provisioning and sync, so the mapping and allowlist cannot be bypassed by enabling sync.
- **Sync is not persisted.** Roles are applied to the callback's principal only. Synced roles carry only the name and the primary flag; a stored super-role or validity window is not inherited.
- **Sync needs a conveyance that carries the principal.** Handoff redemption reloads the user and rebuilds the principal from stored roles, so the chain refuses role sync unless `WithCallbackSuccess` is configured. It refuses at assembly, based on the broker's `RoleSyncProviders()`. A consumer broker opts in by exposing the same method.
- **Documented risk:** a provider that lets end users edit role claims hands them any local role unless an allowlist is configured.

### 9. Handoff code: issuance and conveyance

```go
type HandoffStore interface {
    Insert(ctx context.Context, rec HandoffRecord) error
    FindByTokenID(ctx context.Context, tokenID string) (HandoffRecord, error) // ErrHandoffNotFound
    Consume(ctx context.Context, tokenID string, at time.Time) error          // conditional: unconsumed
    DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
type HandoffRecord struct {
    ID id.ID; TokenID string; SecretHash []byte
    Subject string // username the code was issued for
    Provider, Issuer, SessionID, IDToken string
    ExpiresAt time.Time; ConsumedAt *time.Time; CreatedAt time.Time
}
```

- **Code format:** `<tokenID>.<secret>`. The token id is 16 random bytes and the secret 32, both base64url-encoded, with `SecretHash = SHA-256(secret)`.
- **TTL:** fixed at 60 seconds and not configurable. The code travels in a URL and a refused code stays live, so widening the window is a security decision, not a tuning knob.
- **Its own store, not `one-time-tokens`.** The record needs typed provider-session fields, and `issuer` and `sid` are what later logout matching keys on. A dedicated store also discharges the purpose check structurally.
- **Conveyance hygiene:**
  - the redirect appends `handoff` with `url.Values.Set`;
  - it carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and clears the flow cookie;
  - redemption reads the code from the POST body only (decision 16, departure 5);
  - the README tells the landing page to remove the parameter with `history.replaceState` before loading any third-party resource;
  - the library never logs the code.
- **Redirect allowlist:** `WithOAuth2AllowedRedirects(entries...)` (default empty, so the destination falls back to `/`) and `WithOAuth2AllowedOrigins(origins...)` (default none). Entries are validated at construction and again inside the sanitizer, so no future call site can reintroduce a foreign-origin redirect carrying a live code.
- **Override:** `WithCallbackSuccess(func(ex *httpsec.Exchange, res oidc.CallbackResult, next string) error)` replaces the whole tail, for example for a consumer BFF. No handoff is issued.

### 10. Handoff redemption: check-then-consume, guarded

```go
type RedeemCheck func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error
func (h *HandoffManager) Redeem(ctx context.Context, code string, checks ...RedeemCheck) (HandoffResult, error)
```

**Order inside `Redeem`:**
1. Parse the code.
2. Call `FindByTokenID`.
3. Compare the secret in constant time.
4. Check expiry.
5. Non-authoritative fast path: `ConsumedAt != nil` returns `ErrInvalidHandoff`. This keeps a spent code opaque while the loader is faulting, and skips re-running policy for replays of a spent code.
6. `LoadByUsername(rec.Subject)`. "User not found" or an inactive user returns `ErrInvalidHandoff`; any other fault is returned as itself.
7. Run the checks in order. The first error is returned unwrapped.
8. `Consume` last. A refusal or store error returns no principal.

A refusal or lookup failure never spends the code. Single use rests on step 8 alone. Checks must be side-effect free, and the godoc says so, including for consumer policies evaluated inside the shipped check.

**The interceptor:**
- **Rate limiting** (decision 16, departure 3). The source guard's check step runs first, so a throttled source never reaches `Redeem`. The interceptor records a failure for:
  - `ErrInvalidHandoff`;
  - a policy deny;
  - any other check refusal, unless `WithHandoffRefusalsCounted(false)`.
  
  Store and loader faults are not recorded.
  - Default: an in-memory limiter dedicated to redemption, 10 failures per source in 5 minutes (`WithHandoffRateLimit`, `WithHandoffLimiter`).
- **The policy check** is a closure that evaluates `PostAuthentication` for the `oidc` first factor. It records `evaluated = true` and the decision.
  - A deny returns `policyDenyReason(decision)`: the reason, or `errPolicyDenied` when there is none, which maps to 403.
  - Allow and challenge return nil.
- **Guards after `Redeem`:**
  - an error that `errors.Is` the captured deny error is a policy refusal, not an authentication failure;
  - `!evaluated || decision.Outcome == Deny` on a nil error refuses with `policyDenyReason`.
  
  Denial is classified by identity, not by a sticky flag.
- **Challenge:** the code is consumed and the session created pending, per `sessions` and `security-policy`, and the challenge error is returned.
- **Session and token:** `session.Create` with the OIDC first factor and the federated fields in the creating write, then `token` issuance.
- **Response:** `{"access_token","valid_until","next"}`, the same shape as the magic-link manifest, with `next` re-sanitized, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- **The redeemer is an interface** (`WithHandoffRedeemer`), which is why the guards exist.
- **Stated limit:** a refused but valid code stays live until its TTL, and a copy of the URL can redeem it once the refusing condition clears. The fixed 60-second TTL and the source limit bound this.

### 11. MFA: total exemption as a stated limit

Nothing is added to the policy engine. OIDC is exempt through the `security-policy` classification, so neither the MFA challenge nor the requirement applies to OIDC logins by default, whatever the provider's `amr` or `acr` claims say.

- **Why total:** per-provider assurance mapping is its own design, scheduled as `oidc-mfa-assurance`.
- **Override:** replace the classification. Redemption already handles a challenge (code consumed, session pending) and an enrolment-required deny (code kept).
- **Documented** in the README's security limits and beside the classification.

### 12. Back-channel logout

```go
func (m *Manager) VerifyLogoutToken(ctx context.Context, provider, raw string) (LogoutClaims, error)
func WithLogoutTokenMaxAge(d time.Duration) ManagerOption            // default 2m
func WithBackchannelLogoutScope(s BackchannelLogoutScope) OAuth2Option // default IssuerSessions; AllSessions
func WithBackchannelLogoutPath(p string) OAuth2Option                // default /logout/oauth2/backchannel/{provider}
```

- **Replay bound: `iat` only, no `jti` store.**
  - A `sid` token is inert on replay.
  - A `sub`-only token is bounded from permanent to the maximum age, without a table, three adapters, a suite and a sweep.
  - `jti` must be present and is returned, so a replay guard can wrap the call later.
  - `exp` is optional, as the standard allows, which is why `iat` is mandatory.
  - The future-dated `iat` direction is checked explicitly rather than left to jwx's defaults.
  - `events` must contain the back-channel member with an object value; its contents are ignored.
- **Dispatch:**
  - when `sid` is present, `DeleteByExternalSession(issuer, sid)`;
  - otherwise `Links.FindByExternal(provider, issuer, sub)`, then `DeleteByUserAndIssuer(user, issuer)`, or `DeleteByUser` under `AllSessions`.
  
  The scope keys on the verified issuer, not the provider name, because two registry entries may name one issuer.
- **Why issuer scope by default:** a provider asserts a fact about its own session, and has no authority over a password login or another provider's session.
- **Responses:**
  - 200 with an empty body and `no-store` for any verified token;
  - 400 with an empty body and `no-store` for a missing or invalid token (decision 16, departure 6);
  - discovery and store errors propagate as themselves, and counts go to a sampled log only.
- **Prerequisites:** the endpoint is unauthenticated and needs the key before anything is verified, so decision 3's cooldown and backoff are prerequisites, not refinements.

### 13. RP-initiated logout

`Manager.EndSessionURL(ctx, provider, idTokenHint, postLogoutRedirect, state string) (string, error)` returns `""` and no error when there is no end-session endpoint. It omits empty parameters, because providers compare `post_logout_redirect_uri` byte for byte.

- **Local logout hook:** the local logout in `http-security-chain` gains `WithRPInitiatedLogout(bool)` (default true) and `WithPostLogoutRedirect(url)` (default none, validated at construction). After deleting a session that records a provider, it adds `end_session_url` to the logout response.
- **The ID token is kept** because several providers show a confirmation page instead of logging out when no hint is sent. It is sealed at rest by `secrets-at-rest`, and is never re-verified or accepted as a credential.

### 14. Endpoints and wiring

| Default path | Method | Purpose |
|---|---|---|
| `/oauth2/authorization/{provider}` | GET | start a login |
| `/login/oauth2/callback/{provider}` | GET | callback |
| `/login/oauth2/handoff` | POST | redeem a handoff code |
| `/logout/oauth2/backchannel/{provider}` | POST | back-channel logout |

- **Registration:** `httpsec.EnableOAuth2Login(opts...)` registers the four interceptors in the chain's OAuth2 slot. Transport options live there; provider, discovery, broker and role options belong to the `oidc` constructors.
- **Paths:** `{provider}` must be one non-empty segment with no `/` and must resolve, otherwise the response is 404. Off-route requests pass through untouched.
- **Construction checks:**
  - path collisions;
  - non-positive durations or a negative stale window;
  - options naming unregistered providers;
  - `WithRoleSync` without `WithRoleClaim`, or without `WithCallbackSuccess`;
  - `WithJIT` without a provisioner;
  - invalid allowlist entries or post-logout redirect;
  - an algorithm list containing `none`.
- **Refusal logs:** one `logsample.Sampler` per subsystem (`oidc.callback`, `oidc.handoff`, `oidc.backchannel`), each with a reporter.

### 15. Test-first

- **The in-process test identity provider** (`test` module) serves discovery, a key set and a token endpoint, with rotatable keys and call counters. It emits every malformed token: wrong `iss` or `aud`, expired, future `iat`, bad signature, unknown `kid`, `alg: none`, `HS256` signed with the client secret, wrong `nonce`, missing `sub`, and multiple audiences without `azp`.
- **Conformance suites:**
  - Every refusal case is a pair: the refusal, then the correct call still succeeding. This catches a store that burns before comparing.
  - Concurrent `Complete`, `Consume` and `Insert` use a barrier, and are mutation-checked against read-then-write implementations.
- **Mutations to run by hand,** each killing its own test:
  - `Consume` moved before the checks;
  - the fast path dropped;
  - `return decision.Reason` without the fallback;
  - `!evaluated` dropped;
  - `|| Outcome == Deny` dropped;
  - the cooldown claimed outside the flight;
  - not-attempted refusals fed to the backoff;
  - the stale window serving a fresh entry;
  - `AllSessions` as the default;
  - `sub` checked before `sid`;
  - the `iat` presence check dropped;
  - refusals not recorded against the source guard.
- **Concurrency:** `testing/synctest` with an injected clock for the cooldown, backoff and TTL tests. A goroutine-leak check covers `Stop`.
- **Real provider:** one Keycloak testcontainer test covers discovery, the authorize redirect, the code exchange with both client authentication methods, ID token verification and a back-channel logout.

### 16. Deliberate departures from the established design

Each item names what scrty does differently from the established behaviour of this feature, and why: **(a)** a settled scrty product decision requires it, or **(b)** the established approach has a known defect or an admitted gap.

1. **In-memory flow store as the default; no stateless signed-cookie flow store.** The established default encodes the flow into an HMAC-signed cookie that needs a consumer secret.
   - (a) scrty's security state is in memory by default, and every default must work with no configuration; a required secret cannot be a zero-configuration default.
   - (b) The signed-cookie store admittedly cannot enforce single use (a handle replayed before expiry with a matching state validates again), and its refusals are not uniform, so it cannot meet the flow store contract. Offering it as an option would silently weaken a documented guarantee.
2. **Withdrawn.** Links and handoffs resolve by username, with a stored user-reference guard, as established. No settled decision requires resolving by user reference: `identity-model`'s loader looks up by username.
3. **Handoff redemption is rate limited per source, and refusals of a valid code count by default.** The established endpoint had no limiter, so a denied code could be replayed at no cost for its whole TTL.
   - (a) Refused redemptions count by default, with an opt-out.
4. **A policy deny, a missing policy evaluation or a discarded deny never yields a session, and redemption is check-then-consume.** This matches the established behaviour after its own later correction. It is listed because scrty builds it in from the start, not because the rule differs.
   - (a) One-time credentials are check-then-consume from the start.
5. **The handoff code is read only from the POST body, and the callback redirect adds `Cache-Control: no-store`.** The established redemption read the code from query or body.
   - (a) The conveyance must keep the code out of referrer headers and logs where avoidable, and a code accepted in a query string invites a second URL carrying it.
6. **Back-channel logout answers a bad token with a bare 400.** The established endpoint wrote a coarse error description.
   - (a) With nothing wired, scrty's error responses are a bare status code with no body.
7. **`client_secret_basic` is supported per provider**, keeping `client_secret_post` as the default. The established exchange supported only body credentials.
   - (b) This was an admitted gap: a provider requiring Basic authentication refused the exchange.
8. **An accepted-algorithm list containing `none` fails construction.** The established behaviour silently filtered `none` out, and fell back to `RS256` when nothing remained.
   - (a) Wiring mistakes fail at construction.
9. **Provider key sets live in jwx v3's `jwk.Cache`, behind scrty's own freshness, cooldown, coalescing and backoff wrapper.** The established design wrapped a one-shot fetch in a hand-rolled TTL map.
   - (a) jwx v3, including its JWKS cache, is scrty's single JOSE stack.
   - The wrapper keeps every established guarantee, and adds a `Start`/`Stop` lifecycle because the cache runs background goroutines.
10. **Withdrawn.** Password-hash mapping and claim mirroring are adopted as established, through `identity-model`'s update operation (decision 8a).
11. **Link stores can delete a user's links.** The established store could only find and insert.
    - (b) This was an admitted gap: links outlived users, and removing one needed a direct database write.

## Risks / Trade-offs

- [A consumer renders error text into responses, exposing the cause of a refusal] → Sentinels are uniform, and wrapped causes are for logs. The default response is a bare status (`http-error-propagation`), and godoc says not to render `err.Error()`.
- [A refused handoff code stays live and can be replayed from a URL copy] → Fixed 60-second TTL, refusals counted per source, code only in a POST body, `no-referrer`. Documented as a limit.
- [The in-memory rate limiter multiplies by the replica count] → The stated `rate-limiting` limit applies. `shared-rate-limiting` addresses it later.
- [The in-memory flow store breaks callbacks across replicas without sticky routing] → Documented on the default. Multi-replica deployments wire a durable flow store.
- [`jwk.Cache` retains a last good key set after failed background refreshes] → scrty's wrapper judges freshness from observed successful fetches and refuses expired sets unless the consumer opted into a bounded stale window.
- [Background and on-demand refresh can double the key-set fetch rate] → At most two fetches per provider per TTL. This is not caller-steerable.
- [A provisioned user with no link after a crash between the two writes locks that identity out] → Fails closed. Documented, with the shared-transaction recipe and the operator fix.
- [Total MFA exemption trusts weak provider authentication] → A stated limit, with the classification override, and `oidc-mfa-assurance` scheduled.
- [Role sync de-privileges everyone after a provider misconfiguration, or privileges self-assigned claims] → Off by default, refused without a conveyance that carries it, costs documented, allowlist available.
- [Logout-token replay within the maximum age ends a user's newer sessions] → A stated limit. `jti` is carried for a later guard.
- [A provider's clock drift beyond the leeway makes every logout token invalid] → The wrapped cause is logged. Leeway and maximum age are replaceable.
- [A mapped password hash is a standby local credential that outlives a password change at the provider unless mirrored] → Off by default. Mirroring is available, the limit is documented, and acceptance is restricted to bcrypt within a cost band behind an encoder check.
- [A mirror write fails silently from the user's point of view] → Logged at ERROR with redaction. The next login retries.
- [The durable handoff table names its subject column `user_id` while the record carries a username] → Flagged to `durable-persistence`. The column holds the username as opaque text.
- [Trusted provider configuration can direct outbound requests and the client secret anywhere] → Documented on every field. Revisit if providers load from storage.

## Migration Plan

Not applicable: a new library with no consumers and no tags.

## Open Questions

- **Rehash on login versus mirroring.** If the `authentication` capability rehashes a matched bcrypt password to Argon2id after login, a mirrored bcrypt claim will differ and be written back on every login. That is correct but costs a write per login. Whether to skip rehashing for mirrored users can be decided when authentication's rehash lands, without changing these specs.
