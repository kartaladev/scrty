## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Earlier contracts this change builds on, and does not restate** (named as the code now spells them):
  - `identity-model`: the opaque user reference; the user loader, which loads by username (`LoadByUsername`) and by user reference (`LoadByUserID`); the create-only `Provision` whose collision is decided by the write; the `Update` verb that writes only the fields `identity.ApplyUserOptions(...).IsSet` reports; and `identity.MissingPort` for an absent port.
  - `factor`: the `factor.OIDC` first-factor kind with channel `factor.Federated`, and `Kind.MFAExempt`. The classification is replaced with `policy.WithMFAExemption`, given to both `policy.NewMFAPolicy` and `policy.NewMFARequirementPolicy`.
  - `sessions`: `session.WithExternalSession(provider, issuer, sid, idToken)` in the creating write; `DeleteByExternalSession(issuer, sid)` and `DeleteByUserAndExternalIssuer(user, issuer)`, both returning a count, where an empty argument matches nothing and is not an error; `DeleteByUser`, which returns no count; and `session.NewEncryptedStore`, which already seals `ExternalIDToken` at rest through a `session.Cipher`.
  - `security-policy`: phased evaluation (`Engine.EvaluatePhase(ctx, policy.PostAuthentication, in)`), `policy.ErrPolicyDenied` substituted for a reasonless deny, and `policy.Challenger`.
  - `rate-limiting`: `ratelimit.SourceGuard`, with separate `Check` and `RecordFailure` steps, and `ErrSourceUnattributable`.
  - `token-issuance` and `signing-keys`: the internal access token minted at redemption, with the session id as `jti`.
  - `http-security-chain`, `http-error-propagation` and `outbound-http-confinement` (http-security): the `OrderOIDC` slot; the login tail `completeLogin`; the source-throttle helpers `sourceThrottled` and `recordSourceFailure`; the status table; `outbound.Client` (`Get`, `PostForm`), which enforces the scheme, confines redirects, re-checks the final URL, bounds bodies and applies timeouts; and `internal/origin` (`Allowlist`, `Same`).
  - `magic-link` (auth-methods): the sibling redemption interceptor whose pattern this change follows: `policyOutcome`, `guardRedemption`, `recordRefusal` and a `loginDocument`-embedding response.
- **Persistence split.** This change owns the behaviour of the link, flow and handoff stores and ships in-memory defaults. `durable-persistence` owns the three durable adapters (`security-state-stores`) and a `session.Cipher` implementation for sealing (`secrets-at-rest`). The sealing store itself already exists.
- **One JOSE stack.** `github.com/lestrrat-go/jwx/v4` is scrty's only JOSE, JWT and JWK library. Provider ID tokens, logout tokens and provider key sets are parsed and verified with it. Key sets are fetched through the confined `outbound.Client` and parsed with `jwk.Parse`, behind scrty's own cache (decision 3). The `jwkfetch` companion is not used, and `openspec/config.yaml` is amended to say so.
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
| `oidc` | registry, discovery and key cache, authorize/callback manager, flow store port and in-memory store, ID and logout token verification, broker, link store port and in-memory store, handoff manager, handoff store port and in-memory store | `identity`, `factor`, `session` (types), `outbound`, `pkg/id`, `pkg/logsample`, jwx v4, `golang.org/x/sync/singleflight` |
| `httpsec` (additions) | the authorize, callback, redemption and back-channel logout interceptors, the end-session step on local logout, and create options on the login tail | `oidc`, `factor`, `identity`, `policy`, `ratelimit`, `session`, `token`, `internal/origin` |
| `outbound` (modified) | `PostForm` gains a header argument, for `client_secret_basic`; `AllowsScheme` reports the client's scheme rule, for construction-time validation | — |
| `test` module | `RunLinkStoreSuite`, `RunFlowStoreSuite`, `RunHandoffStoreSuite`, the `LoadByUserID` case in the identity conformance suite, an in-process test identity provider, `RunTestKeycloak` | testcontainers-go |

The `oidc` package has no HTTP-framework import, and makes outbound calls only through `outbound.Client`.

- **New core dependency:** `golang.org/x/sync`, for `singleflight`. It is a Go-project module with no transitive dependencies, and it is neither a framework, a driver, a scheduler nor a DI container, so the `module-layout` guard holds. No other dependency is added.
- **Alternative rejected:** a nested `oidc` module. The core already carries jwx for `token`, and OIDC needs no framework or driver.

### 2. Provider registry: trusted, validated input

```go
type Provider struct {
    Name, Issuer, ClientID, ClientSecret, RedirectURL string
    Scopes      []string         // default: openid, profile, email
    ClientAuth  ClientAuthMethod // default: ClientSecretPost; ClientSecretBasic available
    AuthorizationEndpoint, TokenEndpoint, JWKSURI string // all three or none
    EndSessionEndpoint string    // optional, independent of the pin rule
    SigningAlgs []string         // default: RS256; an empty non-nil list is refused
}
func NewRegistry(providers ...Provider) (*Registry, error)
```

- **Default:** validation at construction, per `oidc-login`. `RedirectURL` is required, and is never derived from the request `Host`, which a client controls.
- **The scheme follows the confined client.** `NewRegistry` checks that the issuer, the redirect URL, the end-session endpoint and every pinned endpoint are absolute URLs with a host, and nothing about their scheme. `NewManager`, which is where the registry meets the outbound client, refuses any of those URLs whose scheme the client does not allow (`outbound.(*Client).AllowsScheme`). Discovery applies the same rule to the endpoints a document names.
  - **Default:** `https` only, because the default client allows only `https`; an `http` issuer fails construction, not the first login.
  - **Override:** a consumer who supplies a client built with `outbound.WithAllowedSchemes("http")` can register an `http` development provider, as decision 2's outbound-client bullet intends.
  - **Why not in `NewRegistry`:** the registry cannot see the client, so an `https`-only registry check made the documented development-provider override impossible, and the drafted spec required both. Decided with the user during implementation.
- **Trusted input.** Beyond `https`, a parsable URL and a host, the destination is not filtered. Loopback and private hosts are accepted, because development IdPs and internal corporate IdPs are real topologies. A pinned token endpoint receives the client secret, so whoever can write provider configuration can direct that secret. This is documented on every URL field and in the README as a limit.
- **`EndSessionEndpoint`** is outside the all-three-or-none rule. Pinning it alone is valid, and an empty value means the provider offers no RP-initiated logout.
- **Symmetric algorithms** (`HS*`) are refused unless listed explicitly for that provider. When listed, the client secret is the key, and that is documented.
- **Override:** everything is plain data. A consumer-built `Registry` from any source is accepted, and the trust statement then applies to that source.
- **Outbound client.** `WithOutboundClient(*outbound.Client)` replaces the default, which is `outbound.New()` with its own defaults (https only, 10 s, 1 MiB, 10 redirects). A consumer supplies one to trust a test CA, to allow `http` for a development provider through `outbound.WithAllowedSchemes`, or to change the bounds. Whatever client is supplied, confinement is `outbound`'s, so no option here can weaken it past what `outbound` itself allows.
- **Identifiers, randomness and time**, as in `onetime` and `magiclink`:
  - `WithIDGenerator(id.Generator)`, default the UUIDv7 generator, for link and handoff record ids;
  - `WithRandom(io.Reader)`, default `crypto/rand.Reader`, for state, nonce, verifier, flow handles and handoff codes;
  - `WithClock(func() time.Time)`, default `time.Now`, for every expiry, TTL, cooldown and backoff decision.

  They are named `ManagerOption`, `BrokerOption` or `HandoffOption` according to the constructor they configure, and each constructor that needs one takes it.
- **Alternative rejected:** default-deny internal destinations. The predicate (private ranges, IPv6 unique-local, DNS names resolving to them, resolution at validation versus request time) is non-trivial and TOCTOU-prone. It is the recommended shape if providers ever load from storage.

### 3. Discovery and key sets: scrty's own cache over the confined client

```go
func WithDiscoveryTTL(d time.Duration) ManagerOption                    // default 15m
func WithDiscoveryFailureBackoff(base, max time.Duration) ManagerOption // default 1s, 30s
func WithDiscoveryStaleWhileError(window time.Duration) ManagerOption   // default 0 (off)
func WithJWKSRefetchCooldown(d time.Duration) ManagerOption             // default 30s
func (m *Manager) Prefetch(ctx context.Context) error                   // optional eager discovery
```

- **One cache, two resources per provider.** The discovery document (`meta:<provider>`) and the key set (`keys:<provider>`) are entries in one in-process map, each holding the parsed value and the time it was fetched. Both are fetched with `outbound.Client.Get` and parsed in memory: the document with `encoding/json`, the key set with `jwk.Parse`. Every byte therefore passes the same confinement as the token exchange: the scheme, the redirect rules, the final-URL re-check, the timeout and the body bound.
- **Freshness is the entry's own age.** An entry younger than the TTL is served with no network call. An older one is refetched on demand. There is no background refresh, so there is no retained last-good copy to second-guess: an expired entry whose refetch fails is refused, unless the stale window below applies.
- **Discovery is same-origin.** The document's `issuer` must equal the configured issuer exactly, and every endpoint it names must satisfy `origin.Same` with the issuer and use a scheme the outbound client allows (decision 2). A provider that pins all three endpoints is never sent a discovery request.
- **Coalescing.** On-demand fetches for a resource run through a `singleflight.Group` with `DoChan`. The shared call runs on `context.WithoutCancel(ctx)` bounded by the outbound timeout, and each caller selects on its own `ctx.Done()`.
- **Unknown `kid`:** a fresh set missing the `kid` triggers one refetch. The cooldown claim is taken inside the flight body, so the goroutine that claims the window is the goroutine that fetches. A refusal inside the cooldown returns an unknown-signing-key error, which verification maps to invalid token, not provider failure.
- **Failure backoff:** doubling windows keyed like the flight. A refusal that never reached the network (cooldown, or a document failure inside a key-set flight) is marked not-attempted, so it neither opens nor widens a window. Each window transition is logged once, directly rather than through the manager's sampler: the sampler's one-minute interval would swallow the 1, 2, 4, 8 and 16 second transitions, and the backoff itself bounds the volume to one record per window per provider and resource (decided during implementation review). A symmetric-only provider has no key set: `Prefetch` skips it, and HS* tokens are verified with the client secret without consulting the cache.
- **Stale-while-error:** off by default. When configured, it serves an expired entry within `TTL + window` after a failed refresh, including a refresh refused because a backoff window is open (that refusal stands for the failed fetch that opened it), logging a warning per use. It never serves a fresh entry after a failed unknown-`kid` refresh, and never serves a stale set that lacks the caller's `kid`.
- **Eager discovery** is `Manager.Prefetch(ctx)`, which a consumer calls at start-up. It fetches every provider's document (when unpinned) and key set, and returns an error naming the first provider that could not be fetched. Lazy is the default because a constructor that takes no context must not touch the network. There is no `Start` or `Stop`: nothing runs between requests.
- **Stated limits:**
  - state is per process, so N replicas refetch up to N times per window;
  - the first request after an entry expires waits for one fetch, bounded by the outbound timeout;
  - the first failure against a cold cache reaches the network;
  - there is no jitter;
  - a second key rotation inside one cooldown waits for the cooldown to end.
- **Alternative rejected:** `jwkfetch.Cache`, the jwx v4 companion. It needs an `httprc.HTTPClient`, which `outbound.Client` is not, so using it meant adding a streaming `Do` to `outbound` and splitting confinement across two packages. Its background refresh keeps the last good copy when a refresh fails, which this design would have had to wrap with its own freshness tracking to refuse, and its workers need a `Start`/`Stop` lifecycle and a leak check. What it adds over this cache is a warm copy after the TTL, at the cost of up to two fetches per TTL. Decided with the user during the drift review of this change.

### 4. Authorization request

`Manager.Authorize(ctx, provider, next)` generates the state, nonce and verifier from the configured random source (`crypto/rand` by default; 32 bytes each, base64url). It sends an `S256` challenge, stores the flow, and returns the redirect URL and handle. `next` is stored verbatim and untrusted.

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
- **Purge:** `DeleteExpired` refuses a zero cutoff with an error, as `one-time-tokens`' purge does, so a caller that forgot to compute a cutoff cannot delete everything or nothing silently. The conformance suite pins it.
- **Override:** any `FlowStore`. `durable-persistence` completes a durable flow with one conditional `UPDATE` (atomic, not constant-time).
- **Stated limit:** the in-memory store is per process. Behind several replicas without sticky routing, a callback that lands on another replica fails. This is documented on the default.

### 6. Callback, exchange and verification

`Manager.Callback(ctx, provider, code, state, handle)` completes the flow, exchanges the code, verifies the ID token and brokers the identity. It returns `CallbackResult{Principal, Provider, Issuer, SessionID, IDToken, Next}`. It does not create a session.

- **Error branch.** `?error=` goes through `AbortFlow` with the echoed state. The cookie is cleared and the provider's error text logged only when the flow was spent. `Callback` joins `ErrFlowUnspent` at exactly the returns at or before `Complete`, and the interceptor clears the cookie only when that marker is absent. A store fault logs at ERROR and propagates as a server error.
- **Exchange:** `outbound.Client.PostForm` with `grant_type`, `code`, `redirect_uri` and `code_verifier`.
  - Client authentication is `client_secret_post` by default. `client_secret_basic` is per provider (decision 16, departure 7), and sends an `Authorization` header. `PostForm` takes no header today, so this change gives it a header argument, like `Get`'s (`outbound-http-confinement`, modified). The redirect rule that refuses to replay a body to another origin covers the header too, because the redirected request is never sent.
  - Bodies are bounded, the error body is logged truncated and never returned, and the provider's access and refresh tokens are discarded.
  - `golang.org/x/oauth2` is permitted but not used: the call is one POST, and its token-source and refresh machinery would sit unused.
- **Verification (jwx v4):**
  - the header algorithm is checked against the provider's allowlist first; a symmetric algorithm is verified with the client secret and never consults the key set; an asymmetric one requires a `kid`, selects that key from the cached set, requires the key to fit that exact algorithm (a key published without `alg` is matched by key type), and verifies with `jwt.WithKey(alg, key)` together with `jwt.WithIssuer(iss)`, `jwt.WithAudience(clientID)`, `jwt.WithAcceptableSkew(skew)` and `jwt.WithValidate(true)`. `jwt.WithKeySet` is not used because it needs an `alg` on every key, which some providers do not publish (decided during implementation);
  - refusal causes are fixed rule names, never the library's parse error text, which can repeat a claim value;
  - then scrty's own checks: `exp` present, `sub` non-empty, `azp` when there are several audiences, and `nonce` in constant time;
  - `WithClockSkew` defaults to 60 s; zero is accepted and means no leeway, a negative value fails construction.
  
  One unexported `parseProviderJWT(raw, provider, requireExp bool)` is shared, and the ID-token and logout-token verifiers are siblings rather than one function with a mode flag, because they disagree on `nonce`, `sub`, `events` and `jti`.
- **Errors:**
  - authentication failures: `ErrInvalidState`, `ErrInvalidIDToken`, `ErrNoLinkedAccount`, `ErrProvisioningRefused` and `ErrInvalidHandoff`. Each wraps `authenticate.ErrAuthenticationFailed`, so the existing status table maps it to 401 with no new row, and a consumer matching either identity matches;
  - not authentication failures: `ErrExchangeFailed` and `ErrDiscoveryFailed`, which wrap no refusal and map to 500;
  - two new status rows (`http-error-propagation`, modified): `ErrUnknownProvider` maps to 404, for an OIDC path naming an unregistered provider, and `ErrInvalidLogoutToken` maps to 400. Both are returned as errors, not written by the interceptor, so a consumer error handler sees them like any other refusal;
  - `oidc` joins the sentinel registry that `TestStatusForErrorCoversEverySentinel` walks, so an unmapped `oidc` sentinel fails that test.

### 7. Broker, links and provisioning

```go
type ExternalIdentity struct {
    Provider, Issuer, Subject, Email string
    EmailVerified bool
    Claims map[string]any // unchanged
}
type IdentityBroker interface {
    Broker(ctx context.Context, ext ExternalIdentity) (*identity.Principal, error)
}
type LinkStore interface {
    FindByExternal(ctx context.Context, provider, issuer, subject string) (*Link, error) // ErrLinkNotFound; a nil link is refused by the broker
    Insert(ctx context.Context, l Link) error                                          // ErrLinkExists
    DeleteByUser(ctx context.Context, user identity.UserID) (int, error)
}
func NewBroker(links LinkStore, users identity.UserLoader, opts ...BrokerOption) (*Broker, error)
```

- **Link row:** `ID id.ID`, `Provider`, `Issuer`, `Subject`, `UserID identity.UserID`, `Username`, `Email` (not normalized) and `CreatedAt`.
- **Resolution by user reference** (decision 16, departure 2).
  - The link is resolved with `UserLoader.LoadByUserID(Link.UserID)`. A username is a reusable handle, and the loader's own contract says a flow that recorded a reference loads by it. `magiclink` does the same.
  - The loaded `Details.ID` must still equal `Link.UserID` byte for byte. A conforming loader guarantees it, but the check is cheap and a non-conforming loader would otherwise authenticate someone else.
  - `Link.Username` is kept for operators and for logs redacted to their domain. It is never used to look a user up.
  - "User not found", nil details, a mismatch and an inactive user all return `ErrNoLinkedAccount`, with the same outcome as an unlinked identity. A dangling or mismatched link logs at WARN, and an inactive user at DEBUG. A loader outage is returned as itself, wrapped, and is not an authentication failure.
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
  | `WithProvisioner(p)` | none | required when any `WithJIT` is set, checked by `NewBroker`, which refuses its absence with `identity.MissingPort("user provisioner")` |

  "Configured" and "configured empty" are told apart by a comma-ok read, never by `len`, so a missing configuration value fails closed.
- **Username = email.** It is safe because email verification is required by default, and because the create-only provisioner refuses an existing username instead of adopting it.
- **Sequence on a miss:**
  1. check the gates;
  2. `Provision` (create-only; `identity.ErrUserExists` becomes a refusal, with no adoption);
  3. `Links.Insert`, binding the returned `det.ID` and `det.Username`, not the requested email, so a provisioner that normalizes usernames still yields a resolvable link.

  `Provision` is called as `Provision(ctx, email, WithUserName(name), WithUserEmail(email), WithUserRoles(roles...), [WithUserPassword(hash)])`. Both collisions are decided by writes.
- **Stated limit:** a crash between steps 2 and 3 leaves a user with no link, and every later login of that identity is refused until an operator inserts the link. A consumer whose provisioner and link store share a database can run both inside one transaction, using each adapter's transaction resolver.
- **Missing ports:** `NewBroker` refuses a nil link store or user loader with `fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort(...))`, as `magiclink` does.
- **Override:** a consumer `IdentityBroker` passed to `NewManager` in place of `*Broker` replaces linking, provisioning and mirroring, and receives every claim unchanged.

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
  - Anything else is ignored and logged without the value. The shape and cost reasons are logged separately, the cost message naming the observed cost and the band. Each (provider, reason) pair logs WARN once per broker (a process normally builds one), then DEBUG through the broker's sampler, so an attacker-controlled malformed claim cannot silence the cost diagnostic.
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
- **Redaction.** Errors from the consumer's ports (`Provision`, `Update`, `LoadByUserID`, and the link store's `FindByExternal` and `Insert`) are wrapped by a scrubbing error whose `Error()` redacts bcrypt-shaped substrings and the identifying values of the login in hand: the external subject, the user reference and the username become `[redacted]`, and an email becomes `[redacted]@<domain>`. `Unwrap` still reaches the original. It is best effort: matching is exact, so a driver that rewrites a value (for example lower-cases an email) is not caught, and `errors.As` into a driver type bypasses it; both are documented. Added during implementation, after review showed a SQL driver's duplicate-key message carrying the subject and email into the log.
- **Mirroring,** on a linked login after the user-id and active checks:
  1. Resolve the mapped options; if none resolve, stop.
  2. Apply the options with `identity.ApplyUserOptions`, and read which fields they name with `(*NewUser).IsSet`.
  3. Compare field by field through one table (`mirroredFields`, keyed by `identity.FieldName` and `identity.FieldPassword`) that also drives copy-back. A field counts only when `IsSet` reports it, so the comparison and the update agree on what "named" means. If nothing differs, stop.
  4. `Update(ctx, det.Username, opts...)` naming only the resolved fields whose value differs from the stored one (`identity-model`'s update verb). `det` is the record just loaded by user reference, so the username is current.
  5. On error, or on a nil result: log ERROR (scrubbed) through the broker's sampler, so repeated failures inside its interval are counted rather than each written, and continue with the loaded details.
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
    FindByTokenID(ctx context.Context, tokenID string) (*HandoffRecord, error) // ErrHandoffNotFound
    Consume(ctx context.Context, tokenID string, at time.Time) error          // conditional: unconsumed
    DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
type HandoffRecord struct {
    ID id.ID; TokenID string; SecretHash []byte
    UserID identity.UserID // the user reference the code was issued for
    Provider, Issuer, SessionID, IDToken string
    Next string // the untrusted destination recorded when the login started, re-resolved at redemption
    ExpiresAt time.Time; ConsumedAt *time.Time; CreatedAt time.Time
}
```

- **Code format:** `<tokenID>.<secret>`. The token id is 16 random bytes and the secret 32, both base64url-encoded, with `SecretHash = SHA-256(secret)`.
- **TTL:** fixed at 60 seconds and not configurable. The code travels in a URL and a refused code stays live, so widening the window is a security decision, not a tuning knob.
- **Purge:** `DeleteExpired` refuses a zero cutoff, as for flows (decision 5).
- **Its own store, not `one-time-tokens`.** The record needs typed provider-session fields, and `issuer` and `sid` are what later logout matching keys on. A dedicated store also discharges the purpose check structurally.
- **Conveyance hygiene:**
  - the redirect appends `handoff` with `url.Values.Set`;
  - it carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and clears the flow cookie;
  - redemption reads the code from the POST body only (decision 16, departure 5);
  - the README tells the landing page to remove the parameter with `history.replaceState` before loading any third-party resource;
  - the library never logs the code.
- **Redirect allowlist:** `WithOIDCAllowedRedirects(entries...)` (default empty, so the destination falls back to `/`) and `WithOIDCAllowedOrigins(origins...)` (default none), built into an `internal/origin.Allowlist` with `origin.NewAllowlist`. The entry and origin rules are therefore exactly the promoted "Browser redirect targets are host-relative or declared" requirement of `outbound-http-confinement`, including a declared `http` loopback origin; this change does not restate them. `Allowlist.Resolve` re-checks at use, so no future call site can reintroduce a foreign-origin redirect carrying a live code. The names carry the `OIDC` prefix because `WithAllowedRedirects` is `magic-link`'s, and one option never governs two subsystems.
- **Override:** `WithCallbackSuccess(func(ex *httpsec.Exchange, res oidc.CallbackResult, next string) error)` replaces the whole tail, for example for a consumer BFF. No handoff is issued.

### 10. Handoff redemption: check-then-consume, guarded

```go
type RedeemCheck func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error // same shape as magiclink.Check
func (h *HandoffManager) Redeem(ctx context.Context, code string, checks ...RedeemCheck) (HandoffResult, error)
```

**Order inside `Redeem`:**
1. Parse the code.
2. Call `FindByTokenID`.
3. Compare the secret in constant time.
4. Check expiry.
5. Non-authoritative fast path: `ConsumedAt != nil` returns `ErrInvalidHandoff`. This skips re-running policy for replays of a spent code.
6. `LoadByUserID(rec.UserID)`, refusing a miss, nil details, an inactive user and a `Details.ID` that differs from `rec.UserID`.
7. Run the checks in order. The first error is returned unwrapped.
8. `Consume` last. A refusal or store error returns no principal.

**Errors follow `magic-link`** (decided with the user during the drift review): the code check, every resolution failure, a store or loader outage, and the consume write all return `ErrInvalidHandoff`, with the cause logged at DEBUG (miss, inactive, mismatch) or ERROR (outage). Only the checks' own errors are returned unchanged. A redemption therefore has one face whatever went wrong, and an outage cannot be told apart from a bad code by the caller. The outage is visible in the ERROR log, not in the status.

A refusal or lookup failure never spends the code. Single use rests on step 8 alone. Checks must be side-effect free, and the godoc says so, including for consumer policies evaluated inside the shipped check.

**The interceptor:**
- **Rate limiting** (decision 16, departure 3), through the chain's source-throttle seam: `sourceThrottled` runs first, and a throttled or unattributable source is refused with `ErrInvalidHandoff` without redeeming, as `magic-link` refuses with its invalid-link error. The guard comes from `config.resolveSourceGuard`, with a limiter dedicated to redemption unless the consumer shares one. `recordSourceFailure` records a failure for every failed redemption, outages included, as `magic-link` does. `WithHandoffCountRefusals(false)` stops recording exactly the policy denies and check refusals; `ErrInvalidHandoff` is always recorded.
  - Default: 10 failures per source in 5 minutes (`WithHandoffRateLimit`, `WithHandoffLimiter`). A nil limiter fails construction.
- **The policy check** follows `magicLinkInterceptor.policyCheck`: a closure that evaluates `PostAuthentication` with `FirstFactor: factor.OIDC` and the password-change time, and captures `evaluated` and the decision through `policyOutcome`.
  - A deny returns the decision's reason, or `policy.ErrPolicyDenied` when it has none (403). A nil return would read as "no refusal" and spend the code.
  - Allow and challenge return nil.
- **Guards after `Redeem`:** `guardRedemption`, as `magic-link` uses it: an error that `errors.Is` the captured deny is a policy refusal, and `!evaluated || decision.Outcome == Deny` on a nil error refuses with the deny reason or `policy.ErrPolicyDenied`. The guard cannot un-spend a code a non-conforming redeemer consumed, and the godoc says so.
- **Login tail:** after a successful redemption the interceptor hands the principal to `completeLogin`, the step every first factor ends through (`http-security-chain`). `completeLogin` therefore gains session create options, so the interceptor passes `session.WithExternalSession(provider, issuer, sid, idToken)` beside `WithFirstFactor(factor.OIDC)` and the federated fields land in the creating write (`http-security-chain`, modified). The tail evaluates `PostAuthentication` a second time, as it does for magic-link, which is one more reason consumer policies must be side-effect free. The tail marks any challenge pending, issues the token with the session id as `jti`, and refuses with the challenge error when one is pending.
- **Response:** `oidcHandoffDocument`, which embeds `loginDocument` as `magicLinkDocument` does (`access_token`, `refresh_token`, `valid_until`) and adds `next`, re-resolved through the allowlist. It is written with `writeSuccessDocument`, with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- **Refusal logs** use the chain's sampler with keys prefixed `oidc.handoff`, so `Chain.FlushRefusalLogs` covers them.
- **The redeemer is an interface** (`WithHandoffRedeemer`), which is why the guards exist.
- **Stated limit:** a refused but valid code stays live until its TTL, and a copy of the URL can redeem it once the refusing condition clears. The fixed 60-second TTL and the source limit bound this.

### 11. MFA: total exemption as a stated limit

Nothing is added to the policy engine. OIDC is exempt through the `security-policy` classification, so neither the MFA challenge nor the requirement applies to OIDC logins by default, whatever the provider's `amr` or `acr` claims say.

- **Why total:** per-provider assurance mapping is its own design, scheduled as `oidc-mfa-assurance`.
- **Override:** replace the classification with `policy.WithMFAExemption`, given to both `NewMFAPolicy` and `NewMFARequirementPolicy`. Redemption already handles a challenge (code consumed, session pending) and an enrolment-required deny (code kept). A classification that can raise an MFA challenge needs `EnableMFA` wired: the chain refuses to assemble a `policy.Challenger` that nothing enforces, and the godoc beside the exemption says so.
- **Documented** in the README's security limits and beside the classification.

### 12. Back-channel logout

```go
func (m *Manager) VerifyLogoutToken(ctx context.Context, provider, raw string) (LogoutClaims, error)
func WithLogoutTokenMaxAge(d time.Duration) ManagerOption            // default 2m
func WithBackchannelLogoutScope(s BackchannelLogoutScope) OIDCOption // default IssuerSessions; AllSessions
func WithBackchannelLogoutPath(p string) OIDCOption                // default /logout/oauth2/backchannel/{provider}
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
  - otherwise `Links.FindByExternal(provider, issuer, sub)`, then `DeleteByUserAndExternalIssuer(user, issuer)`, or `DeleteByUser` under `AllSessions`.

  `DeleteByUser` returns no count, so under `AllSessions` the log records that the user's sessions were ended, not how many. Adding a count to `sessions` for a log line is not worth a contract change.
  
  The scope keys on the verified issuer, not the provider name, because two registry entries may name one issuer.
- **Why issuer scope by default:** a provider asserts a fact about its own session, and has no authority over a password login or another provider's session.
- **Responses:**
  - 200 with an empty body and `no-store` for any verified token;
  - a missing or invalid token returns `ErrInvalidLogoutToken`, which the status table maps to 400, so the default response is a bare 400 (decision 16, departure 6). The interceptor sets `no-store` before returning it;
  - discovery and store errors propagate as themselves, and counts go to the chain's sampled log only, under `oidc.backchannel` keys.
- **A verified token is acted on even if the caller disconnects.** Once the logout token verifies, the session deletes run on `context.WithoutCancel`: they are idempotent, and a provider that drops the connection after sending must not have its logout silently skipped, since most providers do not retry. A request cancelled before verification ends nothing and returns the context error. A refused token is logged, sampled, under `oidc.backchannel.invalid_token` with the failed rule, never the token. Decided during implementation review.
- **Prerequisites:** the endpoint is unauthenticated and needs the key before anything is verified, so decision 3's cooldown and backoff are prerequisites, not refinements.

### 13. RP-initiated logout

`Manager.EndSessionURL(ctx, provider, idTokenHint, postLogoutRedirect, state string) (string, error)` returns `""` and no error when there is no end-session endpoint. It omits empty parameters, because providers compare `post_logout_redirect_uri` byte for byte.

- **Local logout hook** (`http-security-chain`, modified), as the http-security design planned it: an optional end-session dependency on `LogoutDeps`.

  ```go
  type EndSessionBuilder interface {
      EndSessionURL(ctx context.Context, s *session.Session, state string) (string, error)
  }
  type LogoutDeps struct {
      Sessions   *session.Manager
      EndSession EndSessionBuilder // optional; nil means no end-session step
  }
  ```

  - After deleting a session that records a provider, logout calls the builder with the deleted session and the optional `state` form field. A non-empty URL is answered as 200 with `{"end_session_url": "..."}` and `Cache-Control: no-store`. Otherwise the answer stays 200 with an empty body, as today.
  - The session is deleted first, and a builder error after the delete is logged, not returned: the local logout has happened, and failing it would tell the client it had not.
  - **Default:** on when OIDC login is wired. `EnableOIDCLogin` supplies its manager as the builder when `LogoutDeps.EndSession` is nil. `WithOIDCRPInitiatedLogout(false)` turns that off, and an explicit `LogoutDeps.EndSession` always wins.
  - `oidc.WithPostLogoutRedirect(url)` (default none) is validated at construction as an absolute URL with no user information whose scheme the outbound client allows (decision 2). It is manager configuration, so `EndSessionURL(ctx, provider, idTokenHint, state)` takes no redirect argument (decided during implementation).
- **The ID token is kept** because several providers show a confirmation page instead of logging out when no hint is sent. It is sealed at rest when the consumer wires `session.NewEncryptedStore`, which already exists; `secrets-at-rest` supplies a `Cipher`. It is never re-verified or accepted as a credential.

### 14. Endpoints and wiring

| Default path | Method | Purpose |
|---|---|---|
| `/oauth2/authorization/{provider}` | GET | start a login |
| `/login/oauth2/callback/{provider}` | GET | callback |
| `/login/oauth2/handoff` | POST | redeem a handoff code |
| `/logout/oauth2/backchannel/{provider}` | POST | back-channel logout |

- **Registration:** `httpsec.EnableOIDCLogin(m *oidc.Manager, h *oidc.HandoffManager, opts ...OIDCOption) Option` registers the four interceptors at `OrderOIDC`, taking its required dependencies up front as `EnableMagicLink` and `EnableLogout` do. `WithOIDCTokens` and `WithOIDCSessions` are required, as `WithMagicLinkTokens` and `WithMagicLinkSessions` are for magic-link. Transport options (paths, allowlist, conveyance, redemption limiter) live on `OIDCOption`; provider, discovery, broker and role options belong to the `oidc` constructors. The `OrderOIDC` comment gains the back-channel endpoint.
- **Paths:** `{provider}` must be one non-empty segment with no `/`. A segment that names no registered provider returns `ErrUnknownProvider`, which maps to 404. Off-route requests pass through untouched.
- **Construction checks:**
  - path collisions;
  - non-positive durations or a negative stale window;
  - options naming unregistered providers;
  - `WithRoleSync` without `WithRoleClaim`, or without `WithCallbackSuccess`;
  - `WithJIT` without a provisioner;
  - invalid allowlist entries or post-logout redirect;
  - an algorithm list containing `none`.
- **A replaced conveyance turns redemption off.** With `WithCallbackSuccess`, no handoff code is issued, so the redemption endpoint is not registered: `EnableOIDCLogin` then accepts a nil handoff manager and needs no token generator, and it refuses a non-nil handoff manager or any redemption-only option (`WithHandoffRedeemer`, `WithHandoffLimiter`, `WithHandoffRateLimit`, `WithHandoffCountRefusals`, `WithOIDCHandoffPath`) as a contradictory configuration. Decided during implementation review.
- **Naming.** The `httpsec` API is named for OIDC (`EnableOIDCLogin`, `OIDCOption`, `WithOIDC*`, `DefaultOIDC*`), matching `OrderOIDC` and the `oidc` package, with the Go initialism in capitals. The default URL paths keep the conventional `oauth2` segments (`/oauth2/authorization/{provider}`, `/login/oauth2/callback/{provider}`), because they are what a consumer registers at the provider, not Go names. Renamed from an `OAuth2` prefix at the user's request during implementation.
- **Path prefixes** are given without the `{provider}` segment; a missing trailing slash is added, a path not starting with `/` is refused, and the root prefix `/` is refused for the authorize, callback and back-channel endpoints, because it would claim every one-segment path of the application.
- **Refusal logs:** the `httpsec` interceptors use the chain's sampler with keys prefixed `oidc.callback`, `oidc.handoff` and `oidc.backchannel`, as `magic-link` does, so `Chain.FlushRefusalLogs` covers them. Refusals logged inside the `oidc` package (cache backoff transitions, ignored password claims) use one `logsample.Sampler` owned by the `Manager` or `Broker`, always with a reporter.
- **Adapters:** the four endpoints run through `ginsec` and `fibersec` with the same outcomes as `net/http` (`framework-adapters`), which the OIDC slot has not yet been tested against.

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
  - refusals not recorded against the source guard;
  - the `Details.ID` equality check dropped from link and handoff resolution;
  - `LoadByUsername` substituted for `LoadByUserID`;
  - the zero-cutoff refusal dropped from a store's `DeleteExpired`.
- **Concurrency:** `testing/synctest` with the injected clock for the cooldown, backoff and TTL tests. The cache starts no goroutine of its own, and a leak check on a burst of coalesced fetches with cancelled callers pins that.
- **Adapter parity:** the four endpoints run through `net/http`, `ginsec` and `fibersec` with identical outcomes, closing the gap the http-security change left open at `OrderOIDC`.
- **Real provider:** one Keycloak testcontainer test covers discovery, the authorize redirect, the code exchange with both client authentication methods, ID token verification and a back-channel logout.

### 16. Deliberate departures from the established design

Each item names what scrty does differently from the established behaviour of this feature, and why: **(a)** a settled scrty product decision requires it, or **(b)** the established approach has a known defect or an admitted gap.

1. **In-memory flow store as the default; no stateless signed-cookie flow store.** The established default encodes the flow into an HMAC-signed cookie that needs a consumer secret.
   - (a) scrty's security state is in memory by default, and every default must work with no configuration; a required secret cannot be a zero-configuration default.
   - (b) The signed-cookie store admittedly cannot enforce single use (a handle replayed before expiry with a matching state validates again), and its refusals are not uniform, so it cannot meet the flow store contract. Offering it as an option would silently weaken a documented guarantee.
2. **Links and handoff codes resolve the user by user reference, not by username.** The established design resolved by username and guarded the result with the stored reference.
   - (a) A settled scrty decision requires it. `identity.UserLoader.LoadByUserID` exists, its contract says a flow that recorded a reference loads by that reference because a username is a reusable handle, and `magic-link` resolves this way. This departure was withdrawn when the loader could only look up by username, and is reinstated now that it can do more.
   - The reference-equality guard is kept as a second check against a non-conforming loader.
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
9. **Withdrawn.** Provider key sets are fetched one-shot and held in scrty's own TTL cache, as established, with the fetch going through `outbound.Client` and the parse through jwx (decision 3). An earlier draft moved them onto the `jwkfetch` companion's background cache; that was rejected during the drift review, and `openspec/config.yaml` is amended to match.
10. **Withdrawn.** Password-hash mapping and claim mirroring are adopted as established, through `identity-model`'s update operation (decision 8a).
11. **Link stores can delete a user's links.** The established store could only find and insert.
    - (b) This was an admitted gap: links outlived users, and removing one needed a direct database write.

### 18. Refinements made during implementation

Each item was reported by an implementation or review dispatch and accepted by the main session. Decisions already recorded in place above (the scheme rule in 2, backoff logging and the stale window in 3, redaction in 8a, the replaced conveyance, path prefixes and naming in 14, back-channel cancellation in 12, the post-logout redirect in 13, and the `framework-adapters` row in 17) are not repeated.

- **Per-provider algorithms are data.** `Provider.SigningAlgs` replaces the drafted `WithSigningAlgs(provider, …)` manager option. Default: `RS256` when nil; an empty non-nil list is refused. An `HS*` entry also requires a non-empty client secret, and configured `Scopes` must include `openid`.
- **The broker is a required constructor argument.** `NewManager(registry, broker, opts…)` refuses a nil or typed-nil broker, a zero-value registry, and any broker option naming a provider the registry lacks, role sync included. There is no `WithBroker`: a consumer broker is passed in place of `*Broker`.
- **Stores that are ports, not defaults.** `NewBroker` requires a `LinkStore` and `NewHandoffManager` requires a `HandoffStore`; the library's implementations are `NewMemoryLinkStore()` and `NewMemoryHandoffStore()`. Only the flow store defaults (to `NewMemoryFlowStore`, sharing the manager's clock and random source), because the manager alone owns flows. `NewMemoryFlowStore` returns an error for a bad option; a drawn handle that is already held is refused, never overwritten; `ErrFlowStoreFull` maps to 500.
- **Option names follow the constructor they configure.** `WithBrokerLogger`, `WithBrokerClock`, `WithBrokerIDGenerator` for `NewBroker`; `WithHandoffRandom`, `WithHandoffClock`, `WithHandoffIDGenerator`, `WithHandoffLogger` for `NewHandoffManager`; the unprefixed `WithClock`, `WithRandom`, `WithLogger` are the manager's.
- **`HandoffRecord.Next`** carries the untrusted destination from the flow to the redemption, which re-resolves it through the allowlist.
- **Verification details.** Keys published without `alg` are matched by key type; keys marked for another use are dropped. A present `azp` must be a string equal to the client id, for ID and logout tokens alike. Claims reach the broker decoded from the verified payload, unchanged. A symmetric-only provider has no key set.
- **Callback details.** An empty code, and a flow whose stored provider differs from the path's, are refused as an invalid state; a flow the store has already completed is never reported unspent. Repeated `code`, `state` or `error` parameters are refused, which added `QueryValues` to the `httpsec.Request` port (implemented by the net/http and fiber adapters; gin goes through net/http). The flow cookie's `Max-Age` is the remaining lifetime rounded up, at least 1.
- **The exchange** logs a truncated provider body only for a non-200 answer; a malformed 200 is logged without its body, since it may hold live tokens.
- **Provisioning details.** A provisioner that returns an inactive user, nil details or an empty reference is refused and nothing is linked. The link id is generated before `Provision`, so a generator failure cannot leave an unlinked user. `WithJITAllowUnverifiedEmail` or `WithJITEmailDomains` for a provider without `WithJIT` fails construction. A nil role mapping counts as configured empty; a role array with any non-string element yields no roles; role sync also applies to the login that provisioned the user.
- **Redemption.** The code is read only from a bounded form body; an empty code counts against the source without reaching the redeemer. The policy helpers magic-link used are shared from `httpsec/redemption.go`, with magic-link's behaviour unchanged. The `policy.ErrPolicyDenied` fallback after a deny is unreachable through `*policy.Engine`, which substitutes it itself, and is kept as defence in depth.
- **Back-channel details.** An unknown provider is refused before the body is read. A consumer broker without a link store ends nothing for a subject-only token and answers 200 with a warning; a consumer broker that also exposes `Links() oidc.LinkStore` has it resolved. `EndSessionURL` removes an endpoint's own `client_id`, `id_token_hint`, `post_logout_redirect_uri` and `state` when this call supplies none, so a stale value is never sent.
- **fiber sees the decoded path.** `fibersec`'s `Request.Path()` now decodes the raw path as net/http builds `URL.Path`, so `/oauth2/authorization/corp%2F..` passes through on every adapter instead of being refused as an unknown provider on fiber alone. Found by the whole-branch review; pinned by a conformance scenario.
- **Handoff redemption scrubs consumer-port errors** (loader, store find and consume) the way the broker does: bcrypt-shaped text, the token id and the user reference are redacted before logging.
- **Test module shape.** `test/oidc.IdentityProvider.Login` takes token options so malformed ID tokens run through the whole flow, and records which client-authentication channel each token request used. `test.RunTestKeycloak` returns every realm client and user and offers `WithTestKeycloakBackchannelLogout`, which reaches the host through the testcontainers host-port tunnel.

## Risks / Trade-offs

- [A consumer renders error text into responses, exposing the cause of a refusal] → Sentinels are uniform, and wrapped causes are for logs. The default response is a bare status (`http-error-propagation`), and godoc says not to render `err.Error()`.
- [A refused handoff code stays live and can be replayed from a URL copy] → Fixed 60-second TTL, refusals counted per source, code only in a POST body, `no-referrer`. Documented as a limit.
- [The in-memory rate limiter multiplies by the replica count] → The stated `rate-limiting` limit applies. `shared-rate-limiting` addresses it later.
- [The in-memory flow store breaks callbacks across replicas without sticky routing] → Documented on the default. Multi-replica deployments wire a durable flow store.
- [The first login after a key set expires waits for a fetch] → Bounded by the outbound timeout, once per TTL per provider per replica, coalesced across concurrent callers. A consumer who wants the wait moved off the login path lowers it with a longer TTL or eager discovery at start-up.
- [A handoff redemption during a store or loader outage looks like a bad code and counts against the source] → Chosen for one uniform face across one-time credentials, matching `magic-link`. The outage is logged at ERROR. Legitimate users can be throttled for the window of an outage; the limit is 10 failures in 5 minutes and replaceable.
- [A provisioned user with no link after a crash between the two writes locks that identity out] → Fails closed. Documented, with the shared-transaction recipe and the operator fix.
- [Total MFA exemption trusts weak provider authentication] → A stated limit, with the classification override, and `oidc-mfa-assurance` scheduled.
- [Role sync de-privileges everyone after a provider misconfiguration, or privileges self-assigned claims] → Off by default, refused without a conveyance that carries it, costs documented, allowlist available.
- [Logout-token replay within the maximum age ends a user's newer sessions] → A stated limit. `jti` is carried for a later guard.
- [A provider's clock drift beyond the leeway makes every logout token invalid] → The wrapped cause is logged. Leeway and maximum age are replaceable.
- [A mapped password hash is a standby local credential that outlives a password change at the provider unless mirrored] → Off by default. Mirroring is available, the limit is documented, and acceptance is restricted to bcrypt within a cost band behind an encoder check.
- [A mirror write fails silently from the user's point of view] → Logged at ERROR with redaction. The next login retries.
- [Multi-replica deployments need durable link, flow and handoff stores that do not exist yet] → Flagged to `durable-persistence`, whose design now records what this change needs: tables matching `oidc.Link`, `oidc.Flow` and `oidc.HandoffRecord` (the handoff keyed by user reference, `next` stored), the three `test/oidc` conformance suites with their zero-cutoff and racing cases, and a `session.Cipher` for the sealing store. Until then the in-memory defaults are per process, as stated.
- [Trusted provider configuration can direct outbound requests and the client secret anywhere] → Documented on every field. Revisit if providers load from storage.

### 17. Changes to archived capabilities

The drift review found that this change cannot be built on the promoted specs without changing four of them; implementation added a fifth (`framework-adapters`). Each change is additive; nothing is tagged.

| Capability | Change | Why |
|---|---|---|
| `http-security-chain` | Logout gains an optional end-session step (decision 13) and may answer with a body. The login tail accepts session create options (decision 10). | RP-initiated logout needs a URL in the logout response, and every first factor ends through the tail, which today cannot write federated fields. |
| `http-error-propagation` | Two table rows: unknown provider → 404, invalid logout token → 400. | The table has no 404 or back-channel 400 row, and an unmapped sentinel falls to 500. |
| `outbound-http-confinement` | `PostForm` carries caller headers, as `Get` already does. The client reports the schemes it allows. | `client_secret_basic` needs an `Authorization` header on the token request. Provider URLs are validated at construction against the scheme rule the client enforces (decision 2). |
| `framework-adapters` | ginsec commits a 404 refusal, with an empty body, when gin matched no route for the request. Every other refusal stays set-but-uncommitted. | gin's no-route fallback writes `404 page not found` over an uncommitted 404, so an unknown-provider refusal on an OIDC path differed from net/http and fiber. Found by the adapter-parity scenarios; option chosen by the user. |
| `identity-model` | The user loader contract names loading by user reference, and its conformance suite pins it. | `LoadByUserID` exists in code but the promoted spec describes a username-only loader, and the suite does not pin the byte-for-byte reference. This change is the loader's second caller. |

## Migration Plan

Not applicable: a new library with no consumers and no tags.

## Open Questions

- **Rehash on login versus mirroring.** If the `authentication` capability rehashes a matched bcrypt password to Argon2id after login, a mirrored bcrypt claim will differ and be written back on every login. That is correct but costs a write per login. Whether to skip rehashing for mirrored users can be decided when authentication's rehash lands, without changing these specs.
