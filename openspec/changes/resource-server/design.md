# Design

## Context

See proposal.md for the motivation. On `main` after v0.5.0:

- **Credential modes.** Each is its own `Enable*` in a fixed order slot (`httpsec/chain.go:836-921`):
  - the provider's endpoints at 250;
  - Basic 400, API key 450, mTLS reserved 475;
  - `EnableBearerToken` 500, for session tokens, whose `jti` is a session id;
  - `EnableSessionBearer`, for session references;
  - authorization at 900.

  The slots are documented as spaced at least 25 apart (`chain.go:823-826`), though some built-ins sit
  closer (375/380, 650/655/660); a new slot keeps the documented spacing from its neighbours. A mode claims the credentials it
  recognises and hands on the rest. A custom authenticator uses `RegisterInterceptor` and
  `WithCaller`.
- **Challenges.** A refused bearer already gets one challenge: `bearerChallenge`
  (`httpsec/bearer.go:629-690`), registered at `orderDPoPChallenge`, with `WithoutBearerChallenge` and
  a de-duplicating `challengeWatch`. It writes `Bearer error="invalid_token"` with DPoP off, as the
  settled "A 401 on a chain with a built-in bearer carries a challenge" requires.
- **Provider access tokens.** `Provider.VerifyAccessToken` (`oidcprovider/accesstoken.go:269`) reads
  JWT and opaque tokens and checks the grant on every call (`requireGrantHolds`). It checks neither
  the audience nor the binding.
  - It is called by UserInfo (`httpsec/oidc_userinfo.go:120`) and by the provider's revocation and
    introspection (`oidcprovider/revoke.go`).
  - Its `AccessToken` has no authentication time, context or methods, and no claims map.
  - UserInfo's binding check, `holdToKey`, is unexported. Its token reader also reads form bodies.
- **Introspection.** The provider's introspection answer (`describeAccessToken`, `revoke.go`) carries
  no `auth_time`, `acr` or `amr`.
- **Remote keys.** `authenticate/oidc/remote.go` holds a discovery and key-set cache, keyed by
  provider name:
  - TTL, and backoff after a failure;
  - a cooldown on refetching an unknown `kid`;
  - singleflight;
  - per-provider signing algorithms;
  - fetches through `outbound`;
  - confinement of discovered endpoints to the issuer's origin.

  It is unexported.
- **Scopes.** `identity.Principal.Scopes` is documented as "service principals only".
  `authorize.HasAnyScope`/`HasAllScopes` name the missing scopes in their error text, but in no
  structured form.
- **Guards.** The net/http, gin and fiber guards all judge through `internal/guardauth`, which holds
  the recency rule (`SessionAuthenticationTime`, `Recency`) and the refusal mapping. A recency guard
  refuses a caller with no session. Most session endpoints already refuse a caller with no session;
  logout answers such a caller 200 and deletes nothing.
- **Identity links.** `authenticate/oidc.LinkStore` keys links by provider, issuer and subject (the
  settled `identity-linking` capability).
- **The established design** has no resource-server mode. It keeps scopes on service principals
  only, and always conceals inactive accounts. This change departs from it in decisions 17 and 20.

## Goals / Non-Goals

**Goals:**
- One generic resource-server capability for the chain's own provider and for any external issuer,
  usable alone or beside the chain's own sign-in.
- The session-token path (`EnableBearerToken`, `EnableSessionBearer`) keeps its behaviour.
- Guards and chain rules work for access-token callers with no consumer code.
- Every refusal maps onto the settled errors and challenges, or onto a new one that the status table
  and the stable-contract list name.

**Non-Goals:**
- Renaming `EnableBearerToken`/`EnableSessionBearer`, or restructuring chain building.
- A public port for consumer-written token sources (decision 4).
- The IdP's browser signing in with a cookie (the BFF part of `bff-resource-server`).
- Protected-resource metadata (RFC 9728), token exchange (RFC 8693), and RFC 9470's `acr_values`
  parameter.
- Accepting a token from a form body or a query string.

## Decisions

### 1. `EnableResourceServer(resourceID, opts...)`, a credential mode at slot 425

```go
httpsec.EnableResourceServer("urn:example:orders:api",
    httpsec.WithPathPrefix("/api/orders/"),
    httpsec.FromProvider(op),
    httpsec.FromIssuer("https://sso.example.com/realms/main", httpsec.WithSourceAudience("orders-api")),
)
```

- **Name:** it is named for the OAuth role, and pairs with `EnableOIDCProvider`. The user chose it on
  2026-11-25.
- **Slot:** `OrderResourceServer = 425`, between Basic (400) and API keys (450), keeping the
  documented 25-step spacing. It sits:
  - after the provider's endpoints (250), which answer their own tokens, UserInfo included;
  - before the session-token bearer (500), so a recognised access token is claimed first.

  Basic and API keys read other credentials, so their order relative to it does not matter.
- **Consumer interceptors:** the godoc of `RegisterInterceptor` states that one meant to see access
  tokens before the resource server registers before `OrderResourceServer`.
- **Options:** one variadic list. Sources and mode options are both `ResourceServerOption`;
  per-source options go to the source constructor.
- **Alternatives considered:**
  - reusing the session bearer (on-hold option A): it needs branches inside the bearer, where a
    mistake can pass the tests and still be wrong;
  - an option inside `EnableOIDCProvider` (option B): it cannot serve an API without a provider;
  - one mode per source: several switches for one concept.

### 2. Several resource servers per chain, scoped by path prefix (user decision, 2026-11-25)

- **Prefixes:**
  - begin and end with `/`;
  - are absolute, not relative to the base path;
  - match the canonical path whole segment by whole segment (`/api/orders/` does not cover
    `/api/orders-v2/`).
- **A mode with no prefix** covers everything, and is allowed only alone.
- **Overlap** is a construction error. That includes nesting, which is safe to allow later.
- **Routing:** the mode is chosen by path **first**, then the source by token within that mode
  (decision 5). Each mode holds its own sources, so two modes may trust one issuer or one provider.
- **Off-prefix tokens:** a recognised access token on a path no mode covers is refused with
  `invalid_token` at slot 425, and nothing later in the chain sees it. That includes the provider's
  session endpoints at 850 (resume, consent) and the chain's session endpoints. The session-only
  refusal of decision 15 therefore applies on covered paths; off them the answer is `invalid_token`.
  The provider's token-reading endpoints at 250 (UserInfo, token, revocation, introspection) run
  earlier and are unaffected.

### 3. Resource identity

- **Identifier and aliases:**
  - both follow the provider's `validResource` rule;
  - neither may equal the chain provider's issuer: a token whose audience is only the issuer is meant
    for UserInfo;
  - aliases apply to every source of the mode.
- **Per-source audience:** `WithSourceAudience(aud)`:
  - is any non-empty text other than that source's own issuer;
  - is for issuers that cannot emit the identifier (a Keycloak audience mapper value, a Zitadel
    project id; both unverified against current vendor documentation);
  - applies to that source only.
- **The check:** `aud` must contain the identifier, an alias, or that source's audience, by exact
  match (RFC 9068 §4). A token whose audience is only an issuer is refused.

### 4. Sources are a closed set

- **The set:** `FromProvider`, `FromIssuer` and `FromIntrospection`. There is no public source port.
- **Why:** whether revocation state was checked, or which issuer a subject belongs to, is a guarantee
  the library makes. A consumer source could claim it falsely.
- **The line:** a consumer who needs another token kind uses `RegisterInterceptor` before
  `OrderResourceServer`. A public port can be added later without breaking anything.

### 5. Recognition and routing

1. The whole token is bounded before anything is decoded. The bound is the larger of 8 KiB and the
   chain provider's own verifier bound (`2*(maxScope+10*maxResource)+8 KiB`, `accesstoken.go:245`), so
   a token UserInfo accepts is never refused for its size. A longer token is refused.
2. A session token is never offered to a source. Neither is a token typed as the chain's session
   generators declare. A generator whose type the resource server would recognise is a construction
   error. That covers a type equal to `at+jwt` without regard to case, and `JWT` while a source opts in
   to untyped tokens (token-issuance only refuses exact matches).
3. Within the mode covering the path:
   - an `at.` prefix goes to its `FromProvider` source;
   - a JWT, read without verification and only to route it, goes to the source whose issuer equals
     its `iss`;
   - an opaque token goes to its `FromIntrospection` source, if any. With any other mode on the chain
     reading the `Bearer` scheme (session references, or API keys under `WithAPIKeyScheme("Bearer ")`),
     only a token with that source's prefix goes there, and a missing prefix is a construction error
     (decision 12).
4. A JWT typed `at+jwt` that no source of the mode names is refused. Any other unrecognised token
   passes to the next mode.
5. The chain provider's own opaque formats (`at.…` access tokens, `rt.…` refresh tokens) are never
   sent to an introspection source, in any mode. On a mode without a `FromProvider` source they are
   refused with `invalid_token`.
6. Off every covered path, only these are refused (`invalid_token`, under `DPoP` when the token came
   under `DPoP`, `Bearer` otherwise): the provider's own formats, a JWT typed `at+jwt`, a JWT whose
   `iss` names any source, and an opaque token carrying a configured introspection prefix. Every other
   token passes on, so a consumer authenticator at `OrderBearerToken` still sees its own tokens.
7. Two sources naming one issuer **in one mode** is a construction error.

Nothing is granted on the unverified read, and the source verifies again. The routing read is fuzzed.

### 6. Token type and required claims

- **Type:**
  - By default `at+jwt` or `application/at+jwt`, without regard to case (RFC 9068 §2.1,
    RFC 8725 §3.11).
  - `WithUntypedTokens(claim, value)` accepts `typ: JWT`, or no `typ`, only when `claim` equals `value`.
    Keycloak's `typ: Bearer` claim is the example (unverified against current vendor documentation).
  - Without a claim the option is a construction error.
- **Required claims, for external JWTs:**
  - `iss`, `exp`, `aud`, `sub` (non-empty), `iat` and `client_id`;
  - `jti` as well for `at+jwt` (RFC 9068 §2.2);
  - `iat` and `nbf` no later than now plus the larger of the source's skew and 60 seconds, so a token
    used the moment it is issued survives an issuer clock slightly ahead; `exp` keeps the source's
    skew alone.

  Only a source opted in to untyped tokens may take the client from `azp`, because issuers of untyped
  tokens name it there; RFC 9068 requires `client_id` for `at+jwt`.

### 7. Binding: required by default, opt-out per source (user decision, 2026-11-25)

- **Default:** a token without `cnf` is refused with `invalid_token`.
- **Unknown confirmation:** a `cnf` naming only a method the chain cannot check (neither `jkt` nor
  `x5t#S256`) is refused with `invalid_token`, even under `WithUnboundTokens`; it is never treated as
  unbound.
- **Override:** `WithUnboundTokens()` on one source. It is a construction error on a chain whose DPoP
  is required (user decision, 2026-11-25), so the settled "The consumer can require DPoP" guarantee
  is never relaxed. An unbound token presented under the `DPoP` scheme is refused with
  `ErrInvalidDPoPProof` (RFC 9449 §7.1).
- **Binding failures keep the settled refusals:**
  - a DPoP-bound token under `Bearer`, without a proof, with a failing proof or a proof from another
    key → `ErrInvalidDPoPProof` (RFC 9449 §7.1, §7.2);
  - a missing required nonce → the nonce-required refusal with a fresh `DPoP-Nonce` (RFC 9449 §9),
    whenever the chain enables nonces;
  - a missing or mismatched certificate → `ErrCertificateBinding` (RFC 8705 §3).
- **Shared code:** UserInfo's `holdToKey` writes UserInfo's own answers, and answers a key that does
  not fit with `invalid_token`, as UserInfo's settled spec says. It is refactored into a check that
  **returns typed results** (unbound, key mismatch, proof invalid, nonce required, certificate
  mismatch) and writes nothing. UserInfo maps them to its settled answers, unchanged and pinned by its
  existing tests. The resource server maps them to the settled sender-constrained refusals (a key
  mismatch is `ErrInvalidDPoPProof`). There is one replay store. Only the header part of UserInfo's
  reader is shared; its form-body reading stays UserInfo's.
- **Construction check:** the existing check that DPoP needs a verifier of bound credentials counts
  the resource server. Binding required with neither DPoP nor certificate binding is a
  construction error.

### 8. Caller strategies (user decisions, 2026-11-25)

| Strategy | Option | Allowed on | Default for | Caller |
|---|---|---|---|---|
| Claims only | `WithClaimsOnly()` | `FromIssuer`, `FromIntrospection` | `FromIssuer`, `FromIntrospection` | identifier = `<issuer>#<sub>`, never a local user's; scopes; no roles; user kind |
| Claims mapper | `WithClaimsMapper(provider, fn)` | `FromIssuer`, `FromIntrospection` | — | `fn(ctx, claims) (MappedCaller, error)`, where `MappedCaller{Principal *identity.Principal; External bool}`; an error is a dependency failure; a nil principal refuses; the zero value means a local user (fail closed); `provider` names the evidence |
| Local user | `WithLocalUsers(users)` | `FromProvider` only | `FromProvider`, with `op.UserLoader()` | the user loaded by `sub`; must exist, be active, and be that user |
| Linked user | `WithLinkedUsers(links, provider, users)` | `FromIssuer`, `FromIntrospection` | — | the user found by `links.FindByExternal(provider, issuer, sub)`, with the source's configured issuer; unlinked is refused; must exist and be active |

- **No raw external subject:** an external token's `sub` is never used as a local user identifier
  (user decision, 2026-11-25). A claims-only caller's identifier is `<issuer>#<sub>`, so neither the MFA
  requirement lookup, the enrolment lookup, security events nor a consumer's ownership check can
  mistake it for a local user. A mapper's caller is a local user unless
  it sets `External: true`, so a mapper that forgets the flag is judged by the MFA requirement (through
  the federated-assurance mode, under the mapper's provider name) rather than let through.
- **Issuer syntax:** a `FromIssuer` or `FromIntrospection` issuer must be an https URL with no query
  and no fragment (RFC 8414 §2), so `<issuer>#<sub>` cannot be ambiguous.
- **Kind of a claims-only caller:** always the user kind. Whether a token has an end user cannot be
  told reliably across issuers (a client-credentials `sub` is often the client id); a mapper that knows
  returns a service principal. Claims-only callers are not judged by the MFA requirement either way.
- **Every refusal of the caller is `invalid_token`:** an unlinked subject, a missing or inactive user,
  and a mapper returning nil. The resource server judges whether this token is good for this API. Two issuers, or an issuer and the local store, can share subject
  values. That would let issuer A's `sub` 42 act as local user 42, or pass an ownership check on user
  42's records.
- **No mapper on `FromProvider`:** provider tokens publish no claims map (decision 13).
- **Scopes always come from the token.** They are read from `scope` (space-separated), or else from
  `scp` (string or array). A mapper cannot widen them.
- **Role grants:** the principal's role grants follow the settled rules for the active role and the
  request's privilege memo, exactly as for a session principal, because the same loader and
  authorizer are used.

### 9. MFA assurance (user decisions, 2026-11-25)

| Kind | Channel | Exempt | How it meets an MFA requirement, re-judged every request |
|---|---|---|---|
| `access-token` | none | no | The grant records that the library verified a second factor at its sign-in; or, for a grant from a federated sign-in, the federated evidence the grant recorded is met under the federated-assurance mode, re-matched now |
| `external-access-token` | `federated` | no | The federated-assurance mode, from the token's verified `amr`/`acr` |

- **Why a marker, not `amr`:** a grant's `amr` comes from the sign-in assurance mapping, which a
  consumer can replace, and for an OIDC sign-in it copies the upstream's assertion. **REPRODUCED** by
  the review of 2026-11-25 in a disposable copy: `TestGrantAMR_MFAWithoutLibraryVerifiedSecondFactor`,
  run with `go test -count=1 -run TestGrantAMR_MFAWithoutLibraryVerifiedSecondFactor ./httpsec/`,
  failed with `grant amr [mfa] asserts mfa although the library verified no second factor (session
  MFA=none)`. It becomes the first red test of task 4.4.
- **Where the facts live:** grants are made at **exchange**, from the sign-in a resume recorded
  (`newGrant`, `newDeviceGrant` in `oidcprovider/exchange.go`, and the refresh rebuild), and that
  sign-in passes through pending requests, browser sessions, codes and device authorizations first. So
  `oidcprovider.SignIn` gains `SecondFactorVerified`, `ExternalProvider`, `ExternalAMR` and
  `ExternalACR` (`ExternalIssuer` already exists). They are set in `oidcSignInOf`
  (`httpsec/oidc_resume.go`) from the session only (`s.MFA == MFASatisfied`, the session's federated
  record), never from the consumer's mapping. They are copied by every exchange and refresh into the
  grant (`oidc-provider-tokens` delta).

  Re-matching the stored evidence means tightening assurance takes effect for provider tokens as it
  does for sessions. An exempt federated sign-in stays exempt, so such a user is never refused forever.
- **Storage:** every durable record that carries a sign-in keeps them (`security-state-stores` delta).
  That means new columns on `scrty_op_grants`, `scrty_op_authorization_codes` and
  `scrty_op_browser_sessions`, plus fields in the jsonb sign-in documents of pending requests and
  device authorizations, through **a new migration**. It goes after
  `fold-migrations-callback-server-error`'s new security-state baseline
  (`20261126000000_security_state.sql`), is written only after that change merges, and carries a
  populated-upgrade test as `schema-migrations` requires. A grant from
  before the upgrade has no marker and no evidence, so a required user is refused until a new sign-in.
  That is the fail-closed reading, stated in the CHANGELOG.
- **Policy input:** `policy.Input` gains `AccessTokenAssurance`, a type with no public constructor
  that only the resource server mints. It holds whether the caller names a local user and the grant's
  second-factor marker. Its zero value means "a local user, no second factor", so a consumer calling the
  policy directly fails closed. Federated evidence has one home: the input's existing
  `FederatedAssurance`, which the resource server fills (from the grant's or the token's evidence).
- **The policy:** the settled "A required user is challenged or refused, never let through" is
  MODIFIED. Met: allow. Unmet: deny with the insufficient-user-authentication reason, in both challenge
  and refuse mode. Exempt mode, or the policy's `WithMFAExemption` rule for the federated kind, applies
  to external tokens and to provider tokens from federated grants exactly as to that sign-in's session.
  Only this deny reason is answered as `ErrInsufficientUserAuthentication` (401, the RFC 9470 challenge,
  no `max_age`). A failing requirement lookup or assurance source is a dependency failure (500), never
  a 401 that would send the client round a sign-in loop.
- **No local user, no requirement:** a caller naming no local user (claims only, or a mapper declaring
  `External: true`) is allowed by the requirement before any lookup.
- **Linked or mapped users need the policy's assurance source:** the requirement policy decides
  assurance only through its own source (`policy.WithFederatedAssuranceSource`). A chain whose policy
  judges external tokens (`NeedsFederatedAssuranceSource()` true, extended to the
  `external-access-token` kind) fails construction when a source uses `WithLinkedUsers` or
  `WithClaimsMapper` and that source is missing. Exempt mode, or an exemption rule that exempts `oidc`
  (which `NeedsFederatedAssuranceSource` already consults, and which also exempts these callers), needs
  none. The shipped `oidc.RelyingParty` source answers only for providers registered for OIDC login
  whose issuer matches (`authenticate/oidc/assurance.go`), so an API-only chain supplies its own; the
  godoc says so. There is no per-source assurance option.
- **Every per-request challenge** raised for an access-token caller, by the library's policy or a
  consumer's, is refused with `ErrInsufficientUserAuthentication`, because no session can hold it.
  Consumer per-request policies may now receive a request with no session; their godoc says so.
- **Evidence:** the resource server mints the federated evidence from a verified external token: the
  provider name (`WithLinkedUsers`'s, or the mapper's), the source's configured issuer, `amr`, `acr`.
  It also fills the evidence from a provider grant that recorded it. The security-policy delta adds
  both to the places allowed to mint evidence.
- **Enrolment:** the settled allowlist requirement is MODIFIED. Listing either access-token kind is a
  construction error, as for `api-key` and `basic`.

### 10. Revocation per source (user decision, 2026-11-25)

- **`FromProvider`:** immediate. The grant is read on every request.
- **`FromIssuer`:** valid until `exp` (RFC 9068), stated on the option. `WithJWTIntrospection(cfg)`
  introspects each verified JWT, and an inactive answer refuses it.
- **`FromIntrospection`:** active state on every request. The optional cache is bounded (decision 12).

### 11. The remote key set

- **Where it lives:** the cache moves to `internal/keyset`, keyed by an opaque source name, not by the
  issuer. Two consumers with the same issuer and different algorithm lists do not share an entry.
- **This is a refactor:** behavioural tests are **copied** into the new package, and the
  `authenticate/oidc` suite stays byte-identical and green.
- **Discovery:**
  - OpenID Discovery first (`/.well-known/openid-configuration` appended to the issuer), then
    RFC 8414 (`/.well-known/oauth-authorization-server` inserted before the issuer's path).
  - The fallback is taken only on a 404.
  - The metadata's `issuer` must equal the configured issuer (RFC 8414 §3.3, OIDC Discovery §4.3).
  - A discovered `jwks_uri` must be on the issuer's origin.
- **Pinned URL:** `WithJWKSURL(u)` skips discovery, and may name another origin, over https.
- **Outbound client:** `WithOutboundClient(c)` replaces it, for a proxy or custom CAs.
- **Algorithms:** `WithAlgorithms(...)`, default `RS256` and `ES256`. `none` and HS\* are refused at
  construction and at verification. Header `jku`/`jwk`/`x5u` are ignored, and so are keys with
  `use: enc`.
- **No key identifier:** a token with no `kid` is verified only when the key set holds exactly one
  signing key.
- **Clock skew:** `WithClockSkew`, default 0, bounded at 5 minutes. This departs deliberately from
  `authenticate/oidc`'s 60-second ID-token default, because an access token is checked on every
  request, not once at sign-in.

### 12. Introspection

- **Endpoint:** `FromIntrospection(issuer, endpoint, clientID, opts...)` posts `token` and
  `token_type_hint=access_token` through `outbound`. It is built with the issuer it trusts. An answer
  naming another `iss` is refused. The configured issuer keys identity links and assurance evidence,
  so one endpoint fronting several issuers cannot blur them.
- **Source audience:** `WithSourceAudience` applies as for `FromIssuer`, and may not equal the
  configured issuer.
- **Client authentication:** `WithIntrospectionSecret` (`client_secret_basic`, the default) or
  `WithIntrospectionKey` (`private_key_jwt`).
- **Acceptance:** `active: true`, a `token_type` that is absent or names an access token
  (`access_token`, `Bearer`, `DPoP`), an audience naming the resource, a non-empty `sub`, and an `exp`
  in the future. RFC 7662 §2.1 obliges the server to search every token type, so a refresh token can
  come back active.
- **Cache:** `WithIntrospectionCache(maxAge, maxEntries)`, off by default.
  - It is held per source, keyed by the SHA-256 of the token.
  - An answer is never kept past its token's `exp`, and an answer with no `exp` is not cached.
  - Concurrent requests for one token share one call (singleflight).
- **Other credentials:** with any other mode reading the `Bearer` scheme (`EnableSessionBearer`, or
  API keys under that scheme), `WithOpaquePrefix` is required, so neither a session reference nor an
  API key is ever sent to a third party.
- **Throttle:** verification refusals are counted per client address and source. Those are a bad
  signature, type, audience or claim, expiry, and an inactive or unknown token. Binding and nonce
  answers, MFA denies, off-prefix refusals and dependency failures are not counted: ordinary DPoP
  clients answer a nonce challenge on every first request.
  - The count goes through the chain's limiter factory, under the namespace `resource-server`, with
    the chain's IPv6 aggregate.
  - A throttled address is refused with `ErrInvalidToken`, which maps to 401 as the settled table's
    "throttled source" does, before any verification, fetch or call.
  - `WithRefusalLimiter(ratelimit.Limiter)` replaces the limiter, like every other `With*Limiter`; a nil
    limiter fails construction. A failing limiter is a dependency failure.
  - The default follows the API-key limiter's defaults.
  - **Accepted:** clients sharing one address behind a gateway or NAT share the budget, so one
    attacker can make valid tokens from that address be refused until the window passes. This is the
    settled API-key trade-off, and a consumer with such clients raises the limit or keys by a trusted
    proxy's client address.
  - An unattributable request is refused, as for API keys.
- **The provider's own introspection answer** gains `auth_time`, `acr` and `amr`, as RFC 9470 §6.2
  expects. A `FromIntrospection` source pointed at a scrty provider can then serve recency guards.

### 13. What is published

- **Caller:** `WithCaller` with:
  - the strategy's principal, with `Scopes` set from the token;
  - credentials of kind `factor.AccessToken` (provider) or `factor.ExternalAccessToken`;
  - no session.
- **Token:** `httpsec.AccessTokenFromContext(ctx) (*AccessToken, bool)` returns a deep copy, holding:
  - `Resource`, `Issuer`, `Subject`, `ClientID`;
  - `Audience`, `Scopes`;
  - `IssuedAt`, `ExpiresAt`, `AuthTime`;
  - `ACR`, `AMR`, `Confirmation`;
  - `Claims`, which is empty for provider tokens.
- **Provider side:** `oidcprovider.AccessToken` gains `AuthTime`, `ACR` and `AMR`, from the JWT or from
  the grant. `(*Provider).UserLoader()` exposes its loader.
- **Policy:** the per-request policy phase runs, with no session and MFA assurance included
  (decision 9). Any challenge it raises is refused (decision 9).
- **Events:** a refused token emits a new `scrty_` access-token refusal event, naming the resource
  identifier and the source. A throttle emits `excess_rate_limit_exceeded`. DPoP and binding refusals
  keep their events. An event carries a user reference only for a local user; a claims-only caller's
  external subject is never put in its place (`security-events` delta).

### 14. Challenges

| Refusal | Status | Challenge |
|---|---|---|
| `ErrInvalidToken` (wraps `authenticate.ErrAuthenticationFailed`) | 401 | `error="invalid_token"` |
| Binding failures | as settled | as settled |
| `authorize.MissingScopesError` (an access-token caller) | 403 | `error="insufficient_scope", scope="…"` |
| `ErrInsufficientUserAuthentication` (an access-token caller at a recency guard, or with an unmet MFA requirement; wraps `ErrReauthenticationRequired`, carries the window when one applies) | 401 | `error="insufficient_user_authentication"`, with `max_age=<s>` when a window applies |

- **Who writes them:** `bearerChallenge` is extended. The resource server counts as a built-in bearer,
  so an API-only chain gets challenges and may use `WithoutBearerChallenge`. No second challenge
  interceptor is added, and `challengeWatch` keeps it to one challenge per response.
- **Scheme:** `DPoP` with `algs` when the token came under `DPoP` or its source requires DPoP binding;
  `Bearer` otherwise (certificate-bound sources included, as RFC 8705 uses `Bearer`). A resource
  server's refusal carries that one challenge alone, even with DPoP optional. Other 401s keep the
  settled "one of each".
- **`bearerChallenge` answers 403 too:** it writes `insufficient_scope` on a 403 for an access-token
  caller, where today it returns early unless the status is 401.
- **Problem details:** the `problem-details-rendering` delta adds the types `invalid-token`,
  `insufficient-user-authentication` (with `max_age`), `insufficient-scope` (with `scope`) and
  `account-inactive`. `reauthentication-required` is narrowed to session callers.
- **The status table** gains rows for the invalid-token and insufficient-user-authentication
  refusals. The second is judged before the reauthentication-required row (403), so that row keeps
  meaning "a session caller".
- **The stable-contract list** names both, and the inactive-account refusal.
- **`MissingScopesError{Scopes []string, All bool}`** matches `ErrAccessDenied` and `ErrNotGranted`.
  - It is renamed from `ScopeError`, which would collide with `identity.Scope`.
  - A composite requirement wraps the refusing requirement's error, so `errors.As` finds the first
    one, and that one names the challenge's `scope`.
- **Guards:** `internal/guardauth` gains the access-token time source and the error choice. The gin and
  fiber guards build their own time source and return `ReauthenticationRequiredError` themselves
  (`ginsec/guards.go`, `fibersec/guards.go`), so they are changed to take both from `guardauth`, and
  all three adapters behave alike.
- **`AnyOf` keeps the members' errors:** today `AnyOf` returns a fresh error, which loses
  `MissingScopesError`. It is changed to wrap its members' refusals.

### 15. Session-only endpoints refuse access-token callers

- **Which:**
  - password change;
  - passkey registration and management;
  - second-factor enrolment, method listing and verification;
  - saved-code regeneration;
  - re-authentication;
  - session renewal and management;
  - the provider's resume and consent endpoints;
  - `SwitchActiveRole`;
  - logout.
- **The answer:** `ErrAuthenticationRequired` before any work.
- **The session-signal stream keeps its settled answer** (403 for a request without a sign-in,
  `signals.go`), so the settled session-signals spec is untouched.
- **Most of the others already refuse,** because an access-token caller publishes no session. Their tests are
  **characterization tests**: each is shown to fail once by temporarily publishing a fake session (the
  inverted-implementation check of `golang-tdd.md`). That pins the refusal against a future change.
- **Logout is the real change** (user decision, 2026-11-25, standards-based).
  - The settled spec answers any session-less caller 200 and deletes nothing.
  - For an access-token caller that would tell the client "signed out" while its grant stays live.
  - Ending an access token's use is what token revocation (RFC 7009) and the provider's end-session
    endpoint (OpenID Connect RP-Initiated Logout) are for.
  - So logout refuses an access-token caller visibly, and its godoc names those two endpoints.
  - API-key callers keep their settled 200.

### 16. Recency guards and access tokens (user decision, 2026-11-25)

- **The time:** for an access-token caller, the default time source is the token's `AuthTime`. A token
  without one is refused.
- **The refusal:** `ErrInsufficientUserAuthentication`, which carries the window and is also
  identifiable as `ErrReauthenticationRequired`, so existing `errors.Is` handling keeps matching. It
  is answered 401 with `max_age` (RFC 9470).
- **Session callers** keep the session's time and today's 403.
- **Override:** `WithAuthenticationTime` still replaces the time source.
- **BREAKING (behaviour):** an access-token caller was refused before; a fresh one now passes.

### 17. Scopes on user principals

`Principal.Scopes` now also carries an access token's scopes on a user principal. A session principal
carries none. This departs from the established design, which keeps scopes on service principals
only.

### 18. Password policy: consumer rules

- **API:** `password.WithRule(name Rule, check RuleFunc) PolicyOption`, where
  `RuleFunc func(ctx, candidate string, user *identity.Details) (bool, error)`.
- **Order:** consumer rules run after the length check and the common and context lists, and before
  the breach lookup, because they are cheap local checks that should not spend a network call.
- **Refusal:** `RejectedError{Rule: name}`, a password-rejected error but not a reused one. The
  consumer can then tell "weak" from "reused".
- **Failure:** an error from a rule fails closed, behind fixed text, with the error reachable.
- **Default:** no consumer rule. The library imposes no composition rule (NIST SP 800-63B, which
  advises verifiers against composition rules).
- **Construction errors:** a nil, typed-nil or unnamed rule; a name over 64 characters or holding
  anything but letters, digits, `-` and `_` (it reaches error text and the problem's `rule` member); a
  built-in name; or a duplicate.

### 19. Inactive accounts in the password provider

`authenticate.ErrAccountInactive` is joined beneath the uniform failure by the password provider, and
only after the password verifies. An unknown user, a wrong password, and a wrong password on an
inactive account carry no distinguishing error, and cost the same work.

### 20. Inactive-account disclosure (departure from the established design)

- **The option:** `httpsec.WithInactiveDisclosure()` answers the refusal alone, as 403.
- **Scope:** it applies exactly where lock disclosure applies: form login and HTTP Basic. A disclosed
  Basic refusal carries no challenge.
- **Default:** concealed, in status, headers, problem type (prblmsec) and timing.
- **Why:** it mirrors `WithLockDisclosure`, and discloses nothing beyond "this password is right". The
  consumer's sign-in page needs a stable reason.
- **Why 403:** the caller is identified and refused. 401 would invite a retry with the same
  credentials.
- **BREAKING (behaviour):** `errors.Is(err, authenticate.ErrAccountInactive)` newly holds beneath the
  uniform failure.

## Failure modes

| # | Failure | State | What the caller sees |
|---|---|---|---|
| F1 | Empty, scheme-only or duplicated `Authorization` | Handled (the shared header reader), tested | 400 `invalid_request`, or not claimed |
| F2 | Token over 8 KiB; header or payload not base64url or not JSON | Handled before decoding, tested; routing read fuzzed | 401 `invalid_token`, or not recognised |
| F3 | ID, session or logout token sent to an API route | Handled by type routing, required claims and `aud`, tested | Session token: judged by the session modes; others: 401 |
| F4 | Untyped token without the opt-in; a session generator typed like an access token | Handled at verification and at construction, tested | 401; construction error |
| F5 | Unknown issuer on an `at+jwt`; metadata naming another issuer; discovered `jwks_uri` off-origin | Handled, tested | 401; dependency failure |
| F6 | `alg: none`, HS\*, an algorithm outside the list, an embedded key (`jwk`/`jku`/`x5u`) | Handled, tested | 401 |
| F7 | Expired token, including exactly at `exp`; clock skew | Handled (skew 0 by default, at most 5 min), tested | 401 |
| F8 | Audience missing, another API's, issuer-only, or a source audience equal to its issuer | Handled at verification and construction, tested | 401; construction error |
| F9 | External JWT missing a required claim or with an empty `sub` | Handled, tested | 401 |
| F10 | Unbound token under the default; opt-out on a chain that requires DPoP | Handled, tested | 401; construction error |
| F11 | Bound token under `Bearer`; bad, stale, wrong-key or replayed proof; missing nonce; wrong certificate | Handled with the settled refusals, tested | 401 `invalid_dpop_proof`, `use_dpop_nonce` with `DPoP-Nonce`, or the certificate-binding refusal |
| F12 | Two requests race the same proof `jti` | Handled by the shared replay store's atomic record, tested | One accepted, one `invalid_dpop_proof` |
| F13 | Provider grant revoked, expired, or naming another client or user | Handled, tested | 401 |
| F14 | Provider store, key set, metadata, introspection endpoint, user loader, link store, mapper, MFA requirement lookup, assurance source or refusal limiter down or slow | Handled: a dependency failure with fixed text, never retried in the request, bounded by `outbound`'s timeout. Tested | 500 by default, never 401 |
| F15 | Unknown-`kid` flood | Handled: one refetch per cooldown, singleflight. Tested | 401; at most one fetch |
| F16 | Refused-token flood (bogus opaque tokens forcing introspection) | Handled: verification refusals throttled per address and source before any fetch or call, limiter replaceable. Tested | 401 `invalid_token` |
| F17 | Introspection answers a refresh token as active; no `aud`, `sub` or `exp` | Handled, tested | 401 |
| F18 | Introspection cache: kept past revocation; unbounded growth; raw token in memory | Bounded by age, entries and `exp`; keyed by digest; off by default. Stale-within-bound **accepted** | Accepted until the bound |
| F19 | Offline JWT revoked at its issuer | **Accepted** (decision 10), documented | Accepted until `exp` |
| F20 | Session reference sent to a third-party introspection endpoint | Handled at construction (decision 12), tested | Construction error |
| F21 | External `sub` colliding with a local user identifier or another issuer's subject | Handled: no raw-subject strategy; linked users keyed by provider, issuer and subject. Tested | Unlinked: 401 |
| F22 | Local or linked user missing, inactive, or loader answering for another user | Handled, tested | 401; proof not consumed |
| F23 | Loader or link-store outage | Handled, tested | Dependency failure; proof not consumed |
| F24 | Claims mapper errors, returns nil, or tries to widen scopes | Handled: fails closed; scopes always the token's. Tested. A panic propagates (**accepted**, like any consumer port) | Dependency failure / 401 |
| F25 | Role removed after the token was issued | Handled under local and linked users, tested; **accepted** under claims strategies, where the claims are the issuer's statement | Current roles / token roles |
| F26 | Required-MFA user with a password-only external token, or a provider token whose grant has no second factor (including a user made MFA-required mid-grant) | Handled (decision 9), re-judged every request, tested | 401 `insufficient_user_authentication` |
| F27 | Access token at a session-only endpoint, or at logout | Handled, tested (characterization, plus logout's real red) | 401 auth-required; nothing changed |
| F28 | Stale or `auth_time`-less token at a recency guard, on any adapter | Handled, tested on net/http, gin and fiber | 401 `insufficient_user_authentication` |
| F29 | Missing scope at a rule or guard, including inside a composite | Handled, tested | 403 `insufficient_scope` |
| F30 | Two challenge writers on one refusal | Handled: one writer (`bearerChallenge`) and `challengeWatch`. Tested | Exactly one `WWW-Authenticate` |
| F31 | Wiring mistakes (spec "Resource-server wiring mistakes" and "Source wiring mistakes") | Handled, tested | Construction error |
| F32 | Token, secret, key or introspection body in a log, error or event | Handled; fixed reasons only. Tested | — |
| F33 | Handler mutates the published token | Handled; copies on read. Tested | — |
| F34 | Caller cancels during verification or a fetch | Handled, tested | The context's error; no ERROR record |
| F35 | Multi-replica deployment with the in-memory replay store | **Accepted** (settled DPoP behaviour), documented | A proof can be replayed once per replica |
| F36 | Chain clock and provider clock disagree | **Accepted**, documented: wire one clock to both | Expiry and proof age judged on different clocks |
| F37 | Password consumer rule errors or is typed-nil | Error: handled, fails closed, tested. Typed-nil: a construction error | As stated |
| F38 | Inactive check before the password verifies; inactive state leaking through a problem type or log under concealment | Handled, tested (form, Basic, prblmsec) | Uniform 401 |
| F39 | Client-credentials (machine) token under "MFA required for all" | Handled: callers naming no local user are not judged by the requirement (decision 9), tested | Allowed by that policy |
| F40 | API key or session reference sent to a third-party introspection endpoint | Handled at construction (decision 12), tested | Construction error |
| F41 | Throttle shared by clients behind one address | **Accepted** (decision 12), as for API keys; the limit is configurable | Valid tokens from that address refused until the window passes |
| F42 | A grant whose `amr` claims `mfa` with no library-verified second factor (a consumer mapping, an upstream assertion) | Handled: the grant's library marker and re-matched federated evidence decide, never `amr` (decision 9). Tested | 401 `insufficient_user_authentication` when unmet |
| F43 | A grant, code or browser session from before the upgrade (no marker, no evidence) | **Accepted**, fail closed: a required user is refused until a new sign-in. Stated in the CHANGELOG | 401 `insufficient_user_authentication` |
| F44 | A consumer or library per-request policy challenges an access-token caller | Handled: refused, nothing marked on any session (decision 9). Tested | 401 `insufficient_user_authentication` |
| F45 | Linked or mapped users with no policy assurance source on a chain whose policy judges external tokens | Handled at construction (decision 9). Tested | Construction error |
| F46 | The provider's own `at.`/`rt.` token sent to a partner introspection source | Handled: never routed there (decision 5). Tested | 401 `invalid_token`; nothing sent |
| F47 | Issuer with a query or fragment making `<issuer>#<sub>` ambiguous | Handled at construction (decision 8). Tested | Construction error |
| F48 | Unknown confirmation method under `WithUnboundTokens` | Handled: refused, never treated as unbound (decision 7). Tested | 401 `invalid_token` |
| F49 | Issuer clock slightly ahead (`iat`/`nbf` in the near future) | Handled: 60-second leeway on `iat`/`nbf` (decision 6). Tested | Accepted |
| F50 | A claims-only or external-declared caller's subject leaking into events as a user reference | Handled: no user reference for callers naming no local user (decision 13). Tested | — |
| F51 | A mapper forgets to say whether its caller is local | Handled: the zero value is a local user, judged (decision 8). Tested | Judged by the MFA requirement |
| F52 | An unprefixed opaque token on a path no resource server covers | Handled: passes on to the next mode (decision 5). Tested | Judged by that mode |

## Risks / Trade-offs

- [The routing read parses hostile input] → The whole token is bounded, nothing is granted on the
  read, and the read is fuzzed.
- [Extracting the key-set cache could change `authenticate/oidc`] → Tests are copied, not moved; the
  oidc suite stays byte-identical; the dispatch runs on Opus.
- [Behaviour changes: recency for access tokens, logout for access tokens, `ErrAccountInactive`] → Each
  is recorded under *Changed*. Only access-token callers, a new caller kind, see the first two.
- [Path prefixes inside a credential mode overlap with route rules] → Prefixes only choose which API a
  token is for. Who may call what stays with `EnableAuthorization` and guards.
- [A large change in one release] → It is split into lanes and sequential dispatches in `plans.md`,
  each reviewed before the next.
- [Three v0.6.0 changes edit `CHANGELOG.md`] → This change merges last; it hand-merges its entries into
  one *Added* and one *Changed*.

## Migration Plan

- Additive for consumers who enable nothing new, apart from these entries under *Changed* for v0.6.0:
  - **BREAKING (behaviour):** a recency guard accepts a fresh access token (it refused every one);
  - **BREAKING (behaviour):** logout refuses an access-token caller on a covered path;
  - **BREAKING (behaviour):** `ErrAccountInactive` is identifiable beneath the uniform failure after a
    correct password;
  - grants, codes and browser sessions from before the upgrade carry no second-factor marker, so an
    MFA-required user signs in again once (F43);
  - a consumer's per-request policy may now receive a request with no session.
- **A scrty provider in another binary** is trusted through `FromIssuer` (JWKS) or `FromIntrospection`,
  like any issuer. `FromProvider` takes only the chain's own provider (user decision, 2026-11-25).
- **crm-api:**
  1. Set `DefaultAudience: []string{"urn:kartala:hris:api"}` on its client.
  2. Enable DPoP with its public host. This is already required to verify nextgen's bound tokens, and
     without it `EnableResourceServer` fails construction.
  3. Add `httpsec.EnableResourceServer("urn:kartala:hris:api", httpsec.FromProvider(op))`.
  4. Expect tokens issued before step 1 (audience = issuer only) to be refused until nextgen refreshes
     them, within 5 minutes by default.
  5. Sign out a token-holding client through revocation and end-session.
- **Grants:** v0.6.0 adds grant columns through a new migration after the folded security-state
  baseline. Grants made before the upgrade carry no second-factor marker, so an MFA-required user
  signs in again once (F43).
- **Rollback:** downgrade, as the folded baseline of `fold-migrations-callback-server-error` allows:
  recreate the database rather than run v0.5.0 migrations on it.

## Open Questions

None that change the specs. Bounds within stated limits are tuned during implementation: the default
throttle, and the cache's default entry limit when enabled.

## References

**Researched** (consulted 2026-11-24 and 2026-11-25 by the research for this change; figures drift):
- **Decisions 1, 2, 4, 5** (one mode with sources; routing by issuer):
  - [Spring Security: JWT resource server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html).
  - [Spring Security: multitenancy](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html):
    choosing and allow-listing issuers.
  - [ASP.NET Core: policy schemes](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/policyschemes).
- **Decisions 10, 12:**
  - [Spring Security: opaque token](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/opaque-token.html).
  - [zitadel/oidc rs](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rs).
- **Decision 11:**
  - [lestrrat-go/jwx jwk.Cache](https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/jwk).
  - [auth0 go-jwt-middleware jwks](https://pkg.go.dev/github.com/auth0/go-jwt-middleware/v2/jwks).
  - [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc).
- **Decision 7:**
  - [Spring Security: DPoP-bound tokens](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html).
- **User decisions** of 2026-11-25: decisions 1, 2, 7, 8, 9 (provider tokens re-judged by the library's
  grant marker or re-matched federated evidence, external tokens by federated assurance), 10 and 16, `FromProvider` limited to the chain's own
  provider, and the choice in decision 15 to follow the standards.
- **Reasoned from scrty's own settled specs and code, and the established design:** decisions 13, 14,
  15, 17, 19 and 20, drawing on `http-error-propagation`, `sender-constrained-tokens`,
  `reauthentication`, `framework-adapters`, `identity-linking`, `security-policy`, `password-policy`
  and `authentication`.
- **Unverified:** vendor specifics, namely Keycloak's `typ` claim, Keycloak and Zitadel audience
  values, and `scp` as a string at some issuers. They are used only as examples of why an option
  exists.

**Primary documentation** (relied on and cited as such, not re-checked on these dates):
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): §2.1 `at+jwt`; §2.2 required claims; §4 audience
  validation. Decisions 3, 5, 6, 10.
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750): §3.1 `invalid_token`, `insufficient_scope`.
  Decision 14.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): §4.3 proof checks; §7.1 and §7.2 resource-server
  checks and the Bearer downgrade; §9 nonces. Decision 7.
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705): §3 certificate-bound tokens. Decision 7.
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662): §2.1 search across token types; §2.2 response
  members; §4 caching against revocation. Decisions 10, 12.
- [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009): token revocation. Decision 15.
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html):
  ending the provider sign-in. Decision 15.
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707): resource indicators. Decision 3.
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725): §2.8, §3.11 and §3.12 explicit typing.
  Decisions 5, 6.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700): §2.3 audience restriction; §2.2.1
  sender-constraining. Decisions 3, 7.
- [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470): §3 `insufficient_user_authentication` and
  `max_age`; §6.2 introspection members. Decisions 9, 12, 16.
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) §3, §3.3, and
  [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) §4.3:
  metadata location and issuer equality. Decision 11.
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html), the current revision: password
  verifiers impose no composition rules. Decision 18.
