# Design

## Context

See proposal.md for the motivation. On `main` after v0.5.0:

- **Credential modes.** Each is its own `Enable*` in a fixed order slot (`httpsec/chain.go:836-921`):
  - Basic (400), API key (450), mTLS reserved (475);
  - `EnableBearerToken` (500, session tokens: `jti` is a session id);
  - `EnableSessionBearer` (session references);
  - authorization at 900.

  A mode claims the credentials it recognises and hands on the rest. A custom authenticator uses
  `RegisterInterceptor` and publishes its caller with `WithCaller`.
- **Provider access tokens.** `Provider.VerifyAccessToken` (`oidcprovider/accesstoken.go:269`)
  reads JWT and opaque tokens, and checks the grant on every call (`requireGrantHolds`). It does
  not check the audience or the binding.
  - Its `AccessToken` carries no authentication time, although the JWT has `auth_time` and the
    grant holds it.
  - Only UserInfo uses it (`httpsec/oidc_userinfo.go:95-140`). UserInfo's binding check, `holdToKey`,
    is unexported.
- **Remote keys.** `authenticate/oidc/remote.go` holds a discovery and key-set cache: TTL, backoff
  after a failure, a cooldown on refetching an unknown `kid`, singleflight, and fetches through
  `outbound`. It is unexported.
- **Scopes.** `identity.Principal.Scopes` is documented as "service principals only".
  `authorize.HasAnyScope` and `HasAllScopes` refuse with `ErrAccessDenied`/`ErrNotGranted`, and
  report nothing about which scopes were missing.
- **Guards.** They (`httpsec/guards.go`, plus copies in `fibersec` and `ginsec`) judge the published
  principal. Recency guards read the session's authentication time and refuse a caller with no
  session (settled `reauthentication` spec).
- **The established design** has no resource-server mode, keeps scopes on service principals only,
  and always conceals inactive accounts. This change departs from it in decision 15, the inactive
  disclosure.

## Goals / Non-Goals

**Goals:**
- One generic resource-server capability for the chain's own provider and for any external issuer,
  usable alone or beside the chain's own sign-in.
- The session-token path (`EnableBearerToken`, `EnableSessionBearer`) is unchanged.
- Guards and chain rules work for access-token callers with no consumer code.

**Non-Goals:**
- Renaming `EnableBearerToken` or `EnableSessionBearer`, or restructuring how a chain is built
  (research options 5 and 6). These are separate decisions.
- A public port for consumer-written token sources (decision 4).
- Signing in the IdP's own browser with a cookie (the BFF part of `bff-resource-server`).
- Protected-resource metadata (RFC 9728) and token exchange (RFC 8693).
- Accepting a token from a form body or a query string.

## Decisions

### 1. `EnableResourceServer(resourceID, opts...)`, a credential mode in its own slot

```go
httpsec.EnableResourceServer("urn:example:orders:api",
    httpsec.WithPathPrefix("/api/orders/"),
    httpsec.FromProvider(op),
    httpsec.FromIssuer("https://sso.example.com/realms/main", httpsec.WithSourceAudience("orders-api")),
)
```

- **Name:** it is named for the OAuth role, and pairs with `EnableOIDCProvider`. The user chose it on
  2026-11-25 over `EnableOIDCAccessTokens` and `EnableAccessTokens`.
- **Slot:** `OrderResourceServer = 490`. That is after the provider's endpoints (250), which answer
  their own tokens, UserInfo included, and before the session-token bearer (500), so recognised
  access tokens are claimed first.
- **Options:** one variadic list. Sources (`FromProvider`, `FromIssuer`, `FromIntrospection`) and
  mode options (`WithPathPrefix`, `WithResourceAliases`) are all `ResourceServerOption`s. Per-source
  options go to the source constructor.
- **Alternatives considered:** the research options, in order of rejection:
  - **reusing the session bearer (on-hold option A):** it needs special cases inside the bearer, where
    a mistake can pass the tests and still be wrong;
  - **an option inside `EnableOIDCProvider` (option B):** it cannot serve an API without a provider;
  - **one mode per source (option 1):** several switches for one concept.
- **Default:** none, because the mode does nothing until enabled. **Override:** everything below is
  per mode or per source.

### 2. Several resource servers per chain, each scoped by path prefix (user decision, 2026-11-25)

- **The rules:**
  - Each mode covers the paths under its prefixes.
  - A mode with no prefix covers every path, and is allowed only when it is the only mode.
  - Overlapping prefixes are a construction error: equal, or one a prefix of another.
- **Matching:** prefixes match the request's escaped path, as the chain's other route matchers do.
- **A recognised access token on a path no mode covers is refused** with `invalid_token`. It is
  never handed on.
- **Why:** each API keeps its own audience, so a token for one API never works at another (the
  confused deputy).
- **The line:** nesting a narrower API under a broader one is refused for now. Refusing is the safe
  default, and allowing it later is not a breaking change.
- **Alternative considered:** a set of identifiers on one mode where any one matches. Rejected: it
  silently accepts any listed API's token on every route.

### 3. Resource identity: identifier, aliases, per-source audience

- **Identifier and aliases:**
  - Both use the provider's `validResource` rule: an absolute URI with no fragment.
  - An alias applies to every source. It exists for renaming an API while older tokens are still
    live.
  - Neither may equal the chain provider's issuer: every `openid` token names the issuer, so that
    would accept every UserInfo token.
- **Per-source audience:** `WithSourceAudience(aud)` is any non-empty text, for issuers that cannot
  emit the identifier (a Keycloak audience mapper value, a Zitadel project id). It applies to that
  source only.
- **The check:** the token's `aud` must contain the identifier, an alias, or that source's
  audience. An exact match, without normalisation (RFC 9068 §4).

### 4. Sources are a closed set

- **The set:** `FromProvider`, `FromIssuer` and `FromIntrospection` are the only sources. There is no
  public `TokenSource` interface in this change.
- **Why:**
  - Whether a token's revocation state was checked is a guarantee the library makes, and a
    consumer's source could claim it falsely.
  - The extension points consumers actually need are already the caller strategies (decision 8)
    and the claims they read.
- **The line:** a consumer who needs another token kind uses `RegisterInterceptor` and `WithCaller`,
  as today. A public source port can be added later without breaking anything.

### 5. Recognition and routing

- **The order** (the first rule that matches decides):
  1. an `at.` prefix goes to the `FromProvider` source;
  2. a JWT, read without verification and only to route it, goes to the source whose issuer equals
     its `iss`. Its header is bounded at 4 KiB, base64url without padding;
  3. an opaque token goes to the `FromIntrospection` source, when there is one. On a chain with
     session references, only a token with that source's prefix goes there (decision 11);
  4. anything else is not recognised, and passes to the next mode.
- **Never offered to a source:** a session token, typed `scrty+jwt` or whatever the chain's
  generators declare.
- **Nothing is granted on the unverified read.** The source verifies everything again.
- **A JWT naming no configured issuer** is not recognised, unless it is typed `at+jwt`. A typed access
  token with an unknown issuer is refused, because it was clearly meant for a resource server.
- **The same issuer in two sources** is a construction error.
- **`FromProvider` and `FromIssuer`** are told apart by issuer equality, which is checked at
  construction. An issuer source pointing at the chain's own provider is allowed only when no
  provider source exists.

### 6. Token type

- **Default:** `at+jwt` or `application/at+jwt`, without regard to case (RFC 9068 §2.1,
  RFC 8725 §3.11).
- **Override:** `WithUntypedTokens(claim, value)` per source accepts `typ: JWT`, or no `typ`, only when
  `claim` equals `value`. Keycloak's `typ` claim of `Bearer` is the example. Without a claim the
  option is a construction error, because otherwise the issuer's ID tokens would pass.

### 7. Binding: required by default, opt-out per source (user decision, 2026-11-25)

- **Default:** a token with no `cnf` is refused with `invalid_token`.
  - A `cnf.jkt` token needs a DPoP proof, checked in full by the chain's existing verifier
    (RFC 9449 §4.3 and §7.1).
  - A `cnf.x5t#S256` token needs the TLS client certificate (RFC 8705 §3).
  - A bound token under `Bearer` is refused (RFC 9449 §7.2).
- **Override:** `WithUnboundTokens()` on one source.
- **Shared code:** the provider's `holdToKey` moves from `oidc_userinfo.go` into a check that both
  UserInfo and the resource server call, with one replay store.
- **Wiring:** the construction check that DPoP needs a verifier of bound credentials now counts the
  resource server. A mode that requires binding on a chain with neither DPoP nor certificate binding
  fails construction.
- **Sign-in is unaffected:** the requirement never reaches an issuing endpoint or a session token.

### 8. Caller strategies (user decision, 2026-11-25)

| Strategy | Option | Default for | Caller |
|---|---|---|---|
| Claims only | `WithClaimsOnly()` | `FromIssuer`, `FromIntrospection` | subject = `sub`; scopes from `scope` (space-separated) or `scp` (array); no roles; user kind |
| Claims mapper | `WithClaimsMapper(fn)` | — | `fn(ctx, claims) (*identity.Principal, error)`. An error fails closed; a nil principal refuses |
| Local user | `WithLocalUsers(users)` | `FromProvider`, with the provider's own loader | the user loaded by `sub` must exist, be active and be that user; current roles |

- **One strategy per source.** Giving two is a construction error.
- **The provider's loader** is exposed as `(*oidcprovider.Provider).UserLoader()`.
- **Scopes** always come from the token, whatever the strategy, so scope rules mean the same
  everywhere.
- **A client-credentials token** (no user) is whatever the strategy makes of `sub`. The mapper is
  where a consumer turns it into a service principal.

### 9. Revocation per source (user decision, 2026-11-25)

- **`FromProvider`:** immediate. The grant is read on every request.
- **`FromIssuer`:** valid until `exp` (RFC 9068), documented on the option. `WithJWTIntrospection(cfg)`
  opts in to introspecting each verified JWT, and an inactive answer refuses it.
- **`FromIntrospection`:** active state on every request. `WithIntrospectionCache(max)` keeps an
  answer for at most `max`, and never beyond the token's `exp` (RFC 7662 §4).
- **Default cache:** off.

### 10. The remote key set

- **Where it lives:** `authenticate/oidc`'s discovery and key-set cache moves to an internal package
  shared by both users, keeping its behaviour:
  - TTL;
  - backoff after a failure;
  - one refetch per cooldown for an unknown `kid`;
  - singleflight;
  - fetches only through `outbound`, confined to the issuer's origin.
- **Algorithms:** pinned by the key. `none` and HS\* are refused.
- **Discovery:** `FromIssuer(issuer)` finds `jwks_uri` through
  `/.well-known/openid-configuration`, or OAuth server metadata (RFC 8414) as a fallback.
  `WithJWKSURL(u)` skips discovery.
- **Defaults:** those of `authenticate/oidc` (`DefaultDiscoveryTTL`, `DefaultJWKSRefetchCooldown`).
- **This is a refactor** that keeps existing behaviour. The `authenticate/oidc` suites run unchanged
  before and after.

### 11. Introspection

- **Endpoint:** `FromIntrospection(endpoint, clientID, opts...)` posts `token` and
  `token_type_hint=access_token` (RFC 7662 §2.1) through `outbound`.
- **Client authentication:** `client_secret_basic` by default (`WithIntrospectionSecret`), or
  `private_key_jwt` (`WithIntrospectionKey`).
- **Accepted:** only `active: true`, with `iss` and `aud` checked against the source, and with
  `cnf` taken from the response for the binding check.
- **Construction checks:** the endpoint must be https.
- **Session references:** on a chain with `EnableSessionBearer`, the source must be given a prefix
  (`WithOpaquePrefix`), so that a session reference is never sent to a third party. That is a
  construction error otherwise.

### 12. What is published

- **Caller:** `WithCaller` with `authenticate.Authentication`:
  - the principal from the strategy, with `Scopes` set;
  - credentials of kind `factor.AccessToken`;
  - no session.
- **Token:** `httpsec.AccessTokenFromContext(ctx) (*AccessToken, bool)` returns a deep copy. It holds
  `Resource` (the identifier that accepted it), `Issuer`, `Subject`, `ClientID`, `Audience`,
  `Scopes`, `IssuedAt`, `ExpiresAt`, `AuthTime`, `ACR`, `AMR`, `Confirmation` and `Claims`.
- **Policy:** the stateless per-request policy phase runs, as for an API key.
- **Provider side:** `oidcprovider.AccessToken` gains `AuthTime`, `ACR` and `AMR`, from the JWT's
  claims or, for an opaque token, from the grant.

### 13. Challenges

| Refusal | Status | Challenge |
|---|---|---|
| `ErrInvalidToken` (wraps `authenticate.ErrAuthenticationFailed`) | 401 | `error="invalid_token"` |
| A scope rule refused an access-token caller (`authorize.ScopeError`) | 403 | `error="insufficient_scope", scope="…"` (RFC 6750 §3.1) |
| A recency guard refused an access-token caller | 401 | `error="insufficient_user_authentication", max_age=<seconds>` (RFC 9470 §3) |

- **Scheme:** `DPoP` (with `algs`) when the token came under `DPoP` or the source requires binding;
  `Bearer` otherwise.
- **Without DPoP:** an always-registered fallback challenge interceptor writes the `Bearer` form,
  because `dpopChallenge` exists only when DPoP is on.
- **One challenge per response:** an "answered" mark prevents two.
- **Override:** a consumer's error handler can replace or remove the header, as for every challenge.
- **Guards** write the same challenges in `httpsec`, `fibersec` and `ginsec`.
- **`authorize.ScopeError{Scopes []string, All bool}`** matches `ErrAccessDenied` and
  `ErrNotGranted`. Existing `errors.Is` checks therefore keep matching.
- **Session and API-key callers** are answered as before.

### 14. Session-only endpoints refuse access-token callers

- **Which endpoints:**
  - password change;
  - passkey registration and management;
  - MFA enrolment and verification;
  - re-authentication;
  - session renewal and management;
  - logout.
- **The answer:** `ErrAuthenticationRequired` before any work, when the caller's credential kind is
  `access-token`.
- **No override:** these endpoints act on a sign-in session that an access token does not have. A
  client holding only an access token signs out through end-session and revocation instead.
- **This replaces** the on-hold design's single "renewal refusal" with one rule for every session
  endpoint.

### 15. Recency guards and access tokens (user decision, 2026-11-25)

- **The time:** for an access-token caller, the default time source is the token's `AuthTime`. A token
  without one is refused.
- **The refusal:** 401 with the RFC 9470 challenge, so the client can send the user back to
  `/authorize` with `max_age`.
- **Session callers** keep the session's time and today's 403.
- **Override:** `WithAuthenticationTime` still replaces the source for every caller.
- **BREAKING (behaviour):** an access-token caller was refused before; now a fresh one passes.

### 16. Scopes on user principals, and the `access-token` kind

- **Scopes:** `Principal.Scopes` now also carries an access token's scopes on a user principal. A
  session-authenticated principal carries none.
- **The kind:** `factor.AccessToken` has no channel and is exempt from an MFA requirement.
  - The request has no session on which an MFA challenge could be held.
  - The assurance of the sign-in behind the token is the issuer's.
  - A consumer who needs assurance checks `acr`/`amr` from `AccessTokenFromContext`, or derives it in a
    claims mapper.

### 17. Password policy: consumer rules

This is unchanged from the on-hold design's decision 11.
- **API:** `password.WithRule(name, RuleFunc)`.
- **Order:** consumer rules run after the lists and before the breach lookup.
- **Refusal:** `RejectedError{Rule: name}`.
- **Failure:** an error from a rule fails closed.
- **Default:** no rule. The library ships no composition rule (NIST SP 800-63B §5.1.1.2).

### 18. Inactive-account disclosure (departure from the established design)

This is unchanged from the on-hold design's decision 12.
- **Provider side:** the password provider joins `ErrAccountInactive` beneath the uniform failure, and
  only after the password verifies.
- **Chain side:** `WithInactiveDisclosure()` answers it alone, as 403. The default stays concealed.
- **Why:** it mirrors `WithLockDisclosure`, and discloses nothing more than "this password is right".
- **BREAKING (behaviour):** `errors.Is(err, authenticate.ErrAccountInactive)` newly holds.

## Failure modes

| # | Failure | State | What the caller sees |
|---|---|---|---|
| F1 | Empty, scheme-only, or duplicated `Authorization`; token both in the header and in the query | Handled (strict reader shared with UserInfo), tested | 400 `invalid_request`, or not claimed |
| F2 | JWT header oversized, not base64url, not JSON | Handled, tested; the routing peek is fuzzed | Not recognised, or 401 `invalid_token` when typed |
| F3 | ID token, session token, or logout token sent to an API route | Handled by type routing and `aud`, tested | Session token: judged by the session modes; others: 401 |
| F4 | `typ: JWT` access token without the opt-in | Handled, tested | 401 `invalid_token` |
| F5 | Unknown issuer on an `at+jwt` token | Handled, tested | 401 `invalid_token` |
| F6 | `alg: none`, an HS\* algorithm, a key the set does not hold | Handled, tested | 401 `invalid_token` |
| F7 | Expired token, including exactly at `exp`; clock skew | Handled. No skew for provider tokens; `WithClockSkew` per external source, default 0, bounded at 5 minutes. Tested | 401 `invalid_token` |
| F8 | Audience missing, another API's, or issuer-only | Handled, tested | 401 `invalid_token` |
| F9 | Unbound token under the default; bound token under `Bearer`; bad, stale, wrong-key or replayed proof | Handled by the shared binding check, tested | 401 `invalid_token` / `invalid_dpop_proof` |
| F10 | Two requests race the same proof `jti` | Handled by the replay store's atomic record, tested | One accepted, one `invalid_dpop_proof` |
| F11 | Provider grant revoked, expired, or naming another client or user | Handled, tested | 401 `invalid_token` |
| F12 | Provider store, key set, or introspection endpoint down or slow | Handled: a dependency failure with fixed text, never retried in the request, bounded by `outbound`'s timeout. Tested | 500 by default, never 401 |
| F13 | Key-set flood of unknown `kid`s | Handled: one refetch per cooldown, singleflight. Tested | 401 for unknown keys; at most one fetch |
| F14 | A discovery document pointing `jwks_uri` at another origin | Handled by `outbound` origin confinement, tested | Dependency failure; nothing fetched |
| F15 | Introspection answer cached past revocation | Accepted, bounded by `WithIntrospectionCache` and the token's `exp`; off by default | Accepted until the bound |
| F16 | Offline JWT revoked at its issuer | Accepted (decision 9), documented on `FromIssuer` | Accepted until `exp` |
| F17 | Session reference sent to a third-party introspection endpoint | Handled at construction (decision 11), tested | Construction error |
| F18 | Local user missing, inactive, or loader answering for another user | Handled, tested | 401 auth-required; proof not consumed |
| F19 | Loader outage | Handled, tested | Dependency failure; proof not consumed |
| F20 | Claims mapper errors or returns nil | Handled: fails closed, tested. A panic propagates like any consumer port (accepted) | Dependency failure / 401 |
| F21 | Role removed after the token was issued | Handled under local user, tested; accepted under claims strategies (the token's claims are the issuer's statement) | Current roles / token roles |
| F22 | Access token at a session-only endpoint | Handled, tested | 401 auth-required; nothing changed |
| F23 | Stale or `auth_time`-less token at a recency guard | Handled, tested | 401 `insufficient_user_authentication` |
| F24 | Missing scope at a rule or guard | Handled, tested | 403 `insufficient_scope` |
| F25 | Wiring mistakes, listed below | Handled, tested | Construction error |
| F26 | Token, secret or introspection body in a log, error or event | Handled; fixed reasons only. Tested | — |
| F27 | Handler mutates the published token | Handled; copies on read. Tested | — |
| F28 | Caller cancels during verification or a fetch | Handled, tested | The context's error; no ERROR record |
| F29 | Multi-replica deployment with the in-memory replay store | Accepted (settled DPoP behaviour), documented | A proof can be replayed once per replica |
| F30 | Chain clock and provider clock disagree | Accepted, documented: wire one clock to both | Expiry and proof age judged on different clocks |
| F31 | Password consumer rule errors or is typed-nil | Error: handled, fails closed, tested. Typed-nil: a construction error | As stated |
| F32 | Inactive check reached before the password verifies | Handled, tested | Wrong password stays uniform under disclosure |
| F33 | Two challenge writers on one refusal | Handled by the "answered" mark, tested | Exactly one `WWW-Authenticate` |

The wiring mistakes F25 covers:
- no source, or a nil source;
- an identifier or alias that is not a URI, or equals the issuer;
- overlapping prefixes, or an unscoped mode beside another;
- two sources for one issuer;
- binding required with no binding feature;
- two caller strategies on one source;
- an untyped opt-in with no claim;
- introspection beside session references with no prefix;
- an http introspection endpoint;
- a non-positive cache bound;
- a clock skew above the bound.

## Risks / Trade-offs

- [The routing peek parses hostile input] → It is bounded, it grants nothing, and the peek function is
  fuzzed.
- [Extracting the key-set cache could change `authenticate/oidc`] → The extraction is a refactor
  dispatch on Opus. The `authenticate/oidc` suites run unchanged before and after.
- [Recency and `ErrAccountInactive` change behaviour] → Both are recorded under *Changed*, and both
  only widen what a consumer can see or do.
- [Path prefixes inside a credential mode overlap with route rules] → Prefixes only decide which API
  a token is for. Who may call what stays with `EnableAuthorization` and the guards.
- [A large change in one release] → It is split into lanes and sequential dispatches in `plans.md`,
  each reviewed before the next.

## Migration Plan

- Additive for consumers who enable nothing new. The two behaviour changes are recorded in the
  CHANGELOG under *Changed* for v0.6.0.
- **crm-api:**
  1. set `DefaultAudience: []string{"urn:kartala:hris:api"}` on its client;
  2. add `httpsec.EnableResourceServer("urn:kartala:hris:api", httpsec.FromProvider(op))`;
  3. sign out a token-holding client through end-session and revocation.
- **Rollback:** downgrade. No stored data or migration changes.

## Open Questions

None that change the specs. Default values, such as the clock-skew bound and the routing peek's
size, can be tuned during implementation within the stated bounds.

## References

**Researched** (consulted 2026-11-24 and 2026-11-25 by the research for this change; figures
drift):
- **Decisions 1, 2, 4, 5** (one mode with sources; routing by issuer):
  - [Spring Security: JWT resource server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html):
    `oauth2ResourceServer().jwt()`, issuer-location decoders, scope authorities.
  - [Spring Security: multitenancy](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html):
    choosing the issuer from the token, and allow-listing issuers.
  - [ASP.NET Core: policy schemes](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/policyschemes):
    a forward selector choosing the scheme by `iss`.
- **Decision 9** (introspection, opaque tokens):
  - [Spring Security: opaque token](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/opaque-token.html).
  - [zitadel/oidc rs](https://pkg.go.dev/github.com/zitadel/oidc/v3/pkg/client/rs).
- **Decision 10** (key-set caching in Go practice):
  - [lestrrat-go/jwx jwk.Cache](https://pkg.go.dev/github.com/lestrrat-go/jwx/v3/jwk).
  - [auth0 go-jwt-middleware jwks](https://pkg.go.dev/github.com/auth0/go-jwt-middleware/v2/jwks).
  - [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc): its verifier targets ID
    tokens, not `at+jwt`.
- **Decision 7:**
  - [Spring Security: DPoP-bound tokens](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/dpop-tokens.html):
    the resource server checks `cnf.jkt` and `ath`.
- **Decisions 1, 2, 7, 8, 9, 15** came from the user's choices of 2026-11-25.
- **Decisions 12, 14, 16, 17, 18** are reasoned from scrty's own settled specs (`identity-model`,
  `sender-constrained-tokens`, `reauthentication`, `password-policy`, `authentication`) and the
  established design.

**Primary documentation** (relied on and cited as such, not re-checked on these dates):
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): `at+jwt`; the resource server validates the
  audience (§4). Decisions 3, 5, 6, 9.
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750): §3.1 `invalid_token`, `insufficient_scope`.
  Decision 13.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): DPoP. §4.3 proof checks; §7.1 and §7.2 the
  resource server and the Bearer downgrade. Decision 7.
- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705): §3 certificate-bound tokens. Decision 7.
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662): introspection; §4 caching against revocation.
  Decisions 9, 11.
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707): resource indicators as audiences. Decision 3.
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725): §2.8, §3.11 and §3.12 explicit typing and
  cross-JWT confusion. Decisions 5, 6.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700): §2.3 audience restriction; §2.2.1
  sender-constraining. Decisions 3, 7.
- [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470): the step-up challenge,
  `insufficient_user_authentication` with `max_age`. Decision 15.
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) and
  [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html):
  `jwks_uri` discovery. Decision 10.
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html): §5.1.1.2 no composition rules.
  Decision 17.
