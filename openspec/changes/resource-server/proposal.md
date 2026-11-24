# Proposal

## Why

The httpsec chain authenticates only its own sign-in credentials: session tokens and session
references. It cannot act as an OAuth **resource server**: it cannot accept an access token on an
API route, whether the token comes from scrty's own provider or from an external identity provider.

- A chain that embeds the provider and serves its own API answers 401 for every token the provider
  issues. Only `/userinfo` accepts them.
- An application that is only an API, trusting Keycloak, Zitadel, Auth0 or a scrty provider in
  another binary, has no built-in way to verify their tokens. It must hand-write an interceptor,
  key-set fetching, binding checks and principal mapping.

Two earlier proposals covered parts of this:
- `provider-resource-server` (PR #117, on hold) covered only the provider's tokens, by bending the
  session-token bearer.
- `bff-resource-server` covered remote issuers, but is blocked on its browser-session questions.

This change replaces both with one generic capability.

The change also carries two consumer requests that the on-hold proposal held:
- password rules the consumer owns;
- an opt-in disclosure of inactive accounts.

## What Changes

**The resource-server mode**
- `httpsec.EnableResourceServer(resourceID, opts...)`: a credential mode for OAuth access tokens. It
  is named for the role it plays beside `EnableOIDCProvider`. A chain may enable several, each
  scoped to its own path prefixes, one per API.

**Token sources** (several per mode)
- `FromProvider(op)`: the chain's own provider, in process or over a shared store. The grant is
  checked on every request.
- `FromIssuer(issuer)`: any issuer's JWT access tokens, verified against its remote key set (JWKS).
  Each JWT can also be introspected, as an opt-in.
- `FromIntrospection(endpoint)`: opaque or JWT tokens checked at an RFC 7662 introspection
  endpoint.

**Defaults, each overridable per source**
- **Audience:** a token must name the API's resource identifier.
  - `WithResourceAliases` adds other names for the same API.
  - A per-source audience covers issuers that spell it differently.
- **Binding:** DPoP or mTLS binding is required. A source can opt out of it.
- **Token type:** `at+jwt` (RFC 9068) is required. A source can opt in to untyped `JWT` access
  tokens, but only together with a claim that tells them from ID tokens.
- **Caller:** three selectable strategies.
  - *Claims only* (the default for external sources): subject and scopes from the token, no roles.
  - *Claims mapper*: a consumer function derives roles from the claims.
  - *Local user*: the subject's user is reloaded each request, so roles are current. This is the
    default for `FromProvider`.
- **Revocation:**
  - provider tokens: immediate;
  - offline JWTs: valid until `exp`;
  - introspected tokens: immediate, or within a bounded cache.

**What a handler sees**
- `identity.PrincipalFromContext` works unchanged, carrying the token's scopes.
- `httpsec.AccessTokenFromContext` exposes the issuer, client, audience, scopes, authentication
  time and claims.
- A new first-factor kind, `access-token`.

**Refusals**
- A refused access token is answered 401 with `error="invalid_token"` (RFC 6750, RFC 9449).
- A missing scope, at a chain rule or a guard, is answered 403 with `error="insufficient_scope"` and
  the scopes needed (RFC 6750 §3.1).
- The chain's session-only endpoints refuse an access-token caller: password change, passkey and MFA
  management, re-authentication, session renewal and management, and logout.

**Guards**
- Every guard keeps working for access-token callers.
- **BREAKING (behaviour):** recency guards now judge an access-token caller by the token's
  authentication time, instead of refusing it outright.
  - A stale token is answered 401 with `error="insufficient_user_authentication"` and `max_age`
    (RFC 9470).
  - Session callers keep today's 403.

**Shared internals**
- The provider's DPoP check for access tokens moves out of `/userinfo` into code both use.
- The remote key-set cache moves out of `authenticate/oidc` into code both use.

**Consumer password rules**
- `password.WithRule(name, check)` adds a rule the consumer owns. It is checked after the built-in
  lists and before the breach lookup, and its refusal names the rule.

**Inactive accounts**
- **BREAKING (behaviour):** `authenticate.ErrAccountInactive` is now reachable beneath the uniform
  failure, after a correct password.
- `httpsec.WithInactiveDisclosure()` answers that case 403, as an opt-in.

**Retired proposals**
- `provider-resource-server` is superseded and is not applied.
- `bff-resource-server` keeps only its browser-session part.

## Capabilities

### New Capabilities

- `resource-server`: accepting OAuth access tokens on a chain's API routes:
  - resource identity and path scoping;
  - token sources (provider, remote issuer, introspection) and how tokens are routed to them;
  - audience, type and binding checks;
  - caller strategies and what is published to handlers;
  - revocation per source;
  - challenges;
  - construction checks.

### Modified Capabilities

- `http-security-chain`: session-only endpoints refuse an access-token caller; per-endpoint guards
  judge access-token callers.
- `identity-model`: a user principal carries an access token's scopes; the `access-token`
  first-factor kind.
- `authorization`: a scope refusal names the scopes it needed.
- `http-error-propagation`: the invalid-token refusal and challenge, the insufficient-scope
  challenge, the insufficient-user-authentication challenge, and the inactive-account refusal.
- `reauthentication`: the recency guard's authentication time for an access-token caller, and the
  RFC 9470 challenge.
- `sender-constrained-tokens`: a resource server counts as a verifier of bound credentials, and
  requiring bound access tokens does not require proofs at sign-in.
- `authentication`: an inactive account's refusal is identifiable beneath the uniform failure.
- `password-policy`: consumer rules.

## Impact

- **New public API**, all additive:
  - `httpsec`:
    - `EnableResourceServer`, `ResourceServerOption`;
    - `FromProvider`, `FromIssuer`, `FromIntrospection`;
    - `OrderResourceServer`, `WithPathPrefix`, `WithResourceAliases`, `WithSourceAudience`;
    - `WithJWKSURL`, `WithClockSkew`, `WithOpaquePrefix`, `WithIntrospectionSecret`, `WithIntrospectionKey`;
    - `WithUnboundTokens`, `WithUntypedTokens`;
    - `WithClaimsOnly`, `WithClaimsMapper`, `WithLocalUsers`;
    - `WithJWTIntrospection`, `WithIntrospectionCache`;
    - `AccessToken`, `AccessTokenFromContext`, `ErrInvalidToken`, `WithInactiveDisclosure`.
  - `oidcprovider`: `Provider.UserLoader`; `AccessToken` gains `AuthTime`, `ACR` and `AMR`.
  - `authenticate/factor`: `AccessToken`.
  - `authenticate`: `ErrAccountInactive`.
  - `authorize`: `ScopeError`.
  - `authenticate/password`: `WithRule`, `RuleFunc`.
- **Behaviour changes** (recorded under *Changed*):
  - recency guards and access-token callers;
  - `ErrAccountInactive` reachable beneath the uniform failure.
- **Packages:**
  - `httpsec`, `oidcprovider` (a verifier for the resource server; UserInfo's binding check
    shared);
  - `authenticate/oidc`, whose key-set cache moves to an internal package;
  - `identity`, `authorize`, `authenticate`, `authenticate/password`;
  - `httpsec/fibersec` and `httpsec/ginsec` (guards and adapter tests);
  - `test/httpsecconformance`.
- **Dependencies:** none new. Remote fetching uses the existing `outbound` client and `jwx`.
- **Consumers:** crm-api sets its client's `DefaultAudience` and enables the mode. Its sign-out route
  is a session-only endpoint, so a client holding only an access token signs out through the
  provider's end-session and revocation endpoints instead.
- **Supersedes:** `provider-resource-server` (PR #117 is closed, not merged); the resource-server
  half of `bff-resource-server`.
