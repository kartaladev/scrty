## Why

scrty can log a user in through someone else's OpenID Provider (`oidc-login`, `identity-linking`, `oidc-logout`), but an application embedding scrty cannot *be* one. A consumer's other applications (their web apps, mobile apps and APIs) therefore cannot sign users in against the accounts, factors and policies scrty already manages; each must embed scrty itself and share its stores, or the consumer must run a separate identity server beside it.

Most of what an OpenID Provider needs is already in scrty: rotating signing keys and a JWKS endpoint, sessions that record when and how the user authenticated, single-use credentials that are checked before they are spent, session families with rotation and reuse detection, rate limiting, confined outbound HTTP, and (with `close-security-gaps`) DPoP, mTLS binding, CORS, trusted proxies and security events. This change adds the protocol layer on top of them.

It is delivered before `v0.1.0` (decided 2026-11-02), because it changes ports and contracts that would be breaking after the tag.

## What Changes

The scope below is the v1 the research supports (design "Decisions" and "Proposed defaults"). Items marked *proposed* await the user's confirmation. How a grant is stored was decided on 2026-11-02 (design decision 5, option D+).

- **An embeddable OpenID Provider**, built on scrty's own primitives and jwx v4, with no OpenID Provider library underneath (decided 2026-11-02):
  - **Authorization endpoint:** authorization code flow only, PKCE with `S256` required, exact `redirect_uri` matching, `state` and `nonce`, `prompt` (`none`, `login`, `consent`) and `max_age`, and `iss` in every authorization response (RFC 9207).
  - **Login and consent handoff** to the consumer's own pages through a pending authorization request under an opaque handle, resumed through the provider (*proposed*). The consumer's pages sign the user in with scrty's existing endpoints: form login, passkeys, magic links, MFA, recovery, and upstream OIDC login.
  - **Consent, delivered in v1** (decided 2026-11-02): remembered consent per user and client, `prompt=consent`, consent forced for `offline_access`, partial grants, denial, and revocation. Consent is required unless a client is registered as first-party (*proposed default*).
  - **Token endpoint:** authorization code and refresh token grants; client authentication by `client_secret_basic`, `client_secret_post` and `private_key_jwt`; single-use codes whose reuse revokes what they issued; refresh-token rotation with reuse detection (*proposed default*).
  - **Tokens:** ID tokens with `nonce`, `auth_time`, `acr`, `amr`, `azp` and `sid`; JWT access tokens per RFC 9068 by default, opaque by option (*proposed*); DPoP and mTLS binding through `close-security-gaps`' machinery (*proposed for v1*).
  - **UserInfo, revocation (RFC 7009) and introspection (RFC 7662).**
  - **Discovery:** OpenID Provider metadata and OAuth authorization server metadata (RFC 8414), beside the existing JWKS endpoint.
  - **Logout:** RP-initiated logout, and back-channel logout sent to relying parties.
  - **A static client registry** the consumer owns: in-memory from configuration by default, durable through the store adapters, with secrets kept only as digests.
- **Proof of conformance:** the OpenID Foundation conformance suite's Basic OP and Config OP plans run against the provider in CI.
- **Grants stored apart from sign-ins** (decided 2026-11-02, design decision 5):
  - refresh-token lineages reuse `session`'s rotation and reuse detection unchanged, in a table the provider fixes, behind a provider-private manager;
  - refresh tokens take a format no sign-in path accepts;
  - an authoritative grant row holds the client, scopes, authentication facts, binding and a revoked flag;
  - logout ends grants without `offline_access`, security events revoke grants, a password change keeps them unless configured otherwise, and reuse revokes the whole grant.
- **Breaking changes to existing contracts, all before the tag:**
  - a security-state migration for the provider's tables, and new conformance suites;
  - `token` gains the claims an access token and an ID token need;
  - `http-error-propagation`: provider endpoints render the error bodies the protocol requires, a recorded departure from the bare-status default.

**Not in this change** (each only adds, provided v1 leaves the seams; see design "Non-Goals"): single sign-on across relying parties without re-login (it needs `bff-resource-server`'s cookie session), PAR and a FAPI 2.0 profile, dynamic client registration, pairwise subject identifiers, JAR, RAR, token exchange, the device grant, implicit and hybrid flows, front-channel logout and session management.

## Capabilities

### New Capabilities

Proposed names; the boundaries are settled with the specs.

- `oidc-provider-clients`: the client registry, client types, redirect and post-logout URIs, secrets kept as digests, and client authentication methods.
- `oidc-provider-authorization`: the authorization endpoint, request validation, the pending request and its handle, the login and consent handoff, `prompt` and `max_age`, and authorization codes.
- `oidc-provider-consent`: remembered consent, when consent is required, partial grants, denial and revocation.
- `oidc-provider-tokens`: the token endpoint, grants, refresh rotation and reuse, ID token and access token contents, sender-constraining, revocation and introspection.
- `oidc-provider-userinfo`: the UserInfo endpoint and the claims a scope releases.
- `oidc-provider-metadata`: OpenID Provider and authorization server metadata.
- `oidc-provider-logout`: RP-initiated logout and back-channel logout to relying parties.

### Modified Capabilities

Expected; the final list is settled with the specs.

- `token-issuance`: access tokens carry `client_id`, `scope` and a per-resource audience with `typ` `at+jwt`; ID tokens are issued over the same key source; verification enforces `typ`, so each token type validates only as itself.
- `account-recovery`, `multi-factor-auth`, `passkey-authentication`: completing recovery, resetting MFA and detecting a cloned passkey also revoke the user's grants, by default.
- `oidc-logout`: a back-channel logout from an upstream provider also ends the grants without `offline_access` that came from the sessions it ends.
- `security-state-stores`, `schema-migrations`, `store-conformance`: durable stores, a migration and conformance suites for clients, pending requests, consent and grants.
- `http-security-chain`: the provider's endpoints and their slots; local logout and session-family revocation tell the provider which sign-in ended; the password-change endpoint gains an option to revoke grants.
- `http-error-propagation`: protocol-mandated error bodies and statuses for the provider's endpoints.
- `sender-constrained-tokens` (added by `close-security-gaps`): the token endpoint binds tokens, including refresh tokens of public clients and codes bound with `dpop_jkt`.
- `cors`: the provider's token, UserInfo, metadata and JWKS endpoints may be called cross-origin; the authorization endpoint never is.

## Impact

- **New code, core module:** a provider package (name settled with the specs), its endpoints in `httpsec`, and their adapters in `ginsec` and `fibersec` through the existing exchange.
- **Stores:** in-memory defaults, plus `sqlstore`, `pgxstore` and `gormstore` adapters, a security-state migration, and conformance suites in the `test` module.
- **No new dependency in any published module.** jwx v4 remains the single JOSE stack. The conformance suite (Java and MongoDB, in Docker) runs in CI only.
- **Order before the tag (decided 2026-11-02):** `close-security-gaps`, then `pre-release-api-fixes` (the `sub` claim becomes the user identifier, which an OpenID Provider must never reassign), then this change, then `release-readiness`'s gate and tag.
- **Related changes:**
  - `close-security-gaps`: DPoP, mTLS binding, CORS, security headers, trusted proxies, security events, and the session listing (its D12), which gains a "revoke application access" choice when ending other sessions; `session.Store` itself is unchanged by this change;
  - `bff-resource-server`: its resource-server mode is the natural verifier of this provider's access tokens, and its cookie session is the prerequisite for single sign-on, a follow-up;
  - `release-readiness`: its first changelog entry summarises this change.
- **Consumers:** none yet. Nothing is tagged.

## References

See `design.md`, where every source is grouped by the decision it supports.
