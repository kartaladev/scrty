## Why

scrty can log a user in through someone else's OpenID Provider (`oidc-login`, `identity-linking`, `oidc-logout`), but an application embedding scrty cannot *be* one. A consumer's other applications (their web apps, mobile apps and APIs) therefore cannot sign users in against the accounts, factors and policies scrty already manages; each must embed scrty itself and share its stores, or the consumer must run a separate identity server beside it.

Most of what an OpenID Provider needs is already in scrty: rotating signing keys and a JWKS endpoint, sessions that record when and how the user authenticated, single-use credentials that are checked before they are spent, session families with rotation and reuse detection, rate limiting, confined outbound HTTP, and (with `close-security-gaps`) DPoP, mTLS binding, CORS, trusted proxies and security events. This change adds the protocol layer on top of them.

It is delivered before `v0.1.0` (decided 2026-11-02), because it changes ports and contracts that would be breaking after the tag.

## What Changes

The scope below is the v1 the research supports. Items were decided on 2026-11-02, as design decisions 1 to 5 and P1 to P9, and refreshed on 2026-11-04, as R1 to R16. The user accepted R1 to R4, and the logout plans in R5, on 2026-11-04. The user's standing condition is that the provider complies with the standards it implements and follows established security practice; the design maps each requirement to the decision that meets it.

- **An embeddable OpenID Provider**, built on scrty's own primitives and jwx v4, with no OpenID Provider library underneath (decided 2026-11-02):
  - **Authorization endpoint:** authorization code flow only, PKCE with `S256` required by default (a confidential client may rely on the nonce, R1), exact `redirect_uri` matching, `state` and `nonce`, `prompt` (`none`, `login`, `consent`) and `max_age`, and `iss` in every authorization response (RFC 9207).
  - **Login and consent handoff** to the consumer's own pages through a pending authorization request under an opaque handle, resumed through the provider; the handle is bound to the browser that started the request (P1). The consumer's pages sign the user in with scrty's existing endpoints: form login, passkeys, magic links, MFA, recovery, and upstream OIDC login.
  - **A browser session and single sign-on** (R2): `prompt=none` answers from a small provider-only cookie, because the conformance suite and OIDC Core §15.1 require it. It moves SSO from a follow-up into v1.
  - **Consent, delivered in v1** (decided 2026-11-02): remembered consent per user and client, `prompt=consent`, consent forced for `offline_access`, partial grants, denial, and revocation. Consent is required unless a client is registered as first-party, and `offline_access` asks even then (P2).
  - **Token endpoint:** authorization code and refresh token grants; client authentication by `client_secret_basic`, `client_secret_post`, `private_key_jwt` (the issuer as its only audience by default, after CVE-2025-27370) and `none` for public clients; single-use codes whose reuse revokes what they issued; refresh-token rotation with reuse detection, and grants with idle and absolute lifetimes (P5, P7).
  - **Tokens:** ID tokens with `nonce`, `auth_time`, `acr`, `amr`, `azp` and `sid`; JWT access tokens per RFC 9068 (5 minutes, `at+jwt`, audience-restricted) by default, opaque by option (P4); RS256 ID tokens by default (P8); DPoP and mTLS binding through `close-security-gaps`' machinery (P6).
  - **UserInfo, revocation (RFC 7009) and introspection (RFC 7662).**
  - **Discovery:** OpenID Provider metadata and OAuth authorization server metadata (RFC 8414), beside the existing JWKS endpoint.
  - **Logout:** RP-initiated logout, which asks the user unless a hint names the browser's own sign-in (R3), and back-channel logout sent to relying parties.
  - **A static client registry** the consumer owns: in-memory from configuration by default, durable through the store adapters, with secrets kept only as digests.
- **Proof of conformance:** the OpenID Foundation conformance suite's Basic OP, Config OP and logout plans run against the provider in CI, and a green run gates `v0.1.0` (P9, R5).
- **Grants stored apart from sign-ins** (decided 2026-11-02, design decision 5):
  - refresh-token lineages reuse `session`'s rotation and reuse detection unchanged, in a table the provider fixes, behind a provider-private manager;
  - refresh tokens take a format no sign-in path accepts;
  - an authoritative grant row holds the client, scopes, authentication facts, binding and a revoked flag;
  - logout ends grants without `offline_access`, security events revoke grants, a password change keeps them unless configured otherwise, and reuse revokes the whole grant.
- **Breaking changes to existing contracts, all before the tag:**
  - a security-state migration for the provider's tables, and new conformance suites;
  - `token` gains a typed issuer, with the claims an access token and an ID token need, and enforces `typ` (R6);
  - `http-error-propagation`: provider endpoints render the error bodies the protocol requires, a recorded departure from the bare-status default.

**Not in this change** (each only adds, provided v1 leaves the seams; see design "Non-Goals"): PAR and a FAPI 2.0 profile, dynamic client registration, pairwise subject identifiers, JAR, RAR, token exchange, the device grant, implicit and hybrid flows, front-channel logout and session management.

## Capabilities

### New Capabilities

Settled with the specs on 2026-11-02.

- `oidc-provider-clients`: the client registry, client types, redirect and post-logout URIs, secrets kept as digests, and client authentication methods.
- `oidc-provider-authorization`: the authorization endpoint, request validation, the pending request and its handle, the login and consent handoff, `prompt` and `max_age`, and authorization codes.
- `oidc-provider-consent`: remembered consent, when consent is required, partial grants, denial and revocation.
- `oidc-provider-tokens`: the token endpoint, grants, refresh rotation and reuse, ID token and access token contents, sender-constraining, revocation and introspection.
- `oidc-provider-userinfo`: the UserInfo endpoint and the claims a scope releases.
- `oidc-provider-metadata`: OpenID Provider and authorization server metadata.
- `oidc-provider-logout`: RP-initiated logout and back-channel logout to relying parties.

### Modified Capabilities

Settled with the specs on 2026-11-02.

- `token-issuance`: access tokens carry `client_id`, `scope` and a per-resource audience with `typ` `at+jwt`; ID tokens are issued over the same key source; verification enforces `typ`, so each token type validates only as itself.
- `account-recovery`, `multi-factor-auth`, `passkey-authentication`: completing recovery, resetting MFA and detecting a cloned passkey also revoke the user's grants, by default.
- `sessions`: the session manager reports each explicit end of a sign-in to end observers, so the provider ends the grants that came from it (design T4, R16). `session-signals` shares this option.
- `oidc-logout`: a back-channel logout from an upstream provider also ends the grants without `offline_access` that came from the sessions it ends.
- `security-state-stores`, `schema-migrations`, `store-conformance`: durable stores, a migration and conformance suites for clients, pending requests, consent and grants.
- `http-security-chain`: the provider's endpoints and their slots; local logout and session-family revocation tell the provider which sign-in ended; the password-change endpoint gains an option to revoke grants.
- `http-error-propagation`: protocol-mandated error bodies and statuses for the provider's endpoints.
- `sender-constrained-tokens` (added by `close-security-gaps`): the provider counts as a verifier of bound credentials; the token endpoint binds tokens, including refresh tokens of public clients and codes bound with `dpop_jkt`, and asks for a server nonce in the protocol's form; a client can be required to use bound tokens.
- `cors`: the provider's token, UserInfo, metadata and JWKS endpoints may be called cross-origin; the authorization endpoint never is.
- `csrf-protection` (added by `close-security-gaps`): the provider's authorization, token, revocation, introspection and end-session endpoints are exempt from the cross-site check, which relying parties cross by design; the resume, logout confirmation and consent endpoints stay protected.
- `security-events` (added by `close-security-gaps`): grants, consent, code replay, refresh reuse, revocation and failed logout delivery are reported as events.

## Impact

- **New code, core module:** the `oidcprovider` package (design T1), its endpoints in `httpsec`, and their adapters in `ginsec` and `fibersec` through the existing exchange.
- **Stores:** in-memory defaults, plus `sqlstore`, `pgxstore` and `gormstore` adapters, a security-state migration, and conformance suites in the `test` module.
- **No new dependency in any published module.** jwx v4 remains the single JOSE stack. The conformance suite (Java and MongoDB, in Docker) runs in CI only.
- **Order before the tag (decided 2026-11-02):** `close-security-gaps` (archived 2026-11-03), then `pre-release-api-fixes` (merged, #68; the `sub` claim becomes the user identifier, which an OpenID Provider must never reassign), then this change, then `release-readiness`'s gate and tag.
- **Related changes:**
  - `close-security-gaps`: its D8 must count the provider as a DPoP user, so that a chain running only the provider may enable DPoP. It was amended there on 2026-11-02 (design P6). It also provides DPoP, mTLS binding, CORS, security headers, trusted proxies, security events, and the session listing (its D12), which gains a "revoke application access" choice when ending other sessions; `session.Store` itself is unchanged by this change;
  - `session-signals`: defines the same `session.WithEndObserver`; R16 makes it one option, and task 1.3 aligns that change;
  - `split-ci-jobs` (#68): the conformance job takes its shape, behind `ci-ok` (R5);
  - `bff-resource-server`: its resource-server mode is the natural verifier of this provider's access tokens. Single sign-on no longer waits for its cookie session (R2);
  - `release-readiness`: its gate names the conformance job (P9), its first changelog entry summarises this change, and its README task's `prompt=none` limitation goes (R2).
- **Consumers:** none yet. Nothing is tagged.

## References

See `design.md`, where every source is grouped by the decision it supports.
