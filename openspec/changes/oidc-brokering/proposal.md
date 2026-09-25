## Why

Applications embedding scrty can authenticate users with local credentials, but cannot delegate login to the identity provider their organisation already runs. Federation is where login flows most often fail silently:
- an ID token accepted from the wrong issuer, or with `alg: none`;
- an account claimed by matching an email address the attacker set at their own provider;
- a forged callback that destroys a victim's login in flight;
- a one-time code spent by a refusal the holder could have fixed;
- a logout endpoint that lets anyone end a user's sessions, or makes the service fetch key sets on demand.

scrty brokers OpenID Connect login with each of those failures written down as a requirement, on top of the identity, session, policy and persistence contracts the earlier changes define.

## What Changes

- Add an `oidc` package that brokers login against a registry of named providers:
  - provider configuration is trusted operator input, validated at construction;
  - provider metadata and key sets are fetched through the confined outbound client, discovered lazily (or prefetched on request), cached with a TTL, fetched once per burst of concurrent callers, backed off on failure, and refetched on an unknown key id at most once per cooldown per provider;
  - the authorization code flow always uses PKCE (S256), state and nonce;
  - the flow is completed by one atomic operation bound to the provider and state, so a forged callback cannot spend a victim's flow;
  - ID tokens are verified against a pinned algorithm set, the configured issuer and the client id.
- Add external identity linking:
  - a link is keyed by provider, issuer and subject, never by email, and resolves its user by user reference, never by username;
  - a conflicting link is refused, not overwritten;
  - just-in-time provisioning is off by default and, when enabled per provider, is gated on a verified email and an optional domain allowlist, and uses the create-only user provisioner, so an existing account is never adopted;
  - roles can be derived from a configurable claim path at provisioning, and optionally re-derived on every login without being persisted;
  - a display name and a bcrypt password hash can be mapped from claims, the hash only within a bounded cost band and with a matching encoder, and optionally mirrored onto the user on later logins through the user provisioner's update operation.
- Add the handoff from the browser callback to the application session:
  - the callback issues a short-lived, single-use code, and the application redeems it with a POST;
  - redemption is check-then-consume: the account is resolved by user reference and refusal checks run before the atomic consume, so a refusal or lookup failure never spends the code;
  - every failure that is not a policy or check refusal, outages included, answers with one invalid-handoff outcome, as magic-link does;
  - refused redemptions count against the per-source rate limit by default;
  - redemption ends through the chain's shared login tail, which gains the ability to write the federated session fields;
  - a policy deny with no reason still refuses, a challenge still redeems, and guards catch a redemption implementation that skips the checks or discards a deny.
- Add OIDC logout:
  - back-channel logout-token verification, with replay bounded by `iat`;
  - a session-id logout ends exactly the matching sessions, and a subject-only logout ends only sessions from the asserting issuer by default;
  - a federated session records its provider, issuer, provider session id and ID token in the write that creates it;
  - RP-initiated logout builds the provider's end-session URL for a federated session, returned by local logout through a new optional end-session step.
- Add HTTP interceptors to `httpsec` for the authorize, callback, handoff-redemption and back-channel logout endpoints, at the reserved `OrderOIDC` slot, with identical outcomes through the gin and fiber adapters.
- Let `outbound`'s form POST carry headers, for HTTP Basic client authentication.
- Map an unknown provider to 404 and an invalid logout token to 400.
- Add in-memory defaults for the link, flow and handoff stores, and conformance suites for each store contract in the `test` module.

Not in this change:
- MFA assurance from the provider (`amr`/`acr`). OIDC logins are exempt from local MFA by default, which is a stated limit; the `oidc-mfa-assurance` change adds per-provider assurance.
- Cookie-borne sessions for browsers and CSRF defence (`bff-resource-server`).
- Durable store adapters (`security-state-stores`) and their scheduled expiry (`expiry-sweeping`).

## Capabilities

### New Capabilities

- `oidc-login`: the provider registry and its validation, discovery and key-set caching, the authorization code flow with PKCE, state and nonce, the flow store contract, ID token verification, and the handoff code from callback to application session, including its issuance, conveyance, check-then-consume redemption and rate limiting.
- `identity-linking`: mapping a verified external identity to an internal user: the link key, the link store contract, resolution of linked users, gated just-in-time provisioning through the create-only provisioner, and claim-derived roles.
- `oidc-logout`: ending federated sessions: logout-token verification and its replay bound, the back-channel logout endpoint and its scoping, the federated session identity recorded on session creation, and RP-initiated logout.

### Modified Capabilities

- `http-security-chain`: logout gains an optional end-session step and may answer with the provider's end-session URL; the login completion step accepts session create options, so a federated first factor can record its provider session in the creating write.
- `http-error-propagation`: the status table gains an unknown-provider row (404) and an invalid-logout-token row (400).
- `outbound-http-confinement`: a form POST can carry caller-supplied headers, as a GET already can.
- `framework-adapters`: a gin refusal mapped to 404 on a request no gin route matched is committed with an empty body, so gin answers like the other adapters.
- `identity-model`: the user loader contract covers loading by user reference, which the code already provides, and its conformance cases pin it.

## Impact

- **New code, core module:** the `oidc` package (registry, discovery and key cache, flow, verification, broker, links, handoffs, logout tokens, in-memory stores) and OIDC interceptors in `httpsec`.
- **Changed code, core module:** `httpsec` logout and login tail, the status table, and `outbound.Client.PostForm`.
- **Test module:** conformance suites for the link, flow and handoff store contracts, a load-by-reference case in the identity conformance suite, and an in-process test identity provider that can emit malformed tokens. A single real-provider test runs against a Keycloak testcontainer.
- **Dependencies:** no new JOSE library. ID token and key-set work reuses jwx v4, the one chosen by `identity-and-tokens`; key sets are fetched through `outbound` rather than the `jwkfetch` companion, and `openspec/config.yaml` is amended to say so. `golang.org/x/sync` is added to the core module for request coalescing. `golang.org/x/oauth2` is allowed by the project configuration but deliberately unused: the exchange is one form POST (design decision 6).
- **Depends on:**
  - `identity-model`: principal, user loader, create-only user provisioner, first-factor kinds;
  - `factor`: the OIDC first-factor kind, its federated channel and its MFA exemption;
  - `sessions`: federated session fields, deletes by provider session and by user and issuer, and the sealing store that already protects the retained ID token;
  - `security-policy`: post-authentication evaluation and the first-factor classification that exempts OIDC from MFA;
  - `rate-limiting`: the per-source guard;
  - `token-issuance`: the access token minted at redemption;
  - `http-security-chain`, `http-error-propagation` and `outbound-http-confinement` (http-security), each modified as listed above;
  - `magic-link` (auth-methods), whose redemption interceptor is the pattern this one follows;
  - `log-sampling` and `id-generation`.
- **Consumed by:**
  - `security-state-stores` and `secrets-at-rest` (durable link, flow and handoff adapters, and a `Cipher` for the existing sealing store);
  - `expiry-sweeping`;
  - `di-wiring`;
  - `oidc-mfa-assurance`.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
