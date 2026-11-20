## Why

A consumer's command-line applications need to sign users in against the consumer's scrty-based OpenID Provider. On a machine with a browser, a CLI can already do this: scrty accepts native public clients with loopback redirect URIs under PKCE (RFC 8252). On a headless machine (an SSH session, a container, a CI runner, a remote development VM) there is no local browser to receive a redirect, and the only standard flow left is the OAuth 2.0 Device Authorization Grant (RFC 8628). The provider's v1 design listed the device grant as a non-goal that "only adds, provided v1 leaves its seam"; this change adds it.

Device-code phishing is an active attack class (Microsoft's Storm-2372 report, February 2025), and RFC 10027 (BCP 247, August 2026) allows the device grant only with mitigations deployed. The grant is therefore opt-in per client, and its defaults are the safe ones.

**Sequencing.** The artifacts are written now. Implementation starts only after the active changes `harden-chain-boundary` (the `v0.1.1` release) and `split-ci-jobs` are archived. The change only adds: no existing contract breaks, so it can ship in a minor release.

## What Changes

Decided with the user on 2026-11-20, after the research recorded in the design's References.

- **A device authorization endpoint** (`POST /oauth2/device-authorization`, RFC 8628 §3.1–3.2). It authenticates confidential clients as the token endpoint does, and accepts public clients by `client_id`. It returns:
  - a `device_code` with at least 128 bits of entropy, stored only as a digest;
  - a `user_code` of 8 characters from the RFC 8628 §6.1 base-20 alphabet, shown with a dash and also stored only as a digest;
  - `verification_uri`, `expires_in` (600 s by default) and `interval` (5 s by default);
  - `verification_uri_complete`, only when the client opts in, because a prefilled link is the phishing vector.
- **Two ways to enter a user code** (decided 2026-11-20):
  - **the chain's code-entry endpoint** (`/oauth2/device`) by default. The consumer's page is only a form that submits the code there. The endpoint normalises the code, throttles entry, and parks a pending request bound to the browser that entered it. It then hands off to the consumer's existing login and consent pages;
  - **a `Provider` method** for a consumer whose own handler takes the code. The endpoint calls the same method, so both paths get the same normalisation, throttle and binding, and neither is weaker than the other.
- **Throttled code entry with no oracle.** The provider throttles failed code entries per source itself, so both entry paths are covered, and the consumer can replace the limiter. A wrong, expired, spent or already-claimed code gets the same answer (RFC 8628 §5.1, RFC 10027 §6.1.11).
- **Consent is always shown for a device authorization**, even for a first-party client. It carries a warning that a device is asking for access and asks whether the user started the request. Denial is as prominent as approval (RFC 10027 §6.1.14).
- **A new grant at the token endpoint**, `urn:ietf:params:oauth:grant-type:device_code`, answering `authorization_pending`, `slow_down` (the interval grows by 5 s and stays grown), `access_denied` and `expired_token`.
  - An approved device code is exchanged exactly once, also under concurrent polls, and a replay of a spent code revokes the grant it created.
  - A DPoP proof on the poll binds the grant.
  - An ID token is issued for `openid`. A refresh token follows the client's existing registration.
- **Device grants and the approving sign-in** (decided 2026-11-20, option C):
  - **The default** is the same rule as authorization-code grants (OpenID Connect Back-Channel Logout §2.7). A device grant without `offline_access` ends when the browser sign-in that approved it ends, and one with `offline_access` survives.
  - **A new per-client setting** lets a device grant without `offline_access` outlive that sign-in.
  - **The existing per-client setting** still ends every grant with its sign-in. The two settings contradict each other, so setting both fails construction.
- **Opt-in twice, never on by default:**
  - once for the provider, by an option that names the consumer's code-entry page;
  - once per client, through the existing `Client.GrantTypes`.

  A client registered for the grant on a provider that has not enabled it fails construction, or is invalid when read from a registry.
- **Discovery** advertises `device_authorization_endpoint` and the grant type only when the provider has enabled the grant.
- **A device authorization store port**, with an in-memory default, durable SQL adapters, a conformance suite, a security-state migration and an expiry sweep.
- **Security events** for device authorization issued, approved, denied, exchanged, and for a replayed device code.

**Not in this change:**
- a client-side helper, because `golang.org/x/oauth2` already provides `Config.DeviceAuth` and `Config.DeviceAccessToken`;
- CIBA;
- proximity checks (RFC 10027 §6.1.1);
- a deny list of user codes.

The README gains a "CLI clients" section: loopback with PKCE first, the device grant as the fallback.

## Capabilities

### New Capabilities

- `oidc-provider-device-authorization`: the device authorization endpoint, device and user codes, user-code entry (provider endpoint and consumer method), its throttle, the verification handoff to login and consent, and the device authorization's lifecycle.

### Modified Capabilities

- `oidc-provider-tokens`: the token endpoint accepts the device-code grant with its polling errors, single exchange and replay revocation. A device grant's link to its approving sign-in follows the new per-client setting.
- `oidc-provider-clients`: the device-code grant type, valid for which clients; the per-client settings for user-code delivery and for a device grant outliving its sign-in, and their contradictions.
- `oidc-provider-consent`: a device authorization always asks, whatever the client's first-party flag or remembered consent.
- `oidc-provider-metadata`: `device_authorization_endpoint` and the grant type in `grant_types_supported`.
- `http-security-chain`: the two new provider endpoints, and the throttle on failed client authentication at the device authorization endpoint.
- `csrf-protection`: the device authorization endpoint is exempt like the token endpoint, and the code-entry endpoint stays protected.
- `cors`: neither device endpoint ever carries CORS headers.
- `security-state-stores`, `schema-migrations`, `store-conformance`: the device authorization store with its conditional writes and sweep, its migration and its conformance suite.
- `security-events`: the device authorization events.

## Impact

- **Code:** `oidcprovider` (new endpoint handlers, the device authorization record and store port, the token-endpoint grant, consent rules, metadata, client validation, events, expiry task), `httpsec` (endpoint table, operations, chain wiring, base-path and inventory tests), `store/sqlstore` with `store/pgxstore` and `store/gormstore` (adapters), `store/migrate` (one security-state migration), `test` (conformance suite).
- **API:** additions only. These are a `GrantType` constant, two `Client` fields, a store port with options, one `Provider` method for consumer-rendered entry, and options for lifetime, interval, user-code generator and throttle. No existing signature changes.
- **Dependencies:** none new.
- **Docs:** README (CLI clients), CHANGELOG.
