# Proposal

## Why

With `browser-session`, a browser signs in to the consumer's own app through an `HttpOnly` cookie,
and no token reaches JavaScript. When that app then calls internal APIs on the user's behalf, it
needs something to send them, and today scrty gives it nothing: the chain hands out no token on a
cookie chain, and the provider's tokens from a federated sign-in are discarded after the exchange.
Each consumer would hand-roll token minting, provider-token storage, refresh and the outbound hop.

This change takes over the three questions the `bff-resource-server` draft left open about that
path. That draft is retired: its CSRF part landed in `close-security-gaps`, its resource-server part
on 2026-11-25, and its cookie session in `browser-session`.

Q2, Q3 and Q5 were answered on 2026-11-28 (design.md, D1-D5).

## What Changes

- **Outbound tokens, off until enabled, named per API.** A consumer enables outbound tokens on a
  cookie chain and names each downstream API by its resource identifier, which is the token's
  audience. Each API is served by one of two token kinds, chosen per API:
  - **Minted:** a short scrty access token (`at+jwt`, one audience, at most 5 minutes, a fresh
    `jti` that is never the session identifier, never beyond the session's absolute deadline),
    minted per request and never stored. Works for local and federated sign-ins.
  - **Provider:** the access token of the identity provider the session signed in through, kept
    sealed on the session and refreshed with the provider's refresh token shortly before expiry.
    Refreshes of one session are coalesced, and their result is saved by a conditional write. A
    failed refresh fails the call, not the session.
- **Tokens only for cookie-authenticated requests.** The accessor returns a token only for a request
  the session cookie authenticated. It never puts a token in a response.
- **An outbound transport.** scrty ships an HTTP transport built from the same API list. It attaches
  the API's token, removes any `Cookie` header, and refuses any destination outside the configured
  APIs before sending. It runs on the confined outbound client's rules. Routing and any reverse proxy
  stay the consumer's. scrty documents the remaining obligations, among them
  `Cache-Control: private, no-store` on per-user responses.
- **APIs accept minted tokens by opting out of binding for that source.** Minted tokens are unbound.
  A downstream API verifies them with `EnableResourceServer` against the app's published key set and
  opts that source out of binding, as `resource-server` already allows. Binding minted tokens with
  DPoP is left to a later change.
- **Provider tokens are kept only when asked.** `oidc-login` keeps the provider's access token,
  refresh token and expiry on the session only for a provider the consumer configures for
  forwarding. Every other provider discards them, as today.

## Capabilities

### New Capabilities
- `token-forwarding`: obtaining an access token for a downstream API from a cookie-authenticated
  request, minted or the provider's. It also covers the token's audience, lifetime and renewal, the
  outbound transport, and the wiring checks.

### Modified Capabilities
- `oidc-login`: a provider configured for forwarding keeps its access token, refresh token and expiry
  on the session it creates. Other providers are unchanged.
- `sessions`: library-owned provider-token fields, kept apart from consumer data, carried across
  rotation, replaced only by a conditional write, and sealed by the sealing store.
- `secrets-at-rest`: the retained provider access and refresh tokens join the list of secrets stored
  sealed.
- `security-state-stores`: durable session stores persist the provider tokens sealed and bound to
  the session, and implement their conditional replacement.

## Impact

- **Code:**
  - `httpsec`: the enabling option, the accessor and the outbound transport.
  - `oidc`: keeping and refreshing provider tokens.
  - `session`: the new fields, sealing and the conditional replace.
  - `store/sqlstore`, `store/pgxstore`, `store/gormstore`: columns and a security-state migration.
  - Token issuance is reused, with a fresh `jti`.
- **Docs:** a consumer guide for the outbound hop. It covers the obligations the transport cannot
  enforce, such as caching and pass-through routes, how an API opts out of binding for the app's
  source, and the `offline_access` scope that many providers require before they issue a refresh
  token.
- **Depends on:** `browser-session` (archived).
- **Dependencies:** none added. Provider refresh uses the existing OAuth 2.0 client and the confined
  outbound client.

## References

See design.md, `## References`.
