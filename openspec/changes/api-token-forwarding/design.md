# Design

## Context

See proposal.md for why. The three blocking questions were put to the user on 2026-11-28 with a
researched brief. The answers were:

- Q2: both the minted token and the provider token, each opt-in per API.
- Binding: APIs opt out per source.
- Q3: the consumer owns routing, and scrty ships an outbound transport.
- Q5: minted tokens are re-minted from the session, and provider tokens are refreshed with the
  provider's refresh token.

What exists when this change is applied:

- **`browser-session`:** a cookie chain hands out no credential in a body. The session is the single
  source of truth, with idle and absolute expiry and rotation on privilege change.
- **`token-issuance`:** scrty mints signed tokens with a caller-supplied `jti`, a declared type and
  further claims. The chain's signed bearer reads `jti` as the session it names, and its verifier
  accepts only its own token type.
- **`resource-server`:** an API verifies JWT access tokens from any issuer against a remote key set.
  The audience is required and `at+jwt` typing is enforced. Unbound tokens are refused by default,
  with a per-source opt-out. Introspection of every JWT is opt-in.
- **`oidc-login`:** the provider's refresh token is discarded. Its access token lives only for the
  callback, offered as upstream access to a broker that asks.
- **`sessions` / `secrets-at-rest`:** a session retains the provider's ID token, sealed and bound to
  the session's row. A single field can be updated conditionally on the session still existing.
- **`outbound-http-confinement`:** a confined client that restricts origins, redirects, time and
  size.

## Goals / Non-Goals

**Goals:**

- A handler on a cookie chain can call an internal API as the signed-in user without hand-rolling
  token handling. This covers local and federated sign-ins.
- A token never reaches the browser, and the session cookie never reaches an API.
- Revocation stays one session delete, within a bounded window for minted tokens.

**Non-Goals:**

- A reverse proxy shipped by scrty. A proxy helper may follow as its own change, on top of the
  transport.
- OAuth 2.0 token exchange (RFC 8693) and phantom-token gateways.
- Revoking a JWT at a stateless API before it expires. An API that needs this opts in to
  introspection, which `resource-server` already offers.
- Binding minted tokens with DPoP or mTLS. That is a later change.
- Revoking the provider's refresh token at the provider (RFC 7009) on logout. Accepted, see the
  failure modes.

## Decisions

### D1. Two token kinds, chosen per API, both off by default (Q2)

The consumer enables outbound tokens on a chain and names each downstream API by its resource
identifier, an absolute URI that becomes the token's audience. Each API is served by exactly one
source:

- **minted**: a scrty token, see D2;
- **provider**: the access token of a named identity provider, see D5;
- **consumer**: a token source the consumer supplies.

- **Default:** outbound tokens are off. A chain that does not enable them has no accessor result and
  no transport.
- **Override:** each API chooses its source. The consumer source replaces scrty's minting and
  refresh entirely, for an API that needs another issuer's token.
- **Why both:** the established design and established practice (RFC 10017 §6.1; Duende BFF, Spring
  `TokenRelay`, oauth2-proxy) forward the provider's token. That cannot serve local-account
  sign-ins, which have no provider token, and it puts the provider's audience in the API's hands.
  Minted tokens cover both kinds of sign-in, with an audience scrty controls (RFC 9700 §2.3,
  RFC 8707). The user chose to offer both.
- **Departure from common practice:** the minted kind makes the app the issuer for its own APIs.
  Tokens still never reach the browser, so the BFF pattern itself is kept.

### D2. The minted token's shape

- **Header:** `typ` `at+jwt`.
- **Claims:**
  - `iss`: the chain's issuer.
  - `sub`: the session's user reference.
  - `aud`: exactly one API.
  - `client_id`: by default the chain's issuer, replaceable by an option.
  - `iat` and `exp`.
  - `jti`: a fresh random value from `crypto/rand`, **never the session identifier**.
  - These are RFC 9068 §2.2's required claims.
- **Lifetime:** 5 minutes by default, the maximum. Construction refuses a lifetime under 1 second, a
  lifetime that is not whole seconds, or a lifetime over 5 minutes.
- **Expiry:** `exp` is the earlier of the issue time plus the lifetime and the session's absolute
  deadline.
- **Re-minting and storage:** a token is re-minted on each request, and within one request it is
  reused while more than one minute remains. It is never written to the session or any store.

Why a fresh `jti`:

- The chain's signed bearer loads the session that a token's `jti` names, and the session cookie
  carries that same identifier.
- A minted token that carried the session identifier would give every API, and every log it lands
  in, a value it could replay as the user's cookie.
- `token-issuance` already lets the caller choose `jti`. The minted token's distinct type means the
  signed bearer refuses it in any case, since its verifier accepts only its own type.

This hazard is **UNREPRODUCED**, because there is no code yet. Its first task is a failing test that
presents a minted token's `jti` as the session cookie and as a signed bearer token.

### D3. Binding: the API opts out for the app's source

Minted tokens carry no confirmation. A downstream API verifies them with `EnableResourceServer`
against the app's published key set, and opts that one source out of binding, as `resource-server`
already allows. The opt-out stays per source, so the API's other sources keep the default.

- **Default:** none to set in this change. The API side's default still refuses unbound tokens, so
  an API that forgets the opt-out refuses the token. It fails closed.
- **Documented line:** the app-to-API hop must use TLS. An unbound token copied off that hop is
  usable until it expires, at most 5 minutes.
- **Later:** binding minted tokens with DPoP, so the API keeps the default.

### D4. scrty ships an outbound transport; the consumer owns routing (Q3)

The transport is built from the same API list. Each API also names one or more base URLs:

- an origin;
- an optional path prefix, matched by whole segments.

For each request, the transport:

1. refuses, before sending, a destination under no configured API's base URL;
2. resolves the token for the API whose base URL covers the request, and refuses the request when
   it has no token;
3. sets `Authorization: Bearer <token>`, replacing any value already present;
4. removes every `Cookie` header;
5. sends through the confined client's rules: allowed schemes, no redirect to another origin, and
   bounded time and size.

The transport does not follow a redirect to another origin, and never re-sends the token to one.

- **Default:** `https` only. The confinement allows `http` only by an explicit opt-in, which states
  that it removes transport protection.
- **Override:** the consumer may still build requests themselves with the accessor. The transport is
  a convenience that enforces RFC 10017 §6.1.3.6, not the only path.
- **Documented, not enforced:**
  - `Cache-Control: private, no-store` on per-user responses (OWASP Session Management);
  - pass-through routes that forward browser headers;
  - the TLS requirement of D3.

### D5. Renewal is split by kind (Q5)

**Minted tokens** are re-minted as described in D2. There is nothing to refresh.

**Provider tokens:**

- **What is kept.** A provider configured for forwarding has its access token, refresh token and
  access-token expiry kept on the session the callback creates, sealed and bound to the session's
  row. Other providers discard them, as today.
- **Missing expiry.** A token response without `expires_in` is treated as expiring 5 minutes after
  receipt. The fallback can be replaced by an option.
- **When a refresh runs.** When the accessor finds less than one minute left, it refreshes at the
  provider's token endpoint. The request authenticates as the code exchange does and goes through
  the confined client.
- **Coalescing.** Refreshes of one session are coalesced within one process.
- **Conditional save.** The result is saved by a single write, conditional on the session still
  holding the refresh token that was read.
- **Lost race.** A caller whose conditional write loses reloads the session and uses the winner's
  token. A refresh response without a new refresh token keeps the old one.
- **Rejected refresh.** When the provider answers `invalid_grant`, the provider tokens are cleared
  from the session by a conditional write. The accessor then reports the provider token as
  unavailable, and the session survives, as the user chose. The user keeps the app session and needs
  a new federated sign-in only for provider-backed APIs.
- **Provider outage.** A transport failure, timeout or 5xx is a dependency failure. The tokens are
  kept and nothing is cleared.
- **No refresh token.** A provider that issued no refresh token works until its access token
  expires. After that the accessor reports the token as unavailable.
- **Rotation.** Session rotation on privilege change carries the provider tokens to the successor.
  Deleting the session deletes them.
- **The condition compares a digest.**
  - Sealing is randomised, so a durable store cannot compare a sealed refresh token. The condition
    instead compares the SHA-256 digest of the refresh token, kept unsealed next to it.
  - That is a one-way digest of a high-entropy secret, which `secrets-at-rest` allows.
  - The tokens travel in a carrier type whose only field is a pointer, as upstream access does, so
    they print redacted even through reflection.
- **Only the newest session refreshes.** The conditional replace refuses a superseded session. A
  refresh whose save finds its session superseded saves to the newest successor under the same
  condition. A superseded identifier inside its grace window never refreshes, so two members of one
  family never present one refresh token, which a rotating provider would treat as reuse and answer
  by revoking the grant.

### D6. Wiring mistakes fail at construction

Building the chain fails with a configuration error when outbound tokens are enabled and any of the
following holds:

- the chain has no cookie session;
- an API's resource identifier is empty, not an absolute URI, or carries a fragment;
- two APIs share a resource identifier;
- base URLs of different APIs overlap;
- a minted API has no token generator, or the generator's subject mode disagrees with the chain's;
- a minted lifetime is out of range;
- a provider API names a provider that is not configured;
- a provider is configured to keep tokens that no API uses, because nobody would read that secret;
- a sealing cipher is missing where provider tokens are kept durably (`secrets-at-rest`);
- a provider API is configured and the session store does not implement the conditional
  provider-token replace;
- an API has no source, or more than one.

### D7. Who gets a token

The accessor and the transport return a token only for a request that:

- the session cookie authenticated;
- has a session owing no challenge (second factor or enrolment);
- is still within its context.

Any other request gets a no-token error. That error is distinct from a dependency failure, and
handlers map it to 403 rather than signing the user out.

A request that a signed bearer, a session reference, an API key or a resource-server source
authenticated gets no token. This keeps the feature to the BFF case. A token is never written to a
response, and the chain's "no credential in a body" rule for cookie chains is unchanged.

### D8. Secrets never reach logs

Tokens, provider tokens and refresh tokens print as a fixed redacted text under every verb. They
never appear in an error, an event or a log, as `oidc-login` already requires for upstream access.
Provider error descriptions from a refresh are logged in bounded form only.

## Failure modes

| # | Failure | Category | State | Outcome a caller sees |
|---|---|---|---|---|
| F1 | Key source fails while minting | Dependency | Handled, tested | Dependency error wrapping the cause. Not a no-token error, and the session is untouched |
| F2 | Accessor called on a request the cookie did not authenticate, or with a pending challenge | Security | Handled, tested | No-token error, nothing minted |
| F3 | Minted token carries the session identifier | Security | Handled, tested | Fresh `jti`. The token is refused by the signed bearer and does not open the session as a cookie (UNREPRODUCED until its first test) |
| F4 | Session ends while a minted token is still valid | Security | Accepted | A stateless API accepts it until `exp`, at most 5 minutes. An API that needs immediacy opts in to introspection |
| F5 | Session's absolute deadline is closer than the lifetime | Time | Handled, tested | `exp` is the absolute deadline |
| F6 | Two concurrent requests near a minted token's expiry | Concurrency | Handled | Each may mint. Nothing is stored, so nothing races |
| F7 | Two requests or replicas refresh the same provider token | Concurrency | Handled, tested | Coalesced in-process. Across replicas one conditional write wins, and the loser reloads and uses the winner's token |
| F8 | Provider answers `invalid_grant` to a refresh | Dependency | Handled, tested | Provider tokens cleared, accessor reports the token unavailable, session survives |
| F9 | Provider token endpoint is down, slow or answers 5xx | Dependency | Handled, tested | Dependency error, bounded by the confined client's timeout. Tokens kept |
| F10 | Refresh response has no new refresh token | Input | Handled, tested | The old refresh token is kept |
| F11 | Token response has no `expires_in` | Input | Handled, tested | Treated as expiring after the fallback lifetime |
| F12 | Provider issued no refresh token | Input | Handled, tested | Works until the access token expires, then the token is unavailable |
| F13 | Provider token or response is oversized | Input / Resources | Handled, tested | Response bounded by the confined client. A kept token over 16 KiB fails the login as a provider failure |
| F14 | Session deleted while a refresh is in flight | Concurrency / State | Handled, tested | The conditional write fails on the missing session. No session is re-created, and the accessor returns no-token |
| F15 | Session rotated while a refresh is in flight | Concurrency / State | Handled, tested | The replace refuses a superseded session, and the refresh saves to the newest successor, conditional on its still holding the old refresh token. The new tokens are not lost, and the successor never keeps a refresh token the provider already rotated out |
| F27 | Provider's `expires_in` is zero, negative or absurdly large | Input | Handled, tested | Zero or negative takes the fallback. Over 24 hours is capped at 24 hours, so a hostile value cannot pin a stale token |
| F28 | Consumer token source returns a token with whitespace or control characters | Input / Security | Handled, tested | Refused as a dependency error and never put in a header |
| F26 | Two family members refresh one refresh token: a superseded identifier inside its grace window, and the successor | Concurrency / Security | Handled, tested | Only the newest session refreshes. A superseded one near expiry gets provider-token-unavailable, so the provider never sees a reused refresh token and never revokes the grant (RFC 9700 §4.14) |
| F16 | Sealed provider token copied to another session's row | Security | Handled, tested | It does not open, and the load fails closed as `secrets-at-rest` defines |
| F17 | Transport asked to send to an origin no API covers, or redirected to one | Security | Handled, tested | Refused before sending. No token leaves the process |
| F18 | Outgoing request already carries `Cookie` or `Authorization` | Security | Handled, tested | Cookie removed, `Authorization` replaced |
| F19 | Wiring mistakes from D6 | Configuration | Handled, tested | Configuration error at construction |
| F20 | API forgets to opt out of binding | Configuration | Accepted | The API refuses the token as invalid. Fails closed, and the guide documents it |
| F21 | Provider refresh token still valid at the provider after logout | Security | Accepted | scrty deletes it with the session but does not revoke it at the provider. Revocation is a later option |
| F22 | Provider revokes the user while a minted-token session lives | Security | Accepted | Not noticed, as today. Bounded by the session's idle and absolute deadlines |
| F23 | Tokens printed, logged or put in errors | Observability | Handled, tested | Redacted text under every verb |
| F24 | Request context cancelled during mint or refresh | Concurrency | Handled, tested | Error matching the context's error. A coalesced refresh is not cancelled for the other waiters by one caller's cancellation |
| F25 | Consumer token source fails or returns an empty token | Dependency | Handled, tested | Dependency error, and an empty token is treated as an error, never sent |

## Risks / Trade-offs

- **Two token paths double the surface.** The provider path brings sealed storage, a migration and
  cross-replica refresh. It is off unless a provider is configured for forwarding, and D6 refuses
  keeping tokens nobody reads.
- **Unbound minted tokens.** A token copied off the app-to-API hop is replayable for up to 5 minutes.
  This is mitigated by TLS, the single audience and the short lifetime. DPoP binding is the planned
  follow-up.
- **The provider path depends on the provider issuing refresh tokens**, often only with
  `offline_access`. The guide states it, and the failure is F12.

## Migration Plan

- One security-state migration adds the provider-token columns to the sessions table. They are
  nullable, so existing rows need no backfill.
- Rollback: the columns are unused by older code.

## References

**Researched** (accessed 2026-11-28; read through a summarising fetch tool, section numbers as
reported):

- Q2 / D1-D2:
  - [RFC 10017, OAuth 2.0 for Browser-Based Applications (BCP 212)](https://www.rfc-editor.org/rfc/rfc10017.html):
    the BFF forwards the user's access token to resource servers (§6.1, §6.1.1).
  - [RFC 9068, JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html):
    `at+jwt`, required claims (§2.2) and audience checks (§4), which shape the minted token.
  - [RFC 8707, Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html): one audience per
    resource. Multi-audience tokens need high trust (§3).
  - [RFC 9700, OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html): audience
    restriction and least privilege (§2.3, §4.10).
  - [Duende BFF, remote APIs](https://docs.duendesoftware.com/bff/fundamentals/apis/remote/): forwards
    the user's provider token and strips the cookie.
  - [Spring Cloud Gateway TokenRelay](https://docs.spring.io/spring-cloud-gateway/reference/spring-cloud-gateway-server-webflux/gatewayfilter-factories/tokenrelay-factory.html):
    forwards the provider token.
  - [oauth2-proxy configuration](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/):
    `pass_access_token`, off by default.
  - [RFC 8693, Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html): considered and left out
    (non-goal).
  - [Curity, phantom token pattern](https://curity.io/resources/learn/phantom-token-pattern/) and
    [RFC 7662, Token Introspection](https://www.rfc-editor.org/rfc/rfc7662.html): considered and left
    out. The cache-versus-revocation window is in §4.
- D3:
  - [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): sender-constraining where possible
    (§2.2.1). Its deferral to a later change is a recorded trade-off.
- D4:
  - [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html): outbound destination validation is a
    MUST (§6.1.3.6), and the BFF proxy's duties are in §6.1.1.
  - [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html):
    `Cache-Control: no-store` on session-bearing responses.
- D5:
  - [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html): the BFF keeps the refresh token with
    the session and refreshes it (§6.1.2.2, §9.1).
  - [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): refresh-token protection and rotation
    (§4.14, §4.14.1).
  - [Duende AccessTokenManagement](https://docs.duendesoftware.com/accesstokenmanagement/): automatic
    refresh. Its coalescing behaviour is unverified.
  - [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html):
    the absolute timeout is enforced server-side, which bounds re-minting.
- D2's `jti`, D6 and D7: reasoned from scrty's own settled specs (`http-security-chain`,
  `token-issuance`, `resource-server`, `browser-session`, `sessions`, `secrets-at-rest`) and the
  established design.

**Primary documentation:**

- [RFC 6749 §6, Refreshing an Access Token](https://www.rfc-editor.org/rfc/rfc6749.html#section-6):
  the refresh request and the optional new refresh token (D5, F10).
