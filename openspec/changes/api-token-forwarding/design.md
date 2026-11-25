# Design

## Context

See proposal.md for why. This design is a **candidate**: the three questions below block the specs.
Each gives options, a recommendation and its trade-offs; the recommendation is not a decision.

What exists when this change is applied:

- **`browser-session`:** a cookie chain hands out no credential in a body; the session is the
  single source of truth, with idle and absolute expiry and rotation on privilege change.
- **`token-issuance`:** scrty mints signed access tokens whose `jti` is the session identifier.
- **`resource-server`:** an API verifies JWT access tokens from the chain's own provider or from any
  issuer, against a remote key set, with the audience required and `at+jwt` typing.
- **`oidc-login`:** the provider's access and refresh tokens are discarded after the code exchange,
  as a stated non-goal.
- **`secrets-at-rest`:** a sealing wrapper exists for secret session fields.

## Goals / Non-Goals

**Goals:**
- A handler on a cookie chain can call an internal API as the signed-in user without hand-rolling
  token handling.
- Revocation stays one session delete.

**Non-Goals:**
- A reverse proxy shipped by scrty, unless Q3 chooses it.
- OAuth 2.0 token exchange (RFC 8693) and phantom-token gateways, unless Q2 chooses them.
- Revoking a JWT at a stateless API before it expires.

## Open Questions (blocking)

### Q2. What token does the app send to downstream APIs?

| Option | Shape | For | Against |
|---|---|---|---|
| **A. Forward the provider's access token** | The federated provider's access token, kept sealed in the session, is attached as `Authorization: Bearer`. | APIs trust the provider directly; no scrty issuer in the API path. | `oidc-login` must keep and seal provider tokens and refresh them (Q5). Audience is the provider's choice, often too broad. Local-account sign-ins have no provider token at all. |
| **B. Mint a short scrty token** | Per session, through `token-issuance`, with an API audience. | Uses what exists; works for local and federated sign-ins; claims are scrty's own; no provider tokens stored. | APIs must trust scrty's key set. A stateless API sees a revocation only at expiry, so the lifetime must be short. |
| **C. Phantom token** | An opaque reference exchanged for a JWT per request by a gateway or by introspection. | Revocation is immediate at the edge, and APIs still get a JWT. | An exchange on every request, and a gateway plugin or introspection path to run; usually presumes an API gateway (Q3-C). |

- **Recommendation: B.** Lifetime 5 minutes or less, audience required; APIs verify through
  `EnableResourceServer` against scrty's published key set, which already exists. A is added later
  as an option for APIs that must trust the provider.
- **Trade-off:** revocation reaches stateless APIs only at expiry; APIs that need it immediately
  share the session store and use the session bearer.

### Q3. Who owns the reverse proxy in front of the APIs?

| Option | For | Against |
|---|---|---|
| **A. The consumer** (their ingress, gateway or routes) | scrty stays a library; consumers already run ingress. | Each consumer must strip the session cookie upstream and avoid caching authenticated responses. |
| **B. scrty** (a proxy helper or a standalone proxy) | One tested implementation of cookie stripping, token attachment and header hygiene. | scrty owns a network component and its failure modes: streaming, WebSocket, timeouts, hop-by-hop headers. |
| **C. An API gateway with a phantom-token plugin** (follows from Q2-C) | Revocation at the edge. | Ties scrty to a gateway product, out of character for a library. |

- **Recommendation: A.** scrty documents the obligations (strip the cookie, send only the token,
  `Cache-Control: private, no-store` on authenticated responses). A proxy helper can follow as its
  own change.
- **Trade-off:** correctness of the hop from proxy to API rests on the consumer, documented rather
  than enforced.

### Q5. How are tokens renewed?

| Option | Shape | For | Against |
|---|---|---|---|
| **A. Server-side refresh token** | The provider's refresh token sealed in the session; refreshed shortly before expiry, coalesced per session; a failed refresh ends the session. | Long sessions without re-login; needed by Q2-A. | New sealed session fields and an `oidc-login` change; refresh-token rotation races across replicas need a conditional save; provider outages end sessions. |
| **B. No refresh token** | With Q2-B, a new scrty token is minted when the current one is within one minute of expiry, never beyond the session's absolute deadline, and never stored. | Nothing new to store or seal; revocation is one session delete. | With Q2-A, the session cannot outlive the provider's access token without re-login or a silent `prompt=none` round trip. |

- **Recommendation: B, paired with Q2-B.** A is revisited only if Q2-A is adopted.
- **Trade-off:** sessions are bounded by their absolute expiry (12 hours by default), after which a
  federated user re-authenticates at the provider.

## Decisions

Written once the questions are answered. With Q2-B, Q3-A and Q5-B:

- **Default:** outbound tokens are off. **Override:** enabling them per chain, with a required
  audience and a lifetime of at most 5 minutes; a consumer token source replaces minting entirely.
- Minting runs only for a request the cookie authenticated, so a token is never handed to the
  browser; the accessor returns nothing on any other request.
- Construction refuses an audience that is empty or not an absolute URI, a lifetime over the
  maximum, and outbound tokens on a chain without the cookie session.

## Failure modes (to complete with the decisions)

| Failure | Category | Planned outcome |
|---|---|---|
| Key source fails while minting | Dependency | The handler gets an error; the request is not refused as unauthenticated |
| Token requested on a request the cookie did not authenticate | Security | No token |
| Session ends while a minted token is still valid | Security | Accepted: the API accepts it until expiry, at most the configured lifetime |
| Two concurrent requests near expiry | Concurrency | Each may mint; no shared state is written, so nothing races |

## References

Reasoned from scrty's own settled specs (`token-issuance`, `resource-server`, `browser-session`) and
the established design, plus:

**Researched** (accessed 2026-11-25):
- Q2, Q3: [IETF draft-ietf-oauth-browser-based-apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/): the backend-for-frontend pattern, where tokens stay on the server. Its current status was not verified.
