## Context

See proposal.md for why this change exists. **This design is a candidate, not an agreed approach.** The five open questions below block the specs for `bff-session`, `resource-server` and `csrf-protection`. Every decision after them is written as "if the team adopts the recommendation", and names the question it depends on.

The constraints that shape the approach:

- **Starting point.** When this change is applied, the core module holds every earlier change: sessions, policy, authorization, tokens and signing keys, the `httpsec` chain, the durable stores, and OIDC brokering. There are no consumers or tags.
- **What earlier changes already give a cookie session.**
  - **`sessions`:**
    - unguessable 32-byte identifiers;
    - idle and absolute expiry enforced on every load;
    - the first factor and challenge state recorded as library-owned fields;
    - an update-only save, so a racing logout cannot resurrect a session;
    - a sealing wrapper for secret session fields (`secrets-at-rest`).
  - **`token-issuance` and the bearer path in `http-security-chain`:** an issued token carries the session identifier as its `jti`. Each bearer request:
    - verifies the token;
    - loads the live session;
    - reloads the user;
    - runs the `security-policy` per-request phase with the session's recorded first factor;
    - marks any challenge pending on the session;
    - leaves idle write-back to session touch.

    Revocation therefore works today, because a deleted session refuses its tokens. A cookie session needs the same request pipeline, with the cookie in place of the token as the key.
  - **`http-security-chain`:**
    - the exchange is being revised to a framework-neutral request and response surface, which exposes cookie reads, cookie writes and headers;
    - the login completion seam creates the session, then issues the token, then publishes the authentication;
    - the form-login body already carries an empty `refresh_token` field, because no refresh token exists.
  - **`oidc-login`:**
    - the callback success override replaces the handoff-code tail for a consumer running a cookie session, and obliges that consumer to record the federated session fields in the creating write;
    - the flow cookie is already `HttpOnly; Secure; SameSite=Lax` with a derived, clamped `Max-Age`;
    - `Strict` is ruled out there, because it drops the cookie on the provider's cross-site return;
    - provider access and refresh tokens are discarded after the exchange, as a stated non-goal.
  - **`oidc-login` key-set cache:** jwx v3's cache behind scrty's freshness, unknown-`kid` cooldown, coalescing and failure backoff, fetching only through `outbound-http-confinement`.
- **What does not exist yet:**
  - a cookie that authenticates a request;
  - any CSRF defence;
  - identifier rotation (a satisfied second factor saves the same session under the same identifier);
  - refresh tokens;
  - verification of tokens from another issuer as API credentials.
- **Settled rules:**
  - library-design (safe defaults, full override, construction-time errors);
  - errors propagate and the default response is a bare status;
  - options are named after what they govern;
  - nothing brand-specific in defaults;
  - jwx v3 is the only JOSE stack.

This change departs from no established behaviour. Each mode is new. Where a candidate decision needs another capability to change (identifier rotation in `sessions`, a refusal sentinel in `http-error-propagation`, keeping provider tokens in `oidc-login`), it is flagged rather than restated.

## Goals / Non-Goals

**Goals:**
- A browser app whose tokens never reach JavaScript, with cookie defaults that need no configuration and are safe.
- CSRF protection that a consumer can tune or replace, but cannot remove by omission.
- Cookie requests that are decided by exactly the same session, user reload and per-request policy rules as bearer requests.
- An API that verifies tokens from scrty or another issuer with the same algorithm, issuer and audience discipline as scrty's own verifier.
- A decision record the team can answer question by question.

**Non-Goals:**
- Specs and tasks, until the open questions are answered.
- CORS, security headers and cookie consent.
- OAuth 2.0 token exchange (RFC 8693), introspection (RFC 7662) and DPoP. Each is scoped only if question 2 selects it.
- Opaque-token resource servers. Resource-server mode verifies JWTs only.
- Revoking a JWT before its expiry at a resource server that holds no session store.

## Open Questions (blocking)

These are not deferrable. Each changes the specs, the approach or the task breakdown, so specs are written only after the team answers them. Each question gives options, a recommendation and its trade-offs. The recommendation is not a decision.

### Q1. Where does the BFF live?

| Option | Shape | For | Against |
|---|---|---|---|
| **A. In-app middleware** | The consumer's own server is the BFF. `httpsec` gains a cookie session interceptor and CSRF interceptor. Handlers call APIs with a token the chain puts in context. | No new process. Reuses the chain, adapters, error propagation and policy as they are. Fits scrty's identity as an embedded library. | Every consumer app that fronts APIs must forward tokens itself. Polyglot front ends (a Node SPA server) cannot use it. |
| **B. Standalone proxy** | A separate binary or nested module that terminates the browser session and reverse-proxies to APIs, attaching tokens. | One BFF for many front ends and languages. API routing is centralized. | scrty ships and operates a network component, with configuration, streaming, WebSocket and timeout concerns. It needs a new nested module and a deployment story. |
| **C. A with a proxy helper** | A, plus an optional handler that forwards a path prefix to one upstream with the token attached (a thin wrapper over the standard library's reverse proxy). | Gives B's common case without a separate product. | The helper still inherits proxy concerns: hop-by-hop headers, stripping the session cookie upstream, and body limits. |

- **Recommendation: A first, with C as a later, separate change.**
- **Trade-off accepted:** non-Go front ends are out of scope until C, or a consumer's own proxy, exists.

### Q2. What token does the BFF send to the API?

| Option | Shape | For | Against |
|---|---|---|---|
| **A. Forward the upstream access token** | The provider's access token, kept server-side in the session, is attached as `Authorization: Bearer`. | APIs trust the provider directly. There is no scrty issuer in the API path. | `oidc-login` must stop discarding provider tokens: seal them in the session and refresh them (Q5). The token's audience is the provider's choice, often too broad. APIs see provider-shaped claims. |
| **B. Mint an internal token** | The BFF issues a short-lived scrty JWT per session, through `token-issuance`, with an API audience. | Uses what exists. The session stays the single source of truth. There is no provider token storage and no refresh token. Claims are scrty's own. | APIs must trust scrty's key set. A stateless API cannot see a revoked session before the token expires, so the lifetime must be short. |
| **C. Phantom token** | The browser-side reference is opaque. A gateway or the BFF exchanges it for a JWT per request, through introspection or a local lookup. | Revocation is immediate at the edge, and APIs still get a JWT. | An exchange on every request, and an introspection endpoint or a gateway plugin to build and run. It usually presumes an API gateway (Q3). |

- **Recommendation: B.**
  - Internal APIs verify through `resource-server` against scrty's published key set, with the audience required.
  - A token lifetime of 5 minutes or less bounds how long a revocation takes to reach a stateless API.
  - A is added later as an option for APIs that must trust the provider.
- **Trade-off accepted:** revocation reaches stateless APIs only at token expiry. APIs that need immediate revocation share the session store and use the existing bearer path, which loads the session.

### Q3. Who owns the reverse proxy?

| Option | For | Against |
|---|---|---|
| **A. The consumer** (their ingress, gateway or app routes) | scrty stays a library. Consumers already run ingress. | Each consumer must strip the session cookie before upstream calls, and must not cache authenticated responses. |
| **B. scrty** (follows from Q1-B or Q1-C) | One tested implementation of cookie stripping, token attachment and header hygiene. | scrty owns a network component and its failure modes. |
| **C. An API gateway with a phantom-token plugin** (follows from Q2-C) | Revocation at the edge. | Ties scrty to a gateway product, which is out of character for a library. |

- **Recommendation: A**, consistent with Q1-A. scrty documents the obligations (strip the cookie, `Cache-Control: private, no-store` on authenticated responses, forward only the token).
- **Trade-off accepted:** correctness of the hop from proxy to API rests on the consumer, and is documented rather than enforced.

### Q4. Are local accounts supported through the BFF, or OIDC only?

| Option | For | Against |
|---|---|---|
| **A. OIDC only** | One login path through the callback override. Credentials never touch the BFF. The login surface is smaller. | Consumers with local users must run an identity provider. |
| **B. Local accounts and OIDC** | Form login, magic link and a second factor all end in a cookie session through the same login completion seam. | Login CSRF must be defended on every credential endpoint. The step-up endpoints need a cookie variant. The password-change gate's resolve endpoint must also pass CSRF. |

- **Recommendation: B.**
  - Every scrty authentication path already ends in one login completion step, so delivering a cookie instead of a token is one variation at one seam, not a second implementation.
  - Refusing local accounts would make the BFF unusable for the consumers scrty's default identity store targets.
- **Trade-off accepted:** CSRF and rotation must cover the login, step-up and password-change endpoints, which widens the test matrix.

### Q5. How are tokens refreshed?

| Option | Shape | For | Against |
|---|---|---|---|
| **A. Server-side refresh token** | The BFF stores the provider's refresh token sealed in the session. It refreshes the access token shortly before expiry, coalesced per session, and ends the session when refresh fails. | Long sessions without re-login. Works with Q2-A. | New sealed session fields and a change to `oidc-login` to keep tokens. Refresh-token rotation races across replicas need a conditional save. Provider outages end sessions. |
| **B. Short sessions, no refresh token** | The session's idle and absolute expiry are the only lifetime. With Q2-B, the BFF mints a fresh internal token whenever the forwarded one is near expiry, so no refresh token exists anywhere. | Nothing new to store or seal. Revocation is one session delete. | With Q2-A, the session cannot outlive the provider's access token, so re-login, or a silent `prompt=none` round trip, is needed. |

- **Recommendation: B, paired with Q2-B.** A is revisited only if Q2-A is adopted.
- **Trade-off accepted:** sessions are bounded by the absolute expiry (12 hours by default), and a federated user re-authenticates at the provider after it.

## Decisions

The decisions below assume the recommendations: Q1-A, Q2-B, Q3-A, Q4-B, Q5-B. A different answer changes the decisions named in brackets.

### 1. Candidate architecture [Q1, Q2, Q3]

Browser app through an in-app BFF to an API:

```
 +-----------+   cookie: __Host-session=<id>        +--------------------------------+
 |  Browser  |   header: X-CSRF-Token (unsafe only)  |  Consumer app (the BFF)        |
 |  (SPA)    | ------------------------------------> |  httpsec chain:                |
 |           |                                       |   csrf -> cookie session ->    |
 |  no token | <------------------------------------ |   per-request policy ->        |
 |  in JS    |   Set-Cookie (HttpOnly; Secure;       |   authorizer -> handler        |
 +-----------+   SameSite=Lax), JSON bodies          |                                |
                                                     |  session store  signing keys   |
                                                     +---------------+----------------+
                                                                     |
                                     Authorization: Bearer <internal JWT, aud=api, 5m>
                                     (no cookie forwarded)           |
                                                                     v
                                                     +--------------------------------+
                                                     |  API (resource server)         |
                                                     |  verify: kid, alg, exp,        |
                                                     |  iss, aud (both required)      |
                                                     |  map scope/claims -> principal |
                                                     |  -> authorization              |
                                                     +--------------------------------+
```

Resource server verifying JWTs through a remote key set:

```
 +---------+  Bearer JWT  +--------------------------------------------+
 | Client  | -----------> | Resource server                            |
 +---------+              |                                            |
                          |  1. parse header: kid required, alg in     |
                          |     allowlist, never none                  |
                          |  2. key set cache lookup by kid            |
                          |       hit + fresh ------------+            |
                          |       miss/stale -> refetch   |            |
                          |       (coalesced, cooldown,   |            |
                          |        backoff)               |            |
                          |  3. verify signature  <-------+            |
                          |  4. exp/nbf/iat, iss == configured,        |
                          |     aud contains configured                |
                          |  5. claims mapper -> principal (scopes)    |
                          |  6. authorization rules / guards           |
                          +---------------------+----------------------+
                                                | GET jwks_uri
                                                | (outbound confinement:
                                                |  https, same-origin
                                                |  redirects, size, timeout)
                                                v
                          +--------------------------------------------+
                          | Issuer: scrty /.well-known/jwks.json       |
                          |         or an external provider's jwks_uri |
                          +--------------------------------------------+
```

- **Default:** the BFF is the consumer's own app running the `httpsec` chain. APIs run `resource-server`.
- **Override:** a consumer can run either half alone. A cookie session with no downstream API is valid, and so is a resource server for tokens scrty never issued.
- **Alternatives:** see Q1 to Q3.

### 2. Establishing a cookie session [Q4]

The login completion seam gains a delivery step, chosen per chain:

```go
type SessionDelivery interface {
    Deliver(ex *Exchange, sess *session.Session, principal *identity.Principal) (token string, err error)
}
func WithTokenDelivery() Option  // default today: issue a token, return it in the body
func WithCookieDelivery(opts ...CookieOption) Option
```

- **Order.** The existing `Complete` order holds. With cookie delivery, step 4 ("issue the token") becomes "set the session cookie", and the login response carries no token. A challenge still returns `*ChallengeError` with the session, and its `Token` field is empty. The challenged browser calls the step-up endpoint with the cookie it has just received.
- **OIDC.** Cookie delivery also supplies a callback success function for `oidc-login`. That function creates the session with the `oidc` first factor and the federated fields in the creating write, sets the cookie, and redirects to the sanitized `next`. No handoff code is issued.
- **Default:** token delivery, which is unchanged behaviour. Cookie mode is opt-in per chain, because a chain serving both native and browser clients must choose explicitly.
- **Override:** a consumer `SessionDelivery`.
- **Construction errors:**
  - cookie delivery together with token delivery;
  - cookie delivery without CSRF protection resolvable (Decision 6).
- **Alternative rejected:** setting both a cookie and a body token. The body token would be readable by JavaScript, which defeats the mode.

### 3. Cookie attributes

| Attribute | Default | Override | Limit |
|---|---|---|---|
| Name | `__Host-session` | `WithSessionCookieName` | a name starting `__Host-` or `__Secure-` must satisfy that prefix's rules, checked at construction |
| `HttpOnly` | always | none | never readable by JavaScript: the point of the mode |
| `Secure` | always | none | browsers treat `http://localhost` as a secure context, so local development needs no escape |
| `SameSite` | `Lax` | `WithSessionCookieSameSite(Strict)`; `None` only with `WithCrossSiteSessionCookie()` | `None` is refused unless that explicitly named option is used |
| `Path` | `/` | none while `__Host-` is used | required by the prefix |
| `Domain` | none (host-only) | `WithSessionCookieDomain(d)`, which also requires a non-`__Host-` name | sharing across subdomains exposes the cookie to every subdomain, and this is documented |
| `Max-Age` | derived from the session's absolute deadline, rounded up, at least 1 | none | the server-side idle and absolute expiry from `sessions` stay authoritative |

- **Why `Lax`, not `Strict`:**
  - `Strict` withholds the cookie on any cross-site navigation, so a user following a link from email or the identity provider's return lands logged out;
  - the flow cookie reached the same conclusion;
  - CSRF protection (Decision 6) covers what `Lax` does not.
- **Why `Max-Age` follows the absolute deadline:**
  - a browser-session cookie with no `Max-Age` can outlive a closed tab through browser session restore;
  - a cookie refreshed on every touch would be a write on every response;
  - the idle deadline is enforced on the server, so the cookie never needs to track it.
- **Logout and refused sessions:** logout, and a request whose cookie names a missing, expired or unreadable session, expire the cookie (`Max-Age=-1`, same attributes) and then return the existing refusal.

### 4. The cookie session interceptor mirrors the bearer path

`OrderCookieSession`, placed between `OrderBasicAuth` and `OrderBearerToken`:
1. **No cookie:** pass through as anonymous.
2. **Load the session** by the cookie value:
   - missing or expired: clear the cookie, `ErrAuthenticationRequired`;
   - unreadable: clear the cookie, log at ERROR, `ErrAuthenticationRequired`.
3. **Reload the user** by the session's user reference. A missing user returns `ErrAuthenticationRequired`.
4. **Publish** the authentication, session and principal onto the exchange and context.
5. **Run the per-request phase** with the session's recorded first factor, its MFA state and its last access. A deny refuses. A challenge is marked pending and the request continues, so the gate's resolve endpoint stays reachable.
6. **Session touch** writes back after the handler, as today.

- **A request with both a session cookie and a bearer header** is refused with `ErrAuthenticationRequired` rather than resolved by precedence, because an ambiguous credential is a client or wiring bug.
- **Default:** exactly the bearer path's rules, so the same policy decides the same session the same way whichever credential carries it.
- **Override:** the per-request policies (`security-policy`), and the ambiguity rule through `WithCookieAndBearerTogether(PreferCookie|PreferBearer)` for consumers migrating clients.

### 5. Identifier rotation on privilege change

The session identifier is the cookie value, so an identifier known before a privilege change must not authenticate after it. This is a new requirement, not a departure: in token mode the identifier travels only inside a token the client itself presents, so it cannot be planted. A cookie can be planted, for example by a sibling subdomain when the `__Host-` prefix is dropped.

- **Rotation points, by default:**
  - login (always a new session already);
  - a satisfied second factor;
  - a cleared password-change marker;
  - consumer-triggered through `RotateSession(ex)`, for example after a role change.
- **Mechanism:**
  1. create a new session carrying every field of the old one, with a fresh identifier and the old absolute deadline, so rotation never extends a session;
  2. delete the old session;
  3. set the new cookie.

  A delete failure deletes the new session and returns the error, so a failed rotation never leaves two live identifiers. The CSRF token rotates with the identifier.
- **Needs `sessions`:** a rotate operation whose absolute deadline carries over. It is flagged for `authn-authz-core`, and not restated there.
- **Default:** the rotation points above.
- **Override:** `WithSessionRotation(func(event RotationEvent) bool)` can add events. Removing the second-factor and password-change rotations is refused at construction, because they are the privilege changes fixation targets.

### 6. CSRF: layered, on by default, replaceable but not removable

Compared:

| Scheme | How it works | Strength | Weakness |
|---|---|---|---|
| Synchronizer token | A random token stored with the session, sent by the client in a header, compared in constant time | Independent of browser headers; no secret to configure, because the session store holds it | Needs the session loaded first; the SPA must read the token somewhere |
| Signed double-submit | A cookie holding an HMAC over the session identifier and a nonce, echoed in a header | No server-side storage | Needs a consumer secret, so it cannot be a zero-configuration default; subdomain cookie injection is possible without `__Host-` |
| Fetch Metadata / Origin | Refuse unsafe methods whose `Sec-Fetch-Site` is `cross-site` or `same-site`, falling back to comparing `Origin` with the request's own origin | No token plumbing; stops the attack at the browser boundary | Browsers without Fetch Metadata that also omit `Origin` pass through; it relies on the browser |

**Recommended default: both layers, in order.**
1. **Header layer:**
   - runs before the session is loaded, so a cross-site request never touches the store;
   - applies to unsafe methods (everything except `GET`, `HEAD`, `OPTIONS`);
   - refuses `Sec-Fetch-Site` values `cross-site` and `same-site`;
   - when the header is absent, compares `Origin` using the existing origin comparison and refuses a mismatch;
   - passes a request carrying neither header on to layer 2.

   The rules mirror the standard library's cross-origin protection, and a conformance test checks the two agree.
2. **Token layer:**
   - runs after the session is loaded, on unsafe methods that carry a session cookie;
   - the session holds a 32-byte `crypto/rand` token as a library-owned field;
   - the client sends it in `X-CSRF-Token`;
   - it is delivered in a readable `__Host-csrf` cookie, set with the session cookie and rotated with it.

   The token is not a secret from the page's own scripts, only from other origins.
- **Login CSRF:** the header layer also guards credential endpoints that have no session yet (form login, magic-link redemption), so an attacker cannot log a victim into the attacker's account.
- **Bearer-only requests** skip both layers. A cross-site page cannot attach an `Authorization` header without CORS consent.
- **Refusal:** a new `ErrCSRFRejected` sentinel, mapped to 403 with a bare status. It needs a row in `http-error-propagation`'s table, flagged for `http-security`. Refusals are logged at WARN, sampled per flow and reason, with a reporter.
- **Default:** both layers, whenever cookie delivery is enabled.
- **Overrides:**
  - `WithTrustedOrigins(origins...)`, validated like redirect origins;
  - `WithCSRFExemptPaths(paths...)`, exact match only, for example a webhook, and refused when it overlaps a credential endpoint;
  - `WithCSRFTokenHeader(name)` and `WithCSRFCookieName(name)`;
  - `WithCSRFProtector(p CSRFProtector)`, which replaces both layers with the consumer's own, for example signed double-submit using their secret.
- **Stated limits:**
  - there is no option that disables CSRF protection, and a nil protector is refused at construction;
  - `WithCSRFHeaderLayerOnly()` exists, and its godoc states exactly what it gives up: old browsers that send neither header.
- **Alternative rejected:** double-submit as the default, because it needs a secret the consumer must configure.

### 7. Resource-server verification [Q2]

```go
package resource
func NewVerifier(opts ...Option) (*Verifier, error)
func WithIssuer(iss string) Option               // required
func WithAudience(aud string) Option             // required
func WithJWKSURI(uri string) Option              // default: from the issuer's discovery document
func WithAlgorithms(algs ...string) Option        // default RS256; none refused; HS* refused
func WithClockSkew(d time.Duration) Option       // default 60s
func WithRequiredTokenType(typ string) Option    // default: not checked; "at+jwt" recommended
func WithClaimsMapper(m ClaimsMapper) Option     // default: Decision 8
func WithKeySetCache(...) Option                 // oidc-login cache options, same names and defaults
```

- **Verification** uses jwx v3:
  - `kid` required;
  - the key's algorithm must be in the allowlist;
  - `exp` required;
  - `nbf` and `iat` must not be in the future, beyond the skew;
  - `iss` must equal the configured issuer;
  - `aud` must contain the configured audience.
- **Errors:** every rejection joins `authn.ErrAuthenticationFailed` with the cause, which maps to 401. A key-set fetch failure is a server error, not an authentication failure.
- **Key sets** reuse the `oidc-login` cache semantics as they are, not reimplemented:
  - TTL 15 minutes;
  - one refetch on an unknown `kid` per 30-second cooldown;
  - coalesced fetches;
  - failure backoff;
  - stale-while-error off;
  - fetches only through `outbound-http-confinement`;
  - a `Start`/`Stop` lifecycle.

  The cache is extracted to a shared internal package when this is implemented.
- **Issuer and audience are required, not optional as in scrty's own verifier.** A resource server accepts tokens minted elsewhere, and an unchecked audience lets a token for one API, or an ID token, be replayed at another. Missing either is a construction error.
- **Why `typ` is not required by default:** common providers issue `typ: JWT` for access tokens, so requiring `at+jwt` would refuse them. The required audience already rules out ID tokens, whose audience is the client identifier, provided the API's audience differs from it. The godoc states that condition.
- **scrty as issuer:**
  - with Q2-B, the BFF's generator is configured with the API audience;
  - the API points `WithIssuer` and the key set at the BFF's issuer and `/.well-known/jwks.json`;
  - a rotated key signs at once, so the API's unknown-`kid` refetch covers it.
- **Default:** stateless verification. No session lookup and no user reload.
- **Override:** an API that shares the session store uses the existing bearer path instead, which loads the session and sees revocation at once.

### 8. Scopes and claims to authorization

```go
type ClaimsMapper func(ctx context.Context, c VerifiedClaims) (*identity.Principal, error)
```

- **Default mapper:**
  - `sub` becomes `Principal.ID`, opaque and never parsed;
  - `scope` (space-delimited) or `scp` (array) becomes `Principal.Scopes`;
  - no roles;
  - `Kind` is user, or service when `sub` equals `client_id` or `azp`;
  - every claim is carried unchanged in `VerifiedClaims` for the consumer.
- **Authorization:** `authorization`'s `HasAnyScope`, `HasAllScopes` and the privilege requirements apply unchanged.
- **Roles:** there is no default role mapping, because role claims are issuer-specific. A consumer maps a claim path to roles in their mapper. An unmapped role never grants a privilege.
- **Policy phase:** the stateless authentication phase runs with no first factor recorded. By `security-policy`'s rule an unrecorded first factor is enforced, so the MFA requirement policy refuses a required user on a resource server.
  - This is correct for a token that proves nothing about a second factor.
  - It is stated as a limit until `oidc-mfa-assurance` defines how `amr`/`acr` claims map to assurance.
  - A consumer wanting the issuer's word configures no engine on the resource server.
- **Default:** the mapper above.
- **Override:** `WithClaimsMapper`. A mapper error is returned unchanged.

### 9. Refresh [Q5]

- **Default, with Q2-B and Q5-B:** there is no refresh token.
  - The BFF keeps the internal token it minted on the session's request context only, and never stores it.
  - It mints a new token when the current one is within one minute of expiry, and never beyond the session's absolute deadline.
  - The session's idle and absolute expiry are the whole lifetime. Revoking is deleting the session.
- **If Q5-A is adopted:**
  - `oidc-login` keeps the provider refresh and access tokens, sealed by `secrets-at-rest` in new session fields;
  - refresh is coalesced per session, and a rotated refresh token is written with a conditional save so two replicas cannot both spend it;
  - a failed refresh deletes the session.

  This modifies `oidc-login` and `sessions`, and is not written here.
- **Override:** a consumer token source for outbound API calls, `WithAPITokenSource`.

### 10. Construction refuses what cannot take effect

Refused:
- cookie delivery with token delivery;
- cookie delivery with a nil CSRF protector;
- `SameSite=None` without `WithCrossSiteSessionCookie`;
- a `__Host-` name with a domain;
- CSRF exempt paths overlapping credential endpoints;
- trusted origins that fail origin validation;
- removal of the mandatory rotation events;
- a resource verifier without an issuer or audience, or with `none` or `HS*` in its algorithms;
- non-positive skew or cache durations.

### 11. Test-first

- **Conformance:** one scenario table on net/http, gin and fiber covering:
  - the cookie attributes;
  - clearing a cookie on refusal;
  - both CSRF layers with every `Sec-Fetch-Site` value, `Origin` present, absent and mismatched;
  - an old-browser request with neither header;
  - login CSRF;
  - the cookie-and-bearer ambiguity.
- **Rotation:**
  - the pre-rotation identifier refuses after a second factor;
  - the absolute deadline is unchanged;
  - an injected delete failure leaves exactly one live session.
- **Policy parity:** the same per-request policy table run through the bearer and cookie paths must give the same outcomes.
- **Resource server:** the `oidc-login` test identity provider's malformed tokens, plus:
  - a token for another audience;
  - an ID token presented as an access token;
  - a rotated key;
  - a key-set outage.
- **Header layer:** the standard library cross-origin protection as an oracle.

## Risks / Trade-offs

- [The team answers a question differently] → Each decision names its questions. Only those decisions change, and specs start after the answers.
- [`Lax` lets top-level cross-site `GET` requests carry the cookie] → State-changing endpoints must not accept `GET`. The unsafe-method rule and the godoc state it. `Strict` is one option away.
- [A consumer serves a state change on `GET`] → Documented as outside CSRF protection. The chain cannot know a handler's side effects.
- [Stateless APIs see a revoked session only when the internal token expires] → The internal token lifetime is 5 minutes. APIs needing immediate revocation use the session-backed bearer path.
- [The readable CSRF cookie is exposed to scripts on the page] → Only same-origin scripts can read it, and those can already act as the user. It is not an authentication credential.
- [Old browsers with neither Fetch Metadata nor `Origin`] → The token layer covers them. The header-only option documents the gap.
- [Rotation doubles writes at login-adjacent events] → Rotation happens only at privilege changes, not per request.
- [An unrecorded first factor makes MFA-required users fail at resource servers] → A stated limit until `oidc-mfa-assurance`. The consumer can omit the engine.
- [The shared key-set cache couples `resource-server` to `oidc-login` internals] → Extract it to one internal package with its own tests, so both callers run the same code.
- [Proxy obligations under Q3-A are the consumer's] → Documented checklist: strip the cookie upstream, `no-store` on authenticated responses, forward only the token.

## Migration Plan

Not applicable: a new library with no consumers and no tags. Cookie delivery is opt-in, so the token delivery that earlier changes specify stays the default.
