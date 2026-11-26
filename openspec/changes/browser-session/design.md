# Design

## Context

See proposal.md for why. Each decision below names the alternatives considered and why they lost.
The user accepted these decisions on 2026-11-25 (user decision).

What the code already gives a cookie session:

- **The session-reference pipeline.** `EnableSessionBearer` (slot `OrderBearerToken`, 500) reads
  the session identifier from `Authorization`, then: shape check, load by digest, reuse detection
  with family revocation, user reload, per-request policy, per-source throttling of refused
  references, and the outage-versus-refusal split. With it on, every issuing endpoint hands out the
  session identifier (`issueSessionReference`, chosen by `config.credentialIssuer`).
- **CSRF.** `CookieAuthenticator` makes `New` refuse a cookie authenticator without
  `EnableCSRFProtection` (or the explicit opt-out), and refuses one ordered at or before
  `OrderCSRF` (75). Sign-ins carry a CSRF token that survives every rotation (`sessions` spec).
- **Rotation.** Second-factor verification (`mfa_verify.go`) and re-authentication
  (`reauth_resolve.go`) already rotate through `session.Sessions.RotateIssuing`, in every mode.
  Renewal rotates with a grace window (`RotateWithGraceIssuing`). The active-role switch
  (`SelectRole`) and the password change at the gate's resolve endpoint (`Save`) keep the
  identifier. The `bff-resource-server` draft stated that a satisfied second factor keeps its
  identifier; that is no longer true and is not carried forward.
- **Provider linkage.** The session manager reports every explicit end of a sign-in (logout, reuse,
  revocation, deletion) to its end observers, and the chain refuses to build the provider unless the
  manager reports to it. Chain logout ends the sign-in at the provider first, and fails retryably
  when a provider store fails.
- **Responders.** Each issuing endpoint already has a replaceable responder (`WithLoginResponder`,
  `WithMagicLinkResponder`, `WithRenewalResponder`, …). OIDC login has `WithOIDCCallbackSuccess`,
  which replaces the handoff code.
- **Magic link.** Field names are constants (`DefaultMagicLinkAddressParam`, `…NextParam`,
  `…TokenParam`); the body limit is a fixed field with no option. An oversized body is read as
  empty, which keeps the request endpoint's answer uniform.

The established design had no cookie session, so nothing here departs from it. The decisions rest on
scrty's own settled specs, the established design's patterns, and the sources listed in References.

## Goals / Non-Goals

**Goals:**
- One implementation of the session-reference checks, used by both transports.
- No path on a cookie chain that writes a credential anywhere JavaScript can read it.
- Every override bounded by a stated line, checked at construction.

**Non-Goals:**
- The pages that will use this (later changes), and any HTML rendering.
- Tokens for downstream APIs, a reverse proxy, refresh tokens (`api-token-forwarding`, later).
- Cross-site cookies (`SameSite=None`) and a chain that issues both cookies and tokens.

## Decisions

### 1. Scope: the cookie session only; `bff-resource-server` is superseded

The draft's other capabilities landed elsewhere (`csrf-protection`, `resource-server`). Its Q2, Q3
and Q5 (downstream token, proxy, refresh) move to a later `api-token-forwarding` change with the
draft's candidates as its starting point; the draft is retired in a separate step.
- **Alternatives:** keep the draft and answer all five (blocks the pages on unrelated questions); a
  new change beside the old one (two overlapping changes).

### 2. In the consumer's app, for local and federated sign-ins

The session lives in the consumer's chain, because the pages are served from it. Every sign-in path
can create it, because they all end in one completion step and most planned pages are local-account
pages.
- **Default:** no cookie session; it is opt-in per chain.
- **Override:** none needed now. A consumer who wants federated sign-in only enables only
  `EnableOIDCLogin`; a construction check that enforces it can be added later.
- **Alternatives:** a standalone proxy (scrty becomes an operated product); OIDC only (leaves most
  planned pages with nothing to talk to).

### 3. One session-reference pipeline, two transports

The body of `sessionBearer.Intercept` after the header read is extracted into a shared pipeline
that takes the identifier and a transport descriptor (header or cookie) and returns the same
outcomes it returns today. `EnableSessionCookie(deps SessionBearerDeps, opts ...SessionCookieOption)`
wires it at `OrderBearerToken`, reading the identifier from the cookie, and implements
`CookieAuthenticator`. It reuses the session-bearer limiter defaults
(`WithSessionCookieLimiter` replaces it) and calls `CheckCSRFToken` with the loaded session for
unsafe methods before publishing.
- **Default:** cookie name `__Host-scrty-session`; 100 refused references per minute per source, as
  the session bearer.
- **Override:** the options in decisions 7 and 8.
- **Why extract rather than copy:** the six checks are where security bugs live; a second copy
  doubles where they can hide. The existing session-bearer suite runs unchanged against the
  extracted pipeline and is the refactor's safety net.
- **Alternative:** a separate interceptor with its own copy (the draft's `OrderCookieSession`).
- **Settled during implementation:**
  - The pipeline reports whether it judged and refused the reference, or refused without judging
    it; only the former expires the cookie (decision 11).
  - Every `Cookie` header line is parsed, not just the first value. Two values under the session
    cookie's name, or an empty, quoted, oversized or illegal value, are a malformed presentation:
    refused with no lookup, counted against the source, and the cookie expired.
  - A session bound to a sender key (DPoP or certificate) presented as a cookie is refused,
    counted and expired: a cookie carries no proof, so honouring it would let a stolen bound
    reference skip its binding.
  - A user refused on reload (disabled, gone, or not the session's user) expires the cookie, like
    every refusal the pipeline counts against the source.
  - CSRF is checked on the loaded session before the user reload, so an unsafe request without a
    token from a disabled user is answered 403, not 401. A CSRF token source that answers with the
    authentication-required error is treated as a CSRF failure: not counted, cookie kept.
  - The cookie value is never recorded as the request's presented bearer credential, so it can
    never feed a DPoP `ath` binding. Rotations read the loaded session, not the presented value.
  - The cookie transport has its own flow name, `session-cookie`, for refusal logs, sampling and
    the rate-limiter namespace, so cookie and header refusals are told apart and limited apart.

### 4. Delivery is per chain, behind a bounded port

With `EnableSessionCookie` on, `config.credentialIssuer` returns the session identifier, as for the
session bearer, and every issuing endpoint hands the credential to a delivery step instead of its
response body: the default sets the cookie (decision 7) and returns nothing for the body. Issuing
endpoints in scope: form login, magic link redemption, OIDC callback (decision 6), passwordless
passkey login, second-factor verification, re-authentication, recovery completion, session
renewal. A `ChallengeError` raised on a cookie chain carries the session but an empty `Token`.

`New` refuses `EnableSessionCookie` with `EnableSessionBearer` or `EnableBearerToken`. A consumer
serving browsers and native clients builds two chains; one takes `WithBasePath`, as the collision
check already requires.

- **Default:** cookie delivery.
- **Override:** `WithSessionDelivery(SessionDelivery)`, a port that writes the credential.
  The line: the port returns `(bodyCredential string, err error)`; a non-empty `bodyCredential` for
  a request the cookie authenticated (renewal, second factor, re-authentication) is refused as an
  issuing failure before anything is written. On a fresh sign-in (no cookie yet) it is also
  refused, because the chain is a cookie chain. The port therefore customises how the cookie is
  written (extra attributes, audit), not whether a token leaks.
- **Alternatives:** per request, chosen from headers (a script chooses token delivery); no port
  (no control for unusual setups).
- **Settled during implementation (departs from the wording above):**
  - On a cookie chain the credential issuer hands back no credential at all; the delivery step
    reads the identifier from the stored session. No endpoint holds the identifier, so a missed
    delivery shows up as a missing cookie rather than a leak. A token generator given to an issuing
    endpoint on a cookie chain is a construction error.
  - The port is handed a copy of the session and writes into a holding writer. Its writes reach
    the response only if it returned no error and no body credential, wrote no body or status, set
    the session cookie with exactly the chain's attributes (name, value, path, domain, same-site,
    secure, http-only, max-age), and placed the identifier nowhere else (no other header, cookie
    name or attribute). Anything else is an issuing failure.
  - Any delivery failure ends the sign-in: the whole session family is revoked, including the
    session a rotating request presented, on a context the client's hang-up cannot cancel, bounded
    by the same timeout logout's revocation uses. A port that panics ends the sign-in the same way
    before the panic continues; the library does not swallow it.
  - The port's exchange is a detached copy with its own session and none of the request's
    per-request state; publishing a caller or evaluating per-request policy on it is a
    configuration error, so nothing the port does on it reaches the request. The copy is shallow below
    that: the principal is shared, so a port that edits the principal in place changes the caller.
    Accepted: the port is trusted code, and its godoc says not to.
  - The identifier check is literal. It catches a port's mistakes, not a hostile port: an encoded
    copy of the identifier (base64 in a header, say) is not detected. A delivery port is trusted
    code, as every consumer port is.
  - The OIDC provider's own federated completion already discards its credential and keeps doing
    so; it sets no session cookie.

### 5. Both credentials on one request are refused, before either is read

A small guard registered at `OrderCSRF + 5` (80) on cookie chains refuses, with
`ErrAuthenticationRequired`, any request that carries the session cookie and an `Authorization`
header, before Basic (400), the resource server (425) or the cookie session (500) read anything.
- **Default:** refuse. **Override:** none; leniency would make the caller's identity depend on
  interceptor order. A named option stating which credential wins can be added if a real
  deployment needs it.
- **Alternatives:** header wins; cookie wins (both silent).
- **Settled during implementation:**
  - The guard judged neither credential, so its refusal neither counts against the source nor
    expires the cookie.
  - Every built-in authenticator ordered before the cookie session reads `Authorization`, so the
    guard covers them. A consumer authenticator reading its own header is not visible to the
    guard, so the cookie session also refuses, before reading the cookie, whenever another caller
    is already published (unless it is the session this cookie names). A consumer interceptor that
    publishes a default or anonymous caller before the cookie session therefore locks out every
    cookie request; its godoc says so.
  - The OIDC provider's outer endpoints (authorization, token, userinfo, revocation,
    introspection, end-session, device authorization, and the discovery and key-set documents) authenticate by their own credential and never read the
    chain's session, so on a chain that runs the provider with the cookie session the guard exempts
    exactly those paths; the provider's inner, sign-in-dependent routes stay guarded. Without the
    exemption a first-party page on the same origin calling userinfo with an access token would be
    refused, because the browser sends the cookie on its own. Built in task 12.2, with the
    provider's chain check accepting the cookie session as its bearer mode.
  - The exemption is the set of outer paths the provider's outer router actually serves, resolved
    at construction after the base path and path overrides, and matched by exact equality against
    `Request.Path()`, the comparison the outer router itself makes on every adapter. A path that
    decodes to an exempt one (`/oauth2/user%69nfo`) is exempt because the router answers it; a
    trailing slash, a doubled slash, another case or the bare prefix stays guarded. The key set is
    exempt for GET only, since it passes other methods down the chain. An endpoint the provider
    does not serve (a disabled device grant) adds no exemption.

### 6. Federated sign-in completes in the callback

On a cookie chain with no consumer `WithOIDCCallbackSuccess`, the chain supplies one: it runs the
login completion with the `oidc` first factor and the federated fields in the creating write, sets
the cookie, and answers `303` to the destination the redirect allowlist resolved. `New` refuses a
handoff manager on a cookie chain, as `WithOIDCCallbackSuccess` already does. A challenge raised by
the post-authentication phase leaves the cookie of the pending session and still redirects; the
pending-challenge refusals on later requests are what a page answers.
- **Default:** that callback. **Override:** `WithOIDCCallbackSuccess`, unchanged.
- **Settled during implementation:**
  - The callback reloads the user through the cookie session's user loader; an unknown, inactive
    or mismatched user is refused as handoff redemption refuses one, though no handoff exists.
  - Because the stored user is what signs in, role sync, the redemption-only options and
    `WithOIDCTokens` are configuration errors on a cookie chain without `WithOIDCCallbackSuccess`.
  - The callback always answers `303`; a browser is the only thing that follows an authorization
    response, so it does not negotiate.

### 7. Negotiated answers and the destination

Every issuing endpoint's default responder on a cookie chain negotiates:
- **HTML:** the request's `Content-Type` is a form (`application/x-www-form-urlencoded` or
  `multipart/form-data`), or its `Accept` prefers `text/html` to `application/json`. Answer
  `303 See Other` to the destination, `Cache-Control: no-store`.
- **JSON:** otherwise. Answer `200` with `{"idle_expires_at": "<RFC 3339>"}` and no credential.

Destination: the endpoint's existing destination where it has one (magic link and OIDC already
resolve theirs through an allowlist); otherwise the `next` form field (or JSON member), accepted
only as a relative path that begins with exactly one `/` and contains no `\`, or as a target the
consumer allowlisted exactly; anything else is `/`.
- **Default:** as above; field `next`; no allowlisted absolute targets.
- **Override:** each endpoint's responder option, unchanged; `WithSessionCookieNextParam(name)`;
  `WithSessionCookieRedirects(targets ...string)`, exact matches, validated as absolute `https`
  URLs at construction.
- **Alternatives:** always redirect (breaks the later React components); always JSON (breaks plain
  forms).
- **Settled during implementation:**
  - A form `Content-Type` wins over `Accept`, so endpoints that read form bodies only (magic-link
    redemption, TOTP verification, password re-authentication, recovery) always redirect; a script
    that posts a form gets a `303`. `Accept` is ranked by `q` only, at most 64 ranges are read,
    and a malformed header reads as JSON.
  - Recovery completion that reissues codes answers `200` JSON with `idle_expires_at`, the codes,
    `remaining` and `low` (members omitted when none were reissued), whatever the request prefers: the codes exist in readable form only in
    that answer, and a redirect would lose them. Codes are not a session credential. Without
    reissued codes it negotiates like every other endpoint.
  - `next` is read from a URL-encoded or JSON body only, never the query, and at most 64 KiB of it.
    A repeated or non-string member, a multipart body, or an oversized body resolves to `/`.
  - The same-origin rule is stricter than stated above: the raw value must be printable ASCII
    without spaces, and a malformed `%` escape, or DEL or a C1 control after decoding, resolves
    to `/`.

### 8. Cookie attributes

| Attribute | Default | Override | Line, checked by `New` |
|---|---|---|---|
| Name | `__Host-scrty-session` | `WithSessionCookieName` | a valid cookie name; a `__Host-` name takes no `Domain` |
| `Path` | `/` | none | required by `__Host-` |
| `Secure`, `HttpOnly` | always | none | browsers treat `http://localhost` as secure, so local development needs no escape |
| `SameSite` | `Lax` | `WithSessionCookieSameSite(http.SameSiteStrictMode)` | `None` and `Default` refused |
| `Domain` | none | `WithSessionCookieDomain` | needs a `__Secure-` name |
| `Max-Age` | none | decision 9 | never past the absolute deadline |

`Lax`, not `Strict`: `Strict` drops the cookie on any cross-site navigation, so a user following a
link from email or returning from an identity provider would land signed out; the OIDC flow cookie
reached the same conclusion. CSRF protection covers what `Lax` leaves.

### 9. Persistence per sign-in, recorded on the session

`WithSessionCookiePersistence(decide func(*Exchange) bool)` is asked at every new sign-in. True
creates the session with the new `session.WithPersistentCookie()` create option, which sets the
library-owned `Session.PersistentCookie` in the creating write; every rotation carries it, and
`Save` keeps the stored value, as `MFAAtFirstFactor` works today. A persistent cookie's `Max-Age`
is the seconds to the session's absolute deadline, rounded up, at least 1. A chain-wide choice is
`func(*Exchange) bool { return true }`.
- **Default:** nil decision; every cookie is a browser-session cookie.
- **Why on the session:** a rotation has no sign-in form to ask again, and the browser does not send
  `Max-Age` back, so the choice must be stored to survive rotation.
- **Cost:** a new `scrty_sessions.persistent_cookie boolean NULL` column through one new
  security-state migration, in `sqlstore`, `pgxstore`, `gormstore` and the conformance suite. As
  the project's added columns do, it is nullable with no default, so adding it rewrites no row, and
  a NULL reads as unset: a sign-in from before the migration gets a browser-session cookie, the
  fail-closed reading.
- **The provider's refresh-token lineage table takes the column too.** `scrty_op_refresh_tokens`
  mirrors `scrty_sessions` column for column, and the session statements run over both, so the same
  migration adds `persistent_cookie boolean NULL` to it. Found during implementation; the existing
  test that the lineage table mirrors the sessions table would otherwise fail.
- **Alternatives:** persistent by default with `Max-Age` on every cookie (the draft's candidate;
  unsafe on shared machines); chain-wide only (no "remember me").
- **Note:** a chain-wide option and a per-form-login option were both considered; one decision
  function asked at every sign-in path covers both with one option.
- **Settled during implementation:**
  - The decision is asked once per sign-in, before anything is stored, on every path: form login,
    passwordless passkey, magic link, both federated paths, and recovery. A decision that panics is
    the consumer's panic; nothing is stored.
  - `Max-Age` is computed by the chain's clock and capped at `MaxInt32`. A delivery port that
    computes it itself may read the clock a second later, so the port's cookie passes the exact
    check with the expected `Max-Age` or one second less, never below 1: shorter is the safe
    direction.
  - At a password change on a recovery-pending sign-in, the re-set cookie's `Max-Age` follows the
    absolute deadline the session will have once the change is saved, not the lowered recovery
    one; otherwise the browser would drop a cookie whose session is still live. If the change is
    refused, the cookie outlives the session, and the server refuses the session and expires it.
    A role switch made inside the change function re-sets the cookie with the same restored
    deadline, so the last cookie the browser keeps matches the saved session.
  - `Max-Age` is never set past the deadline the session has, or will have once the request's
    change is saved. A deadline lowered later without a new cookie (a per-request policy marking
    enrolment pending) leaves the cookie longer-lived; accepted, since the server's deadline is
    authoritative.

### 10. Rotation on privilege change: on by default, opt-out only for the rotations this change adds

On a cookie chain, the active-role switch and the password change at the password-change gate's
resolve endpoint rotate through `RotateIssuing` and re-set the cookie. Second-factor verification
and re-authentication already rotate and keep doing so; on a cookie chain they re-set the cookie.
Sign-in always creates a new session.
- `SwitchActiveRole` gets the request's response through the chain-owned role source it already
  reads from the context, so it can re-set the cookie; called on a context the chain did not
  resolve, it fails as today.
- **Default:** all four rotate.
- **Override:** `WithoutSessionRotation(RotateOnRoleSwitch, RotateOnPasswordChange)`, each named;
  its documentation states that it reopens session fixation for those changes.
- **Line:** no option turns off rotation at second-factor verification or re-authentication. They
  rotate today in every mode and the `sessions` spec relies on it; offering an off switch would
  weaken a guarantee scrty already makes. The user asked for both behaviours to be selectable
  ("i still need both applicable selection", user decision, 2026-11-25); this line keeps that
  choice for every rotation the change adds, and not for the two that already exist.
- **Alternatives:** rotate only at sign-in (leaves session fixation open at every later privilege
  change); both behaviours as equal peers (nothing safe by default).
- **Settled during implementation (departs from the wording above):**
  - The role switch and the password change rotate with a grace window
    (`RotateWithGrace`), the renewal endpoint's grace when the chain has one, otherwise
    `session.DefaultRenewalGrace`. A strict rotation never reports reuse, so "Old identifier
    presented late" could not hold, and a second tab's in-flight request would be refused and expire
    the new cookie.
  - The password change rotates and re-sets the cookie before grants are revoked and before the
    consumer's change function runs, because that function owns the response and a cookie set after
    it has begun never reaches the browser. A refused change therefore still rotates, which only
    issues a fresh identifier. A recovery-pending session rotates too.
  - On a cookie chain, `SwitchActiveRole` called on a context kept past its request is a
    configuration error and changes nothing: the response is gone, and a rotation the browser never
    learns of would make its next request reuse. With the role-switch rotation turned off it
    behaves as on any chain, since no cookie is owed.
  - `WithoutSessionRotation` accepts a repeated point, or the option given twice, as the union:
    asking twice weakens nothing more than asking once. An empty list, `0` or an unknown point is
    `ErrConfig`.
  - Accepted: with the password-change rotation off, a persistent cookie is not re-set, so on a
    recovery-pending sign-in it keeps the lowered recovery deadline as its `Max-Age`. The browser
    drops it before the server would refuse the session, the fail-closed direction; documented on
    the option.
  - The role is recorded in the rotation's own write (user decision, 2026-11-26). A new
    `session.WithSuccessorRole(role string)` rotate option, taken by `RotateWithGrace` and
    `RotateWithGraceIssuing`, sets `Supersession.SuccessorRole` (a `*string`); `Store.Supersede`
    then gives the successor that role instead of the old record's stored one, inside the same
    atomic operation, and the empty role clears it. Without the option the store carries the old
    role as today. `Sessions` compares the role the store writes back to `Successor.SelectedRole`
    with the one asked for, and a store that ignored the field fails the rotation with a
    store-contract error; the store-conformance suite pins the behaviour on every backend. The
    role switch uses it, so a logout landing before the write makes the switch fail with
    `ErrAuthenticationRequired`, no cookie re-set and nothing stored, and a logout landing after it
    is an ordinary later logout. This replaces the earlier two writes (rotation, then
    `SelectRole`), whose gap let a failed switch still re-set a cookie naming a successor the
    logout had deleted.
  - Accepted: a role switch called after the handler began its response stores the rotation but the
    re-set cookie is dropped; the old identifier becomes reuse after the window and the sign-in is
    revoked, the fail-closed outcome. No writer exposes whether the response began; the godoc says to
    switch before writing.
  - The password change's resolution is saved on the latest successor the chain holds in memory
    (after any role switch made inside the change function), never reloaded from the store: the
    store's `Save` keeps the stored selected role, so nothing is erased and no read or presentation
    mark is added. The target comes from the chain, never from the consumer-writable
    `Exchange.Session`; a target of another user or family is refused and nothing is saved. That
    refusal is unreachable through the public API and is tested on the internal function.
  - A switch whose rotation fails, including one refused because the store ignored the requested
    role, sets no cookie and leaves the role unchanged; the user retries on a live session.

### 11. Ending the cookie

- Logout success: the cookie is expired with the attributes it was set with (`Max-Age=0`).
- A cookie refused because its session is missing, expired, unreadable or reused: the refusal
  response expires the cookie.
- A store or cipher outage while loading: the cookie is left alone, because the session may be fine.
- A request refused without its session being judged keeps the cookie too: the source over its
  allowance, the source limiter unable to answer, and a CSRF failure on an unsafe method. Expiring
  on these would let one abusive client behind a shared address, a limiter outage, or a cross-site
  page sign every affected browser out. The shared pipeline therefore tells its caller whether it
  refused the reference itself or never judged it, and only the former expires the cookie.
  (Decided during implementation, from the review of the pipeline extraction.)
- A logout that fails on a provider store: nothing is expired, the session stays, and the logout
  can be retried, as the chain's logout already guarantees.

### 12. The provider's browser sessions end with the sign-in

Kept as two records (the chain session, the provider's `BrowserSession`), linked by the sign-in.
The linkage already exists: the manager reports every explicit end to the provider, and the chain
refuses to build the provider without it. This change adds the `browser-session` requirement and
tests that the cookie path's ends (logout, reuse detected through the cookie, revocation) reach it.
The provider today refuses to build on a chain without a bearer mode; this change lets it build on a
cookie chain, taking the cookie session as the sign-in its inner routes depend on (task 12.2).
- **Alternatives:** merge into one record (rewrites a settled provider design); one cookie value
  keying both stores (one secret opening two stores).
- **The resume reads the cookie sign-in** (user decision, 2026-11-26). On a cookie chain the
  provider's resume endpoint takes as its sign-in the session the built-in cookie session
  published, recognised by a mark the cookie session sets on the exchange, not by `ex.Session`
  alone, so a session a consumer interceptor published is still refused. The resume is a POST, so
  CSRF protection covers it. An `Authorization` line beside the cookie is still refused (the guard
  refuses it first). On a chain with a header bearer the resume is unchanged. Without this, a
  browser could complete an authorization only through server-side completion, since a page can
  neither read the `HttpOnly` cookie nor add an `Authorization` header beside it.
- **Completion on a cookie chain needs no handoff manager.** When server-side completion
  (`WithOIDCProviderCompletion`) finds a step owed, it conveys the pending sign-in as the cookie
  chain's own callback does: it stores it, sets its cookie and answers `303` to the parked login
  page carrying the handle, where the page finishes the step and resumes through the endpoint
  above. The per-request challenge fallback works the same way.

### 13. Magic-link parity

`WithMagicLinkParams(address, next, token string)` and `WithMagicLinkBodyLimit(limit int64)`,
mirroring `WithLoginParams` and `WithLoginBodyLimit`. Names apply to form bodies and, for the
request endpoint, JSON members. An oversized body keeps today's behaviour: read as no values.
- **Default:** `email`, `next`, `token`; 64 KiB.
- **Override:** the two options. **Line:** empty or duplicate names, and a limit of zero or less,
  fail construction.

## Failure modes

| Failure | Category | State | Outcome a caller sees |
|---|---|---|---|
| Cookie session without CSRF protection | Wiring | Handled, tested | `ErrConfig` from `New` (existing `CookieAuthenticator` rule) |
| Cookie session with a bearer mode | Wiring | Handled, tested | `ErrConfig` naming both |
| Cookie overrides breaking a prefix rule, `SameSite=None`, bad name | Wiring | Handled, tested | `ErrConfig` |
| Handoff manager on a cookie chain | Wiring | Handled, tested | `ErrConfig` |
| Malformed, unknown, expired cookie | Input | Handled, tested | 401, counted against the source, cookie expired |
| Superseded identifier after its window, in the cookie | Security | Handled, tested | 401 + reuse; family revoked; provider sessions end |
| Session or user store outage on load | Dependency | Handled, tested | dependency failure (500 by default), cookie kept |
| Source over its allowance, or the source limiter down, on a cookie request | Dependency / Security | Handled, tested | 401, cookie kept (not judged) |
| CSRF token missing or wrong on an unsafe cookie request | Security | Handled, tested | 403 (`ErrCrossSiteRequest`), cookie kept, not charged to the source |
| Cookie and `Authorization` together | Input | Handled, tested | 401 before any credential is read |
| `next` off-site (`https://…`, `//…`, `/\…`) | Security | Handled, tested | `303` to `/` |
| Delivery port returning a body credential | Configuration | Handled, tested | issuing failure, nothing written |
| Delivery port weakening the cookie, changing the identifier, or placing it elsewhere | Configuration / Security | Handled, tested | issuing failure, nothing written, sign-in ended |
| Delivery fails after the session was stored | State | Handled, tested | 500; the family is revoked on an uncancellable, time-bounded context; a revoke failure is logged and the 500 stands |
| Delivery port panics | Configuration | Handled, tested | the family is revoked as for any delivery failure, nothing is written, and the panic continues |
| Session store panics while ending the sign-in after a delivery panic | Dependency | Accepted | the store's panic replaces the port's; a double fault, left to the consumer's recovery middleware |
| Another tab re-rotates the presented identifier inside a password change's function, superseding the gate's successor | Concurrency | Accepted | the password changes and the resolution lands on a superseded record; the response succeeds, the next request on that cookie is reuse and the family is revoked, so the user signs in again: fail-closed |
| Password change ending a recovery is refused or fails to save on a persistent sign-in | State | Accepted | the cookie was set for the restored deadline while the session keeps the lowered one; the server refuses the session at its deadline and expires the cookie |
| Delivery port writes an encoded copy of the identifier elsewhere | Security | Accepted | not detected; the port is trusted code, and its godoc says the check is literal |
| Delivery fails at recovery completion | State | Accepted | the user's recovery codes were already replaced and the new ones are never shown, so the user recovers again; only a consumer port can fail here |
| Session cookie beside a credential a consumer authenticator reads | Security | Handled, tested | 401 before the cookie is read |
| Two tabs rotating at once (role switch, renewal) | Concurrency | Handled, tested | one rotation wins; the loser's identifier works through the window (barrier test) |
| Logout landing during a role switch | Concurrency | Handled, tested | before the rotation's write: the switch fails with `ErrAuthenticationRequired`, no cookie re-set, nothing stored; after it: an ordinary later logout (role recorded in the same write, decision 10) |
| A session store that ignores the requested successor role | Dependency / Configuration | Handled, tested | the rotation fails with a store-contract error; the switch sets no cookie; the conformance suite catches the store |
| Client hangs up after a rotation's write has committed | Concurrency | Accepted | the new cookie never arrives; the old identifier works through the grace window and is reuse after it, revoking the sign-in; `session.WithUnusedSuccessorRecovery` softens it |
| Cookie resume at the provider with an `Authorization` line too | Security | Handled, tested | 401 from the guard before either credential is read |
| Persistent cookie with the password-change rotation turned off on a recovery-pending sign-in | State | Accepted | the cookie keeps the lowered recovery `Max-Age` and is dropped early by the browser: fail-closed; documented on the option |
| Request context cancelled during rotation | Concurrency | Handled, tested | nothing stored, cookie not re-set, the old identifier still valid |
| Rotation write fails | State | Handled, tested | dependency failure, old cookie kept |
| Logout: provider store fails | State | Handled, tested | retryable failure, cookie not expired |
| Persistent mark lost by a store or a rotation | State | Handled, tested | conformance round trip; rotation carries it |
| Rows written before the migration | State | Handled, tested | read with the mark unset |
| Build deployed before the migration is applied | Configuration | Accepted | every session create and load fails with the store's wrapped "column does not exist" error until the migration runs, as for every added column; the migration plan orders it first |
| Persistent cookie on a shared machine | Security | Accepted | opt-in only; documented on the option |
| Opted-out rotation reopens fixation | Security | Accepted | named per change; documented on the option |
| Cookie dropped by a browser (blocked cookies, private mode) | Dependency | Accepted | the user appears signed out; the server state is unaffected |
| Refused-cookie responses not expiring on a framework adapter | Wiring | Handled, tested | adapter suites on net/http, gin and fiber assert the expiring `Set-Cookie` |

## Risks / Trade-offs

- [Extracting the pipeline changes shipped security code] → test-first against the existing
  session-bearer suite before and after, with an Opus implementer and reviewer.
- [Every issuing endpoint must route through delivery; one missed path leaks a token into a body]
  → a table test over every issuing endpoint asserting no credential in body or headers on a
  cookie chain.
- [Negotiation misclassifies a client] → the rule uses only `Content-Type` and `Accept`, and
  every responder is replaceable.
- [The new session column touches three stores and a migration] → the column has a default and is
  write-once like `MFAAtFirstFactor`; the conformance suite carries the round trip.
- [Two chains on one mux confuse consumers] → an example test and godoc showing the two-chain
  setup with `WithBasePath`.

## Migration Plan

- Additive: chains without `EnableSessionCookie` behave as before.
- Apply the new security-state migration before deploying a build that writes the column; existing
  rows hold NULL, read as unset. Rolling back the build leaves the column unused.
- After this change is archived, `bff-resource-server` is retired and `api-token-forwarding` is
  proposed with Q2, Q3 and Q5.

## Open Questions

- The exact helper names for the rotation opt-outs (`RotateOnRoleSwitch` or a typed set) can be
  settled during implementation without changing the specs.

## References

**Researched** (accessed 2026-11-25):
- Decisions 3, 8, 10, 11:
  - [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): renew the session identifier after any privilege change; restrictive cookie attributes.
  - [MDN: Session management](https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Session_management): renewal and the OWASP guidance on non-persistent cookies (decision 9).
- Decision 2:
  - [IETF draft-ietf-oauth-browser-based-apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/): the backend-for-frontend pattern. Its current status (draft or RFC) was not verified.
- Decision 5:
  - [draft-ietf-oauth-browser-based-apps-11](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-11): `SameSite` is not by itself sufficient CSRF protection (2022 text).
- Decisions 4, 10:
  - [Spring Security: session management](https://docs.spring.io/spring-security/reference/5.7/servlet/authentication/session-management.html): fixation protection on by default, `none` as an explicit setting; separate filter chains per path.
- Decision 12:
  - [Keycloak CookieType](https://www.keycloak.org/docs-api/26.5.7/javadocs/org/keycloak/cookie/CookieType.html) and the [Keycloak forum on cookies](https://forum.keycloak.org/t/how-are-cookies-used-in-operations/4098): separate SSO and application cookies, and reports of the layers drifting apart at logout (forum reports, not official documentation).

**Primary documentation:**
- [RFC 6265bis, cookie name prefixes](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/): `__Host-` and `__Secure-` rules (decision 8).

Decisions 1, 6, 7 and 13 are reasoned from scrty's own settled specs and the established design.
