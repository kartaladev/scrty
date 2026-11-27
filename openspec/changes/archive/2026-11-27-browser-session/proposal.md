# Proposal

## Why

scrty answers every sign-in with a credential in a JSON body. That suits mobile apps, CLIs and
single-page apps that keep the token themselves, but a browser has nowhere safe to keep it: any
credential JavaScript can read, an injected script can steal. Pages served from the server have no
way to stay signed in at all.

The planned scrty-served sign-in pages (sign-in form, magic link, second factor, password change,
recovery, and the provider's login and consent) all need a sign-in that the browser holds as an
`HttpOnly` cookie. That is the one capability they wait on. Two of the three capabilities the
`bff-resource-server` draft proposed have since landed elsewhere (`csrf-protection` in
`close-security-gaps`, `resource-server` on 2026-11-25), so this change carries only the cookie
session, and the questions about calling downstream APIs move to a later change.

## What Changes

**The cookie session**
- `httpsec.EnableSessionCookie(deps, opts...)`: a chain authenticates requests by a session cookie.
  It reads the session identifier from the cookie and runs the same session-reference pipeline as
  `EnableSessionBearer`: shape check, load by digest, reuse detection, user reload, per-request
  policy, throttling, and the outage-versus-refusal split. The pipeline is shared, not copied.
- It declares `CookieAuthenticator`, so the chain already refuses to build it without CSRF
  protection.

**Delivery is per chain**
- A chain with the cookie session hands out cookies and never a credential in a body. It cannot be
  combined with `EnableSessionBearer` or `EnableBearerToken`. A consumer serving browsers and native
  clients runs two chains, one with `WithBasePath`.
- Every endpoint that issues a credential (form login, magic link, federated sign-in, passwordless
  passkey, second-factor verification, re-authentication, recovery completion, session renewal)
  sets the cookie instead.
- A request carrying both the session cookie and an `Authorization` header is refused.

**What a browser sign-in answers**
- A form post, or a request that prefers HTML, is answered `303 See Other` to a safe destination.
  A JSON request is answered with JSON that carries no credential. Each endpoint's responder stays
  replaceable.
- `next` is accepted only as a relative path on the same origin, unless the consumer allowlists an
  exact target.
- In cookie mode, federated sign-in completes in the callback: it creates the session, sets the
  cookie and redirects. No handoff code is issued.

**Cookie attributes and lifetime**
- Default cookie: `__Host-scrty-session`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, no
  `Domain`, and no `Max-Age`, so it is a browser-session cookie.
- Overrides: the name (with prefix rules checked), `SameSite=Strict`, a shared `Domain` (only with a
  `__Secure-` name), and persistence, decided per sign-in ("remember me"). A persistent cookie's
  `Max-Age` follows the session's absolute deadline. The server's idle and absolute deadlines stay
  authoritative in every case.
- Persistence is recorded on the session, so it survives rotation. That is a new library-owned
  session field, kept by every store.

**Rotation on privilege change**
- Sign-in always creates a new session. Second-factor verification and re-authentication already
  rotate the identifier, in every mode.
- In cookie mode, switching the active role and changing the password also rotate the identifier
  and re-set the cookie. A consumer can opt out of these two rotations by name, and the option's
  documentation states the session-fixation risk.

**Ending a sign-in**
- Logout, and a request whose cookie names a missing, expired or unreadable session, expire the
  cookie. A store outage keeps it.
- Every end of a cookie sign-in (logout, reuse detection, revocation) also ends the provider's
  browser sessions of that sign-in, through the session manager's existing end reports.

**Magic link parity**
- `WithMagicLinkParams` and `WithMagicLinkBodyLimit` make magic link's form fields and body limit
  replaceable, as form login's already are.

**Not in this change**
- Tokens for downstream APIs, a reverse proxy, refresh tokens: moved to a later
  `api-token-forwarding` change.
- The pages themselves: later changes.

## Capabilities

### New Capabilities
- `browser-session`: authenticating browser requests by an `HttpOnly` session cookie: its transport,
  attributes and lifetime, per-chain delivery, the answers browser sign-ins give, rotation on
  privilege change, and how the cookie ends.

### Modified Capabilities
- `sessions`: a session records whether its browser cookie persists, and every rotation carries it.
- `security-state-stores`: the durable session stores keep that choice.
- `magic-link`: the redemption and request endpoints' form field names and body limit become
  replaceable.

## Impact

- **Code:** `httpsec` (a new cookie-session option; the session-reference pipeline extracted from
  `session_bearer.go` and shared; credential delivery in every issuing endpoint; negotiated default
  responders; rotation at role switch and password change; magic-link options), `session` (the
  persistence field and its carry-over in every rotation), `store/sqlstore`, `store/pgxstore`,
  `store/gormstore` (the new column), and `store/migrate/securitystate` (one new migration).
- **Tests:** the shared conformance suites in `test` gain the persistence field. A browser-session
  suite runs on net/http, gin and fiber.
- **APIs:** additive. Existing chains without the cookie session behave exactly as before.
- **Dependencies:** none added.
- **OpenSpec:** `bff-resource-server` is superseded. Its Q2, Q3 and Q5 move to `api-token-forwarding`,
  and the draft is retired in a separate step.
