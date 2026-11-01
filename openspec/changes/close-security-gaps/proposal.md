# Proposal

> Reconciled on 2026-11-02 with `reauthentication` (archived) and `key-port-context` (PR #39). `design.md` D1 records what changed.

## Why

A sweep against the OWASP Top 10:2025, the OWASP API Security Top 10:2023, OWASP ASVS 5.0 and NIST SP 800-63B-4 found that scrty is strong on authentication itself but leaves thirteen gaps. Most sit around the browser and the deployment:
- no security response headers;
- no CORS and no CSRF protection;
- no way to trust a reverse proxy;
- bearer tokens a thief can replay.

A few sit in the account lifecycle:
- no password acceptance policy;
- no rehash on login;
- no session listing;
- no security-event port.

Several of these become breaking changes once `v0.1.0` is tagged, so all thirteen close in this one change before `release-readiness` tags it.

## What Changes

- **Security response headers**, opt-in through `httpsec.EnableSecurityHeaders`:
  - HSTS, sent only over HTTPS;
  - a strict CSP with a per-response nonce handed to templates;
  - `nosniff`, Referrer-Policy and COOP;
  - separate profiles for documents and APIs, chosen by route;
  - Clear-Site-Data on logout, opt-in.
- **CORS**, opt-in through `httpsec.EnableCORS`:
  - an exact origin allowlist;
  - preflights answered before authentication;
  - `*` with credentials and the `null` origin refused at construction.
- **CSRF protection**, moved here from `bff-resource-server`:
  - a Fetch Metadata and Origin-versus-Host check on unsafe methods;
  - a token layer for cookie-authenticated requests.
- **Trusted proxies and API gateways**, opt-in through `httpsec.EnableTrustedProxies`, absorbing `trusted-proxy-client-ip`:
  - the client IP, scheme and host are resolved from one named header family, only from listed proxies, right to left with a hop limit;
  - a forwarded host must be on a required allowlist;
  - consumed headers are removed by default;
  - downstream code reads the resolved values through an accessor, and the request is not rewritten.
- **`httpsec.Request` gains `Host()` and `Secure()`**, and every adapter implements them. **BREAKING** for a consumer's own `Request` implementation; nothing is tagged yet.
- **Sender-constrained tokens:**
  - DPoP (RFC 9449), opt-in through `httpsec.EnableDPoP` for both bearer modes and every issuing endpoint: proofs verified on every request, tokens bound with `cnf.jkt` at sign-in and kept through every rotation, a bad proof leaving links and codes unspent, and a bound token presented as a bearer token refused;
  - mTLS-bound tokens (RFC 8705), including a client certificate forwarded by a trusted proxy and decoded by a replaceable decoder.
- **One password policy.** `password.Policy` holds minimum length, a common-password list, context words and an opt-in breach check, and absorbs the reuse guard as its `NoReuse` rule. **BREAKING**: `NewReuseGuard` is removed before the tag.
- **Rehash on login** when a stored hash's algorithm or parameters are outdated, through an optional encoder interface and a consumer write that receives the hash it replaces, so a concurrent password change is never undone.
- **User-facing session management:**
  - list a user's live sessions and revoke one, or all others;
  - sign-in metadata is recorded only when the consumer opts in.
  - **BREAKING** for a consumer's own `session.Store`.
- **A security-event port** emitting OWASP Logging Vocabulary events, which the existing lockout and reuse observers fold into.
- **Security notices:**
  - removing a passkey notifies the user by default;
  - an opt-in notice for a sign-in from a device matching none of the user's live sign-ins.
- **An automation-challenge seam** before login, magic-link requests and recovery start. No vendor is bundled.
- **Supply-chain hygiene:** CI actions pinned to commit SHAs, automated dependency updates, and an SBOM per release.

## Capabilities

### New Capabilities

- `security-headers`: response headers that harden browsers, their document and API profiles, the CSP nonce, and Clear-Site-Data.
- `cors`: the cross-origin resource sharing policy, preflight handling and its construction-time refusals.
- `csrf-protection`: refusing cross-site, state-changing requests by Fetch Metadata, Origin and token.
- `trusted-proxies`: resolving a request's client address, scheme and host from trusted proxies' forwarded headers.
- `sender-constrained-tokens`: binding access and refresh tokens to a DPoP key or a TLS client certificate, and verifying the binding.
- `password-policy`: the rules a new password must pass, including reuse of the user's own recent passwords.
- `security-events`: the typed events scrty emits for security-relevant outcomes.
- `automation-challenge`: the pluggable challenge that slows automated attacks on unauthenticated flows.
- `supply-chain`: how the repository pins, updates and describes what it builds from.

### Modified Capabilities

- `http-security-chain`:
  - requests expose host and scheme;
  - client attribution through trusted proxies;
  - new outermost slots;
  - session-management endpoints;
  - rehash at login;
  - Clear-Site-Data at logout;
  - sign-in notices.
- `framework-adapters`: every adapter resolves the client address, host and scheme through scrty's own trusted-proxy rules, and implements `Host()` and `Secure()`.
- `http-error-propagation`: the new refusals join the public contract and the status table, whose reused-password row moves to `password-policy`.
- `sessions`: listing a user's sessions, opt-in sign-in metadata, and a key binding carried through every rotation.
- `security-state-stores`: durable stores list sessions by user and persist the metadata and key binding.
- `store-conformance`: the session suite covers listing, metadata and binding.
- `schema-migrations`: a security-state migration adds the session metadata and binding columns; listing uses the existing user index.
- `password-encoding`: the reuse-guard requirements move to `password-policy`; encoders can report that a hash needs upgrading.
- `token-issuance`: issued tokens can carry a confirmation claim.
- `passkey-authentication`: removing a passkey notifies the user by default.

## Impact

- **Code, core module:**
  - `httpsec`: new interceptors and slots, options, errors, the `Request` interface and the client accessor;
  - `authenticate/password`: the policy, the absorbed reuse guard and the upgrade signal;
  - `session`: listing, metadata and binding;
  - `token`: the confirmation claim;
  - the store packages and a new security-state migration;
  - `notify`: new notices;
  - a new security-events package.
- **Code, nested modules:** `httpsec/ginsec` and `httpsec/fibersec` (adapters, guards, client resolution), and `store/pgxstore` and `store/gormstore` (listing, metadata, binding).
- **Tests:** conformance suites in `test`; every new interceptor on net/http, gin and fiber.
- **CI:** `.github/workflows/` (SHA pins), a Dependabot configuration and an SBOM step.
- **Dependencies:** none new in the core module. The breach check calls the Have I Been Pwned range API through the existing confined outbound client.
- **Other changes, edited in the same pass:**
  - `trusted-proxy-client-ip` is superseded by this change;
  - `bff-resource-server` no longer owns `csrf-protection`;
  - `release-readiness` lists this change among those that land before it.
- **Builds on** `reauthentication` (archived):
  - the guards and recency check;
  - the re-proof endpoints, which the CSRF layer covers and which bind DPoP tokens on rotation;
  - the error table this change extends.
- **Also builds on** `key-port-context` (PR #39): the bearer and token-issuance requirements, which DPoP extends; issue before spend, which decides where a proof is checked; and the outage and hang-up rules every new dependency follows.
- **Consumers:** none yet. Nothing is tagged, so every breaking item above is recorded as a decision, not a compatibility obligation.

## References

See `design.md`, which carries the sources for every decision.
