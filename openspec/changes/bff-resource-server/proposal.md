## Why

scrty's HTTP flows today end with an access token that the client holds and sends back as a bearer header. This covers native apps and API clients. It fits browser apps poorly:
- a token that JavaScript can read can also be stolen by any script injected into the page;
- scrty has no cookie-borne session;
- scrty has no defence against cross-site request forgery, which a cookie session needs.

APIs that sit behind a browser app, or that accept tokens from another issuer, also need to verify a token without sharing scrty's session store or signing keys.

Before either mode can be specified, the team must decide where the browser-facing component lives and what token it sends to APIs. This change proposes both modes, sets out a candidate architecture, and records the open questions that block their specs.

## What Changes

- Add a **backend-for-frontend (BFF) session mode**:
  - the browser holds only an opaque session cookie;
  - tokens stay on the server, and no token is readable by JavaScript;
  - the cookie is `HttpOnly`, `Secure`, `SameSite` and host-bound by default;
  - its lifetime follows the idle and absolute expiry that `sessions` already enforces;
  - the session identifier rotates whenever the session's privilege changes;
  - every request runs the per-request policy phase with the session's recorded first factor, exactly as the bearer path does.
- Add a **resource-server mode**:
  - an API verifies JWTs issued by scrty or by another issuer, using a remote key set;
  - issuer and audience are required configuration;
  - verified scopes and claims are mapped into the principal that `authorization` evaluates.
- Add **CSRF protection** that is on by default for every cookie-authenticated, state-changing request and cannot be switched off silently. The default layers a Fetch Metadata and Origin check with a token check, and each layer is replaceable.
- Record a comparison of token refresh strategies: a refresh token held by the BFF on the server, or short sessions that fall back to re-login.
- List five **open questions** for the team. They block the specs for all three capabilities.

Not in this change:
- Specs and tasks. They follow once the open questions are answered.
- A reverse proxy, unless the team chooses one (open question 3).
- Token exchange (RFC 8693) or phantom-token introspection endpoints, unless the team chooses that token shape (open question 2).
- CORS and general security headers.

## Capabilities

### New Capabilities

Specs for all three are deferred until the open questions in design.md are answered.

- `bff-session`: the cookie-borne browser session:
  - cookie attributes and naming;
  - establishing a session at login without handing a token to the browser;
  - identifier rotation on privilege change;
  - expiry and logout;
  - per-request policy evaluation with the recorded first factor;
  - how the BFF obtains and forwards tokens to APIs, including refresh.
- `resource-server`: verifying bearer JWTs from a configured issuer against its remote key set:
  - required issuer and audience;
  - algorithm pinning;
  - key-set caching and refetch;
  - mapping scopes and claims into the principal used for authorization.
- `csrf-protection`: refusing cross-site, state-changing requests that carry a cookie session:
  - Fetch Metadata and Origin checks;
  - the token scheme;
  - safe-method and exemption rules;
  - the refusal contract.

### Modified Capabilities

None. No specs have been archived yet. Two modifications are expected once the questions are answered, and each would be raised with its owning change:
- `sessions`, for an identifier rotation operation;
- `http-error-propagation`, for a CSRF refusal sentinel and its status.

## Impact

- **New code (expected), core module:**
  - cookie session and CSRF interceptors in `httpsec`;
  - a resource-server verifier.
- **Placement is not decided.** It depends on open question 1, the in-app BFF versus a standalone proxy.
- **Dependencies:** no new JOSE library. Remote key sets reuse jwx v3 and the key-set cache semantics that `oidc-brokering` defines. A standalone proxy, if chosen, would be a new nested module.
- **Depends on:**
  - `sessions`, `security-policy`, `authorization`, `rate-limiting` (authn-authz-core);
  - `token-issuance`, `signing-keys`, `identity-model` (identity-and-tokens);
  - `http-security-chain`, `http-error-propagation`, `framework-adapters`, `outbound-http-confinement` (http-security);
  - `oidc-login` and `oidc-logout` (oidc-brokering), whose callback override is the natural place to establish a cookie session.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
