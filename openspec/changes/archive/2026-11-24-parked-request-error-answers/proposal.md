# Proposal

## Why

The provider parks an authorization request while the user signs in on the consumer's login page.
Several failures on that path leave the request parked and the browser on a raw problem body,
somewhere the client never looks. A standard OAuth client (oidc-client-ts, AppAuth, NextAuth) only
understands the error response at its redirect URI, so it waits until it times out and the user is
stranded. The failures are:

- a brokered SSO login that fails at its start (discovery) or at its callback: a refusal, a hook
  refusal, a cancel at the identity provider, an outage or a fault;
- a user who gives up on the login page, because the page has no way to end the request;
- a store failure during a resume;
- a request that expires while the user is still on the login page;
- a client that lost its grant or scopes after the request was parked.

One cause sits under all of them: the library has no public way to end a parked request with an
error, so only its internals can answer the client. A consumer whose own frontend is a standard
client has hit this, and an audit of the released version found the same root cause in the other
paths. The same audit found that a 401 from the built-in bearer carries no `WWW-Authenticate`
challenge outside the provider's own endpoints, so a standard client cannot tell an expired token.

## What Changes

- **Ending a parked request with an error.** A new public provider operation ends a login-stage
  parked request with an error code from a closed set. It checks the handle, the browser's flow
  secret and the stage, as a resume does. It answers the client's redirect URI with `error`,
  `state` and `iss`, and spends the request. Device-flow requests are refused, since they have no
  redirect URI.
- **A cancel endpoint for the login page.** A new endpoint, `POST /authorize/cancel` under the
  provider prefix, lets the login page end the request with `access_denied`. It needs no signed-in
  session. It follows the resume endpoint's TLS, origin, flow-cookie and throttle rules, and
  answers `redirect_to` as a resume does.
- **A failed brokered SSO login returns to the login page.** With server-side completion on, a
  brokered login whose destination is the parked request's login URL now goes back to that page
  with an `error` code when it fails, either at the start or at the callback. The request stays
  parked, so the user can retry or choose another way in, or cancel. The codes are
  `access_denied`, `temporarily_unavailable` and `server_error`, and none says anything about an
  account. An option sends the error straight to the client and ends the request instead.
  **BREAKING** (behaviour): such failures used to answer a problem body at the SSO callback or
  start URL.
- **Resume failures that can be answered are answered.** A store failure after the request was
  read answers `server_error` at the client's redirect URI. A client that lost the code grant
  answers `unauthorized_client`. A client left with no usable scope answers `invalid_scope`. A
  client removed, or a redirect URI unregistered, is still refused with no redirect.
  **BREAKING** (behaviour).
- **Expired requests are answered within a grace window.** A request that expired, is still bound
  to this browser and is still within a grace window answers the client with an error. The
  pending-request sweep keeps expired requests for that window before deleting them. After the
  window, the answer is today's unknown handle. **BREAKING** (behaviour).
- **A refusal beside an outage is reported as a refusal.** A callback whose error is both a
  refusal and an outage now emits the login-failure event, for every login, parked or not. It used
  to emit nothing. **BREAKING** (events).
- **Bearer 401s carry a challenge.** When the chain has a built-in bearer, every 401 the chain
  answers carries a `Bearer` challenge, with `error="invalid_token"` when a bearer token was
  presented and refused. An option turns this off. This revises the settled rule that a 401
  outside the provider's endpoints is unaffected. **BREAKING** (headers).
- **Opt-in hardening, all off by default:**
  - a ceiling on live parked requests, answering `temporarily_unavailable` when reached;
  - 429 with `Retry-After` in place of `invalid_client` for a throttled source at the token,
    revocation, introspection and device-authorization endpoints;
  - `unsupported_token_type` when a client revokes a JWT access token the provider cannot revoke;
  - a redirect to the code-entry page with `result=invalid` or `result=throttled` for a bad or
    throttled user code.
- **Documentation.** A short README note lists every job a deployment on durable stores must run on
  a schedule. Durable stores are not swept unless the consumer runs these expiry tasks. A wiring guide
  is left for later work.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `oidc-provider-authorization`: ending a parked request with an error, the cancel endpoint,
  resume failures answered at the redirect URI, expiry with a grace window, the parked-request
  ceiling.
- `oidc-login`: a failed brokered login for a parked request returns to the login page or answers
  the client, at the start and at the callback, including completion's own refusals.
- `http-error-propagation`: 401 challenges beyond the provider's endpoints.
- `oidc-provider-clients`: the opt-in 429 for a throttled client-authenticating source.
- `oidc-provider-tokens`: the opt-in `unsupported_token_type` for revoking a JWT access token.
- `oidc-provider-device-authorization`: the opt-in redirect for a bad or throttled user code.
- `identity-linking`: a sign-in hook's UserInfo failure is reported as that provider failure, so a
  UserInfo outage inside a hook returns to the login page with `temporarily_unavailable`.

## Impact

- `oidcprovider`:
  - a new public method to end a parked request;
  - the resume's failure answers;
  - the pending-request sweep's cutoff;
  - new options for the ceiling, revocation and grace;
  - an optional counting interface for pending-request stores.
- `authenticate/oidc`: a failed callback and an aborted flow can report the flow's stored
  destination, through new API that leaves `Callback`'s and `AbortFlow`'s signatures unchanged. A
  sign-in hook's UserInfo failure passes through as that outcome.
- `httpsec`:
  - the cancel endpoint and its path constant;
  - the SSO start, callback and completion failure paths;
  - the bearer challenge;
  - new options for the login-page error parameter, straight-to-client answers, the bearer
    challenge opt-out, 429 throttling and user-code redirects.
- `store/sqlstore`, `store/pgxstore`, `store/gormstore`: the counting interface for the
  parked-request ceiling.
- README, CHANGELOG.
- No new dependency.
