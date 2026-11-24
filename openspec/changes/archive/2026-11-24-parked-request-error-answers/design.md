# Design

## Context

- **Parking.** The provider stores a validated authorization request as a pending request
  (`oidcprovider/pending.go`). It sits at the login stage under a handle bound to the browser's
  `__Host-` flow cookie, until a resume moves it on. Each stage is spent by one conditional write
  (`PendingRequestStore.Advance`).
- **The only error answer is private.** `refuseRequest` (`oidcprovider/resume.go`) spends the stage
  and builds `<redirect_uri>?error=…&state=…&iss=…`. It is reached only by an `id_token_hint`
  mismatch (`login_required`) and a consent denial (`access_denied`). A deny at the login stage is
  refused as an unknown handle, and a test pins that.
- **Brokered SSO failures answer a problem body.** In `httpsec/oidc_login.go`, `callback` returns
  every `RelyingParty.Callback` error unwritten, and `authorize` does the same for a discovery
  failure. `RelyingParty.Callback` returns an empty `CallbackResult` after the flow is spent
  (`authenticate/oidc/login.go`), so the flow's stored destination, and with it the parked handle,
  is lost. `AbortFlow` returns only a bool. Completion's refusals (`httpsec/oidc_completion.go`)
  are returned the same way.
- **Error descriptions.** The provider sends no `error_description` by default
  (`oidc-provider-authorization`, "Errors after validation are redirected with state and issuer").
- **Sweeping.** The `oidc-provider.pending-requests` expiry task deletes every record past
  `ExpiresAt` (`oidcprovider/expiry.go`). Durable stores are swept only when the consumer runs the
  expiry tasks through `expiry.Runner` or `expiry/sweep`. The README never says so.
- **Bearer 401s.** A 401 from the bearer interceptor outside the provider's endpoints carries no
  challenge, which the settled `http-error-propagation` spec requires today.

The scope and the default came from the user, after a standards audit, a survey of established
providers, a threat model of the design against the code, and a sweep of v0.4.0 for the same class
of problem.

## Goals / Non-Goals

**Goals:**

- Every failure on the parked-request path that can safely reach the client does reach it, by the
  standard authorization error response, or goes back to the login page so the user can recover.
- The login page can end a request.
- No answer reveals anything about an account.
- Nothing redirects anywhere a resume would not.
- A 401 on a bearer chain carries the challenge RFC 9110 requires.
- Hardening for parked-request volume and the remaining audit items is available as opt-in options.

**Non-Goals:**

- An invalid or unknown state at the SSO callback. Nothing trustworthy names a request there (D5).
- Device-flow requests. They have no redirect URI.
- The handoff path without completion.
- Stateless parking.
- End-session with a failing hint (F9). It stays a refusal: RP-Initiated Logout lets the provider
  decline, and there is no page of the library's to fall back to.
- An oversized `state` (F10). It stays out of the error redirect: echoing a value refused for its
  size would carry it anyway.

## Decisions

### D1. One public operation ends a login-stage parked request

`(*oidcprovider.Provider).EndPending(ctx, EndPendingInput{Handle, FlowSecret, Code})` returns a
`ResumeResult` with `Outcome: ResumeOutcomeClientError`. The method and its input are new.


1. It loads the request as `Resume` does, with the flow-digest comparison in constant time.
2. It requires `StageLogin` and refuses a device request (`DeviceAuthorizationID != Nil`) as an
   unknown handle. A device request has no redirect URI, so `withQuery("", …)` would build a
   relative `Location`.
3. It runs `rejudge` (D9).
4. It spends the stage with the same conditional write.
5. It returns `refuseRequest`'s location.

`Code` must be one of `access_denied`, `temporarily_unavailable` or `server_error`. Anything else
is `ErrConfig`, and nothing is read. A lost race with a resume is `ErrUnknownHandle`.

- **Default:** not called by anything unless completion or the cancel endpoint is in use.
- **Override:** the consumer calls it from their own handler.

Alternatives:

- *Extend `Resume` with a deny at the login stage.* `Resume`'s contract pins that refusal, and its
  input carries a sign-in a cancel does not have.
- *Expose `refuseRequest` as is.* It skips the handle and flow checks.

### D2. The cancel endpoint is separate from the resume endpoint

A new endpoint, `OIDCCancel`, defaults to `/authorize/cancel` under the provider prefix. It takes a
POST with the JSON body `{"req":"<handle>"}`. It answers 200
`{"redirect_to":"<redirect_uri>?error=access_denied&state=…&iss=…"}` with `Cache-Control: no-store`.

It joins the resume group's guards: TLS, the body limit and content type, the cross-site rules, the
throttle with an unknown handle charged, and the flow cookie. It needs **no session**, because a
user who gives up has not signed in, and the resume endpoint requires a session (`RequiresSession`).
Refusals are the resume's: an unknown handle is 400, a throttled source is 429.

- It is a second route of the resume group, outside the sign-in slot but still under CSRF
  protection. It shares the resume's limiter (`WithOIDCResumeLimiter`) and body limit, so a source
  guessing handles has one budget across both endpoints. Throttle records for it are labelled with
  the resume's name.
- A body that is not JSON, or has the wrong content type, is 400 as at the resume, not 415.
- Like the resume, it never carries a CORS header, so a script on another origin cannot read a
  `redirect_to` holding `state`.
- A caller that has already gone ends nothing and is not charged.

- **Default:** served whenever the provider is enabled.
- **Override:** `WithOIDCProviderPath(OIDCCancel, …)`. There is no switch to remove it. It is harmless
  without a caller, as the resume endpoint is.

### D3. A failed brokered login for a parked request returns to the login page

With completion on, a login whose stored destination passes `parkedHandle` and that fails with a
mapped failure (D4) is answered with a 303 to `<LoginURL>?req=<handle>&<param>=<code>`, carrying
`no-store` and `no-referrer`. The request stays parked, so the user can retry or choose another way
in. This covers:

- `callback` failures after the flow is spent;
- `providerError` once `AbortFlow` ends the flow;
- `authorize` with `ErrDiscoveryFailed`, where the destination is the query's `next`, matched by
  `parkedHandle` exactly;
- completion's refusals after `precheckParked`.

The redirect target is the provider's own configured login URL. It is never taken from the request,
so it adds no open-redirect surface.

- **Default:** the login page, with the parameter named `error` (`DefaultOIDCLoginErrorParam`).
- **Override:**
  - `WithOIDCLoginErrorParam(name)` renames the parameter. An empty name, `req`, `handoff`, a name
    outside RFC 3986's unreserved characters, or the option without completion fails construction.
  - `WithOIDCFailToClient()` ends the request with `EndPending` and redirects to the
    client instead. Set without completion, it fails construction.

Why the login page by default: Keycloak, Dex and Zitadel keep the user on their own pages for
upstream failures. Ending the request on every failure would remove a recovery for a user who has
another way in, or who hit a brief outage. Auth0, Entra and Okta redirect `access_denied` to the
client, which the override reproduces.

### D4. An allow-list maps failures to codes, and everything else keeps its answer

| Failure | Code |
|---|---|
| `ErrInvalidIDToken`, `ErrNoLinkedAccount`, `ErrProvisioningRefused` (including hook refusals and the one-link rule) | `access_denied` |
| A provider `error=` on a completed flow | `access_denied` |
| Completion's `ErrInvalidHandoff` (unknown, inactive or mismatched user), a post-authentication denial, a per-request refusal | `access_denied` |
| The session store's failure, or the held-recovery canceller's, while completion commits the session; the token issuer's failure | `server_error` |
| `ErrDiscoveryFailed`, `ErrExchangeFailed`, `ErrUserInfoFailed` | `temporarily_unavailable` |
| The user loader's failure, the session store's failure in completion | `server_error` |

Anything unlisted keeps today's answer, with no redirect:

- an invalid state;
- `ErrUnknownProvider`;
- a flow-store fault before the flow is spent;
- an error whose walk aborted;
- a hung-up caller;
- completion's transport, throttle and unknown-handle refusals;
- `ErrOIDCReauthenticate`;
- a broker failure the walk cannot classify, as a default refusal rather than a guess.

`ErrUserInfoFailed` maps wherever it reaches the callback. With the library's `Broker`, UserInfo is
read only from a sign-in hook, and the hook's errors are opaque by the settled hook rule. That rule
now passes `ErrUserInfoFailed` through as a bare sentinel from the hook's decision, as it already
does for the two refusals, with none of the hook's text. A hook could report a refusal as an
outage, but that only changes the code the user sees. Any other wrapped library outcome stays a
broker failure. This revises the settled `identity-linking` requirement "Hook refusals and failures
are reported like the broker's own", by the user's decision.

An error that is both a refusal and an outage, such as a consumer broker's join of
`ErrNoLinkedAccount` and `ErrUserInfoFailed`, is a refusal: it is answered `access_denied` and
emits `AuthnLoginFail`, so the failed login is always recorded.

Completion's failures are mapped by where they arose, not by their value: a consumer's denial
reason, its user loader's error and its session store's error can be any value. The user loader
maps to `server_error`, a denial or refusal to `access_denied`, and the session write to
`server_error`. Only the bare `ErrInvalidHandoff` counts as a refused user; a loader failure that
wraps it is `server_error`. The refusal stage is coarse: a store failure inside the policy steps
(the second-factor methods lookup, the per-request challenge mark) is answered `access_denied`,
since a call site cannot tell it apart from a denial.

A per-request refusal after the session is stored ends that session first. If ending it fails,
the original refusal is answered, with no redirect, so no browser is sent on with a live session
the policy refused.

When the pending-request store fails during the return's own check, the original error is
answered and one ERROR record is written, holding the error type alone.

The classification reuses the one bounded walk `readCallbackFailure` already makes. No second walk is
added.

`temporarily_unavailable` stretches RFC 6749's wording ("temporary overloading or maintenance") to an
upstream outage. No surveyed provider uses it this way. It is kept because it is the only code that
tells a client to retry, and the client sees scrty as the authorization server, whose sign-in
depends on the upstream. The straight-to-client override uses the same codes.

### D5. The flow's destination is read from the stored flow record, never from an error

`RelyingParty.Callback` keeps its signature. After the flow is spent, a failure now returns a
`CallbackResult` holding only `Next`, read from the stored flow. `ErrFlowUnspent` failures still
return the empty result.

A new method returns the destination alongside the ended flag: `AbortFlowNext(ctx, provider,
state, handle) (AbortedFlow{Ended bool; Next string}, error)`. `AbortFlow`
keeps `(bool, error)` and calls it. v0.4.0 is tagged, so the public signature does not change.

`Next` is never recovered with `errors.As` from the broker's error chain, which the consumer
controls. An invalid or unknown state yields no flow and therefore no `Next`. That is why D3 cannot
reach it: a forged callback would otherwise name a victim's handle.

### D6. Returning anywhere passes completion's checks first

Before any D3 redirect, the library runs, in order:

1. the transport guard;
2. the resume throttle's `admit`;
3. `PendingRequest` with this browser's provider flow cookie;
4. the login-stage check, charging an unknown handle as `precheckParked` does.

A failure gets the original error's answer. On the callback path the source is charged once even
when completion's own pre-check already ran, because a failure from completion's pre-check is
unlisted (D4) and skips this step.

A request expired within its grace window (D7) is answered at the client by `EndPending`, because
returning to a page for a dead request helps no one. An expired request `EndPending` refuses (one
at its consent stage, or a device request) is charged as an unknown handle, since it cannot be told
apart from a guessed one.

A device request has no redirect URI, so it is never answered at the client. Under
`WithOIDCFailToClient`, a failed login for a parked device request returns to the login page, as by
default, and writes no ERROR record.

### D7. Expired requests are answered within a grace window, which the sweep keeps

A request past `ExpiresAt`, bound to this browser's flow cookie, and less than the grace window past
expiry, is answered `access_denied` at the client and spent. That applies at a resume, an end, a
completion, or a D3 return. Past the window, the answer stays an unknown handle.

The sweep's cutoff becomes `now - grace`. The store contract is unchanged: `DeleteExpired(before)`
already takes the cutoff. This follows the codes task, which keeps spent codes a minute past expiry.

The window is `[ExpiresAt, ExpiresAt + grace)`: the instant of expiry is answered, and exactly
`ExpiresAt + grace` is an unknown handle. The sweep deletes records with `ExpiresAt < now - grace`,
so the window and the sweep never overlap.

Within the window:

- A client that is gone, a redirect URI it no longer registers, or a device request is still an
  unknown handle, as D9 says.
- Otherwise the answer is `access_denied`, even where a rejudge would have said
  `unauthorized_client` or `invalid_scope`, and even when `EndPending` asked for another code.
- The spend is the only write. If it fails, the call returns `ErrDependency`, with no `server_error`
  retry.

The memory store's own pruning keeps expired records too, or it would defeat the grace in the
default setup. A store the provider builds for itself keeps them for the provider's grace. A
`MemoryPendingRequestStore` a consumer builds keeps them for 30 minutes past expiry, the largest
grace allowed. Its bound on held records becomes lifetime plus grace.

- **Default:** 10 minutes, equal to the default lifetime.
- **Override:** `WithPendingRequestGrace(d)`, with `0 ≤ d ≤ 30m`. `0` restores today's behaviour.
  Anything else fails construction.

Code: `access_denied`, chosen by the user over `login_required`. OIDC Core defines `login_required`
for `prompt=none` requests.

### D8. A dependency failure after the request is read answers `server_error`

When a resume or an end has loaded and rejudged the request and a later dependency fails, the
provider tries `refuseRequest` with `server_error`. That covers a store write, a later read (the
remembered consent, the browser session's `Load` and `Touch`) and the user loader. This matches how `Authorize` answers a
dependency failure. If that spend also fails, the original dependency error is returned unchanged
(F2).

A code record is not linked to its pending request, so the exchange cannot tell that a failed
resume wrote it. Every failure after a code is written therefore withdraws that code: the provider
records its grant family as revoked with the cause `CauseUnanswered`, and the exchange already
refuses a revoked family. The withdrawal runs on its own budget (the existing revocation budget,
10 seconds), detached from the caller, so a hung grant store can add that much to a failure path.
It runs on every failure after the write is attempted, whether the answer is `server_error` or the
original error, including a write that committed and then reported a failure. The
same holds wherever the provider writes a code it then fails to hand out, including `Authorize`
answering from an existing browser session (F29).

If the withdrawal fails too, it is logged at ERROR with the error type alone. The code then lives
out its lifetime unredeemed: it was never put in an answer, a log or an error, so nobody holds it.

- **Default:** on, with no option. A code nobody was given has no use, so there is nothing to
  configure.

Further rules:

- A caller whose context is already cancelled gets no `server_error` answer, and the request is not
  spent. Nobody would receive the answer, and spending would only cost the user their request.
- `EndPending`'s only write is the spend. If it fails, the call returns `ErrDependency` and the
  request stays parked. There is no `server_error` retry.
- A resume answered with a client error skips the resume endpoint's sign-in confirmation. The
  answer grants nothing, and the request is already spent, so a session-store failure there must
  not replace the client's answer.

### D9. A rejudge that can answer, answers

`rejudge` now returns a verdict.

| Verdict | Answer |
|---|---|
| Client gone, or redirect URI unregistered | Unknown handle, no redirect, as today |
| Code grant lost | `unauthorized_client` at the redirect URI, spent |
| `openid` lost, or no scope left | `invalid_scope`, spent |
| Lost scopes, resources or `offline_access` | Dropped, as today |

This applies at resume, end and completion (F4). A device request keeps today's verdict, since it
has no redirect URI.

The verdict is judged before any sign-in check, at both the login and consent stages. A browser
holding the handle and its flow cookie can therefore get `unauthorized_client` or `invalid_scope`
without signing in. That is no more than it learns by ending the request (D1), and it only tells
the client its own registration.

### D10. No `error_description`, by the settled default

The provider's settled rule is that error redirects carry no `error_description` by default. Every
new redirect follows it, and the login-page return carries only `req` and the code.

The user first chose fixed generic text for the redirect to the client. Once the settled rule
surfaced, the user chose to keep one rule for every provider redirect. If descriptions are wanted
later, a separate change adds one provider-wide option, whose text must stay within RFC 6749
§4.1.2.1's character set.

### D11. Bearer 401s carry a challenge on a bearer chain

When the chain has a built-in bearer, every 401 the chain answers outside the provider's endpoints
gets `WWW-Authenticate`. The answering step that already writes challenges at the resume and consent
endpoints writes it:

- `Bearer` by default, with `error="invalid_token"` when the refusal came from a built-in bearer
  rejecting a presented token;
- `DPoP` when DPoP is on.

A challenge for a scheme the consumer's handler already set is not added again. A chain with no
built-in bearer is untouched, because a cookie-only site has no scheme to name.

- With DPoP required, the challenge is `DPoP` alone. With DPoP optional, a 401 that DPoP's own
  challenge does not cover carries `DPoP` and `Bearer`, as the resume endpoint already does (RFC
  9449 §7.1 lets a server accepting both schemes name both).
- CORS exposes `WWW-Authenticate` whenever the chain adds a challenge, so a cross-origin client can
  read it.
- Duplicates are prevented for anything inside the chain: a consumer interceptor's challenge is seen
  and not repeated. A consumer's net/http error handler runs after the chain, so the library cannot
  see what it writes. With `Header().Set` it replaces the library's challenge. With `Header().Add`
  it adds a second one, which is a documented limit (F25).
- The challenge is chosen from the refusal before the consumer's error handler runs. A handler
  that answers a 401 with another status, such as a redirect to a login page, finds the challenge
  set and must clear it. This is a documented limit, as it already is for DPoP's challenge.
- A consumer interceptor ordered before the built-in bearer that refuses a valid `Bearer` token
  with 401 gets `error="invalid_token"`, since no session is published yet. Only that unusual
  ordering causes it, and the godoc states it.
- Two bearer chains assembled one inside the other each add a challenge, as DPoP's challenge does
  today. This is accepted; chains stacked with `Middleware` are unaffected.

- **Default:** on.
- **Override:** `WithoutBearerChallenge()`. On a chain with no built-in bearer it fails construction.

This revises the settled "a 401 elsewhere SHALL be unaffected", by the user's decision, on RFC 9110
§15.5.2 and RFC 6750 §3. **BREAKING** for a consumer that asserts the header is absent.

### D12. Opt-in hardening

All of these are off by default. Each option names what it governs.

- **Parked-request ceiling.**
  - `WithPendingRequestLimit(n)` counts live requests through a new optional store interface,
    `PendingRequestCounter.CountLive(ctx, now)`, before parking. At `n` or above it answers
    `temporarily_unavailable` at the redirect URI and stores nothing.
  - A store without the interface fails construction. The memory store implements the interface,
    and so do the `sqlstore`, `pgxstore` and `gormstore` adapters, as `COUNT(*) WHERE expires_at >
    now`.
  - Trade-off: the ceiling protects the database, not availability. A flood that reaches it refuses
    every user until requests expire, so it is opt-in, and the godoc says so.
  - The check and the insert are not atomic. The ceiling can be exceeded by the number of
    concurrent parks, which is accepted (F17).
  - The ceiling applies only to requests `Authorize` parks: for the login page, or from a browser
    session for the consent page. Device code-entry and logout parks are counted, but never
    refused, since neither has a redirect URI to answer at.
  - Each refusal logs one WARN record that names no request.
  - A `CountLive` error, or a negative count, which breaks the counter's contract, is a dependency
    failure answered `server_error`.
- **429 for throttled client sources.** `WithOIDCThrottle429()` applies at
  the token, revocation, introspection and device-authorization endpoints. `Retry-After` comes from
  the limiter's window, since `ratelimit.Limiter` reports no retry time: the chain's own window for
  its limiter, `PolicyReporter`'s window for a consumer's limiter, and 1 second for a limiter that
  reports neither. It is in whole seconds, at least 1 and at most a day. Every throttled source gets
  the same value, so it reveals nothing about a client. A limiter outage, or a source that cannot
  be attributed, still answers `invalid_client`. The body is the
  endpoint's JSON error shape with `temporarily_unavailable`, a code that names no client (F6).
- **`unsupported_token_type` for revoking a JWT access token.**
  `WithStrictRevocation()` answers 400 for a valid JWT access token of the calling
  client. Anything else is answered as today (F7), including another client's JWT, which is
  answered with success, after the token is verified, which reads the key and the grant. With the option on, a key source or grant store that
  cannot answer is `ErrDependency` rather than success, since success would claim the token ended.
- **Code-entry redirects.** `WithOIDCEntryRedirects()` redirects an invalid entry with
  `result=invalid` and a throttled one with `result=throttled`, both under the existing one-answer
  rule (F8).

### D13. Documentation

- **README, a short note for later work.** "Scheduled jobs (later work)" lists what a deployment on durable stores must run on a schedule. Each entry is an `expiry.Task` that deletes expired state: the consumer collects them and runs them through `expiry.Runner`, the `expiry/sweep` scheduler, or a job of their own. Durable stores are not swept otherwise. A wiring guide, and any helper that gathers the tasks, are later work and not part of this change.
  - `oidcprovider.ExpiryTasks`:
    - `oidc-provider.pending-requests`, which keeps the D7 grace;
    - `oidc-provider.browser-sessions`;
    - `oidc-provider.codes`;
    - `oidc-provider.grants`;
    - `oidc-provider.refresh-tokens`;
    - `oidc-provider.access-tokens`;
    - `oidc-provider.assertion-ids`;
    - `oidc-provider.device-authorizations`, with the device grant.
  - `(*httpsec.Chain).ExpiryTasks`:
    - `mfa-challenges:<method>`;
    - `reauth-challenges:<method>`;
    - the account-recovery tasks: `recovery-issued-codes`, `recovery-finish-tokens` and `recovery-cancel-tokens`.
  - `session.ExpiryTask`: `sessions`.
  - `lockout.ExpiryTask`: `login-attempts`.
  - `ratelimit.ExpiryTask`: `ratelimit`, for a limiter store that needs pruning.
  - `oidc.FlowExpiryTask`: `oidc-flows`.
  - `oidc.HandoffExpiryTask`: `oidc-handoffs`.
  - `magiclink.ExpiryTask`: `magiclink-tokens`.
  - `(*passkey.Passkeys).ExpiryTasks`: `passkey-login-challenges` and `passkey-registration-challenges`.
  - `onetime.ExpiryTask` and `ExpiryTaskNamed`: for the consumer's own one-time tokens.
  - Not an expiry task: the signing-key manager rotates (hourly by default) and reloads (every minute) on its own once it is started. It only needs `Start`.
- **README, "Federated sign-in without a page script".** It describes the return to the login page, the code list, the cancel endpoint and the override.
- **CHANGELOG.** It lists each behaviour change as such.

## Failure modes

| # | Failure | State | Outcome |
|---|---|---|---|
| F1 | Attacker starts their own SSO login with a victim's handle | Handled, tested | The handle is not bound to the attacker's flow cookie, so the request is an unknown handle, charged. No redirect, and the victim's request is unchanged (D6) |
| F2 | Forged callback with an unknown state names a handle | Handled, tested | No flow, so no `Next`. Invalid state, as today (D5) |
| F3 | Broker error chain carries a forged destination | Handled, tested | `Next` is read from the flow record only (D5) |
| F4 | Device request reaches `EndPending` | Handled, tested | Unknown handle, no relative `Location` (D1) |
| F5 | `EndPending` asked for a code outside the set | Handled, tested | `ErrConfig`, nothing read (D1) |
| F6 | `EndPending` races a resume of the same handle | Handled, tested | One conditional write wins. The loser is an unknown handle, and the request is answered once (D1) |
| F7 | Ending fails, from a store fault or a lost race | Handled, tested | The original login error is answered, and one ERROR record of the type is logged (D4) |
| F8 | Completion's pre-check refused (transport, throttle, unknown handle) | Handled, tested | Unlisted, so the answer is unchanged, with no double charge (D4, D6) |
| F9 | Unreadable error, or a hung-up caller | Handled, tested | Unlisted, with no redirect and no end (D4) |
| F10 | Client's redirect URI unregistered after parking | Handled, tested | Unknown handle, no redirect (D9) |
| F11 | Client lost its grant or scopes after parking | Handled, tested | `unauthorized_client` or `invalid_scope`, spent (D9) |
| F12 | Store fails after the request is read | Handled, tested | `server_error`, if the spend succeeds. Otherwise the dependency error is returned unchanged (D8) |
| F13 | Request expired, within the grace window or past it | Handled, tested | Within it, `access_denied` at the client. Past it, an unknown handle (D7) |
| F14 | Sweep runs within the grace window | Handled, tested | The record is kept, because the cutoff is `now - grace` (D7) |
| F15 | Consumer never runs the expiry tasks on a durable store | Accepted | Expired rows accumulate. They are unusable, and only storage grows. Documented (D13) |
| F16 | Flood of valid authorization requests from many sources | Accepted by default, handled by opt-in | Per-source throttle, a 10-minute lifetime and the sweep. Records are now held for the lifetime plus the grace window, so twice as long by default (D7). The ceiling is opt-in, with its trade-off documented (D12) |
| F30 | A consumer builds their own `MemoryPendingRequestStore` and sets a short grace | Accepted | The store keeps expired records 30 minutes past expiry, the largest grace allowed, since it cannot know the provider's grace. The retention is not configurable. The records are unusable, and running the expiry tasks deletes them on the provider's cutoff (D7) |
| F17 | Concurrent parks exceed the ceiling | Accepted | Overshoot bounded by the concurrency at the instant of the check (D12) |
| F18 | Login page ignores `error=` | Accepted | The user stays on a usable login page. The request expires, and is answered within the grace window if resumed (D7) |
| F19 | Code reveals account state | Handled, tested | Every refusal is `access_denied`, with no description and no other parameter (D3, D10) |
| F20 | Duplicate `AuthnLoginFail`, or a handle, state or target in a log | Handled, tested | One event as today, and one sampled record holding the code alone |
| F21 | Upstream `error=` with a wrong state | Handled, tested | Changes nothing, as today. No flow is ended, so no return |
| F22 | Upstream `error=` whose `iss` names another issuer | Accepted | The outcome is `access_denied` either way. No assertion is made on its strength |
| F23 | Wiring: the straight-to-client override without completion, an invalid error parameter, an out-of-range grace, a ceiling over a store that cannot count | Handled, tested | Configuration error at construction |
| F24 | Held recoveries cancelled before a completion that is later refused | Accepted (as brokered-sign-in-hook D12) | Unchanged by this design. The request now stays parked, so the user can retry |
| F25 | A consumer's 401 handler already sets a challenge | Handled, tested | No duplicate for the same scheme (D11) |
| F26 | A resume writes a code and then fails, leaving the code stored | Handled, tested | The code's grant family is revoked with `CauseUnanswered`, so the exchange refuses the code. If the revocation fails, it is logged, and the code, which nobody holds, expires unredeemed (D8) |
| F27 | `prompt=none` request parked | Handled | Never parked: answered `login_required` at authorize. Covered by the existing tests |
| F29 | `Authorize` answering from an existing browser session writes a code, then fails to update the session | Handled, tested | The code is withdrawn as in F26, and the answer is `server_error` as today (D8) |
| F31 | The clock moves backwards between the return's lookup, which judged the request expired, and `EndPending` | Accepted | A request judged expired within its grace window could be live by `EndPending`'s clock and is ended at the client with `access_denied`. The user is answered rather than stranded, and only the provider's own clock can cause it (D6, D7) |
| F32 | `WithOIDCFailToClient` meets a failed login for a parked device request | Handled, tested | The login page is answered, as by default, and no ERROR record is written (D6) |
| F28 | A consumer's flow store completes a flow whose state differs from the one presented, breaking its own contract | Handled, tested | Treated as a foreign flow: the flow is spent, the callback is `ErrInvalidState` and no `Next` is reported, since `Next` is now trusted to name a parked request (D5) |

## Risks / Trade-offs

- **Behaviour changes on a tagged release.**
  - Failed brokered logins on parked requests now redirect.
  - Some resume refusals now redirect.
  - Bearer 401s now carry a challenge.

  Each is listed in the CHANGELOG as a behaviour change, with its opt-out where one exists. Before
  v1, the release policy allows this with a minor bump.
- **The login page must handle `error=`.** A page that ignores it leaves the user on the login page
  with no message. It is still a better answer than a raw problem body.
- **The grace window keeps expired rows longer.** By default that is twice the lifetime in the
  worst case. They are unusable.
- **Every request takes the same path to its answer.** Distinguishing refusals by timing is no
  easier than through today's problem statuses.

## Migration Plan

Behaviour-only, with no schema change. The ceiling's count uses the existing `expires_at` column,
which is indexed for the sweep. Consumers who want today's behaviour:

- set `WithPendingRequestGrace(0)`;
- set `WithoutBearerChallenge()`;
- keep completion off, or accept the login-page return.

There is no switch back to the problem body at the callback. A consumer who needs it calls the
provider's operations from their own conveyance.

## References

### Researched (accessed 2026-11-24)

- **D3, D4: established practice.**
  - [Keycloak IdentityBrokerService](https://raw.githubusercontent.com/keycloak/keycloak/main/services/src/main/java/org/keycloak/services/resources/IdentityBrokerService.java):
    upstream cancel and failures re-render the login flow or show an error page; no client redirect.
  - [Dex callback handling](https://raw.githubusercontent.com/dexidp/dex/master/server/authflow/callback.go):
    connector failures answered on Dex's own page with fixed text.
  - [Zitadel external login](https://zitadel.com/docs/guides/integrate/login-ui/external-login):
    a failed IdP login goes to an error page (search snippet only).
  - [Auth0, troubleshooting access_denied](https://support.auth0.com/center/s/article/troubleshooting-the-access-denied-error):
    rule and Action denials redirect `access_denied` to the client.
  - [Microsoft Entra authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow):
    `access_denied` on user cancel; `server_error` and `temporarily_unavailable` as redirectable codes.
  - [Ory Hydra API, reject login request](https://raw.githubusercontent.com/ory/hydra/master/spec/api.json):
    a login UI rejects a request with an error code; the closest analogue to D1.
- **D4, D10, F19: generic refusals.** [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html):
  answer missing, locked and disabled accounts alike, with uniform status and timing.
- **D1, D3, D4, D8, D9, D10: the error response.** [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.txt):
  §4.1.2.1 codes, `state` echo and `error_description` characters; §3.1.2.4 no redirect to an
  invalid redirect URI.
- **D7: `login_required` belongs to `prompt=none`.** [OpenID Connect Core 1.0 §3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
- **D1, D8: `iss` on error responses.** [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.txt).
- **D3: 303 status, no referrer.** [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt): §4.12 and §4.2.4.

### Primary documentation

- [RFC 9110 §15.5.2](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2): D11, a 401 carries
  `WWW-Authenticate`.
- [RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750#section-3): D11, the `Bearer` challenge and
  `invalid_token`.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449): D11, the `DPoP` challenge.
- [RFC 7009 §2.2.1](https://www.rfc-editor.org/rfc/rfc7009#section-2.2.1): D12, `unsupported_token_type`.
- [RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585#section-4): D12, 429 Too Many Requests.
- [RFC 8628 §3.3](https://www.rfc-editor.org/rfc/rfc8628#section-3.3): D12, the user interaction is
  the server's.
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1): D3, 307 excluded.

**D2, D5, D6, D7 (sweep), D13:** reasoned from scrty's own settled specs and code, and the
established design.
