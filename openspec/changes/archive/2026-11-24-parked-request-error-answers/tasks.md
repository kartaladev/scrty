# Tasks

Every task is test-first. For each one:

1. Write the failing test.
2. Run it focused: `go test -run '<Name>' -count=1 ./<pkg>/`.
3. Confirm it fails for the intended reason, not a compile error or a missing fixture.
4. Implement until it is green, then refactor.

Each task's verification names the test or command that shows it is done. Table tests follow the `table-test` skill, and mocks the `use-mockgen` skill. Store tests use the `use-testcontainers` helpers.

## 1. Ending a parked request (`oidcprovider`)

- [x] 1.1 Add `EndPending` with the closed code set (D1). **Verify:** a table test where each of `access_denied`, `temporarily_unavailable` and `server_error` answers `<redirect_uri>?error=…&state=…&iss=…` with no `error_description`, keeping a registered query. `state` is left out when none was sent. Any other code is `ErrConfig`, and the store is never read (F5).
- [x] 1.2 Refuse what `EndPending` must not end (D1). **Verify:** a table test where each of these is `ErrUnknownHandle` with the request unchanged: a wrong flow secret, an unknown handle, a request at the consent stage, a spent request, and a device request (F4).
- [x] 1.3 Make ending and resuming race-safe (D1). **Verify:** a barrier test runs `EndPending` and `Resume` on one handle concurrently, under `-race`. Exactly one succeeds and the other is `ErrUnknownHandle` (F6).
- [x] 1.4 Have `rejudge` return a verdict (D9). **Verify:** a table test over resume and end with these rows (F10, F11):
  - redirect URI unregistered: unknown handle, no `Location`;
  - client removed: unknown handle;
  - code grant lost: `unauthorized_client`, spent;
  - `openid` lost: `invalid_scope`;
  - no scope left: `invalid_scope`;
  - one scope dropped: the code is issued as today.
- [x] 1.5 Answer a dependency failure after the read with `server_error` (D8). **Verify:**
  - with a mocked `Advance` or code store failing once, the answer is `redirect_to` with `error=server_error`;
  - with the spend failing too, the original `ErrDependency` is returned and the request is still at the login stage (F12);
  - a code a failed write left behind is refused at the exchange, because its grant family is recorded revoked with `CauseUnanswered` (F26);
  - a code store whose write commits and then reports a failure still has the code's family recorded revoked (F26);
  - `Authorize` answering from an existing browser session, whose session update fails after the code is written, answers `server_error` and has the code's family recorded revoked (F29).
- [x] 1.6 Add `WithPendingRequestGrace` and the expired answer (D7). **Verify:**
  - a table test on a fake clock covers expiry 2 minutes ago (`access_denied` at the client, spent), 11 minutes ago (unknown handle), and grace 0 (unknown handle), for both resume and end (F13);
  - construction refuses a negative grace and one over 30 minutes.
- [x] 1.7 Move the pending-request sweep's cutoff to `now - grace` (D7). **Verify:** a test with a fake clock shows the record kept at 5 minutes past expiry and removed at 11 minutes, with the default grace (F14).
- [x] 1.8 Add the `PendingRequestCounter` interface, the memory store's implementation, and `WithPendingRequestLimit` (D12). **Verify:**
  - with no option, everything parks;
  - at the ceiling, a valid request gets `temporarily_unavailable` at the redirect URI and nothing is stored;
  - a store without the interface fails construction (F23).
- [x] 1.9 Add `WithStrictRevocation` (D12). **Verify:** a table test:
  - without the option, a valid JWT access token gets 200;
  - with it, 400 `unsupported_token_type`;
  - with it, an unknown value and an opaque token get 200.
- [x] 1.10 Run the lane's scoped verification. **Verify:** `go test ./oidcprovider/... ./httpsec/...`, the `test` module's dependents of `oidcprovider`, `go vet` and `gofmt -l` are clean.

## 2. The flow's destination on failure (`authenticate/oidc`)

- [x] 2.1 Have `Callback` return `CallbackResult{Next}` after the flow is spent (D5). **Verify:**
  - a table test for discovery, exchange, invalid ID token and broker refusals shows `Next` equal to the stored flow's, with every other field zero;
  - unspent failures still return the empty result;
  - a broker error that wraps a forged destination does not change `Next` (F3).
- [x] 2.2 Add `AbortFlowNext` and have `AbortFlow` delegate to it, keeping its signature (D5). **Verify:**
  - the ended flag and `Next` come back for a matching state;
  - a wrong or missing state gives `Ended=false` with an empty `Next` (F21);
  - the existing `AbortFlow` tests pass unchanged.
- [x] 2.3 Run the lane's scoped verification. **Verify:** `go test ./authenticate/oidc/... ./httpsec/...` and the `test` module's dependents, `go vet` and `gofmt -l` are clean.
- [x] 2.4 Pass a sign-in hook's `ErrUserInfoFailed` through as a bare sentinel (D4, `identity-linking`). **Verify:**
  - a hook returning an error that wraps `ErrUserInfoFailed` fails the login with `errors.Is(err, ErrUserInfoFailed)`, and the error's text is `ErrUserInfoFailed`'s alone, with none of the hook's text;
  - a hook error wrapping another library outcome is still a broker failure;
  - the apply step's errors are unchanged;
  - through the chain, a UserInfo outage inside a hook of a parked login returns to the login page with `temporarily_unavailable`.

## 3. Counting live parked requests (store adapters)

- [x] 3.1 Add a `CountLive` conformance case to the pending-request suite in the `test` module. **Verify:** the case fails on an adapter without it, because the type assertion fails.
- [x] 3.2 Implement `CountLive` in `store/sqlstore`, `store/pgxstore` and `store/gormstore` as a count of rows with `expires_at` after `now` (D12). **Verify:**
  - the conformance case passes on each adapter against PostgreSQL via testcontainers;
  - expired and spent-but-live rows are counted as the contract states.

## 4. Provider endpoints (`httpsec`)

- [x] 4.1 Add the `OIDCCancel` endpoint at `/authorize/cancel` with no session requirement (D2). **Verify:** a table test through the chain:
  - a live handle with its flow cookie gets 200 `redirect_to` with `access_denied`, `state` and `iss`, and `no-store`;
  - an unknown handle gets 400 and is charged;
  - a throttled source gets 429 before the lookup;
  - plain HTTP, a cross-site POST and an oversized body are refused as at resume;
  - a path set with `WithOIDCProviderPath` serves it there;
  - the endpoint appears in `Chain.Endpoints()`.
- [x] 4.2 Have the resume endpoint and completion answer the new client-error outcomes (D7, D8, D9). **Verify:**
  - resume answers 200 `redirect_to` for `server_error`, `unauthorized_client`, `invalid_scope` and an expired request within grace;
  - completion's `answerFor` treats them as `answerEnded`;
  - an unknown outcome is still refused.
- [x] 4.3 Add the bearer challenge on bearer chains, and `WithoutBearerChallenge` (D11). **Verify:** a table test through the chain:
  - an expired bearer at a consumer route gets one `Bearer error="invalid_token"`;
  - no credential gets a bare `Bearer`;
  - DPoP on gets `DPoP`;
  - the opt-out gets no challenge;
  - a cookie-only chain gets none;
  - a consumer handler's own challenge is not duplicated (F25);
  - the provider endpoints behave as before.
- [x] 4.4 Add the 429 option for throttled client sources (D12). **Verify:**
  - the default stays 401 `invalid_client`;
  - with the option, the token, revocation, introspection and device-authorization endpoints answer 429 with an integer `Retry-After` of at least 1.
- [x] 4.5 Add `WithOIDCEntryRedirects` (D12). **Verify:**
  - the default is unchanged;
  - with the option, an unknown, expired or claimed code gets a 303 to the entry page with `result=invalid`, and a throttled source `result=throttled`, with nothing else in the query.
- [x] 4.6 Run every framework adapter against tasks 4.1–4.5. **Verify:** the adapter parity tests in `httpsec/ginsec` and `httpsec/fibersec` show the same status, headers and body.

## 5. Failed brokered logins for parked requests (`httpsec`)

- [x] 5.1 Add `DefaultOIDCLoginErrorParam`, `WithOIDCLoginErrorParam` and `WithOIDCFailToClient` (D3). **Verify:** construction refuses an empty parameter, the name `req`, an invalid query key, and the to-client option without completion (F23).
- [x] 5.2 Map failures to codes from the existing single walk (D4). **Verify:**
  - a table test over every listed error gives its code;
  - every unlisted case gives no code: an invalid state, an unknown provider, an unspent store fault, an aborted walk, a hung-up caller, `ErrOIDCReauthenticate`, completion's transport, throttle and unknown-handle refusals, and an unclassifiable broker error (F8, F9).
- [x] 5.3 Run completion's checks before any return (D6). **Verify:**
  - a handle bound to another browser gets the original error, no redirect and one charge (F1);
  - a request at the consent stage gets the original error;
  - over plain HTTP, the original error;
  - throttled, the original error;
  - a source is never charged twice for one callback (F8).
- [x] 5.4 Return a failed callback to the login page (D3). **Verify:** a table test through the chain shows a 303 to `<LoginURL>?req=h-1&error=<code>` with `no-store`, `no-referrer` and nothing else in the query, the request still resumable, and the flow cookie cleared, for each of:
  - a hook refusal;
  - the one-link rule;
  - an invalid ID token;
  - no linked account;
  - an exchange outage;
  - a userinfo outage.
- [x] 5.5 Return an upstream `error=` on a completed flow (D3, D5). **Verify:**
  - the real state gives a 303 to the login page with `access_denied` and the cookie cleared;
  - a forged state changes nothing, as today (F21).
- [x] 5.6 Return a discovery failure at the login start (D3). **Verify:**
  - with `next=<LoginURL>?req=h-1`, the answer is a 303 with `temporarily_unavailable`, no flow is stored and no flow cookie is set;
  - with an ordinary `next`, the answer is unchanged.
- [x] 5.7 Return completion's own refusals (D3, D4). **Verify:** a table test:
  - an unknown, inactive or mismatched user gets `access_denied` and no session;
  - a post-authentication denial gets `access_denied`;
  - a per-request refusal gets `access_denied`, with the stored session ended;
  - a user loader failure gets `server_error`;
  - a session store failure gets `server_error`;
  - an owed step still falls back to the handoff.
- [x] 5.8 Answer an expired request within grace at the client on these paths (D6, D7). **Verify:** a parked request that expired 2 minutes before the failure gets a 303 to the client's redirect URI with `access_denied`, `state` and `iss`, and is spent.
- [x] 5.9 Answer the client directly under `WithOIDCFailToClient` (D3). **Verify:**
  - a hook refusal gets a 303 to the client with `access_denied`, `state` and `iss`, and the handle is spent;
  - if ending fails, the original error is answered and one ERROR record logged (F7).
- [x] 5.10 Keep events and logs as before (F20). **Verify:**
  - exactly one `AuthnLoginFail` per refused parked login and none for outages;
  - one sampled record per redirect carrying the code;
  - no record holds a handle, state, code or redirect target, checked by scanning the captured log output.
- [x] 5.11 Leave non-parked logins unchanged. **Verify:** existing callback and completion tests pass, including an ordinary destination, an extra parameter, a look-alike path and completion off, without edits.
- [x] 5.12 Run every framework adapter against tasks 5.4–5.9. **Verify:** the adapter parity tests pass.

## 6. Documentation

- [x] 6.1 Add a short README note, "Scheduled jobs (later work)", listing every expiry task and its source, the signing-key manager's own rotation and reload loop, and the parked-request grace. It states that durable stores are swept only when the consumer runs the tasks, and that wiring guidance is later work (D13). **Verify:** the note names every task listed in D13, with no wiring example and no new test.
- [x] 6.2 Update the README sections "Federated sign-in without a page script" and "OpenID Provider" (D2, D3, D11). **Verify:** they describe the return to the login page, the code list, the cancel endpoint, the to-client override, the bearer challenge and its opt-out, with no wording left saying "a refusal sends no redirect".
- [x] 6.3 Write godoc for every new option, method, constant and interface, naming the default each replaces. **Verify:** `go doc` on each shows the default and the override.
- [x] 6.4 Add CHANGELOG entries listing each behaviour change and its opt-out. **Verify:** each entry matches a **BREAKING** item in the proposal.

## 7. Final gate

- [x] 7.1 Run the whole-branch review against every requirement in the change's specs. **Verify:** a fresh reviewer's report has no open finding.
- [x] 7.2 Run the full suite once, after the last code edit. **Verify:** `make check` and `make spec-check` pass, with the output read by the main session.

## Workflow follow-up

- Archive the change after release, and send the release to the CRM session.
