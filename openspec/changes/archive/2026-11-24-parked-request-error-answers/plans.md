# Parked-Request Error Answers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code: every task below is a subagent dispatch (`.claude/rules/subagent-delegation.md`).

**Goal:** Every failure on the parked-request path that can safely reach the client gets the standard authorization error response, or a return to the login page. The bearer chain's 401 carries its challenge. Opt-in hardening covers the rest.

**Architecture:** One new provider operation (`EndPending`) is the single place a login-stage request is ended with an error. Resume, cancel, completion and the brokered-SSO failure paths all reach the client through it, or through `refuseRequest`'s existing location builder. `authenticate/oidc` reports the stored flow destination on failure, so `httpsec` can recognise a parked request without trusting an error chain. `httpsec` maps failures to codes with an allow-list and runs completion's guards before any redirect.

**Tech Stack:** Go 1.27, `oidcprovider`, `authenticate/oidc`, `httpsec` (plus `ginsec`, `fibersec` parity), `store/{sqlstore,pgxstore,gormstore}`, the `test` module, testify, `go.uber.org/mock`, testcontainers (PostgreSQL).

**Spec:**
- `openspec/changes/parked-request-error-answers/proposal.md`
- `design.md`: decisions D1–D13, failure modes F1–F27
- `specs/{oidc-provider-authorization,oidc-login,http-error-propagation,oidc-provider-clients,oidc-provider-tokens,oidc-provider-device-authorization}/spec.md`
- `tasks.md`

## Global Constraints

**Codes and messages**
- End codes: exactly `access_denied`, `temporarily_unavailable`, `server_error`. Anything else is `oidcprovider.ErrConfig`.
- Rejudge codes: `unauthorized_client` (code grant lost), `invalid_scope` (`openid` lost or no scope left).
- No `error_description` on any new redirect (D10).
- No new log record or error text holds a handle, state, code, flow secret or redirect target.

**Grace window**
- Default 10 minutes, bounded 0 to 30 minutes inclusive. `0` turns it off.
- Expired-within-grace answer: `access_denied`.
- Sweep cutoff: `now - grace`, judged by the provider's clock.

**Names and endpoints**
- Login-page error parameter: `DefaultOIDCLoginErrorParam = "error"`. Refuse empty, `req`, or an invalid query key.
- Cancel endpoint: `OIDCCancel`, default `/authorize/cancel` under the provider prefix, POST, JSON body `{"req":"<handle>"}`, no session requirement.

**Compatibility**
- Public signatures stay as they are: `RelyingParty.Callback`, `RelyingParty.AbortFlow`, `Provider.Resume`, `PendingRequestStore`. Only additions.
- Every new option's godoc names the default it replaces (library-design).
- Godoc is concise: a short first sentence saying what the symbol does, then only what a caller needs (the default, the override, and the outcome a caller sees on failure). No restating of the design, no internal mechanism, no history. Most symbols need two to five lines.

**Process**
- Test-first: red run focused with `go test -run '<Name>' -count=1 ./<pkg>/`. The failure is read and must be the intended one; a compile error is not a red step.
- Table tests use the `table-test` skill: an `assert` closure, a `ctx` modifier, and `t.Context()`. Mocks use `use-mockgen` with `--typed`. Store tests use the `use-testcontainers` helpers.
- The read-only reference follows `legacy-reference.md`. No discarding git command (`checkout --`, `restore`, `reset --hard`, `stash`, `clean`).

## Review Focus

1. **A login page that POSTs cancel twice** (double click), or races its own resume. Expect one `redirect_to`, then an unknown handle, never two answers. Pinned in Task 1.3 and Task 4.1 (`TestCancel_SecondCancelIsUnknownHandle`).
2. **A login URL whose path the consumer later moves**, while flows started under the old URL are still in flight. Their `next` no longer matches `parkedHandle`, so the failure keeps today's answer and is never redirected to a stale page. Pinned in Task 5.4 (`TestCallback_UnparkedDestinationKeepsAnswer`).
3. **A clock that jumps backwards between the grace check and the spend.** The record must not be both answered as expired and resumed. Pinned in Task 1.6 (`TestEndPending_ExpiredGraceIsSpentOnce`).
4. **A consumer error parameter that collides with a parameter the login page reads**, such as `req` or `handoff`. Pinned in Task 5.1 (`TestParkedFailureOptions_Construction`), which refuses `req` and `handoff`.
5. **`Retry-After` from a limiter that reports a zero or negative retry time.** Expect `Retry-After: 1`. Pinned in Task 4.4.

---

## Lanes, order and models

| Lane | Tasks | Owns (writes) | Depends on | Model | Reason |
|---|---|---|---|---|---|
| A | 1.1–1.10 | `oidcprovider/*` | — | Opus | Security-critical refusal logic and races (end vs resume, conditional spend) |
| B | 2.1–2.3 | `authenticate/oidc/*` | — | Sonnet | Signatures and tests fixed here; a known pattern |
| B2 | 2.4 | `authenticate/oidc/broker_hook.go` and its tests | B | Sonnet | One more bare sentinel in an existing classifier; the chain-level row belongs to E2 |
| C | 3.1–3.2 | `test/storetest/oidcprovider_pending_suite.go`, `store/{sqlstore,pgxstore,gormstore}/oidcprovider_stores.go` | A (1.8 interface) | Sonnet | A conformance case plus three SQL counts against a stated contract |
| D | 4.1–4.6 | `httpsec/oidc_resume.go`, `httpsec/oidc_cancel.go` (new), `httpsec/oidc_provider_options.go`, `httpsec/oidc_provider.go`, `httpsec/dpop_nonce.go`, `httpsec/bearer.go`, `httpsec/oidc_token.go`, `httpsec/oidc_revoke.go`, `httpsec/oidc_device.go`, `httpsec/oidc_client_auth.go`, adapter parity tests | A, B | Opus | New endpoint and a chain-wide header change other lanes compile against |
| E | 5.1–5.12 | `httpsec/oidc_login.go`, `httpsec/oidc_completion.go`, `httpsec/oidc_options.go`, `httpsec/oidc_parked_failure.go` (new) | A, B, and D's 4.2 (`answerFor`) | Opus | Refusal mapping and guard ordering; a mistake here would pass tests and still be wrong |
| Docs | 6.1–6.4 | `README.md`, `CHANGELOG.md` | D, E | Sonnet | Docs against settled behaviour |

- **Lanes D and E both write `httpsec`, but disjoint files.** `oidc_completion.go`'s `answerFor` is changed by D (task 4.2) and is read by E. So E starts after D's dispatch 4.1–4.2 lands, not after all of D.
- **Dispatches.**
  - A is split at its natural seam: A1 = 1.1–1.5, A2 = 1.6–1.10.
  - D: D1 = 4.1–4.2, D2 = 4.3–4.6.
  - E: E1 = 5.1–5.6, E2 = 5.7–5.12.
- **Order:**
  1. A1 ∥ B;
  2. A2;
  3. C ∥ D1;
  4. D2 ∥ E1;
  5. E2;
  6. Docs;
  7. 7.x.

  A fresh reviewer runs after each dispatch, on the same model tier.
- **Scoped verification per lane** (`test-scope.md`):
  - **A:** `go test -count=1 ./oidcprovider/... ./httpsec/...`, then `cd test && go test -count=1 ./... -run 'OIDCProvider|Pending|Expiry'`, and `go vet ./oidcprovider/... && gofmt -l oidcprovider`.
  - **B:** `go test -count=1 ./authenticate/oidc/... ./httpsec/...`, then `cd test && go test -count=1 ./... -run 'OIDC'`, and `go vet ./authenticate/oidc/...`.
  - **C:** `cd test && go test -count=1 ./storetest/... ./... -run 'Pending|OIDCProvider'` (Docker), plus `go vet` in each store module.
  - **D, E:** `go test -count=1 ./httpsec/...`, then `cd httpsec/ginsec && go test ./...`, `cd httpsec/fibersec && go test ./...`, `cd test && go test -count=1 ./... -run 'OIDC|Chain|Bearer'`, and `go vet ./httpsec/...`.

---

### Task 1.1: `EndPending` with the closed code set

**Files:**
- Create: `oidcprovider/endpending.go`
- Test: `oidcprovider/endpending_test.go`

**Interfaces:**
- Produces:
  - `type EndPendingInput struct { Handle, FlowSecret, Code string }`
  - `func (p *Provider) EndPending(ctx context.Context, in EndPendingInput) (ResumeResult, error)`, returning `Outcome: ResumeOutcomeClientError` and `RedirectTo` built by `redirectRefusal.location`.
  - Exported constants for the set: the existing `CodeAccessDenied`, a new `CodeTemporarilyUnavailable = "temporarily_unavailable"`, and `codeServerError` made public as `CodeServerError = "server_error"`, keeping the old unexported name as an alias.
  - `EndPendingInput` gets redacted `Format` and `LogValue`, like `ResumeInput`.

- [ ] **Step 1:** Write `TestEndPending_AnswersRedirectURIWithCode`, a table over the three codes. Each case parks with `state=s-1` and redirect URI `https://rp.example.com/cb?tenant=a`. `assert`: `RedirectTo` equals `https://rp.example.com/cb?tenant=a&error=<code>&iss=<issuer>&state=s-1` (query-compared), contains no `error_description`, and has `Outcome == ResumeOutcomeClientError`. Add a row with no state that asserts `state` is absent.
- [ ] **Step 2:** Write `TestEndPending_RefusesCodeOutsideSet` with `invalid_grant`, `""` and `ACCESS_DENIED`. `assert`: `errors.Is(err, ErrConfig)`, and a typed `PendingRequestStore` mock expects **no** `Load` call (F5).
- [ ] **Step 3:** Run `go test -run 'TestEndPending_' -count=1 ./oidcprovider/`. Expect FAIL with `undefined: EndPending`. That is a compile failure, so stub the method to return `ResumeResult{}, nil`, rerun, and expect assertion failures.
- [ ] **Step 4:** Implement: validate the code first; `loadPending`; `rc` and `rejudge` as in `Resume`; then `refuseRequest(ctx, r, StageLogin, code)`.
- [ ] **Step 5:** Rerun and expect PASS. Commit: `feat(oidcprovider): end a login-stage parked request with an error`.

### Task 1.2: What `EndPending` refuses

**Files:** Modify `oidcprovider/endpending.go`. Test `oidcprovider/endpending_test.go`.

- [ ] **Step 1:** Write `TestEndPending_RefusesAsUnknownHandle`, a table with these rows: wrong flow secret, unknown handle, consent stage, already spent, device request parked by `EnterUserCode`. `assert`: `errors.Is(err, ErrUnknownHandle)`, `RedirectTo == ""`, and a following `PendingRequest` (with the right flow) still shows the original stage for the live rows (F4).
- [ ] **Step 2:** Run it focused and expect FAIL on the device and consent rows.
- [ ] **Step 3:** Implement the stage check and refuse `r.DeviceAuthorizationID != id.Nil` before `rejudge`.
- [ ] **Step 4:** Expect PASS. Commit.

### Task 1.3: End and resume race

**Files:** Test `oidcprovider/endpending_race_test.go`.

- [ ] **Step 1:** Write `TestEndPending_RacesResumeOnce`, using the barrier pattern from `test/storetest/oidcprovider_race.go`. Over 50 iterations, `EndPending` and `Resume` on one handle start together. `assert`: exactly one returns a nil error, and the other `ErrUnknownHandle`.
- [ ] **Step 2:** Write `TestEndPending_SecondEndIsUnknownHandle` (Review Focus 1).
- [ ] **Step 3:** Run `go test -race -run 'TestEndPending_(Races|Second)' -count=1 ./oidcprovider/`. If it passes immediately, temporarily replace the conditional `Advance` with an unconditional write in a scratch copy and confirm the test fails, then restore by editing back.
- [ ] **Step 4:** Commit.

### Task 1.4: `rejudge` returns a verdict

**Files:** Modify `oidcprovider/resume.go` (`rejudge`, `Resume`). Test `oidcprovider/resume_rejudge_test.go`.

**Interfaces:**
- Produces: `rejudge(r, rc) (req *PendingRequest, dropped []string, verdict rejudgeVerdict)`, with these verdicts:
  - `rejudgeOK`;
  - `rejudgeUnknown`: client gone, or redirect URI unregistered;
  - `rejudgeUnauthorized`: answer `unauthorized_client`;
  - `rejudgeInvalidScope`: answer `invalid_scope`.

  Exported constants `CodeUnauthorizedClient` and `CodeInvalidScope` already exist.

- [ ] **Step 1:** Write `TestResume_RejudgeAnswers`, a table over resume and `EndPending` (F10, F11):
  - redirect URI unregistered: unknown handle, no `RedirectTo`;
  - client removed: unknown handle;
  - code grant lost: `error=unauthorized_client`, then a second resume is unknown;
  - `openid` lost: `error=invalid_scope`;
  - every scope lost: `error=invalid_scope`;
  - `profile` lost: a code issued for `openid` only.
- [ ] **Step 2:** Run it focused and expect FAIL on the three redirect rows (today they are unknown handles).
- [ ] **Step 3:** Implement the verdicts. A redirect verdict calls `refuseRequest` with the code from the request's current stage. A device request keeps `rejudgeUnknown`.
- [ ] **Step 4:** PASS, plus the existing `TestResume*` tests unchanged. Commit.

### Task 1.5: Dependency failure after the read answers `server_error`

**Files:** Modify `oidcprovider/resume.go`, `oidcprovider/endpending.go`. Test `oidcprovider/resume_dependency_test.go`.

- [ ] **Step 1:** Write `TestResume_DependencyFailureAnswersServerError` with the typed mocks (`use-mockgen`):
  - the code store's `Create` fails once and the pending store's `Advance` succeeds: `RedirectTo` carries `error=server_error`;
  - both fail: `errors.Is(err, ErrDependency)`, `RedirectTo == ""`, and the request is still at `StageLogin` (F12).
- [ ] **Step 2:** Write `TestExchange_CodeLeftByFailedResumeIsRefused` (F26).
- [ ] **Step 3:** Run it focused and expect FAIL on row 1.
- [ ] **Step 4:** Implement: wrap the post-`rejudge` part of `resumeLogin` and `resumeConsent` so that an `ErrDependency` tries `refuseRequest(…, CodeServerError)` and returns the original error if that fails. Not for `ErrReauthenticate`, `ErrConsentMalformed` or `ErrUnknownHandle`. A code written before the failure is withdrawn by `withdrawCode`, which records its grant family revoked with `CauseUnanswered` (D8, F26).
- [ ] **Step 5:** PASS. Commit.

**Interfaces (added after review):**
- Produces: `CauseUnanswered RevocationCause = "unanswered"`. `issueCode` reports the code's grant family even when `codes.Create` fails, so the caller can withdraw a code whose write committed and then reported a failure.

- [ ] **Step 6:** Write `TestResume_CommittedCodeWriteFailureIsWithdrawn` (F26). The typed code-store mock's `Create` writes the record to a memory store, then returns an outage. `assert`: `redirect_to` carries `error=server_error`, and `grants.Load(family)` shows the family revoked with `CauseUnanswered`.
- [ ] **Step 7:** Write `TestAuthorize_SessionTouchFailureWithdrawsCode` (F29). `Authorize` answers from an existing browser session, the session store's `Touch` fails after the code is written. `assert`: the answer carries `error=server_error`, and the code's family is recorded revoked with `CauseUnanswered`.
- [ ] **Step 8:** Run `go test -run 'TestResume_CommittedCodeWriteFailureIsWithdrawn|TestAuthorize_SessionTouchFailureWithdrawsCode' -count=1 ./oidcprovider/`. Expect FAIL with `ErrNotFound` from `grants.Load`: the family was never recorded revoked.
- [ ] **Step 9:** Implement:
  - `issueCode` returns the family on a `Create` failure;
  - `answerConsent` sets the issued family before its error check;
  - `Authorize`'s browser-session answer calls `withdrawCode` when a step after the code write fails.
- [ ] **Step 10:** PASS, together with `TestResume_DependencyFailureAnswersServerError`, `TestExchange_CodeLeftByFailedResumeIsRefused` and the `WriteOrder` tests. Commit.
- [ ] **Step 11 (review nits):**
  - make the hung-up row of `resume_dependency_test.go` fail its store with an outage on a cancelled context, so removing the `ctx.Err()` check fails that row;
  - assert in `TestEndPending_RacesResumeOnce` that the losing resume's code family is recorded revoked.

### Task 1.6: Grace window and the expired answer

**Files:** Modify `oidcprovider/options.go`, `oidcprovider/pending.go` (`loadPending`), `oidcprovider/resume.go`, `oidcprovider/endpending.go`. Test `oidcprovider/pending_grace_test.go`.

**Interfaces:**
- Produces:
  - `func WithPendingRequestGrace(d time.Duration) Option`, default `defaultExpiredRequestGrace = 10 * time.Minute`, max `maxExpiredRequestGrace = 30 * time.Minute`;
  - `loadPending` gains a result that says "expired within grace" (unexported), which `Resume` and `EndPending` turn into `refuseRequest(…, CodeAccessDenied)`;
  - `PendingRequest` (the view) still refuses expired requests as unknown.

- [ ] **Step 1:** Write `TestExpiredRequestGrace`, a table on `clockwork.NewFakeClock` over resume and end (F13):
  - +2m past expiry: `access_denied` at the client, then unknown;
  - +11m past expiry: unknown;
  - grace 0, +1m past expiry: unknown;
  - an expired request bound to another flow: unknown.
- [ ] **Step 2:** Write `TestWithPendingRequestGrace_Bounds`: `-1ns` and `30m+1ns` give `ErrConfig`; `0` and `30m` build.
- [ ] **Step 3:** Write `TestEndPending_ExpiredGraceIsSpentOnce` (Review Focus 3): the fake clock moves back 1 minute between two calls, and only one answers.
- [ ] **Step 4:** Run them focused and expect FAIL. Implement. Expect PASS. Commit.

### Task 1.7: Sweep cutoff

**Files:** Modify `oidcprovider/expiry.go` (`sweepPendingRequests`). Test `oidcprovider/expiry_test.go`.

- [ ] **Step 1:** Write `TestSweepPendingRequests_KeepsGraceWindow`: a fake clock, a memory store, a request expired 5 minutes ago (kept) and one 11 minutes ago (removed), with the count asserted as `1` (F14).
- [ ] **Step 2:** Run it, FAIL, implement `DeleteExpired(ctx, now.Add(-grace))`, PASS. Update the `ExpiryTasks` godoc line for `"oidc-provider.pending-requests"`. Commit.

### Task 1.8: Counter interface and ceiling

**Files:** Modify `oidcprovider/store.go`, `oidcprovider/store_memory.go`, `oidcprovider/options.go`, `oidcprovider/pending.go` (`parkAt`). Test `oidcprovider/pending_ceiling_test.go`.

**Interfaces:**
- Produces:
  - `type PendingRequestCounter interface { CountLive(ctx context.Context, now time.Time) (int, error) }` counts records with `ExpiresAt` strictly after `now`, whatever the stage;
  - `func WithPendingRequestLimit(n int) Option`, with `n > 0`;
  - a store without the counter fails construction with `ErrConfig` naming the store;
  - at the ceiling, `Authorize` answers `refuseAtRedirectURI(req, CodeTemporarilyUnavailable)`, and `Create` is not called;
  - a `CountLive` error is `ErrDependency`, answered `server_error` as today's dependency path.

- [ ] **Step 1:** Write `TestPendingRequestCeiling`, a table:
  - no option, 3 parks: 3 parked;
  - ceiling 2, 3 parks: the third gets `temporarily_unavailable` with `state` and `iss`, and the mock expects no third `Create`;
  - the counter errs: `server_error`;
  - ceiling 0: `ErrConfig`.
- [ ] **Step 2:** Write `TestWithPendingRequestLimit_StoreCannotCount`: a store mock without `CountLive` gives `ErrConfig` (F23).
- [ ] **Step 3:** FAIL, implement (including the memory store's `CountLive` under its lock), PASS. Regenerate mocks with `go generate ./oidcprovider/...`. Commit.

### Task 1.9: Revocation refusal option

**Files:** Modify `oidcprovider/revoke.go`, `oidcprovider/options.go`. Test `oidcprovider/revoke_test.go`.

**Interfaces:**
- Produces: `func WithStrictRevocation() Option`, which makes `Revoke` return `&Error{Code: "unsupported_token_type"}` (a new constant `CodeUnsupportedTokenType`) for a valid, unexpired JWT access token of the calling client.

- [ ] **Step 1:** Write `TestRevoke_JWTAccessToken`, a table:
  - default: nil error;
  - option on: the `unsupported_token_type` error;
  - option on with an unknown value: nil;
  - option on with an opaque token: revoked and nil;
  - option on with another client's JWT: success with nothing read, as today.
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 1.10: Lane A verification

- [ ] Run lane A's scoped commands (see Lanes). Expect every package to say `ok`, `go vet` to be silent, and `gofmt -l` to print nothing. Report the red outputs of 1.1–1.9.

---

### Task 2.1: `Callback` reports the destination after the flow is spent

**Files:** Modify `authenticate/oidc/login.go` (`Callback`, godoc). Test `authenticate/oidc/login_next_test.go`.

**Interfaces:**
- Produces: on any error after `completeFlow` succeeds, `Callback` returns `CallbackResult{Next: f.Next}` with every other field zero. The godoc states it.

- [ ] **Step 1:** Write `TestCallback_FailureAfterSpendCarriesNext`, a table where the flow is parked with `Next: "https://op.example/login?req=h-1"`:
  - discovery fails;
  - exchange fails;
  - invalid ID token;
  - broker `ErrNoLinkedAccount`;
  - broker error wrapping a struct with a `Next` field of `"https://evil"`.

  `assert`: `res.Next` equals the flow's, `res.Principal == nil`, and `res.IDToken == ""` (F3).
- [ ] **Step 2:** Write `TestCallback_UnspentFailureHasNoNext`: an unknown state and an empty code give `CallbackResult{}`.
- [ ] **Step 3:** FAIL, implement, PASS. Commit.

### Task 2.2: `AbortFlowNext`

**Files:** Modify `authenticate/oidc/login.go`. Test `authenticate/oidc/login_abort_test.go`.

**Interfaces:**
- Produces:
  - `type AbortedFlow struct { Ended bool; Next string }`
  - `func (m *RelyingParty) AbortFlowNext(ctx context.Context, provider, state, handle string) (AbortedFlow, error)`
  - `AbortFlow` returns `(res.Ended, err)` from it.
  - A foreign flow gives `Ended: true, Next: ""`.

- [ ] **Step 1:** Write `TestAbortFlowNext`, a table:
  - matching state: `{true, flow.Next}`;
  - wrong state: `{false, ""}`;
  - empty state: `{false, ""}`;
  - foreign flow: `{true, ""}`;
  - store fault: an error wrapping the store's, with `Ended` false.
- [ ] **Step 2:** FAIL, implement, PASS. The existing `AbortFlow` tests pass untouched. Commit.

### Task 2.3: Lane B verification

- [ ] Run lane B's scoped commands and report.

### Task 2.4: A hook's UserInfo failure passes through

**Files:** Modify `authenticate/oidc/broker_hook.go` (`hookError`, its godoc). Test `authenticate/oidc/broker_hook_test.go`.

**Interfaces:**
- Produces: `hookError` returns the bare `ErrUserInfoFailed` when, at `hookStageDecide`, the hook's error matches it by `errors.Is`. It is checked after the unwalkable check and beside the two refusal sentinels, and logs no refusal record. The apply stage and every other wrapped library outcome are unchanged.
- Consumed by: Task 5.4 (lane E2 adds the chain-level row).

- [ ] **Step 1:** Add rows to the existing hook-error table:
  - the hook returns `fmt.Errorf("lookup for %s: %w", email, ErrUserInfoFailed)`: `errors.Is(err, ErrUserInfoFailed)`, `err.Error() == ErrUserInfoFailed.Error()`, and the text holds neither the email nor the access token;
  - the apply step returns an error wrapping `ErrUserInfoFailed`: a broker failure, not `ErrUserInfoFailed`;
  - the hook returns an error wrapping `ErrExchangeFailed`: still a broker failure (the settled "Wrapped library outcome" scenario).
- [ ] **Step 2:** Run `go test -run '<table name>' -count=1 ./authenticate/oidc/`. Expect FAIL on the first row: the error is a `*hookFailure`.
- [ ] **Step 3:** Implement. Rerun and expect PASS, with the existing hook tests unchanged.
- [ ] **Step 4:** Run lane B's scoped commands.

---

### Task 3.1: Conformance case for `CountLive`

**Files:** Modify `test/storetest/oidcprovider_pending_suite.go`.

- [ ] **Step 1:** Add the subtest `CountLive`:
  - park 3 records: 2 live (one at `StageDone`) and 1 expired;
  - `assert`: the store implements `oidcprovider.PendingRequestCounter`, and `CountLive(now) == 2`;
  - `CountLive(now)` with `now == ExpiresAt` of a record excludes it.
- [ ] **Step 2:** Run `cd test && go test -run 'Pending.*CountLive' -count=1 ./...`. Expect FAIL on the durable adapters with "does not implement PendingRequestCounter", and PASS on memory.

### Task 3.2: Adapters

**Files:** Modify `store/sqlstore/oidcprovider_stores.go`, `store/pgxstore/oidcprovider_stores.go`, `store/gormstore/oidcprovider_stores.go`.

- [ ] **Step 1:** Implement `CountLive` as `SELECT count(*) FROM <pending table> WHERE expires_at > $1`, using each adapter's existing table-name helper and `WithTx` resolution. Errors are wrapped with fixed text, as the adapter's other methods do.
- [ ] **Step 2:** Run lane C's command and expect PASS on PostgreSQL. Commit `feat(store): count live pending requests`.

---

### Task 4.1: Cancel endpoint

**Files:**
- Create: `httpsec/oidc_cancel.go`
- Modify: `httpsec/oidc_provider_options.go` (add `OIDCCancel: {"OIDCCancel", "/authorize/cancel"}`), `httpsec/oidc_provider.go` (route table: `at(OIDCCancel, OperationOAuth2AuthorizeCancel, NoSessionRequired, http.MethodPost)`, using the same name the table uses for the authorize route's no-session flag), `httpsec/endpoints.go` (`OperationOAuth2AuthorizeCancel = "scrty.oauth2.authorize.cancel"`), `httpsec/oidc_resume.go` (share the group's guards)
- Test: `httpsec/oidc_cancel_test.go`

**Interfaces:**
- Consumes: `oidcprovider.EndPending` (1.1).
- Produces: the endpoint answers 200 `{"redirect_to": …}` with `Cache-Control: no-store`. Refusals go through `oidcResumeRefusal`.

- [ ] **Step 1:** Write `TestCancel`, a table through a full chain (`httptest`):
  - live handle and flow cookie: 200, `redirect_to` query has `error=access_denied`, `state`, `iss`;
  - unknown handle: 400, and the throttle mock records one charge;
  - throttled source: 429, and the provider is never called;
  - plain HTTP: refused as at resume;
  - cross-site POST: refused as at resume;
  - body over the limit: 413;
  - wrong content type: 400, as at resume;
  - `WithOIDCProviderPath(OIDCCancel, "/login/give-up")`: served there, and the default path is 404;
  - `Chain.Endpoints()` lists `OperationOAuth2AuthorizeCancel`.
- [ ] **Step 2:** Write `TestCancel_SecondCancelIsUnknownHandle` (Review Focus 1).
- [ ] **Step 3:** Run `go test -run 'TestCancel' -count=1 ./httpsec/`. Expect FAIL with 404.
- [ ] **Step 4:** Implement. Expect PASS. Commit.

### Task 4.2: Resume and completion answer the new client-error outcomes

**Files:** Modify `httpsec/oidc_resume.go`, `httpsec/oidc_completion.go` (`answerFor`). Test `httpsec/oidc_resume_test.go`, `httpsec/oidc_completion_test.go`.

- [ ] **Step 1:** Write `TestResume_ClientErrorOutcomes`, a table:
  - `server_error` (mock store);
  - `unauthorized_client`;
  - `invalid_scope`;
  - expired within grace.

  `assert` 200 and `redirect_to` holding the code.
- [ ] **Step 2:** Write `TestAnswerFor_ClientErrorEnds`: `ResumeOutcomeClientError` gives `answerEnded`, and `ResumeOutcomeUnknown` gives `answerRefused`.
- [ ] **Step 3:** FAIL where expected, implement, PASS. Commit.

### Task 4.3: Bearer challenge on bearer chains

**Files:** Modify `httpsec/dpop_nonce.go` (`dpopChallenge.Intercept`: apply beyond the provider endpoints when the chain has a built-in bearer), `httpsec/bearer.go` (option `WithoutBearerChallenge() Option`, a chain option). Test `httpsec/bearer_challenge_test.go`.

- [ ] **Step 1:** Write `TestBearerChallenge`, a table through the chain, protecting route `/api` (F25):
  - expired bearer, DPoP off: exactly one `WWW-Authenticate: Bearer error="invalid_token"`;
  - no credential: `Bearer` with no `error=`;
  - DPoP on: a `DPoP` challenge;
  - `WithoutBearerChallenge()`: no header;
  - a cookie-only chain: no header;
  - a consumer handler that sets `Bearer realm="x"`: the header has one `Bearer` entry, the consumer's;
  - the resume endpoint: as before, from the existing tests.
- [ ] **Step 2:** Update the existing test pinned by the settled spec (`guards_test.go`, "DPoP off: no challenge") to the new requirement. That edit is the spec revision, so name it in the report.
- [ ] **Step 3:** FAIL on rows 1–2, implement, PASS. Commit.

### Task 4.4: 429 for throttled client sources

**Files:** Modify `httpsec/oidc_client_auth.go`, `httpsec/oidc_provider_options.go` (option `WithOIDCThrottle429() OIDCProviderOption`). Test `httpsec/oidc_client_throttle_test.go`.

- [ ] **Step 1:** Write `TestClientThrottle429`, a table over the token, revoke, introspect and device-authorization endpoints:
  - default: 401 `invalid_client`;
  - option on: 429, `Retry-After` an integer ≥ 1, body `{"error":"temporarily_unavailable"}`, and the client's credentials are not checked;
  - a limiter reporting retry ≤ 0: `Retry-After: 1` (Review Focus 5).
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 4.5: Code-entry redirects

**Files:** Modify `httpsec/oidc_device.go`, `httpsec/oidc_provider_options.go` (option `WithOIDCEntryRedirects() OIDCProviderOption`). Test `httpsec/oidc_device_test.go`.

- [ ] **Step 1:** Write `TestDeviceEntryRedirects`, a table:
  - default with an unknown code: the existing refusal;
  - option on with unknown, expired or claimed codes: 303 to the entry URL with query exactly `result=invalid`;
  - option on with a throttled source: `result=throttled`, and the provider mock expects no lookup.
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 4.6: Adapter parity

- [ ] Add the cancel endpoint, a bearer-challenge request, a 429 throttle and a device redirect to the parity tables in `httpsec/ginsec` and `httpsec/fibersec`. Run lane D's commands and expect PASS.

---

### Task 5.1: Options for failed parked logins

**Files:** Modify `httpsec/oidc_options.go` (options, `check`). Test `httpsec/oidc_parked_failure_options_test.go`.

**Interfaces:**
- Produces:
  - `const DefaultOIDCLoginErrorParam = "error"`
  - `func WithOIDCLoginErrorParam(name string) OIDCOption`
  - `func WithOIDCFailToClient() OIDCOption`
  - interceptor fields `loginErrorParam string` and `parkedToClient bool`.

- [ ] **Step 1:** Write `TestParkedFailureOptions_Construction`: `""`, `"req"`, `"handoff"` and `"a b"` each give a configuration error (Review Focus 4).
- [ ] **Step 2:** Add rows to `TestParkedFailureOptions_Construction`: `WithOIDCFailToClient` without completion, and `WithOIDCLoginErrorParam` without completion (F23).
- [ ] **Step 3:** FAIL, implement, PASS. Commit.

### Task 5.2: Allow-list mapping

**Files:**
- Create: `httpsec/oidc_parked_failure.go`
- Modify: `httpsec/oidc_login.go` (`callbackFailure` gains `code string`, set by `readCallbackFailure` from the same walk)
- Test: `httpsec/oidc_parked_failure_test.go`

**Interfaces:**
- Produces: `func parkedFailureCode(f callbackFailure) (string, bool)`, plus `func completionFailureCode(err error) (string, bool)`, which walks once through the existing `walkRefusal`.

- [ ] **Step 1:** Write `TestParkedFailureCode`, a table over the D4 rows (listed) and the unlisted rows. `assert` the code, or `ok == false` (F8, F9).
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 5.3: Guards before return

**Files:** Modify `httpsec/oidc_parked_failure.go`. Test the same file.

**Interfaces:**
- Produces: `func (i *oidcInterceptor) returnParked(ex *Exchange, provider, handle, code string, original error) error`. It runs `transport → admit → PendingRequest → stage` (or the expired-within-grace path), then writes the 303. On any guard failure it returns `original`.

- [ ] **Step 1:** Write `TestReturnParked_Guards`, a table:
  - another browser's handle: `original` returned, no `Location`, one charge;
  - consent stage: `original`;
  - plain HTTP: `original`;
  - throttled: `original`, no lookup;
  - completion's pre-check already charged: total charges == 1 (F1, F8).
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 5.4: Callback failures return to the login page

**Files:** Modify `httpsec/oidc_login.go` (`callback`). Test `httpsec/oidc_parked_failure_callback_test.go`.

- [ ] **Step 1:** Write `TestCallback_ParkedFailureReturnsToLogin`, a table over hook refusal, one-link, invalid ID token, not linked, exchange outage, userinfo outage, and a userinfo outage inside the library broker's sign-in hook (Task 2.4), which gives `temporarily_unavailable`. `assert`:
  - 303;
  - `Location` equals `<LoginURL>?req=h-1&error=<code>` (query exactly two keys);
  - `Cache-Control: no-store`, `Referrer-Policy: no-referrer`;
  - the flow cookie is cleared;
  - `PendingRequest(h-1)` is still at `StageLogin`.
- [ ] **Step 2:** Write `TestCallback_UnparkedDestinationKeepsAnswer` (Review Focus 2), with rows for a moved login URL, an ordinary destination, a look-alike path, an extra parameter and completion off.
- [ ] **Step 3:** FAIL, implement, PASS. Commit.

### Task 5.5: Upstream `error=` returns

**Files:** Modify `httpsec/oidc_login.go` (`providerError`, which now uses `AbortFlowNext`). Test `httpsec/oidc_parked_failure_callback_test.go`.

- [ ] **Step 1:** Write `TestProviderError_ParkedReturnsToLogin`:
  - real state: 303 with `access_denied` and the cookie cleared;
  - forged state: invalid state, no cookie header (F21).
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 5.6: Discovery failure at the start

**Files:** Modify `httpsec/oidc_login.go` (`authorize`). Test `httpsec/oidc_parked_failure_start_test.go`.

- [ ] **Step 1:** Write `TestAuthorize_DiscoveryFailureReturnsToLogin`:
  - `next=<LoginURL>?req=h-1`: 303 `temporarily_unavailable`, no `Set-Cookie`, and the flow store mock expects no `Begin`;
  - `next=/welcome`: the existing error.
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 5.7: Completion refusals return

**Files:** Modify `httpsec/oidc_completion.go`. Test `httpsec/oidc_completion_test.go`.

- [ ] **Step 1:** Write `TestCompletion_RefusalsReturnToLogin`, a table:
  - unknown, inactive and mismatched user: `access_denied`, no session;
  - policy deny: `access_denied`;
  - per-request refusal: `access_denied`, and the session family revoked (mock expects `RevokeFamily`);
  - user loader fails: `server_error`;
  - session store fails: `server_error`;
  - owed step: handoff as today.
- [ ] **Step 2:** Update the settled scenarios "Policy denies" and "Per-request policy refuses" in the existing tests to the modified requirements.
- [ ] **Step 3:** FAIL, implement, PASS. Commit.

### Task 5.8: Expired within grace goes to the client

- [ ] **Step 1:** Write `TestParkedFailure_ExpiredWithinGraceAnswersClient` across the callback, start and completion paths: a 303 to the client with `access_denied`, `state` and `iss`, and the handle spent.
- [ ] **Step 2:** FAIL, implement (in `returnParked`, call `EndPending` with `CodeAccessDenied` when the view reports expired within grace), PASS. Commit.

### Task 5.9: Straight-to-client override

- [ ] **Step 1:** Write `TestParkedFailureToClient`:
  - a hook refusal gives a 303 to the client with `access_denied`, `state=s-1` and `iss`, and the handle is spent;
  - `EndPending` failing (store mock) gives the original error and exactly one ERROR record of the error's type (F7).
- [ ] **Step 2:** FAIL, implement, PASS. Commit.

### Task 5.10: Events and logs

- [ ] **Step 1:** Write `TestParkedFailure_EventsAndLogs`. The event sink counts `AuthnLoginFail`: 1 for a refusal and 0 for an outage. The captured slog output has one record per redirect with attribute `code`, and none of the handle, state, flow cookie value or `Location` appears in any record (byte search) (F20).
- [ ] **Step 2:** FAIL if needed, implement, PASS. Commit.

### Task 5.11: Non-parked logins unchanged

- [ ] Run `go test -count=1 -run 'TestCallback|TestCompletion|TestRedeem|TestParked' ./httpsec/`. Every pre-existing test passes with no edits beyond the two named in 4.3 and 5.7.

### Task 5.12: Adapter parity and lane E verification

- [ ] Add rows for 5.4–5.9 to the `ginsec` and `fibersec` parity tables. Run lane E's commands and report.

---

### Task 6.1: README note on scheduled jobs (later work)

**Files:** Modify `README.md`.

- [ ] Add the short section "Scheduled jobs (later work)" with the list from design D13: each task name, its source, and the signing-key `Start` note. It says that durable stores are swept only when these run, and that a wiring guide is later work. There is no example code and no new test. Check with `rg -n 'oidc-provider.pending-requests|login-attempts|oidc-handoffs|passkey-login-challenges' README.md`, which must match the note.

### Task 6.2: README behaviour sections

- [ ] Update "Federated sign-in without a page script" and "OpenID Provider". Then `rg -n 'refusal sends no redirect' README.md` must print nothing.

### Task 6.3: Godoc

- [ ] Every new exported symbol from Tasks 1–5 must name its default and override. Check it with `go doc` on each.

### Task 6.4: CHANGELOG

- [ ] Add the "Unreleased" entries: the behaviour changes (parked SSO failures redirect, resume refusals redirect, the expired grace answer, the bearer challenge), each with its opt-out, and the additions. Each **BREAKING** item in `proposal.md` must have a matching entry.

---

### Task 7.1: Whole-branch review

- [ ] Dispatch a fresh Opus reviewer with the six spec deltas, `design.md` (D1–D13, F1–F27) and the branch diff. It enumerates failure modes before judging, and labels claims `REPRODUCED`/`UNREPRODUCED`. Done when no finding is open.

### Task 7.2: Final gate

- [ ] The main session runs `make check && make spec-check` after the last code edit and reads the output. Expect both to succeed.
