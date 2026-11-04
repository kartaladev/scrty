# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done. Run the module's full suite with `-race` at the end of each group. Revised on 2026-11-03 after the design was checked against `main` at `4649c90`, its scenarios were swept, and its decisions were reviewed against security standards.

## 1. Baseline and adapter streaming (D1)

- [x] 1.1 Rebase onto `main` after `close-security-gaps` has merged, and recheck what the design relies on: `CookieAuthenticator`, `EndSignIn` and `EndOtherSignIns`, the re-authentication window, the internal-set pattern (D8 there) and the security-event emission points. Record any difference in `design.md`. Verify: `openspec validate session-signals --strict` passes, and the design names the merged commit. *(Done 2026-11-03: the design's Context and D3, D5 record the differences, at `4649c90`.)*
- [ ] 1.2 Establish fiber first, on the fiber and fasthttp versions `httpsec/fibersec` pins when this task runs: in a test with a fasthttp server whose `WriteTimeout` is 3 seconds, a `SendStreamWriter` body that sets the connection's write deadline forward on each flush must stay open for 30 seconds. If it cannot, stop and amend the `framework-adapters` delta and D1 before any other task. Verify: `go test -run 'TestFiber_StreamOutlivesWriteTimeout' -count=1 ./...` in `httpsec/fibersec`.
- [ ] 1.3 Add `ResponseWriter.Stream`, `EventWriter`, `ErrStreamingUnsupported` and `ErrStreamingStarted`, and implement them for net/http with `http.ResponseController`, test-first: the body runs inline; the write deadline is extended by `StreamWriteWindow` when the stream starts and on each write and flush; an idle gap longer than the server's write timeout does not end a stream, over HTTP/1.1 and over HTTP/2 (which is also the red test for D1's UNREPRODUCED reason for the window's length); the body's context ends when the client leaves; the headers set before `Stream` are sent; `Stream` after `Write`, or called twice, returns `ErrStreamingStarted` and writes nothing. Verify: `go test -run 'TestHTTPResponseWriter_Stream' -count=1 ./httpsec/`.
- [ ] 1.4 Implement `Stream` in `ginsec` over gin's writer, with the same five behaviours, test-first. Verify: `go test -run 'TestGin_Stream' -count=1 ./...` in `httpsec/ginsec`.
- [ ] 1.5 Implement `Stream` in `fibersec` through `SendStreamWriter`, test-first: a context detached from the chain's end-of-request cancellation, ended by a failed flush or by shutdown; the per-flush deadline from 1.2; the headers the chain set are sent; and `ErrStreamingStarted` as in 1.3. Verify: `go test -run 'TestFiber_Stream' -count=1 ./...` in `httpsec/fibersec`.
- [ ] 1.6 Add the adapter scenarios to conformance on all three adapters: a flushed event arrives while the response is open; headers set before streaming are sent; a stream after the response began fails; a stream outlives a 3-second write timeout; an ordinary response keeps the deadline; a client that leaves stops the stream within a heartbeat. Add a fiber case where server shutdown ends an open stream. Godoc `Stream` and `EventWriter`, including what a consumer adapter that cannot stream returns. Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/stream' ./...` in the `test` module.

## 2. Ended sign-ins reported by the session manager (D5)

- [x] 2.1 Add `session.EndObserver` with `EndObserverFunc`, the repeatable `session.WithEndObserver`, `EndReport{Cause, User, Family, KeptFamily, ExternalIssuer, ExternalSessionID, At}` and `EndCause`, test-first, extending what `oidc-provider` added if it landed first. A nil observer fails construction. Use one table row per call in D5's table:
  - `Delete` → `EndDeleted`, with user and family loaded first only when an observer is set;
  - `EndSignIn` → `EndByHandle`;
  - reuse detection → `EndReuse`, and `RevokeFamily` → `EndFamilyRevoked`;
  - `DeleteByUser` → `EndUserSessions`;
  - `DeleteByUserExcept` → `EndUserSessionsExcept`, with the kept *session's* family as `KeptFamily`;
  - `EndOtherSignIns` → `EndOtherSignIns`, with the current family as `KeptFamily`;
  - `DeleteByUserAndExternalIssuer` → `EndUserExternalIssuer`;
  - `DeleteByExternalSession` → `EndExternalSession`, with the issuer and upstream session and no user or family.

  Every row asserts that no session identifier appears. Also include: no observer; a failed write, where nothing is reported; a panicking observer, where the outcome is unchanged; and a caller whose context is cancelled, where the observer is still called. Verify: `go test -run 'TestSessions_EndObserver' -count=1 -race ./session/`.
- [x] 2.2 Add `(*Sessions).AddEndObserver`, test-first: a nil observer gives `ErrConfig`, an added observer runs after those given at construction, the first of two observers panicking still calls the second, and adding while reports run is clean under `-race`. Also show that sweeping and passing a deadline report nothing. Godoc all of it, naming the default (no observer). Verify: `go test -run 'TestSessions_AddEndObserver|TestSessions_EndObserver_NotOnExpiry' -count=1 -race ./session/`.

## 3. Configuration and construction (D2)

- [ ] 3.1 Add the `Signal` constants, the `SessionSignals` configuration with its defaults (including `AssuranceWindow`, defaulting to `DefaultRecentAuthenticationWindow`), `EnableSessionSignals` and `OrderSessionSignals`, test-first. One construction table covers:
  - defaults filled;
  - an unknown signal name;
  - a heartbeat of 4 s and of 61 s;
  - a warning window of zero, and one not shorter than the idle timeout;
  - an assurance window of zero;
  - each cap at 0, `MaxPerSignIn` above `MaxPerUser`, and `MaxPerUser` above `MaxStreams`;
  - `assurance_lapsed` without re-authentication;
  - a path another endpoint serves;
  - enabled twice;
  - a session manager that already has an end observer, which builds, and whose observer is still told.

  Verify: `go test -run 'TestSessionSignals_Construction' -count=1 ./httpsec/`.
- [ ] 3.2 Godoc every field with its default and its range: `AssuranceWindow` names the guards' window it should match, and `OrderSessionSignals` its place after the gates and below `OrderSessionTouch`. Verify: `go doc ./httpsec SessionSignals` names each default, and `go vet ./httpsec/` is clean.

## 4. The endpoint (D3, D7, D10)

- [ ] 4.1 Answer the endpoint, test-first: not enabled → passes through; `GET` → 200, `text/event-stream`, `no-store`, `X-Accel-Buffering: no`; another method → 405 with `Allow: GET`; a consumer path; a consumer adapter that cannot stream → 501. Verify: `go test -run 'TestSessionSignals_Endpoint' -count=1 ./httpsec/`.
- [ ] 4.2 Admit only a signed-in request, test-first:
  - no credential → 401;
  - a session reference only in the query → 401;
  - HTTP Basic, an API key, or a token with no session → 403;
  - a sign-in owing a second factor, an enrolment, a recovery or a password change → refused by its gate;
  - a consumer `CookieAuthenticator` session → opens.

  Verify: `go test -run 'TestSessionSignals_Admission' -count=1 ./httpsec/`.
- [ ] 4.3 Record no session activity for the stream, test-first: opening a stream and holding it past the manager's touch interval leaves the last-activity time and idle deadline unchanged, because the endpoint sits below `OrderSessionTouch`; and `RecordsSessionActivity(ex)` reports false for the stream to a consumer interceptor. Verify: `go test -run 'TestSessionSignals_NoActivity' -count=1 ./httpsec/`.
- [ ] 4.4 Write the wire format, test-first:
  - `retry: 5000` first, then the `session` snapshot with the two deadlines and `authenticated_at` in RFC 3339 UTC, and no identifier;
  - events as `event:` and `data:` with no `id:`, and heartbeats as comments;
  - the writer refuses an event whose name or data holds a raw CR or LF.

  Verify: `go test -run 'TestSessionSignals_WireFormat' -count=1 ./httpsec/`.
- [ ] 4.5 Narrow by the `signals` query parameter, test-first: narrowed; a widening name ignored; a malformed name dropped; 17 names, or more than 256 bytes → 400; no parameter → the chain's set. Verify: `go test -run 'TestSessionSignals_Narrowing' -count=1 ./httpsec/`.
- [ ] 4.6 Show the early slots and the cross-site rule, test-first. The first case is the red test for D3's UNREPRODUCED claim: a `Sec-Fetch-Site: cross-site` request from an origin CORS does not allow must be refused with 403 *and leave the sign-in's stream count unchanged*. Then:
  - the same with CSRF protection off;
  - `Origin: null` refused;
  - no `Sec-Fetch-Site` and no `Origin` (a bearer client) → opens;
  - an allowed origin → opens with its CORS headers;
  - a CORS preflight for `Authorization` is answered with no stream;
  - a same-origin cookie stream opens without a CSRF token;
  - a rate-limited source gets no stream.

  Add the README section "Session signals": enabling it, the `EventSource` and `fetch()` clients (rebuilding the `EventSource` with backoff after an error), the defaults table, and proxy buffering. Verify: `go test -run 'TestSessionSignals_EarlySlots|TestSessionSignals_CrossSite' -count=1 ./httpsec/`.

## 5. Stream lifecycle against the store (D4)

- [ ] 5.1 Reload the sign-in at each heartbeat with ±10% jitter, test-first, one row per line of D4's reload table:
  - gone after `logout`, `ended`, `reuse`, `all_ended` or `provider_logout` → `session_ended` with that reason, then close;
  - the user no longer active → `ended`;
  - gone with no report, or past a deadline → `expired`;
  - still valid → a comment only;
  - **a store failure → a comment, no `session_ended`, the stream stays open, and a later successful reload that finds the sign-in ended closes it.**

  Also: a reconnect after `session_ended` with the same credential → 401; a consumer heartbeat interval is used. Verify: `go test -run 'TestSessionSignals_Heartbeat' -count=1 -race ./httpsec/`.
- [ ] 5.2 Send a new `session` event when a reload finds a deadline or `authenticatedAt` moved, test-first, including a re-authentication on the same sign-in. Verify: `go test -run 'TestSessionSignals_DeadlineMoved' -count=1 ./httpsec/`.
- [ ] 5.3 Arm one timer per stream for `session_expiring` (once per window, naming the earlier deadline), for expiry (`session_ended` with `expired`) and for the assurance lapse, test-first on the fake clock. Cover: a consumer warning window; activity after a warning moves the deadline, so the stream does not end at the old one; and a store outage that lasts until the absolute deadline still ends the stream. Verify: `go test -run 'TestSessionSignals_Expiring' -count=1 -race ./httpsec/`.
- [ ] 5.4 Send `assurance_lapsed` once when `AssuranceWindow` passes, test-first: the default 15 minutes; a consumer's 5 minutes; and, after a re-authentication, a `session` event and later one more `assurance_lapsed`. Verify: `go test -run 'TestSessionSignals_AssuranceLapsed' -count=1 ./httpsec/`.
- [ ] 5.5 End to end: a stream left open with no other request reaches the idle deadline and ends with `expired`. Send `session_ended` even when narrowed away. Update the README with the lifecycle and the store-load arithmetic. Verify: `go test -run 'TestSessionSignals_IdleTab|TestSessionSignals_EndedAlwaysSent' -count=1 ./httpsec/`.

## 6. Bus, registry and caps (D6, D8, D9)

- [ ] 6.1 Add `SignalBus`, `SignalEnvelope`, the in-process default, and the per-replica registry fed by one subscription, test-first: an envelope reaches only its user's streams, and `session_ended` only its family's, or every stream of the user when it names no family. Verify: `go test -run 'TestSessionSignals_Bus' -count=1 -race ./httpsec/`.
- [ ] 6.2 Treat bus envelopes as untrusted, test-first:
  - a bus `session_ended` forwards only when the reload agrees, so a message whose session still exists (a rolled-back outer transaction, or a forged message) is not forwarded, and the heartbeat ends the stream later;
  - several wake-ups coalesce into one reload;
  - a library signal with an unknown name, malformed data, or more than 8 KiB is dropped, and an `app.` envelope outside `PublishSignal`'s limits is dropped.

  Verify: `go test -run 'TestSessionSignals_BusWakeUp|TestSessionSignals_BusUntrusted' -count=1 -race ./httpsec/`.
- [ ] 6.3 Handle bus failures, test-first: a failing `Publish` leaves the raising request's outcome unchanged and is logged with sampling; a failing `Subscribe` is retried with backoff from 1 s up to 30 s; the heartbeat still ends streams; with the default bus, a signal raised on another replica is not delivered. Verify: `go test -run 'TestSessionSignals_BusOutage' -count=1 -race ./httpsec/`.
- [ ] 6.4 Enforce the caps per replica, test-first: a fifth stream per sign-in, a seventeenth per user and one over the total → 429 `ErrTooManyStreams`, nothing charged, no existing stream closed; two requests racing for the last place → exactly one opens (a barrier test); a client that leaves frees its place; consumer caps are used. Verify: `go test -run 'TestSessionSignals_Caps' -count=1 -race ./httpsec/`.
- [ ] 6.5 Bound each stream's queue at 32, test-first: a slow stream drops its own events, never another stream's, and never blocks the publisher; a slow stream whose sign-in is then ended still sends `session_ended`. Godoc the bus (including that a shared bus should authenticate its transport), the replica limit and the caps. Verify: `go test -run 'TestSessionSignals_SlowStream' -count=1 -race ./httpsec/`.
- [ ] 6.6 End every open stream on `chain.CloseSessionSignals(ctx)`, test-first:
  - each stream closes without an event and frees its place;
  - a stream requested afterwards gets 200 with only the `retry` line, its connection is closed, and it is not registered;
  - closing twice does nothing;
  - an `http.Server.Shutdown` with the call registered through `RegisterOnShutdown` returns before its deadline while a stream is open.

  Document the registration in the README. Verify: `go test -run 'TestSessionSignals_Close' -count=1 -race ./httpsec/`.

## 7. Where signals come from (D5)

- [ ] 7.1 Raise `credential_changed` from the chain's endpoints after their write succeeds, test-first, one row per endpoint: password-change resolve (`password`), recovery finish (`password` or `second_factor`), passkey registration and removal (`passkey`), and MFA enrolment confirmation and removal (`second_factor`). Check the kind, and that no credential detail appears. Verify: `go test -run 'TestSessionSignals_CredentialChanged' -count=1 ./httpsec/`.
- [ ] 7.2 Add `ReportCredentialChange` for changes made outside the chain, test-first: a consumer's password change reaches every stream of the user; signals disabled; an unknown kind. Verify: `go test -run 'TestSessionSignals_ReportCredentialChange' -count=1 ./httpsec/`.
- [ ] 7.3 Add `PublishSignal`, test-first:
  - `app.` names reach every stream of the user unchanged;
  - refused: a name outside `^app\.[a-z0-9][a-z0-9._-]{0,62}$` (including one holding a newline), data over 8 KiB, and data that is not JSON;
  - signals disabled → `ErrSessionSignalsDisabled`;
  - a user with no open stream → no error;
  - a client's narrowing applies.

  Verify: `go test -run 'TestSessionSignals_Publish' -count=1 ./httpsec/`.
- [ ] 7.4 Show that the stream never carries the audit feed, test-first, with one row each for: a failed login, a lockout, a rate-limit, CSRF, host and DPoP refusal, and another user's sign-in, lockout and password change. The stream sends nothing for any of them. Update the README with the signal list and the consumer's API. Verify: `go test -run 'TestSessionSignals_NoAuditFeed' -count=1 ./httpsec/`.

## 8. Integration

- [ ] 8.1 Run the stream scenarios end to end on all three adapters in conformance: snapshot, ended from another sign-in, narrowing, caps, a cross-site refusal, and a consumer signal. Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/signals' ./...` in the `test` module.
- [ ] 8.2 Run every module's full suite with the race detector, one module at a time, then `govulncheck`, `gofmt -l` and `go vet` on every module. Verify: every command's output is clean.
- [ ] 8.3 Review the whole branch against every requirement in this change's spec deltas, every design decision and the security review table, with each finding reproduced or labelled UNREPRODUCED. Verify: the review is recorded and its findings are resolved.

## Workflow follow-up

- Add the stream and the `ResponseWriter.Stream` break to `release-readiness`'s first changelog entry.
- Archive the change once its review requirements are satisfied, before `release-readiness` tags `v0.1.0`.
- Follow-up changes: Redis and PostgreSQL `SignalBus` implementations, each authenticating its transport.
