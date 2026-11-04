# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done, run with `-v`, because `go test -run` exits 0 when nothing matches: the test names the task gives must appear in the output, and a conformance pattern must show subtests that ran. A timing-sensitive test also passes 16 concurrent copies of its compiled binary, for several rounds, before it counts. Run the module's full suite with `-race` at the end of each group. Revised on 2026-11-03 after the design was checked against `main` at `4649c90`, its scenarios were swept, and its decisions were reviewed against security standards.

## 1. Baseline and adapter streaming (D1)

- [x] 1.1 Rebase onto `main` after `close-security-gaps` has merged, and recheck what the design relies on: `CookieAuthenticator`, `EndSignIn` and `EndOtherSignIns`, the re-authentication window, the internal-set pattern (D8 there) and the security-event emission points. Record any difference in `design.md`. Verify: `openspec validate session-signals --strict` passes, and the design names the merged commit. *(Done 2026-11-03: the design's Context and D3, D5 record the differences, at `4649c90`.)*
- [x] 1.2 Establish fiber first, on the fiber and fasthttp versions `httpsec/fibersec` pins when this task runs: in a test with a fasthttp server whose `WriteTimeout` is 3 seconds, a `SendStreamWriter` body that sets the connection's write deadline forward on each flush must stay open for 30 seconds. If it cannot, stop and amend the `framework-adapters` delta and D1 before any other task. Verify: `go test -run 'TestFiber_StreamOutlivesWriteTimeout' -count=1 ./...` in `httpsec/fibersec`.
- [x] 1.3 Add `ResponseWriter.Stream`, `EventWriter`, `ErrStreamingUnsupported` and `ErrStreamingStarted`, and implement them for net/http with `http.ResponseController`, test-first: the body runs inline; the write deadline is extended by `StreamWriteWindow` when the stream starts and on each write and flush; an idle gap longer than the server's write timeout does not end a stream, over HTTP/1.1 and over HTTP/2 (which is also the red test for D1's UNREPRODUCED reason for the window's length); the body's context ends when the client leaves; the headers set before `Stream` are sent; `Stream` after `Write`, or called twice, returns `ErrStreamingStarted` and writes nothing. Verify: `go test -run 'TestHTTPResponseWriter_Stream' -count=1 ./httpsec/`.
- [x] 1.4 Implement `Stream` in `ginsec` over gin's writer, with the same five behaviours, test-first. Verify: `go test -run 'TestGin_Stream' -count=1 ./...` in `httpsec/ginsec`.
- [x] 1.5 Implement `Stream` in `fibersec` through `SendStreamWriter`, test-first: a context detached from the chain's end-of-request cancellation, ended by a failed flush, by shutdown, or by a reader that sees the client leave, with `Connection: close` on the stream; the deadline from 1.2, moved on each write and flush, shown by a stream that outlives several short windows; the headers the chain set are sent; `ErrStreamingStarted` as in 1.3; a panicking body logs nothing of its panic value; a body that holds no exchange; and, on every adapter, if `Stream` returns nil its body runs exactly once, which on fiber is on an already-ended context if the chain refused, and including a `Stream` after the chain has returned and a body calling `runtime.Goexit`. A body's panic under a recovery middleware leaves a response that does not look complete. A writer that cannot flush, with no `Unwrap` or under `http.TimeoutHandler`, or reporting it only at run time, gets `ErrStreamingUnsupported` with nothing written, and a wrapper whose `Unwrap` returns itself does not hang. Verify: `go test -run 'TestFiber_Stream' -count=1 ./...` in `httpsec/fibersec`.
- [x] 1.6 Add the adapter scenarios to conformance on all three adapters: a flushed event arrives while the response is open; headers set before streaming are sent; a stream after the response began fails; a stream outlives a 3-second write timeout; an ordinary response keeps the deadline; a client that leaves stops the stream within a heartbeat. Add a fiber case where server shutdown ends an open stream. Godoc `Stream` and `EventWriter`, including what a consumer adapter that cannot stream returns, that a body must not read the exchange, what a nil `Flush` promises, and how long a client that stops reading can hold a stream, naming `HTTP2.WriteByteTimeout`. Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/stream' ./...` in the `test` module.

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
- [x] 2.3 Add `(*Sessions).Logout(ctx, user, family) (int, error)` and the cause `EndLogout`, appended after the existing causes, test-first: it ends the whole family, a renewal's successor included; it reports user and family; the chain's logout uses it, with its edit to `httpsec/logout.go` kept to the one call; and through the chain, a logout reports `EndLogout` naming the user, where it reported `EndFamilyRevoked` naming no one. Godoc that `RevokeFamily` keeps its own cause. Verify: `go test -run 'TestSessions_EndObserver|TestSessions_Logout|TestLogout_ReportsLogoutCause' -count=1 -race ./session/ ./httpsec/`.
- [x] 2.4 Add `(*Sessions).SignInState(ctx, user, family) (SignInState, error)` over `Store.ListByUser`, test-first, one row per `sessions` delta scenario: after a renewal past its grace window; after a strict rotation; never presented; ended; past a deadline; another user's family; a store failure, which is not `ErrNotFound`; and a sealed store whose key was retired. Each row also asserts that nothing was revoked or marked, and no reuse reported. Run the rows against the memory store, and against the durable backends through the store conformance suite. Verify: `go test -run 'TestSessions_SignInState' -count=1 -race ./session/`, and the conformance suite's new rows in the `test` module.

## 3. Configuration and construction (D2)

- [x] 3.1 Add the `Signal` constants, the `SessionSignals` configuration with its defaults (including `AssuranceWindow`, defaulting to `DefaultRecentAuthenticationWindow`), `EnableSessionSignals` and `OrderSessionSignals`, test-first. One construction table covers:
  - defaults filled;
  - an unknown signal name;
  - a heartbeat of 4 s and of 61 s;
  - a field at zero takes its default;
  - a negative warning window, and one not shorter than the idle timeout;
  - a negative assurance window;
  - each cap negative, `MaxPerSignIn` above `MaxPerUser`, and `MaxPerUser` above `MaxStreams`;
  - `assurance_lapsed` without re-authentication;
  - a path another endpoint serves;
  - enabled twice;
  - a session manager that already has an end observer, which builds, and whose observer is still told;
  - no session manager; no user loader and no built-in bearer's; a consumer's `Users`;
  - a path that lacks its leading slash, ends in a slash, or holds `?`, `#`, `%` or whitespace;
  - a warning window or assurance window set without its signal; a `ReconnectDelay` or `BusyDelay` under 1 ms;
  - a warning window above the idle timeout less the touch interval;
  - a `MaxAge` below twice the heartbeat, `NoMaxAge`, and `MaxPerSource` above `MaxStreams`;
  - a `ReloadTimeout` not shorter than the heartbeat, and its default at heartbeats of 5, 15 and 60 s (2.5, 7.5 and 10 s); a `BusQueue` or `BusTimeout` below 1;
  - a chain clock that cannot wait;
  - a failed build leaves no observer on the manager, because the hub wires in last.

  Verify: `go test -run 'TestSessionSignals_Construction' -count=1 ./httpsec/`.
- [x] 3.2 Godoc every field with its default and its range: `AssuranceWindow` names the guards' window it should match, and `OrderSessionSignals` its place after the gates and below `OrderSessionTouch`. Verify: `go doc ./httpsec SessionSignals` names each default, and `go vet ./httpsec/` is clean.

## 4. The endpoint (D3, D7, D10)

- [x] 4.1 Answer the endpoint, test-first: not enabled → passes through; `GET` → 200, `text/event-stream`, `no-store, no-transform`, `X-Accel-Buffering: no`; another method → 405 with `Allow: GET`; a consumer path; a consumer adapter that cannot stream → 501, including a wrapper with no `Unwrap` and `http.TimeoutHandler`, and delete `ErrStreamingUnsupported`'s `unmapped` entry in `httpsec/errors_test.go`; a consumer's interceptor that already wrote → the chain's error mapping. The endpoint copies everything its body needs from the exchange before `Stream`. Verify: `go test -run 'TestSessionSignals_Endpoint' -count=1 ./httpsec/`.
- [x] 4.2 Admit only a signed-in request, test-first:
  - no credential → 401;
  - a session reference only in the query → 401;
  - HTTP Basic, an API key, or a token with no session → 403;
  - a sign-in owing a second factor, an enrolment, a recovery or a password change → refused by its gate;
  - a consumer `CookieAuthenticator` session → opens.

  Verify: `go test -run 'TestSessionSignals_Admission' -count=1 ./httpsec/`.
- [x] 4.3 Record no session activity for the stream, test-first: opening a stream and holding it past the manager's touch interval leaves the last-activity time and idle deadline unchanged, because the endpoint sits below `OrderSessionTouch`; and `RecordsSessionActivity(ex)` reports false for the stream to a consumer interceptor. Holding a stream also records no presentation and revokes nothing. Verify: `go test -run 'TestSessionSignals_NoActivity' -count=1 ./httpsec/`.
- [ ] 4.4 Write the wire format, test-first:
  - `retry: <ms>` first, within `ReconnectDelay` ±30% and differing across streams, then the `session` snapshot with the two deadlines and `authenticated_at` in RFC 3339 UTC, null when none is recorded, and no identifier;
  - events as `event:` and `data:` with no `id:`, and heartbeats as comments;
  - the writer refuses an event whose name or data holds a raw CR or LF.

  Verify: `go test -run 'TestSessionSignals_WireFormat' -count=1 ./httpsec/`.
- [ ] 4.5 Narrow by the `signals` query parameter, test-first, reading every occurrence through `QueryValues`: narrowed; a widening name ignored; a malformed name dropped; 17 names, or more than 256 bytes, across repeated parameters too → 400; an empty parameter → only what is always sent; no parameter → the chain's set. Verify: `go test -run 'TestSessionSignals_Narrowing' -count=1 ./httpsec/`.
- [ ] 4.6 Show the early slots and the cross-site rule, test-first. The first case is the red test for D3's UNREPRODUCED claim: a `Sec-Fetch-Site: cross-site` request from an origin CORS does not allow must be refused with 403. That it leaves the sign-in's stream count unchanged is asserted with task 6.4, once the registry exists. Then:
  - the same with CSRF protection off;
  - `Origin: null` refused;
  - no `Sec-Fetch-Site` and no `Origin` (a bearer client) → opens;
  - an allowed origin → opens with its CORS headers, including `Vary: Origin`;
  - a cookie stream from an origin named without credentials → 403; a bearer stream from it → opens;
  - a consumer's cookie authenticator that calls `RecordPresentedToken` is still judged as a cookie, while a cookie with an unclaimed `Authorization` header stays a cookie;
  - `*` with a cookie cross-site → 403; `*` with a bearer token → opens; `Origin: null` with a bearer token under `*` → 403; and no CORS at all with a cross-origin `Origin` → 403;
  - `same-site` from an untrusted origin → 403; the refusal is `ErrCrossSiteStream`, emits no `MaliciousCSRF` event, and is logged with sampling;
  - a `POST` under CSRF protection reaches 405 once CSRF passes;
  - a CORS preflight for `Authorization` is answered with no stream;
  - a same-origin cookie stream opens without a CSRF token;
  - a source refused by a consumer's rate-limiting interceptor below the slot gets no stream.

  Add the README section "Session signals": enabling it; the `EventSource` client, which probes an ordinary endpoint before rebuilding, so a 401 stays final, and rebuilds on `visibilitychange`, `pageshow` and `online`; the `fetch()` client, which reads the current credential on every attempt; the defaults table; and the operator's section listing each intermediary and server setting in the design's failure sweep, the concurrent-stream limits and what happens at them (ASVS 7.1.2), how a provider's logout reaches streams (7.1.3), where logs go (16.2.3), and that the chain's authorizer is not re-run until a reconnection. Verify: `go test -run 'TestSessionSignals_EarlySlots|TestSessionSignals_CrossSite' -count=1 ./httpsec/`.

## 5. Stream lifecycle against the store (D4)

- [ ] 5.1 Reload the sign-in at each heartbeat with ±10% jitter, through `SignInState` and `Users`, test-first, one row per line of D4's reload table. The first read at admission also reads the user, so a tenant-scoped user store with no hook and a disabled user on a cookie authenticator both fail there:
  - gone after `logout`, `ended`, `reuse`, `all_ended` or `provider_logout` → `session_ended` with that reason, then close;
  - the user not found or no longer active → `ended`;
  - gone with no report → `ended`; gone, a held deadline passed → `expired`;
  - still valid → a comment only, and every row asserts that nothing was presented or revoked;
  - **a session or user-store failure → a comment, no `session_ended`, the stream stays open, and a later successful reload that finds the sign-in ended closes it;**
  - a store that hangs → the read times out, the session and user reads sharing the budget, a comment is still sent, and it counts as a failure; a consumer's `ReloadTimeout` is used;
  - a renewal past its grace window, a strict rotation and a step-up → the stream stays open, the sign-in stays live, and no reuse is reported;
  - a transaction on the opening request, committed since → reloads read current state; a tenant carried by `ReloadContext`; a tenant-scoped store with no hook → no stream opens, and the failure is logged and answered as a dependency failure;
  - **a panic in the stream's own code or a consumer's loader, on all three adapters** → the chain's logger gets the type, phase, family and frames, no log anywhere holds the value, the place is freed, and the process runs on;
  - a stream's open and close log at DEBUG with user, family, client address, origin and reason, and no token or identifier, and the stream itself sends no client address;
  - back-channel logout through `DeleteByExternalSession` → `provider_logout`.

  Also: a reconnect after `session_ended` with the same credential → 401; a consumer heartbeat interval is used. Verify: `go test -run 'TestSessionSignals_Heartbeat' -count=1 -race ./httpsec/`.
- [ ] 5.2 Send a new `session` event when a reload finds a deadline or `authenticatedAt` moved, test-first, including a re-authentication on the same sign-in. Verify: `go test -run 'TestSessionSignals_DeadlineMoved' -count=1 ./httpsec/`.
- [ ] 5.3 Arm one timer per stream for `session_expiring` (once per window, naming the earlier deadline), for expiry (`session_ended` with `expired`) and for the assurance lapse, test-first on the fake clock. Each timer reloads before it speaks. Cover: a consumer warning window; activity after a warning moves the deadline, so the stream does not end at the old one; activity one second before the deadline; a clock ahead of the store, which stays open and does not spin; a clock step, corrected at the next reload; the idle deadline passing during a store outage, which stays open; a store outage that lasts until the absolute deadline still ends the stream; equal deadlines name `absolute`; a deadline already inside the window at open; and each timer firing once. Verify: `go test -run 'TestSessionSignals_Expiring' -count=1 -race ./httpsec/`.
- [ ] 5.4 Send `assurance_lapsed` once when `AssuranceWindow` passes, test-first: the default 15 minutes; a consumer's 5 minutes; after a re-authentication, a `session` event and later one more `assurance_lapsed`; a zero `AuthenticatedAt`, which never lapses; and a window already passed at open. Verify: `go test -run 'TestSessionSignals_AssuranceLapsed' -count=1 ./httpsec/`.
- [ ] 5.5 End to end: a stream left open with no other request reaches the idle deadline and ends with `expired`. Send `session_ended` even when narrowed away. Update the README with the lifecycle and the store-load arithmetic, counting two reads per heartbeat. Verify: `go test -run 'TestSessionSignals_IdleTab|TestSessionSignals_EndedAlwaysSent' -count=1 ./httpsec/`.
- [ ] 5.6 Close a stream at `MaxAge`, test-first: the default, with its jitter; a consumer's value; `NoMaxAge`; it closes without an event, and frees its place; and a reconnection with a bearer token that has since expired → 401. Godoc what `NoMaxAge` gives up, and that a stream follows its family across renewals. Verify: `go test -run 'TestSessionSignals_MaxAge' -count=1 -race ./httpsec/`.

## 6. Bus, registry and caps (D6, D8, D9)

- [ ] 6.1 Add `SignalBus`, `SignalEnvelope`, the in-process default, and the per-replica registry fed by one subscription, test-first: an envelope reaches only its user's streams, and `session_ended` only its family's, or every stream of the user when it names no family, sparing `Kept`, and waking all of them when `Kept` is nil; a family-only report reaches its family; an upstream-session report reaches the streams holding that digest, and the envelope carries the digest and never the raw session; a report naming no one reaches no stream; empty registry keys are removed. Verify: `go test -run 'TestSessionSignals_Bus' -count=1 -race ./httpsec/`.
- [ ] 6.2 Treat bus envelopes as untrusted, test-first:
  - a bus `session_ended` forwards only when the reload agrees, so a message whose session still exists (a rolled-back outer transaction, or a forged message) is not forwarded, and the heartbeat ends the stream later;
  - several wake-ups coalesce into one reload;
  - a `Reason` outside the known values is ignored, and a kept reason is used only if the store agrees within two heartbeats of its receipt, so a forged `reuse` does not name a logout an hour later; within that window `reuse` outranks a later report, so a logout reporting a family already revoked for reuse does not relabel it;
  - a library signal with an unknown name, malformed data, or more than 8 KiB is dropped, and an `app.` envelope outside `PublishSignal`'s limits is dropped.

  Verify: `go test -run 'TestSessionSignals_BusWakeUp|TestSessionSignals_BusUntrusted' -count=1 -race ./httpsec/`.
- [ ] 6.3 Handle bus failures, test-first: a failing `Publish` leaves the raising request's outcome unchanged and is logged with sampling; a `Publish` that hangs does not hold up a logout, and is abandoned after 5 s; the queue overflowing drops with a sampled log and a counted drop, and a consumer's signal gets `ErrSignalsBusy`; a consumer's `BusQueue` and `BusTimeout` are used; `Publish` receives none of the request's values; a failing `Subscribe`, one returning early with no error, and a panic in either, logged as the stream's panics are, are all retried with backoff from 1 s up to 30 s; `deliver` called concurrently, or after close, is safe; no goroutine runs before first use, or after close (goleak); the heartbeat still ends streams; with the default bus, a signal raised on another replica is not delivered. Verify: `go test -run 'TestSessionSignals_BusOutage' -count=1 -race ./httpsec/`.
- [ ] 6.4 Enforce the caps per replica, test-first: a fifth stream per sign-in, a seventeenth per user and one over the total → 200 with only `retry` within `BusyDelay` ±30%, `ErrTooManyStreams` internally, a sampled WARN, nothing charged, no existing stream closed; a dependency failure at admission → the same answer, on this path only, with other paths' 5xx unchanged; two requests racing for the last place → exactly one opens (a barrier test); a client that leaves frees its place; a chain refusing after `Stream`, on all three adapters, frees it once; a cross-site refusal leaves the count unchanged; a panicking body frees it once; consumer caps are used; `MaxPerSource` off by default, and used when set; `SessionSignalStats` counts each, including bus drops, publish failures and reload failures in a row, and its godoc says it is for operators. Verify: `go test -run 'TestSessionSignals_Caps' -count=1 -race ./httpsec/`.
- [ ] 6.5 Bound each stream's queue at 32, test-first: a slow stream drops its own events, never another stream's, and never blocks the publisher; a slow stream whose sign-in is then ended still sends `session_ended`. Godoc the bus (including that a shared bus should authenticate its transport), the replica limit and the caps. Verify: `go test -run 'TestSessionSignals_SlowStream' -count=1 -race ./httpsec/`.
- [ ] 6.6 End every open stream on `chain.CloseSessionSignals(ctx)`, test-first:
  - each stream closes without an event and frees its place;
  - a closing stream's last bytes are a fresh `retry` between 1 s and 3 × `ReconnectDelay`;
  - a stream requested afterwards gets 200 with only a `retry` line, its response ends, and it is not registered;
  - closing twice ends nothing new, and a second call waits on its own context for streams a first call timed out on;
  - a body blocked in a write does not stop `CloseSessionSignals` returning when its context ends;
  - no registry key is left afterwards;
  - an `http.Server.Shutdown` with the call registered through `RegisterOnShutdown` returns before its deadline while a stream is open.

  Document the registration in the README. Verify: `go test -run 'TestSessionSignals_Close' -count=1 -race ./httpsec/`.

## 7. Where signals come from (D5)

- [ ] 7.1 Raise `credential_changed` from the chain's endpoints after their write succeeds, test-first, one row per endpoint: password-change resolve (`password`), recovery finish (`password` or `second_factor`), passkey registration and removal (`passkey`), and MFA enrolment confirmation and removal (`second_factor`). Check the kind, that no credential detail appears, that a refused request raises nothing, and that a stream the same change ended sends `session_ended` and not `credential_changed`. Verify: `go test -run 'TestSessionSignals_CredentialChanged' -count=1 ./httpsec/`.
- [ ] 7.2 Add `ReportCredentialChange` for changes made outside the chain, test-first: a consumer's password change reaches every stream of the user; signals disabled; an unknown kind. Verify: `go test -run 'TestSessionSignals_ReportCredentialChange' -count=1 ./httpsec/`.
- [ ] 7.3 Add `PublishSignal`, test-first:
  - `app.` names reach every stream of the user unchanged;
  - refused: a name outside `^app\.[a-z0-9][a-z0-9._-]{0,62}$` (including one holding a newline), data over 8 KiB, data that is not JSON, data that is not valid UTF-8, and `json.MarshalIndent` output, with its raw line breaks;
  - signals disabled → `ErrSessionSignalsDisabled`;
  - a user with no open stream → no error;
  - a client's narrowing applies.

  Verify: `go test -run 'TestSessionSignals_Publish' -count=1 ./httpsec/`.
- [ ] 7.4 Show that the stream never carries the audit feed, test-first, with one row each for: a failed login, a lockout, a rate-limit, CSRF, host and DPoP refusal, and another user's sign-in, lockout and password change. The stream sends nothing for any of them. Update the README with the signal list and the consumer's API. Verify: `go test -run 'TestSessionSignals_NoAuditFeed' -count=1 ./httpsec/`.

## 8. Integration

- [ ] 8.1 Run the stream scenarios end to end on all three adapters in conformance: snapshot, ended from another sign-in, logout naming `logout`, a renewal that leaves the stream open, narrowing, caps, a chain refusing after `Stream`, a cross-site refusal, a gzip wrapper in front, a fiber stream's copied values staying correct as later requests reuse the buffers, and a consumer signal. Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/signals' ./...` in the `test` module.
- [ ] 8.2 Run every module's full suite with the race detector, one module at a time, then `govulncheck`, `gofmt -l` and `go vet` on every module. Verify: every command's output is clean.
- [ ] 8.3 Review the whole branch against every requirement in this change's spec deltas, every design decision and the security review table, with each finding reproduced or labelled UNREPRODUCED. Verify: the review is recorded and its findings are resolved.

## Workflow follow-up

- Add the stream and the `ResponseWriter.Stream` break to `release-readiness`'s first changelog entry.
- Archive the change once its review requirements are satisfied, before `release-readiness` tags `v0.1.0`.
- Follow-up changes: Redis and PostgreSQL `SignalBus` implementations, each authenticating its transport.
