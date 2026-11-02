# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done. Run the module's full suite with `-race` at the end of each group.

## 1. Baseline and adapter streaming (D1)

- [ ] 1.1 Rebase onto `main` after `close-security-gaps` has merged, and recheck what the design relies on: `CookieAuthenticator`, `EndSignIn` and `EndOtherSignIns`, the re-authentication window, the internal-set pattern (D8 there) and the security-event emission points. Record any difference in `design.md`. Verify: `openspec validate session-signals --strict` passes, and the design names the merged commit.
- [ ] 1.2 Establish fiber first: in a test with a fasthttp server whose `WriteTimeout` is 3 seconds, a `SendStreamWriter` body that sets the connection's write deadline forward on each flush must stay open for 30 seconds. If it cannot, stop and amend the `framework-adapters` delta and D1 before any other task. Verify: `go test -run 'TestFiber_StreamOutlivesWriteTimeout' -count=1 ./...` in `httpsec/fibersec`.
- [ ] 1.3 Add `ResponseWriter.Stream`, `EventWriter` and `ErrStreamingUnsupported`, and implement them for net/http with `http.ResponseController`. Run the body inline, extend the write deadline on each flush, and end the body's context when the client leaves, test-first. Verify: `go test -run 'TestHTTPResponseWriter_Stream' -count=1 ./httpsec/`.
- [ ] 1.4 Implement `Stream` in `ginsec` over gin's writer, with the same three behaviours, test-first. Verify: `go test -run 'TestGin_Stream' -count=1 ./...` in `httpsec/ginsec`.
- [ ] 1.5 Implement `Stream` in `fibersec` through `SendStreamWriter`, with a context detached from the chain's end-of-request cancellation, ended by a failed flush or by shutdown, and the per-flush deadline from 1.2, test-first. Verify: `go test -run 'TestFiber_Stream' -count=1 ./...` in `httpsec/fibersec`.
- [ ] 1.6 Add the adapter scenarios to conformance on all three adapters: a flushed event arrives while the response is open; a stream outlives a 3-second write timeout; an ordinary response keeps the deadline; a client that leaves stops the stream within a heartbeat. Godoc `Stream` and `EventWriter`, including what a consumer adapter that cannot stream returns. Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/stream' ./...` in the `test` module.

## 2. Ended sign-ins reported by the session manager (D5)

- [ ] 2.1 Add `session.WithEndObserver` and `EndReport{User, Family, Reason}`, reported after each successful end, with no session identifier, test-first, one table row per reason: `logout`, `ended`, `reuse`, `all_ended`, `provider_logout`. Include no observer, a failed write (nothing reported) and a panicking observer (the outcome is unchanged). Verify: `go test -run 'TestManager_EndObserver' -count=1 -race ./session/`.
- [ ] 2.2 Add `session.EndObservers(...)`, which composes observers, and show that sweeping and passing a deadline report nothing, test-first. Godoc both, naming the default (no observer). Verify: `go test -run 'TestEndObservers|TestManager_EndObserver_NotOnExpiry' -count=1 ./session/`.

## 3. Configuration and construction (D2)

- [ ] 3.1 Add the `Signal` constants, the `SessionSignals` configuration with its defaults, `EnableSessionSignals` and `OrderSessionSignals`, test-first. One construction table covers: defaults filled; an unknown signal name; a heartbeat of 4 s and 61 s; a warning window of zero, and one not shorter than the idle timeout; each cap at 0; `assurance_lapsed` without re-authentication; enabled twice; and a consumer's manager that already has an end observer. Verify: `go test -run 'TestSessionSignals_Construction' -count=1 ./httpsec/`.
- [ ] 3.2 Godoc every field with its default and its range, and `OrderSessionSignals` with its place after authentication. Verify: `go doc ./httpsec SessionSignals` names each default, and `go vet ./httpsec/` is clean.

## 4. The endpoint (D3, D7)

- [ ] 4.1 Answer the endpoint, test-first: not enabled → passes through; `GET` → 200, `text/event-stream`, `no-store`, `X-Accel-Buffering: no`; another method → 405; a consumer path; a consumer adapter that cannot stream → 501. Verify: `go test -run 'TestSessionSignals_Endpoint' -count=1 ./httpsec/`.
- [ ] 4.2 Admit only a signed-in request, test-first: no credential → 401; a session reference only in the query → 401; HTTP Basic, an API key, or a token with no session → 403; a sign-in still owing a second factor, enrolment or recovery → refused as the gates refuse it; a consumer `CookieAuthenticator` session → opens. Verify: `go test -run 'TestSessionSignals_Admission' -count=1 ./httpsec/`.
- [ ] 4.3 Record no session activity for the stream, test-first: the built-in authenticators consult the internal set, and `RecordsSessionActivity(ex)` reports it to a consumer authenticator. Verify: `go test -run 'TestSessionSignals_NoActivity' -count=1 ./httpsec/`.
- [ ] 4.4 Write the wire format, test-first: `retry: 5000` first; then the `session` snapshot with the two deadlines and `authenticated_at` in RFC 3339 UTC, and no identifier; events as `event:` and `data:` with no `id:`; heartbeats as comments. Verify: `go test -run 'TestSessionSignals_WireFormat' -count=1 ./httpsec/`.
- [ ] 4.5 Narrow by the `signals` query parameter, test-first: narrowed; a widening name ignored; more than 16 names or 256 bytes; no parameter → the chain's set. Verify: `go test -run 'TestSessionSignals_Narrowing' -count=1 ./httpsec/`.
- [ ] 4.6 Show that the early slots apply, test-first: a rate-limited source gets no stream, an origin CORS allows with credentials gets a stream, and another origin gets none. Add the README section "Session signals", covering enabling, the `EventSource` and `fetch()` clients, the defaults table, and proxy buffering. Verify: `go test -run 'TestSessionSignals_EarlySlots' -count=1 ./httpsec/`.

## 5. Stream lifecycle against the store (D4)

- [ ] 5.1 Reload the sign-in at each heartbeat with ±10% jitter, test-first: gone, revoked, superseded past its window, or logged out → `session_ended` with the store's reason, then close; the user no longer active → `session_ended` with `ended`, as the bearer refuses such a user; still valid → a comment only; a reconnect after `session_ended` with the same credential → 401; a consumer heartbeat interval is used. Verify: `go test -run 'TestSessionSignals_Heartbeat' -count=1 -race ./httpsec/`.
- [ ] 5.2 Send a new `session` event when a reload finds a deadline moved, test-first. Verify: `go test -run 'TestSessionSignals_DeadlineMoved' -count=1 ./httpsec/`.
- [ ] 5.3 Arm one timer per stream for `session_expiring` (once per window, the earlier deadline named) and for expiry (`session_ended` with `expired`), with a consumer warning window, test-first on the fake clock. Verify: `go test -run 'TestSessionSignals_Expiring' -count=1 ./httpsec/`.
- [ ] 5.4 Send `assurance_lapsed` once when the re-authentication window passes, and again only after a new authentication lapses, test-first. Verify: `go test -run 'TestSessionSignals_AssuranceLapsed' -count=1 ./httpsec/`.
- [ ] 5.5 End to end: a stream left open with no other request reaches the idle deadline and ends with `expired`. Send `session_ended` even when narrowed away. Update the README with the lifecycle and the store-load arithmetic. Verify: `go test -run 'TestSessionSignals_IdleTab|TestSessionSignals_EndedAlwaysSent' -count=1 ./httpsec/`.

## 6. Bus, registry and caps (D6, D8)

- [ ] 6.1 Add `SignalBus`, `SignalEnvelope`, the in-process default, and the per-replica registry fed by one subscription, test-first: an envelope reaches only its user's streams, and `session_ended` only its family's. Verify: `go test -run 'TestSessionSignals_Bus' -count=1 -race ./httpsec/`.
- [ ] 6.2 Treat a bus `session_ended` as a wake-up, test-first: it forwards only when the reload agrees. A message whose session still exists (a rolled-back outer transaction, or a forged message) is not forwarded, and the heartbeat ends the stream later. Verify: `go test -run 'TestSessionSignals_BusWakeUp' -count=1 -race ./httpsec/`.
- [ ] 6.3 Handle bus failures, test-first: a failing `Publish` leaves the raising request's outcome unchanged and is logged with sampling; a failing `Subscribe` is retried with backoff; the heartbeat still ends streams. Verify: `go test -run 'TestSessionSignals_BusOutage' -count=1 -race ./httpsec/`.
- [ ] 6.4 Enforce the caps per replica, test-first: a fifth stream per sign-in, a seventeenth per user and one over the total → 429 `ErrTooManyStreams`, nothing charged, no existing stream closed; a client that leaves frees its place; consumer caps are used. Verify: `go test -run 'TestSessionSignals_Caps' -count=1 -race ./httpsec/`.
- [ ] 6.5 Bound each stream's queue at 32, test-first: a slow stream drops its own events, never another stream's, and never blocks the publisher. Godoc the bus, the replica limit and the caps. Verify: `go test -run 'TestSessionSignals_SlowStream' -count=1 -race ./httpsec/`.

- [ ] 6.6 End every open stream on `chain.CloseSessionSignals(ctx)`, test-first: each stream closes without an event and frees its place, a stream opened afterwards is refused with 503, and an `http.Server.Shutdown` with the call registered through `RegisterOnShutdown` returns before its deadline while a stream is open. Document the registration in the README. Verify: `go test -run 'TestSessionSignals_Close' -count=1 -race ./httpsec/`.

## 7. Where signals come from (D5)

- [ ] 7.1 Raise `credential_changed` from the chain's endpoints, test-first, one row per endpoint: password-change resolve, recovery finish, passkey registration, passkey removal, MFA enrolment confirmation, MFA removal. Check the kind and that no credential detail appears. Verify: `go test -run 'TestSessionSignals_CredentialChanged' -count=1 ./httpsec/`.
- [ ] 7.2 Add `ReportCredentialChange` for changes made outside the chain, test-first, including signals disabled and an unknown kind. Verify: `go test -run 'TestSessionSignals_ReportCredentialChange' -count=1 ./httpsec/`.
- [ ] 7.3 Add `PublishSignal`, test-first: `app.` names reach every stream of the user unchanged; a name without the prefix and data over 8 KiB are refused; signals disabled → `ErrSessionSignalsDisabled`; a client's narrowing applies. Verify: `go test -run 'TestSessionSignals_Publish' -count=1 ./httpsec/`.
- [ ] 7.4 Show that the stream never carries the audit feed, test-first: one row each for a failed login, a lockout, a rate-limit, CSRF, host and DPoP refusal, and another user's sign-in, and the stream sends nothing for any of them. Update the README with the signal list and the consumer's API. Verify: `go test -run 'TestSessionSignals_NoAuditFeed' -count=1 ./httpsec/`.

## 8. Integration

- [ ] 8.1 Run the stream scenarios end to end on all three adapters in conformance: snapshot, ended from another sign-in, narrowing, caps, and a consumer signal. Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/signals' ./...` in the `test` module.
- [ ] 8.2 Run every module's full suite with the race detector, one module at a time, then `govulncheck`, `gofmt -l` and `go vet` on every module. Verify: every command's output is clean.
- [ ] 8.3 Review the whole branch against every requirement in this change's spec deltas and every design decision, with each finding reproduced or labelled UNREPRODUCED. Verify: the review is recorded and its findings are resolved.

## Workflow follow-up

- Add the stream and the `ResponseWriter.Stream` break to `release-readiness`'s first changelog entry.
- Archive the change once its review requirements are satisfied, before `release-readiness` tags `v0.1.0`.
- Follow-up changes: Redis and PostgreSQL `SignalBus` implementations.
