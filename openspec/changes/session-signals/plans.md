# Session Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every task to a subagent and reviews it (`.claude/rules/subagent-delegation.md`).

**Goal:** An opt-in `text/event-stream` endpoint that tells a front end about the signed-in user's own session, through an allowlisted set of signals, on net/http, gin and fiber.

**Architecture:**
- The adapters gain `ResponseWriter.Stream(ctx, body)`. The body runs inline on net/http and gin, and through `SendStreamWriter` on fiber.
- The endpoint sits after authentication. Each stream reloads its sign-in from the session store at every heartbeat, and the store is the truth.
- Signals from the session manager's end observer, the chain's endpoints and the consumer reach streams through a bus. There is one subscription per replica and a local registry by user and family. A bus message only wakes a stream.

**Tech Stack:** Go 1.27; `net/http` `ResponseController`; gin v1.12; fiber v3.5 / fasthttp v1.73; testify, uber-go/mock, the project's fake clock.

**Spec:** `openspec/changes/session-signals/` (`proposal.md`, `design.md` D1–D8, `specs/{session-signals,framework-adapters,http-security-chain,sessions}/spec.md`, `tasks.md`).

## Global Constraints

- Test-first for every task: a red run that fails on an assertion (a compile error is not red), then green, then refactor (`.claude/rules/golang-tdd.md`). Tables follow the `table-test` skill: an `assert` closure, and `t.Context()`.
- Mocks come from `mockgen` (`use-mockgen`), never hand-rolled. Database-backed tests use the `test` module's testcontainers helpers.
- Defaults are safe. Every option names its default in godoc, and a meaningless configuration is `ErrConfig` from `New` (`.claude/rules/library-design.md`).
- Defaults pinned by the spec:
  - path `/session/signals`;
  - signals `session_ended` and `session_expiring`;
  - heartbeat 15 s, within 5–60 s;
  - warning window 2 min, greater than 0 and shorter than the idle timeout;
  - caps 4 per sign-in, 16 per user, 10 000 in total, per replica;
  - `retry: 5000`;
  - consumer data up to 8 KiB, with an `app.` prefix;
  - a queue of 32 per stream;
  - at most 16 `signals` query names and 256 bytes.
- Statuses: 401 for no credential or a credential in the query; 403 for Basic, an API key or a token with no session; 405 for another method; 429 `ErrTooManyStreams`; 501 `ErrStreamingUnsupported`; 503 after `CloseSessionSignals`.
- The stream never carries the audit feed, any session identifier, or a client address.
- Never read or cite `.claude/.legacy`. Never edit `openspec/` from an implementer.
- Run modules' suites one at a time, never in parallel.

## Review Focus

1. **Shutdown with streams open:** `http.Server.Shutdown` must return before its deadline. That is task 6.6's test.
2. **A user deactivated while a stream is open:** the next heartbeat ends the stream as the bearer would refuse it. That is task 5.1's "user no longer active" row.
3. **A browser reconnecting after `session_ended`:** it must get 401 and stop. That is task 5.1's reconnect row.
4. **Deadlines across time zones:** every time on the wire is RFC 3339 UTC. That is task 4.4's assertion.
5. **One user, many sign-ins:** ending one family must not end the others' streams. That is task 6.1's family-filter row.

---

### Task 1.1: Baseline after `close-security-gaps`

**Files:** `openspec/changes/session-signals/design.md`. The main session edits it.

- [ ] Rebase `docs/session-signals-proposal`, or the implementation branch, onto `main` once `close-security-gaps` has merged.
- [ ] Use gopls to confirm these exist: `httpsec.CookieAuthenticator`, the session-management `EndSignIn`/`EndOtherSignIns`, the re-authentication window accessor, `session.Sessions.ListByUser`, and the D13 emission points. Record any name that differs in D3 and D5.
- [ ] Run `openspec validate session-signals --strict`. It is expected to report valid, with the design naming the merged commit.

### Tasks 1.2–1.6: Adapter streaming (D1)

**Files:**
- Modify: `httpsec/exchange.go` (the `ResponseWriter` interface).
- Create: `httpsec/stream.go` (`EventWriter`, `ErrStreamingUnsupported`).
- Modify: `httpsec/nethttp.go` (the net/http writer, which gin also uses through `NewHTTPResponseWriter`).
- Modify: `httpsec/fibersec/exchange.go` (`responseWriter`).
- Tests: `httpsec/nethttp_stream_test.go`, `httpsec/ginsec/stream_test.go`, `httpsec/fibersec/stream_test.go`.
- Conformance: `test/httpsecconformance/stream_scenarios.go`, registered in `scenarios.go`.

**Interfaces produced:**
```go
// httpsec
type ResponseWriter interface { /* existing four */; Stream(ctx context.Context, body func(ctx context.Context, w EventWriter) error) error }
type EventWriter interface { io.Writer; Flush() error }
var ErrStreamingUnsupported = errors.New("httpsec: response writer cannot stream")
```

- [ ] **1.2 Red:** `TestFiber_StreamOutlivesWriteTimeout`. A fasthttp server with `WriteTimeout: 3*time.Second` serves a fiber route whose `SendStreamWriter` body writes `:\n\n`, flushes, and calls `fc.RequestCtx().Conn().SetWriteDeadline(time.Now().Add(10*time.Second))` every 5 s for 30 s. The client reads with `bufio.Reader` and counts 6 comments. First run it without the deadline call and expect the read to fail near 3 s. With the call it should pass. If it never passes, stop and report to the main session (design D1 risk).
- [ ] **1.3 Red:** `TestHTTPResponseWriter_Stream`, a table over `httptest.NewUnstartedServer` with `Config.WriteTimeout = 3s`:
  - the client receives the first event before the body returns;
  - the stream lives 30 s with 5 s flushes;
  - an ordinary handler sleeping 4 s is cut;
  - closing the client ends the body's `ctx` within 1 s.

  **Green:** `Stream` runs `body` inline. `Flush` calls `rc.SetWriteDeadline(now + 10s)`, then writes, then `rc.Flush()`. `ctx` is the request context.
- [ ] **1.4:** `TestGin_Stream` asserts the same rows through `ginsec.Middleware`. Expect green without new production code, because gin uses `NewHTTPResponseWriter`. If it is red, fix it in `nethttp.go`.
- [ ] **1.5 Red:** `TestFiber_Stream` uses the same rows, with client loss detected within one flush interval. **Green:**
  - `Stream` calls `fc.SendStreamWriter` with a closure that builds `ctx` from `context.WithoutCancel(chainCtx)`;
  - the closure cancels it on a `Flush` error, or when `RequestCtx.Done()` closes;
  - each `Flush` sets the connection deadline (from 1.2), then calls `w.Flush()`.
- [ ] **1.6:** Add conformance scenarios named `stream: …` for the four `framework-adapters` scenarios, plus a consumer writer returning `ErrStreamingUnsupported` that yields 501 (exercised from Task 4.1). Godoc `Stream`, `EventWriter` and `ErrStreamingUnsupported`.
- [ ] Verify each task's command from `tasks.md`, then `go test -race -count=1 ./...` in the root, `httpsec/ginsec`, `httpsec/fibersec` and `test`. Commit `feat(httpsec)!: response writers can stream`.

### Tasks 2.1–2.2: End observer (D5)

**Files:**
- Create: `session/end_observer.go`.
- Modify: `session/sessions.go` (`Delete`, `DeleteByUser`, `DeleteByUserExcept`, `DeleteByUserAndExternalIssuer`, `RevokeFamily`, and the reuse path in `session/reuse.go`).
- Modify: `session/sessions_options.go`.
- Test: `session/end_observer_test.go`.

**Interfaces produced:**
```go
type EndReason string // EndLogout "logout", EndEnded "ended", EndReuse "reuse", EndAllEnded "all_ended", EndProviderLogout "provider_logout"
type EndReport struct { User identity.UserID; Family id.ID; Kept id.ID; Reason EndReason }
type EndObserver func(ctx context.Context, r EndReport)
func WithEndObserver(o EndObserver) Option
func EndObservers(os ...EndObserver) EndObserver
func (m *Sessions) HasEndObserver() bool // read by httpsec at construction (Task 3.1)
func (m *Sessions) DeleteWithReason(ctx context.Context, id string, r EndReason) error // httpsec passes logout/ended
```

- [ ] **2.1 Red:** `TestManager_EndObserver`, one row per reason, each asserting the exact `EndReport` and that no identifier field exists:
  - `Delete` → `{User, Family, ended}`. With an observer set it loads first.
  - `RevokeFamily` → `{Family, ""}`, with the reason given by the caller path: `reuse` from the reuse path, `logout` through `DeleteWithReason`.
  - `DeleteByUser` → `{User, all_ended}`.
  - `DeleteByUserExcept` → `{User, Kept, all_ended}`.
  - `DeleteByUserAndExternalIssuer` → `{User, provider_logout}`.
  - With no observer, nothing is reported.
  - A store error is not reported.
  - A panicking observer leaves `err == nil`.

  **Green:** the manager calls the observer after the store call returns nil, with a deferred `recover`, as `WithReuseObserver` does.
- [ ] **2.2 Red:** `TestEndObservers` checks that both are called in order and that a panic in the first still calls the second. `TestManager_EndObserver_NotOnExpiry` checks that `DeleteExpired` and loading past a deadline report nothing. Godoc: the default is no observer.
- [ ] Verify with `go test -race -count=1 ./session/` and the root suite. Commit `feat(session): report ended sign-ins to an optional observer`.

### Tasks 3.1–3.2: Configuration (D2)

**Files:**
- Create: `httpsec/signals.go` (types, config, `EnableSessionSignals`).
- Modify: `httpsec/options.go` (the slot constant and construction).
- Test: `httpsec/signals_construction_test.go`.

**Interfaces produced:**
```go
type Signal string // SignalSessionEnded, SignalSessionExpiring, SignalAssuranceLapsed, SignalCredentialChanged
type SessionSignals struct { Path string; Signals []Signal; Heartbeat, ExpiryWarning time.Duration; MaxPerSignIn, MaxPerUser, MaxStreams int; Bus SignalBus }
const DefaultSessionSignalsPath = "/session/signals"
const OrderSessionSignals Order // after every authentication slot, beside session management
func EnableSessionSignals(s SessionSignals) Option
var ErrSessionSignalsDisabled, ErrInvalidSignal, ErrTooManyStreams error
```

- [ ] **3.1 Red:** `TestSessionSignals_Construction`, one table with every row listed in `tasks.md` 3.1. The refusing rows assert `errors.Is(err, ErrConfig)` and that the message names the field. **Green:** validate after all options have applied, so the idle timeout and re-authentication are known. Install the end observer on the chain's session manager, and refuse when `HasEndObserver()` is already true, naming `session.EndObservers`.
- [ ] **3.2:** Godoc each field with its default and range. Verify with `go doc ./httpsec SessionSignals`. Commit.

### Tasks 4.1–4.6: The endpoint (D3, D7)

**Files:**
- Create: `httpsec/signals_endpoint.go` (the interceptor), `httpsec/signals_wire.go` (event encoding).
- Modify: `httpsec/session_bearer.go`, `httpsec/bearer.go` (the activity skip), and the CSRF `CookieAuthenticator` godoc.
- Tests: `httpsec/signals_endpoint_test.go`.
- Docs: the README section "Session signals".

**Interfaces produced:**
```go
func RecordsSessionActivity(ex *Exchange) bool
func writeEvent(w io.Writer, name string, data any) error // "event: %s\ndata: %s\n\n"; data is JSON
```

- [ ] **4.1–4.5 Red, one table per task:**
  - `TestSessionSignals_Endpoint`: status, `Content-Type`, `Cache-Control`, `X-Accel-Buffering`; 405; the consumer path; 501 from a consumer writer.
  - `TestSessionSignals_Admission`: 401, 401 for a query credential, 403 three ways, a pending sign-in refused, a `CookieAuthenticator` session opens.
  - `TestSessionSignals_NoActivity`: the idle deadline is unchanged after opening, and `RecordsSessionActivity` is false on the path.
  - `TestSessionSignals_WireFormat`: the first line is `retry: 5000`, then `event: session` with `idle_deadline`, `absolute_deadline` and `authenticated_at` all ending in `Z`, no `id:` line anywhere, and heartbeats as `:`.
  - `TestSessionSignals_Narrowing`: narrowed, widening ignored, 17 names → 400, 257 bytes → 400, and no parameter.
- [ ] **4.6 Red:** `TestSessionSignals_EarlySlots` covers a rate-limited source, an allowed origin and an other origin. Then write the README section: enabling, an `EventSource` example (cookie session), a `fetch()` reader example (bearer), the defaults table, and nginx `proxy_buffering off`.
- [ ] Verify each task's command, then the root suite. Commit per task.

### Tasks 5.1–5.5: Lifecycle (D4)

**Files:**
- Create: `httpsec/signals_stream.go` (the per-stream loop: heartbeat, reload, timers).
- Tests: `httpsec/signals_stream_test.go`. The fake clock drives every timer.

**Interfaces consumed:** `session.Sessions` load, and the user loader the bearer uses (for the active-user check).

- [ ] **5.1 Red:** `TestSessionSignals_Heartbeat`, every row in `tasks.md` 5.1. The jitter row asserts each interval is within `[0.9, 1.1] × heartbeat` over 20 beats.
- [ ] **5.2–5.4 Red:**
  - `TestSessionSignals_DeadlineMoved`;
  - `TestSessionSignals_Expiring`: the idle deadline 90 s away gives `{"deadline":"idle"}`; a consumer window of 5 min; reaching the absolute deadline gives `expired`;
  - `TestSessionSignals_AssuranceLapsed`: once, and again only after a new authentication.
- [ ] **5.5 Red:** `TestSessionSignals_IdleTab` and `TestSessionSignals_EndedAlwaysSent`. Then update the README lifecycle section, including "10 000 streams at 15 s ≈ 670 reads/s per replica".
- [ ] Verify each task's command with `-race`. Commit.

### Tasks 6.1–6.6: Bus, registry, caps, shutdown (D6, D8)

**Files:**
- Create: `httpsec/signals_bus.go` (the port and the in-process default), `httpsec/signals_registry.go`.
- Tests: `httpsec/signals_bus_test.go`, `httpsec/signals_registry_test.go`.
- Mock: `SignalBus`, through a `//go:generate` directive per `use-mockgen`.

**Interfaces produced:**
```go
type SignalBus interface {
    Publish(ctx context.Context, e SignalEnvelope) error
    Subscribe(ctx context.Context, deliver func(SignalEnvelope)) error
}
type SignalEnvelope struct { User identity.UserID; Family id.ID; Kept id.ID; Name string; Data json.RawMessage }
func (c *Chain) CloseSessionSignals(ctx context.Context) error
```

- [ ] **6.1–6.5 Red:**
  - `TestSessionSignals_Bus`: routing by user, by family, and by user minus `Kept`. Two families of one user, where ending one leaves the other's stream open.
  - `TestSessionSignals_BusWakeUp`: a wake-up whose session exists is not forwarded, and the heartbeat ends it later.
  - `TestSessionSignals_BusOutage`: `Publish` fails and the raising request still returns 200; `Subscribe` fails twice and then succeeds (retried); the heartbeat still ends streams.
  - `TestSessionSignals_Caps`.
  - `TestSessionSignals_SlowStream`: a stream that never reads loses its 33rd event, another stream gets all 33, and `PublishSignal` returns within 10 ms.
- [ ] **6.6 Red:** `TestSessionSignals_Close`. Streams close with no event, a new stream gets 503, and `srv.Shutdown(ctx with 2s)` returns nil when `CloseSessionSignals` is registered with `RegisterOnShutdown`. Then update the README shutdown snippet.
- [ ] Verify each task's command with `-race`. Commit.

### Tasks 7.1–7.4: Signal sources (D5)

**Files:**
- Modify: `httpsec/password_change.go`, `httpsec/recovery.go`, `httpsec/passkey_register.go`, `httpsec/passkey_manage.go`, `httpsec/mfa_enrol.go`, and the MFA removal endpoint once 1.1 has located it.
- Create: `httpsec/signals_publish.go`.
- Tests: `httpsec/signals_sources_test.go`.

**Interfaces produced:**
```go
type CredentialKind string // "password", "passkey", "second_factor"
func (c *Chain) ReportCredentialChange(ctx context.Context, user identity.UserID, kind CredentialKind) error
func (c *Chain) PublishSignal(ctx context.Context, user identity.UserID, name string, data json.RawMessage) error
```

- [ ] **7.1–7.4 Red:**
  - `TestSessionSignals_CredentialChanged`: one row per endpoint, asserting `{"kind":…}` only.
  - `TestSessionSignals_ReportCredentialChange`.
  - `TestSessionSignals_Publish`.
  - `TestSessionSignals_NoAuditFeed`: every row asserts that the stream read for two heartbeats holds only comments.

  **Green:** each endpoint calls the internal raise after its write succeeds, never on a refusal.
- [ ] Update the README with the signal list and the consumer's API. Verify each task's command. Commit.

### Tasks 8.1–8.3: Integration

- [ ] **8.1:** `test/httpsecconformance/signals_scenarios.go`, with scenarios named `signals: …` covering the five listed in `tasks.md` 8.1, on all three adapters.
- [ ] **8.2:** Run every module's suite one at a time with `-race`, then `govulncheck ./...`, `gofmt -l .` and `go vet ./...` per module. All output must be clean.
- [ ] **8.3:** An Opus reviewer checks the branch against every requirement in the four spec deltas and every decision D1–D8. Each finding is REPRODUCED with a failing test or labelled UNREPRODUCED (`.claude/rules/defect-claims.md`). Findings go back to a fresh dispatch.
