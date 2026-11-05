# Session Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every task to a subagent and reviews it (`.claude/rules/subagent-delegation.md`).

**Goal:** An opt-in `text/event-stream` endpoint that tells a front end about the signed-in user's own session, through an allowlisted set of signals, on net/http, gin and fiber.

**Architecture:**
- The adapters gain `ResponseWriter.Stream(ctx, contentType, body)`. The body runs inline on net/http and gin, and through `SendStreamWriter` on fiber.
- The endpoint is a terminal interceptor at `OrderSessionSignals` (673): after authentication and the pending-session gates, and below session touch (800), so it never records activity. It refuses cross-site requests by Fetch Metadata and `Origin` itself.
- Each stream reads its sign-in by user and family through `Sessions.SignInState`, and its user, at every heartbeat, and never through `Sessions.Load`. The store is the truth. Signals from the session manager's end observer, the chain's endpoints and the consumer reach streams through a bus. There is one subscription per replica, and a local registry by user and family. A bus message only wakes a stream.

**Tech Stack:** Go 1.27; `net/http` `ResponseController`; gin v1.12.0; fiber v3.5.0 and fasthttp v1.73.0, or whatever `httpsec/fibersec` pins when task 1.2 runs; testify, uber-go/mock, the project's fake clock.

**Spec:** `openspec/changes/session-signals/` (`proposal.md`, `design.md` D1–D10 and its security review, `specs/{session-signals,framework-adapters,http-security-chain,sessions}/spec.md`, `tasks.md`). Revised on 2026-11-03 against `main` at `4649c90`.

## Global Constraints

- Test-first for every task: a red run that fails on an assertion (a compile error is not red), then green, then refactor (`.claude/rules/golang-tdd.md`). Tables follow the `table-test` skill: an `assert` closure, and `t.Context()`.
- Mocks come from `mockgen` (`use-mockgen`), never hand-rolled. Database-backed tests use the `test` module's testcontainers helpers.
- Defaults are safe. Every option names its default in godoc, and a meaningless configuration is `ErrConfig` from `New` (`.claude/rules/library-design.md`).
- Defaults pinned by the spec:
  - path `/session/signals`;
  - signals `session_ended` and `session_expiring`;
  - heartbeat 15 s, within 5–60 s, with ±10% jitter;
  - warning window 2 min, not negative and shorter than the idle timeout, with zero taking the default;
  - assurance window `DefaultRecentAuthenticationWindow` (15 min), not negative, with zero taking the default;
  - caps 4 per sign-in, 16 per user and 10 000 in total, per replica;
  - `ReconnectDelay` 5 s ±30% per stream, `BusyDelay` 30 s ±30% per refusal, and on closing a fresh `retry` between 1 s and 3 × `ReconnectDelay`;
  - `MaxAge` 1 hour ±10%, `NoMaxAge` to turn it off, at least 2 × heartbeat; `MaxPerSource` off;
  - `ReloadTimeout` half the heartbeat, within 2–10 s, shorter than the heartbeat if set, one budget for the session and user reads together;
  - `BusQueue` 1024, at most 1 048 576, and `BusTimeout` 5 s, for a consumer's bus only;
  - a queue of 32 per stream, and a wake channel of 1;
  - at most 16 `signals` query names and 256 bytes;
  - consumer data up to 8 KiB of valid JSON and valid UTF-8, with no raw CR or LF;
  - consumer names matching `^app\.[a-z0-9][a-z0-9._-]{0,62}$`;
  - `Subscribe` retried with backoff from 1 s to 30 s.
- Statuses (design D10):
  - 400 for a `signals` parameter over its limits;
  - 401 for no credential, a credential only in the query, or a reconnect after the end;
  - 403 for Basic, an API key, a token with no session, or a cross-site request from an untrusted origin (`ErrCrossSiteStream`);
  - 405 with `Allow: GET`;
  - 501 `ErrStreamingUnsupported`, including a writer that cannot flush;
  - **no 429 and no 5xx on this path: a cap reached (`ErrTooManyStreams` internally) or a dependency failure at admission is 200 with only `retry` within `BusyDelay` ±30%, then the response ends;**
  - **after `CloseSessionSignals`, 200 with only `retry`, then the response ends. Never 503.**
- The stream never carries the audit feed, any session identifier or a client address. No raw CR or LF ever reaches the wire inside an event field.
- A store failure during a reload never ends a stream (user's choice, 2026-11-03). Only a store that agrees, or the absolute deadline during an outage, ends one.
- **A stream never calls `Sessions.Load`, holds no session identifier, and no read of its can present, judge or revoke.** Every reload row asserts it.
- A body reads nothing from the exchange: the endpoint copies what it needs before `Stream`, with `strings.Clone` for strings.
- No log holds a panic's value, a token or a session identifier. The chain's own stream body, publisher and subscription goroutines recover their panics and log through the chain's logger; the adapter's recover is only a backstop.
- Verify commands run with `-v`, and the named tests must appear. Timing-sensitive tests also pass 16 concurrent copies of the compiled binary, for several rounds. Tests order events with barriers, not sleeps.
- Never read or cite `.claude/.legacy`. Never edit `openspec/` from an implementer. Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.
- Run modules' suites one at a time, never in parallel. Navigate with gopls (`.claude/rules/gopls-navigation.md`).

## Review Focus

1. **A cross-site page holding the victim's stream places.** Expected: 403 before registration, and the count is unchanged. Task 4.6's first row, which is also the red test for design D3's UNREPRODUCED claim.
2. **A store blip while thousands of streams are open.** Expected: no `session_ended` and no closed streams, and the first successful reload after the outage ends any stream whose sign-in was ended meanwhile. Task 5.1's store-failure row.
3. **A rolling deploy.** Expected: streams on the closing replica end without an event, and a new request there gets 200 with only `retry`, so browsers reconnect elsewhere. Task 6.6.
4. **A consumer signal name built from user input.** Expected: `app.x\nevent: session_ended` is refused by `PublishSignal`, and the writer refuses a raw CR or LF even if a name slips through. Tasks 4.4 and 7.3.
5. **One user, many sign-ins.** Expected: ending one family leaves the other families' streams open, and a user-wide report with `KeptFamily` spares that family's streams. Task 6.1.
6. **A renewal while a stream is open.** Expected: the stream stays open, the sign-in stays live, and no reuse is reported. Tasks 2.4 and 5.1.
7. **An ordinary logout.** Expected: other tabs hear `logout`, never `reuse`. Tasks 2.3 and 8.1.
8. **A timer on a stale deadline.** Expected: an active user is not told their session ended. Task 5.3.
9. **A bus or store that hangs.** Expected: a logout completes, heartbeats continue. Tasks 5.1 and 6.3.
10. **A chain refusing after `Stream`, on fiber.** Expected: the client gets the refusal and the place is freed. Tasks 1.5 and 6.4.

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | A | 1.2–1.6 | `httpsec/exchange.go`, `httpsec/stream.go` (new), `httpsec/nethttp.go`, `httpsec/fibersec/exchange.go`, the three adapters' stream tests, `test/httpsecconformance/stream_scenarios.go` and its registration in `scenarios.go`, and every other implementer of `httpsec.ResponseWriter` that gopls finds | Opus: an interface every later lane compiles against, and fiber's write-deadline behaviour under a real server |
| 1 (parallel) | B | 2.1–2.2 | `session/end_observer.go` (new), `session/sessions.go`, `session/signins.go`, `session/reuse.go`, `session/sessions_options.go` and their tests | Sonnet: an observer on the existing `WithReuseObserver` pattern, with a stated report table |
| 1b (after A and B) | B2 | 2.3–2.4 | `session/end_observer.go`, `session/sessions.go`, `session/signins.go`, `session/store.go` godoc only, `httpsec/logout.go` (one call), `test/storetest` rows, and tests | Opus: `SignInState` is what stops a stream harming a live sign-in, and a mistake there passes the tests and is still wrong |
| 2 (after A and B) | C1 | 3.1–3.2, 4.1–4.3 | `httpsec/signals.go` (new), `httpsec/signals_endpoint.go` (new), `httpsec/options.go`, the `CookieAuthenticator` and `OrderSessionTouch` godoc, and tests | Opus: admission and refusal logic written for the first time |
| 3 | C2 | 4.4–4.6 | `httpsec/signals_wire.go` (new), `signals_endpoint.go`, and tests, plus the README section | Opus: the cross-site refusal and the injection guard are security-critical |
| 4 | C3 | 5.1–5.6 | `httpsec/signals_stream.go` (new) and tests | Opus: a per-stream loop of timers, reloads and cancellation |
| 5 | C4 | 6.1–6.6 | `httpsec/signals_bus.go` (new), `httpsec/signals_registry.go` (new), `signals_stream.go`, the bus mock, and tests | Opus: a registry under a mutex, cap races, non-blocking delivery and shutdown |
| 6 | C5 | 7.1–7.4 | `httpsec/signals_publish.go` (new), `password_change.go`, `recovery.go`, `passkey_register.go`, `passkey_manage.go`, `mfa_enrol.go`, and the MFA removal endpoint, and tests | Sonnet: raising a known signal after existing writes, and input checks the plan states |
| 7 | D | 8.1 | `test/httpsecconformance/signals_scenarios.go` | Sonnet: conformance cases in an existing suite |
| 8 | main | 8.2–8.3 | — | Opus reviewer for 8.3 |

- **Parallel waves** (revised 2026-11-04; these supersede the Order column and the C rows' task lists). Dispatches in one wave run at the same time, and writers in one Go package each get their own git worktree, so a half-edited file cannot break another's build. The main session integrates a wave, and verifies and reviews it, before the next starts. At most three writers run at once, and the main session runs timing-sensitive load rounds one suite at a time, because the machine is shared.

  | Wave | Dispatches, in parallel | Tasks | Why it cannot go earlier |
  |---|---|---|---|
  | 0 | A; B2 | 1.2–1.6; 2.3–2.4 | Different packages. B2's one edit in `httpsec` is `logout.go`, which A does not own |
  | 1 | C1 | 3.1–3.2, 4.1–4.3 | Declares the types, the sentinels and the test helpers every later file compiles against, and alone owns `options.go` and `errors_test.go`'s registry |
  | 2 | C2a wire format; C2b cross-site check and README; C4a registry and caps | 4.4–4.5; 4.6; 6.4's and 6.5's registry rows | Each fills one file behind a signature C1 fixes, unit-tested without a stream |
  | 2b | C4b bus and publisher | 6.1's bus rows, 6.3 | Its routing and `app.` rows need the real registry and validators, so it follows C2a and C4a. It may change `hub.close` to take a context, if its leak checks need that, because it alone calls it so far |
  | 3 | C3, then C4c (sequential) | 5.1–5.6; 6.1, 6.2, 6.4–6.6's stream rows | The stream loop consumes all of wave 2, and is one goroutine's logic that does not split. 5.x then 6.x extend one file |
  | 4 | C5a | 7.2–7.3 | Needs the stream to show a signal arriving. D's consumer-signal row needs `PublishSignal` |
  | 5 | C5b; D | 7.1, 7.4; 8.1 | Different modules. **Check with `oidc-provider` before C5b**, which shares `httpsec/password_change.go`, `recovery.go` and `passkey_manage.go` with its group 11 |
  | 6 | main, then one reviewer | 8.2–8.3 | The final gate |

  **Merge order** (revised 2026-11-05). `oidc-provider` and this change agreed that whichever PR is ready first merges first, the user having left the order to them and being free to overrule it. So before the final gate this branch is rebased onto `main`, carrying only the end-observer commit it builds on, and the gate runs on that tree. `feat/oidc-provider` is not rewritten: it merges `main` in afterwards. That session is told when this branch is rebased and when it merges.

  A task spanning waves is ticked only when all its rows pass. In wave 2 each dispatch fills one file C1 created with stubs, and adds tests and its own `signals_<lane>_export_test.go`; any change to another file goes back to the main session:

  | Dispatch | Owns |
  |---|---|
  | C2a | `signals_wire.go`, where `wants` is already done: `writeEvent`, `writeRetry`, `writeHeartbeat`, `sessionEventData`, `validAppSignalName`, `validSignalData`, `narrowed` |
  | C2b | `signals_crosssite.go`: `crossSiteAllowed`; and the README |
  | C4a | `signals_registry.go`: `newSignalRegistry`, `admit`, the `deliver…` methods, `close`, `stats` |
  | C4b | `signals_bus.go`: `raise`, `start`, `deliver`, `close`, `stats`, and the default bus |
- **Reviews.** Each dispatch gets a fresh reviewer that edits nothing: Opus for A, B2, C1, C2, C3 and C4, and Sonnet for B, C5 and D. Tasks 5.1–5.6 and 6.1–6.6 are the lane's largest dispatches: if either proves too large, split it at a seam, as the delegation rule allows. The next dispatch of a lane starts only when verification is green and the review is clean.

---

### Tasks 1.2–1.6: Adapter streaming (D1; dispatch A)

**Files:**
- Modify: `httpsec/exchange.go` (the `ResponseWriter` interface).
- Create: `httpsec/stream.go` (`EventWriter`, `ErrStreamingUnsupported`, `ErrStreamingStarted`).
- Modify: `httpsec/nethttp.go` (the net/http writer, which gin also uses through `NewHTTPResponseWriter`).
- Modify: `httpsec/fibersec/exchange.go` (`responseWriter`).
- Tests: `httpsec/nethttp_stream_test.go`, `httpsec/ginsec/stream_test.go`, `httpsec/fibersec/stream_test.go`.
- Conformance: `test/httpsecconformance/stream_scenarios.go`, registered in `scenarios.go`.

**Interfaces produced:**
```go
// httpsec
type ResponseWriter interface { /* SetHeader, AddHeader, SetCookie, WriteHeader, Write */; Stream(ctx context.Context, contentType string, body func(ctx context.Context, w EventWriter) error) error }
type EventWriter interface { io.Writer; Flush() error }
var ErrStreamingUnsupported = errors.New("httpsec: response writer cannot stream")
var ErrStreamingStarted = errors.New("httpsec: response already started")
const StreamWriteWindow = 2 * time.Minute // twice the largest heartbeat; every adapter uses it (design D1)
```

- [ ] **1.2 Red:** `TestFiber_StreamOutlivesWriteTimeout`. A fasthttp server with `WriteTimeout: 3*time.Second` serves a fiber route whose `SendStreamWriter` body writes `:\n\n`, flushes, and calls `fc.RequestCtx().Conn().SetWriteDeadline(time.Now().Add(httpsec.StreamWriteWindow))` every 5 s for 30 s. The client reads with `bufio.Reader` and counts 6 comments. First run it without the deadline call, and expect the read to fail near 3 s. With the call it should pass. If it never passes, stop and report to the main session (design D1 risk). Record the fiber and fasthttp versions in the report.
- [ ] **1.3 Red:** `TestHTTPResponseWriter_Stream`, a table over `httptest.NewUnstartedServer` with `Config.WriteTimeout = 3s`:
  - the client receives the first event before the body returns;
  - the stream lives 30 s with 5 s flushes, over HTTP/1.1 and over HTTP/2 (`EnableHTTP2` with `StartTLS`);
  - over HTTP/2, a stream idle for longer than the write window survives, shown against a shortened window: first run the row with a window shorter than the gap and record the stream reset (the red for design D1's UNREPRODUCED reason), then with `StreamWriteWindow`;
  - an ordinary handler sleeping 4 s is cut;
  - closing the client ends the body's `ctx` within 1 s;
  - `Cache-Control` and `Access-Control-Allow-Origin` set before `Stream` arrive with the response;
  - `Stream` after `Write`, and a second `Stream`, return `ErrStreamingStarted` and add no bytes.

  Also: a run-time `ErrNotSupported` leaves nothing written and an ordinary answer possible; a body's panic under a recovery middleware, `gin.Recovery` included, leaves a response that does not look complete; a wrapper whose `Unwrap` returns itself does not hang; a `Flush`-only wrapper is accepted.

  **Green:** `Stream` runs `body` inline. `Stream`, each `Write` and each `Flush` first call `rc.SetWriteDeadline(now + StreamWriteWindow)`; `Flush` then calls `rc.Flush()`. `ctx` is the request context. A started flag guards against a second start.
- [ ] **1.4:** `TestGin_Stream` asserts the same rows through `ginsec.Middleware`. Expect green with no new production code, because gin uses `NewHTTPResponseWriter`. If it is red, fix it in `nethttp.go`.
- [ ] **1.5 Red:** `TestFiber_Stream`, with the same rows, client loss detected within one flush interval, and a server `ShutdownWithTimeout` that ends an open stream. **Green:**
  - `Stream` calls `fc.SendStreamWriter` with a closure that builds `ctx` from `context.WithoutCancel(chainCtx)`;
  - the closure cancels it on a `Flush` error, when `Done()` closes, or when a reader goroutine on the connection sees the client leave; a stream response carries `Connection: close`, and the reader exits on every path, unblocked by a read deadline;
  - `Middleware` holds the body behind a gate until the chain has returned;
  - a panicking body is recovered, the connection closed, and nothing of the panic value logged;
  - the closure's start, each `Write` and each `Flush` set the connection deadline to `now + StreamWriteWindow` (from 1.2); `Flush` then calls `w.Flush()`;
  - the closure holds the connection and the `Done()` channel, copied while the chain runs, and never the fiber `Ctx` or the `*fasthttp.RequestCtx`, which are pooled.

  Also: a body that calls `runtime.Goexit` ends the response as cut; a `Stream` after the chain has returned keeps the promise, running the body or returning an error; and `TestFiber_Stream` shows a stream outliving several short windows through `NewResponseWriterWithStreamWindow` (with the moves removed, it must fail), and the body ending within one heartbeat of the client leaving, over plain TCP and TLS.
- [ ] **1.6:** Add conformance scenarios named `stream: …` for every `framework-adapters` scenario, plus a consumer writer returning `ErrStreamingUnsupported` that yields 501 (exercised from Task 4.1). The client-leaves row asserts a time, within one heartbeat, and says so in its name; the outlives row uses a window shorter than its gaps. Godoc `Stream`, `EventWriter`, `StreamWriteWindow` and both errors: a body must copy what it needs from the exchange before `Stream`, strings included; a nil `Flush` hands the event on and does not promise delivery; and how long a client that stops reading can hold a stream, naming the server's `HTTP2.WriteByteTimeout`.
- [ ] Verify each task's command from `tasks.md`, then `go test -race -count=1 ./...` in the root, `httpsec/ginsec`, `httpsec/fibersec` and `test`. Commit `feat(httpsec)!: response writers can stream`.

### Tasks 2.1–2.2: End observer (D5; dispatch B)

**Files:**
- Create: `session/end_observer.go`.
- Modify: `session/sessions.go` (`Delete`, `DeleteByUser`, `DeleteByUserExcept`, `DeleteByUserAndExternalIssuer`, `RevokeFamily`), `session/signins.go` (`EndSignIn`, `EndOtherSignIns`), `session/reuse.go` (the reuse path), `session/sessions_options.go`.
- Test: `session/end_observer_test.go`.

**Interfaces produced:**
```go
type EndCause uint8 // EndReuse, EndFamilyRevoked, EndDeleted, EndUserSessions, EndUserSessionsExcept, EndExternalSession, EndUserExternalIssuer, EndByHandle, EndOtherSignIns
type EndReport struct { Cause EndCause; User identity.UserID; Family id.ID; KeptFamily id.ID; ExternalIssuer, ExternalSessionID string; At time.Time }
type EndObserver interface { SignInsEnded(ctx context.Context, r EndReport) }
type EndObserverFunc func(ctx context.Context, r EndReport) // implements EndObserver
func WithEndObserver(o EndObserver) Option                  // repeatable
func (m *Sessions) AddEndObserver(o EndObserver) error      // called by httpsec at construction (Task 3.1)
```

These names are `oidc-provider`'s (its R16). If that change landed first, extend what it added, and add only what is missing.

- [ ] **2.1 Red:** `TestSessions_EndObserver`, one row per line of design D5's table, each asserting the exact `EndReport`:
  - `Delete` → `{EndDeleted, User, Family}`, and with an observer set, the session is loaded first;
  - `EndSignIn` → `{EndByHandle, User, Family}`;
  - the reuse path → `{EndReuse, User, Family}`, and `RevokeFamily` → `{EndFamilyRevoked, Family}`;
  - `DeleteByUser` → `{EndUserSessions, User}`;
  - `DeleteByUserExcept` → `{EndUserSessionsExcept, User, KeptFamily: <the kept session's family>}`;
  - `EndOtherSignIns` → `{EndOtherSignIns, User, KeptFamily: <current family>}`;
  - `DeleteByUserAndExternalIssuer` → `{EndUserExternalIssuer, User, ExternalIssuer}`;
  - `DeleteByExternalSession` → `{EndExternalSession, ExternalIssuer, ExternalSessionID}`, with no user or family.

  Also: `WithEndObserver(nil)` fails construction with `ErrConfig`; with no observer, nothing is reported and `Delete` does no extra load; a store error is not reported; a panicking observer leaves `err == nil`; a cancelled caller context still reports, and the observer's `ctx.Err()` is nil.

  **Green:** call each observer in order after the store call returns nil, each with its own deferred `recover`, on `context.WithoutCancel(ctx)`, as `WithReuseObserver` does.
- [ ] **2.2 Red:** `TestSessions_AddEndObserver` checks that a nil observer gives `ErrConfig` and changes nothing, that an added observer runs after those given at construction, that a panic in the first still calls the second, and that adding during reports is clean under `-race`. `TestSessions_EndObserver_NotOnExpiry` checks that `DeleteExpired` and loading past a deadline report nothing. **Green:** hold the list in an `atomic.Pointer`, and copy it on add. Godoc: the default is no observer, and `AddEndObserver` is for wiring at construction.
- [ ] Verify with `go test -race -count=1 ./session/` and the root suite. Commit `feat(session): report ended sign-ins to an optional observer`.

### Tasks 2.3–2.4: Logout's cause, and a read that harms nothing (D4, D5; dispatch B2)

**Interfaces produced:**
```go
const EndLogout EndCause // appended after EndOtherSignIns, so existing values do not shift
func (m *Sessions) Logout(ctx context.Context, user identity.UserID, family id.ID) (int, error)
type SignInState struct { IdleDeadline, AbsoluteDeadline, AuthenticatedAt time.Time; ExternalIssuer, ExternalSessionID string }
func (m *Sessions) SignInState(ctx context.Context, user identity.UserID, family id.ID) (SignInState, error) // ErrNotFound when no live session; a store failure is not ErrNotFound
```

- [ ] **2.3 Red:** `TestSessions_Logout` and a row in `TestSessions_EndObserver`: `{EndLogout, User, Family}`, and a renewal's successor goes too. `TestLogout_ReportsLogoutCause` through the chain, starting from the reviewer's `TestSweep_ChainLogoutReportsDeletedCause`. **Green:** `Logout` does what `RevokeFamily` does with its own report. `httpsec/logout.go`'s edit is the one call, because `oidc-provider` group 11 also edits that function.
- [ ] **2.4 Red:** `TestSessions_SignInState`, every row in `tasks.md` 2.4, starting from `TestSweep_Candidate_ListByUserFollowsFamilyHead`. **Green:** over `Store.ListByUser` at the manager's clock, matching the family. A listing failure wraps what `ListSignIns` wraps. Add the rows to the store conformance suite if `ListByUser`'s existing rows do not already pin following a family across renewal and strict rotation on every backend.
- [ ] Verify each task's command, then `go test -race -count=1 ./session/`. Commit per task.

### Tasks 3.1–3.2, 4.1–4.3: Configuration, endpoint, admission, activity (D2, D3; dispatch C1)

**Files:**
- Create: `httpsec/signals.go` (types, config, `EnableSessionSignals`), `httpsec/signals_endpoint.go` (the interceptor).
- Modify: `httpsec/options.go` (construction), and the godoc of `CookieAuthenticator` (`httpsec/csrf.go`) and `OrderSessionTouch` (`httpsec/chain.go`).
- Tests: `httpsec/signals_construction_test.go`, `httpsec/signals_endpoint_test.go`.

Admission judges a request as bearer only when the chain recorded a credential and `Authorization` carries it, so a consumer's cookie authenticator calling `RecordPresentedToken` stays a cookie. The stream's own code gets a cancel-only context, and a stream holds the upstream digest, never the raw values.

**Interfaces produced:**
```go
type Signal string // SignalSessionEnded, SignalSessionExpiring, SignalAssuranceLapsed, SignalCredentialChanged
type SessionSignals struct {
    Path string; Signals []Signal
    Heartbeat, ExpiryWarning, AssuranceWindow, MaxAge, ReconnectDelay, BusyDelay time.Duration
    MaxPerSignIn, MaxPerUser, MaxStreams, MaxPerSource int
    Users identity.UserLoader; ReloadContext func(context.Context) context.Context; ReloadTimeout time.Duration
    Bus SignalBus; BusQueue int; BusTimeout time.Duration
}
const NoMaxAge time.Duration = -1
const DefaultSessionSignalsPath = "/session/signals"
const OrderSessionSignals = OrderSessionManagement - 1
func EnableSessionSignals(s SessionSignals) Option
func RecordsSessionActivity(ex *Exchange) bool
var ErrSessionSignalsDisabled, ErrInvalidSignal, ErrTooManyStreams, ErrCrossSiteStream, ErrSignalsBusy error
```
`SignalBus` is declared here as the port's interface only. C4 adds the default and the envelope.

- [ ] **3.1 Red:** `TestSessionSignals_Construction`, with every row in `tasks.md` 3.1. A field at zero takes its default, and negatives are refused. The refusing rows assert `errors.Is(err, ErrConfig)` and that the message names the field. **Green:**
  - validate after all options have applied, so the idle timeout and re-authentication are known;
  - add the hub's observer with `AddEndObserver` to the chain's session manager, and do not refuse a manager that already has one. The row with an existing observer asserts that it builds and that the consumer's observer is still told. The hub maps `EndCause` to the wire reason by D5's table in one function, and routes `EndExternalSession` by its digest.
- [ ] **Note for the endpoint (4.1 onward):** copy everything the body needs from the exchange before calling `Stream`, strings included with `strings.Clone`. On fiber the body runs after the chain has returned, and the request's values are reused buffers (design D1). When `ErrStreamingUnsupported` gets its 501, delete its `unmapped` entry in `httpsec/errors_test.go`.
- [ ] **3.2:** Godoc each field with its default and range. `AssuranceWindow` says to match the guards' window. Verify with `go doc ./httpsec SessionSignals`.
- [ ] **4.1–4.3 Red, one table per task:**
  - `TestSessionSignals_Endpoint`: status, `Content-Type`, `Cache-Control` of `no-store, no-transform`, `X-Accel-Buffering`; 405 with `Allow: GET`; the consumer path; 501 from a consumer writer, a wrapper with no `Unwrap`, and `http.TimeoutHandler`;
  - `TestSessionSignals_Admission`: every row in `tasks.md` 4.2;
  - `TestSessionSignals_NoActivity`: hold a stream past `Sessions.TouchInterval()` on the fake clock, and assert that `LastAccessedAt` and `IdleExpiresAt` are unchanged in the store and that `RecordsSessionActivity` is false.
- [ ] Verify each task's command, then the root suite. Commit per task.

### Tasks 4.4–4.6: Wire format, narrowing, cross-site refusal (D2, D3, D7; dispatch C2)

**Files:**
- Create: `httpsec/signals_wire.go` (event encoding).
- Modify: `httpsec/signals_endpoint.go`.
- Tests: `httpsec/signals_wire_test.go`, `httpsec/signals_endpoint_test.go`.
- Docs: the README section "Session signals".

**Interfaces produced:**
```go
func writeEvent(w io.Writer, name string, data any) error // "event: %s\ndata: %s\n\n"; refuses CR or LF in name or encoded data
var appSignalName = regexp.MustCompile(`^app\.[a-z0-9][a-z0-9._-]{0,62}$`)
func crossSiteAllowed(ex *Exchange, cors *corsPolicy) bool // the csrf-protection origin rule, applied to GET
```

- [ ] **4.4 Red:** `TestSessionSignals_WireFormat`:
  - the first line is `retry: <ms>` within `ReconnectDelay` ±30%, then `event: session` with `idle_deadline`, `absolute_deadline` and `authenticated_at` all ending in `Z`;
  - there is no `id:` line anywhere, and heartbeats are `:`;
  - `writeEvent` with a name or data holding `\n` or `\r` returns an error and writes nothing.
- [ ] **4.5 Red:** `TestSessionSignals_Narrowing`: narrowed; widening ignored; `app.Bad` and `app.x:y` dropped; 17 names → 400; 257 bytes → 400; no parameter.
- [ ] **4.6 Red:** `TestSessionSignals_CrossSite`. The first row: `Sec-Fetch-Site: cross-site` with `Origin: https://evil.example`, CORS allowing only `https://app.example.com`, returns 403. That the registered count stays 0 is asserted with 6.4. Then:
  - the same with CSRF protection off;
  - `Origin: null` → 403;
  - `same-site` from a disallowed origin → 403;
  - neither header → opens;
  - an allowed origin → opens with its CORS headers.

  Also `TestSessionSignals_EarlySlots`: a CORS preflight for `Authorization` gets 204 with no stream; a same-origin cookie stream opens without a CSRF token; a rate-limited source gets no stream. **Green:** a stream-specific check before registration. Trusted means, for a cookie-authenticated stream, an origin CORS names exactly or by pattern with credentials allowed, a wildcard not counting; and for one authenticated by `Authorization`, any origin CORS allows, a wildcard counting. `Origin: null` never passes, under `*` included. Do not reuse CORS's `allowedOrigin`, which says yes to everything under `*`, `null` included, nor the CSRF layer's trusted list, nor `ErrCrossSiteRequest`, which emits `MaliciousCSRF`. A refusal logs with sampling.
- [ ] Write the README section: enabling it; an `EventSource` client (cookie session) that probes an ordinary endpoint before rebuilding, and rebuilds on `visibilitychange`, `pageshow` and `online`; a `fetch()` client (bearer) that reads the current credential on every attempt; the defaults table; and the operator's section, one line per setting that the design's failure sweep names.
- [ ] Verify each task's command, then the root suite. Commit per task.

### Tasks 5.1–5.5: Lifecycle (D4; dispatch C3)

**Files:**
- Create: `httpsec/signals_stream.go` (the per-stream loop: ticker, timer, wake channel, queue).
- Tests: `httpsec/signals_stream_test.go`. The fake clock drives every timer.

**Interfaces consumed:** `session.Sessions.SignInState`, and `SessionSignals.Users`. Never `Sessions.Load`. The clock is the chain's, as `clock.Timed`.

**Decisions the implementer cannot make alone:**
- A timer reloads before it speaks. On a store failure only the absolute deadline ends the stream. Alive per the store while past per the clock re-arms no sooner than the next heartbeat.
- A read runs in its own goroutine, at most one in flight per stream, and hands its result over a buffered channel, so all held state and writes stay in the body. A beat, timer or wake wanting a read meanwhile is remembered. A timeout counts as a failure at once, and a later result is discarded. A body's exit cancels the read and does not wait for it. A real-time row over a real connection covers the heartbeat, a client leaving and an instant logout.
- A wake reloads at once if the stream has not reloaded from a wake in the last second. Otherwise it stays pending, and is honoured when the second is up, so a flood costs at most one read a second per stream and the last wake is never lost. The gap is a constant (design D4).
- A reason from a report is kept with its local receipt time, and used only if the store says gone within two heartbeats. It has its own field, since the wake channel carries nothing. Within that window a later report replaces it, except that `reuse` is never replaced, so a logout reporting a family already revoked for reuse does not relabel it (task 6.2).
- The hub routes `session_ended` only through `deliverEnd…`, never `deliverSignal`, because `wants` always wants it and it must not land on the queue (D9). `SignInState`'s limits stand as the design states them: a stream treats its failure as an outage, including the one undecodable row of a user, and `ConsecutiveReloadFailures` is how an operator sees that.
- The reload's context comes from `ReloadContext`, called once at admission, and defaults to one with none of the request's values. The first read at admission uses it too, and reads the user as well as the sign-in, so a missing tenant fails there, as a dependency failure. `ReloadTimeout` covers the session and user reads together.
- The body's first deferred step recovers a panic and logs through the chain's logger, with the value's type, the phase (`stream`, `reload`, `bus`), the family, and frames as function, file and line. It frees the place. It never logs the value, nor `debug.Stack()`, which quotes arguments.
- Open and close log at DEBUG with user, family, client address, origin and reason.

- [ ] **5.1 Red:** `TestSessionSignals_Heartbeat`, every row in `tasks.md` 5.1. The jitter row asserts that each interval is within `[0.9, 1.1] × heartbeat` over 20 beats. The store-failure row uses a store double that fails for two reloads and then reports the sign-in gone. It asserts two comments and no event, then `session_ended`.
- [ ] **5.2–5.4 Red:**
  - `TestSessionSignals_DeadlineMoved`, including a re-authentication that moves `authenticated_at`;
  - `TestSessionSignals_Expiring`: the idle deadline 90 s away gives `{"deadline":"idle"}`; a consumer window of 5 min; activity after a warning; reaching the absolute deadline gives `expired`, even when the store fails throughout;
  - `TestSessionSignals_AssuranceLapsed`: 15 min default, 5 min consumer, and once more after a re-authentication.
- [ ] **5.5 Red:** `TestSessionSignals_IdleTab` and `TestSessionSignals_EndedAlwaysSent`. Then update the README lifecycle section, including "10 000 streams at 15 s ≈ 670 session reads and 670 user reads per second per replica".
- [ ] **5.6 Red:** `TestSessionSignals_MaxAge`, every row in `tasks.md` 5.6.
- [ ] Verify each task's command with `-race`. Commit.

### Tasks 6.1–6.6: Bus, registry, caps, shutdown (D6, D8, D9; dispatch C4)

**Files:**
- Create: `httpsec/signals_bus.go` (the port's default and the envelope), `httpsec/signals_registry.go`.
- Modify: `httpsec/signals_stream.go` (the wake and queue inputs).
- Tests: `httpsec/signals_bus_test.go`, `httpsec/signals_registry_test.go`.
- Mock: `SignalBus`, through a `//go:generate` directive per `use-mockgen`.

**Interfaces produced:**
```go
type SignalBus interface {
    Publish(ctx context.Context, e SignalEnvelope) error
    Subscribe(ctx context.Context, deliver func(SignalEnvelope)) error
}
type SignalEnvelope struct { User identity.UserID; Family, Kept id.ID; Upstream string /* SHA-256 of issuer, a separator and upstream session */; Name, Reason string; Data json.RawMessage }
func (c *Chain) CloseSessionSignals(ctx context.Context) error
type SessionSignalStats struct { Open int; RefusedByCap, ReloadFailures, ConsecutiveReloadFailures, BusDropped, BusPublishFailures, StreamDropped uint64; BusSubscribed bool }
func (c *Chain) SessionSignalStats() SessionSignalStats
```

- [ ] **6.1–6.5 Red:**
  - `TestSessionSignals_Bus`: routing by user, by family, and by user minus `Kept`. With two families of one user, ending one leaves the other's stream open.
  - `TestSessionSignals_BusWakeUp`: a wake-up whose session exists is not forwarded, and the heartbeat ends it later; three wake-ups cause one reload.
  - `TestSessionSignals_BusUntrusted`: an unknown library name, malformed data, a 9 KiB payload, and `app.X` arriving from the bus are all dropped.
  - `TestSessionSignals_BusOutage`: every row in `tasks.md` 6.3, including a `Publish` that hangs while a logout completes; `Subscribe` fails twice and then succeeds, retried at 1 s and 2 s; the default bus does not cross a second chain instance.
  - `TestSessionSignals_Caps`, including a cross-site refusal leaving the count unchanged, and a barrier test where two goroutines request the fourth place at once and exactly one opens, and the other gets 200 with only `retry`. Tell the two apart by the first event, since both are 200.
  - `TestSessionSignals_SlowStream`: a stream that never reads loses its 33rd event, another stream gets all 33, `PublishSignal` returns within 10 ms, and ending the slow stream's sign-in still delivers `session_ended`.
- [ ] **6.6 Red:** `TestSessionSignals_Close`:
  - streams close with no event;
  - a new request gets 200 with a body of only one `retry:` line, the response ends, and the registry count stays 0;
  - a closing stream's last bytes are a fresh `retry`, with no `event:`;
  - a second `CloseSessionSignals` ends nothing new, and waits on its own context;
  - `srv.Shutdown` with a 2 s context returns nil when `CloseSessionSignals` is registered with `RegisterOnShutdown`.

  Then update the README shutdown snippet.
- [ ] Verify each task's command with `-race`. Commit.

### Tasks 7.1–7.4: Signal sources (D5; dispatch C5)

**Files:**
- Modify: `httpsec/password_change.go`, `httpsec/recovery.go`, `httpsec/passkey_register.go`, `httpsec/passkey_manage.go`, `httpsec/mfa_enrol.go`. `httpsec` has no MFA removal endpoint (design D5).
- Modify: `recovery/recover_complete.go` (`Result.Removed`), `authenticate/passkey/recovery_kind.go` (`RecoveryKindName`).
- Create: `httpsec/signals_publish.go`.
- Tests: `httpsec/signals_sources_test.go`.

**Interfaces produced:**
```go
type CredentialKind string // CredentialPassword "password", CredentialPasskey "passkey", CredentialSecondFactor "second_factor"
func (c *Chain) ReportCredentialChange(ctx context.Context, user identity.UserID, kind CredentialKind) error
func (c *Chain) PublishSignal(ctx context.Context, user identity.UserID, name string, data json.RawMessage) error
// recovery
type Result struct { /* existing fields */; Removed []AuthenticatorRef } // what a completed recovery removed; empty for a hold
// authenticate/passkey
const RecoveryKindName = "passkey"
```

- [ ] **7.1–7.4 Red:**
  - `TestSessionSignals_CredentialChanged`: one row per endpoint and path, asserting `{"kind":…}` only, and no event on a refused request: passkey registration through finish and through confirm, and MFA enrolment through confirm and email redemption;
  - `TestSessionSignals_CredentialChanged_Recovery`: under `WithoutSessionRevocation`, a recovery removing a second factor and a passkey raises each kind once; by default the streams send `session_ended` and no `credential_changed`; nothing removed, only a consumer's kind, a hold and a refusal raise nothing;
  - `TestSessionSignals_CredentialChanged_EndedStream`: passkey removal ending another sign-in gives that stream `session`, `session_ended`; and `TestSessionSignals_BusWakeUp_QueueHold` for the hold's rows (D4);
  - `TestRecoverer_Complete`: `Result.Removed` holds what went, leaving out a proven method, under the default and a custom `ResetPolicy`;
  - `TestSessionSignals_ReportCredentialChange`;
  - `TestSessionSignals_Publish`: every row in `tasks.md` 7.3, including `app.x\nevent: session_ended` and `json.MarshalIndent` output, both refused with `ErrInvalidSignal`;
  - `TestSessionSignals_NoAuditFeed`: every row asserts that the stream, read for two heartbeats, holds only comments.

  **Green:** each endpoint calls the internal raise after its write succeeds, never on a refusal. A recovery's one call follows its `RecoveryCompleted` event, and maps `recovery.MFAKind` to `second_factor` and `passkey.RecoveryKindName` to `passkey`. A stream holding an end notice sends nothing queued until a read begun after it answers (D4).
- [ ] Update the README with the signal list and the consumer's API. Verify each task's command. Commit.

### Tasks 8.1–8.3: Integration (dispatch D, then the main session)

- [ ] **8.1:** `test/httpsecconformance/signals_scenarios.go`, with scenarios named `signals: …` covering everything listed in `tasks.md` 8.1, on all three adapters.
- [ ] **8.2:** Run every module's suite one at a time with `-race`, then `govulncheck ./...`, `gofmt -l .` and `go vet ./...` per module. All output must be clean.
- [ ] **8.3:** An Opus reviewer checks the branch against every requirement in the five spec deltas, every decision D1–D10, and each row of the security review table. Each finding is REPRODUCED with a failing test or labelled UNREPRODUCED (`.claude/rules/defect-claims.md`). Findings go back to a fresh dispatch.

### Tasks 9.1–9.11: Findings from reviewing the pull request (design R1–R12)

Each dispatch brought in the disposable test that proved its finding, under a behaviour name, and saw it fail on the tree before fixing (the design's "Where the proofs landed" names them).

**Dispatches.** Writers in one package each get a worktree. 9.7 changes a signature every test compiles against, so it lands before anything else in `httpsec`.

| Wave | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | E1 | 9.7 | `httpsec/exchange.go`, `nethttp.go`, `signals_endpoint.go`, `signals_retry.go`, `httpsec/ginsec`, `httpsec/fibersec`, `test/httpsecconformance`, every `ResponseWriter` double | Opus: an interface other lanes compile against, on three adapters |
| 1 (parallel) | E2 | 9.6 | `session/`, `store/{sqlstore,pgxstore,gormstore}`, `internal/pgschema`, `test/storetest` | Opus: several packages, and a read whose mistake would pass the tests and still be wrong |
| 2 (parallel) | E3 | 9.1, 9.2, 9.3, 9.5 | `signals_retry.go`, `signals_endpoint.go`, `signals_publish.go`, `signals.go`, `signals_close.go`, `resolve.go`, `session/sessions.go` godoc, their tests | Opus: which refusals are final is security-critical |
| 2 (parallel) | E4 | 9.4 | `signals_stream.go`, the notice's type in `signals.go`, `signals_bus.go`'s `deliverEnd`, their tests | Opus: ordering in the stream's loop |
| 3 | E5 | 9.8, 9.9 | `signals.go`'s lookup, `signals_bus.go`, `signals_endpoint.go`'s and `signals_retry.go`'s headers, `nethttp.go`, `fibersec/exchange.go`, `internal/diag`, `README.md` | Opus: a refactor that must keep behaviour |
| 4 | main, one reviewer | 9.11, then 9.10 | — | Opus reviewer. The review runs before the gate, as `subagent-delegation.md` requires |

Each dispatch gets a fresh reviewer that edits nothing, on Opus. Findings go to a fresh dispatch of that lane. **Run `make lint` in every dispatch's verification:** it stops at the first failing module, so run `golangci-lint run ./...` in each module a dispatch changed.

**Interfaces produced:**
```go
// httpsec
Stream(ctx context.Context, contentType string, body func(ctx context.Context, w EventWriter) error) error // on ResponseWriter
type SessionSignalStats struct { /* existing */; Throttled uint64 }
// session
type FamilyReader interface {
    ListByFamily(ctx context.Context, user identity.UserID, family id.ID, now time.Time) ([]*Session, error)
}
// internal/diag: the frame walk, 32 frames, empty functions skipped, "; " between frames; and endedWriter
```

**Decisions the implementer cannot make alone:**
- 9.1: only `ratelimit.ErrThrottled`, and only from the chain's per-request policy evaluation of the published sign-in (corrected by review: `ex.Session` alone reopened the oracle; design R1). 429 stays final, and two existing rows pin that. It answers at `BusyDelay` ±30%, counts `Throttled`, and never `ReloadFailures`. `RetryableError` is asked about it.
- 9.2: cut at `crossSiteOriginLogLimit` before the clone, in `newStreamStart`.
- 9.3: the guard goes in `raiseCredentialChange`, so every raise passes it. A later row must still show a set holding the signal publishes.
- 9.4: mark a notice `broad` in `deliverEnd`'s user branch. Clear only a broad one, when a read begun after it answers alive. Clearing every notice breaks the pinned row `a kept reason within its window names the end`. A broad notice does not replace a family-naming one within its window, and every report with a known reason holds the queue, kept or refused (design R5).
- 9.5: `EndDeleted` → `ended` in `endReason`. Change `Construction_EndReports` and `Heartbeat_Ends`' rows to `ended`, and leave `TestLogout_ReportsLogoutCause` as it is.
- 9.6: `ListByFamily` has `ListByUser`'s contract narrowed to one family: live, not superseded, no sealed field opened. The manager keeps its own filtering over either. The sealing decorator asserts the optional interface on what it wraps, and falls back to listing. No migration.
- 9.7: fiber holds the type and sets it in `chainReturned` when not refused, replacing its delete. `Cache-Control` and `X-Accel-Buffering` still go before `Stream`. A consumer's refusal over a begun response keeps its own headers.
- 9.8: `signalsEndpoint` guards `c.perRequest == nil`, so a zero-value `Chain` answers `ErrSessionSignalsDisabled`. The fiber backstop's record changes to the agreed frames, and each line keeps its message and keys.
- `ErrUnavailable` does not change (R2).

**Review Focus for this group:**
1. A concealed lock on the stream's path, under Basic. Expected: 401, the same as any wrong password, never the throttle's retry. Task 9.1.
2. A consumer's own 429 on the stream's path. Expected: that 429. Task 9.1.
3. A chain's own logout after 9.5. Expected: other tabs still hear `logout`. Task 9.5.
4. A store whose `ListByFamily` and `ListByUser` disagree. Expected: conformance rows fail on any backend where they do. Task 9.6.
5. A stream refused on fiber after `Stream`, with a consumer's error handler setting a type. Expected: the handler's type. Task 9.7.

- [ ] **9.1–9.9:** per the table above, each test-first, verifying with each task's command in `tasks.md`, with `-v`, and `golangci-lint run ./...` in every module changed.
- [ ] **9.11:** an Opus reviewer checks group 9 against R1–R12 and the scenarios they added, rerunning the real-library and README harnesses, since 9.7 changes what they drive.
- [ ] **9.10:** on the tree rebased onto `main`, `make lint fmt-check vet generate-check pincheck tools-check`, every module's suite with `-race` at `-parallel 4`, `govulncheck`, `go mod tidy -diff`, 16 copies of the signal conformance rows for 3 rounds, and CI green on the pull request.
