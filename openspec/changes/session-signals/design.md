# Design

## Context

See `proposal.md` for why, and the four spec deltas for the required behaviour. This design was checked against `main` at `4649c90` on 2026-11-03, after `close-security-gaps` was merged (#45) and archived (#66). What shapes the approach:

- **The chain is an around-interceptor chain behind an adapter.**
  - `httpsec.ResponseWriter` has `SetHeader`, `AddHeader`, `SetCookie`, `WriteHeader` and `Write`, and nothing streams.
  - On net/http and gin, an interceptor can block for as long as it likes, and the request context ends when the client leaves.
- **Fiber writes a streamed body after the handlers return.** Read from fiber v3.5.0 and fasthttp v1.73.0 on 2026-11-02, the versions `httpsec/fibersec` still pins on `main`:
  - `Ctx.SendStreamWriter(func(*bufio.Writer))` is the only streaming path, and it runs once the handler chain has returned;
  - fasthttp's `RequestCtx.Done()` closes only at server shutdown, so a client that leaves is seen only when a write or flush fails;
  - fasthttp sets one write deadline for the whole response before writing it (`server.go`, around line 2640). A per-request override exists only as a positive value, through the `HeaderReceived` hook the server owner sets.

  So a `Flush()` called inside the chain cannot work on fiber: whatever the handler writes is sent only when it returns. Dependabot proposes fiber v3.6.1 and fasthttp v1.77.0 (#52, #54). Task 1.2 re-establishes these facts on whatever versions are pinned when it runs.
- **Sessions are ended in `session.Sessions`.** The calls that end them, and the store calls behind them:

  | Call | What it ends | Names |
  |---|---|---|
  | `Delete(id)` | one session (logout) | the session only |
  | `EndSignIn(user, handle)` | one sign-in of the user | user, and the sign-in's family |
  | `EndOtherSignIns(user, current)` | every sign-in but the current one | user, and the kept family |
  | `DeleteByUser(user)` | every session of the user | user |
  | `DeleteByUserExcept(user, keep)` | every session of the user but one | user, and the kept *session* |
  | `RevokeFamily(family)`, and reuse detection through `Store.DeleteFamily` | one family | the family (reuse also knows the user) |
  | `DeleteByUserAndExternalIssuer(user, issuer)` | the user's sessions from one provider | user |
  | `DeleteByExternalSession(issuer, sid)` | sessions from a provider's back-channel logout | neither user nor family |
  | `DeleteExpired()` | swept expired sessions | nothing |

  It already has one post-commit observer, `WithReuseObserver`, called after the family is revoked, and a security-event sink (`WithSecurityEvents`). This change follows the observer's pattern, and deliberately not the sink's (D5).
- **Activity is recorded after the handler, by one interceptor.** `sessionTouch` sits in `OrderSessionTouch` (800). It calls `next` and then `Sessions.Touch`. No authenticator records activity itself. A terminal endpoint in an earlier slot therefore never reaches it.
- **Recency is a guard's, not the chain's.** `Guards.RequireRecentAuthentication` uses `DefaultRecentAuthenticationWindow` (15 minutes) unless `WithRecentAuthenticationWindow` or a per-route `RequireAuthenticationWithin` says otherwise. `EnableReauthentication` adds the re-proof endpoints but holds no window. `Session.AuthenticatedAt` is what both read.
- **Already on `main` from `close-security-gaps`:** session management (`EndSignIn`, `EndOtherSignIns`, `OrderSessionManagement`), re-authentication, `CookieAuthenticator` with its CSRF binding, the security-event emission points (its D13), and the internal-set pattern (`bindingVerifiers`, its D8).

### How the pieces fit

```
 browser / app                     one replica                                  shared
 ─────────────                     ───────────                                  ──────
 EventSource (cookie)  ─┐   adapter (net/http | gin | fiber)
 fetch() + Authorization┘        │
                                 ▼
                 ┌──────────────── httpsec chain ────────────────┐
                 │ 25 headers · 50 CORS · 75 CSRF · proxies ·    │
                 │ rate limits                                   │
                 │ 100–500 authentication (bearer, session ref,  │
                 │          consumer CookieAuthenticator)        │
                 │ 598–655 pending-session gates, re-auth        │
                 │ 673 OrderSessionSignals ──► stream endpoint ──┼──► Stream(body)
                 │ 674 session management                        │        │
                 │ 800 session touch   (never reached by stream) │        │
                 │ 900 authorizer      (never reached by stream) │        │
                 └───────────────────────────────────────────────┘        │
                                                                          ▼
   session.Sessions ──EndReport──► signal hub ◄──── registry ◄──── stream goroutine
   (Delete, EndSignIn, …)            │  ▲          user → streams        │  ▲
   chain endpoints ──credential──►   │  │          family → streams      │  │ reload each
   chain.PublishSignal ──app.*──►    │  │                               │  │ heartbeat
                                     ▼  │                               ▼  │
                                  SignalBus ◄──────────────────────► session store
                              (in-process default,                  (the only truth)
                               or the consumer's shared bus)
```

## Goals / Non-Goals

**Goals:**
- One stream implementation in `httpsec`, run identically by three very different adapters.
- The session store as the only source of truth. A signal can wake a stream early, but it never ends one by itself.
- Bounded cost per stream: one goroutine, one ticker, one timer and one store read per heartbeat.

**Non-Goals:**
- Delivery guarantees beyond "within one heartbeat": no acknowledgements, no ordering across signals, no replay.
- Redis and PostgreSQL bus implementations (follow-ups).
- A browser client library. The README shows `EventSource` for cookie sessions and a `fetch()` reader for bearer clients.
- Metrics. Streams log at DEBUG when they open and close, and bus failures log with sampling. A consumer who wants counts wraps the bus.

## Decisions

### D1. The adapters gain `Stream`, not `Flush`

```go
type ResponseWriter interface {
    SetHeader(name, value string)
    AddHeader(name, value string)
    SetCookie(c *Cookie)
    WriteHeader(status int)
    Write(b []byte) (int, error)
    // Stream sends the status and headers set so far, then runs body until it returns.
    // Each EventWriter.Flush reaches the client before body continues.
    Stream(ctx context.Context, body func(ctx context.Context, w EventWriter) error) error
}

type EventWriter interface {
    io.Writer
    Flush() error // also pushes the connection's write deadline forward
}
```

- **net/http and gin:**
  - `Stream` runs `body` inline, so `Stream` returns when the stream ends;
  - `Flush` uses `http.ResponseController.Flush`, and before each write calls `SetWriteDeadline(now + 2 × heartbeat)`;
  - the client leaving ends `body`'s context.
- **fiber:**
  - `Stream` registers `body` with `SendStreamWriter` and returns at once;
  - `body` runs after the chain has unwound, on a context detached from the chain's end-of-request cancellation, and cancelled when fasthttp's `Done()` fires at shutdown or when a flush fails;
  - each `Flush` sets the connection's write deadline to `now + 2 × heartbeat` through `RequestCtx.Conn()`, so the deadline fasthttp set once for the whole response does not cut the stream. *Unverified:* this rests on a later `SetWriteDeadline` on the `net.Conn` replacing the one fasthttp set. Task 1.2's first test establishes it on fiber before anything else is built.

```
 net/http, gin                                   fiber
 ─────────────                                   ─────
 chain ─► endpoint ─► Stream(body) ┐             chain ─► endpoint ─► Stream(body)
                      headers sent │                                  registers body,
                      body runs    │ blocks                           returns nil
                      flush, flush │ until       chain unwinds ◄──────┘
                      ...          │ body        (no slot ≥ 800 was on the stack)
                      body returns ┘ returns     fasthttp sends status + headers
 Stream returns ◄─────────────────               body runs on a detached context:
 chain unwinds                                     flush (deadline pushed), flush ...
                                                   ends on: body return, failed flush,
                                                            Done() at shutdown
```

- **The headers are frozen when `Stream` is called.** Every adapter sends the status and the headers set so far, and later `SetHeader` calls have no effect. On fiber, everything the chain set before returning is sent, because fasthttp writes the header block when it starts the body.
- **`Stream` once, before anything else is written.** `Stream` called after `WriteHeader` or `Write`, or a second time, returns `ErrStreamingStarted` and writes nothing. The endpoint never does this; the rule exists so a consumer adapter's contract is complete.
- **Why not `Flush()` on `ResponseWriter`**, as the proposal first said: on fiber, it cannot deliver anything before the handler returns. A body function is the shape all three adapters can honour.
- **Breaking, before the tag:** a consumer's own `ResponseWriter` must implement `Stream`. A consumer adapter that cannot stream may return `ErrStreamingUnsupported`. The endpoint then answers 501, and the godoc says so.
- **Override:** none. This is the adapter contract.
- *Alternative considered:* an optional `Streamer` interface beside `ResponseWriter`. Rejected for the same reason `close-security-gaps` made `HeaderValues` required: a missing implementation would be discovered only as a broken stream at runtime, not as a compile error in the consumer's adapter.

### D2. The endpoint and its configuration

```go
signals := httpsec.SessionSignals{
    Path:            "/session/signals",                                          // default
    Signals:         []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring}, // default
    Heartbeat:       15 * time.Second,  // default; 5–60 s
    ExpiryWarning:   2 * time.Minute,   // default; > 0 and < the idle timeout
    AssuranceWindow: httpsec.DefaultRecentAuthenticationWindow, // default 15 min; used by assurance_lapsed
    MaxPerSignIn:    4,                 // default
    MaxPerUser:      16,                // default
    MaxStreams:      10_000,            // default, per replica
    Bus:             nil,               // default: in-process
}
chain, err := httpsec.New(..., httpsec.EnableSessionSignals(signals))
err = chain.PublishSignal(ctx, userID, "app.roles_changed", json.RawMessage(`{"roles":["editor"]}`))
err = chain.ReportCredentialChange(ctx, userID, httpsec.CredentialPassword)
err = chain.CloseSessionSignals(ctx)
```

- **Slot:** a terminal endpoint in a new slot, `OrderSessionSignals = OrderSessionManagement - 1` (673). Everything below it applies as on any protected route: headers, proxies, CORS, CSRF, rate limits, authentication, and the pending-session and re-authentication gates. Session touch (800) and the chain's authorizer (900) are above it and never run for the stream, as for the session-management endpoints beside it.
- **Construction rules** (`library-design` rule 6):
  - a signal name outside the four;
  - a heartbeat outside 5–60 seconds;
  - a warning window of zero or less, or not shorter than the session manager's idle timeout;
  - an assurance window of zero or less;
  - a cap below 1, or `MaxPerSignIn` above `MaxPerUser`, or `MaxPerUser` above `MaxStreams`;
  - `assurance_lapsed` without `EnableReauthentication`, because the front end would be told to re-prove with no way to do it;
  - a `Path` that another enabled endpoint already serves;
  - `EnableSessionSignals` given twice.
- **`AssuranceWindow`** (user's choice, 2026-11-03). The chain has no re-authentication window of its own: each recency guard has one. The field defaults to `DefaultRecentAuthenticationWindow`, the guards' default, and its godoc says to set it to the window of the guards the front end must satisfy. The two cannot be checked against each other, because `Guards` are constructed apart from the chain.
- **The query string:** `?signals=` is split on commas, at most 16 names and 256 bytes in all, and more than that is refused with 400. A name that is not in the chain's set is dropped. `app.` names are matched the same way, so a client can narrow to its own signals too.
- **Consumer signal names are a fixed shape** (security review, 2026-11-03). A name must match `^app\.[a-z0-9][a-z0-9._-]{0,62}$`. An event name goes onto the wire as an `event:` line, and a CR or LF in it would start a new field or event: the SSE injection that GHSA-22cc-p3c6-wpvm and CVE-2026-44214 describe in other libraries. The shape also excludes `:` and NUL. A client's `?signals=` entries are held to the same shape before they are compared, and a malformed entry is dropped like an unknown one.
- **`PublishSignal`:**
  - it returns `ErrSessionSignalsDisabled` when the stream is not enabled, `ErrInvalidSignal` for a name outside that shape, or data over 8 KiB or not valid JSON, and the bus's error otherwise;
  - a user with no open stream is not an error: the signal reaches no one;
  - it never blocks on a slow stream (D9).
- **`ReportCredentialChange`:** returns `ErrSessionSignalsDisabled` when disabled, and `ErrInvalidSignal` for a kind outside `password`, `passkey` and `second_factor`.
- **Override:** every field, and the bus.

### D3. Who may open a stream

- The resolved `Authentication` must carry a session: a session reference, a signed bearer tied to a stored session, or a consumer's `CookieAuthenticator` session. Otherwise the answer is 401 (nothing authenticated) or 403 (Basic, an API key, or a token with no session).
- A sign-in still owing a second factor, enrolment or recovery is refused by the pending-session gates below the stream's slot, exactly as they refuse every other protected route.
- The authenticating interceptors never read a credential from the query string, so that spec rule holds already. A test pins it.
- **CSRF:** a `CookieAuthenticator` calls `CheckCSRFToken`, which checks only unsafe methods. The stream is a `GET` and changes nothing, so it passes without a token. A test pins that, so a later tightening of CSRF cannot break `EventSource`, which cannot send a token header.
- **Cross-site requests are refused by the stream itself** (security review, 2026-11-03). CORS in scrty decides only which response headers an origin gets. For a disallowed origin it leaves them out, and the request still runs. A page on another site could therefore open credentialed streams that its browser cannot read, each taking one of the victim's per-sign-in places. That is UNREPRODUCED, since there is no code yet, and the first test of task 4.6 writes it. The stream therefore applies, to its `GET`, the origin rule the CSRF layer applies to unsafe methods (`csrf-protection`), whether or not CSRF protection is enabled:
  - `Sec-Fetch-Site` of `same-origin` or `none` passes;
  - `same-site`, `cross-site` or any other value passes only when its `Origin` is one CORS allows with credentials;
  - with no `Sec-Fetch-Site`, a cross-origin `Origin` passes only when CORS allows it, and no `Origin` at all passes, since old browsers and non-browser clients send neither;
  - `Origin: null` never passes;
  - a refusal is 403, before the stream is registered, so it costs no place.

  This is the resource isolation policy that web.dev's Fetch Metadata guidance describes, and OWASP's advice for WebSocket handshakes to validate `Origin` every time. **Override:** the CORS allowlist, which already names the origins a consumer trusts. There is no switch to turn the check off, because a stream that a foreign page can hold open is the denial of service it exists to prevent.
- **Activity, corrected 2026-11-03.** The draft relied on an internal set that the built-in authenticators consult before recording activity. On `main`, authenticators never record activity: only `sessionTouch` does, after the handler, at slot 800. A terminal endpoint at 673 is never inside it, so the built-in paths need no set. A consumer interceptor below 673 that records activity on its own asks `httpsec.RecordsSessionActivity(ex)`, which reports false for the stream's path. The godoc on `CookieAuthenticator` and on `OrderSessionTouch` says so.
- **Default and override:** the admission rules have no override, since a stream for no sign-in has nothing to report. The path is the consumer's (D2).

### D4. The store is the truth; signals are wake-ups

- Each stream holds `{user, family, handle, idle deadline, absolute deadline, authenticatedAt}` from its first load.
- **At every heartbeat** it reloads its session by identifier, through the read the bearer uses, without recording a presentation. The outcome decides the next step:

  | Reload finds | The stream sends | Then |
  |---|---|---|
  | the session, unchanged | `:` comment | keeps going |
  | a deadline or `authenticatedAt` moved | `session` | re-arms its timer |
  | gone after a logout | `session_ended` `logout` | closes |
  | gone after an ended sign-in, or the user no longer active | `session_ended` `ended` | closes |
  | gone, its family revoked on reuse | `session_ended` `reuse` | closes |
  | gone after a user-wide end | `session_ended` `all_ended` | closes |
  | gone after a provider logout | `session_ended` `provider_logout` | closes |
  | gone with no known reason, or past a deadline | `session_ended` `expired` | closes |
  | a store failure, not "not found" | `:` comment | keeps going, logs with sampling, reloads next heartbeat |

  The reason comes from the latest end report the stream was woken with, through D5's mapping. A stream that learns of the end only from its heartbeat, with no report (another replica, no shared bus), sends `ended`, or `expired` when a deadline has passed.
- **A store outage keeps the stream open** (user's choice, 2026-11-03). The store has not said the sign-in ended, and the stream grants no access, so closing would only make every client reconnect at once when the store returns. The stream's own timer still ends it at its absolute deadline.
- **A `session_ended` arriving from the bus triggers the same reload at once.** It is forwarded only if the store agrees, which removes three problems:
  - a spurious end, when a consumer's outer transaction rolls back after `Sessions.Delete` returned;
  - a forged or replayed bus message;
  - races between replicas.

  If the store still shows the session, the heartbeat catches the end later.
- **Timers:** `session_expiring`, expiry and `assurance_lapsed` come from the held deadlines and `authenticatedAt` through a single timer per stream, armed for the earliest of the three and re-armed after each reload.
- **Heartbeat jitter:** ±10% of the interval, so streams opened together do not reload together.
- **Override:** the heartbeat interval. The rule that the store decides has none, because trusting a message to end a session is exactly what this decision rejects.

```
            admit (D3) ──refused──► 400 / 401 / 403 / 405 / 429 / 501, no stream
                │       └─closing (D8)─► 200, `retry` only, connection closed
                │
                ▼
          register in registry (caps, D8) ──► send retry: 5000, then `session`
                │
                ▼
     ┌─────► wait ◄───────────────────────────────────────────────┐
     │        │                                                   │
     │        ├─ heartbeat tick ──► reload ──┬─ unchanged ─► ":" ─┤
     │        │                              ├─ moved ─► `session`, re-arm timer ─┤
     │        │                              ├─ store error ─► ":", log ──────────┤
     │        │                              └─ gone ─► `session_ended` ─┐
     │        ├─ bus wake (session_ended) ──► reload (same branches) ──┤
     │        ├─ timer ──┬─ warning window ─► `session_expiring` ──────┼──┘
     │        │          ├─ lapse ─► `assurance_lapsed` ───────────────┼──┘
     │        │          └─ deadline ─► `session_ended` expired ─┐     │
     │        ├─ queue (credential_changed, app.*) ─► event ─────┼─────┘
     │        ├─ client left / flush failed ───────────────────┐ │
     │        └─ CloseSessionSignals ──────────────────────────┤ │
     │                                                         ▼ ▼
     └──────────────────────────────────────────────  unregister, free cap, return
```

### D5. Where signals come from

- **Ended sign-ins:**
  - **One option, shared with `oidc-provider`** (revised 2026-11-04, that change's R16). Both changes defined `session.WithEndObserver` differently, and neither is built. Whichever lands first adds the option, and the other adds to it.
  - `session.EndObserver` is an interface with one method, `SignInsEnded(ctx, session.EndReport)`, with an `EndObserverFunc` adapter so a closure still fits. `session.WithEndObserver` is repeatable.
  - `EndReport{Cause EndCause, User identity.UserID, Family id.ID, KeptFamily id.ID, ExternalIssuer, ExternalSessionID string, At time.Time}` is reported after each successful end. It carries no session identifier.
  - The causes, the calls that raise them, and the `session_ended` reason this change sends for each. `session` knows only the cause. The wire reason is this change's, and the hub maps it:

    | Cause | Raised by | Report names | Wire reason |
    |---|---|---|---|
    | `EndDeleted` | `Delete(id)` | user and family, from a load before the delete, made only when an observer is set | `logout` |
    | `EndByHandle` | `EndSignIn` | user and family | `ended` |
    | `EndReuse` | reuse detection, after `Store.DeleteFamily` | user and family | `reuse` |
    | `EndFamilyRevoked` | `RevokeFamily(family)` | family only | `reuse` |
    | `EndUserSessions` | `DeleteByUser` | user, no family | `all_ended` |
    | `EndUserSessionsExcept` | `DeleteByUserExcept` | user, no family, the spared family as `KeptFamily` | `all_ended` |
    | `EndOtherSignIns` | `EndOtherSignIns` | user, no family, the spared family as `KeptFamily` | `all_ended` |
    | `EndUserExternalIssuer` | `DeleteByUserAndExternalIssuer` | user, issuer, no family | `provider_logout` |
    | `EndExternalSession` | `DeleteByExternalSession` | issuer and upstream session, neither user nor family | none: the hub drops it, and the heartbeat ends those streams |
    | (not reported) | `DeleteExpired`, a deadline passing | a deadline is not an event | |

  - **A bulk end is one report** (settled while planning, 2026-11-02). Listing the sign-ins first would cost a read per bulk delete and race the delete. The stream reloads anyway (D4), so a report that names only the user is enough to wake every stream of that user.
  - **`KeptFamily` for `DeleteByUserExcept`** (corrected 2026-11-03). That call keeps a *session*, not a family, and a report carries no session identifier. When an observer is set, the manager loads the kept session first and reports its family. `EndOtherSignIns` already holds the current session, and reads its family without a load.
  - **The observer's context** keeps the caller's values but not its cancellation, as the reuse observer's does, so a client that hangs up cannot drop the report.
  - Panics are recovered and logged without the report's contents, the next observer still runs, and an observer has no error to return, as with `WithReuseObserver`. Observers run synchronously, in the order given, so the hub's never blocks.
  - `EnableSessionSignals` adds the hub's observer to the session manager the chain uses, beside any the consumer gave. It no longer refuses a manager with an observer, and `session.EndObservers` is gone, since the option is repeatable.
  - **How it is added** (found while aligning, 2026-11-04). The plan said "install", and no exported call could do that to a built manager from `httpsec`. `(*Sessions).AddEndObserver(EndObserver) error` does, refusing a nil observer with `ErrConfig`. It is for wiring at chain construction, and copies the list on write, so a report running meanwhile is not a data race. *Rejected:* asking the consumer to pass the hub through `WithEndObserver`, which breaks this change's no-wiring default, because the hub does not exist until the chain is built.
- **`credential_changed`:**
  - raised by the chain's own endpoints, after their write succeeds: password-change resolve (`password`), recovery finish (`password` or `second_factor`, as the recovery replaced), passkey registration and removal (`passkey`), and MFA enrolment confirmation and removal (`second_factor`);
  - for changes the consumer makes outside those endpoints (an admin console, a password reset of its own), `chain.ReportCredentialChange(ctx, userID, kind)` raises the same library signal;
  - it is the one library signal a consumer may raise, because the change happened in the consumer's code.
- **The consumer's own signals:** `chain.PublishSignal`.
- **`session_expiring` and `assurance_lapsed`:** the stream's own timer (D4).
- *Alternative considered:* deriving signals from the security-event sink (`WithSecurityEvents`, `close-security-gaps` D13), which already emits `session_logout` and similar. Rejected: that sink is the operator's feed and covers every user. A filter between it and browsers is the coupling the proposal rules out, since an event added to it later would reach browsers by default. And `EndSignIn` and the bulk deletes raise no event there.

```
 session.Sessions ── EndReport ──┐
   (D5 table)                    │
 chain endpoints ── credential ──┼──► hub.raise(envelope) ──► SignalBus.Publish ──┐
 chain.ReportCredentialChange ───┤      never blocks; a failing                   │
 chain.PublishSignal (app.*) ────┘      Publish is logged, not returned           │
                                        to the request that raised it             │
                                                                                  ▼
            one Subscribe per replica ◄──────────────────────────────── other replicas
                     │
                     ▼
     registry: user → streams, family → streams
                     │
       ├─ session_ended ─► wake streams of that family (or of the user, when no family)
       │                    → each reloads; forwards only if the store agrees (D4)
       └─ other signals ─► enqueue on each stream of the user that wants that name
```

### D6. The bus

```go
type SignalBus interface {
    Publish(ctx context.Context, e SignalEnvelope) error
    Subscribe(ctx context.Context, deliver func(SignalEnvelope)) error // once per chain; blocks until ctx ends
}
type SignalEnvelope struct {
    User   identity.UserID // empty only for a family-only end report
    Family id.ID           // the zero ID for user-wide signals
    Kept   id.ID           // for an all_ended report that spared a family (the report's KeptFamily)
    Name   string
    Reason string          // session_ended only
    Data   json.RawMessage
}
```

- **One subscription per replica,** not per stream. The chain keeps a local registry `user → streams` and `family → streams`, and hands each envelope to the streams it names (D5's diagram).
  - This lets a Redis or PostgreSQL bus use one channel, not one per user.
- **The default bus** delivers only within the process. With several replicas and no shared bus, `session_ended` still arrives within a heartbeat. `credential_changed` and the consumer's signals reach only the streams on the replica that raised them. The godoc says so, as the rate limiter documents its N-replica limit.
- **A failing `Publish`** is logged with sampling and never changes the outcome of the request that raised it. A failing `Subscribe` is retried with backoff, from 1 second doubling to 30 seconds, while the heartbeat keeps ending streams.
- **An envelope from the bus is untrusted.** A `session_ended` only triggers a reload (D4). Any other library signal from the bus is delivered only when its name is one of the four, its data parses, and it is no more than 8 KiB. `app.` envelopes are held to the `PublishSignal` limits again on receipt.
- **Override:** the port.

### D7. The wire format

- The first bytes are `retry: 5000` and then the `session` event.
- Each event is `event: <name>\ndata: <json>\n\n`, with no `id:`. A heartbeat is `:\n\n`.
- The data:
  - `session`: `{"idle_deadline", "absolute_deadline", "authenticated_at"}` in RFC 3339, UTC;
  - `session_ended`: `{"reason"}`;
  - `session_expiring`: `{"deadline":"idle"|"absolute","at"}`;
  - `assurance_lapsed`: `{"authenticated_at"}`;
  - `credential_changed`: `{"kind":"password"|"passkey"|"second_factor"}`;
  - `app.*`: the consumer's JSON, unchanged, on one `data:` line. JSON already escapes its newlines, and `PublishSignal` requires valid JSON.
- **No raw CR or LF reaches the wire inside a field.** The event writer refuses, and does not send, an event whose name or data line holds one. That is a second check behind D2's name shape and the JSON rule, so a later change cannot reopen the injection.
- Headers: `Content-Type: text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`. `no-store` keeps the stream out of every cache (RFC 9111 §5.2.2.5). `X-Accel-Buffering` works only where the operator's proxy honours it, and the README says so.
- **Reconnection follows WHATWG's rules.** Any response other than 200 with `text/event-stream` fails an `EventSource` for good, and a dropped connection makes it reconnect after `retry`. So every answer is chosen for what the browser does next:

  | Answer | The browser then | Used for |
  |---|---|---|
  | 200, stream, then the connection closes | reconnects after `retry` | shutdown (D8), a client-side drop |
  | 200, `session_ended`, then close | reconnects, and gets 401 | an ended sign-in |
  | 401, 403, 400, 405, 429, 501 | stops for good | refusals that a retry would not change |

  A client that wants to retry after 429 (a tab freed elsewhere) or after a 5xx at admission builds a new `EventSource` itself, and the README shows that with backoff.
- After `session_ended` the stream closes. The browser's reconnection then gets 401, which ends `EventSource`'s retries.
- **Override:** none for the format. It is the contract front ends code against.

### D8. Caps and shutdown

- The caps are kept in the local registry and counted per replica. With N replicas, a user can hold N × `MaxPerUser` streams, which the godoc states.
- A request over a cap gets 429, `ErrTooManyStreams`, and is charged to nothing. A stream frees its place when its body returns, whatever ended it.
- **Override:** the three fields.
- **Shutdown** (settled while planning, 2026-11-02). `http.Server.Shutdown` waits for active handlers and does not cancel their contexts, so an open stream would hold it until its deadline. `chain.CloseSessionSignals(ctx)` ends every stream without an event, and returns when every body has returned or `ctx` ends. A stream requested afterwards gets 200 with only the `retry` line, and its connection is closed at once. *Changed from 503 by the security review, 2026-11-03:* WHATWG fails an `EventSource` for good on any non-200 answer, so a 503 during a rolling deploy would stop every client that reached the closing replica. A dropped stream makes the browser reconnect, and the load balancer then sends it to a live replica. It is idempotent. The README registers it with `RegisterOnShutdown`. On fiber, fasthttp's `Done()` at shutdown ends streams too. Without the call, streams end at the shutdown deadline as they would otherwise.

### D9. Concurrency inside one replica

- **One goroutine per stream:** the body. It `select`s over:
  - its context (the client left, a flush failed, or shutdown);
  - the heartbeat ticker, with jitter;
  - the single timer (D4);
  - a wake channel of capacity 1, which a bus `session_ended` fills without blocking, and which coalesces several wake-ups into one reload;
  - a queue of capacity 32 for `credential_changed` and `app.*`.
- **The publisher never waits.** Raising a signal sends to each stream's queue with a non-blocking send. A full queue drops that event for that stream only, and logs with sampling. `session_ended` never goes through the queue: it comes from the stream's own reload, so it is never dropped.
- **The registry is one mutex around three maps:** `user → streams`, `family → streams`, and a per-sign-in count. Admission checks all three caps and registers under the same lock, so two requests racing for the last place cannot both get it. Delivery copies the target streams under the lock and sends after releasing it.
- **Writes happen only in the body goroutine,** so no event can interleave with another or with a heartbeat.

### D10. Status before and after the stream starts

| When | Condition | Answer |
|---|---|---|
| before streaming | stream not enabled | the request passes through to the consumer's routes |
| before streaming | method other than `GET` | 405, with `Allow: GET` |
| before streaming | no credential | 401 |
| before streaming | authenticated without a sign-in | 403 |
| before streaming | a cross-site request from an origin CORS does not allow | 403 |
| before streaming | a pending sign-in | as the pending-session gate answers it |
| before streaming | `signals` over 16 names or 256 bytes | 400 |
| before streaming | a cap reached | 429 `ErrTooManyStreams` |
| before streaming | the adapter cannot stream | 501 `ErrStreamingUnsupported` |
| before streaming | after `CloseSessionSignals` | 200 with only `retry`, then the connection closes |
| while streaming | any failure | the stream closes; the status was already sent |

- Every refusal goes through the chain's error mapping, as every other refusal does, so a consumer's error responder shapes the body.

## Security review against standards (2026-11-03)

Each decision was checked against the standards and practice listed under References. "Complies" means no change was needed. The changes are recorded in the decisions they touch.

| Decision | Checked against | Verdict |
|---|---|---|
| No credential in the query string (D3) | RFC 6750 §2.3 and §5.3 (SHOULD NOT); OWASP Session Management and WebSocket cheat sheets (URLs leak into logs) | Complies, and is stricter than RFC 6750: never, rather than SHOULD NOT |
| Cross-origin streams (D3) | WHATWG `withCredentials`; OWASP HTML5 (CORS for `EventSource`, no `*`); OWASP WebSocket (validate `Origin` on every handshake); web.dev resource isolation policy | **Gap, fixed.** CORS alone does not refuse the request, so the stream applies the CSRF layer's Fetch Metadata and `Origin` rule to its `GET` |
| No session activity (D3) | OWASP Session Management (idle time since the last request; attackers keep sessions alive with periodic activity); NIST SP 800-63B-4 ("without activity from the subscriber"); ASVS 5.0 V7.3.1 | Complies. No standard defines a background request as activity; this is a design decision that reads "activity from the subscriber" strictly, not a claim that a standard requires it |
| What the stream tells the user (D5) | ASVS 5.0 V7.4.1–V7.4.3 and V7.5.2 (terminated sessions unusable, terminate others after a credential change, view and end sessions); OWASP Session Management (alert on concurrent sign-ins, remote termination); NIST SP 800-63B-4 §4.1.2.1 (notify the subscriber when an authenticator is added) | Complies, and supports these. `credential_changed` does not replace the notice NIST requires: the out-of-band notices scrty already sends (passkey binding notices, sign-in notices) remain that |
| No audit feed (D5, the never-carries requirement) | OWASP Authentication Cheat Sheet (generic answers whatever the account state; lockouts can be abused) | Complies. A lockout or refusal signal would give an attacker holding a session the feedback that guidance withholds |
| Vocabulary (D5) | OpenID CAEP 1.0 (`session-revoked`, `credential-change`, `assurance-level-change`) | Complies as stated: scrty borrows the vocabulary, not the protocol. Its credential kinds are coarser than CAEP's `credential_type` on purpose, so a stream never says which passkey or factor changed |
| Event names and data (D2, D7) | WHATWG event-stream parsing (CR, LF or CRLF end a line, and a blank line dispatches); GHSA-22cc-p3c6-wpvm and CVE-2026-44214 (newline injection in other SSE libraries) | **Gap, fixed.** Consumer names have a fixed shape, and the writer refuses a raw CR or LF |
| Reconnection and shutdown (D7, D8) | WHATWG (a non-200 answer fails the connection with no retry; a drop reconnects after `retry`, "a few seconds") | **Conflict, fixed.** Shutdown no longer answers 503. Every other answer is chosen for what the browser does next (D7's table) |
| Caps, queue, heartbeat (D8, D9) | OWASP DoS Cheat Sheet (load limits, absolute connection timeout); OWASP WebSocket (per-user and total connection limits, heartbeats, backpressure); RFC 9113 §6.5.2; WHATWG (a comment every 15 seconds or so) | Complies. Streams are capped per sign-in, per user and per replica. Queues are bounded and drop slow clients' events. A client that stops reading is ended by the per-flush write deadline. The absolute session deadline bounds every stream's life |
| Caching (D7) | OWASP Session Management (`no-store` for session data); RFC 9111 §5.2.2.5; nginx `X-Accel-Buffering` | Complies. The README notes that `X-Accel-Buffering` depends on the operator's proxy |
| The bus (D4, D6) | OpenID SSF 1.0 (authenticate transmitters, validate `iss`, ignore unknown fields); CAEP 1.0 | Complies with the practice. Neither standard prescribes an internal bus, so scrty treats bus messages as untrusted: an end only triggers a store check, other envelopes are revalidated, and the port's godoc asks a shared bus to authenticate its transport |

## Risks / Trade-offs

- **[Store load]** 10 000 streams at 15 s is about 670 session reads per second per replica.
  → Jitter spreads them out. The interval can go to 60 s, and the README gives the arithmetic. A shared bus lets a consumer lengthen the heartbeat without delaying `session_ended`.
- **[Fiber write deadline]** The fiber design rests on resetting the connection's deadline per flush, which is unverified.
  → Task 1.2 tests it first. If it fails, the fiber adapter documents that a `HeaderReceived` hook giving the stream path a long `WriteTimeout` is required, and the `framework-adapters` delta is amended before any other task.
- **[A lost bus message]**
  → The heartbeat bounds the delay. Signals are wake-ups, never the only path.
- **[A slow client]**
  → Each stream's queue is bounded, and a full queue drops that stream's events. `session_ended` comes from the stream's own reload, so it is never dropped.
- **[A store outage]** Streams cannot tell an ended sign-in from an unreachable store.
  → They stay open and keep sending heartbeats, and end at the absolute deadline at the latest. A sign-in ended during the outage is signalled at the first reload that succeeds.
- **[An assurance window that differs from the guards']**
  → The front end is told too early or too late, and the guard's 403 still decides. The godoc names the coupling, and the default matches the guards' default.
- **[Many tabs on HTTP/1.1]**
  → The cap of 4 per sign-in refuses the fifth tab, not an existing one. The README recommends one shared stream (BroadcastChannel or SharedWorker), or HTTP/2.
- **[A breaking adapter interface]**
  → It lands before `v0.1.0`, which `release-readiness` records. `ErrStreamingUnsupported` gives a consumer adapter a way out.
- **[A refusal at admission stops `EventSource` for good]** A 5xx from a store outage while the stream opens fails the connection permanently (WHATWG).
  → It is the chain's ordinary dependency-failure answer and is not changed here. The README's client snippet rebuilds the `EventSource` after an error, with backoff.
- **[The chain's authorizer does not see the stream]**
  → The stream reveals only the caller's own sign-in, and the session-management endpoints already sit at the same place. A consumer who must gate it puts an interceptor below `OrderSessionSignals`.

## Migration Plan

- Off by default. Enabling it needs no data migration: the stream reads existing session fields.
- The only API break is `ResponseWriter.Stream`, before the tag.
- To roll back, remove `EnableSessionSignals`. Clients then get 404 from the consumer's router, or whatever their route does, and `EventSource` stops retrying.

## Open Questions

- The default `retry` of 5 seconds may be worth tuning once real front ends use it. Changing it touches no spec or task.

## References

**D1: streaming on each adapter** (accessed 2026-11-02)
- [fiber v3 `Ctx.SendStreamWriter`](https://pkg.go.dev/github.com/gofiber/fiber/v3), read through `go doc` at v3.5.0: a body stream writer that fiber runs after the handlers return.
- [fasthttp](https://pkg.go.dev/github.com/valyala/fasthttp), read through `go doc` and its source at v1.73.0: `RequestCtx.Done` closes only at shutdown, and `server.go` sets one write deadline per response.
- [net/http `ResponseController`](https://pkg.go.dev/net/http#ResponseController): `Flush` and `SetWriteDeadline` per response.

**D4, D7: the stream and its wire format** (accessed 2026-11-02)
- [WHATWG HTML: server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html): the event format, `retry`, no custom headers on `EventSource`, a non-200 response failing the connection, comment heartbeats every 15 seconds or so, and the per-server connection limit.

**D5: which signals** (accessed 2026-11-02)
- [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html): the vocabulary for session and credential events.

**Security review** (researched, accessed 2026-11-03; quotes were read through fetched summaries)
- [RFC 6750 §2.3 and §5.3](https://www.rfc-editor.org/rfc/rfc6750#section-2.3): bearer tokens SHOULD NOT be sent in the URI or page URLs (D3).
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): identifiers in URLs, idle timeout measured from the last request, `no-store`, viewing and ending sessions (D3, D5, D7).
- [OWASP ASVS 5.0, V7 Session Management](https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x16-V7-Session-Management.md): V7.3.1, V7.4.1–V7.4.3, V7.5.2 (D3, D5).
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html): the inactivity timeout, and notifying the subscriber when an authenticator is added (§4.1.2.1) (D3, D5).
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): Fetch Metadata as the primary signal, and `Origin` (D3).
- [web.dev: Fetch Metadata resource isolation](https://web.dev/articles/fetch-metadata): the resource isolation policy the stream applies (D3).
- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html): `EventSource` across origins uses CORS; no `*` and no blind reflection (D3).
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html): validate `Origin` on every handshake, no tokens in the query string, connection limits and heartbeats (D3, D8).
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): generic answers, and lockout as a denial-of-service lever (the never-carries requirement).
- [WHATWG HTML: server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html): line endings and dispatch; a non-200 answer fails the connection with no reconnection; reconnection after `retry` (D7, D8).
- [GHSA-22cc-p3c6-wpvm](https://osv.dev/vulnerability/GHSA-22cc-p3c6-wpvm) and [CVE-2026-44214](https://www.sentinelone.com/vulnerability-database/cve-2026-44214/): newline injection in other SSE libraries' event fields. Read through search summaries, not the full advisories (D2, D7).
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html): load limits and absolute connection timeouts (D8).
- [RFC 9113 §6.5.2](https://www.rfc-editor.org/rfc/rfc9113#section-6.5.2): `SETTINGS_MAX_CONCURRENT_STREAMS`, so each stream counts against an HTTP/2 connection's streams (D8).
- [RFC 9111 §5.2.2.5](https://www.rfc-editor.org/rfc/rfc9111#name-no-store): `no-store` (D7).
- [nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html): `X-Accel-Buffering`, and that `proxy_ignore_headers` can disable it (D7).
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html): transmitter authentication, `iss` validation, ignoring unknown fields (D6).
- [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html): the event types and their fields (D5).
- *Unverified:* the Fetch standard's own text on credentialed cross-origin reads; whether browsers retry after a 5xx beyond WHATWG's current text; SSF's security-considerations text on signing and replay.

**D2, D3, D5, D9, D10: the tree as it stands** (checked 2026-11-03, at `4649c90`)
- Reasoned from scrty's own settled specs and code, and the established design: the reuse observer and the ending calls in `sessions`; `sessionTouch` and the slot order in `http-security-chain`; the recency guards and their default window in `reauthentication`; and `close-security-gaps` D8 (the internal-set pattern), D12 (session management) and D13 (security events).
