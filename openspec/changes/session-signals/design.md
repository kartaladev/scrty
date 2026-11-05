# Design

## Context

See `proposal.md` for why, and the five spec deltas for the required behaviour. This design was checked against `main` at `4649c90` on 2026-11-03, after `close-security-gaps` was merged (#45) and archived (#66). What shapes the approach:

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
- Bounded cost per stream: one body goroutine, one timer re-armed for the next beat and the next deadline, a short-lived goroutine for a read in flight, and two reads per heartbeat, the sign-in and its user (D4). Fiber adds two goroutines per stream, its `Done()` watcher and its connection reader (D1).

**Non-Goals:**
- Delivery guarantees beyond "within one heartbeat": no acknowledgements, no ordering across signals, no replay.
- Redis and PostgreSQL bus implementations (follow-ups).
- A browser client library. The README shows `EventSource` for cookie sessions and a `fetch()` reader for bearer clients.
- A metrics integration. Streams log at DEBUG when they open and close, bus failures and cap refusals log with sampling, and `chain.SessionSignalStats()` returns plain counts for the consumer to export (D8).

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
    // Each EventWriter.Flush hands the event on to be sent before body continues.
    Stream(ctx context.Context, contentType string, body func(ctx context.Context, w EventWriter) error) error
}

type EventWriter interface {
    io.Writer
    Flush() error // also pushes the connection's write deadline forward
}
```

- **net/http and gin:**
  - `Stream` runs `body` inline, so `Stream` returns when the stream ends;
  - `Flush` uses `http.ResponseController.Flush`, and `Stream`, each `Write` and each `Flush` first call `SetWriteDeadline(now + StreamWriteWindow)`. A hand-written walk that carried on past a wrapper's `Flush` was tried and removed: it sent the head from beneath `gzhttp`, which had not yet chosen its encoding, so a client received raw gzip with no `Content-Encoding` (REPRODUCED against klauspost/compress v1.17.6). Gin's `Flush` silently does nothing over a writer that cannot flush, so `ginsec` handles that itself, in a small wrapper around gin's writer. Inspecting wrappers is limited to 32 layers, and beyond that a writer counts as unable to flush;
  - the client leaving ends `body`'s context.
- **fiber:**
  - `Stream` registers `body` with `SendStreamWriter` and returns at once;
  - `body` runs after the chain has unwound, on a context detached from the chain's end-of-request cancellation, and cancelled when fasthttp's `Done()` fires at shutdown, when a flush fails, or when the client leaves. `SetBodyStreamWriter` starts its goroutine at once (fasthttp v1.77.0), so the adapter's middleware holds the body behind a gate until the chain has returned;
  - **a reader sees the client leave** (user's choice, 2026-11-04). A failed write is seen too late: the stream's writes go through an in-memory pipe, so a nil `Flush` does not mean the bytes reached the socket, and a client that left is noticed 2 to 3 heartbeats later, while its stream keeps its place under the caps. So one goroutine reads the connection while the stream is open, and EOF ends `body`'s context. A stream response carries `Connection: close`, because the reader may consume pipelined bytes, so its connection is not reused. A client that half-closes counts as having left. This costs one goroutine and about 2.7 KiB per stream (measured over 1000 streams). *Rejected:* amending the spec to three heartbeats on fiber, because a reloaded tab could then meet 429, which ends an `EventSource` for good;
  - the body's start, each `Write` and each `Flush` set the connection's write deadline to `now + StreamWriteWindow` through the connection, so the deadline fasthttp set once for the whole response does not cut the stream. Task 1.2 established this on fiber v3.6.1 and fasthttp v1.77.0 (`TestFiber_StreamOutlivesWriteTimeout`, 2026-11-04): without the later deadline the stream is cut at its first write after 3 seconds, and with it the stream stays open for 30 seconds.
  - the closure holds the connection and the `Done()` channel, copied while the chain runs, and never the fiber `Ctx` or the `*fasthttp.RequestCtx`, which are pooled.
- **A body must not read the exchange** (review, 2026-11-04). On fiber the request and everything read from it are views into buffers that are reused once the chain returns, so a body reading them can see another user's request (`TestFiber_StreamBodyMustNotReadExchange` shows the hazard). `Stream`'s godoc requires a caller to copy what its body needs before calling it, strings included, on every adapter.
- **The write window is one fixed constant** (corrected 2026-11-04, before implementation; this draft said `2 × heartbeat`, and the plan `now + 10s`). `httpsec.StreamWriteWindow` is 2 minutes, twice the largest heartbeat D2 allows, and every adapter uses it.
  - The adapter is never told the heartbeat: `Stream` does not carry it, so `2 × heartbeat` could not be built.
  - The window must outlast the gap between two writes, not only cover a write in flight. On HTTP/2, Go's server resets the stream when its write-deadline timer fires, even with no write in flight (`onWriteTimeout`, read in `net/http/internal/http2/server.go` at Go 1.27.3). So a 10-second window would end every idle stream on the default 15-second heartbeat. REPRODUCED by `TestHTTPResponseWriter_Stream/over_HTTP/2_a_window_shorter_than_an_idle_gap_resets_the_stream`: with a 500 ms window and a 2 s gap, `stream error: stream ID 1; INTERNAL_ERROR; received from peer` at 0.51 s.
  - *Trade-off:* a client that stops reading holds its stream and its place for longer, not 30 seconds at the default heartbeat. The caps bound what that costs, and a client that reads can hold a place anyway. `CloseSessionSignals` is bounded by its own context (D8). The bound, measured on 2026-11-04, applies once the kernel's buffers are full, which at one heartbeat comment every 15 seconds can take days (72 050 comments on macOS loopback), so until then only the session's own end limits such a stream:
    - net/http over HTTP/1.1, and an HTTP/2 flow-control stall: the window. Over TLS, up to 5 seconds more, because closing a TLS connection sends its alert under its own deadline.
    - fiber: up to about 5 heartbeats plus the window, because each flush the pipe accepts also moves the deadline of the socket write that is stuck.
    - **net/http over HTTP/2, when the TCP connection itself stalls: no bound from the adapter.** Go's server queues the reset but sends nothing while a frame write is blocked, so the body stays blocked (`after 20s the body is still blocked`, with a 1 s window). Only the server's own `HTTP2.WriteByteTimeout` bounds it (1.00 s when set to 1 s), and the server is the consumer's. The godoc and the README say to set it.
  - *Rejected:* a window parameter on `Stream`, which every consumer adapter would have to honour for a value only the stream endpoint chooses.
  - **Override:** none, as for the rest of the adapter contract.

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

- **A refusal carries no stream type** (review, 2026-11-05; R9). A type set before `Stream` could reach a refusal (REPRODUCED on net/http and on fiber), and a blank left in its place survived a framework's render and net/http's detection (REPRODUCED). So `Stream` takes the type, and an adapter sets it only when it commits the head. **Known difference between adapters, stated:** a consumer's response begun with 503 that then returns an error goes out as 500 on fiber, through its `ErrorHandler`, and likewise on gin, and stays 503 on net/http (REPRODUCED). This is those adapters' refusal contract, which predates this change, so it is left as it is.
- **The headers are frozen when `Stream` is called.** Every adapter sends the status and the headers set so far, and later `SetHeader`, `AddHeader` and `SetCookie` calls have no effect, on fiber too, where fasthttp could otherwise still send what the chain sets while unwinding. On every adapter they also have no effect once an ordinary response has begun, even where a framework still holds the head (REPRODUCED before the fix on fiber and gin). **A consumer-visible change, before the tag:** on gin, or behind a buffering wrapper, a header set through `ex.Writer` after a bare `WriteHeader` used to land and no longer does, and a declared trailer set through it is dropped. Trailers belong to the framework's own writer, and the godoc says so. After `Stream`, `Write` returns `ErrStreamingStarted` and `WriteHeader` does nothing. `Stream` sends 200, because gin holds 404 for a path with no route, and fiber whatever status was already on its context. A run-time refusal can only be real from a layer with no `Unwrap`, so only the bottom of the `Unwrap` chain is asked before the status is named, and every wrapper above it still sees its own `WriteHeader`, as `httpsnoop` and so otelhttp depend on (REPRODUCED: a probe of the top writer skipped that hook). A bottom writer with `SetWriteDeadline` counts as the connection, below any number of wrappers, so its status is named first; if it then says not supported, the status has gone out, though the body still does not run. Three rare limits, each stated in the godoc: a wrapper with `FlushError` and no `Unwrap` skips its own `WriteHeader`; under a gin middleware that replaces `c.Writer` with a wrapper adding `FlushError`, a path with no route carries gin's 404; and under a gin middleware whose wrapper has `Unwrap` back to gin's writer, over a writer with no `Flush` method, a stream delivers nothing, because gin's `Flush` does nothing there (REPRODUCED). Walking past that wrapper to reach one that can flush would skip its own `Flush`, which is what corrupted the stream behind `gzhttp`. A `Stream` after the chain has returned, on fiber, returns `ErrStreamingStarted` and its body never runs, because fiber's context is unsafe by then.
- **If `Stream` returns nil, its body runs exactly once; if it returns an error, its body never runs** (failure sweep, 2026-11-04), on every adapter. On fiber, whose body runs after the chain has returned, when the chain refused or the connection has gone, the body runs on an already-cancelled context and what it writes goes nowhere, so what it holds is always released. On net/http and gin the body runs inline, so by the time an outer interceptor could refuse, the stream has been sent.
  - **A limit, stated.** Fiber middleware *outside* the adapter's, failing after the chain returned nil, cannot take the stream back: the gate has opened, so the error handler's status goes out with the live stream. An `EventSource` refuses a non-200 answer, and what was sent is the caller's own sign-in. The godoc on fibersec's `Middleware` says to place such middleware inside.
  - **Body panics.** A panic that a recovery middleware outside the adapter catches, such as `gin.Recovery`, must not leave a response that looks complete, so on net/http and gin `Stream` cuts the connection before the panic goes on. The stream's own code recovers its panics first (D8), so this guards a consumer calling `Stream` directly.
 `Stream` drops what the body returned, because the body has already been run and a caller must not release its place a second time; a body that wants its failure seen logs it. A panicking body on fiber ends the response through the stream reader, which reports an unexpected end, so the head is always written first; closing the connection instead raced the head, and a client could get nothing at all (REPRODUCED under load, `TestFiber_Stream/a_body_that_panics…`).
- **A writer that cannot flush is reported, not mistaken for a client leaving.** `Stream` returns `ErrStreamingUnsupported` with nothing written, following `Unwrap` before believing a writer's own `Flush`, because gin's `Flush` silently does nothing over a writer that cannot flush (REPRODUCED: `http.TimeoutHandler` over gin). A consumer's wrapper needs `Unwrap` for the deadline and for a body's panic to cut the response; one with only `Flush` or `FlushError` streams without them, and its godoc says so. A consumer's own adapter must keep the deadline and client-leaving promises, or return `ErrStreamingUnsupported`.
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
    MaxPerSource:    0,                 // default: off
    MaxAge:          time.Hour,         // default; NoMaxAge turns it off
    ReconnectDelay:  5 * time.Second,   // default; ±30% per stream
    BusyDelay:       30 * time.Second,  // default; ±30% per refusal
    Users:           nil,               // default: the built-in bearer's loader
    ReloadContext:   nil,               // default: a context with none of the request's values
    ReloadTimeout:   0,                 // default: half the heartbeat, within 2–10 s
    Bus:             nil,               // default: in-process
    BusQueue:        1024,              // default; a consumer's bus only
    BusTimeout:      5 * time.Second,   // default; a consumer's bus only
    RetryableError:  nil,               // default: every 5xx-mapped failure on the path is retried (D7)
}
chain, err := httpsec.New(..., httpsec.EnableSessionSignals(signals))
err = chain.PublishSignal(ctx, userID, "app.roles_changed", json.RawMessage(`{"roles":["editor"]}`))
err = chain.ReportCredentialChange(ctx, userID, httpsec.CredentialPassword)
err = chain.CloseSessionSignals(ctx)
```

- **Slot:** a terminal endpoint in a new slot, `OrderSessionSignals = OrderSessionManagement - 1` (673). Everything below it applies as on any protected route: headers, proxies, CORS, CSRF, rate limits, authentication, and the pending-session and re-authentication gates. Session touch (800) and the chain's authorizer (900) are above it and never run for the stream, as for the session-management endpoints beside it.
- **Construction rules** (`library-design` rule 6). A field left at zero takes its default, because `SessionSignals{}` must work and an explicit zero looks the same as unset, so these refuse negative values rather than zero, as `NoMaxAge` = -1 fits:
  - a signal name outside the four;
  - a heartbeat outside 5–60 seconds;
  - a negative warning window, or one not shorter than the session manager's idle timeout; and a warning window set without `session_expiring` in the set, since nothing would use it;
  - a negative assurance window, and one set without `assurance_lapsed` in the set;
  - a negative cap, or `MaxPerSignIn` above `MaxPerUser`, or `MaxPerUser` above `MaxStreams`;
  - `assurance_lapsed` without `EnableReauthentication`, because the front end would be told to re-prove with no way to do it;
  - a `Path` that another enabled endpoint already serves;
  - `EnableSessionSignals` given twice;
  - no session manager on the chain, as session management already refuses;
  - no `Users` and no built-in bearer's loader to default to, because a stream could not tell that its user was disabled;
  - a `Path` that lacks its leading slash, ends in a slash, or holds `?`, `#`, `%` or whitespace, since it would silently never be served, because paths are compared decoded;
  - a `ReconnectDelay` or `BusyDelay` under 1 millisecond, which would be sent as `retry: 0`;
  - a warning window above the idle timeout less the touch interval, since a user who is active but whose activity writes coalesce would be warned;
  - a `MaxAge` below twice the heartbeat, or `MaxPerSource` above `MaxStreams`;
  - a `ReloadTimeout` not shorter than the heartbeat, or a `BusQueue` or `BusTimeout` below 1 when set, or a `BusQueue` above 1 048 576, which would fail or exhaust memory at first use;
  - a chain clock (`WithClock`) that cannot wait (`clock.Timed`), because a controlled `Now` with real waits fires timers at the wrong moments.
- **`AssuranceWindow`** (user's choice, 2026-11-03). The chain has no re-authentication window of its own: each recency guard has one. The field defaults to `DefaultRecentAuthenticationWindow`, the guards' default, and its godoc says to set it to the window of the guards the front end must satisfy. The two cannot be checked against each other, because `Guards` are constructed apart from the chain.
- **The query string:** `?signals=` is split on commas, at most 16 names and 256 bytes in all, and more than that is refused with 400. A name that is not in the chain's set is dropped. `app.` names are matched the same way, so a client can narrow to its own signals too.
- **Consumer signal names are a fixed shape** (security review, 2026-11-03). A name must match `^app\.[a-z0-9][a-z0-9._-]{0,62}$`. An event name goes onto the wire as an `event:` line, and a CR or LF in it would start a new field or event: the SSE injection that GHSA-22cc-p3c6-wpvm and CVE-2026-44214 describe in other libraries. The shape also excludes `:` and NUL. A client's `?signals=` entries are held to the same shape before they are compared, and a malformed entry is dropped like an unknown one.
- **`PublishSignal`:**
  - it returns `ErrSessionSignalsDisabled` when the stream is not enabled; `ErrInvalidSignal` for a name outside that shape, or data over 8 KiB, not valid JSON, not valid UTF-8, or holding a raw line break between its tokens, as `json.MarshalIndent` output does; and `ErrSignalsBusy` when a consumer's bus has fallen so far behind that the signal was dropped (D6). Data is delivered unchanged, so it is refused here, not compacted, and not found out later by the wire writer;
  - a user with no open stream is not an error: the signal reaches no one;
  - it never blocks on a slow stream (D9).
- **`ReportCredentialChange`:** returns `ErrSessionSignalsDisabled` when disabled, and `ErrInvalidSignal` for a kind outside `password`, `passkey` and `second_factor`.
- **Override:** every field, and the bus.

### D3. Who may open a stream

- The resolved `Authentication` must carry a session: a session reference, a signed bearer tied to a stored session, or a consumer's `CookieAuthenticator` session. Otherwise the answer is 401 (nothing authenticated) or 403 (Basic, an API key, or a token with no session).
- A sign-in still owing a second factor, enrolment or recovery is refused by the pending-session gates below the stream's slot, exactly as they refuse every other protected route.
- The authenticating interceptors never read a credential from the query string, so that spec rule holds already. A test pins it.
- **CSRF:** a `CookieAuthenticator` calls `CheckCSRFToken`, which checks only unsafe methods. The stream is a `GET` and changes nothing, so it passes without a token. A test pins that, so a later tightening of CSRF cannot break `EventSource`, which cannot send a token header.
- **Cross-site requests are refused by the stream itself** (security review, 2026-11-03). CORS in scrty decides only which response headers an origin gets. For a disallowed origin it leaves them out, and the request still runs. A page on another site could therefore open credentialed streams that its browser cannot read, each taking one of the victim's per-sign-in places. That is REPRODUCED: against a check that allowed everything, `TestSessionSignals_CrossSite`'s first row got 200 where 403 is required. The stream therefore applies, to its `GET`, the origin rule the CSRF layer applies to unsafe methods (`csrf-protection`), whether or not CSRF protection is enabled:
  - `Sec-Fetch-Site` of `same-origin` or `none` passes;
  - `same-site`, `cross-site` or any other value passes only for a trusted origin. This is stricter than web.dev's policy, which allows `same-site`, and than Go's `http.CrossOriginProtection`, which allows every `GET`: neither has a place to lose, and this endpoint does;
  - with no `Sec-Fetch-Site`, a cross-origin `Origin` passes only when trusted, and no `Origin` at all passes, since old browsers and non-browser clients send neither. **Limit, stated** (review, 2026-11-04): browsers send no `Sec-Fetch-Site` to a URL that is not potentially trustworthy, so over plain HTTP, and from a browser without Fetch Metadata, a cross-site tag or navigation arrives with neither header and passes. Refusing it would refuse every non-browser client, as the spec requires it not to. `SameSite` and `Secure` on the consumer's cookie are the defence there, and the README recommends them. Over HTTPS on a current browser, a foreign page cannot open a cookie stream;
  - `Origin: null` never passes, whatever CORS says;
  - **a request counts as bearer only when the chain recorded a credential and that credential is what its `Authorization` header carries.** A consumer's cookie authenticator is told to call `RecordPresentedToken`, so the recording alone would judge a foreign page's ambient cookie as a bearer token (REPRODUCED). A consumer bearer on a custom header is then judged as a cookie, which is the stricter rule;
  - **trusted depends on how the stream authenticated** (failure sweep, 2026-11-04). A cookie is sent by the browser on its own, so a cookie-authenticated stream needs an origin CORS names, exactly or by pattern, with credentials allowed, and a wildcard never counts. An `Authorization` header is not ambient, and a page can only send one it already holds, so that stream needs only an origin CORS allows, and a wildcard counts (corrected by the standards review, 2026-11-04): a public API on `*` with bearer tokens is a legitimate CORS configuration, and refusing it would protect nothing. `AllowCredentials` defaults to false, so requiring it of every client would refuse a bearer page whose preflight had just passed. *Not reused:* CORS's `allowedOrigin` answers yes for every origin under `*`, `null` included, and the CSRF layer's trusted list ignores credentials and does not exist with CSRF off;
  - a refusal is 403 with its own sentinel, `ErrCrossSiteStream`, before the stream is registered, so it costs no place. It does not reuse `ErrCrossSiteRequest`, which would emit `MaliciousCSRF` for a page that merely tried. It is still logged, with sampling, as an attempt to get past a control (ASVS 5.0 16.3.3);
  - a response that echoes an origin carries `Vary: Origin`.

  This is the resource isolation policy that web.dev's Fetch Metadata guidance describes, and OWASP's advice for WebSocket handshakes to validate `Origin` every time. **Override:** the CORS allowlist, which already names the origins a consumer trusts. There is no switch to turn the check off, because a stream that a foreign page can hold open is the denial of service it exists to prevent.
- **Activity, corrected 2026-11-03.** The draft relied on an internal set that the built-in authenticators consult before recording activity. On `main`, authenticators never record activity: only `sessionTouch` does, after the handler, at slot 800. A terminal endpoint at 673 is never inside it, so the built-in paths need no set. A consumer interceptor below 673 that records activity on its own asks `httpsec.RecordsSessionActivity(ex)`, which reports false for the stream's path. The godoc on `CookieAuthenticator` and on `OrderSessionTouch` says so.
- **Default and override:** the admission rules have no override, since a stream for no sign-in has nothing to report. The path is the consumer's (D2).

### D4. The store is the truth; signals are wake-ups

- Each stream holds `{user, family, upstream digest, idle deadline, absolute deadline, authenticatedAt}` from its first load, and no session identifier or credential.
- **The reload reads by user and family, never by identifier** (corrected by the failure sweep, 2026-11-04; the draft said "the read the bearer uses"). `Sessions.Load` is what a presentation goes through, so it cannot be the reload. After a renewal's grace window it revokes the family and raises a false theft alarm, after a strict rotation it answers not found, and it records a first presentation (REPRODUCED: `session/sessions.go:375,383`, `session/reuse.go:496,533`). So a stream that reloaded through it would sign its user out. The raw `Store.Load` fails the other way, answering with stale deadlines after the current session has moved or gone. So:
  - `(*Sessions).SignInState(ctx, user, family) (SignInState, error)` returns the family's current session's two deadlines, `AuthenticatedAt` and upstream identifiers, or `ErrNotFound`. It reads through `FamilyReader` when the store has it (R8), and otherwise through the existing `Store.ListByUser`. Either lists one live current session per family, opens no sealed field, and can judge, revoke or mark nothing. No required store method changes.
  - A renewal, a strict rotation or a step-up leaves the family and moves its current session, so the stream carries on and reports the new state. `TestSessions_SignInState` pins this, and the store conformance suite pins it on PostgreSQL through sqlstore, pgxstore and gormstore.
  - Its cost is one indexed query that returns that user's sign-ins.
  - **Limits of reading only a listing** (review, 2026-11-04; both REPRODUCED, and stated in the godoc):
    - A listing shows no superseded session. Where a successor dies before its predecessor, under `WithRenewalLifetime` shorter than the grace window or idle timeout, the read answers not found while the predecessor can still load or renew, so such a stream can report `expired` or `ended` to a user who can still reach the sign-in. Its reconnection is then judged as any request is. With the default lifetime this does not arise. Seeing superseded sessions would need a new store method on every backend, which this decision declined.
    - A store fails a listing it cannot read in full, so one undecodable session of a user makes the read fail for all of that user's sign-ins, ended ones included, and those streams treat it as an outage until `MaxAge`. `ConsecutiveReloadFailures` shows it. With `FamilyReader` (R8), only the sign-in holding that row is affected.
    - The cost per user per heartbeat is that user's streams × their rows, and retained predecessors count until their family ends: 200 rows scanned for 50 sign-ins renewed three times, 0.9 ms locally on PostgreSQL. Measured once, and it drifts with data.
  - **Limit:** a stream follows its family, so it keeps following after a renewal it took no part in, including a thief's stream opened before the victim renewed. `MaxAge` (below) bounds that.
- **At every heartbeat** it reloads through that read, and through `Users.LoadByUserID`. The outcome decides the next step:

  | Reload finds | The stream sends | Then |
  |---|---|---|
  | the session, unchanged | `:` comment | keeps going |
  | a deadline or `authenticatedAt` moved | `session`, after the beat's comment | re-arms its timer |
  | gone after a logout | `session_ended` `logout` | closes |
  | gone after an ended sign-in, or the user no longer active | `session_ended` `ended` | closes |
  | gone, its family revoked on reuse | `session_ended` `reuse` | closes |
  | gone after a user-wide end | `session_ended` `all_ended` | closes |
  | gone after a provider logout | `session_ended` `provider_logout` | closes |
  | gone with no report, no deadline passed | after up to 500 ms for a report, `session_ended` with that report's reason, or `ended` | closes |
  | gone, a held deadline passed | `session_ended` `expired` | closes |
  | a session or user-store failure, or a read that timed out | `:` comment | keeps going, logs with sampling, reloads next heartbeat |

  A beat's comment goes out at the beat, before its read answers, so the gap between bytes stays within 1.1 × heartbeat plus a write, whatever a read does. The reason comes from the latest end report the stream was woken with, through D5's mapping, and only if the store says gone within two heartbeats of receiving it (local receipt time), a user-wide report being narrower still (R5). So a report whose end did not happen, a rolled-back transaction or a forged bus message, cannot name a later real end. Within that window `reuse` outranks a later report: a logout that finds its family just revoked for reuse still reports, because a write matching nothing is reported, and must not relabel a theft as a logout. A report for a session deleted from a family that stays live changes nothing, because the store still answers. A user who is not found or not active ends the stream with `ended`.
- **A reload has a timeout,** and a timeout counts as a store failure (CWE-1088). The session read and the user read share it. Without one, a store that hangs instead of failing stops the heartbeat, the timers and the queue, because they share one goroutine. A read runs in its own goroutine, at most one in flight per stream, and the loop `select`s on its result, so that even a store that ignores its context cannot stop the heartbeat, `MaxAge`, `closing` or a client leaving (review, 2026-11-04; REPRODUCED with the read inline: no heartbeat in 5 minutes). A read still in flight when its timeout passes counts as a failure, and no second read starts while it runs, so such a store costs one goroutine per stream, held until it returns, and the godoc says so. *Rejected:* narrowing the spec's "a store that hangs" to a store honouring its context, since a consumer's user loader is likely to be the one that does not. The default is half the heartbeat, within 2 to 10 seconds, because half of 60 seconds is long for a session read, and half of 5 too short under load. No standard sets a fraction: this is a judgment. **Override:** `ReloadTimeout`, which must be shorter than the heartbeat.
- **A reload does not run on the request's context** (failure sweep, 2026-11-04). The adapters' body context keeps the request's values (REPRODUCED), so the stream hands its own code a cancel-only context, which reads as holding no values, and a `session_ended` or a slip in later code cannot reach the session or its raw identifier through it. What a stream holds of the upstream session is its digest: the raw values are cleared once it is taken. A consumer's transaction attached with `WithTx` would stay open for the stream's life on net/http, pinning a pooled connection, and on fiber be committed when the chain returns, so that every reload failed and an ended sign-in looked alive until its absolute deadline. So reloads and user reads run on a context with none of those values. **Override:** `ReloadContext func(ctx) ctx`, called once at admission, lets a multi-tenant consumer carry its tenant. The first read, at admission, uses the same context, and reads the user as well as the sign-in. So a tenant-scoped store with no hook fails closed where it can be seen: a dependency failure at admission, logged at WARN, not an open stream that never hears of an end (OWASP's Multi-Tenant cheat sheet: fail closed when the tenant context is missing, and re-establish it for asynchronous work). It cannot read another tenant's data. A panic in the hook is recovered, logged with the family and without its value, and answered as a dependency failure (REPRODUCED: it took the process down, its value in the crash).
- **`MaxAge` also bounds a store outage** (standards review, 2026-11-04). No standard says whether a notification stream stays open while its store is down; ASVS 5.0 16.5.2 and 16.5.3 ask for no fail-open processing, and the stream processes nothing and grants nothing, since every other request is still judged by the store. The stream reconnects at `MaxAge`, and re-admission fails closed, so an outage does not keep a stream past its age unless the consumer chose `NoMaxAge`. The user's choice of 2026-11-03 stands.
- **A store outage keeps the stream open** (user's choice, 2026-11-03). The store has not said the sign-in ended, and the stream grants no access, so closing would only make every client reconnect at once when the store returns. The stream's own timer still ends it at its absolute deadline.
- **A `session_ended` arriving from the bus triggers the same reload at once.** It is forwarded only if the store agrees, which removes three problems:
  - a spurious end, when a consumer's outer transaction rolls back after `Sessions.Delete` returned;
  - a forged or replayed bus message;
  - races between replicas.

  If the store still shows the session, the heartbeat catches the end later.
- **A wake cannot become a store-read flood** (review, 2026-11-04). Coalescing merges only unread wakes, so a stream reading each one would reload once per envelope, and a shared bus can wake every stream of a user at will. The first wake reloads at once, so a real end still arrives before the next heartbeat. After that a stream reloads from a wake at most once a second, and a later wake stays pending, not dropped, so the last one is still honoured. At 10 000 streams a forged flood could still ask for 10 000 reads a second across a replica, which is why a shared bus should authenticate its transport (D6). No standard sets the gap: it is a judgment, and a constant, because it protects the store from a message and not a consumer's policy.
- **A read can land between an end and its report** (review, 2026-11-05). A report follows the store's write, so a read can answer gone first, and an ordinary logout was named `ended` (REPRODUCED: `TestSessionSignals_Heartbeat_ReportBehindTheRead`, `expected: {"reason":"logout"}`, `actual: {"reason":"ended"}`; seen in conformance in 3 of 48 runs under load). So a read that says gone with no report waits up to `streamReportGrace`, 500 ms, for one. Only the queue waits: heartbeats, reads, `MaxAge`, `closing` and a client leaving carry on. A report ends the stream at once, and a read answering alive cancels the wait. `expired` and an inactive user do not wait. Every end with no local report pays it, which includes every end from another replica on the default bus, so "within one heartbeat" is one heartbeat and half a second there. The length is a judgment: a same-process report follows far sooner, and only a label is at stake, so a longer wait would only serve a bus already in trouble. **Override:** none, because it protects a label and not a consumer's policy.
- **A stream told of an end says nothing queued until the store answers** (review, 2026-11-04). An end only wakes a stream, and a change that ends a sign-in raises its signal just after, so without this a stream sent `credential_changed` and then `session_ended`, against D5 (REPRODUCED: `TestSessionSignals_CredentialChanged_EndedStream`, 298 of 300 runs). A stream holding an end notice that no read begun after it has answered does not send from its queue:
  - gone discards what was queued, with the close;
  - alive, a failure or a timeout resumes the queue, so a forged end loses nothing but the 32-entry queue's own overflow, a counted drop;
  - a read begun before the notice cannot answer it, and a read past its timeout holds nothing, however long it hangs;
  - after two answered reads with a later notice still unanswered the queue flows again, so a forged flood from a shared bus's holder costs ordering, not the queue. *Rejected:* skipping a stream with a pending notice at delivery, because a forged end would then lose a real signal for good.
  - A report with no known reason holds nothing, and a stream spared by `KeptFamily` is not woken or held.
  - **Limits, stated** (review, 2026-11-05):
    - a hold can last about two `ReloadTimeout`s plus a wake gap, because a read older than the notice can use nearly a whole timeout before the one that answers begins (REPRODUCED, at 12.001 s against a bound once stated as one timeout);
    - a stream keeping up can drop signals while held, since its queue of 32 fills: a forged end costs that burst past the 32, and `StreamDropped` counts it (REPRODUCED: 40 raised, 32 delivered);
    - a notice that ended nothing can use up the bound, so a signal can then overtake a real end behind it. A shared bus's holder can bring this about on purpose, and gains only that ordering. It is accepted, because a forged flood must stay bounded, and a larger bound only moves the threshold (REPRODUCED);
    - a consumer's transaction not yet committed when the observer fires reads alive, which releases the queue (UNREPRODUCED); and a shared bus that delivers the signal before the end cannot be held for, so ordering there is best effort.
- **Timers:** `session_expiring`, expiry and `assurance_lapsed` come from the held deadlines and `authenticatedAt` through a single timer per stream, armed for the earliest of what has not yet been sent, and re-armed after every reload, moved or not, so that a clock step is corrected.
- **A timer reloads before it speaks** (failure sweep, 2026-11-04). Held deadlines can be a whole heartbeat stale, so a timer alone would tell a user who is working that their session ended. On any timer the stream reloads first. It ends only if the store agrees; on a store failure only the *absolute* deadline ends it, because the idle deadline may have moved in a store it cannot read. If the store says alive while the local clock says past, the timer re-arms no sooner than the next heartbeat, so it cannot spin. `SignInState` judges a deadline by the manager's clock, so where the chain and manager share a clock, as they normally do, a clock ahead reads as gone, and the stream says `expired` up to the skew early, and only within that skew of a deadline. That replica's `Load` refuses the session too when its store judges by the same clock; a store on its own clock may still answer, so a request can still succeed for the length of the skew. A chain on a clock of its own stays open.
- **Equal or absent values:** when the two deadlines are equal, `session_expiring` names `absolute`, so a front end does not offer a "stay signed in" that cannot work. A zero `AuthenticatedAt` is sent as `null`, and is not treated as lapsed. A deadline already inside the warning window at open warns at once. "Once" holds per connection, so a reconnecting client hears it again.
- **A maximum age** (user's choice, 2026-11-04). Admission is judged once, so with no limit a stream outlives its bearer token, its certificate, and a policy that would now refuse it, for up to the 12-hour absolute default. `MaxAge`, default 1 hour with ±10% jitter, closes the stream with no event, and the client reconnects and is judged again. OWASP's DoS guidance asks for an absolute connection timeout, and it keeps a consumer under a proxy's hard limit. *Rejected:* closing at a token's `exp`, as Mercure does, because a short-lived token would make `fetch()` clients reconnect every few minutes. **Override:** the field, or `NoMaxAge`, whose godoc says what it gives up.
- **A disabled user** (user's choice, 2026-11-04). Disabling revokes nothing, so the session read sees no change. Each reload therefore also reads the user, doubling the reads per heartbeat. **Override:** `Users`, which defaults to the built-in bearer's loader, and is required when there is none.
- **Heartbeat jitter:** ±10% of the interval, so streams opened together do not reload together.
- **Override:** the heartbeat interval. The rule that the store decides has none, because trusting a message to end a session is exactly what this decision rejects.

```
            admit (D3) ──refused──► 400 / 401 / 403 / 405 / 501, no stream
                │       ├─a cap, or a dependency failure (D7)─► 200, `retry` only
                │       └─closing (D8)─► 200, `retry` only, connection closed
                │
                ▼
          register in registry (caps, D8) ──► send retry: 5000, then `session`
                │
                ▼
     ┌─────► wait ◄───────────────────────────────────────────────┐
     │        │                                                   │
     │        ├─ heartbeat tick ──► ":", then read ──┬─ unchanged ─────┤
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
  - **One option, shared with `oidc-provider`** (revised 2026-11-04, that change's R16). Both changes defined `session.WithEndObserver` differently, so one was agreed: `oidc-provider` built it, and this change builds on that commit and adds `AddEndObserver`, `Logout` and `SignInState`. `(*Sessions).ReportsEndsTo` comes with that commit: it is for `oidc-provider`'s wiring check, and nothing in this change calls it outside tests.
  - `session.EndObserver` is an interface with one method, `SignInsEnded(ctx, session.EndReport)`, with an `EndObserverFunc` adapter so a closure still fits. `session.WithEndObserver` is repeatable.
  - `EndReport{Cause EndCause, User identity.UserID, Family id.ID, KeptFamily id.ID, ExternalIssuer, ExternalSessionID string, At time.Time}` is reported after each successful end. It carries no session identifier.
  - The causes, the calls that raise them, and the `session_ended` reason this change sends for each. `session` knows only the cause. The wire reason is this change's, and the hub maps it:

    | Cause | Raised by | Report names | Wire reason |
    |---|---|---|---|
    | `EndLogout` | `Logout(user, family)`, which the chain's logout calls | user and family | `logout` |
    | `EndDeleted` | `Delete(id)` | user and family, from a load before the delete, made only when an observer is set | `ended` (R7) |
    | `EndByHandle` | `EndSignIn` | user and family | `ended` |
    | `EndReuse` | reuse detection, after `Store.DeleteFamily` | user and family | `reuse` |
    | `EndFamilyRevoked` | `RevokeFamily(family)` | family only | `ended` |
    | `EndUserSessions` | `DeleteByUser` | user, no family | `all_ended` |
    | `EndUserSessionsExcept` | `DeleteByUserExcept` | user, no family, the spared family as `KeptFamily` | `all_ended` |
    | `EndOtherSignIns` | `EndOtherSignIns` | user, no family, the spared family as `KeptFamily` | `all_ended` |
    | `EndUserExternalIssuer` | `DeleteByUserAndExternalIssuer` | user, issuer, no family | `provider_logout` |
    | `EndExternalSession` | `DeleteByExternalSession` | issuer and upstream session, neither user nor family | `provider_logout`, routed by a third registry key, a digest of issuer and upstream session |
    | (not reported) | `DeleteExpired`, a deadline passing | a deadline is not an event | |

  - **Logout gets its own cause** (user's choice, 2026-11-04). The chain's logout ends the family through `RevokeFamily`, deliberately, so that the successor of a renewal goes too. That reports no user, and the draft mapped it to `reuse`, so every ordinary logout would have told the user's other tabs that their credentials were stolen (REPRODUCED, and pinned by `TestLogout_ReportsLogoutCause`). `Logout` ends the family in the same way and names the user. Only `EndReuse` ever says `reuse`. *Rejected:* mapping `EndFamilyRevoked` to `logout`, which would mislabel an administrator's revocation.
  - **Back-channel logout reaches the stream** (failure sweep, 2026-11-04). Its preferred path is `DeleteByExternalSession`, which names neither user nor family, so dropping its report would make the stream learn a heartbeat late, with the wrong reason. OpenID Connect Back-Channel Logout says `sid` is opaque and need only be unique per issuer, and does not call it confidential; a forged one gains nothing, because an end only triggers a reload. It still identifies a session upstream, so it stays out of bus payloads and logs: a stream holds, and the envelope carries, `Upstream`, the SHA-256 of issuer, a separator and `sid`. An unkeyed hash is enough, because the aim is to keep the raw value out of a broker's logs and replays, not to resist guessing.
  - **A report naming no one** (`EndDeleted` after a failed read) reaches no stream, and the heartbeat ends it. A nil `KeptFamily` means nothing was spared: every stream of the user is woken and reloads, and the store keeps the live one open.
  - **A bulk end is one report** (settled while planning, 2026-11-02). Listing the sign-ins first would cost a read per bulk delete and race the delete. The stream reloads anyway (D4), so a report that names only the user is enough to wake every stream of that user.
  - **`KeptFamily` for `DeleteByUserExcept`** (corrected 2026-11-03). That call keeps a *session*, not a family, and a report carries no session identifier. When an observer is set, the manager loads the kept session first and reports its family. `EndOtherSignIns` already holds the current session, and reads its family without a load.
  - **The observer's context** keeps the caller's values but not its cancellation, as the reuse observer's does, so a client that hangs up cannot drop the report.
  - Panics are recovered and logged without the report's contents, the next observer still runs, and an observer has no error to return, as with `WithReuseObserver`. Observers run synchronously, in the order given, so the hub's never blocks.
  - `EnableSessionSignals` adds the hub's observer to the session manager the chain uses, beside any the consumer gave. It no longer refuses a manager with an observer, and `session.EndObservers` is gone, since the option is repeatable.
  - **How it is added** (found while aligning, 2026-11-04). The plan said "install", and no exported call could do that to a built manager from `httpsec`. `(*Sessions).AddEndObserver(EndObserver) error` does, refusing a nil observer with `ErrConfig`. It is for wiring at chain construction, and copies the list on write, so a report running meanwhile is not a data race. *Rejected:* asking the consumer to pass the hub through `WithEndObserver`, which breaks this change's no-wiring default, because the hub does not exist until the chain is built.
- **`credential_changed`:**
  - raised by the chain's own endpoints, after their write succeeds: password-change resolve (`password`), passkey registration and removal (`passkey`), MFA enrolment confirmation and email redemption (`second_factor`), and a recovery's completion, for what it removed;
  - **a recovery reports what it removed** (user's choice, 2026-11-05; corrected from "`password` or `second_factor`, as the recovery replaced"). A recovery removes authenticators by kind, and the built-in kinds are `mfa` and `passkey`, so it never removes a password; one bound afterwards raises through password change. `recovery.Result` said nothing of what went, so it gains `Removed []AuthenticatorRef`, the list the notice already uses, and `passkey.RecoveryKindName` names the kind. The chain maps `mfa` to `second_factor` and the passkey kind to `passkey`, once per kind. A consumer's own kinds raise nothing, because the signal's kinds are a closed set, and no reference reaches a stream. By default a recovery ends the other sign-ins, so their streams hear `session_ended`; only `WithoutSessionRevocation` leaves a stream to hear this. Completion includes finishing a held recovery, and a hold itself raises nothing. *Rejected:* raising nothing and leaving it to `ReportCredentialChange`, which narrows the spec and leaves a consumer unable to tell what went. **Limit, stated** (review, 2026-11-05; made by the main session while the user was away): a recovery that fails after removing one kind keeps that removal, returns an error and no `Result`, so it raises no signal and sends no notice (REPRODUCED by the review's `TestRepro_RemovalFailsPartway_StreamsNotTold`, in a disposable copy). The signal and the notice agree, and the request reports its failure. *Rejected:* a typed error carrying the partial removals, which is new API for a rare path;
  - **no endpoint removes a second factor** (found 2026-11-04; the draft listed one). `httpsec` has none: removal happens in a recovery, above, or in the consumer's own code, which reports it through `ReportCredentialChange`;
  - for changes the consumer makes outside those endpoints (an admin console, a password reset of its own), `chain.ReportCredentialChange(ctx, userID, kind)` raises the same library signal;
  - it is the one library signal a consumer may raise, because the change happened in the consumer's code;
  - **a stream the same change ends does not hear of it** (failure sweep, 2026-11-04). Removing a passkey and finishing a recovery end the user's other sign-ins, so those streams close with `session_ended`, and that is what tells them. The signal reaches every stream *still open*.
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
    Upstream string        // SHA-256 of issuer and upstream session, for a provider's logout (D5)
    Name   string
    Reason string          // session_ended only
    Data   json.RawMessage
}
```

- **One subscription per replica,** not per stream. The chain keeps a local registry `user → streams` and `family → streams`, and hands each envelope to the streams it names (D5's diagram).
  - This lets a Redis or PostgreSQL bus use one channel, not one per user.
- **The default bus** delivers only within the process. With several replicas and no shared bus, `session_ended` still arrives within a heartbeat and half a second (D4). `credential_changed` and the consumer's signals reach only the streams on the replica that raised them. The godoc says so, as the rate limiter documents its N-replica limit.
- **A failing `Publish`** is logged with sampling and never changes the outcome of the request that raised it. A failing `Subscribe` is retried with backoff, from 1 second doubling to 30 seconds, while the heartbeat keeps ending streams. A `Subscribe` that returns early with no error is treated as a failure, and a panic in either is recovered, so that a consumer's bus cannot take down the process.
- **A hanging `Publish` cannot hang a logout** (failure sweep, 2026-11-04). Observers run synchronously in the caller's transaction, so publishing inline would turn a bus outage into a logout outage, holding row locks while it waited. A consumer's bus is therefore fed from a bounded queue by one publisher goroutine, with a timeout per `Publish`, on a context with none of the request's values. Overflow drops the message with a sampled log and a counted drop; a consumer-raised signal returns `ErrSignalsBusy`. The default bus needs none of this: it hands each stream a non-blocking send inline.
  - Google's SRE guidance on cascading failures is to reject early when a queue is full and to set deadlines. Shared buses are themselves lossy: Redis Pub/Sub is at-most-once. No source sets a size or a timeout, so 1024 and 5 seconds are judgments, and they are options.
  - **What a drop costs.** A dropped `session_ended` costs at most a heartbeat and half a second, because the store decides. A dropped `credential_changed` or `app.*` is gone, and a consumer must not rely on one alone: the out-of-band notices stay the record that NIST asks for. The godoc says so.
  - **Override:** `BusQueue` and `BusTimeout`.
- **Goroutine lifetimes.** The publisher and the subscription start at the first stream or the first raised signal, and the default bus starts neither, so a chain with signals enabled and never used leaks nothing. After `CloseSessionSignals`, `deliver` and `raise` do nothing, and a chain's observer stays on its manager, as `AddEndObserver` documents, inert. A consumer's transaction that rolls back after a report causes one extra reload, and no false end. A `credential_changed` raised before a consumer's own transaction rolls back cannot be recalled: `ReportCredentialChange`'s godoc says to call it after commit.
- **What a shared bus's holder can do** (review, 2026-11-04). A forged end cannot end a stream, and a forged signal is revalidated. But re-forging `reuse` inside its window could label a real end as theft, and flooding wakes costs store reads up to the stream's limit. So the port's godoc asks a shared bus to authenticate its transport, and this is the reason why. A consumer's log handler that blocks can hold a raising call on a sampled record, as on every chain log path, so `WithLogger`'s godoc asks it not to block. `Publish` that ignores its context keeps the publisher goroutine, and `CloseSessionSignals` does not wait for it, since a goroutine cannot be killed: the queue fills and later signals are dropped and counted. An envelope still queued at close is lost.
- **An envelope from the bus is untrusted.** A `session_ended` only triggers a reload (D4), and its `Reason` is checked against the known reasons before it is kept. Of the other library signals, only `credential_changed` is ever delivered from the bus, since a stream's own timer raises `session_expiring` and `assurance_lapsed`, and only when its kind is known, its data parses, and it is no more than 8 KiB. `app.` envelopes are held to the `PublishSignal` limits again on receipt.
- **Override:** the port.

### D7. The wire format

- The first bytes are `retry: <ms>` and then the `session` event. The value is `ReconnectDelay` ±30%, rounded up to at least 1 ms, chosen per stream (failure sweep, 2026-11-04): a replica's streams close together on a deploy, and a fixed value would bring them all back at the same moment. The heartbeat's jitter does nothing for that. `retry` is the only delay a server can set on `EventSource`.
- Each event is `event: <name>\ndata: <json>\n\n`, with no `id:`. A heartbeat is `:\n\n`.
- The data:
  - `session`: `{"idle_deadline", "absolute_deadline", "authenticated_at"}` in RFC 3339, UTC;
  - `session_ended`: `{"reason"}`;
  - `session_expiring`: `{"deadline":"idle"|"absolute","at"}`;
  - `assurance_lapsed`: `{"authenticated_at"}`;
  - `credential_changed`: `{"kind":"password"|"passkey"|"second_factor"}`;
  - `app.*`: the consumer's JSON, unchanged, on one `data:` line. JSON escapes line breaks inside its strings but allows them between tokens, so `PublishSignal` refuses data holding a raw one (REPRODUCED: `json.MarshalIndent` output is valid JSON holding LF).
- **No raw CR or LF reaches the wire inside a field.** The event writer refuses, and does not send, an event whose name or data line holds one. That is a second check behind D2's name shape and the JSON rule, so a later change cannot reopen the injection.
- Headers: `Content-Type: text/event-stream`, `Cache-Control: no-store, no-transform`, `X-Accel-Buffering: no`. `no-store` keeps the stream out of every cache (RFC 9111 §5.2.2.5). `no-transform` asks intermediaries not to compress it (*unverified:* RFC 9111 §5.2.2.6 was not read). Middleware differs, as the conformance suite shows: fiber's compress middleware honours it and leaves the stream alone, while `gzhttp` compresses the stream anyway, and its events stay readable because each flush goes through it. `X-Accel-Buffering` works only where the operator's proxy honours it, and the README says so.
- **Reconnection follows WHATWG's rules.** Any response other than 200 with `text/event-stream` fails an `EventSource` for good, and a dropped connection makes it reconnect after `retry`. So every answer is chosen for what the browser does next:

  | Answer | The browser then | Used for |
  |---|---|---|
  | 200, stream, then the connection closes | reconnects after `retry` | shutdown (D8), `MaxAge`, a client-side drop |
  | 200, only a longer `retry`, then close | reconnects after `retry` | a cap reached, a dependency failure at admission, a per-request throttle of the sign-in (R1) |
  | 200, `session_ended`, then close | reconnects, and gets 401 | an ended sign-in |
  | 401, 403, 400, 405, 501 | stops for good | refusals that a retry would not change |

  **A refusal a retry could fix is not final** (user's choice, 2026-11-04). A 429 or a 5xx ends an `EventSource` for good, and `EventSource` cannot see a status, so a client cannot tell them from 401. A phone that changes network can meet its own dead streams at the cap, and a store blip at admission would stop every tab that reconnected during it. So a cap refusal and a dependency failure on the stream's path answer 200 with only `retry: <BusyDelay ±30%>` and close, caught for the dependency failure by an outer step on this path alone. A rate limit a consumer's own interceptor answers is the consumer's. *Rejected:* keeping 429 with a client probe, because a client that does not copy the snippet dies; and evicting the oldest stream, because five live tabs would evict each other every few seconds. The trade-off: a fifth tab keeps retrying at a low rate, and a `fetch()` client sees a 200 with no `session` event, which the godoc states and `SessionSignalStats` counts. The README's client, which must rebuild a dead `EventSource` for sleep and network changes, probes an ordinary endpoint first, so a 401 stays final.
- **How the dependency failure is caught.** A step at `After(OrderCORS)`, on this path and method alone, wraps everything that reads a store, including a consumer's `CookieAuthenticator` just inside CSRF, and acts on the way out. A failure means an error `StatusForError` maps to 5xx, other than `ErrStreamingStarted` and `ErrStreamingUnsupported`. Only the context as the request entered this step says a client left, because an inner interceptor may cancel its own on the way out (REPRODUCED: a live `EventSource` got a 500). Once that context is cancelled, any error counts as a hang-up, however a store words it, so a real outage on a request whose client has gone is uncounted, and others count it. An entry context past its deadline is a server's own, and stays a dependency failure (REPRODUCED). The answer is written even if the request's context has ended, since a consumer's interceptor may cancel its own on the way out (REPRODUCED: an empty 200). A response already begun is left alone.
- **`RetryableError`** (review, 2026-11-05; made by the main session while the user was away, and theirs to overrule). The step cannot tell a consumer's own refusal from an outage, so such an error is retried for ever at `BusyDelay`, counted as a failure, and skips the consumer's error handler (REPRODUCED). **Default:** nil retries every failure, because a store failure in a consumer's authenticator must not end an `EventSource` for good, and an access decision is unaffected, as no stream opens. **Override:** `SessionSignals.RetryableError func(error) bool`; false sends the error through the chain's mapping, which is final for a browser. A panic in it is recovered and logged without its value, and the failure retried. *Rejected:* retrying only errors the library marks, which sends a consumer authenticator's store failure back to a final 500. **Limit, stated** (review, 2026-11-05; made by the main session while the user was away): `authenticate.ErrUnavailable` from a consumer's authenticator maps to 401, not 5xx, so it stays final for a browser (REPRODUCED). That 401 stops an account-existence oracle for Basic and a consumer's own credentials, which reach this path too, so it is not weakened here (R2). The godoc and README tell such a consumer to return an error that maps to 5xx on this path.
- After `session_ended` the stream closes. The browser's reconnection then gets 401, which ends `EventSource`'s retries.
- **Override:** none for the format. It is the contract front ends code against.

### D8. Caps and shutdown

- The caps are kept in the local registry and counted per replica. With N replicas, a user can hold N × `MaxPerUser` streams, which the godoc states.
- A request over a cap gets 200 with only a longer `retry` (D7), and is charged to nothing. Inside the library this is `ErrTooManyStreams`, and it is logged with sampling at WARN.
- **A place is freed exactly once, whatever ended the stream.** `Stream` promises that if it returns nil its body runs exactly once, on a cancelled context when the chain refused, because on fiber the place is taken in the chain and the body runs after it returned (REPRODUCED, and pinned by `TestFiber_Stream`'s refusal row). The place is also freed when `Stream` returns an error. A release is idempotent, and empty registry keys are removed.
- **One party cannot be stopped from filling a replica by the three caps alone:** 625 accounts at 16 streams fill 10 000 places. `MaxPerSource`, off by default, caps streams per client address, as the chain resolved it. Behind a proxy with no trusted-proxy setting every client shares one address, so it stays off by default.
- **`MaxPerSource` is off by default, which is common practice.** OWASP's WebSocket sheet prefers per-user limits, with per-IP where a user cannot be identified. The per-user caps are on, and Mercure's own per-client limit is off by default too. Mercure answers 429 over a cap; scrty's 200 is a deliberate departure (D7).
- **`chain.SessionSignalStats()`** returns `{Open, RefusedByCap, ReloadFailures, Throttled, ConsecutiveReloadFailures, BusSubscribed, BusDropped, BusPublishFailures, StreamDropped}`, so an operator can see a cap being hit, a mis-wired tenant, a bus falling behind, or a slow stream. `BusDropped` counts what a consumer's bus could not take, and `StreamDropped` what a stream's own queue dropped, because one stalled tab must not read as a bus falling behind. It reads counters and takes no lock on the delivery path. Its godoc says the counts are for operators, not untrusted callers. *Rejected:* keeping "wrap the bus" as the only visibility, which shows none of these.
- **Logs** (standards review, 2026-11-04). A stream's open and close log at DEBUG with its user, family, client address, origin and close reason, and never a token or session identifier (OWASP's WebSocket sheet: log connection establishment and termination with user identity, IP and origin). These logs are the operator's: a client address never reaches a stream. Cap refusals and cross-site refusals log with sampling (ASVS 5.0 16.3.2 and 16.3.3). Refusals the chain already answers keep their existing records.
- **A panic in the stream's own code** (user's choice, 2026-11-04). The body recovers its own panics and logs through the chain's logger on every adapter, so a stream's panic reaches the logger the consumer chose, and on net/http and gin never reaches the standard library's logging of the panic value, which could carry a secret from a consumer's bus or loader (ASVS 5.0 16.2.5, 16.5.4; CWE-532). It logs the value's type, the phase (`stream`, `reload`, `bus`), the family, and the frames as function, file and line, and never the value: type alone would not say where or what (ASVS 5.0 16.2.1). The publisher and subscription goroutines do the same. The adapter's own recover stays as a backstop for a consumer who calls `Stream` directly, and writes to `slog.Default`, which its godoc states. *Rejected:* an exported `Chain.Logger()`, which is permanent API for one rare path, and an adapter option, which would have to be configured twice.
- **Override:** the four fields.
- **Shutdown** (settled while planning, 2026-11-02). `http.Server.Shutdown` waits for active handlers and does not cancel their contexts, so an open stream would hold it until its deadline. `chain.CloseSessionSignals(ctx)` ends every stream without an event, and returns when every body has returned or `ctx` ends. A stream requested afterwards gets 200 with only a `retry` line, and its response ends at once (on HTTP/1.1 the connection closes; on HTTP/2, Go's server takes `Connection: close` as a graceful GOAWAY for the whole connection, so requests in flight finish and a client's next request opens a new connection, corrected by review, 2026-11-05: `TestSessionSignals_Close_ConnectionOnTheWire`, `TestSessionSignals_Close_HTTP2GoAwaySparesARequestInFlight`). A store failing on a closing replica gets the closing answer too. *Changed from 503 by the security review, 2026-11-03:* WHATWG fails an `EventSource` for good on any non-200 answer, so a 503 during a rolling deploy would stop every client that reached the closing replica. A dropped stream makes the browser reconnect, and the load balancer then sends it to a live replica. A closed stream's last act is a fresh `retry` between 1 second and 3 × `ReconnectDelay`, so a drained replica's clients spread out; it is a field, not an event. A second call ends nothing new and waits on its own context for streams a first call timed out on. The README registers it with `RegisterOnShutdown`, which Go runs in its own goroutine and does not wait for, so `Shutdown` itself is what waits for handlers. On fiber, fasthttp's `Done()` at shutdown ends streams too. Without the call, streams end at the shutdown deadline as they would otherwise.

### D9. Concurrency inside one replica

- **One body goroutine per stream** (fiber adds its `Done()` watcher and connection reader, D1, and a read in flight has its own, D4). It `select`s over:
  - its context (the client left, a flush failed, or shutdown);
  - a read's result;
  - the heartbeat, re-armed with fresh jitter on each beat;
  - the single timer (D4);
  - a wake channel of capacity 1, which a bus `session_ended` fills without blocking, and which coalesces several wake-ups into one reload;
  - a queue of capacity 32 for `credential_changed` and `app.*`, whose arm closes while an end notice is unanswered (D4). One signal taken as a notice lands is parked and goes first when the hold ends.
- **The publisher never waits.** Raising a signal sends to each stream's queue with a non-blocking send. A full queue drops that event for that stream only, and logs with sampling. `session_ended` never goes through the queue: it comes from the stream's own reload, so it is never dropped.
- **The registry is one mutex around its maps:** `user → streams`, `family → streams`, `upstream digest → streams`, a per-sign-in count and a per-source count. Admission checks every cap and registers under the same lock, so two requests racing for the last place cannot both get it. Delivery copies the target streams under the lock and sends after releasing it.
- **Writes happen only in the body goroutine,** so no event can interleave with another or with a heartbeat.
- **Default and override:** the queue of 32, the wake channel of 1 and the one-a-second wake gap have no override, and neither has D2's 8 KiB on consumer data. They bound what one stream or one message can cost a replica, and no consumer's policy turns on their values. Past the queue a stream drops only its own events, and a signal is meant to be a short pointer. Asking for an option is free, once a real front end shows a need.

### D10. Status before and after the stream starts

| When | Condition | Answer |
|---|---|---|
| before streaming | stream not enabled | the request passes through to the consumer's routes |
| before streaming | `Stream` reports `ErrStreamingStarted` (a consumer's interceptor already wrote) | the chain's error mapping, as a 500 |
| before streaming | method other than `GET` | 405, with `Allow: GET` |
| before streaming | no credential | 401 |
| before streaming | authenticated without a sign-in | 403 |
| before streaming | a cross-site request from an origin not trusted (D3) | 403 `ErrCrossSiteStream` |
| before streaming | a pending sign-in | as the pending-session gate answers it |
| before streaming | `signals` over 16 names or 256 bytes | 400 |
| before streaming | a cap reached | 200 with only a longer `retry`, then the response ends (`ErrTooManyStreams` internally) |
| before streaming | a dependency failure at admission | 200 with only a longer `retry`, then the response ends |
| before streaming | a failure `RetryableError` declines (D7) | the chain's error mapping |
| before streaming | the adapter cannot stream, including a consumer's wrapper with no `Unwrap`, or `http.TimeoutHandler` | 501 `ErrStreamingUnsupported` |
| before streaming | after `CloseSessionSignals` | 200 with only `retry`, then the response ends |
| while streaming | any failure | the stream closes; the status was already sent |

- Every refusal but the two 200 answers goes through the chain's error mapping, as every other refusal does, so a consumer's error responder shapes the body. By default a consumer's own 5xx-mapped error is retried and does not reach it (D7). A responder must not redirect on this path: a redirect to a login page fails an `EventSource` for good, and the README says so.

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
| Caps, queue, heartbeat (D8, D9) | OWASP DoS Cheat Sheet (load limits, absolute connection timeout); OWASP WebSocket (per-user and total connection limits, heartbeats, backpressure); RFC 9113 §6.5.2; WHATWG (a comment every 15 seconds or so) | Complies. Streams are capped per sign-in, per user and per replica. Queues are bounded and drop slow clients' events. A client that stops reading is ended by the write deadline once the kernel's buffers fill, except for a stalled TCP connection over HTTP/2, which needs the server's `HTTP2.WriteByteTimeout` (D1). The absolute session deadline bounds every stream's life |
| Caching (D7) | OWASP Session Management (`no-store` for session data); RFC 9111 §5.2.2.5; nginx `X-Accel-Buffering` | Complies. The README notes that `X-Accel-Buffering` depends on the operator's proxy |
| The bus (D4, D6) | OpenID SSF 1.0 (authenticate transmitters, validate `iss`, ignore unknown fields); CAEP 1.0 | Complies with the practice. Neither standard prescribes an internal bus, so scrty treats bus messages as untrusted: an end only triggers a store check, other envelopes are revalidated, and the port's godoc asks a shared bus to authenticate its transport |

## Failure sweep (2026-11-04)

The user asked that everything that can go wrong be anticipated. The design was traced through the code, and production failures of long-lived streams were researched. Each row states what would have happened, and where it is now handled. "Reproduced" means a failing test against existing code; "unreproduced" means no code existed yet, and its first task wrote the test. The statuses are as they stood on that date; each row now has its test.

| What goes wrong | What would have happened | Handled by | Status |
|---|---|---|---|
| A renewal or step-up while a stream is open | The stream's own reload revokes the live sign-in, or reports it ended | D4, `SignInState` | Reproduced |
| An ordinary logout | Other tabs told `reuse` | D5, `EndLogout` | Reproduced |
| A chain that refuses after `Stream`, on fiber | A place leaks, and shutdown waits for a body that never runs | D8, D1's promise | Reproduced |
| A request-scoped transaction | Held open for the stream's life, or closed under every reload | D4, `ReloadContext` | Retention reproduced; consequences unreproduced |
| `json.MarshalIndent` data | Accepted, then dropped by the writer | D2, D7 | Reproduced for the standard library |
| A fetch client reconnecting with a token captured before a renewal | The family is revoked | README: read the current credential on each attempt | Revocation reproduced |
| `go test -run` matching no test | The verify command stays green | `tasks.md`: `-v`, and the named tests must appear | Reproduced |
| A timer firing on a stale deadline | An active user told their session ended | D4 | Unreproduced |
| A store that hangs instead of failing | Heartbeat, timers and queue all stop | D4, reload timeout | Unreproduced |
| A hanging bus | Logout hangs, holding row locks | D6, publisher queue | Unreproduced |
| A forged or stale report | A later real end is given the wrong reason | D4, D6 | Unreproduced |
| A wrapper with no `Unwrap`, or `http.TimeoutHandler` | Looks like a client leaving, so the browser reconnects forever | D10, 501 | Unreproduced until dispatch A's row |
| A replica draining | Every client reconnects at the same moment | D7, D8, jittered `retry` | Unreproduced |
| A panic in a consumer's bus | The process dies | D6, D8 | Unreproduced |
| A panic in a stream's own code | The value reaches the standard library's log, or the wrong logger | D8 | Unreproduced |
| A tenant-scoped store with no `ReloadContext` | A stream that never hears of an end | D4: fails at admission | Unreproduced |
| A retired sealing key | The stream stays open | `ListByUser` opens no sealed field; a row confirms it | Unreproduced |
| Compression above the adapter | Nothing arrives, no write fails, the place is held | D7 `no-transform`, a test per adapter, README | Unreproduced |

**Handled by documentation, because the consumer owns the setting.** The README gains: intermediary timeouts (nginx 60 s, ALB 60 s, CloudFront 30 s between packets, API Gateway's hard 15-minute limit, and Envoy's route timeout, which must be set to `0s`); compression middleware; `http.Server.HTTP2.WriteByteTimeout`; TCP keepalive and dead peers; `SETTINGS_MAX_CONCURRENT_STREAMS` (Go's default of 250) when a gateway shares one upstream connection; fasthttp's `Concurrency`, which counts every stream, and `MaxConnsPerIP`, which counts connections; pod termination (`terminationGracePeriodSeconds` longer than the shutdown context, and a `preStop` wait); buffering corporate proxies; and a client that rebuilds on `visibilitychange`, `pageshow` and `online`, because iOS and Firefox can leave a dead `EventSource` with no error, and a client that falls back to polling when the first `session` event does not arrive. `StripPrefix` means `Path` is the inner path.

**Checked and found not to apply.** A DPoP proof expiring mid-stream (a proof is per request, checked at open). `Server.ReadTimeout` and `IdleTimeout` ending a net/http stream (source reading only). A BOM (the stream sends none). An event split across flushes (no flush splits one, and an unterminated event is discarded). Odd casing in `Sec-Fetch-Site` (falls to the refusing branch). bfcache and `no-store` (no source ties it to a subresource). Read-replica lag producing a false "gone" (it would also 401 ordinary requests, so the store contract already rules it out). `MaxStreams` per-family counting across rotation (rotation keeps the family).

## Review of the sweep's decisions against standards (2026-11-04)

The user asked that each decision the sweep made be checked for compliance with security standards and common practice, and evidence against each was sought. None conflicts. "Judgment" means no standard sets the value. The changes are recorded in the decisions they touch.

| Decision | Checked against | Verdict |
|---|---|---|
| Panic logging (D8) | ASVS 5.0 16.2.1, 16.2.3, 16.2.5, 16.3.4, 16.5.4; OWASP Logging; CWE-532 | **Changed.** Type alone was too little to diagnose, so phase, family and frames are added. Stricter than Go's `net/http`, which logs the value |
| A timer checks the store first; only the absolute deadline ends a stream during an outage (D4) | ASVS 5.0 7.3, 7.4.1, 16.5.2, 16.5.3; NIST SP 800-63B-4 (session); OWASP WebSocket (re-validate periodically); CAEP 1.0 (no receiver action) | Complies. It is a notifier and grants nothing; OWASP's "close on expiry" holds once a reload answers. `MaxAge` bounds an outage |
| A clean reload context (D4) | OWASP Multi-Tenant; Go `context` | **Changed.** The first read uses it too, so a missing tenant fails closed at admission |
| A bounded bus queue that drops (D6) | Google SRE; Redis Pub/Sub; SSF 1.0; AWS Builders' Library | **Changed.** Sizes are options, and drops are counted. The sizes are a judgment. NIST AU-5 was not read; this is not the audit feed |
| A reload timeout (D4) | CWE-1088; Google SRE; AWS Builders' Library | **Changed.** Configurable, clamped, and one budget for both reads. The fraction is a judgment |
| Upstream session routed on the bus (D5) | OIDC Back-Channel Logout 1.0; OWASP Session Management; SSF 1.0 §10.1 | **Changed.** A digest travels instead of the raw value, and D6's envelope gained the field it lacked |
| Per-source cap off; stats (D8) | OWASP WebSocket, DoS; Mercure | Complies. The godoc says stats are for operators |
| Cross-origin rule by credential type (D3) | Go `http.CrossOriginProtection`; web.dev; OWASP CSRF; MDN CORS | Complies, and stricter than each. **Changed:** `*` now counts for an `Authorization` stream. No `Origin` or `Sec-Fetch-Site` passes, as in both references |
| Consumer data one line of UTF-8 JSON, refused (D2) | WHATWG; CWE-117; RFC 7493 | Complies. Duplicate keys are not refused: nothing requires I-JSON here, and the library does not interpret consumer data |
| `session_ended`, not `credential_changed`, for a stream the change ended (D5) | ASVS 5.0 7.4.3; CAEP 1.0; OWASP Session Management | Complies. Terminating is stronger than the option ASVS asks for. No reason or kind is added, so a thief is not told what the victim did |
| `retry` ±30% (D7) | WHATWG; AWS Builders' Library and jitter article | No standard applies. Compatible with the guidance, and ±30% is a judgment. Only the library sets `retry`, so a consumer cannot abuse it |

**What standards ask that the design lacked, now added:** logging refused cross-site streams (ASVS 16.3.3), which D3 adds; documenting concurrent-session limits and what happens at them (ASVS 7.1.2), federated session coordination (7.1.3) and the log destination (16.2.3), which the README's operator section adds; and saying that the chain's authorizer never runs for a stream, as D2 states, so what is judged below the slot is judged again only at a reconnection, bounded by `MaxAge`, which the README adds.

**Where no standard was found:** the queue size, the publish timeout, the reload fraction, the `retry` spread, and whether a notification stream stays open during an outage. These are judgments, labelled as such.

## Whole-branch review (2026-11-05)

Task 8.3, by a reviewer that wrote none of it, against all 53 requirements of the five spec deltas, D1 to D10 and the three tables above, on the tree rebased onto `main`. No high-severity defect. What it found, and where each went:

| Finding | Status | Resolution |
|---|---|---|
| A user store's text reached a returned error at a stream's first read, against the library's promise | REPRODUCED | Fixed: `TestSessionSignals_Caps_FirstReadReturnsNoDependencyText` |
| A consumer authenticator's `authenticate.ErrUnavailable` is final for a browser on the stream's path | REPRODUCED | A stated limit (D7), and documented |
| A back-channel logout of every session says `all_ended`, where the README said `provider_logout` | REPRODUCED later, on the wire (R6) | The README states both, and the spec settles it |
| Artifacts and the README had drifted from the code | Reading | Corrected |

Real conditions, which earlier reviews showed find what doubles do not: `gzhttp`, httpsnoop, otelhttp, chi and gin in `TestReal_`; the README's clients through their harness; and 58 checks with Node's real `EventSource` and `fetch` against real listeners on all three adapters. All passed. **Not run:** a real browser, so Fetch Metadata is covered by Go tests only.

The final gate then passed on the final tree: every module's suite with `-race`, at `-parallel 4` because PostgreSQL cleanup times out at the default on a heavily loaded machine; `go vet`, `gofmt` and `go mod tidy -diff`; and `govulncheck`, which finds no reachable vulnerable code. It reports advisories in required modules that are not called, at versions this change did not touch.

## Review of the pull request (2026-11-05)

The user asked for a code review and a security review of #73, then for every finding to be triaged for proof before these artifacts changed, and then fixed. The security review reported no vulnerability at its bar. The tests named below ran in disposable copies, and each becomes the red step of its task in group 9.

| Finding | Status | Decision |
|---|---|---|
| A policy's `ratelimit.ErrThrottled` is final for a browser | REPRODUCED: `TestTriageT1_PolicyThrottleIsNotFinal`, `expected: 200, actual: 401`, 30 of 30 | R1 |
| `authenticate.ErrUnavailable` is final for a browser | Stated behaviour | R2: stays |
| An `Origin` of any size is held for a stream's life and logged whole | REPRODUCED: `TestSessionSignals_Triage_OpenRecordQuotesAnUnboundedOrigin`, length 1 048 583 against a cap of 256 | R3 |
| `credential_changed` crosses a shared bus when no stream can send it | REPRODUCED: `TestChain_Triage_ReportCredentialChangeOnDefaultSetPublishesToBus`, and one returning `ErrSignalsBusy` | R4 |
| A user-wide report names a sign-in it did not end | REPRODUCED: `TestSessionSignals_BusWakeUp_UserWideReport`, `expected expired, actual provider_logout`, 30 of 30 | R5 |
| A subject-only logout under `BackchannelLogoutScopeAll` says `all_ended` | Stated behaviour, now shown on the wire by `TestTriageT5_ScopeAllSaysProviderLogout` | R6: stays |
| `EndDeleted` says `logout` | Stated behaviour, shown by `TestTriageT6_DeleteDoesNotSayLogout` | R7: changes |
| Each reload lists all of a user's sessions | Confirmed, by a benchmark | R8 |
| Four mechanisms take back a `Content-Type` set too early | Confirmed | R9 |
| A second lookup of the endpoint | Confirmed | R10 |
| The panic-frame walk and `endedWriter` exist in two copies, and the stream's headers in two places | Confirmed: `endedWriter` is identical, and the frame walks differ | R11 |
| Two tenants sharing a `UserID` hear each other's signals | REPRODUCED: `TestSessionSignals_Triage_PublishReachesOnlyTheTenantOfTheCaller`, but no defect | R12 |

- **R1. A throttled sign-in is told to retry.**
  - A consumer's policy denying with `ratelimit.ErrThrottled` at `PerRequest` maps to 401, which ends an `EventSource`, though a retry would succeed. D7's "a rate limit a consumer's own interceptor answers is the consumer's" does not cover this, because a policy cannot write its own answer. No library policy denies this way, so this takes a consumer's policy.
  - **Default:** on the stream's path, an `ErrThrottled` denial from the chain's per-request policy evaluation of the published sign-in (`EvaluatePerRequest` included) answers 200 with only `retry` at `BusyDelay` ±30%. It has its own sampled log record, is counted in a new `SessionSignalStats.Throttled`, and is not counted in `ReloadFailures`, because no dependency failed. Any other `ErrThrottled` goes through the chain's mapping, with a sign-in beside it or not, so Basic, an API key and a concealed lock keep their answers. A first version took any `ErrThrottled` with a sign-in published, and a review reproduced the oracle that opened: `ex.Session` says who is signed in, not whose credential was refused, so a caller with a sign-in of their own could tell right from wrong (200 against 401; `TestSessionSignals_Caps` holds those rows now).
  - **How:** the denial carries an unexported mark, on this path only, so a consumer's `errors.Is` still matches and `==` does not; `EvaluatePerRequest`'s godoc says so. A sticky flag on the exchange was rejected: a throttle passed over would then read as a later credential's refusal.
  - **Limit, stated in the godoc (REPRODUCED):** a consumer that verifies a password on every request, publishes a session, and uses a per-request policy as a guess throttle answers 200 against 401 on this path. A per-request throttle fires only after a credential succeeded, so a limit on guesses belongs at pre-authentication or stateless; `RetryableError` returning false restores the chain's mapping.
  - **Override:** `RetryableError` is asked about it, given the policy's own reason, and false sends it through the chain's mapping.
  - **429 stays final.** A consumer's 429 is an answer it chose, and tests pin that.
- **R2. `ErrUnavailable` stays 401** (settled in `http-error-propagation`; no decision to the contrary was found in this change or in `oidc-provider`). Retrying it "unless the request carries Basic or an API key" was proposed, tried and rejected: the library cannot see a consumer's own account-naming credential, and such a request then answered `known=200 unknown=401` (`TestTriageT2_ConsumerCredentialsAnswerAlikeForKnownAndUnknown`, 10 of 10 with the edit). `ErrUnavailable` comes only from the password provider, recovery and the API-key owner check, so a cookie authenticator gets it only by choosing it. **Override:** return an error that maps to 5xx, which is retried (`TestTriageT2_ConsumerRouteIsRetried`).
- **R3. A stream holds a capped `Origin`.** **Default:** `newStreamStart` cuts it to `crossSiteOriginLogLimit` (256 bytes), as the cross-site refusal does. Only logs read it, so a longer origin is only named in part. `Sec-Fetch-Site: none` passes with any `Origin`, so the size is the client's to choose. **Override:** none, because the value is the operator's diagnostic and no behaviour rests on it.
- **R4. A signal no stream can send is not raised.** **Default:** `credential_changed` is raised only when the chain's set holds it, so the chain's endpoints and `ReportCredentialChange` hand a broker nothing on a default set, and cannot answer `ErrSignalsBusy` for it. Every replica is expected to run the same set, and the godoc says so. **Override:** the set. `app.*` has no such case.
- **R5. A user-wide report names only a sign-in it ended.** `DeleteByUserAndExternalIssuer` wakes every stream of the user, so a password sign-in kept `provider_logout` for two heartbeats, and if it then expired or ended unreported it said so, against D4's table. **Default:** a notice from a report naming only a user is marked broad, and is cleared when a read begun after it answers alive; a read that failed or timed out clears nothing. A report naming an upstream session is not broad. A notice naming the stream's family or upstream session keeps its window, and a broad notice does not replace it inside that window, so a family's `logout` is not lost to another sign-in's report taken back. Any report with a known reason still holds the queue, kept or refused, as D4 requires. A user-only `reuse` is never taken back, because that would let a bus's sender erase a family's reuse. **Limits, all stated in the godoc and pinned by rows, each costing a label and never a wrong end:**
  - A report of a superseded session's deletion names a family that stays live, and it can still name a later end in its window (REPRODUCED). Clearing every notice would lose a report that arrives before its write is visible, which a test pins.
  - A real user-wide report that arrives ahead of its visible write, under a consumer's `WithTx` or replica lag, says `ended`, which is never false: this sequence is the same as another sign-in's report (REPRODUCED).
  - A user-wide report arriving during the wait for a report can name this stream's end, since that sequence is the same as a real `all_ended` following its write (REPRODUCED).
  - A real `all_ended` refused by a family notice that ended nothing says the family's reason, and one refused near the end of that window, whose gone is seen after it, says `ended` (REPRODUCED).

  **Override:** none, as for `streamReportGrace`: it protects a label.
- **R6. Scope-all says `all_ended`.** A stream under that scope fits two spec scenarios, and the spec now settles it: `all_ended` is accurate, since password sign-ins end too. The default scope and a logout naming a `sid` say `provider_logout`. **Override:** the scope.
- **R7. A deleted session says `ended`** (changed; made by the main session on the user's instruction to fix every finding). D5 rejected mapping `EndFamilyRevoked` to `logout` because it "would mislabel an administrator's revocation", and `Delete` did exactly that. The library's own logout uses `Logout`, and no production path calls `Sessions.Delete`. **Override:** a consumer's logout should call `Logout`, which also ends a renewal's successor, and `Delete`'s godoc says so. **Compatibility:** free before the first tag.
- **R8. A store may read one family.** A reload listed every live session of the user to find one family, so one unreadable row failed all of that user's sign-ins, and the memory store's cost grows with every session it holds (19.8 µs for 50 sign-ins among 1000 others, measured once, and it drifts). **Default:** `session.FamilyReader` is an optional interface beside `Store`: `ListByFamily(ctx, user, family, now) ([]*Session, error)`, which is `ListByUser`'s contract narrowed to one family. `SignInState` uses it when the store has it, and falls back to `ListByUser`. Every store in this repository implements it, and the sealing decorator delegates, falling back when what it wraps has none. The `sessions_family` index already exists, so no migration is needed. **Override:** a consumer's own `Store` gains nothing it must implement, and nothing breaks. **What it removes:** the undecodable-row limit, for another family's rows; a family's own row that will not decode still fails its read. The superseded-predecessor limit stays, because the contract is the listing's. **What it does not change:** the memory store's `ListByFamily` saves copying the user's other sign-ins and still scans every record, because the memory store has no index and this change adds none. **The nil family:** a family read answers it with nothing, where a listing may list a row stored in it, the one designed difference between the two; `SignInState` answers `ErrNotFound` before reading for the nil family, so it never reaches that difference. **A limit, stated in the godoc:** a store embedding a concrete store and overriding `ListByUser` inherits that store's `ListByFamily`, so it overrides both or embeds the `Store` interface. *Rejected:* a required `Store` method, which breaks every consumer's store for a saving.
- **R9. `Stream` takes the content type** (the user's instruction: not deferred; breaking, and free before the first tag). `Stream(ctx, contentType, body)` makes the type the adapter's to set, so no caller has anything to take back. That removes `unsetStreamType`, `responseHeaderRemover` and the empty-value contract on `SetHeader`. On net/http the question and the head can be the same call, a flush, so the writer sets the type before asking, and puts back what was there, a consumer's type included, on the two refusals where the head has not gone. **Limit, stated in the godoc and the spec:** a wrapper above the bottom can be asked only once the status is named (D1), so its late refusal reaches a client as 200 with the stream's type, and on gin with a render's body. This is unchanged by R9, and no real library is known to have this shape. **Changed:** a consumer's own `Content-Type` set before a refused `Stream` now stays on the refusal, where the old code removed it, since the consumer chose it. An empty type sets none. Fiber, whose `Stream` returns before the chain does, holds the type and sets it in `chainReturned` only when the chain did not refuse, replacing its delete. `Cache-Control` and `X-Accel-Buffering` still go before `Stream`, because they are right on a refusal or do no harm there. **Override:** none, as for the rest of the adapter contract. It touches every `ResponseWriter` double and about 95 test call sites.
- **R10. One source for the chain's endpoint.** `signalsEndpoint` returns `c.perRequest.signals`, guarded for a zero-value `Chain`, which still answers `ErrSessionSignalsDisabled` (`TestChain_Triage_ZeroValueReportsDisabled`).
- **R11. One copy.** The frame walk and `endedWriter` move to `internal/diag`, which `fibersec` can import. The copies differ today, 64 frames against 32 and newlines against `"; "`, so they become one: 32 frames, empty functions skipped, and `"; "` between them. Only a fiber backstop's log record changes. The stream's three headers go through one helper, with a constant for `X-Accel-Buffering`. Each log line keeps its own message and keys.
- **R12. A `UserID` must be unique across one chain.** No behaviour changes. `Store.ListByUser`, `DeleteByUser` and the lockout store assume this already, and the identity spec's example encodes its tenant. But `ReloadContext`'s godoc invites another reading, so it and the godoc of `PublishSignal` and `ReportCredentialChange` say: a multi-tenant consumer encodes its tenant into the `UserID`. Session ends route by family and are not affected. *Rejected:* a tenant-aware registry key, which is a breaking change no requirement asks for.

Also corrected by the triage: `checkOwner` runs only after a key has verified, so an API key is no part of `ErrUnavailable`'s oracle, and D7's limit says so now.

## Risks / Trade-offs

- **[Store load]** 10 000 streams at 15 s is about 670 session reads and 670 user reads per second per replica.
  → Jitter spreads them out. The interval can go to 60 s, and the README gives the arithmetic. A shared bus lets a consumer lengthen the heartbeat without delaying `session_ended`.
- **[Fiber write deadline]** The fiber design rests on resetting the connection's deadline per flush.
  → Task 1.2 established it on the pinned versions. A fiber or fasthttp upgrade could change it, and `TestFiber_StreamOutlivesWriteTimeout` would then fail.
- **[A stalled client over HTTP/2]** The adapter cannot bound a stalled TCP connection under Go's HTTP/2 server (D1).
  → The godoc and the README tell the consumer to set `HTTP2.WriteByteTimeout`. `CloseSessionSignals` is bounded by its own context.
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
- **[A refusal that hides a problem]** Answering 200 to a cap refusal or a dependency failure hides it from browser tools and status-code dashboards.
  → It is logged at WARN with sampling and counted in `SessionSignalStats`.
- **[A stream that follows a thief]** A stream follows its family across renewals it took no part in (D4).
  → `MaxAge` bounds it to an hour by default, and `app.*` godoc warns against sensitive data.
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
- [net/http HTTP/2 server](https://cs.opensource.google/go/go/+/refs/tags/go1.27.3:src/net/http/internal/http2/server.go), read in the local Go 1.27.3 tree on 2026-11-04: `onWriteTimeout` and `SetWriteDeadline`, the reason the write window outlasts the largest heartbeat.

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

**Failure sweep** (researched, accessed 2026-11-04; "read" unless marked)
- D1, D6: Go 1.27.3 `net/http` (`responsecontroller.go`, `server.go`, `http2.go`, `internal/http2/server.go`); fasthttp v1.77.0 `server.go`; [golang/go #52183](https://github.com/golang/go/issues/52183) (open: an HTTP/2 client leaving may be seen only at the next write); [fasthttp #1591](https://github.com/valyala/fasthttp/issues/1591) (open); [fiber #4145](https://github.com/gofiber/fiber/issues/4145) and [#4263](https://github.com/gofiber/fiber/issues/4263) (no disconnect signal in fasthttp; `Done` fires only at shutdown); [GO-2023-2102](https://pkg.go.dev/vuln/GO-2023-2102).
- D3: [CVE-2026-61593](https://corgea.com/advisories/vulnerabilities/CVE-2026-61593) (an SSE `GET` with no `Origin` check); [CVE-2026-46431](https://advisories.gitlab.com/golang/github.com/xyproto/algernon/CVE-2026-46431/) (`*` on an SSE endpoint); [Mercure spec](https://mercure.rocks/spec), first 100k characters (no `*` or reflection; closing at `exp`; a maximum connection lifetime).
- D7, D8: [AWS Builders' Library: backoff with jitter](https://builder.aws.com/content/3EumjoZascWd1oZiEgL8ORlv3qE/timeouts-retries-and-backoff-with-jitter); [Mercure hub configuration](https://mercure.rocks/docs/hub/config) (`write_timeout`, `drain_timeout`, `subscription_limits`); [Kubernetes pod termination](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination).
- README guidance: [nginx proxy](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) and [gzip](https://nginx.org/en/docs/http/ngx_http_gzip_module.html); [ALB attributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-load-balancer-attributes.html); [CloudFront origin settings](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesOrigin.html); [API Gateway streaming](https://docs.aws.amazon.com/apigateway/latest/developerguide/response-transfer-mode.html); [Caddy #6293](https://github.com/caddyserver/caddy/issues/6293); [Apple forum 765183](https://developer.apple.com/forums/thread/765183); [Mozilla 1251117](https://bugzilla.mozilla.org/show_bug.cgi?id=1251117); [Chrome Page Lifecycle](https://developer.chrome.com/docs/web-platform/page-lifecycle-api); [WebKit 202370](https://bugs.webkit.org/show_bug.cgi?id=202370); [web.dev bfcache](https://web.dev/articles/bfcache).
- Read through summaries only: [Istio and SSE](https://oneuptime.com/blog/post/2026-02-24-how-to-configure-istio-for-server-sent-events/view) and [Envoy and SSE](https://dzone.com/articles/thoughts-on-server-sent-events-http2-and-envoy-1); [LibreChat #12038](https://github.com/danny-avila/LibreChat/discussions/12038) on corporate proxies; [a Shopify thread](https://community.shopify.com/t/how-can-i-do-sse-and-auth-session-at-the-same-time-without-a-302-redirect/334742) on login redirects.
- *Unverified:* HAProxy's timeouts; RFC 9111's `no-transform`; the Fetch standard's redirect rules; whether a `retry` sent just before closing is honoured by every browser; Cloudflare's rule for whether data resets its 125-second timer.

**Review against standards** (researched, accessed 2026-11-04; requirement numbers in ASVS V7 and V16, the WebSocket and Multi-Tenant sheets and `go doc` were checked against the primary text by the main session)
- Logging: [ASVS 5.0 V16](https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md): 16.2.1, 16.2.3, 16.2.5, 16.3.2, 16.3.3, 16.3.4, 16.5.2, 16.5.3, 16.5.4. [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html). [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- Sessions: [ASVS 5.0 V7](https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x16-V7-Session-Management.md): 7.1.2, 7.1.3, 7.3, 7.4.1, 7.4.3. [NIST SP 800-63B-4, session](https://pages.nist.gov/800-63-4/sp800-63b/session/). [OWASP WebSocket](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html): re-validate sessions periodically, per-user limits preferred, log establishment and termination. [OWASP DoS](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html).
- Tenancy: [OWASP Multi-Tenant](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html). [Go `context`](https://pkg.go.dev/context#WithoutCancel).
- Bus and timeouts: [Google SRE, addressing cascading failures](https://sre.google/sre-book/addressing-cascading-failures/). [Redis Pub/Sub](https://redis.io/docs/latest/develop/pubsub/): at-most-once. [CWE-1088](https://cwe.mitre.org/data/definitions/1088.html). [Mercure hub configuration](https://mercure.rocks/docs/hub/config): `subscription_limits` off by default, `dispatch_timeout`.
- Back-channel logout: [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html): `sid`. [SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) §10.1.
- Cross-origin: [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection). [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS). [OWASP CSRF](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Input: [CWE-117](https://cwe.mitre.org/data/definitions/117.html). [RFC 7493](https://www.rfc-editor.org/rfc/rfc7493).
- Jitter: [AWS: exponential backoff and jitter](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/).
- *Unverified:* NIST SC-24, AC-12, AU-5 and SI-4; CWE-209, CWE-400, CWE-770, CWE-778; RFC 8259; the Fetch standard's credential text. NIST SP 800-63B-4 §4.1.2.1 was not re-read in this review. These were not read at source, and no decision rests on them alone.

**D8: `Connection: close` on HTTP/2** (read 2026-11-05)
- [net/http HTTP/2 server](https://cs.opensource.google/go/go/+/refs/tags/go1.27.3:src/net/http/internal/http2/server.go), read in the local Go tree, lines 2605-2616: the header starts a graceful GOAWAY.

**R1 to R12: review of the pull request** (2026-11-05)
- Reasoned from scrty's own settled specs and code, and the established design: `http-error-propagation` for R1 and R2, `identity-model` for R12. No external source was consulted, and the measurement in R8 was taken once, on a laptop.

**D2, D3, D5, D9, D10: the tree as it stands** (checked 2026-11-03, at `4649c90`)
- Reasoned from scrty's own settled specs and code, and the established design: the reuse observer and the ending calls in `sessions`; `sessionTouch` and the slot order in `http-security-chain`; the recency guards and their default window in `reauthentication`; and `close-security-gaps` D8 (the internal-set pattern), D12 (session management) and D13 (security events).
