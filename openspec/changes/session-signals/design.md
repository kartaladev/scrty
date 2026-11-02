# Design

## Context

See `proposal.md` for why, and the four spec deltas for the required behaviour. What shapes the approach:

- **The chain is an around-interceptor chain behind an adapter.**
  - `httpsec.ResponseWriter` today has `SetHeader`, `SetCookie`, `WriteHeader` and `Write`, and nothing streams.
  - On net/http and gin, an interceptor can block for as long as it likes, and the request context ends when the client leaves.
- **Fiber writes a streamed body after the handlers return.** Read from fiber v3.5.0 and fasthttp v1.73.0 on 2026-11-02:
  - `Ctx.SendStreamWriter(func(*bufio.Writer))` is the only streaming path, and it runs once the handler chain has returned;
  - fasthttp's `RequestCtx.Done()` closes only at server shutdown, so a client that leaves is seen only when a write or flush fails;
  - fasthttp sets one write deadline for the whole response before writing it (`server.go`, around line 2640). A per-request override exists only as a positive value, through the `HeaderReceived` hook the server owner sets.

  So a `Flush()` called inside the chain cannot work on fiber: whatever the handler writes is sent only when it returns.
- **Sessions are ended in the `session.Manager`.** It has delete, delete-per-user, family revocation on reuse, and provider logout. It already has one post-commit observer, `WithReuseObserver`, whose pattern this change follows.
- **`close-security-gaps` adds, before this change:**
  - session management (`EndSignIn`, `EndOtherSignIns`, D12);
  - re-authentication windows;
  - `CookieAuthenticator`;
  - the security-event emission points (D13).

  This change depends on that branch being merged.

## Goals / Non-Goals

**Goals:**
- One stream implementation in `httpsec`, run identically by three very different adapters.
- The session store as the only source of truth. A signal can wake a stream early, but it never ends one by itself.
- Bounded cost per stream: one goroutine, one timer, one store read per heartbeat.

**Non-Goals:**
- Delivery guarantees beyond "within one heartbeat": no acknowledgements, no ordering across signals, no replay.
- Redis and PostgreSQL bus implementations (follow-ups).
- A browser client library. The README shows `EventSource` for cookie sessions and a `fetch()` reader for bearer clients.

## Decisions

### D1. The adapters gain `Stream`, not `Flush`

```go
type ResponseWriter interface {
    SetHeader(name, value string)
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
  - each `Flush` sets the connection's write deadline to `now + 2 × heartbeat` through `RequestCtx.Conn()`, so the deadline fasthttp set once for the whole response does not cut the stream. *Unverified:* this rests on a later `SetWriteDeadline` on the `net.Conn` replacing the one fasthttp set. Task 1.1's first test establishes it on fiber before anything else is built.
- **Why not `Flush()` on `ResponseWriter`**, as the proposal first said: on fiber, it cannot deliver anything before the handler returns. A body function is the shape all three adapters can honour.
- **Breaking, before the tag:** a consumer's own `ResponseWriter` must implement `Stream`. A consumer adapter that cannot stream may return `ErrStreamingUnsupported`. The endpoint then answers 501, and the godoc says so.
- **Override:** none. This is the adapter contract.

### D2. The endpoint and its configuration

```go
signals := httpsec.SessionSignals{
    Path:          "/session/signals",                                         // default
    Signals:       []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring}, // default
    Heartbeat:     15 * time.Second,  // default; 5–60 s
    ExpiryWarning: 2 * time.Minute,   // default; > 0 and < the idle timeout
    MaxPerSignIn:  4,                 // default
    MaxPerUser:    16,                // default
    MaxStreams:    10_000,            // default, per replica
    Bus:           nil,               // default: in-process
}
chain, err := httpsec.New(..., httpsec.EnableSessionSignals(signals))
err = chain.PublishSignal(ctx, userID, "app.roles_changed", json.RawMessage(`{"roles":["editor"]}`))
```

- **Slot:** it is a terminal endpoint in a new slot, `OrderSessionSignals`, after every authentication slot and beside session management. Anything before it (headers, proxies, CORS, rate limits, authentication) applies as on any route.
- **Construction rules** (`library-design` rule 6):
  - a signal name outside the four;
  - a heartbeat outside 5–60 seconds;
  - a warning window of zero or less, or not shorter than the idle timeout;
  - a cap below 1;
  - `assurance_lapsed` without re-authentication enabled, since there is no window to lapse;
  - `EnableSessionSignals` given twice.
- **The query string:** `?signals=` is split on commas, at most 16 names and 256 bytes in all, and more than that is refused with 400. A name that is not in the chain's set is dropped.
- **`PublishSignal`:**
  - it returns `ErrSessionSignalsDisabled` when the stream is not enabled, `ErrInvalidSignal` for a name without `app.` or data over 8 KiB, and the bus's error otherwise;
  - it never blocks on a slow stream: each stream has a buffered queue of 32, and a full queue drops the event for that stream only.
- **Override:** every field, and the bus.

### D3. Who may open a stream

- The resolved `Authentication` must carry a session: a session reference, a signed bearer tied to a stored session, or a consumer's `CookieAuthenticator` session. Otherwise the answer is 401 (nothing authenticated) or 403 (Basic, API keys, or a token with no session).
- A sign-in still owing a second factor, enrolment or recovery is refused, as the pending-session gates refuse every other protected route.
- The authenticating interceptors never read a credential from the query string, so that spec rule holds already. A test pins it.
- **Activity:** the endpoint's path is in an internal set that the built-in authenticators consult before recording activity. A consumer's `CookieAuthenticator` asks `httpsec.RecordsSessionActivity(ex)`, and the godoc on `CookieAuthenticator` says so. This works like the internal `bindingVerifiers` set in `close-security-gaps` D8.

### D4. The store is the truth; signals are wake-ups

- Each stream holds `{user, family, deadlines, authenticatedAt}` from its first load.
- **At every heartbeat** it reloads its session by identifier. If the session is gone, superseded beyond its window, revoked, or past a deadline, it sends `session_ended` (`ended`, `logout`, `reuse` or `expired`, as the store reports) and closes. If a deadline moved, it sends `session`.
- **A `session_ended` arriving from the bus triggers the same reload at once.** It is forwarded only if the store agrees, which removes three problems:
  - a spurious end, when a consumer's outer transaction rolls back after `Manager.Delete` returned;
  - a forged or replayed bus message;
  - races between replicas.

  If the store still shows the session, the heartbeat catches the end later.
- **Timers:** `session_expiring` and `assurance_lapsed` come from the held deadlines and `authenticatedAt` through a single timer per stream, re-armed after each reload. They need no bus.
- **Heartbeat jitter:** ±10% of the interval, so streams opened together do not reload together.
- **Override:** the heartbeat interval. The rule that the store decides has none, because trusting a message to end a session is exactly what this decision rejects.

### D5. Where signals come from

- **Ended sign-ins:**
  - `session.WithEndObserver(func(ctx, session.EndReport))` reports `{User, Family, Kept, Reason}` after each successful end. The reasons are `logout`, `ended`, `reuse`, `all_ended` and `provider_logout`.
  - **A bulk end is one report** (settled while planning, 2026-11-02). `DeleteByUser` and `DeleteByUserExcept` report the user with no `Family`, and `Kept` for the family the second one spares. Listing the sign-ins first would cost a read per bulk delete and race the delete. The stream reloads anyway (D4), so a report that names only the user is enough to wake every stream of that user.
  - **`Delete(id)`** loads the session before deleting only when an observer is set, so it can name the user and the family. Without an observer, nothing changes.
  - **`RevokeFamily(family)`** names only the family, and reports it without a user. The registry routes by family as well as by user (D6).
  - **An end that names neither** (`DeleteByExternalSession`, which names only the provider's session) is not reported. The heartbeat ends those streams within its interval.
  - Panics are recovered and errors ignored, as with `WithReuseObserver`.
  - `EnableSessionSignals` installs it on the manager the chain uses, and refuses construction if the consumer's manager already has another one. The consumer then composes the two with `session.EndObservers(a, b)`.
  - Sweeping reports nothing. A deadline is an expiry, which the stream's own timer handles.
- **`credential_changed`:**
  - raised by the chain's own endpoints: the password-change resolve, recovery finish, passkey registration and removal, MFA enrolment confirmation and removal;
  - for changes the consumer makes outside those endpoints (an admin console, a password reset of its own), `chain.ReportCredentialChange(ctx, userID, kind)` raises the same library signal;
  - it is the one library signal a consumer may raise, because the change happened in the consumer's code.
- **The consumer's own signals:** `chain.PublishSignal`.
- **`session_expiring` and `assurance_lapsed`:** the stream's own timers (D4).

### D6. The bus

```go
type SignalBus interface {
    Publish(ctx context.Context, e SignalEnvelope) error
    Subscribe(ctx context.Context, deliver func(SignalEnvelope)) error // once per chain; blocks until ctx ends
}
type SignalEnvelope struct {
    User   identity.UserID
    Family string          // empty for user-wide signals
    Name   string
    Data   json.RawMessage
}
```

- **One subscription per replica,** not per stream. The chain keeps a local registry `user → streams` and hands each envelope to the user's streams, filtered by family for `session_ended`.
  - This lets a Redis or PostgreSQL bus use one channel, not one per user.
- **The default bus** delivers only within the process. With several replicas and no shared bus, `session_ended` still arrives within a heartbeat. `credential_changed` and the consumer's signals reach only the streams on the replica that raised them. The godoc says so, as the rate limiter documents its N-replica limit.
- **A failing `Publish`** is logged with sampling and never changes the outcome of the request that raised it. A failing `Subscribe` is retried with backoff, while the heartbeat keeps ending streams.
- **Override:** the port.

### D7. The wire format

- The first bytes are `retry: 5000` and then the `session` event.
- Each event is `event: <name>\ndata: <json>\n\n`, with no `id:`. A heartbeat is `:\n\n`.
- The data:
  - `session`: `{"idle_deadline", "absolute_deadline", "authenticated_at"}` in RFC 3339;
  - `session_ended`: `{"reason"}`;
  - `session_expiring`: `{"deadline":"idle"|"absolute","at"}`;
  - `assurance_lapsed`: `{"authenticated_at"}`;
  - `credential_changed`: `{"kind":"password"|"passkey"|"second_factor"}`.
- Headers: `Content-Type: text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`.
- After `session_ended` the stream closes. The browser's reconnection then gets 401, which ends `EventSource`'s retries (WHATWG: a non-200 response fails the connection).
- **Override:** none for the format. It is the contract front ends code against.

### D8. Caps

- The caps are kept in the local registry and counted per replica. With N replicas, a user can hold N × `MaxPerUser` streams, which the godoc states.
- A request over a cap gets 429, `ErrTooManyStreams`, and is charged to nothing. A stream frees its place when its body returns.
- **Override:** the three fields.
- **Shutdown** (settled while planning, 2026-11-02). `http.Server.Shutdown` waits for active handlers and does not cancel their contexts, so an open stream would hold it until its deadline. `chain.CloseSessionSignals(ctx)` ends every stream without an event, and refuses new ones with 503. The README registers it with `RegisterOnShutdown`. On fiber, fasthttp's `Done()` at shutdown ends streams too. Without the call, streams end at the shutdown deadline as they would otherwise.

## Risks / Trade-offs

- **[Store load]** 10 000 streams at 15 s is about 670 session reads per second per replica.
  → Jitter spreads them out. The interval can go to 60 s, and the README gives the arithmetic. A shared bus lets a consumer lengthen the heartbeat without delaying `session_ended`.
- **[Fiber write deadline]** The fiber design rests on resetting the connection's deadline per flush, which is unverified.
  → Task 1.1 tests it first. If it fails, the fiber adapter documents that a `HeaderReceived` hook giving the stream path a long `WriteTimeout` is required, and the `framework-adapters` delta is amended before any other task.
- **[A lost bus message]**
  → The heartbeat bounds the delay. Signals are wake-ups, never the only path.
- **[A slow client]**
  → Each stream's queue is bounded, and a full queue drops that stream's events. `session_ended` comes from the stream's own reload, so it is never dropped.
- **[Many tabs on HTTP/1.1]**
  → The cap of 4 per sign-in refuses the fifth tab, not an existing one. The README recommends one shared stream (BroadcastChannel or SharedWorker), or HTTP/2.
- **[A breaking adapter interface]**
  → It lands before `v0.1.0`, which `release-readiness` records. `ErrStreamingUnsupported` gives a consumer adapter a way out.

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
- Reasoned from scrty's own settled specs and the established design: the reuse observer in `sessions`, and `close-security-gaps` D8 (the internal set pattern), D12 and D13.
