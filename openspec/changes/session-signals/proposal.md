# Proposal

## Why

A front end learns that its session ended, from another device, an administrator, the identity provider or a password change, only when its next request fails with 401. It also has no way to warn the user before an idle or absolute deadline ends the session, or to ask for step-up before a sensitive action instead of after it.

Applications fill the gap by polling, or by forwarding their audit feed to the browser. The audit feed (`close-security-gaps` D13) is built for the operator: it covers every user, carries client addresses, and reports failed logins, lockouts and refusals. Forwarding it, even through a filter, would let anything added to it later reach browsers by default, and would show an attacker holding a stolen session that the defences are reacting.

This change gives the front end a feed of its own: few signals, typed, and only about the user's own sign-in. It must land before `release-readiness` tags `v0.1.0`, because it adds a required method to the adapters' `ResponseWriter`. After the tag, that would be a breaking change.

## What Changes

- **An opt-in session-signal stream.** `httpsec.EnableSessionSignals(...)` adds an authenticated `GET` endpoint that streams server-sent events (`text/event-stream`) about the signed-in user's own session.
  - It is off by default.
  - It authenticates through whatever the chain already uses: a cookie session works with the browser's `EventSource`; a bearer or session-reference client reads the same stream with `fetch()`, which can send `Authorization`. A credential is never accepted in the query string.
  - A page on another site cannot open a stream: the stream judges `Sec-Fetch-Site` and `Origin` as unsafe requests are judged, so only origins CORS allows with credentials get one.
- **A closed set of library signals, chosen by allowlist.**
  - `session_ended`: this sign-in ended, by logout elsewhere, an ended sign-in, family revocation, a password change or an identity-provider logout.
  - `session_expiring`: an idle or absolute deadline is near.
  - `assurance_lapsed`: the re-authentication or step-up window has passed.
  - `credential_changed`: a password, passkey or second factor of the user changed.
  - By default the first two are sent. The consumer narrows or widens the set from these names only.
  - A client may narrow the set further for its own connection, never widen it.
  - Failed logins, lockouts, refusals, rate limits, client addresses and other users' activity are not signals. No option forwards them.
- **The consumer's own signals.** The consumer may publish its own named signals to a user's streams, for example "your role changed". These are namespaced apart from the library's signals, and their payload is stored and returned unchanged.
- **A snapshot on connect.** The first event states the sign-in's idle and absolute deadlines and its assurance time, so a client that reconnects learns the current state instead of replaying missed events. `Last-Event-ID` replay is a non-goal.
- **Correct on any number of replicas without new infrastructure.** By default, each open stream re-checks its sign-in in the session store at every heartbeat. A sign-in ended on another replica is therefore signalled within one heartbeat interval.
  - An optional signal-bus port delivers signals as they happen across replicas. The library ships an in-process implementation. Redis and PostgreSQL buses are follow-ups.
- **The stream obeys the session.**
  - The stream closes, after sending `session_ended`, the moment its sign-in ends.
  - The stream never records activity on the session, so an open tab cannot keep an idle session alive.
  - Once the session is gone, the stream answers in a way that stops the browser reconnecting.
- **Bounded resources.**
  - The number of streams is capped per sign-in, per user and in total, each with a default and an option.
  - A heartbeat comment keeps proxies from dropping the connection, and responses are `no-store`.
  - Write deadlines are extended for the stream only.
- **BREAKING: `httpsec.ResponseWriter` gains a required `Stream` method** (changed from `Flush` in the design, D1, because fiber writes a streamed body only after the handlers return). It is implemented by the net/http, gin and fiber adapters. An adapter of the consumer's own must add it, as with `AddHeader` before it, or report that it cannot stream.

## Capabilities

### New Capabilities

- `session-signals`: the signal stream and its endpoint. It covers:
  - the library's signal names and payloads, and how they are allowlisted;
  - the consumer's own signals;
  - the snapshot on connect;
  - how a stream authenticates and closes;
  - re-checking against the store, and the signal-bus port;
  - stream caps and the heartbeat;
  - what the stream never sends.

### Modified Capabilities

- `framework-adapters`: `ResponseWriter` gains a required `Stream` method, and each adapter supports streaming. A streamed response flushes each event, holds no response buffer, and has its write deadline extended.
- `http-security-chain`: the stream endpoint's place in the chain. It answers only authenticated requests and records no session activity. CORS governs a cross-origin read.
- `sessions`: the manager reports when a sign-in ends, is revoked with its family or is ended with the user's other sign-ins, so signals can be raised where sessions are ended rather than inferred.

## Impact

- **Code:**
  - `httpsec`: the endpoint, the stream writer, the signal types, the bus port and its in-process default.
  - `httpsec/ginsec` and `httpsec/fibersec`: flushing and streaming.
  - `session`: the end-of-sign-in report.
  - `test/httpsecconformance`: stream scenarios on all three adapters.
- **API:**
  - new: `EnableSessionSignals` and `SessionSignals`, the signal names, `PublishSignal` for the consumer's signals, `ReportCredentialChange`, `CloseSessionSignals`, the bus port, and `session.WithEndObserver` with `(*Sessions).AddEndObserver`, the option shared with `oidc-provider`;
  - **breaking:** `ResponseWriter.Stream`, with `ErrStreamingUnsupported` and `ErrStreamingStarted`.
- **Dependencies:** none new. The stream uses net/http's `http.ResponseController`.
  - *Unverified:* fiber v3 streams through fasthttp's body stream writer, a different model from net/http. Its fit is the first thing the design must establish.
- **Order:** after `close-security-gaps`, whose security-event emission points (D13) and session-management endpoints this change raises signals beside; before `release-readiness` tags `v0.1.0`. `bff-resource-server` is not required. Its cookie session will work with the stream when it lands.
- **Operations:**
  - one long-lived connection per open stream;
  - a proxy in front must not buffer `text/event-stream`;
  - on HTTP/1.1, one stream per tab can run into the browser's per-server connection limit, so the docs recommend sharing one stream across tabs, or HTTP/2.
- **Out of scope:**
  - WebSocket;
  - Web Push to closed tabs;
  - replaying missed events;
  - forwarding audit events;
  - Redis and PostgreSQL buses (follow-ups).

## References

### The stream (accessed 2026-11-02)
- [WHATWG HTML: server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html):
  - `EventSource` takes only `withCredentials` and sets no custom headers, so a bearer client needs `fetch()`;
  - `Last-Event-ID` and `retry`;
  - a 204 stops reconnection;
  - a comment line every 15 seconds or so keeps legacy proxies from dropping the connection;
  - the per-server connection limit, and sharing one `EventSource` through a shared worker.

### Which signals (accessed 2026-11-02)
- [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0-final.html) (published 29 August 2025): the session and credential event vocabulary (`session-revoked`, `credential-change`, `assurance-level-change`, `token-claims-change`), which this change's signal names follow. CAEP itself is exchanged between cooperating transmitters and receivers over the Shared Signals Framework, not with browsers. So scrty borrows its vocabulary, not its protocol.

### Security review (accessed 2026-11-03)
- Each decision was checked against RFC 6750, RFC 9111, RFC 9113, WHATWG server-sent events, OWASP (Session Management, CSRF, HTML5, WebSocket, Authentication and DoS cheat sheets; ASVS 5.0 V7), NIST SP 800-63B-4, web.dev's Fetch Metadata guidance, and OpenID SSF 1.0 and CAEP 1.0. `design.md`'s "Security review against standards" gives each verdict, and its References list each source.

### Separate from the audit feed
- Reasoned from scrty's own settled specs and the established design: `close-security-gaps` D13 (security events for the operator), D14 (sign-in notices) and D12 (session-management endpoints).
