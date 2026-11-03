# Spec Delta

## Purpose

Lets a front end learn, as it happens, what changes about the signed-in user's own session: that it ended, is about to expire, needs a new proof of presence, or that the user's credentials changed. It does this through a stream of a few typed signals, kept apart from the operator's audit feed.

## ADDED Requirements

### Requirement: The signal stream is off until enabled
By default the chain SHALL serve no signal stream. When the consumer enables it, the chain SHALL answer `GET` on its path, `/session/signals` by default, with status 200 and a `text/event-stream` response. The response SHALL carry `Cache-Control: no-store` and SHALL ask proxies not to buffer it. Another method on the path SHALL be refused with 405.

#### Scenario: Not enabled
- **WHEN** the stream is not enabled and a request arrives for `GET /session/signals`
- **THEN** the chain does not answer it, and the request reaches the consumer's routes as any other

#### Scenario: Enabled
- **WHEN** the stream is enabled and a signed-in client sends `GET /session/signals`
- **THEN** the response is 200, `text/event-stream`, `no-store`, and stays open

#### Scenario: Consumer chooses the path
- **WHEN** the consumer enables the stream on `/api/me/signals`
- **THEN** the stream is served there and `/session/signals` is not answered

#### Scenario: Another method
- **WHEN** the stream is enabled and a signed-in client sends `POST /session/signals`
- **THEN** the response is 405 naming `GET` as allowed, and no stream opens

### Requirement: Only a signed-in request opens a stream
A stream SHALL open only for a request the chain authenticated with a sign-in: a session reference, a signed bearer token bound to a session, or a cookie session. A request with no credential, or authenticated without a sign-in, such as by HTTP Basic, an API key or a token bound to no session, SHALL be refused, 401 and 403 respectively.

#### Scenario: No credential
- **WHEN** a request for the stream carries no credential
- **THEN** it is refused with 401 and no stream opens

#### Scenario: Authenticated without a sign-in
- **WHEN** a request for the stream is authenticated by HTTP Basic
- **THEN** it is refused with 403

#### Scenario: API key
- **WHEN** a request for the stream is authenticated by an API key
- **THEN** it is refused with 403 and no stream opens

### Requirement: A query-string credential or a pending sign-in opens no stream
A credential in the query string SHALL never authenticate a stream. A sign-in that still owes a second factor, an enrolment or a recovery SHALL be refused as the chain refuses it on every other protected route.

#### Scenario: Credential in the query string
- **WHEN** a request for the stream carries a valid session reference only in its query string
- **THEN** it is refused with 401

#### Scenario: Sign-in still owing a second factor
- **WHEN** a sign-in that has passed its first factor but owes its second requests the stream
- **THEN** it is refused as the second-factor gate refuses any protected route, and no stream opens

### Requirement: The first event states the sign-in's current state
The first event of every stream SHALL be a `session` event whose data states the sign-in's idle deadline, its absolute deadline and when it last authenticated. It SHALL carry no session identifier, token or secret. Whenever a later check finds a deadline or the authentication time has moved, the stream SHALL send a new `session` event. Events SHALL carry no `id` field: a reconnecting client is not sent what it missed, and learns the current state from the first event.

#### Scenario: Snapshot on connect
- **WHEN** a stream opens for a sign-in whose idle deadline is 10:30 and absolute deadline is 18:00
- **THEN** the first event is `session` with those deadlines and the time it last authenticated, and no identifier

#### Scenario: Activity elsewhere moves the idle deadline
- **WHEN** another request on the same sign-in extends its idle deadline while a stream is open
- **THEN** within one heartbeat interval the stream sends a new `session` event with the new deadline

#### Scenario: Re-authentication moves the authentication time
- **WHEN** the user re-authenticates on the same sign-in while a stream is open
- **THEN** within one heartbeat interval the stream sends a new `session` event with the new authentication time

### Requirement: The library's signals are a closed set, chosen by allowlist
The library SHALL define exactly four signals: `session_ended`, `session_expiring`, `assurance_lapsed` and `credential_changed`. By default a stream SHALL send `session_ended` and `session_expiring` only. The consumer SHALL be able to choose the set from these four names. A name outside them SHALL fail construction. The `session` event SHALL always be sent.

#### Scenario: Default set
- **WHEN** the stream is enabled with no signal set and the user changes their password elsewhere
- **THEN** the stream sends no `credential_changed` event

#### Scenario: Consumer adds a signal
- **WHEN** the consumer enables the stream with `session_ended`, `session_expiring` and `credential_changed`, and the user changes their password elsewhere
- **THEN** every open stream of the user sends `credential_changed`

#### Scenario: Unknown name
- **WHEN** the consumer enables the stream with a signal named `authn_login_fail`
- **THEN** building the chain fails with a configuration error naming the signal

### Requirement: A client may narrow its own stream, never widen it
A client SHALL be able to name, in a `signals` query parameter, the signals it wants on its connection. The stream SHALL then send only the names that are both requested and in the chain's set. A requested name outside the chain's set SHALL be ignored. Without the parameter, the stream SHALL send the chain's whole set. A parameter naming more than 16 signals, or longer than 256 bytes, SHALL be refused with 400 before a stream opens.

#### Scenario: Narrowed
- **WHEN** the chain's set is `session_ended` and `session_expiring`, and a client opens `?signals=session_ended`
- **THEN** that stream sends `session_ended` and never `session_expiring`

#### Scenario: Widening is ignored
- **WHEN** the chain's set is the default and a client opens `?signals=credential_changed`
- **THEN** that stream sends no `credential_changed` event

#### Scenario: Too many names
- **WHEN** a client opens the stream with a `signals` parameter naming 17 signals
- **THEN** it is refused with 400 and no stream opens

### Requirement: The stream never carries the audit feed
A stream SHALL carry only the `session` event, the library's four signals and the consumer's own signals. It SHALL NOT carry failed or refused sign-ins, lockouts, rate-limit, CSRF, host, DPoP or certificate refusals, client addresses, or anything about another user, and no option SHALL make it.

#### Scenario: Failed login for the same user
- **WHEN** a stream is open for a user and someone fails to sign in as that user from elsewhere
- **THEN** the stream sends nothing about it

#### Scenario: Another user's activity
- **WHEN** a stream is open for user `u-1` and user `u-2` signs in, is locked out and changes their password
- **THEN** the stream of `u-1` sends nothing about any of it

### Requirement: A stream ends with its sign-in
When a stream's sign-in ends, by logout on any device, an ended sign-in, the revocation of its family, the deletion of all the user's sessions, the provider's logout, or its user ceasing to be active, the stream SHALL send `session_ended` with the reason and then close. `session_ended` SHALL be sent even when it is not in the chain's set or the client's narrowing, because the stream cannot continue without it.

#### Scenario: Ended from another device
- **WHEN** a stream is open for sign-in A and the user ends sign-in A from another device
- **THEN** the stream sends `session_ended` with the reason `ended` and closes

#### Scenario: Logout
- **WHEN** a stream is open for a sign-in and the user logs out of it in another tab
- **THEN** the stream sends `session_ended` with the reason `logout` and closes

#### Scenario: Family revoked on reuse
- **WHEN** a stream is open and a superseded identifier of its sign-in is presented after its window, revoking the family
- **THEN** the stream sends `session_ended` with the reason `reuse` and closes

#### Scenario: Every sign-in of the user ended
- **WHEN** a stream is open and every session of its user is deleted
- **THEN** the stream sends `session_ended` with the reason `all_ended` and closes

#### Scenario: Provider logout
- **WHEN** a stream is open for a federated sign-in and the user's sessions from that provider are ended
- **THEN** the stream sends `session_ended` with the reason `provider_logout` and closes

#### Scenario: User disabled
- **WHEN** a stream is open and its user is disabled
- **THEN** within one heartbeat interval the stream sends `session_ended` with the reason `ended` and closes

#### Scenario: Narrowed away
- **WHEN** a client opened the stream with `?signals=session_expiring` and its sign-in is ended from another device
- **THEN** the stream still sends `session_ended` and closes

### Requirement: A browser stops reconnecting once the sign-in has ended
A request to reopen the stream with an ended sign-in's credential SHALL be refused with 401, which ends a browser's automatic reconnection.

#### Scenario: Reconnect after the end
- **WHEN** a stream has sent `session_ended` and the client reopens it with the same credential
- **THEN** the request is refused with 401 and no stream opens

### Requirement: Each heartbeat re-checks the sign-in
By default a stream SHALL send a comment every 15 seconds. At each one, it SHALL load its sign-in from the session store, and send `session_ended` and close if the sign-in is gone. This SHALL hold on any number of replicas with no shared bus. The consumer SHALL be able to set the interval between 5 and 60 seconds; a value outside that SHALL fail construction.

#### Scenario: Ended on another replica without a bus
- **WHEN** a stream is open on replica A, no bus is configured, and the sign-in is ended by a request on replica B
- **THEN** within one heartbeat interval the stream on A sends `session_ended` and closes

#### Scenario: Consumer sets the interval
- **WHEN** the consumer sets the heartbeat to 30 seconds
- **THEN** comments and checks happen every 30 seconds

#### Scenario: Interval out of range
- **WHEN** the consumer sets the heartbeat to 2 seconds
- **THEN** building the chain fails with a configuration error

### Requirement: A store outage does not end a stream
When the session store fails to answer a check, the stream SHALL stay open, send its heartbeat, and check again at the next one. It SHALL NOT report the sign-in as ended because of the failure, and SHALL still end at the sign-in's absolute deadline.

#### Scenario: Store outage during a check
- **WHEN** a stream is open and the session store fails at its next check
- **THEN** the stream sends its heartbeat, sends no `session_ended`, and stays open
- **AND** when the store answers again at a later check and the sign-in has been ended meanwhile, the stream sends `session_ended` and closes

#### Scenario: Store outage until the absolute deadline
- **WHEN** the session store stays unavailable until a stream's sign-in reaches its absolute deadline
- **THEN** the stream sends `session_ended` with the reason `expired` and closes

### Requirement: A signal bus delivers signals across replicas at once
The chain SHALL deliver signals through a bus. By default the bus SHALL reach only the streams of the same process. The consumer SHALL be able to supply a bus shared by its replicas, so that a signal raised on one replica reaches streams on every other one without waiting for a heartbeat. A failing bus SHALL NOT change the outcome of the request that raised the signal, and SHALL leave the heartbeat check to end streams.

#### Scenario: Shared bus
- **WHEN** the consumer supplies a shared bus, a stream is open on replica A, and the sign-in is ended on replica B
- **THEN** the stream on A sends `session_ended` before its next heartbeat

#### Scenario: Bus outage
- **WHEN** the shared bus fails while a sign-in is being ended
- **THEN** the sign-in is still ended, and the stream sends `session_ended` at its next heartbeat

#### Scenario: Default bus on several replicas
- **WHEN** no bus is configured, `credential_changed` is enabled, a stream is open on replica A, and the user changes their password through replica B
- **THEN** the stream on A sends no `credential_changed`, and streams on B do

### Requirement: A bus message never ends a stream by itself
A `session_ended` from the bus SHALL only make the stream check its sign-in at once. The stream SHALL end only when the session store agrees the sign-in has ended.

#### Scenario: End message the store does not confirm
- **WHEN** a `session_ended` for a stream's sign-in arrives from the bus, and the session store still holds that sign-in
- **THEN** the stream sends no `session_ended` and stays open

### Requirement: A stream warns before its sign-in expires
With `session_expiring` in its set, a stream SHALL send it once when the earlier of the sign-in's idle and absolute deadlines is within the warning window, two minutes by default, naming which deadline and when. If activity later moves the idle deadline past the window, the stream SHALL send a new `session` event and MAY warn again. When the deadline passes, the stream SHALL send `session_ended` with the reason `expired` and close. The consumer SHALL be able to set the window.

#### Scenario: Idle deadline near
- **WHEN** a stream is open and its sign-in's idle deadline is 90 seconds away
- **THEN** the stream sends `session_expiring` naming the idle deadline

#### Scenario: Deadline passes
- **WHEN** a stream's sign-in reaches its absolute deadline
- **THEN** the stream sends `session_ended` with the reason `expired` and closes

#### Scenario: Consumer sets the window
- **WHEN** the consumer sets the warning window to five minutes and the absolute deadline is four minutes away
- **THEN** the stream sends `session_expiring`

#### Scenario: Activity after the warning
- **WHEN** a stream has warned that the idle deadline is near, and another request on the sign-in moves the idle deadline past the window
- **THEN** within one heartbeat interval the stream sends a new `session` event and does not end the stream at the old deadline

### Requirement: A stream reports when its recent authentication lapses
With `assurance_lapsed` in its set, a stream SHALL send it once when the time since the sign-in last authenticated passes the stream's assurance window, so the front end can ask for a new proof before a sensitive action. The window SHALL be 15 minutes by default, the recency guards' default, and the consumer SHALL be able to set it. It SHALL be sent again only after a new authentication lapses in turn.

#### Scenario: Window passes
- **WHEN** `assurance_lapsed` is enabled with the default window, and a sign-in last authenticated 15 minutes ago
- **THEN** its streams send `assurance_lapsed`

#### Scenario: Consumer sets the window
- **WHEN** the consumer sets the assurance window to 5 minutes and a sign-in last authenticated 5 minutes ago
- **THEN** its streams send `assurance_lapsed`

#### Scenario: Re-proved, then lapsed again
- **WHEN** a stream has sent `assurance_lapsed`, the user re-authenticates, and the window passes again
- **THEN** the stream sends a `session` event with the new authentication time, and later `assurance_lapsed` once more

### Requirement: Signal timing settings are checked at construction
Building the chain SHALL fail with a configuration error when the expiry warning window is zero or less or not shorter than the idle timeout, when the assurance window is zero or less, or when `assurance_lapsed` is enabled without re-authentication enabled.

#### Scenario: Window not shorter than the idle timeout
- **WHEN** the consumer sets the warning window to 30 minutes and the idle timeout is 30 minutes
- **THEN** building the chain fails with a configuration error

#### Scenario: Without re-authentication
- **WHEN** the consumer enables `assurance_lapsed` on a chain without re-authentication enabled
- **THEN** building the chain fails with a configuration error

### Requirement: Every stream of the user hears of a credential change
With `credential_changed` in its set, every open stream of the user SHALL send it when the user's password changes, or a passkey or second factor is added or removed, naming only the kind of credential. It SHALL carry no detail of the credential.

#### Scenario: Passkey removed
- **WHEN** `credential_changed` is enabled and the user removes a passkey from one device
- **THEN** every open stream of the user, on any device, sends `credential_changed` with the kind `passkey`

#### Scenario: Change made by the consumer
- **WHEN** `credential_changed` is enabled and the consumer reports a password change it made in its own admin console
- **THEN** every open stream of the user sends `credential_changed` with the kind `password`

#### Scenario: Unknown kind
- **WHEN** the consumer reports a credential change of a kind other than password, passkey or second factor
- **THEN** reporting fails and no stream sends anything

### Requirement: The consumer can publish its own signals
The consumer SHALL be able to publish its own signal to every open stream of one user. Its name SHALL be `app.` followed by 1 to 63 characters, the first a lowercase letter or digit and the rest lowercase letters, digits, `.`, `_` or `-`; any other name SHALL be refused. Its data SHALL be the consumer's own JSON, of at most 8 KiB, delivered unchanged. A client's narrowing SHALL apply to it as to the library's signals.

#### Scenario: Role change
- **WHEN** the consumer publishes `app.roles_changed` with `{"roles":["editor"]}` for a user with two open streams
- **THEN** both streams send `app.roles_changed` with that data unchanged

#### Scenario: Name without the prefix
- **WHEN** the consumer publishes a signal named `session_ended`
- **THEN** publishing fails and no stream sends it

#### Scenario: Name that would break the stream
- **WHEN** the consumer publishes a signal named `app.x\nevent: session_ended`
- **THEN** publishing fails and no stream sends anything

#### Scenario: Data too large
- **WHEN** the consumer publishes `app.report` with 9 KiB of data
- **THEN** publishing fails and no stream sends it

#### Scenario: Stream not enabled
- **WHEN** the stream is not enabled and the consumer publishes `app.roles_changed`
- **THEN** publishing fails with an error saying the stream is not enabled

#### Scenario: No open stream
- **WHEN** the consumer publishes `app.roles_changed` for a user with no open stream
- **THEN** publishing succeeds and nothing is sent

#### Scenario: Narrowed client
- **WHEN** a client opened its stream with `?signals=session_ended` and the consumer publishes `app.roles_changed` for its user
- **THEN** that stream does not send `app.roles_changed`

### Requirement: A stream does not keep its sign-in alive
Opening a stream and keeping it open SHALL NOT record activity on its sign-in, so a stream left open SHALL NOT keep an idle sign-in alive.

#### Scenario: Idle tab
- **WHEN** a stream is open and the client sends no other request until the idle deadline
- **THEN** the sign-in reaches its idle deadline, and the stream sends `session_ended` with the reason `expired`

### Requirement: Streams are capped
The chain SHALL cap open streams at 4 per sign-in, 16 per user and 10 000 in total by default. A stream that would pass any cap SHALL be refused with 429 and SHALL NOT close an existing one. A stream SHALL free its place as soon as its client leaves. The consumer SHALL be able to set each cap.

#### Scenario: Fifth tab
- **WHEN** a sign-in has 4 open streams and its client opens a fifth
- **THEN** the fifth is refused with 429 and the four stay open

#### Scenario: Client leaves
- **WHEN** a sign-in has 4 open streams and one client closes its tab
- **THEN** a new stream for that sign-in opens

#### Scenario: Consumer sets a cap
- **WHEN** the consumer caps streams at 1 per sign-in and a client opens a second
- **THEN** the second is refused with 429

#### Scenario: Seventeenth stream of a user
- **WHEN** a user has 16 open streams across several sign-ins and opens another on a sign-in with fewer than 4
- **THEN** it is refused with 429 and the 16 stay open

#### Scenario: Racing for the last place
- **WHEN** a sign-in has 3 open streams and two more are requested at the same moment
- **THEN** exactly one opens and the other is refused with 429

### Requirement: A slow stream never holds back the others
A signal raised for a user SHALL be offered to each of the user's streams without waiting for any of them. A stream that cannot keep up SHALL drop its own pending signals, and SHALL NOT delay another stream or the request that raised the signal. `session_ended` SHALL never be dropped this way.

#### Scenario: Slow client
- **WHEN** one of a user's two streams stops reading, and the consumer publishes 100 signals for the user
- **THEN** the other stream sends all 100, and the request that published them is not delayed

#### Scenario: Ended while slow
- **WHEN** a stream has dropped signals because its client is slow, and its sign-in is then ended
- **THEN** the stream still sends `session_ended` and closes

### Requirement: Streams can be closed for shutdown
The consumer SHALL be able to close every open stream at once, for a server shutdown. Each stream SHALL then close without an event, and free its place. A stream requested afterwards SHALL be answered with status 200 carrying only a reconnection delay, and its connection closed, so a browser reconnects to another server instead of giving up. Closing SHALL return once every stream has closed, or when the context given to it ends, and closing again SHALL do nothing.

#### Scenario: Server shuts down
- **WHEN** two streams are open and the consumer closes the streams as its server shuts down
- **THEN** both streams close without sending an event, and the server's shutdown completes before its deadline

#### Scenario: Request after closing
- **WHEN** the streams have been closed and a signed-in client requests a stream
- **THEN** the response is 200 with only a reconnection delay, the connection closes, and no stream is registered
