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
The first event of every stream SHALL be a `session` event, read from the sign-in's current state, whose data states the sign-in's idle deadline, its absolute deadline and when it last authenticated. It SHALL carry no session identifier, token or secret. Whenever a later check finds a deadline or the authentication time has moved, the stream SHALL send a new `session` event.

#### Scenario: Activity elsewhere moves the idle deadline
- **WHEN** another request on the same sign-in extends its idle deadline while a stream is open
- **THEN** within one heartbeat interval the stream sends a new `session` event with the new deadline

#### Scenario: Re-authentication moves the authentication time
- **WHEN** the user re-authenticates on the same sign-in while a stream is open
- **THEN** within one heartbeat interval the stream sends a new `session` event with the new authentication time

### Requirement: A reconnecting client learns the current state, not what it missed
Events SHALL carry no `id` field. A reconnecting client SHALL NOT be sent what it missed, and SHALL learn the current state from its first event.

#### Scenario: Snapshot on connect
- **WHEN** a stream opens for a sign-in whose idle deadline is 10:30 and absolute deadline is 18:00
- **THEN** the first event is `session` with those deadlines and the time it last authenticated, and no identifier

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
- **THEN** the stream sends `session_ended` with the reason `logout`, and never `reuse`, and closes

#### Scenario: Family revoked by a consumer
- **WHEN** a stream is open and the consumer revokes its family directly
- **THEN** the stream sends `session_ended` with the reason `ended` and closes

#### Scenario: Family revoked on reuse
- **WHEN** a stream is open and a superseded identifier of its sign-in is presented after its window, revoking the family
- **THEN** the stream sends `session_ended` with the reason `reuse` and closes

#### Scenario: Every sign-in of the user ended
- **WHEN** a stream is open and every session of its user is deleted
- **THEN** the stream sends `session_ended` with the reason `all_ended` and closes

#### Scenario: Provider logout
- **WHEN** a stream is open for a federated sign-in and the user's sessions from that provider are ended
- **THEN** the stream sends `session_ended` with the reason `provider_logout` and closes

#### Scenario: Back-channel logout of one upstream session
- **WHEN** a stream is open for a federated sign-in and a provider logs out its upstream session through the back channel
- **THEN** the stream sends `session_ended` with the reason `provider_logout` and closes, without waiting for a heartbeat

#### Scenario: User disabled
- **WHEN** a stream is open and its user is disabled
- **THEN** within one heartbeat interval the stream sends `session_ended` with the reason `ended` and closes

#### Scenario: Narrowed away
- **WHEN** a client opened the stream with `?signals=session_expiring` and its sign-in is ended from another device
- **THEN** the stream still sends `session_ended` and closes

### Requirement: A stream follows its sign-in and never harms it
A stream SHALL check its sign-in without presenting a credential: it SHALL hold no session identifier or credential, record no presentation, and never cause reuse handling or a family revocation. A renewal, a rotation or a step-up on its sign-in SHALL NOT end the stream.

#### Scenario: Renewal while a stream is open
- **WHEN** a stream is open and its sign-in is renewed, and the renewal's grace window passes
- **THEN** the stream stays open and sends a `session` event with the new deadlines, the sign-in stays live, and no reuse is reported

#### Scenario: Strict rotation while a stream is open
- **WHEN** a stream is open and its sign-in re-authenticates or steps up in another tab, rotating its session strictly
- **THEN** the stream stays open and sends a `session` event with the new authentication time

#### Scenario: A sign-in never yet presented
- **WHEN** a stream's check reads a session never yet presented
- **THEN** no presentation is recorded

#### Scenario: A sealing key retired
- **WHEN** a stream is open and its session's sealed fields can no longer be read
- **THEN** the check still answers, because it reads no sealed field

### Requirement: A stream is checked again at a maximum age
A stream SHALL close without an event once it reaches its maximum age, one hour by default with jitter, so that the client reconnects and every admission check runs again. The consumer SHALL be able to set the age, or turn it off with a documented named value.

#### Scenario: Maximum age passes
- **WHEN** a stream reaches its maximum age
- **THEN** it closes without an event, and a reconnection is judged as a new request

#### Scenario: A bearer token expired during the stream
- **WHEN** a stream's bearer token expired before its maximum age, and the stream then reaches that age
- **THEN** the stream closes, and a reconnection with the expired token is refused with 401

#### Scenario: Turned off
- **WHEN** the consumer turns the maximum age off
- **THEN** the stream stays open until its sign-in ends

### Requirement: A browser stops reconnecting once the sign-in has ended
A request to reopen the stream with an ended sign-in's credential SHALL be refused with 401, which ends a browser's automatic reconnection.

#### Scenario: Reconnect after the end
- **WHEN** a stream has sent `session_ended` and the client reopens it with the same credential
- **THEN** the request is refused with 401 and no stream opens

### Requirement: Each heartbeat re-checks the sign-in
By default a stream SHALL send a comment every 15 seconds. At each one, it SHALL read its sign-in from the session store and its user from the user store, and send `session_ended` and close if the sign-in is gone or the user is not active. This SHALL hold on any number of replicas with no shared bus. The consumer SHALL be able to set the interval between 5 and 60 seconds; a value outside that SHALL fail construction.

#### Scenario: Ended on another replica without a bus
- **WHEN** a stream is open on replica A, no bus is configured, and the sign-in is ended by a request on replica B
- **THEN** within one heartbeat interval the stream on A sends `session_ended` and closes

#### Scenario: Consumer sets the interval
- **WHEN** the consumer sets the heartbeat to 30 seconds
- **THEN** comments and checks happen every 30 seconds

#### Scenario: Interval out of range
- **WHEN** the consumer sets the heartbeat to 2 seconds
- **THEN** building the chain fails with a configuration error

### Requirement: A check is bounded and independent of the opening request
A check SHALL time out within half the heartbeat interval, and within 2 to 10 seconds, by default, so a store that hangs cannot stop the heartbeat. The consumer SHALL be able to set the timeout, which SHALL be shorter than the heartbeat. It SHALL NOT run inside a transaction or other request-scoped value of the request that opened the stream, unless the consumer carries one over.

#### Scenario: A store that hangs
- **WHEN** a stream's check blocks with no answer, whether or not the store honours its context
- **THEN** the stream sends its heartbeat within the interval, treats the check as a store failure, and still closes when its client leaves or its maximum age passes

#### Scenario: A transaction on the opening request
- **WHEN** a consumer's middleware attached a transaction to the request that opened a stream, and has since committed it
- **THEN** the stream's checks still read current state

#### Scenario: Multi-tenant consumer
- **WHEN** the consumer supplies a function carrying its tenant from the opening request to the checks
- **THEN** the checks run with that tenant

#### Scenario: A tenant-scoped store with no such function
- **WHEN** a store needs a tenant, and the consumer supplies no function to carry it
- **THEN** the stream does not open, the failure is logged, and no other tenant's data is read

### Requirement: A store outage does not end a stream
When the session store or the user store fails to answer a check, the stream SHALL stay open, send its heartbeat, and check again at the next one. It SHALL NOT report the sign-in as ended because of the failure, and SHALL still end at the sign-in's absolute deadline.

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

#### Scenario: A bus that hangs
- **WHEN** a consumer's bus blocks forever while a user logs out
- **THEN** the logout completes without waiting for it

#### Scenario: A bus that panics or stops
- **WHEN** a consumer's bus panics, or its subscription returns with no error
- **THEN** the process keeps running, and the subscription is retried with backoff

#### Scenario: A bus that has fallen behind
- **WHEN** a consumer's bus has fallen so far behind that a consumer's signal cannot be queued
- **THEN** publishing fails with an error saying so

#### Scenario: Consumer sets the queue and the timeout
- **WHEN** the consumer sets the bus's queue size and publish timeout
- **THEN** those are used

#### Scenario: An upstream session on the bus
- **WHEN** a provider logs out an upstream session and the signal crosses a shared bus
- **THEN** the message carries a digest of the issuer and session and not the session itself, and the matching stream on another replica ends

#### Scenario: Default bus on several replicas
- **WHEN** no bus is configured, `credential_changed` is enabled, a stream is open on replica A, and the user changes their password through replica B
- **THEN** the stream on A sends no `credential_changed`, and streams on B do

### Requirement: A bus message never ends a stream by itself
A `session_ended` from the bus SHALL only make the stream check its sign-in at once. The stream SHALL end only when the session store agrees the sign-in has ended. A message's reason SHALL be used only when it is a known reason and the store agrees shortly after it arrived.

#### Scenario: End message the store does not confirm
- **WHEN** a `session_ended` for a stream's sign-in arrives from the bus, and the session store still holds that sign-in
- **THEN** the stream sends no `session_ended` and stays open

#### Scenario: A stale reason does not name a later end
- **WHEN** a forged `session_ended` naming `reuse` arrives from the bus, the store still holds the sign-in, and the sign-in is logged out an hour later
- **THEN** the stream sends the reason `logout`

### Requirement: A stream warns before its sign-in expires
With `session_expiring` in its set, a stream SHALL send it once when the earlier of the sign-in's idle and absolute deadlines is within the warning window, two minutes by default, naming which deadline and when. If activity later moves the idle deadline past the window, the stream SHALL send a new `session` event and MAY warn again. The consumer SHALL be able to set the window.

#### Scenario: Idle deadline near
- **WHEN** a stream is open and its sign-in's idle deadline is 90 seconds away
- **THEN** the stream sends `session_expiring` naming the idle deadline

#### Scenario: Consumer sets the window
- **WHEN** the consumer sets the warning window to five minutes and the absolute deadline is four minutes away
- **THEN** the stream sends `session_expiring`

#### Scenario: Activity after the warning
- **WHEN** a stream has warned that the idle deadline is near, and another request on the sign-in moves the idle deadline past the window
- **THEN** within one heartbeat interval the stream sends a new `session` event and does not end the stream at the old deadline

#### Scenario: Both deadlines the same
- **WHEN** a sign-in's idle deadline has been capped at its absolute deadline, and it comes within the window
- **THEN** `session_expiring` names the absolute deadline

#### Scenario: Already within the window at open
- **WHEN** a stream opens with a deadline already within the window
- **THEN** the stream sends `session_expiring` at once, after its first event

### Requirement: A stream checks the store before saying its sign-in expired
When a deadline passes, the stream SHALL check its sign-in first, and SHALL send `session_ended` with the reason `expired` and close only if the store agrees, or, when the store cannot answer, only at the absolute deadline.

#### Scenario: Deadline passes
- **WHEN** a stream's sign-in reaches its absolute deadline
- **THEN** the stream sends `session_ended` with the reason `expired` and closes

#### Scenario: Activity just before the deadline
- **WHEN** a request moves the idle deadline one second before the old one, and the stream's timer then fires
- **THEN** the stream sends no `session_ended`, and sends a new `session` event

#### Scenario: A chain's clock ahead of the manager's
- **WHEN** a chain's clock says a deadline has passed, and its session manager, on a clock of its own, still answers for the sign-in
- **THEN** the stream stays open, and does not check again before its next heartbeat

#### Scenario: A clock ahead, shared with the manager
- **WHEN** a replica's clock, shared by its chain and manager, has passed a sign-in's deadline
- **THEN** the stream says `expired`, which can be early by up to the skew

#### Scenario: Idle deadline during a store outage
- **WHEN** the session store is unavailable as the idle deadline passes, before the absolute deadline
- **THEN** the stream stays open

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

#### Scenario: No authentication time recorded
- **WHEN** a stream opens for a sign-in with no recorded authentication time
- **THEN** its `session` event states null, and the stream sends no `assurance_lapsed`

### Requirement: Signal timing settings are checked at construction
Building the chain SHALL fail with a configuration error when the expiry warning window is negative, or leaves less than the session manager's touch interval before the idle timeout; when the assurance window is negative; when the maximum age is less than twice the heartbeat; when `assurance_lapsed` is enabled without re-authentication enabled; when the chain has no session manager; when no user loader is available; when the path is malformed; or when the chain's clock cannot wait.

#### Scenario: Window not shorter than the idle timeout
- **WHEN** the consumer sets the warning window to 30 minutes and the idle timeout is 30 minutes
- **THEN** building the chain fails with a configuration error

#### Scenario: Without re-authentication
- **WHEN** the consumer enables `assurance_lapsed` on a chain without re-authentication enabled
- **THEN** building the chain fails with a configuration error

#### Scenario: Malformed path
- **WHEN** the consumer sets the path to `session/signals`
- **THEN** building the chain fails with a configuration error

#### Scenario: No user loader
- **WHEN** the chain has only a consumer's cookie authenticator, and the consumer supplies no user loader
- **THEN** building the chain fails with a configuration error

### Requirement: Every stream of the user hears of a credential change
With `credential_changed` in its set, every stream of the user still open after the change SHALL send it when the user's password changes, or a passkey or second factor is added or removed, naming only the kind of credential. It SHALL carry no detail of the credential.

#### Scenario: Passkey removed
- **WHEN** `credential_changed` is enabled and the user removes a passkey from one device
- **THEN** that device's stream sends `credential_changed` with the kind `passkey`
- **AND** a stream of another device whose sign-in the removal ended sends `session_ended` instead

#### Scenario: Passkey added
- **WHEN** `credential_changed` is enabled and the user adds a passkey on one device, ending no sign-in
- **THEN** every open stream of the user, on any device, sends `credential_changed` with the kind `passkey`

#### Scenario: Change made by the consumer
- **WHEN** `credential_changed` is enabled and the consumer reports a password change it made in its own admin console
- **THEN** every open stream of the user sends `credential_changed` with the kind `password`

#### Scenario: Unknown kind
- **WHEN** the consumer reports a credential change of a kind other than password, passkey or second factor
- **THEN** reporting fails and no stream sends anything

### Requirement: The consumer can publish its own signals
The consumer SHALL be able to publish its own signal to every open stream of one user. Its name SHALL be `app.` followed by 1 to 63 characters, the first a lowercase letter or digit and the rest lowercase letters, digits, `.`, `_` or `-`; any other name SHALL be refused. Its data SHALL be the consumer's own JSON, of at most 8 KiB, on one line, valid UTF-8, delivered unchanged; other data SHALL be refused when it is published. A client's narrowing SHALL apply to it as to the library's signals.

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

#### Scenario: Pretty-printed data
- **WHEN** the consumer publishes `app.report` with JSON holding a raw line break between its tokens
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

### Requirement: A panic in a stream reaches the consumer's logger, without its value
A panic in the stream's own code, or in a consumer's bus or loader it calls, SHALL be recovered on every adapter and logged through the chain's logger, naming the value's type, where it happened and the sign-in's family, and never the value. The stream SHALL then close and free its place, and the process SHALL keep running.

#### Scenario: A panic carrying a secret
- **WHEN** a consumer's user loader panics with a value holding a token, on any of the three adapters
- **THEN** the chain's logger records the panic's type and location, no log holds the token, and the stream's place is freed

### Requirement: A stream's lifecycle and refusals can be seen
A stream's open and close SHALL be logged with its user, family, client address, origin and reason, and never a token or session identifier. A cap refusal and a cross-site refusal SHALL be logged with sampling. The chain SHALL report drops and failures of a consumer's bus with its other counts, and failures of checks in a row.

#### Scenario: A refused cross-site stream
- **WHEN** a request for the stream is refused as cross-site
- **THEN** it is logged with sampling, and no CSRF attack is reported

#### Scenario: A bus falling behind
- **WHEN** a consumer's bus drops a signal
- **THEN** the chain's counts show it

### Requirement: A stream does not keep its sign-in alive
Opening a stream and keeping it open SHALL NOT record activity on its sign-in, so a stream left open SHALL NOT keep an idle sign-in alive.

#### Scenario: Idle tab
- **WHEN** a stream is open and the client sends no other request until the idle deadline
- **THEN** the sign-in reaches its idle deadline, and the stream sends `session_ended` with the reason `expired`

### Requirement: Streams are capped
The chain SHALL cap open streams at 4 per sign-in, 16 per user and 10 000 in total by default. A stream that would pass any cap SHALL NOT open, SHALL NOT close an existing one, and SHALL be answered with status 200 carrying only a longer reconnection delay, so a browser tries again. The consumer SHALL be able to set each cap, and to add one per client address, which is off by default. The chain SHALL report open streams, cap refusals, failed checks and whether its subscription is up.

#### Scenario: Fifth tab
- **WHEN** a sign-in has 4 open streams and its client opens a fifth
- **THEN** the fifth gets 200 with only a longer reconnection delay, opens no stream, and the four stay open

#### Scenario: Consumer sets a cap
- **WHEN** the consumer caps streams at 1 per sign-in and a client opens a second
- **THEN** the second opens no stream

#### Scenario: Cap per client address
- **WHEN** the consumer caps streams at 2 per client address and a third is requested from that address
- **THEN** the third opens no stream, and streams from other addresses still open

#### Scenario: A dependency failure at admission
- **WHEN** the session store fails while a stream is being admitted
- **THEN** the response is 200 with only a longer reconnection delay, so a browser tries again

#### Scenario: Seventeenth stream of a user
- **WHEN** a user has 16 open streams across several sign-ins and opens another on a sign-in with fewer than 4
- **THEN** it opens no stream and the 16 stay open

#### Scenario: Racing for the last place
- **WHEN** a sign-in has 3 open streams and two more are requested at the same moment
- **THEN** exactly one opens and the other gets only a longer reconnection delay

### Requirement: A stream frees its place exactly once
A stream SHALL free its place exactly once, as soon as its client leaves or the chain refuses it, whatever ended it.

#### Scenario: Client leaves
- **WHEN** a sign-in has 4 open streams and one client closes its tab
- **THEN** a new stream for that sign-in opens

#### Scenario: Refused after the stream started
- **WHEN** an interceptor outside the stream's slot refuses a request after the stream was started, on any of the three adapters
- **THEN** the stream's place is freed exactly once, and on fiber, whose stream has not begun, the client gets the refusal

### Requirement: A slow stream never holds back the others
A signal raised for a user SHALL be offered to each of the user's streams without waiting for any of them. A stream that cannot keep up SHALL drop its own pending signals, and SHALL NOT delay another stream or the request that raised the signal. `session_ended` SHALL never be dropped this way.

#### Scenario: Slow client
- **WHEN** one of a user's two streams stops reading, and the consumer publishes 100 signals for the user
- **THEN** the other stream sends all 100, and the request that published them is not delayed

#### Scenario: Ended while slow
- **WHEN** a stream has dropped signals because its client is slow, and its sign-in is then ended
- **THEN** the stream still sends `session_ended` and closes

### Requirement: Streams can be closed for shutdown
The consumer SHALL be able to close every open stream at once, for a server shutdown. Each stream SHALL then close without an event, and free its place. A stream requested afterwards SHALL be answered with status 200 carrying only a reconnection delay, and its connection closed, so a browser reconnects to another server instead of giving up.

#### Scenario: Server shuts down
- **WHEN** two streams are open and the consumer closes the streams as its server shuts down
- **THEN** both streams close without sending an event, and the server's shutdown completes before its deadline

#### Scenario: Request after closing
- **WHEN** the streams have been closed and a signed-in client requests a stream
- **THEN** the response is 200 with only a reconnection delay, the response ends, and no stream is registered

### Requirement: Closing streams is bounded and repeatable
Closing SHALL return once every stream has closed, or when the context given to it ends. Closing again SHALL end nothing new, and SHALL wait on its own context for any stream still closing.

#### Scenario: A stream that will not finish
- **WHEN** a stream's body is blocked writing to a stalled client as the consumer closes the streams
- **THEN** closing returns when its context ends

#### Scenario: Closing again
- **WHEN** a first close timed out with a stream still closing, and the consumer closes again
- **THEN** the second call ends nothing new, and waits on its own context for that stream

### Requirement: Reconnection delays vary by stream
Reconnection delays SHALL vary by stream, so that clients of a closing server do not all return at the same moment.

#### Scenario: Clients spread out
- **WHEN** many streams are opened
- **THEN** the reconnection delays they state differ, within the configured range
