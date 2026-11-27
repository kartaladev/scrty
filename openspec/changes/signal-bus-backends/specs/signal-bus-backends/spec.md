## Purpose

Lets a consumer running several replicas carry session signals between them through Redis or PostgreSQL, with one encoding, authenticated messages by default, and failures an operator can see.

## ADDED Requirements

### Requirement: A shared bus reaches every replica
The Redis and PostgreSQL buses SHALL deliver a published envelope to every replica subscribed to the same channel, including the one that published it. A bus MAY lose a message while disconnected.

#### Scenario: A sign-in ended on another replica
- **WHEN** two chains share a bus, a stream is open on replica A, and the sign-in is ended on replica B
- **THEN** the stream on A sends `session_ended` before its next heartbeat

#### Scenario: A consumer's signal crosses
- **WHEN** two chains share a bus and replica B publishes an `app.*` signal for a user with a stream on replica A
- **THEN** that stream sends the signal with its data unchanged

#### Scenario: Separate channels
- **WHEN** the consumer gives two groups of replicas different channels on one server
- **THEN** neither hears the other

### Requirement: A bus authenticates its messages unless told not to
A bus SHALL be constructed with signing keys or with an explicit statement that it trusts the broker, and SHALL refuse a construction with neither. A signed bus SHALL drop any message it cannot verify, without ending its subscription.

#### Scenario: Neither keys nor an opt-out
- **WHEN** a bus is constructed with no keys and no `WithoutAuthentication`
- **THEN** the constructor fails with a configuration error naming both options

#### Scenario: A key too short
- **WHEN** a bus is given a key of fewer than 32 bytes
- **THEN** the constructor fails with a configuration error

#### Scenario: A forged message
- **WHEN** a signed bus receives a message with a wrong MAC, an unknown key, or an altered field
- **THEN** it is dropped and counted, nothing reaches a stream, and the subscription carries on

#### Scenario: A message moved between channels
- **WHEN** a signed message captured on one channel is replayed on another with the same keys
- **THEN** it is dropped

#### Scenario: Rotation with no outage
- **WHEN** replicas hold keys `[old, new]`, then some switch to `[new, old]`, and then all drop `old`
- **THEN** every message at each stage is accepted by every replica holding its key

#### Scenario: A stale message
- **WHEN** a signed message is older than the replay window, 5 minutes by default
- **THEN** it is dropped

#### Scenario: The consumer widens or removes the window
- **WHEN** the consumer sets a replay window, or sets it to zero
- **THEN** messages are judged by that window, or by none

#### Scenario: The consumer trusts the broker
- **WHEN** a bus is constructed with `WithoutAuthentication`
- **THEN** its messages carry no MAC, and such a bus refuses signed ones it cannot verify as any malformed message

### Requirement: A bus's failure is visible and is retried
A bus SHALL return a failed subscription to the chain, so that the chain's backoff and log apply, and SHALL NOT hide a dead connection as silence. Its errors SHALL be typed, because the chain logs only an error's type.

#### Scenario: Redis goes away
- **WHEN** a Redis bus's server stops while it is subscribed
- **THEN** `Subscribe` returns an error within its health interval, and the chain retries with backoff

#### Scenario: A silent connection
- **WHEN** a PostgreSQL bus's listening connection stops answering without the socket being reported closed
- **THEN** `Subscribe` returns an error within its health interval

#### Scenario: The server comes back
- **WHEN** the server returns after a failed subscription
- **THEN** a later retry subscribes, and new messages are delivered

#### Scenario: A broker's refusal
- **WHEN** the broker refuses a bus's credentials or permissions
- **THEN** the error's type says so, and carries no broker address or message text

#### Scenario: A hang during a logout
- **WHEN** a bus's broker stops answering while a user logs out
- **THEN** the logout completes

### Requirement: Redis's bus uses one channel and offers sharding
The Redis bus SHALL use Pub/Sub on one channel, by default `scrty:signals`, and SHALL refuse at construction a client whose context timeouts are off.

#### Scenario: A client that ignores contexts
- **WHEN** the bus is given a client without `ContextTimeoutEnabled`
- **THEN** the constructor fails with a configuration error

#### Scenario: The consumer's channel
- **WHEN** the consumer sets a channel
- **THEN** publish and subscribe use it

#### Scenario: Sharded on a cluster
- **WHEN** the consumer sets `WithSharded` on a Redis Cluster 7.0 or later
- **THEN** signals cross through sharded Pub/Sub

### Requirement: PostgreSQL's bus listens on a dedicated connection
The PostgreSQL bus SHALL publish through the consumer's pool and SHALL listen on a connection of its own that takes no slot from that pool, on a channel by default `scrty_signals`. It SHALL refuse a channel name PostgreSQL would cut.

#### Scenario: The pool is untouched
- **WHEN** the bus is subscribed
- **THEN** the pool's acquired connection count is unchanged, and the listening connection closes when the subscription ends

#### Scenario: A channel too long
- **WHEN** the consumer sets a channel of more than 63 bytes
- **THEN** the constructor fails with a configuration error

#### Scenario: A transaction pooler
- **WHEN** the consumer's pool points at a transaction pooler and the consumer sets a listening connection's configuration
- **THEN** publishing uses the pool, and listening uses that configuration

#### Scenario: A hot standby
- **WHEN** `Verify` runs against a hot standby
- **THEN** it returns an error of a type naming the standby

### Requirement: A signal too large for the backend is refused, never cut
A bus whose backend has a size limit SHALL refuse an envelope over it when it is raised, and SHALL never cut one.

#### Scenario: Too large for PostgreSQL
- **WHEN** a consumer publishes a signal with data that would exceed the PostgreSQL bus's limit
- **THEN** `PublishSignal` returns `ErrEnvelopeTooLarge`, and nothing is sent

#### Scenario: Signals with no consumer data
- **WHEN** a `session_ended` or `credential_changed` crosses the PostgreSQL bus with the largest identifiers the chain produces
- **THEN** it fits

#### Scenario: The same signal on Redis
- **WHEN** the same signal is published on the Redis bus
- **THEN** it is delivered

### Requirement: A bus can be verified at start
Each bus SHALL offer `Verify`, which proves the path a message takes. The library SHALL NOT call it unasked.

#### Scenario: A working path
- **WHEN** `Verify` runs against a reachable broker with the right permissions
- **THEN** a probe message crosses, and it returns nil

#### Scenario: Missing permissions
- **WHEN** `Verify` runs with credentials that cannot publish or subscribe on the channel
- **THEN** it returns an error of a type naming the refusal
