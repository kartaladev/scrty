# Proposal

## Why

`httpsec.SignalBus` is a port with one implementation, the in-process default. On several replicas a sign-in ended on another replica is told within a heartbeat and half a second, and every other signal reaches only the replica that raised it. A consumer who wants more has to write its own bus, and get a reconnect loop, a size limit and message authenticity right alone. `session-signals` named Redis and PostgreSQL buses as its follow-up.

## What Changes

- **`httpsec/redisbus`**, a nested module: a `SignalBus` over Redis Pub/Sub on one channel, with sharded Pub/Sub as an option.
- **`httpsec/pgxbus`**, a nested module: a `SignalBus` over PostgreSQL `LISTEN`/`NOTIFY` on one channel, through pgx.
- **`httpsec/signalwire`**, a core package holding the one wire encoding and the message authentication both backends share, with no driver dependency.
- **Authenticity by default:** a bus's constructor takes signing keys or an explicit `WithoutAuthentication()`, and refuses neither.
- **An optional port, `SignalBusChecker`**, so that a signal a bus can never carry is refused to the caller of `PublishSignal` at once, instead of being logged later.
- **A shared conformance suite** in the `test` module, on real Redis and real PostgreSQL.

Neither bus changes what a stream trusts: an envelope only wakes a stream to read the store, and the store decides.

## Capabilities

### New Capabilities
- `signal-bus-backends`: the Redis and PostgreSQL buses, their encoding, authentication, limits and failure behaviour.

### Modified Capabilities
- `session-signals`: a bus may refuse an envelope when it is raised.
- `module-layout`: two new integration modules under `httpsec`.

## Impact

- **New modules:** `httpsec/redisbus` (go-redis v9.23.0), `httpsec/pgxbus` (pgx v5.12.0), in `go.work` and the layout guard's `integrationTable`. The core gains no driver dependency.
- **New core package:** `httpsec/signalwire`.
- **Core change:** `SignalBusChecker`, consulted by the hub's `raise`. Consumers with their own bus gain nothing they must implement.
- **`release-readiness`:** both modules join its tag list and `GOWORK=off` gate.
- **Migrations:** none. PostgreSQL's channel needs no table.

## References

See `design.md`.
