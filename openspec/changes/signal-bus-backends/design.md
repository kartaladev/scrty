# Design

## Context

`SignalBus` has `Publish(ctx, SignalEnvelope) error` and `Subscribe(ctx, deliver func(SignalEnvelope)) error`. The hub calls `Publish` from one goroutine under `BusTimeout`, retries a failed or returned `Subscribe` with backoff from 1 s to 30 s, and logs only an error's type, never its text. With a consumer's bus, `raise` queues the envelope and does not deliver locally, so a replica hears its own signals through `Subscribe`. An envelope from a bus is untrusted: `session_ended` only wakes a stream to read the store, and everything else is checked again on receipt. Data is up to 8 KiB of valid one-line JSON.

## Goals / Non-Goals

**Goals:** a safe bus for each backend with no configuration beyond a client and keys; one encoding; failures the operator can see; limits refused rather than degraded.

**Non-goals:** delivery guarantees. A bus stays lossy, and the heartbeat bounds `session_ended`. No outbox table, and no GORM or `database/sql` listener. No `Resync` or `Ready` port for now (see Open Questions).

## Decisions

### D1. Modules and shapes

`github.com/kartaladev/scrty/httpsec/redisbus` and `.../httpsec/pgxbus`, nested modules under the concept they extend, each package named after its path's last element. A bus is not storage, so `<driver>store` does not apply.

```go
func redisbus.New(client redis.UniversalClient, opts ...Option) (*Bus, error)
func pgxbus.New(pool *pgxpool.Pool, opts ...Option) (*Bus, error)
func (b *Bus) Verify(ctx context.Context) error
```

**Default:** the consumer's own client or pool; `New` closes nothing it was handed. **Override:** options, per decision below. A wiring mistake is `httpsec.ErrConfig` from `New`, as the library's rule requires.

### D2. Redis: classic Pub/Sub on one channel, read with `ReceiveTimeout`

**Default:** `PUBLISH` and `SUBSCRIBE` on channel `scrty:signals`, which works on standalone, Sentinel and Cluster. **Override:** `WithChannel(name)`, because Pub/Sub ignores database numbers, so environments sharing a server must differ by channel; and `WithSharded()` for `SPUBLISH`/`SSUBSCRIBE` on Cluster 7.0+, which spares the message crossing the whole cluster bus. With one channel it puts all traffic on one shard, so it does not scale throughput, and the godoc says so.

The subscribe loop uses `ReceiveTimeout` and a `Ping` on each timeout, and returns any error, so the hub's backoff and its log apply. **`PubSub.Channel()` is rejected:** its goroutine retries forever, surfaces nothing but `ErrClosed`, and makes a dead server look like silence. `New` refuses a client without `ContextTimeoutEnabled`, as `redisstore` does. Health interval defaults to 5 s, and `WithHealthInterval` changes it.

*Rejected:* Streams. They bring retention, trimming and cursors for a signal whose loss a heartbeat already bounds.

### D3. PostgreSQL: `LISTEN`/`NOTIFY` on one dedicated connection

**Default:** `SELECT pg_notify($1, $2)` through the pool, autocommitted as its own statement, and `LISTEN` on a dedicated `pgx.Conn` built from `pool.Config().ConnConfig`, on channel `scrty_signals`. The listener takes no pool slot and closes when `Subscribe` returns. Each wait has a deadline of the health interval, 5 s by default, followed by a `Ping`, so a dead connection is found even if the operating system has not reported it.

**Override:** `WithChannel(name)`, refused above 63 bytes, because PostgreSQL would silently cut it and two names could become one. `WithListenConfig(*pgx.ConnConfig)`, for a pool that points at a transaction pooler: PgBouncer in transaction mode cannot `LISTEN`, though it can publish. `WithHealthInterval`.

**Limits, stated in godoc:** primary only, since `LISTEN` and `NOTIFY` fail on a hot standby; `Verify` reports a standby with `ErrStandby`. A commit holding `NOTIFY` takes a global lock, on which the two sources read disagree for current versions; signals are few, and each is its own statement, so the lock is held only for it. *Rejected:* `Acquire` plus `Hijack`, which permanently takes a connection from the pool with the same result. *Rejected:* a GORM or `database/sql` backend: pgx states `LISTEN`/`NOTIFY` is not available through `database/sql`. A GORM consumer passes a pgx pool for this one purpose. *Rejected for now:* an outbox table for large envelopes (D6).

### D4. One encoding, in `httpsec/signalwire`

Both backends need the same encoding, and a nested module cannot rely on the core's `internal`. So the core gains `httpsec/signalwire`, with no driver dependency:

```go
func Encode(e httpsec.SignalEnvelope, s *Signer, now time.Time) ([]byte, error)
func Decode(raw []byte, s *Signer, now time.Time) (httpsec.SignalEnvelope, error)
```

`signalwire` imports `httpsec`, so `httpsec` does not import it, and the hub's check goes through the port (D7). The encoding is versioned JSON. A Decode failure is counted and dropped by the backend, which never ends `Subscribe`, because a sender could otherwise stop a replica's subscription at will.

### D5. Authenticity: keys or an explicit opt-out

**Default:** `New` requires `WithKeys(keys...)` or `WithoutAuthentication()`, and refuses neither with `ErrConfig`. Keys are at least 32 bytes. The MAC is HMAC-SHA-256, over the exact bytes received, which cover a version, the channel name, a timestamp and every envelope field, so a message cannot move between channels. The sender signs with the first key and the receiver accepts any listed, with its identifier in the message, so rotation needs no outage: add the new key everywhere, make it first, then drop the old one.

**Override:** `WithoutAuthentication()` says in code that the broker is trusted. `WithReplayWindow(d)` changes the timestamp check, 5 minutes by default, and `WithReplayWindow(0)` turns it off. The window figure is a judgement, not researched: long enough for ordinary clock skew, short enough to keep an old `app.*` signal from reaching browsers. No nonce cache, because a replayed wake-up costs one store read.

**Why stricter than established practice:** Socket.IO's Redis adapter states messages are unsigned and Redis is trusted, and Action Cable, Django Channels and Phoenix.PubSub show nothing on signing. But a holder of a scrty bus can label a real end as reuse in its window, and its `app.*` data reaches browsers. PostgreSQL offers no role restriction on a channel in the documentation read (unverified as an absolute), so any role in the database could inject. Redis ACLs can scope a channel, which is what the opt-out is for. The library's rule is that when safe and convenient disagree, the default is the safe one.

*Rejected:* encryption. The envelope already holds a digest for the upstream session, and this is a wake-up. *Rejected:* separate defaults per backend, which are harder to document than one rule.

### D6. A signal too large for PostgreSQL is refused

An envelope with 8 KiB of data, plus its fields and MAC, exceeds `NOTIFY`'s limit of under 8000 bytes. **Default:** the bus refuses it with `pgxbus.ErrEnvelopeTooLarge`, through the check in D7, so `PublishSignal` returns the error. It never truncates, since the data is the consumer's and would no longer be valid JSON. `session_ended` and `credential_changed` carry no consumer data, so they always fit; a row pins that. The usable limit is measured in the task that builds this, and the godoc states it. **Override:** smaller signals, or the Redis bus. *Rejected for now:* Socket.IO's approach of spilling to a table, which needs a migration and cleanup for a case that a consumer can avoid by sending a key to look up.

### D7. `SignalBusChecker`, an optional port

```go
type SignalBusChecker interface {
    CheckEnvelope(e SignalEnvelope) error
}
```

Today `raise` queues an envelope and returns nil, so a signal a bus cannot carry fails later as a sampled log. **Default:** when a consumer's bus implements this, `raise` calls it before queueing, and returns its error. `PublishSignal` passes it to the caller, and an end report ignores it, as it ignores `ErrSignalsBusy`. **Override:** a bus without it behaves as today, so nothing a consumer wrote breaks. *Rejected:* a required `Publish`-time error, which the caller can never see.

### D8. Errors an operator can read

The hub logs only an error's type, so each backend returns typed errors: `ErrUnauthorized` for a broker's refusal, `ErrStandby`, `ErrEnvelopeTooLarge`, and `httpsec/signalwire`'s decode errors. **Override:** none, since these describe failures.

### D9. `Verify`

`Verify(ctx)` is called by the consumer at start, as `redisstore.Verify` is, and sends one probe through a short-lived subscription to prove the permissions and the path. On PostgreSQL it also checks `pg_is_in_recovery()`. It is not in the port. **Default:** not called, so it costs nothing unasked, and the README says to call it.

## Risks / Trade-offs

- **[A reconnect loses messages]** Both backends lose what was sent while disconnected. → The heartbeat bounds `session_ended`. Other signals are lost, as the port already states.
- **[A bus outage silences this replica's own signals]** With a consumer's bus, nothing is delivered locally. → Stated in the godoc. The heartbeat still ends streams. This is the port's existing behaviour.
- **[The listener needs a direct connection]** → `WithListenConfig`, and the README states it.
- **[A clock skewed past the window drops signals]** → Counted, typed, `WithReplayWindow(0)` turns it off, and the heartbeat bounds `session_ended`.
- **[The MAC does not stop a broker dropping messages]** → A bus may be lossy by contract.

## Migration Plan

None. Both modules are opt-in, and `SignalBusChecker` is optional.

## Open Questions

- Should the port learn to say a subscription resumed, so that streams reread at once? Only a latency improvement, so left until something needs it.
- `redis.UniversalClient` having `SSubscribe` was not verified. If it lacks it, `WithSharded()` type-asserts and refuses at construction (task 2.3).

## References

### Redis mechanism (D2)

**Researched (accessed 2026-11-05):**
- [Redis Pub/Sub](https://redis.io/docs/latest/develop/pubsub/): at-most-once delivery, sharded Pub/Sub, database scoping.
- [Redis SSUBSCRIBE](https://redis.io/docs/latest/commands/ssubscribe/): shard channel slot rule.
- [Redis ACL](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/): `&channel` rules, used by the opt-out in D5.
- [Redis TLS](https://redis.io/docs/latest/operate/oss_and_stack/management/security/encryption/): transport protection.
- [Redis protocol spec](https://redis.io/docs/latest/develop/reference/protocol-spec/): the default 512 MB bulk limit, so 8 KiB is no concern.
- go-redis v9.23.0 `pubsub.go`, from the module cache: `Receive` returns errors, `Channel()` retries forever, reconnect and resubscribe.

### PostgreSQL mechanism (D3, D6)

**Researched (accessed 2026-11-05):**
- [PostgreSQL NOTIFY](https://www.postgresql.org/docs/current/sql-notify.html): payload under 8000 bytes, 8 GB queue, failure at commit.
- [PostgreSQL LISTEN](https://www.postgresql.org/docs/current/sql-listen.html): session scope, so a reconnect loses messages.
- [PostgreSQL hot standby](https://www.postgresql.org/docs/current/hot-standby.html): both commands fail on a standby.
- [PostgreSQL lexical structure](https://www.postgresql.org/docs/current/sql-syntax-lexical.html): the 63-byte identifier limit and truncation.
- [PgBouncer features](https://www.pgbouncer.org/features.html): `LISTEN` unsupported in transaction pooling, `NOTIFY` supported.
- [Recall.ai on LISTEN/NOTIFY](https://recall.ai/blog/postgres-listen-notify-does-not-scale) and [DBOS on LISTEN/NOTIFY](https://dbos.dev/blog/postgres-listen-notify-scalability): the global commit lock, on which they disagree.
- pgx v5.12.0 source and README, from the module cache: `WaitForNotification`, and `LISTEN`/`NOTIFY` unavailable through `database/sql`.
- [gorm connecting to the database](https://gorm.io/docs/connecting_to_the_database.html): gorm sits on `database/sql`.
- [Socket.IO Postgres adapter](https://socket.io/docs/v4/postgres-adapter/): the 8000-byte threshold and table spill.

### Authenticity (D5)

**Researched (accessed 2026-11-05):**
- [Socket.IO Redis adapter](https://socket.io/docs/v4/redis-adapter/): states messages are unsigned and Redis is trusted.
- [Rails Action Cable](https://guides.rubyonrails.org/action_cable_overview.html), [Django Channels layers](https://channels.readthedocs.io/en/stable/topics/channel_layers.html), [Phoenix.PubSub](https://phoenix-pubsub.hexdocs.pm/Phoenix.PubSub.html): nothing found on signing bus messages.

**Primary documentation:**
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104): HMAC.

### Live facts (accessed 2026-11-05; these drift)

- [OSV query API](https://api.osv.dev/v1/query): no record for go-redis v9.23.0 or pgx v5.12.0, which is not proof of absence.
- [proxy.golang.org](https://proxy.golang.org/github.com/redis/go-redis/v9/@latest): go-redis v9.23.0 and pgx v5.12.0 are the latest there.

### Modules and the port (D1, D4, D7, D8, D9)

Reasoned from scrty's own settled specs and the established design.
