## Why

`shared-rate-limiting` gives multi-replica deployments a shared limiter on Redis or Valkey. Many durable deployments already run PostgreSQL and no Redis. For them the per-replica multiplication of every rate limit remains, unless they take on a new server. A PostgreSQL limiter closes the gap with infrastructure they already have, provided its write and read cost on the security-state database is acceptable and measured.

It is a separate change because, unlike Redis, a table does not expire its own rows. The limiter needs a prune task from `expiry-sweeping` (change `operation-hardening`), which is not built yet.

## What Changes

- **A PostgreSQL limiter** behind `ratelimit.Limiter` and `ratelimit.LimiterFactory`, in the `sqlstore` and `pgx` adapters. gorm consumers pass `db.DB()` to `sqlstore`. It passes the `ratelimit` conformance suite from `shared-rate-limiting`, and the same sliding-window semantics:
  - one row per namespace and key, holding at most the limit's number of newest stamps;
  - one atomic upsert per record;
  - one read per check;
  - time from `clock_timestamp()` by default.
- **Designed for PostgreSQL's update path:**
  - no index on a column that changes on every write, so updates can be HOT;
  - a lowered `fillfactor` and per-table autovacuum settings, chosen by benchmark;
  - a logged table only, because an unlogged table is emptied by a crash or failover, which would silently disarm every limit;
  - a cap on the limit, so a row stays well under the TOAST threshold;
  - a `lock_timeout` alongside the operation timeout.
- **Primary only.** Reads from a standby undercount. `Verify` refuses a connection in recovery and checks that the table exists.
- **The limiter ignores ambient transactions.** A failure recorded in the request's transaction would roll back with it. The limiter is excluded from the store ambient-transaction conformance suite, and the exclusion is stated.
- **Pruning through `expiry-sweeping`.** The prune never removes a key whose newest stamp is inside the longest window any replica recorded with. The `operation-hardening` task constructor for the rate limiter is widened from the in-memory type to a pruner interface.
- **One table in the security-state migration set**, folded into the initial file before the first tag. Its SQL lives in `internal/pgschema`.
- **A benchmark** of check and record latency under contention, with a separate pool and with a shared one. It decides the documented recommendation for API-key-heavy traffic.
- **Wiring:** plain constructors. Container selection from a registered database is in `di-wiring`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rate-limiting`: adds the PostgreSQL limiter's guarantees (primary only, ambient transactions ignored, the prune bound).
- `security-state-stores` and `schema-migrations`: the limiter table, and its exception to ambient-transaction participation.
- `expiry-sweeping`: the rate-limiter task accepts any limiter that can prune.

## Impact

- **New code:** limiters in `sqlstore` and `pgx`, the shared SQL in `internal/pgschema`, one migration, conformance and benchmark runs in the `test` module.
- **Depends on:** `shared-rate-limiting` (factory, unavailable modes, conformance suite) and `operation-hardening` (`expiry-sweeping`).
- **Consumers:** none yet. Nothing is tagged.

## References

### PostgreSQL storage and update path
**Researched (accessed 2026-10-03):**
- [PostgreSQL: Heap-Only Tuples](https://www.postgresql.org/docs/current/storage-hot.html): an update that changes an indexed column is never HOT; `fillfactor`.
- [PostgreSQL: CREATE TABLE](https://www.postgresql.org/docs/current/sql-createtable.html): unlogged tables are truncated after a crash and not replicated; per-table storage parameters.
- [PostgreSQL: TOAST](https://www.postgresql.org/docs/current/storage-toast.html): the roughly 2 kB threshold.
- [PostgreSQL: hot standby](https://www.postgresql.org/docs/current/hot-standby.html): standbys are eventually consistent.
- [PostgreSQL: date/time functions](https://www.postgresql.org/docs/current/functions-datetime.html) and [WITH queries](https://www.postgresql.org/docs/current/queries-with.html): `clock_timestamp()` semantics; a volatile CTE is evaluated once.
- [PostgreSQL: SELECT, the locking clause](https://www.postgresql.org/docs/current/sql-select.html): `SKIP LOCKED` suits queue-like consumers such as a pruner.

### Established practice
**Researched (accessed 2026-10-03):**
- [Bucket4j](https://bucket4j.com/8.14.0/toc.html): a PostgreSQL backend with `SELECT FOR UPDATE` or advisory locks, and manual expiry.
- [rate-limiter-flexible, PostgreSQL store](https://github.com/animir/node-rate-limiter-flexible/wiki/PostgreSQL): about 995 requests per second, and a warning to test above 500. Indicative only, because it uses a different algorithm.
- [Keycloak caching guide](https://raw.githubusercontent.com/keycloak/keycloak/main/docs/guides/server/caching.adoc) and [Django-axes configuration](https://django-axes.readthedocs.io/en/latest/4_configuration.html): brute-force state kept in the database.
