## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** `shared-rate-limiting` (archived) defines everything backend-neutral, and this change reuses it unchanged:
  - the `ratelimit.Limiter` port;
  - `ratelimit.LimiterFactory`, `ratelimit.Verifier` and `ratelimit.PolicyReporter`;
  - `ratelimit.UnavailableMode`, and the `internal/unavailable.Wrap` decorator. The decorator carries the operation timeout (default 250ms), the breaker's probe interval (default 1s), the three modes, the local refusal hold after a failed record, and sampled allow-mode logging;
  - the conformance suite `test/ratelimittest` (`Harness{New, Advance, SecondInstance}`, `Run`).

  The Redis limiter is the model for every shared-limiter rule this design does not restate: sliding-window-log semantics with no trimming by time on record, namespaces, the colon rule, digests for long keys, factory dedupe, the precision in microseconds and constructors that perform no I/O.
- **`operation-hardening`** (archived) provides `expiry.Task` and `ratelimit.ExpiryTask(l *ratelimit.MemoryLimiter)`, which calls `MemoryLimiter.Prune() int`. Its decision 3 calls each owner's purge once, with no batching.
- **Adapters.**
  - `sqlstore` (core, `*sql.DB`) and `pgx` (nested module, `*pgxpool.Pool`) share their SQL through `internal/pgschema` constants.
  - The stores pick up an ambient transaction from the context or from `WithTxResolver`.
  - `gorm` has native stores of its own over `*gorm.DB`.
- **Migrations.** The security-state set is one embedded goose file, `migrate/securitystate/20260926000000_security_state.sql`, with fourteen tables and no storage parameters. The fourteenth, `login_failure_streaks`, came with `consecutive-failure-hold`, and the migration tests pin every table's exact columns and indexes. Nothing is tagged, so the file may still be edited.
- **The test module** provides:
  - `RunTestPostgres(t, opts...) PostgresConn{DB *sql.DB, DSN string}`, on a shared server per image or an own server;
  - a matrix over `SCRTY_TEST_POSTGRES_IMAGE`, with 15 and 18 in CI;
  - for Redis only, `Stop` and `Start` on its own containers.
- **The established design** has an in-memory limiter, its prune and a sweep task, and no database-backed limiter. Every decision it records for the limiter is kept. Nothing in this change departs from it.

## Goals / Non-Goals

**Goals:**
- A PostgreSQL limiter that passes the same conformance suite as the Redis one, on both backends and both supported PostgreSQL majors.
- A write path that stays HOT and out of TOAST, and a lock wait the server itself abandons.
- One expiry task that bounds the table, and can never free quota.
- A benchmark that settles the storage parameters and the pool recommendation, with the numbers recorded here.

**Non-Goals:**
- **Changing the default.** In-memory stays the default for every flow.
- **A gorm-native limiter.** The limiter ignores ambient transactions, so a gorm-native one would add nothing over `sqlstore` on `db.DB()`.
- **Batched or incremental pruning.** This follows `operation-hardening` decision 3.
- **Container selection.** That belongs to `di-wiring`.
- **Closing the check-then-record overshoot.** It is the same documented bound as for Redis.
- **Reading from standbys, and partitioned or sharded tables.**

## Decisions

### 1. Where the code lives, and its API

| Module | Package | Adds |
|---|---|---|
| core | `internal/pgschema` | `ratelimit.go`: the limiter's statements, shared by both backends |
| core | `sqlstore` | `NewLimiter(db *sql.DB, namespace string, limit int, window time.Duration, opts ...LimiterOption) (*Limiter, error)`, `NewLimiterFactory(db *sql.DB, opts ...LimiterOption) (*LimiterFactory, error)` |
| `pgx` | `pgx` | the same two constructors over `*pgxpool.Pool` |
| core | `ratelimit` | `Pruner`, and `ExpiryTask(p Pruner)` (decision 8) |
| core | `migrate/securitystate` | the `rate_limit_buckets` table, in the initial file (decision 2) |
| `test` | root, `ratelimittest` | the conformance runs, fault tests, the standby helper and the benchmark (decisions 10 and 11) |

- **The limiter has its own option type, `LimiterOption`.** Store options would make `WithTxResolver` and `WithIDGenerator` look meaningful to a limiter, and an option should be named after what it governs.
  - **The options:** `WithLimiterClock`, `WithLimiterOnUnavailable`, `WithLimiterOperationTimeout`, `WithLimiterProbeInterval`, `WithLimiterUnavailableLogInterval`, `WithLimiterLogger`.
  - **Defaults:** the decorator's defaults, the database clock (decision 5) and `slog.Default()`.
  - **The prefix:** Redis's options are unprefixed because the `scrtyredis` package holds only a limiter. Here the package also holds stores, so the prefix says which component an option governs.
- **Both types implement** `ratelimit.Limiter`, `ratelimit.PolicyReporter` and `ratelimit.Verifier`. The factory also implements `ratelimit.LimiterFactory` and `ratelimit.Pruner`.
- **gorm consumers** pass `db.DB()` to `sqlstore`. The `gorm` package's godoc says so, with an example.
- **Construction errors** (`ratelimit.ErrConfig`, as for Redis):
  - a nil handle, typed nil included;
  - an empty namespace, or one containing a colon;
  - a limit below 1 or above 128, or a namespace longer than 64 bytes (decision 3);
  - a window under one microsecond;
  - a nil clock or logger, an unknown mode, or a non-positive timeout or probe interval.
  - **The colon rule is kept although columns separate namespace and key.** A namespace valid on one shared backend should be valid on the other, so switching backends cannot fail at startup.

### 2. One table, shaped for PostgreSQL's update path

```sql
CREATE TABLE rate_limit_buckets (
    namespace         text        NOT NULL,
    key               text        NOT NULL,
    stamps            timestamptz[] NOT NULL,  -- at most `limit` newest, ascending
    newest_at         timestamptz NOT NULL,    -- greatest stamp ever recorded for the row
    longest_window_us bigint      NOT NULL,    -- longest window any instance recorded with
    PRIMARY KEY (namespace, key)
) WITH (fillfactor = <benchmark>, autovacuum_vacuum_scale_factor = <benchmark>,
        autovacuum_vacuum_insert_scale_factor = <benchmark>);
```

- **No index beyond the primary key.** The key columns never change, and every column that does change is unindexed, so an update can be HOT whenever the page has room.
  - **No index on `newest_at`:** the prune reads the whole table instead (decision 7). Indexing it would make every record non-HOT, which is exactly the cost decision 1 of `shared-rate-limiting` flagged.
  - **A BRIN index is not used either.** BRIN-only updates can be HOT only on newer majors, and CI's oldest supported major is 15.
- **A natural key, not a uuid.** A bucket is not a library-owned record with an identity. It is the pair (namespace, key). A uuid would add a second unique index and buy nothing. This is a stated exception to `schema-migrations`' uuid-key rule, made through this change's delta.
- **Logged.** An unlogged table is truncated after a crash and is not replicated to standbys. Every limit would silently restart at zero on failover. `Verify` refuses an unlogged table (decision 6).
- **`timestamptz[]`:**
  - it is microsecond-precise, the precision the shared limiters already document;
  - it reads naturally out of band;
  - a 1-D array of 128 elements without nulls is 24 + 128 × 8 = 1,048 bytes.
- **Storage parameters come from the benchmark** (decision 11). They are set in the migration, so an operator can still change them with `ALTER TABLE … SET (…)`. That is the override. The library never changes them at runtime.
- **The table name is fixed**, as every security-state table's name is. The override is a consumer's own limiter behind the port. A table-name option would be the only one of its kind in the adapters.
- **Migration:** added to the initial file before the first tag, with the matching `DROP TABLE IF EXISTS` in the down section. The set's table-list tests go from fourteen to fifteen, and the bucket table joins the tests' exact column and index maps.

### 3. Each row stays under the TOAST threshold

PostgreSQL compresses, then moves out of line, any row wider than about 2 kB. A toasted `stamps` array would turn each record into a de-TOAST and re-TOAST of the array, plus a write to the TOAST table.

The widest row has these parts:

| Part | Bytes |
|---|---|
| tuple header | 24 |
| namespace (at most 64) | about 65 |
| key (at most 512, longer keys stored as a 71-byte digest) | about 516 |
| `stamps` (at most 128) | 1,048 |
| `newest_at`, `longest_window_us` and alignment | about 24 |
| **Total** | about 1,680, under the threshold with room to spare |

- **Default and limit:** a limit above 128, or a namespace above 64 bytes, is a configuration error that names the maximum (library-design rule 4). The largest built-in default is 30 (the passwordless begin).
- **Override:** none. A consumer who needs more than 128 failures per window is far past NIST's 100-failure ceiling for a single account. That consumer uses the Redis limiter, which has no row to fit.
- **Long keys:** the digest rule of the Redis limiter applies. A key longer than 512 bytes, or one that begins with `sha256:`, is stored as `sha256:` followed by its hex digest.

### 4. The statements: one read per check, one upsert per record

All of these live in `internal/pgschema/ratelimit.go`. `$now` is `NULL` in database-clock mode, and each statement takes its time once, from `coalesce($now, clock_timestamp())` in a CTE.

**Check** is one primary-key lookup, with no write and no row lock:
```sql
WITH t AS (SELECT coalesce($4::timestamptz, clock_timestamp()) AS now)
SELECT count(*) FROM rate_limit_buckets b, t, unnest(b.stamps) s
WHERE b.namespace = $1 AND b.key = $2 AND s > t.now - $3 * interval '1 microsecond';
```

**Record** is one `INSERT … ON CONFLICT DO UPDATE` statement:
- **insert:** `stamps = ARRAY[now]`, `newest_at = now`, `longest_window_us = $window`;
- **on conflict:**
  - `stamps` becomes the newest `$limit` of `old || now`, ascending;
  - `newest_at` becomes `GREATEST(old, now)`;
  - `longest_window_us` becomes `GREATEST(old, $window)`;
- **no trimming by time**, for the reason recorded for Redis: a short-window replica would delete failures that a long-window replica still counts;
- **simpler than Redis:** the row keeps `newest_at` and the longest window in their own columns, so app-clock skew needs no member rewrite. A stamp that sorts below the newest cannot take the carried window with it.
- **Stated trade-off:** `longest_window_us` only grows while the row lives. After a namespace's window is lowered, a busy key is kept longer than needed until it goes idle. That only delays the prune, and `Exceeded` always uses the checking instance's own window.

**Clock (decision 5):** the record's `now` comes from the same CTE.

**Lock wait (decision 6):** the upsert's source row also evaluates `set_config('lock_timeout', $ms, true)`.

### 5. Time comes from the database by default

- **Default:** `clock_timestamp()`, read once per statement through a CTE. It is not `now()`, which is the transaction's start and would be stale inside a consumer's long-lived pooled transaction, if a misconfigured handle ever gave one. It is also not read twice per statement, because two calls give two different values.
- **Override:** `WithLimiterClock(clock.Clock)` passes the application's time as `$now`. That is the app-clock mode the conformance suite uses. A nil clock is a configuration error.
- **Stated limit:** in app-clock mode, replica clocks must agree to well within the window, as for Redis.

### 6. Operation timeout, lock timeout, availability and primary-only

- **Operation timeout:** the decorator bounds each call with a context deadline (default 250ms). Both drivers send a cancel request when that deadline passes.
- **Lock timeout:** a cancel request is asynchronous and needs a new connection. So the record also tells the server to stop waiting for the row: `set_config('lock_timeout', <operation timeout>, true)`, transaction-local.
  - **Bound:** the lock timeout is the operation timeout in whole milliseconds, at least 1ms. PostgreSQL refuses a `lock_timeout` above 2,147,483,647ms (about 24.8 days), and every record would then fail as unavailable. So an operation timeout above that maximum is a configuration error naming it, not a value silently capped (library-design rules 4 and 6).
  - **Where it runs:** it is evaluated in the `SELECT` that feeds the `INSERT`, so it is in force before the conflict path waits for the row. That keeps the record to one statement and one round trip on both backends.
  - **Proof:** the order is the executor's, not something the documentation promises. The `rate-limiting` scenario "Row held by another session" is the test that proves it, on both supported majors.
  - **Fallback if it fails red-for-the-wrong-reason or flakes:** wrap the record in an explicit transaction with `SET LOCAL lock_timeout`, as a pipelined batch on pgx and `BeginTx` on `database/sql`. Record the switch here.
  - **The check needs no lock timeout.** An MVCC read takes no row lock. A table-level conflict, such as a migration's `ALTER TABLE`, is bounded by the operation timeout.
- **Unavailable:** these all go to the decorator, so the breaker, the modes and the local refusal hold after a failed record behave exactly as for Redis:
  - any driver error, a lock timeout (SQLSTATE `55P03`) or pool exhaustion while the caller's context is live;
  - an undefined table at runtime. `Verify` is where that is diagnosed; at runtime it fails closed like any error.
- **The ended-context rules** are those of every shared limiter, enforced by the decorator.
- **Primary only.** A standby lags, so it undercounts, and it refuses writes. `Verify(ctx)`, on both the limiter and the factory, fails with `ErrConfig` when:
  - `pg_is_in_recovery()` is true;
  - `server_version_num` is below 150000, the oldest major CI supports;
  - `to_regclass('rate_limit_buckets')` is null, naming the security-state migration set;
  - the table's `relpersistence` is not `p` (unlogged);
  - a probe cannot run the check, record and prune statements. A permission error (SQLSTATE `42501`) names the refused statement.

  The probe row uses an empty namespace, which no limiter can have, and a random key. It is deleted in the same call.
- **Not detectable, so documented:** a pooler or proxy that routes some connections to a standby after `Verify` passed. The godoc requires a handle that reaches only the primary.
- **Overrides:** the decorator's options (decision 1). There is no option to skip a `Verify` check. Every check guards a limit that would otherwise be silently disarmed, and a consumer who disagrees does not call `Verify` (library-design rule 4).

### 7. Pruning through one expiry task over the whole table

```sql
WITH t AS (SELECT coalesce($1::timestamptz, clock_timestamp()) AS now),
victims AS (
    SELECT b.namespace, b.key FROM rate_limit_buckets b, t
    WHERE b.newest_at + b.longest_window_us * interval '1 microsecond' <= t.now
    FOR UPDATE OF b SKIP LOCKED)
DELETE FROM rate_limit_buckets b USING victims v
WHERE b.namespace = v.namespace AND b.key = v.key;
```

- **The bound:** a row is removed only when its newest stamp is at least the longest recorded window old. At that point no instance that recorded the key still counts any of its stamps. This is the rule `rate-limiting` already requires of every shared limiter.
- **Races:**
  - a row a record holds is skipped, not waited for;
  - a row updated between snapshot and lock is rechecked against its new version under READ COMMITTED, and kept;
  - a record that waited on a deleted row inserts it fresh. That row was idle, so nothing counted is lost.
- **Owner:** the factory's `Prune(ctx) (int, error)`, across every namespace. The time source is the factory's.
  - **Why one task for the table and not one per limiter:** thirteen namespaces would mean thirteen sequential scans of one table, and thirteen task names to keep unique.
  - **A consumer who built limiters with `NewLimiter` only** builds a factory for the prune. The godoc shows it.
- **Cost, stated:** a sequential scan per run. The benchmark measures it at 10⁵ and 10⁶ rows, and the godoc gives the figure and recommends an interval.
- **No cutoff parameter:** `Prune` accepts none (`expiry-sweeping`).

### 8. The expiry task accepts any pruner

```go
// in ratelimit
type Pruner interface { Prune(ctx context.Context) (removed int, err error) }
func ExpiryTask(p Pruner) expiry.Task // name "ratelimit", interval unset
```

- **`MemoryLimiter.Prune` becomes `Prune(ctx) (int, error)`.** It ignores the context and never errors. That matches the `Prune(ctx)` the `operation-hardening` design already listed for it, and gives one shape for both prunes.
  - **Compatibility:** an untagged signature change, free under library-design rule 7, and recorded here.
  - **Call sites:** every caller of `Prune()` moves to the new form in the same dispatch, found with gopls references (`subagent-delegation.md`).
- **Default and override:** unchanged. The task name is `ratelimit`, and a consumer renames it or writes their own task.

### 9. Ambient transactions are ignored, on purpose

- The limiter takes a pool, never a transaction. It has no `WithTxResolver`, and never reads the adapters' context attachment.
- **Why:** a failure recorded inside the request's transaction would roll back when that request fails, which is exactly when it must count.
- **Scope:** this applies to the PostgreSQL limiter only.
  - It is excluded from `storetest.RunAmbientTx`, and the suite's package documentation states the exclusion.
  - A dedicated test pins the opposite guarantee: a recorded failure survives the caller's rollback.
- **Override:** none. Joining the transaction would break the guarantee (library-design rule 4).

### 10. Conformance and fault tests

The tests live in the `test` module, because no other module may import it:
- **Conformance:** `ratelimittest.Run` against both backends, on the shared server with app-clock harnesses, so `Advance` drives time. `SecondInstance` builds a limiter of the other backend, which proves the scenario "Backends share one table".
- **Database clock:** a separate short-window real-time test, as for Redis. It also records several failures on one key and asserts that each record's `newest_at` equals its newest stamp exactly, which pins the read-once rule of decision 5.
- **Outage:**
  - `RunTestPostgres` gains `Stop`/`Start` for own servers, mirroring `RedisConn`;
  - one test per unavailable mode, plus one that the breaker refuses without waiting.
- **Held row:** a second connection holds the row with `SELECT … FOR UPDATE`. The record errors within the timeout, and `pg_stat_activity` shows no session still waiting on that row.
- **Standby:** a helper, `RunTestPostgresStandby`, starts a streaming standby of an own primary with `pg_basebackup -R` in a second container from the same image. `Verify` against it is the red step.
- **Privileges:** `Verify` through a role granted only `SELECT`.
- **Unlogged:** `ALTER TABLE … SET UNLOGGED`, then `Verify`.
- **Prune:** the two-window race of the `rate-limiting` scenario, an idle key, and a row locked by another session.
- **Seen to fail:** each scenario must fail against a broken variant kept in the tests, as `store-conformance` requires:
  - trimming by time on record;
  - a prune that uses the checking instance's window;
  - a limiter that joins the ambient transaction;
  - the time read twice in one record statement, once for the stamp and once for `newest_at`. In app-clock mode both reads return the passed `$now`, so the variant behaves exactly like the real statement and the conformance run cannot catch it. Its proof is the database-clock test instead: two `clock_timestamp()` calls differ by microseconds on nearly every record, so across several records `newest_at` departs from the newest stamp. The correct statement can never make them differ, so the test does not flake when green.

### 11. The benchmark settles storage parameters and the pool advice

The benchmark lives in the `test` module, against an own server, on PostgreSQL 18 and 15. It runs a sweep of these cases:
- **fillfactor:** 100, 90, 70 and 50;
- **autovacuum:** the server default, and `autovacuum_vacuum_scale_factor = 0.01` with `autovacuum_vacuum_insert_scale_factor = 0.01`;
- **load:**
  1. a hot set of 100 keys under 32 concurrent recorders;
  2. 10⁵ distinct keys with one record each;
  3. a check-heavy mix of 95% checks;
- **pools:** the limiter on its own pool, and on a pool shared with a simulated login load.

**Measured:**
- p50 and p99 for checks and records;
- the HOT ratio, from `n_tup_hot_upd / n_tup_upd` in `pg_stat_user_tables`;
- table size after a run;
- prune time at 10⁵ and 10⁶ rows;
- login-path p99 with and without the limiter on a shared pool.

**Decided from the results, and written here and into the migration by the main session:**
- the `fillfactor`;
- the two autovacuum settings;
- the recommendation for API-key-heavy traffic, which does one check per request: a separate pool, or the shared one, and from what request rate;
- the prune interval the godoc recommends.

Until then the migration carries provisional values: `fillfactor = 70`, with the server's autovacuum defaults.

### 12. Departures

- **None from established behaviour.** It has no database-backed limiter. The in-memory limiter's recorded decisions are kept, and the prune keeps their rule: no cutoff, never disarm.
- **From scrty's own settled specs**, each through a delta in this change:
  - `schema-migrations`: a fifteenth table, with a natural key in place of a uuid;
  - `security-state-stores` and `store-conformance`: the limiter does not join ambient transactions, and does not run that suite;
  - `expiry-sweeping`: the rate-limiter task covers any pruner;
  - `MemoryLimiter.Prune`'s signature (decision 8).

## Risks / Trade-offs

- **[Every passkey begin, recovery start and enrolment begin writes a row and WAL on the primary]** → It is measured (decision 11). The godoc states the write rate per flow and recommends Redis above the measured ceiling.
- **[A check on every API-key request shares the login pool]** → The benchmark settles whether a separate pool is advised. The constructor takes any pool.
- **[The prune scans the whole table]** → The benchmark measures it, the godoc recommends an interval, and `SKIP LOCKED` keeps it off hot rows.
- **[The lock-timeout ordering is executor behaviour, not documented]** → It is pinned by a test on both majors, with an explicit-transaction fallback (decision 6).
- **[Table bloat if autovacuum falls behind]** → A lowered fillfactor, per-table autovacuum settings from the benchmark, and a table size the godoc documents.
- **[A PostgreSQL outage refuses every guarded flow in the default mode]** → Logins on the same database are failing anyway. The unavailable modes are the same explicit overrides as for Redis.
- **[A pooler routing to a standby after `Verify`]** → The godoc requires a primary-only handle; it cannot be detected per call.
- **[Source keys and user references stored at rest in the security-state database]** → Stored as given and bounded by the prune, with the same reasoning as for Redis.

## Migration Plan

There are no tags and no consumers. The table is folded into the initial security-state migration. A deployment opts in in four steps:
1. apply the set;
2. build a factory on a primary-only pool;
3. call `Verify` at startup;
4. pass the factory to the chain, and add `ratelimit.ExpiryTask(factory)` to its sweeper.

It rolls back by removing the factory. Counts then restart per replica.

## Open Questions

None that change the specs or the task breakdown. The benchmark's numbers (decision 11) settle values, not structure.

## References

### Decisions 2 and 3: the update path, storage and TOAST
**Researched (accessed 2026-10-05):**
- [PostgreSQL: Heap-Only Tuples](https://www.postgresql.org/docs/current/storage-hot.html): an update is HOT only when no indexed column changes (summarizing indexes, that is BRIN, excepted) and the page has room; lowering `fillfactor` helps; HOT counts in `pg_stat_all_tables`.
- [PostgreSQL: TOAST](https://www.postgresql.org/docs/current/storage-toast.html): `TOAST_TUPLE_THRESHOLD` and `TOAST_TUPLE_TARGET` are normally 2 kB.

**Researched (accessed 2026-10-03, carried from the proposal):**
- [PostgreSQL: CREATE TABLE](https://www.postgresql.org/docs/current/sql-createtable.html): unlogged tables are truncated after a crash and not replicated; per-table storage parameters.

### Decisions 4–6: statements, clock, timeouts and primary-only
**Researched (accessed 2026-10-05):**
- [PostgreSQL: client connection defaults, `lock_timeout`](https://www.postgresql.org/docs/current/runtime-config-client.html): it applies to each lock acquisition, row locks included; a `statement_timeout` at or below it makes it pointless.
- `go doc github.com/jackc/pgx/v5.Conn.SendBatch`: a batch runs in one implicit transaction (the fallback in decision 6).

**Researched (accessed 2026-10-03, carried from the proposal):**
- [PostgreSQL: date/time functions](https://www.postgresql.org/docs/current/functions-datetime.html) and [WITH queries](https://www.postgresql.org/docs/current/queries-with.html): `clock_timestamp()` semantics, and a volatile CTE evaluated once.
- [PostgreSQL: hot standby](https://www.postgresql.org/docs/current/hot-standby.html): standbys are eventually consistent.

### Decision 7: pruning
**Researched (accessed 2026-10-03, carried from the proposal):**
- [PostgreSQL: SELECT, the locking clause](https://www.postgresql.org/docs/current/sql-select.html): `SKIP LOCKED` for queue-like consumers.

### Decision 11 and the backend choice
**Researched (accessed 2026-10-03, carried from the proposal):**
- [Bucket4j](https://bucket4j.com/8.14.0/toc.html): a PostgreSQL backend using `SELECT FOR UPDATE` or advisory locks, with manual expiry.
- [rate-limiter-flexible, PostgreSQL store](https://github.com/animir/node-rate-limiter-flexible/wiki/PostgreSQL): about 995 requests per second, and advice to test above 500. Indicative only, because it uses a different algorithm.
- [Keycloak caching guide](https://raw.githubusercontent.com/keycloak/keycloak/main/docs/guides/server/caching.adoc) and [Django-axes configuration](https://django-axes.readthedocs.io/en/latest/4_configuration.html): brute-force state kept in the database.

**Primary documentation:**
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), §3.2.2: at most 100 consecutive failures per account (the limit maximum, decision 3).

### Decisions 1, 8–10 and 12
Reasoned from scrty's own settled specs (`rate-limiting`, `expiry-sweeping`, `schema-migrations`, `security-state-stores`, `store-conformance`), the archived designs of `shared-rate-limiting` and `operation-hardening`, and the established design.
