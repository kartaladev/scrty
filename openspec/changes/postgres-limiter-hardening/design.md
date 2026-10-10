## Context

See proposal.md for why. The starting point is the PostgreSQL limiter of `shared-rate-limiting-postgres` (archived 2026-10-10; design decisions 1–12 there), on branch `feat/shared-rate-limiting-postgres`, PR #13. This change corrects that design where the review proved it wrong, and keeps everything else.

Constraints that shape the approach:
- **Row shape.** A bucket is one row per (namespace, key). It has a `timestamptz[]` of at most `limit` stamps. The table is logged, keyed only by its primary key, with `fillfactor = 70` and both autovacuum scale factors at 0.01. The migration is untagged, so it may still be edited in place.
- **Failure handling.** Every backend error goes to `internal/unavailable`, which opens a breaker for the whole namespace. In the default mode it refuses every check for the probe interval (1s), and a failed record holds its key as exceeded for one window.
- **Sweeping.** The `operation-hardening` design, decision 3, says the runner never batches. It allows "a store whose purge bounds itself".
- **What the chain asks for.** The default chain's largest asks are password login at 200 (50 × the IPv6 aggregate's multiplier of 4) and passwordless begin at 120. Then come API key at 80, and magic link, OIDC handoff and both recovery flows at 40 each. `WithIPv6Aggregate` takes any multiplier.
- **No precedent to depart from.** The established design has no database-backed limiter, so nothing here departs from it.

## Goals / Non-Goals

**Goals:**
- The default chain builds over either PostgreSQL factory. A test pins it.
- No limiter statement waits on another limiter statement past the operation timeout.
- Every database the limiter cannot serve is refused by `Verify`, before traffic.
- One copy of the logic both adapters share.

**Non-Goals:**
- **A cap-free limiter (one row per failure).** It stays the escape hatch for limits above the new maximum (decision 1, option C).
- **Clamping the chain's default aggregate to a backend's maximum.** It would add an interface to `ratelimit` and change `httpsec` for a case the new maximum already covers.
- **Any change to the Redis limiter's behaviour.** Only its godoc sentence changes (decision 8).

## Decisions

### 1. The limit maximum — **PENDING: the user's decision**

The specs and tasks wait on this decision. The prune, encoding and other decisions below do not depend on it.

**Measured** (postgres 15.19 and 18.6, Docker on arm64 macOS; directional, single client):
- **The binding ceiling is HOT, not TOAST.** An update is HOT only while old and new versions fit one 8 kB page, so a row of about 4,072 bytes or less. At 4,168 bytes, HOT fell to 0%, with about 4.5 kB of WAL per update. TOAST's trigger, a row of about 2,032 bytes, can be raised.
- **Row sizes**, uncompressed, with a 64-byte namespace:
  - 200 stamps: 1,776 bytes with a 40-byte key, 2,256 bytes with a 512-byte key;
  - 400 stamps: 3,376 and 3,856 bytes;
  - 450 stamps: 4,256 bytes with a 512-byte key.
- **The hard per-row limit** is 8,160 bytes (`row is too big`), about 1,010 stamps.

**Options:**
- **A (recommended).** Set `toast_tuple_target = 8160` on `rate_limit_buckets` in the migration, and raise the maximum to **400**.
  - **Measured:** the array stays in-line and uncompressed. HOT was 100% up to about 450 stamps, even at the 512-byte key maximum. At 256 stamps it ran 5,273 tps against 4,236 for default storage on pg18.
  - **Reach:** covers the defaults, and a login limit doubled to 100.
  - **Above 400:** a configuration error naming 400. The consumer uses the Redis limiter or their own limiter behind the port.
  - **Override:** an operator can still change the parameter with `ALTER TABLE … SET`. Losing it degrades rows to TOAST, so it costs performance, not correctness, and `Verify` does not refuse its absence.
- **B.** Store raw keys above 128 bytes as digests, and raise the maximum to 200. It fits the default TOAST threshold, which allows about 220 stamps, and covers the defaults with no headroom. It also lowers the digest threshold that `shared-rate-limiting-postgres` decision 3 set at 512 bytes.
- **C.** One row per failure: an insert-only log keyed by (namespace, key, stamp).
  - **No cap.** Measured checks are comparable to the array's: 0.07–0.13ms over 200–480 rows.
  - **Cost:** it is a redesign. It needs new statements, a new prune and the benchmark redone, and it churns dead tuples on trim.
- **D.** A, plus the chain clamping its default aggregate to a factory-reported maximum. It adds a `ratelimit` interface and changes `httpsec`.

**Rejected:**
- **Accepting TOAST:** about 3.5 kB of WAL per update at 512 stamps against about 340 bytes at 200, and TOAST-table churn.
- **`SET STORAGE MAIN`:** it still compresses on every update, so HOT depends on how well the stamps compress.
- **Compact stamp encodings:** `int4` microsecond offsets overflow at 35.8 minutes, and two defaults use one-hour windows. Milliseconds lose the microsecond precision the conformance suite pins.
- **An approximate counter:** the suite requires exact counting.

**Corrections to `shared-rate-limiting-postgres` decision 3, whatever is chosen:**
- The largest built-in ask is 200, not 30.
- NIST SP 800-63B's 100-failure ceiling bounds consecutive failures on one account. An IPv6 aggregate spans many accounts, so the ceiling does not size it.

### 2. The prune bounds itself in batches of keys

**Problem:**
- The single statement locks every victim (`LockRows`) and holds the locks until it commits. That took 1.4–2.8s at 10⁶ idle rows.
- A record on a victim key waits on it. With the real statements, every timed record against a locked victim failed at 251–254ms with SQLSTATE 55P03, on both majors.
- Under 300 records per second, 23% of records waited over 250ms, up to 1.76s. Each would open its namespace's breaker.

**Decision:** the prune loops over batches. Each batch is its own transaction:
```sql
WITH v AS (
  SELECT b.namespace, b.key FROM rate_limit_buckets b
  WHERE b.newest_at + b.longest_window_us * interval '1 microsecond' <= $1
  LIMIT $2 FOR UPDATE SKIP LOCKED)
DELETE FROM rate_limit_buckets d USING v
WHERE d.namespace = v.namespace AND d.key = v.key
```
- **The time.** `$1` is fixed once per run: the factory's clock, or one `clock_timestamp()` read before the first batch. A record during the run stamps later than `$1`, so it is never a victim.
- **The loop.**
  - It stops when a batch removes fewer than `$2` keys.
  - It checks `ctx` between batches.
  - A failed batch ends the run. The batches before it stay committed.
- **The count.** The keys removed by committed batches. On error, the partial count is returned with the error.
- **Default:** 1,000 keys per batch.
- **Override:** a new factory option, `WithLimiterPruneBatchSize(n)`, on both backends. An `n` below 1 is a configuration error.
- **Measured** at batches of 1,000, with 10⁶ idle rows and the same record load:
  - batches took 18–29ms;
  - the worst record wait was 9–92ms, and no record waited over 250ms;
  - the run took 2.7–2.8s in total;
  - no recorded key was lost.
  - At steady state (2% victims), 392ms against 410ms for the single statement.
  - Batches of 5,000 or more ran 116–289ms each, too close to the record's timeout.
- **Guarantees.** Both were tested with a forced race:
  - **A key updated after the batch's snapshot is kept.** The locking subquery rechecks the bound on the new version.
  - **A held row is skipped, not waited for.**
- **Rejected alternatives:**
  - **A lock-free `DELETE … WHERE (namespace, key) IN (…)`** deleted a freshly updated key in the race test. It breaks the first guarantee.
  - **Lock-free `ctid` deletes** wait on held rows.
  - **`NOWAIT`** fails the whole batch.
  - **A `ctid`-keyed locking variant** was about 3× faster. Key-based was chosen so correctness does not rest on tuple-address stability.
- **The godoc's 10-minute interval stands.** The caveat that a large backlog can open the breaker goes.
- **Consistency with `operation-hardening` decision 3:** the purge bounds itself, which that decision allows, and the runner is unchanged.

### 3. `Verify` requires a UTF-8 database

**Evidence** (postgres:18, the pgx v5 driver natively and through `database/sql`):
- pgx sends no `client_encoding`, so a connection takes the database's own.
- On LATIN1, WIN1252 and SQL_ASCII, default connections stored UTF-8 bytes unconverted and counted correctly.
- On EUC_JP and EUC_KR, every non-ASCII key failed with SQLSTATE 22021.
- With `client_encoding=UTF8` set on the connection, every non-UTF-8 database except SQL_ASCII failed unrepresentable keys with SQLSTATE 22P05.
- The breaker trip that follows is the documented path for any statement error. It was not run end to end.
- No part of scrty states an encoding requirement, though every store's `text` columns assume UTF-8.

**Decision:** `Verify`, on the limiter and the factory, reads `server_encoding` with the other server facts. It refuses anything but `UTF8` with `ErrConfig` naming the encoding, SQL_ASCII included. The godoc of both factories states the requirement.
- **Default and override:** there is no override, as for every other `Verify` check (`shared-rate-limiting-postgres` decision 6). A consumer who disagrees does not call `Verify`.

**Rejected alternatives:**
- **Treating data errors (class 22) as per-request outcomes.** Refusing locks out every user with such a name. Allowing is a fail-open an attacker chooses.
- **Digesting every non-ASCII key.** It closes the class at runtime, but makes operator-readable keys opaque, for a database the rest of scrty does not support either.

### 4. A failed prune repeats none of the server's text

`Prune` wraps the driver's error with `%w`. The error reaches the expiry runner's report and logs carrying the PostgreSQL message, which can quote values.

**Decision:** wrap the error with `internal/diag.Wrap`, as `Verify` does. This keeps the context sentinels, so a cancellation is still told from a failure.
- **Default:** the fixed text. There is no override: the library does not repeat dependency text anywhere it reports.
- **Check and record:** their errors already reach logs only through `unavailable`'s `diag.Wrap`/`diag.Failure`, and stay as they are.

### 5. `Verify` names a temporary table

**Problem:** a `rate_limit_buckets` in `pg_temp` resolves first through `search_path`, with `relpersistence = 't'`. `Verify` calls it unlogged and advises `SET LOGGED`, which cannot apply to a temporary table.

**Decision:** report the persistence itself. `'u'` keeps today's message. `'t'` says the name resolves to a temporary table, which shadows the migration's and lasts only for its session.

### 6. The factories validate without building

**Problem:** `NewLimiterFactory` builds a whole limiter under a probe namespace, then discards it, to validate its options. That builds a decorator, a breaker and, in fall-back mode, a sharded in-memory limiter. It then computes the configuration a second time.

**Decision:** build the configuration once, and validate it with the same function the limiter constructor uses. `internal/unavailable` gains a validation-only entry point, so the decorator's rules are checked without constructing it. The refusals and messages are unchanged, and existing construction tests pin them.

### 7. One shared core for both adapters

**Problem:** `sqlstore` and `pgx` duplicate nearly everything except the driver call:
- the construction rules and messages;
- `lockTimeout` and the time argument;
- the server-facts check;
- the policy registry;
- the option set and its configuration.

Two copies can drift, and then a namespace valid on one backend is refused on the other, breaking "the two count together".

**Decision:** a new core-module internal package, `internal/pglimiter`, holds:
- the configuration and its validation;
- the server-facts check (decisions 3 and 5);
- the policy registry;
- the argument helpers;
- the batched prune loop (decision 2).

It runs statements through a small interface each adapter implements over its handle. Each adapter keeps:
- its public types, constructors and option functions, with their godoc;
- its error prefixes;
- its driver call.

The public API is unchanged. `LimiterOption` stays a distinct type in each package, so neither package's API names an internal type.
- **Can `pgx` import it?** Yes. The `pgx` module already imports core internal packages (`internal/pgschema`, `internal/unavailable`), which Go permits because the import paths share the module root.

### 8. The factory godoc states the conflict check's reach

**Problem:** the godoc says a factory "cannot see other processes". It is silent about other factories in the same process, and the documented example builds two over one handle.

**Decision:** state that the check covers one factory, and that the same namespace must not be built with different policies by any two factories or processes. Make the example's two factories visibly build disjoint namespaces.
- **Scope:** `sqlstore`, `pgx`, and the identical sentence in `redis`.
- **Rejected: a process-wide registry.** It would be global mutable state, and still blind to other processes.

### 9. Own test servers stay on tmpfs unless asked to restart

**Problem:** since `shared-rate-limiting-postgres`, every `WithTestPostgresOwnServer` server keeps its data on the container's disk, because only data on disk survives `Stop`/`Start`. Only the Stop/Start and outage tests need that.

**Decision:**
- A new test option, `WithTestPostgresRestartable()`, keeps an own server's data on disk.
- Without it, an own server uses tmpfs, as before.
- `Stop` and `Start` fail the test on a server built without it, naming the option.
- The standby helper and the benchmark state what they need.

### 10. The record statement's godoc

Change the record statement's godoc to say it keeps the newest `limit` stamps, the new one included. The current text, "the newest $3 of its stamps and the new one", reads as up to `limit` + 1.

## Defect claims

Each claim is marked REPRODUCED or UNREPRODUCED, as `defect-claims.md` requires.

- **Decision 1 — REPRODUCED.**
  - **Test:** `TestRepro_PostgresFactoryWithDefaultFormLogin`, in a disposable export of the branch outside the project, beside `httpsec`'s login harness.
  - **Command:** `go test -count=1 -run TestRepro_PostgresFactoryWithDefaultFormLogin ./httpsec/`
  - **Failure:** `EnableFormLogin could not build its IPv6 aggregate limiter for namespace "password-login-ipv6-aggregate": ratelimit: invalid configuration: a limit of 200 is above 128, the most failure stamps a bucket's row holds`
  - **Shown to target the defect:** it passes once the maximum is raised in the export.
  - **First task:** the same test, over both PostgreSQL factories, is this change's first red step.
- **Decision 2 — REPRODUCED by experiment; failing test pending.** The measurements are in decision 2. The first task for it is a Go test in which a record on a victim key, during a prune over enough rows, fails against the single statement.
- **Decision 3 — REPRODUCED by experiment for the SQLSTATEs; UNREPRODUCED for the breaker trip.** The first task is a `Verify` test against a LATIN1 and an EUC_JP database, seen passing vacuously today, then red once asserted.
- **Decisions 4 and 5 — UNREPRODUCED** (no failing test yet). The first task for each is the failing test:
  - a prune error over a driver error with a distinctive message, whose text must not appear;
  - `Verify` against a temporary table, whose message must name it.
- **Decisions 6–10** are quality and documentation changes, not defect claims. Existing tests pin the behaviour 6 and 7 must keep.

## Risks / Trade-offs

- **[Rows near 4 kB cost more WAL per update]** (option A): about 1.2–1.4 kB at 400–500 stamps. → Only limiters configured that high pay it. Every default stays at or below 200 stamps.
- **[An operator recreates the table without the storage parameter]** (option A) → Rows above the TOAST threshold degrade to TOAST: slower, never wrong. Documented beside the migration and in the factory godoc.
- **[A batched prune over a sparse table scans repeatedly]** → Each batch scans from the start until it finds `n` victims. At victims of about one per 10⁴ rows, that is roughly one scan per batch. This case was not measured. The steady state was measured, at 2% victims and with none.
- **[A prune cancelled mid-run reports a partial count]** → Documented as a lower bound, returned with the error.
- **[The shared core is a refactor of tested code]** → Both adapters' existing suites must stay green unchanged. Its review is held to the stricter standard of a refactor that keeps behaviour.

## Migration Plan

There are no tags and no consumers. The migration is edited in place if decision 1 takes option A. The change lands on PR #13's branch, before it merges, or as its own branch after it.

## Open Questions

None beyond decision 1, which is not deferrable: it decides the specs and tasks, and waits on the user.

## References

### Decision 1: the limit maximum
**Researched (accessed 2026-10-10):**
- [PostgreSQL 18: TOAST](https://www.postgresql.org/docs/18/storage-toast.html): the roughly 2 kB `TOAST_TUPLE_THRESHOLD`, and the PLAIN, EXTENDED, EXTERNAL and MAIN strategies.
- [PostgreSQL 18: Heap-Only Tuples](https://www.postgresql.org/docs/18/storage-hot.html): a HOT update needs room for the new version on the same page.
- [PostgreSQL 18: CREATE TABLE](https://www.postgresql.org/docs/18/sql-createtable.html): `toast_tuple_target` ranges from 128 to 8,160 bytes and applies to new tuples.
- [PostgreSQL 18: ALTER TABLE](https://www.postgresql.org/docs/18/sql-altertable.html): `SET STORAGE` applies only to future rows.
- [NIST SP 800-63B-4, §3.2.2](https://pages.nist.gov/800-63-4/sp800-63b.html): no more than 100 consecutive failed attempts on a single subscriber account, an upper bound.
- Measurements on postgres 15.19 and 18.6: row sizes, the HOT line and throughput. They are directional and drift with hardware.

### Decision 2: the batched prune
**Researched (accessed 2026-10-10):**
- [PostgreSQL: SELECT, the locking clause](https://www.postgresql.org/docs/current/sql-select.html): `SKIP LOCKED` for queue-like tables; `LIMIT` with `FOR UPDATE` stops locking at the limit; rows updated after the snapshot are rechecked.
- [river, job cleaner](https://raw.githubusercontent.com/riverqueue/river/master/internal/maintenance/job_cleaner.go): batched deletes that loop while a batch is full. Only the loop was read.
- [Rails solid_cache, expiry](https://raw.githubusercontent.com/rails/solid_cache/main/lib/solid_cache/store/expiry.rb): an expiry batch size of 100. The delete query was not read.
- Measurements and race tests on postgres 15 and 18: lock holding, record waits, batch timings and both guarantees.

### Decision 3: encoding
**Researched (accessed 2026-10-10):**
- [PostgreSQL 18: Character Set Support](https://www.postgresql.org/docs/18/multibyte.html): server encodings, client-encoding conversion, and SQL_ASCII performing no conversion.
- [PostgreSQL 18: Error codes](https://www.postgresql.org/docs/18/errcodes-appendix.html): 22P05 `untranslatable_character`, 22021 `character_not_in_repertoire`.
- pgx v5.11.0 source (module cache): it sends no `client_encoding` at startup.
- Experiments on postgres:18 with LATIN1, WIN1252, SQL_ASCII, EUC_JP and EUC_KR databases, through pgx and `database/sql`.

### Decisions 4–10
Reasoned from scrty's own settled specs (`rate-limiting`, `expiry-sweeping`), the archived designs of `shared-rate-limiting-postgres` and `operation-hardening`, the project's `internal/diag` convention, and the established design.
