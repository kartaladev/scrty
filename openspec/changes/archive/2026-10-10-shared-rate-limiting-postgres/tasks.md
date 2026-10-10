# Tasks

Every task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), then implement, then refactor with the tests green.

## 1. The expiry task accepts any pruner

- [x] 1.1 Add `ratelimit.Pruner` and change `ratelimit.ExpiryTask` to accept it. Change `MemoryLimiter.Prune` to `Prune(ctx) (int, error)`, and move every caller, found with gopls references, to the new form (design decisions 8 and 12). Red: a test that a fake `Pruner`'s count and error reach the task's result, plus the existing test that the in-memory limiter's quota is unchanged by a run. Verify: `go test -count=1 ./ratelimit/... ./expiry/...` and `go test -count=1 ./...` in the `test` module, both green, and `go vet ./...` clean.
- [x] 1.2 Godoc on `Pruner` and `ExpiryTask` names both built-in pruners, states that the task name is `ratelimit` and that no cutoff is accepted, and shows the rename for a second pruner. Verify: `go doc ./ratelimit Pruner` and `go doc ./ratelimit ExpiryTask` show it.

## 2. The table and its statements

- [x] 2.1 Add `rate_limit_buckets` to the initial security-state migration, with its `DROP TABLE IF EXISTS` in the down section (design decision 2): a logged table, primary key `(namespace, key)`, no other index, and provisional `fillfactor = 70`. Red: extend `test/migrate_securitystate_test.go` so the table list holds fifteen tables, the bucket table's columns and indexes join the test's exact column and index maps (`securityStateColumns`, `securityStateIndexes`), the key-type exception is checked, and new cases assert a logged table (`relpersistence = 'p'`), the primary-key index as its only index, and `reloptions` that declare a fillfactor. Verify: `go test -count=1 -run 'SecurityState' ./...` in the `test` module, green on both `postgres:15` and `postgres:18` (`SCRTY_TEST_POSTGRES_IMAGE`), and the leftover-table check passes after rollback.
- [x] 2.2 Add the check, record, prune and verify statements, the maximums and the long-key digest rule to `internal/pgschema/ratelimit.go` (design decisions 3–7). Red: a unit test of the key mapping (512 bytes stored as given, 513 bytes and a `sha256:`-prefixed key stored as the digest). The statements themselves are proven through the public limiters, because the `test` module cannot import an internal package. Those proofs are:
  - the record keeps only the newest `limit` stamps in ascending order;
  - `newest_at` and `longest_window_us` take the larger value;
  - the check counts strictly after the cutoff;
  - the prune removes only rows past `newest_at + longest_window_us`.

  They are the conformance and prune runs of 4.2, 4.3 and 6.5. Verify: `go test -count=1 ./internal/pgschema/` green now. Tick this task only once 4.2 is green.

## 3. Test helpers

- [x] 3.1 Give `PostgresConn` `Stop` and `Start` for own servers, mirroring `RedisConn`, refusing both on a shared server. Red: a test that a query after `Stop` errors and one after `Start` succeeds, and a test that `Stop` on a shared server is refused. Verify: `go test -count=1 -run 'TestRunTestPostgres' ./...` in the `test` module.
- [x] 3.2 Add `RunTestPostgresStandby`, which starts a streaming standby of an own primary with `pg_basebackup -R`, from the same image (design decision 10). Red: a test that `pg_is_in_recovery()` is true on the standby, and that a row written on the primary appears there. Verify: that test green on both majors.

## 4. The limiter on `database/sql` (`sqlstore`)

- [x] 4.1 `sqlstore.NewLimiter`, `LimiterOption` and its options, with construction refusals (design decision 1, `rate-limiting` "refuses a policy too large for one row"). Red: a construction table test for each refusal:
  - a nil handle, typed nil included;
  - an empty namespace or one with a colon;
  - a limit of 0 or 129, or a namespace of 65 bytes;
  - a window under a microsecond;
  - a nil clock or logger, an unknown mode, a non-positive timeout or probe interval;

  plus the accepted cases at 128 and 64. Verify: `go test -count=1 -run 'TestNewLimiter' ./sqlstore/`.
- [x] 4.2 `Exceeded` and `RecordFailure` over the `pgschema` statements, wrapped by `internal/unavailable.Wrap`. The record sets `lock_timeout` in its source row, and long keys are stored as digests (design decisions 3–6). Red: the `ratelimittest` conformance run for `sqlstore` in app-clock mode, seen failing against the trimming-by-time variant. (The time-read-twice variant is invisible in app-clock mode; 6.3 proves it.) Verify: `go test -count=1 -run 'TestSQLStoreLimiter_Conformance' ./...` in the `test` module, green on both majors.
- [x] 4.3 `sqlstore.NewLimiterFactory`: same-namespace dedupe, conflicting-policy refusal, `Prune(ctx)` across namespaces, and `Verify` on both factory and limiter (design decisions 6 and 7). Red: table tests for dedupe and conflict, and `Verify` tests against a standby, a missing table, an unlogged table, a `SELECT`-only role and a supported server. Verify: `go test -count=1 -run 'TestSQLStoreLimiter' ./...` in the `test` module, green on both majors.
- [x] 4.4 Godoc for the limiter, the factory and each option: the defaults, the 128 and 64 maximums, primary-only, ignored ambient transactions, `Verify` at startup, and the factory as pruner. Add an example. The `gorm` package's godoc shows `sqlstore.NewLimiterFactory(db.DB())`. Verify: `go test -count=1 -run Example ./sqlstore/ ./gorm/` and `go doc ./sqlstore NewLimiterFactory`.

## 5. The limiter on pgx (`pgx` module)

- [x] 5.1 `pgx.NewLimiter`, `LimiterOption` and its construction refusals, mirroring 4.1 over `*pgxpool.Pool`. Red: the same construction table. Verify: `go test -count=1 -run 'TestNewLimiter' ./...` in `pgx`.
- [x] 5.2 `Exceeded` and `RecordFailure`, mirroring 4.2. Red: the conformance run for pgx in app-clock mode, with a `SecondInstance` from `sqlstore`, which proves the scenario "Backends share one table". Verify: `go test -count=1 -run 'TestPgxLimiter_Conformance' ./...` in the `test` module, green on both majors.
- [x] 5.3 `pgx.NewLimiterFactory`, `Prune` and `Verify`, mirroring 4.3. Red: the same table and `Verify` tests for pgx. Verify: `go test -count=1 -run 'TestPgxLimiter' ./...` in the `test` module, green on both majors.
- [x] 5.4 Godoc and example, mirroring 4.4. Verify: `go test -count=1 -run Example ./...` in `pgx`.

## 6. Fault, clock and transaction behaviour (both backends)

- [x] 6.1 Held row: a second connection holds `k` with `SELECT … FOR UPDATE`. A record with a 250ms timeout errors within about 250ms, and `pg_stat_activity` shows no session waiting on the row (`rate-limiting` "does not wait on a held row"). If this goes red for the wrong reason, or flakes, switch to the explicit-transaction fallback of design decision 6 and report it to the main session. Verify: `go test -count=1 -run 'HeldRow' ./...` in the `test` module, green on both majors and both backends.
- [x] 6.2 Outage: one test per unavailable mode, plus a breaker test that refusal does not wait for the timeout, by stopping an own server (3.1). Verify: `go test -count=1 -run 'Unavailable' ./...` in the `test` module.
- [x] 6.3 Database clock: a short-window real-time test, in which a failure stops counting one window after it was recorded with no `WithLimiterClock`; and several records on one key each leave `newest_at` equal to the newest stamp, seen failing against a record that reads `clock_timestamp()` separately for each (design decision 10). Both backends. Verify: `go test -count=1 -run 'DatabaseClock' ./...` in the `test` module.
- [x] 6.4 Ambient transactions ignored: a failure recorded while a caller's attached transaction (and, separately, a resolver's) rolls back still counts, while a session saved in that transaction does not. The test must be seen failing against a variant that joins the transaction. Document the exclusion in `storetest`'s package godoc for `RunAmbientTx`. Verify: `go test -count=1 -run 'IgnoresAmbientTx' ./...` in the `test` module, and `go doc` on `storetest` shows the exclusion.
- [x] 6.5 Prune: run the `rate-limiting` prune scenarios and the `expiry-sweeping` scenario "One task prunes the PostgreSQL limiter table" through `ratelimit.ExpiryTask(factory)`: the longest recorded window protects a key, an idle key is removed and counted, and a locked row is skipped without waiting. The test must be seen failing against a prune that uses the checking instance's window. Verify: `go test -count=1 -run 'Prune' ./...` in the `test` module, green on both majors and both backends.

## 7. Benchmark and the decisions it settles

- [x] 7.1 Write the benchmark in the `test` module (design decision 11), covering:
  - fillfactor 100, 90, 70 and 50;
  - default and lowered autovacuum scale factors;
  - the three loads;
  - an own pool and a shared pool against a simulated login load;
  - prune time at 10⁵ and 10⁶ rows.

  It reports the p50/p99 latencies, the HOT ratio from `pg_stat_user_tables` and the table size. Verify: `go test -run '^$' -bench 'PostgresLimiter' -benchtime=… ./...` completes on 18 and 15, and the raw output is saved for the main session.
- [x] 7.2 The main session reads the results, then:
  - sets the fillfactor and autovacuum values in the migration;
  - writes the numbers, the pool recommendation for API-key-heavy traffic and the recommended prune interval into design decision 11;
  - updates the godoc of both factories with the recommendation, the prune interval and per-flow write cost.

  Verify: the migration tests of 2.1 still pass, and `go doc` shows the recommendation.

## 8. Integration

- [x] 8.1 Whole-branch gate: `gofmt -l` empty; `go vet ./...` clean in every module; the race detector green on core, `pgx` and `test` (`go test -race -count=1 ./...`), on both `SCRTY_TEST_POSTGRES_IMAGE` majors; and the module dependency guard passes (the core module has no new dependency).
- [x] 8.2 Whole-branch review against every requirement in this change's deltas (`rate-limiting`, `schema-migrations`, `security-state-stores`, `store-conformance`, `expiry-sweeping`). Every finding is either fixed or recorded in `design.md`.
