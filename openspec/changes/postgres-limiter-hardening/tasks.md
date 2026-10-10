# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason (a
compile error is not a red step), then implement and re-run. Integration tests live in the `test`
module and run with `go test -count=1 -run '<Name>' ./...` from `test/`.

## 1. The limit maximum rises to 400 (decisions 1, 10)

- [ ] 1.1 Red: add a `test` module test that builds the default HTTP chain, with password login and the default IPv6 aggregate, over the `sqlstore` and the `pgx` limiter factory, and checks that the aggregate limiter counts to 200. Verify it fails on both with the configuration error naming 128.
- [ ] 1.2 Red: in `sqlstore/limiter_test.go` and `pgx/limiter_test.go`, move the boundary cases from 128/129 to 400/401 (constructor and factory tables), and add a `test` module case that records 400 failures for one key and sees it exceeded. Verify the 400 cases fail before 1.3.
- [ ] 1.3 Raise `pgschema.LimiterMaxLimit` to 400, and set `toast_tuple_target = 8160` on `rate_limit_buckets` in `migrate/securitystate/20260926000000_security_state.sql`, with a comment beside it saying what dropping it costs. Verify 1.1 and 1.2 pass, and that a `test` module assertion reads the parameter from `pg_class.reloptions` on a migrated database.
- [ ] 1.4 Update every godoc and comment that states the maximum (`sqlstore/limiter*.go`, `pgx/limiter*.go`, `internal/pgschema/ratelimit.go`) to 400, and say in the factory godoc that the table's storage parameter keeps rows in-line. Change the record statement's godoc to say it keeps the newest `limit` stamps, the new one included. Verify with `grep -rn '128' sqlstore/limiter* pgx/limiter* internal/pgschema/ratelimit.go` showing no stale maximum, and `go vet` clean.

## 2. Own test servers stay on tmpfs unless restartable (decision 9)

- [ ] 2.1 Red: add tests in `test/testutils_postgres_test.go` that an own server built without the new option runs on tmpfs, and that `Stop` on it fails the test with a message naming `WithTestPostgresRestartable`. Verify both fail before 2.2.
- [ ] 2.2 Add `WithTestPostgresRestartable()` to `test/testutils.go`. It keeps an own server's data on disk. Without it, an own server uses tmpfs again, and `Stop`/`Start` refuse it. Verify 2.1 passes.
- [ ] 2.3 Pass `WithTestPostgresRestartable()` in every test, the standby helper and the benchmark that stop or restart a server, and in nothing else. Verify `TestPGLimiter_Unavailable*` and every other Stop/Start user in `test/` pass.

## 3. One shared limiter core (decisions 6, 7)

- [ ] 3.1 Record a green baseline before the refactor: run the `sqlstore`, `pgx` and `test` module limiter suites (`-run 'Limiter|PGLimiter'`) and keep the output. Verify the outputs exist and are green.
- [ ] 3.2 Red: add a validation-only entry point test in `internal/unavailable` that checks the decorator's rules without building it, using the existing refusal cases. Verify it fails because the entry point is missing its behaviour (stubbed), not because of a compile error.
- [ ] 3.3 Implement the validation-only entry point in `internal/unavailable`. Verify 3.2 and the package's existing tests pass.
- [ ] 3.4 Create `internal/pglimiter` with its own unit tests, written first: configuration and validation, the server-facts check, the policy registry, the time and lock-timeout argument helpers, all behind a small statement-runner interface. Verify its tests were seen red, then pass.
- [ ] 3.5 Move `sqlstore` and `pgx` onto `internal/pglimiter`, keeping their public types, constructors, options, godoc and error prefixes. The factories validate their configuration once, with the constructor's function, instead of building and discarding a limiter. Verify the 3.1 suites pass unchanged, and `go doc` of both packages shows the same exported API as before.

## 4. `Verify` refuses what the limiter cannot serve (decisions 3, 5)

- [ ] 4.1 Red: add `test` module `Verify` cases for both backends, limiter and factory: LATIN1, SQL_ASCII and EUC_JP databases are refused with a configuration error naming the encoding, and a UTF-8 database passes. Verify the refusal cases fail today because the error names the missing table, not the encoding (the new databases carry no migration, and the encoding check runs before the table check).
- [ ] 4.2 Red: add a `test` module `Verify` case in which a temporary `rate_limit_buckets` shadows the migration's. The error must name a temporary table and must not advise `SET LOGGED`. Verify it fails today on the message.
- [ ] 4.3 Read `server_encoding` with the other server facts in `internal/pglimiter` and the server-facts query, refuse anything but `UTF8`, and report a temporary table's persistence for what it is. State the UTF-8 requirement in both factories' godoc. Verify 4.1, 4.2 and the existing `Verify` suites pass.

## 5. The prune bounds itself in batches (decisions 2, 4)

- [ ] 5.1 Red: add a `test` module test that runs the prune over 1,000,000 idle keys (the spec's floor is 100,000; a million makes today's statement hold its locks well past 250ms) while records with a 250ms operation timeout hit victim keys. Every record must complete within its timeout, and every recorded key must be kept. Verify it fails against today's single statement with a record timing out.
- [ ] 5.2 Red: add tests for the batch-size option on both factories. A size of 2 prunes 5 idle keys and reports 5, and a size of 0 is a configuration error. Verify they fail before 5.4.
- [ ] 5.3 Red: add tests for a failed or cancelled prune. In the `test` module, a test-database trigger raises an error with a distinctive message on the third row deleted. A prune with batch size 2 over 5 idle keys must return 2 with an error that does not contain the message, and those 2 keys stay removed. In `internal/pglimiter`, a fake runner cancels the context during the first batch, and the prune must return that batch's count with an error matching `context.Canceled`. Verify each fails today for the stated reason (the server text appears; the count is 0).
- [ ] 5.4 Replace the prune statement in `internal/pgschema/ratelimit.go` with the batched `FOR UPDATE SKIP LOCKED` form, and put the loop in `internal/pglimiter`. Fix the time once per run, stop on a short batch, check `ctx` between batches, return the committed count with any error, and wrap errors with `internal/diag.Wrap`. Add `WithLimiterPruneBatchSize` to `sqlstore` and `pgx`, defaulting to 1,000. Remove the godoc caveat that a large backlog can open the breaker. Verify 5.1–5.3 and the existing prune suites (`TestPGLimiter_Prune*`, `Test*Limiter_FactoryPrune`) pass.
- [ ] 5.5 Re-point the prune's broken-variant edits in `test/pg_ratelimit_prune_test.go` at the batched statement, and add a `prune-without-skip-locked` variant. The existing cases "row another session holds is skipped without waiting" and "prune against an uncommitted record on an idle key keeps the key" pin the two guarantees. Verify `TestPGLimiter_PruneCatchesBrokenVariants` passes, with every variant caught by its named case.

## 6. Factory godoc states the conflict check's reach (decision 8)

- [ ] 6.1 Rewrite the policy-conflict sentence in the `sqlstore`, `pgx` and `redis` factory godoc: the check covers one factory, and no two factories or processes may build one namespace with different policies. Make the documented example's two factories build visibly disjoint namespaces. Verify that `go vet` and the example tests pass, and that `go doc` shows the new text.

## 7. Integration

- [ ] 7.1 Run `go test -count=1 ./...` in every workspace module, `go vet ./...`, `gofmt -l .` and the project's lint target. Verify all are clean, and keep the output.
- [ ] 7.2 Run `BenchmarkPostgresLimiter` and `BenchmarkPostgresLimiterPrune` on PostgreSQL 15 and 18, and compare them with the figures in `design.md`. Verify there is no regression at the default limits, and record any drift in `design.md`.
- [ ] 7.3 Run a whole-branch review against every requirement in `specs/rate-limiting/spec.md` and decisions 1–10. Verify every finding is fixed or answered.

## Workflow follow-up

- Archive the change after review, and sync `specs/rate-limiting` into the main spec.
