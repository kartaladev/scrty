# Tasks

Every code task is test-first: write the failing test, run it and see it fail for the intended reason (a compile error is not a red step), make it pass, then refactor. Where a task rewrites an existing test rather than adding behaviour, the red step is to break what the test guards, temporarily (for instance, make the proxy's stop a no-op), and watch the rewritten test fail. Each task names how it is verified. Every existing test in the `test` module passes under `-race` at the end of every group. Requirement names in quotes are those of `specs/test-provisioning/spec.md`.

This change starts after `stabilize-intermittent-tests` has classified the intermittent `TestRedisLimiter_Fault` failure (proposal, "Order").

## 1. Baseline and precondition

- [ ] 1.1 Confirm the precondition. `stabilize-intermittent-tests` has recorded its classification of the `TestRedisLimiter_Fault` failure, and its fix has landed. Record in design.md, under Risks, what its finding means for the hung-server control case. Verify by the finding being cited there.
- [ ] 1.2 Record the baseline (D6), on a Docker host with no other containers running:
  - container starts per package of the `test` module, by image, from `docker events` during one `go test -race -count=1 ./...`;
  - the same per package run alone;
  - wall time per package, in the full run and alone;
  - passed and skipped tests and subtests from `go test -json`;
  - the root package's own-server starts attributed to the test that made them.

  Verify by the figures appearing in design.md D6 under "Before".

## 2. The outage proxy

- [ ] 2.1 Stop and start (D2), tested against a loopback TCP server in the test process, with no container:
  - stop closes every open connection through the proxy and refuses new ones;
  - start listens again on the same address, and data then flows;
  - a second stop or start is harmless.

  Verify with `go test -race -count=1 -run 'TestOutageProxy' .` in `test`.
- [ ] 2.2 Hang (D2), tested the same way:
  - connections stay open and new ones are accepted;
  - nothing is forwarded in either direction;
  - a read with a deadline fails at the deadline, not with a closed connection;
  - bytes sent while hung are delivered after start;
  - stop while hung closes everything.

  Verify with `go test -race -count=1 -run 'TestOutageProxy' .` in `test`.
- [ ] 2.3 Start when the port has been taken meanwhile fails the test and names the port (D2). Also run stop and start in a loop across parallel proxies, to show the address comes back. Verify with `go test -race -count=1 -run 'TestOutageProxy' .` in `test`.

## 3. Outage-capable PostgreSQL calls

- [ ] 3.1 The option on `RunTestPostgres` (D3):
  - `DSN` and `DB` go through a proxy in front of the shared server;
  - the call's database is cloned from the template as usual;
  - `Stop`, `Start` and the new `Hang` act on the proxy.

  Covers "A call can stage an outage without a server of its own" ("Many outage-capable calls, one server"), "Stopping an outage-capable connection cuts off only that call" (both scenarios) and "Hanging an outage-capable connection stops answers without closing connections" (both scenarios). Verify with `go test -race -count=1 -run 'TestRunTestPostgres' .` in `test`, and by a container count of one for the many-calls test.
- [ ] 3.2 Teardown after an outage (D2). The proxy is started again before the call's teardown, and closed last. Covers "An outage-capable call cleans up whatever state its test left it in" ("Test ends with the connection stopped"), for a test left stopped and one left hung. Verify with `go test -race -count=1 -run 'TestRunTestPostgres' .` in `test`.
- [ ] 3.3 Refused combinations (D3), each failing before anything starts:
  - the option together with `WithTestPostgresOwnServer()` or `WithTestPostgresRestartable()`;
  - `Hang` on a direct connection;
  - `Stop`, `Start` or `Hang` on the shared server.

  Covers "Contradictory outage requests fail at the call" (both scenarios). Verify with `go test -race -count=1 -run 'TestRunTestPostgres' .` in `test`.
- [ ] 3.4 Child processes (D3). A child that inherits its parent's server builds its own proxy and starts no container. Covers "A call can stage an outage without a server of its own" ("A broken-variant child stages an outage"). Confirm that "A real outage is still available" is covered by the existing restartable test, and add the scenario if it is not. Verify with `go test -race -count=1 -run 'TestRunTestPostgres|TestEnsureTestPostgresServer' .` in `test`, and a container count of one for the child test.
- [ ] 3.5 Godoc on `RunTestPostgres`, the new option, `PostgresConn.Stop`, `Start` and `Hang`: the default (a direct connection), what each mode does, the teardown guarantee, and the refused combinations. Verify with `go doc` on each symbol in `test`, and `go vet ./...`.

## 4. Outage-capable and configuration-shared Redis calls

- [ ] 4.1 Pin "Every Redis call gets a database of its own" (both scenarios), which today's helper already does. Find or add a test per scenario. The red step is to break the behaviour temporarily: hand out a held database, and skip the flush. Verify with `go test -race -count=1 -run 'TestRunTestRedis' .` in `test`.
- [ ] 4.2 The outage option on `RunTestRedis` (D3):
  - the call gets its own logical database on the shared server, through a proxy;
  - `Stop`, `Start` and `Hang` act on the proxy;
  - the proxy is started again before the flush at cleanup;
  - the refused combinations match 3.3.

  Covers the outage requirements' scenarios for Redis. Verify with `go test -race -count=1 -run 'TestRunTestRedis' .` in `test`.
- [ ] 4.3 Servers shared by image and start-up flags (D5):
  - `WithTestRedisServerArgs` without `WithTestRedisOwnContainer` gives a server shared by calls with the same image and the same flags, in the same order, each with a database of its own;
  - `Stop`, `Start` and `Hang` are refused on it;
  - the test that pinned the old refusal is updated.

  Covers "Redis calls in one process share a server per image and start-up flags" (all three scenarios). Verify with `go test -race -count=1 -run 'TestRunTestRedis' .` in `test`, and a container count of one for "Same flags, one server".
- [ ] 4.4 Godoc on `RunTestRedis`, the outage option, `WithTestRedisServerArgs` and `WithTestRedisOwnContainer`:
  - the defaults;
  - sharing by flags;
  - that a test sending `CONFIG SET` needs a server of its own (D5).

  Verify with `go doc` on each symbol in `test`, and `go vet ./...`.

## 5. Move the outage and configuration tests

- [ ] 5.1 The driver spike (D4). Run each outage case of `TestPGLimiter_Unavailable` (both backends), the verify "unreachable server" case and `TestRedisLimiter_Fault`, both through the proxy and against a real server of their own. Record each driver's error and the limiter's observable outcome. A case whose outcome differs stays real. Verify by the table in design.md D4 and the list of cases that stay real.
- [ ] 5.2 `TestPGLimiter_Unavailable` and its broken-variant child move to the proxy, except one real stop-then-start case per backend (D4). The red step: with the proxy's stop made a no-op, each moved case fails. Verify by:
  - `go test -race -count=1 -run 'TestPGLimiter_Unavailable' .` in `test`;
  - the broken-variant guard still catching `no-breaker`;
  - a `docker events` count of PostgreSQL starts for that run.
- [ ] 5.3 The limiter verify case "unreachable server" moves to the proxy, unless 5.1 keeps it real. It runs once per backend. The red step is the same. Verify with `go test -race -count=1 -run 'TestSQLStoreLimiter_Verify|TestPgxLimiter_Verify' .` in `test`.
- [ ] 5.4 `TestRedisLimiter_Fault` moves to the proxy, except one real stop-then-start case:
  - stopped cases use stop;
  - hung cases use hang in place of `DEBUG SLEEP`, unless 5.1 or the finding recorded in 1.1 keeps one real.

  The red step: with stop or hang made a no-op, each moved case fails. Verify by `go test -race -count=1 -run 'TestRedisLimiter_Fault' .` in `test`, run 20 times with `-count=20` and green each time, and a `docker events` count.
- [ ] 5.5 `TestRedisVerify` (D5):
  - flagged cases use servers shared by flags;
  - ACL cases run on the shared server, under an ACL user named for the call and deleted at its cleanup;
  - cases that change or inspect the server itself keep `WithTestRedisOwnContainer()`.

  The red step: with the ACL user's command permissions widened, the ACL cases fail. Verify with `go test -race -count=1 -run 'TestRedisVerify' .` in `test`, and a `docker events` count of five or fewer own Redis servers for the table.
- [ ] 5.6 Update the `use-testcontainers` skill (D7):
  - reach for the proxy when a test only needs its connection to fail, hang or recover;
  - keep a server of one's own only to change or inspect the server;
  - one real outage per backend.

  Verify by reading the skill's revised practice against D7.

## 6. Measure and confirm

- [ ] 6.1 Repeat 1.2's measurement on the same host (D6), and record the "After" figures in design.md D6. Verify against the acceptance list in D6:
  - the passed test count has not dropped;
  - every test passes under `-race`;
  - the root package starts at least 20 fewer containers;
  - the gap between each store package's time in the full run and alone is recorded, with its cause measured if it has not closed.
- [ ] 6.2 Run `make check` locally three times in a row, all green, and one CI run of each job. Record the CI container counts and wall times in design.md D6. Verify by the CI run's URL and figures being recorded there.

## Workflow follow-up

- Run the whole-branch review against every requirement in `specs/test-provisioning/spec.md` before the final gate.
- Archive the change once the review is clean, and verify the synced `openspec/specs/test-provisioning/spec.md`.
