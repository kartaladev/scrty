# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **Measured on 2026-10-23.** One local `go test -race -count=1 ./...` of the `test` module on 14 CPUs (Docker Desktop 29.8.0), with container starts counted by `docker events`. The Docker host was also running about a dozen containers from other projects, so wall times are noisier than `testcontainers-optimize`'s.

  | Package | Containers started (alone) | Alone (s) | In the full run (s) |
  |---|---|---|---|
  | `test` | 44 PostgreSQL, 34 Redis or Valkey, Keycloak, Mailpit, sshd, 2 Ryuk | 95 | 176 |
  | `test/sqlstore` | 1 PostgreSQL, Ryuk | 17 | 118 |
  | `test/pgxstore` | 1 PostgreSQL, Ryuk | 18 | 113 |
  | `test/gormstore` | 1 PostgreSQL, Ryuk | 19 | 119 |
  | `test/crossbackend` | 1 PostgreSQL, Ryuk | 10 | 20 |

  Full run: 87 containers, 179 s wall time, every package green. The store packages' growth from about 18 s to about 115 s comes with no change in their own containers. That they are slowed by the root package's load on the same Docker host and CPUs is an inference, not a measurement. D6 checks it.
- **Where the root package's servers of its own come from**, tallied from the code. The events do not name the test, so these are approximate.
  - PostgreSQL:
    - `TestPGLimiter_Unavailable`: 2 backends × 4 cases, each with `WithTestPostgresRestartable()`.
    - Its broken-variant child: 4 more. A restartable server is always the call's own, so a child cannot inherit it.
    - The "unreachable server" verify case: 2, one per backend (`TestSQLStoreLimiter_Verify`, `TestPgxLimiter_Verify`).
    - Standby pairs: about 6.
    - The helper's own image, own-server and restartable tests.
  - Redis:
    - `TestRedisVerify`: 13, one per case, for start-up flags or an ACL user.
    - `TestRedisLimiter_Fault`: 8, for stop, start and hang.
    - The helper's own tests: about 4.
    - One shared server for each of the 5 supported images.
- **How outages are staged today.**
  - `PostgresConn.Stop` and `Start`, and their Redis twins, stop and restart the container of a call's own.
  - A hung Redis server is staged with `DEBUG SLEEP`, which blocks the whole server. A shared server therefore cannot be hung.
- **What the outage tests observe.** Each test sees the outage only through its own client: errors, timings, breaker state and log records. None of them looks at the server itself while it is down.
- **The established design** started a container per test and had no outage proxy. Nothing here departs from a behaviour it guaranteed.

## Goals / Non-Goals

**Goals:**
- Remove the root package's servers of a test's own that exist only to stage an outage or carry a fixed configuration.
- Keep every test and every assertion. Where a case moves to the proxy, the outcome it asserts is unchanged.
- Keep at least one real server outage per backend.

**Non-Goals:**
- Changing the standby helper. Its tests need a real replica, and a shared standby pair would need its own analysis of what those tests write. It can be a later change.
- Changing the helpers' own tests that are about starting a server of one's own: image, own-server, restartable and tmpfs tests. Their container is what they test.
- Simulating network conditions beyond stop, hang and start: no latency, bandwidth or packet loss.

## Decisions

### D1. An in-process proxy, not Toxiproxy and not a pool of servers

- **What.** A TCP proxy in the test process, written with the standard library. It listens on a loopback port and forwards each connection to the shared server's mapped address.
- **Alternatives rejected:**
  - **Toxiproxy** (testcontainers module `modules/toxiproxy`, v0.44.0). Its `down` and `timeout` toxics are exactly the stop and hang modes. But it costs one container per process plus an HTTP control API. The extra toxics (latency, bandwidth, packet loss) are not needed (see Non-Goals). The goal is fewer containers, and this would add one per process.
  - **A pool of servers of one's own, recycled between tests.** The pool's containers are still started, and recycling a stopped server means a restart and a reset between tests. It saves fewer containers than a proxy, and adds state that can leak between tests.
- **Default and override.** The default stays a direct connection, with no proxy. A test asks for the proxy through an option on the PostgreSQL and Redis helpers (D3). A test that needs a real outage keeps `WithTestPostgresRestartable()` or `WithTestRedisOwnContainer()`.

### D2. What stop, hang and start do

The modes are chosen to match what a client sees from a real server in each state:

- **Stop:**
  - closes every connection open through the proxy;
  - closes the listener, so a new connection is refused, as with a stopped container's port.
- **Start:**
  - listens again on the same address, so the test's DSN and clients still reach it;
  - if that port has been taken meanwhile, the test fails and names the port. It never moves to another port silently.
- **Hang:**
  - keeps every connection open and keeps accepting new ones;
  - forwards nothing in either direction until start.
  - This matches a server blocked by `DEBUG SLEEP`, whose kernel still accepts connections while nothing answers.
  - Bytes received while hung are delivered once forwarding resumes, as a blocked server would answer them.
- **Who it affects.** The shared server is never touched. Only clients that connect through this call's proxy see the outage.
- **Teardown.** The proxy is started again before the call's own teardown runs. So the migration rollback, finalize scripts, leftover check and database drop run as for any other call, whatever state the test left the proxy in. The proxy is closed last.
  - This is the counterpart of `f16e71c`, where an own server left stopped still cleans up.

### D3. How a test asks for the proxy

- **PostgreSQL.** A new option, named in the specs, gives the call a proxied connection on the shared server.
  - `PostgresConn.DSN` and `DB` go through the proxy.
  - The database is still the call's own, cloned from the template as usual.
  - `Stop` and `Start` act on the proxy, and a new `Hang` is added.
  - `Stop` and `Start` keep their meaning: "the server is unreachable to this call" and "it is reachable again". They act on the real container only for an own server.
- **Redis.** The same option on `RunTestRedis`: the call gets its own logical database on the shared server, through a proxy. `Stop`, `Start` and `Hang` act on the proxy.
- **Refused combinations.** Each fails the test at the call, before anything starts (`library-design.md` rule 6):
  - `Hang` on a connection with no proxy;
  - the proxy option together with a server of one's own.
- **Child processes.** A broken-variant child builds its own proxy in front of the server it inherits. It starts no container.

### D4. One real outage per backend stays

- **Which cases.** For each of the PostgreSQL limiter's two backends, and for the Redis limiter, one stop-then-start case keeps a real server of its own.
  - The chosen case is the one where the breaker refuses without calling the server, and a probe reaches it once it is restarted, on each backend.
  - It asserts the same outcome as the proxied cases.
- **Why.** A real PostgreSQL shutdown sends its clients `57P01 admin_shutdown` before it closes their connections. A proxy cut sends nothing. The drivers may classify those differently, and only a real outage would show it. This is the risk of a test that passes and is still wrong.
- **The first task measures the difference.** Before any case moves, a spike runs each backend's outage cases both ways and records each driver's error and the limiter's observable outcome.
  - A case whose outcome differs between proxy and real stays on a real server, and the difference is recorded here.
  - The result can only keep more cases on real servers. It cannot remove the anchors.

### D5. Servers of one's own for Redis are shared by configuration

- **Today.** `WithTestRedisServerArgs` is refused unless `WithTestRedisOwnContainer` is also given, so every flagged case gets a server of its own.
- **Default.** A call with start-up flags and no request for a server of its own gets a server shared by the calls in the process with the same image and the same flags, in the same order.
  - Each call still gets a logical database of its own on that server, as on the default shared server.
  - `Stop`, `Start` and `Hang` are refused on it, as on any shared server. The helper cannot stop a test from sending `CONFIG SET` through its own client, so the godoc says such a test needs a server of its own.
- **Override.** `WithTestRedisOwnContainer()` still gives a server of one's own, for a test that stops, reconfigures or inspects the server itself.
- **ACL cases** run on the default shared server, under an ACL user created for the call with a generated name and deleted at its cleanup. ACL users are server-wide but distinctly named, so two calls never share one.
- **Effect on the verify table.** About 13 servers of their own become one per distinct flag set: three eviction policies, a renamed `CONFIG` and a renamed `SCRIPT`. That is 5, with ACL cases on the shared server.
- **Alternative rejected: setting flags at run time with `CONFIG SET` on the shared server.** Flags such as `--rename-command` can only be given at start-up, and a run-time change would reach every other call on the server.

### D6. Quality and speed are measured, not assumed

- **Before:** the 2026-10-23 figures in Context. Task 1 repeats them on an otherwise idle Docker host, and adds the passing test count from `go test -json` and the root package's own-server count by test.
- **After:** the same commands on the same host.
- **Acceptance:**
  - the passing test count does not drop, and every test passes under `-race`;
  - the root package starts at least 20 fewer containers;
  - each store package's wall time in the full run is recorded against its time alone. If the gap does not close, the cause is measured and recorded rather than assumed. No wall-time target is set, because the gap's cause is not yet shown.
- **CI.** One CI run per job confirms the counts and records the wall times.

### D7. The project's testcontainers convention changes with it

The `use-testcontainers` skill gains:

- reach for the proxy, not a server of one's own, when a test only needs its connection to fail, hang or recover;
- keep a server of one's own only when the test changes or inspects the server itself;
- the one-real-outage-per-backend rule from D4.

## Risks / Trade-offs

- **[A proxy outage is not a real one.]** → D4 keeps a real outage per backend, and its spike keeps any case whose outcome differs on a real server.
- **[Start cannot get its port back.]** → The test fails and names the port (D2). Ports are picked by the kernel from the ephemeral range, so a clash within one test is unlikely. The helper's own tests run stop and start in a loop, in parallel, to show it holds.
- **[A bug in the proxy hides a bug in the limiter.]** → The proxy is test code under the helper's own tests: each mode, the restore before teardown, and refused combinations, each written red first.
- **[Hang behaves differently from `DEBUG SLEEP`.]** → Both keep connections open and answer nothing. The hung-server cases assert only timing and errors seen by the client, which the spike in D4 compares both ways.
- **[A configured Redis server shared by several calls.]** → Each call still has its own logical database. Stop, start and hang are refused on it, and the godoc names a run-time `CONFIG SET` as needing a server of one's own (D5). `redisDatabases` bounds how many calls one such server holds at once, as on the default shared server.
- **[Overlap with `stabilize-intermittent-tests`.]** → This change starts only after that one has classified the `TestRedisLimiter_Fault` failure. Its finding then decides whether the hung-server control case moves to the proxy or stays real.

## Migration Plan

- Test code only. Each step lands with its tests green under `-race`.
- No consumer migration: the helpers' existing options keep their meaning, and the new option is additive.
- **Behaviour change:** `WithTestRedisServerArgs` without `WithTestRedisOwnContainer` used to be refused, and now gives a server shared by configuration. A test that relied on the refusal is updated.
- **Rollback:** revert the change. Nothing outside the test module depends on it.

## References

### Researched (accessed 2026-10-23)

- **D1, D2. The outage proxy and its modes.**
  - [Toxiproxy](https://github.com/Shopify/toxiproxy): the `down` toxic (a disabled proxy) and the `timeout` toxic (with 0, it keeps the connection open and drops data). These are the established forms of the stop and hang modes, and the rejected alternative in D1.
  - `go list -m -versions github.com/testcontainers/testcontainers-go/modules/toxiproxy`: v0.43.0 and v0.44.0 exist.
- **D4. Why one real outage per backend stays.**
  - [PostgreSQL error codes, Appendix A](https://www.postgresql.org/docs/current/errcodes-appendix.html): `57P01 admin_shutdown` and `57P03 cannot_connect_now` in class 57, Operator Intervention, which a proxy cut does not send.
- **Non-goals. Sharing across processes.**
  - testcontainers-go v0.44.0, `docs/features/common_functional_options.md`: `WithReuseByName` is experimental.
  - testcontainers-go v0.44.0, `docs/features/test_session_semantics.md`: each package's tests run in their own process.
- **D5, D6. Measurements and the shape of the tests.** Reasoned from scrty's own settled specs (`test-provisioning`), the archived `testcontainers-optimize` design and the established design. Measured locally on 2026-10-23 with `docker events`. The figures depend on the host and drift.

### Primary documentation

- [testcontainers-go](https://golang.testcontainers.org/): the container lifecycle and the reaper (Ryuk), which the helpers already rely on.
