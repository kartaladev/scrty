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

  ```
  Today: a server of its own per outage case

    case A ----------> +------------------+   Stop = docker stop
                       | own container A  |
                       +------------------+
    case B ----------> +------------------+   one start and one readiness
                       | own container B  |   wait per case
                       +------------------+

  With the proxy: one shared server, a proxy per call

                       test process                      Docker
                  +----------------------------+
    case A ------>| proxy A  127.0.0.1:<a>  -X-|----+
                  |   (stopped: only A sees it)|    |    +-------------------+
    case B ------>| proxy B  127.0.0.1:<b>  ---|----+--->| shared server     |
                  |                            |    |    | (never stopped)   |
    other tests --|----------------------------|----+    | t_<a> t_<b> t_<c> |
                  +----------------------------+         +-------------------+
                                                          one database per call
  ```
- **Alternatives rejected:**
  - **Toxiproxy** (testcontainers module `modules/toxiproxy`, v0.44.0). Its `down` and `timeout` toxics are exactly the stop and hang modes. But it costs one container per process plus an HTTP control API. The extra toxics (latency, bandwidth, packet loss) are not needed (see Non-Goals). The goal is fewer containers, and this would add one per process.
  - **A pool of servers of one's own, recycled between tests.** The pool's containers are still started, and recycling a stopped server means a restart and a reset between tests. It saves fewer containers than a proxy, and adds state that can leak between tests.
  - **Toxiproxy embedded as a Go library** (`github.com/Shopify/toxiproxy/v2` v2.13.0), which runs in the test process with no container or HTTP listener:
    - its `timeout` toxic drops the bytes it holds, so a request sent while hung is never answered, where D2 requires it to be;
    - removing the toxic closes the connection;
    - toxics are added only as JSON;
    - it brings 15 indirect modules, among them the Prometheus client, zerolog and gorilla/mux.
  - **Other Go TCP proxies.** `inetaf/tcpproxy` routes connections but cannot close or hold them. `jpillora/go-tcp-proxy` has no fault modes. No other maintained in-process fault proxy was found.
  - **Outages staged on the shared server alone, with no proxy.** Each mechanism stages stop only, and gives new connections a server error where a stopped server gives a refused dial:
    - PostgreSQL: ending the call's sessions, plus `ALTER DATABASE … ALLOW_CONNECTIONS false` for new ones. New connections then get `55000` ("is not currently accepting connections").
    - Redis: `ACL SETUSER … off` plus `CLIENT KILL USER` for the call's ACL user. Reconnects then get `WRONGPASS`.
    - Neither server can hang one call's connections (D2).
    - The first half of the PostgreSQL mechanism is kept, as the stop step in D2.
  - **Faults in the client's dialer** (`pgconn.DialFunc`, `redis.Options.Dialer`). It needs no port, but reaches only clients built from the helper's configuration, not a handle a test opens on `DSN`. A full stop or hang also means wrapping every connection, which is the proxy again, inside the driver.
  - **`docker pause`** of a server matches hang, but needs a server of one's own. testcontainers-go v0.44.0's `Container` has no pause either.
- **Default and override.** The default stays a direct connection, with no proxy. A test asks for the proxy through an option on the PostgreSQL and Redis helpers (D3). A test that needs a real outage keeps `WithTestPostgresRestartable()` or `WithTestRedisOwnContainer()`.

### D2. What stop, hang and start do

The modes are chosen to match what a client sees from a real server in each state:

```
                 Stop                         Hang
  +-----------+ -----> +---------+    +------------+ <----- +-----------+
  | forwarding|        | stopped |    |    hung    |        | forwarding|
  +-----------+ <----- +---------+    +------------+ -----> +-----------+
                 Start                         Start
                              Stop while hung -> stopped

  forwarding: listener open, bytes flow both ways
  stopped:    listener closed (dial refused), every pair closed
  hung:       listener open, pairs open, nothing forwarded; held bytes are
              delivered on Start
  Every mode change is harmless to repeat. Close ends the proxy from any mode.
```

- **Stop:**
  - closes the listener first, so a new connection is refused, as with a stopped container's port;
  - then runs the backend's stop step, if it has one;
  - then closes every connection still open through the proxy. Bytes the server sends before it closes a connection are forwarded first. Connections still open one second after the step are closed by the proxy.
  - **PostgreSQL's stop step** ends the call's sessions at the server. Through the server's admin pool, it runs `pg_terminate_backend` on every backend of the call's own database. Each open client then reads the server's own `FATAL` with SQLSTATE `57P01 admin_shutdown`, the error a fast shutdown sends, because both deliver SIGTERM to the backend. The filter is the call's clone, whose name no other call shares, and it excludes the admin pool's own session.
  - **Redis has no stop step.** A connection the server kills reads EOF, which is what the proxy's close gives, so a step would add nothing.

    ```
    Stop on a proxied PostgreSQL call

     client (pool)        proxy                 shared server       admin pool
         |                  |                         |                  |
         |                  | 1. close listener       |                  |
         |  new dial -----> X  refused                |                  |
         |                  |                         |                  |
         |                  | 2. stop step ----------------------------->|
         |                  |                         |<-- pg_terminate_backend(pid)
         |                  |                         |    WHERE datname = t_<call>
         |                  |<-- FATAL 57P01 ---------|                  |
         |<-- FATAL 57P01 --|   (forwarded first)     |                  |
         |                  |<-- close ---------------|                  |
         |<-- close --------|                         |                  |
         |                  | 3. after 1 s, close any pair still open    |
    ```
  - **Default and override.** The stop step is part of `Stop` on a proxied PostgreSQL call, with no option to turn it off. A cut without it shows a client less than a real stop does. A test that needs the real shutdown phase uses `WithTestPostgresRestartable()` (D4).
- **Start:**
  - listens again on the same address, so the test's DSN and clients still reach it;
  - if that port has been taken meanwhile, the test fails and names the port. It never moves to another port silently.
- **Hang:**
  - keeps every connection open and keeps accepting new ones;
  - forwards nothing in either direction until start.
  - This matches a server blocked by `DEBUG SLEEP`, whose kernel still accepts connections while nothing answers.
  - Bytes received while hung are delivered once forwarding resumes, as a blocked server would answer them. A paused container does the same: after `docker unpause`, a reply held during the pause is delivered.
  - **Hang stays in the proxy**, because no server can hang one call's connections alone:
    - Redis `CLIENT PAUSE` and `DEBUG SLEEP` are server-wide;
    - a held PostgreSQL table lock hangs only queries on that table, while `SELECT 1` still answers;
    - a PostgreSQL `login` event trigger hangs only new connections, needs PostgreSQL 17 or later, and leaves the slept backend running.
- **Who it affects.** The shared server is never stopped, hung or reconfigured. Only clients that connect through this call's proxy see the outage. PostgreSQL's stop step ends this call's sessions and no others.
- **Teardown.** The proxy is started again before the call's own teardown runs. So the migration rollback, finalize scripts, leftover check and database drop run as for any other call, whatever state the test left the proxy in. The proxy is closed last. `t.Cleanup` runs last-registered first, so the order of registration sets this:

  ```
  registered          runs
  1. proxy.Close      3rd  closed for good
  2. teardown         2nd  rollback, finalize, leftover check, DROP DATABASE
  3. proxy.Start      1st  undoes whatever the test left
  ```
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
- **Why.** A real PostgreSQL shutdown shows a client two things.
  - Its open connections get `57P01 admin_shutdown`. D2's stop step reproduces this on the shared server.
  - While the server shuts down and restarts, new connections get `57P03 cannot_connect_now` and then a refused dial, and the restarted server has lost every session. Neither the proxy nor its stop step reproduces this phase, and only a real outage shows it.
  - A difference there that the drivers act on is the risk of a test that passes and is still wrong.

  ```
                     open connections      new connections          after start
  real fast stop     FATAL 57P01           57P03, then refused      new server process,
  (own server)                                                      every session lost
  proxy + stop step  FATAL 57P01           refused                  same server,
  (shared server)    (from the server)     (closed listener)        other sessions intact
  proxy, no step     closed, no error      refused                  same server
  (rejected)         (pgx: SafeToRetry)
  ```
- **The drivers do tell such errors apart.** In a spike on 2026-11-01 on pgx v5.11.0:
  - a server-sent `57P01` arrived as `*pgconn.PgError`, with `SafeToRetry` false;
  - a bare close of an idle connection gave "conn closed", with `SafeToRetry` true (one stub-server case);
  - pgx has no special case for `57P01`.

  This is why D2 has a stop step, and why the spike below still compares both ways.
- **Alternative rejected: the proxy writes a crafted `57P01`.** pgx reads a `pgproto3.ErrorResponse` with `Code` `57P01` as the real one. But the proxy would have to parse the backend stream to insert it on a message boundary, and D2's stop step gets the server's own error with no parsing.
- **The first task measures the difference.** Before any case moves, a spike runs each backend's outage cases both ways, through the proxy with PostgreSQL's stop step and against a real server of their own. It records each driver's error and the limiter's observable outcome.
  - A case whose outcome differs between proxy and real stays on a real server, and the difference is recorded here.
  - The result can only keep more cases on real servers. It cannot remove the anchors.

### D5. Servers of one's own for Redis are shared by configuration

- **Today.** `WithTestRedisServerArgs` is refused unless `WithTestRedisOwnContainer` is also given, so every flagged case gets a server of its own.
- **Default.** A call with start-up flags and no request for a server of its own gets a server shared by the calls in the process with the same image and the same flags, in the same order.
  - Each call still gets a logical database of its own on that server, as on the default shared server.

    ```
    registry key (image, flags in order)              server       databases
    (redis:8, "")                                  -> default      0..255, one per call
    (redis:8, "--maxmemory-policy allkeys-lru")    -> server 2     0..255
    (redis:8, "--maxmemory-policy noeviction")     -> server 3     0..255
    (redis:8, "--rename-command CONFIG \"\"")      -> server 4     0..255
    WithTestRedisOwnContainer(), any flags         -> own server   not in the registry
    ```
  - `Stop`, `Start` and `Hang` are refused on it, as on any shared server. The helper cannot stop a test from sending `CONFIG SET` through its own client, so the godoc says such a test needs a server of its own.
- **Override.** `WithTestRedisOwnContainer()` still gives a server of one's own, for a test that stops, reconfigures or inspects the server itself.
- **ACL cases** run on the default shared server, under an ACL user created for the call with a generated name and deleted at its cleanup. ACL users are server-wide but distinctly named, so two calls never share one.
- **Effect on the verify table.** About 13 servers of their own become one per distinct flag set: three eviction policies, a renamed `CONFIG` and a renamed `SCRIPT`. That is 5, with ACL cases on the shared server.
- **Alternative rejected: setting flags at run time with `CONFIG SET` on the shared server.** Flags such as `--rename-command` can only be given at start-up, and a run-time change would reach every other call on the server.
- **Alternative rejected: ACL users in place of `--rename-command`.** It would save the two renamed-command servers, but it tests another error:
  - a renamed command answers `ERR unknown command 'config', …`;
  - a command the ACL refuses answers `NOPERM … 'config|get' command`, on Redis and Valkey alike;
  - `Verify` reads the two by different paths, and its `noPermCommand` pattern does not match `config|get`, so the case would no longer test what it names.
  - Eviction policies are server-wide and cannot be set per call at all.

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

- **[A proxy outage is not a real one.]** → On PostgreSQL, D2's stop step gives open connections the server's own `57P01`. D4 keeps a real outage per backend for the shutdown phase, and its spike keeps any case whose outcome differs on a real server.
- **[The stop step reaches another call's sessions.]** → It filters by the call's own clone, whose name no other call shares, and excludes the admin pool's own session. The helper's own test runs a direct call beside a stopped one, and asserts that the direct call's query succeeds.
- **[The proxy closes a connection before the server's `FATAL` reaches the client.]** → Stop closes connections only after the stop step and its bound, and forwards what the server sent first. The proxy's own test pins this with an upstream that writes before it closes.
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

### Researched (accessed 2026-11-01)

Spikes ran on `postgres:18.6-alpine`, `redis:8.10.2` and `valkey:8.1.10`, with pgx v5.11.0 and raw sockets, in disposable containers.

- **D1. Embedded Toxiproxy and other proxies.**
  - `go doc github.com/Shopify/toxiproxy/v2` (v2.13.0): `NewServer`, `NewProxy`, `Proxy.Start` and `Stop`, `NewToxicCollection`, and `ToxicCollection.AddToxicJson`. A spike ran it in-process; `go get` added 15 indirect modules.
  - [Toxiproxy `toxics/timeout.go`](https://raw.githubusercontent.com/Shopify/toxiproxy/main/toxics/timeout.go): "Drop the data on the ground". In the spike, the request held while hung got no reply, and the client saw EOF once the toxic was removed.
  - `gh api repos/Shopify/toxiproxy`: release v2.13.0 of 2026-10-14, 12,478 stars, MIT. [OSV query](https://api.osv.dev/v1/query) for `github.com/Shopify/toxiproxy/v2`: no advisories. The figures drift.
  - `gh api repos/inetaf/tcpproxy` and `go doc`: a router whose `Close` closes only its own listeners. `gh api repos/jpillora/go-tcp-proxy`: no fault modes, last push 2024-01-08.
  - `go doc github.com/testcontainers/testcontainers-go Container` (v0.44.0): no pause and no network fault injection.
- **D2, D4. PostgreSQL's stop step, and what only a real outage shows.**
  - [PostgreSQL `postgres.c`, REL_18_STABLE](https://raw.githubusercontent.com/postgres/postgres/REL_18_STABLE/src/backend/tcop/postgres.c), `ProcessInterrupts`: a backend that gets SIGTERM reports "terminating connection due to administrator command" with `ERRCODE_ADMIN_SHUTDOWN`.
  - [PostgreSQL 18: shutting down the server](https://www.postgresql.org/docs/18/server-shutdown.html) and [system administration functions](https://www.postgresql.org/docs/18/functions-admin.html): a fast shutdown and `pg_terminate_backend` both send SIGTERM. In the spike both gave idle and in-flight connections the same `57P01`. After a real shutdown, new connections got `57P03`, then a refused dial.
  - [PostgreSQL `postinit.c`, REL_18_STABLE](https://raw.githubusercontent.com/postgres/postgres/REL_18_STABLE/src/backend/utils/init/postinit.c): "is not currently accepting connections" (`55000`) for a database with `ALLOW_CONNECTIONS false`, the rejected alternative in D1.
  - [PostgreSQL 18: event trigger definition](https://www.postgresql.org/docs/18/event-trigger-definition.html): the `login` event, absent from PostgreSQL 16's docs, for the hang alternative in D2.
  - pgx v5.11.0 source and the spike: no special case for `57P01`, and the `SafeToRetry` difference recorded in D4.
  - `go doc github.com/jackc/pgx/v5/pgproto3`: `ErrorResponse` and `Encode`, for the crafted-error alternative in D4.
- **D1, D2. What Redis can stage per call.**
  - [Redis `acl.c`](https://raw.githubusercontent.com/redis/redis/unstable/src/acl.c): `ACL SETUSER … off` only changes the user's flags, which are checked at authentication, so open connections stay up. The spike confirmed this, and that `CLIENT KILL USER` closes them.
  - [Redis `networking.c`](https://raw.githubusercontent.com/redis/redis/unstable/src/networking.c): `CLIENT PAUSE` pauses the whole server. In the spike, a pause delayed another user's `PING` on Redis and Valkey alike.
  - Spike: `docker pause` of a Redis container held a `PING`, and its reply was delivered after `docker unpause`.
- **D5. ACL users in place of `--rename-command`.** Spike on Redis and Valkey: `ERR unknown command 'config', …` for a renamed command, and `NOPERM … 'config|get' command` for one an ACL refuses. Read against `ratelimit/redisstore/verify.go`'s `noPermCommand` pattern.

### Primary documentation

- [testcontainers-go](https://golang.testcontainers.org/): the container lifecycle and the reaper (Ryuk), which the helpers already rely on.
