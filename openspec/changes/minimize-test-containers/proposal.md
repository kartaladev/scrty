# Proposal

## Why

A full `go test -race -count=1 ./...` of the `test` module on 2026-10-23 started **87 containers** and took 179 s. `testcontainers-optimize` had left the store packages at one PostgreSQL server each, and that still holds: each finishes in about 18 s alone. In the full run, though, they took 113 to 119 s, while the root package started 44 PostgreSQL and 34 Redis or Valkey containers beside them. Most of the root package's containers are servers of a test's own, started only so the test can stop, restart or hang it. Every one costs a start, a readiness wait and a share of the Docker host the other packages are waiting on.

## What Changes

- **Outages through a proxy, not a server of one's own.** The PostgreSQL and Redis helpers can hand a test a connection that runs through a proxy in the test process, in front of the shared server. The test drives the proxy:
  - **stop**: close every open connection and refuse new ones;
  - **hang**: keep connections open and forward nothing;
  - **start**: accept and forward again.

  The shared server never stops, so other tests on it are unaffected.
- **The outage tables move onto the proxy.** The cases that stop, restart or hang a server use the proxy instead of a server of their own:
  - the PostgreSQL limiter's unavailable cases, on both backends and in their broken-variant child;
  - the limiter's "unreachable server" verify case;
  - the Redis limiter's fault cases.
- **One real outage per backend stays.** For each backend, one case keeps stopping and restarting a real server of its own, so a difference between a proxy cut and a real shutdown cannot pass unseen. PostgreSQL, for one, tells its clients `57P01 admin_shutdown` before it closes their connections, where a proxy just closes them.
- **Own Redis servers are shared by configuration.**
  - Calls that ask for a server of their own with identical start-up flags, and that do not stop or change it, share one such server per process.
  - ACL cases run on the shared server, each under an ACL user named for its test.
  - A call that stops, hangs or reconfigures its server still gets one of its own.
- **Measured before and after**, as `testcontainers-optimize` was:
  - container starts and wall time per package;
  - the passing test count, which must not drop;
  - every test passing under `-race`.
- **Order.** This change starts after `stabilize-intermittent-tests` has explained the intermittent `TestRedisLimiter_Fault` failure. That change must reproduce the failure against today's fault tests, which this change rewrites, and both changes own `test/redis_fault_test.go`.
- **Not in scope:**
  - sharing one server across package processes, which the user ruled out on 2026-10-02;
  - the Keycloak image and start time;
  - the Redis image list run in each CI job;
  - `make check`'s `-p`, `-parallel` and `-race` settings.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `test-provisioning`:
  - adds the outage proxy: what stop, hang and start do, and that the server behind it stays shared and unaffected;
  - adds the Redis requirements: a database of its own per call, a shared server per image and process, and sharing own servers by identical configuration;
  - states when a call still gets a server of its own.

## Impact

- **Test helpers** (`test/testutils*.go` and new files beside them):
  - the proxy;
  - its option on the PostgreSQL and Redis helpers;
  - the Redis own-server registry keyed by image and flags.
- **Tests rewritten to use them:**
  - `test/pg_ratelimit_fault_test.go`;
  - the "unreachable server" case in `test/pg_ratelimit_test.go`;
  - `test/redis_fault_test.go`;
  - `test/redis_verify_test.go`;
  - the helpers' own tests in `test/testutils_postgres_test.go` and `test/redis_testutils_test.go`.
- **The `use-testcontainers` skill**: says when to reach for the proxy, and when a server of one's own is still needed.
- **No product code, public API, dependency or migration change.** The proxy uses only the standard library.
- **CI**: unchanged.

## References

### Researched (accessed 2026-10-23)

- Outage proxy: what a proxy can stage, and how a real shutdown differs from it.
  - [Toxiproxy](https://github.com/Shopify/toxiproxy): an established TCP proxy for staging outages in tests. Its `down` (disable a proxy) and `timeout` (stop forwarding) toxics are the stop and hang modes proposed here.
  - [PostgreSQL error codes, Appendix A](https://www.postgresql.org/docs/current/errcodes-appendix.html): `57P01 admin_shutdown`, which clients of a stopping server receive and which a proxy cut does not send. This is why one real outage per backend stays.
  - `go list -m -versions github.com/testcontainers/testcontainers-go/modules/toxiproxy`: v0.43.0 and v0.44.0 exist, for the Toxiproxy alternative weighed in the design.
- Sharing across processes stays out of scope.
  - testcontainers-go v0.44.0 docs, `common_functional_options.md`: `WithReuseByName` is experimental.
  - testcontainers-go v0.44.0 docs, `test_session_semantics.md`: each package runs in its own process.
- Measurements: one local run of the `test` module and five single-package runs, counted with `docker events`, on 2026-10-23.
