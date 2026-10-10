## Why

The code review of `shared-rate-limiting-postgres` (PR #13) found that the PostgreSQL limiter cannot serve the default HTTP chain. The chain asks for a limit of 200: password login is 50, and the IPv6 aggregate, on by default, counts four times that. The limiter refuses anything above 128, so `httpsec.New` fails at startup with the PostgreSQL factory. The same review, and the research that followed, found two ways a backend error can open the breaker for a whole namespace:
- a prune that keeps its row locks on every victim until it commits, so records on idle keys wait on it;
- a database whose encoding cannot hold a key.

It also found smaller defects in error text, diagnostics, construction, duplication, documentation and test helpers.

## What Changes

- **The limit maximum rises above the largest built-in ask.** How it rises is the decision still open in `design.md`, decision 1. The recommended answer is a table storage parameter and a maximum of 400. A limit above the new maximum stays a configuration error naming it.
- **The prune bounds itself.** It deletes in short batches of 1,000 keys by default, each its own transaction, so no record waits on it past its timeout. The returned count is the keys removed by batches that committed. A new option sets the batch size.
- **`Verify` refuses a database whose server encoding is not UTF-8**, SQL_ASCII included, with a configuration error naming the encoding. The godoc states the requirement.
- **A failed prune's error no longer carries the server's text**, as `Verify`'s errors already do not.
- **`Verify` names a temporary table for what it is**, instead of calling it unlogged and advising `SET LOGGED`.
- **The factories validate their options without building and discarding a limiter.**
- **The driver-agnostic parts of the two limiters live once**, in an internal package both adapters use. These are validation, the server-facts check, the policy registry, the time and lock-timeout arguments, and the prune loop. Each adapter keeps only how it runs a statement.
- **The factory godoc states the policy-conflict check's reach**: one factory only, not other factories in the same process and not other processes. This covers the `sqlstore` and `pgx` factories, and the `redis` factory's identical sentence.
- **Own test PostgreSQL servers keep their data on tmpfs again.** A restartable server, on disk, becomes an explicit option of the test helper. `Stop` and `Start` refuse a server built without it.
- **The record statement's godoc says what the statement keeps**: at most `limit` stamps, the new one included.
- **The archived design's two wrong claims are corrected here.** The largest built-in ask is 200, not 30. NIST's 100-failure ceiling bounds an account, not an aggregate.

## Capabilities

### New Capabilities
None.

### Modified Capabilities
- `rate-limiting`:
  - "A PostgreSQL limiter refuses a policy too large for one row" gets a new maximum, and a scenario showing the default chain builds.
  - "A PostgreSQL limiter reads and writes only the primary" adds the UTF-8 refusal.
  - "The PostgreSQL limiter prunes idle keys through an expiry task" adds that a record never waits on a prune past its timeout, and the batch-size override.

## Impact

- **Code:**
  - `internal/pgschema/ratelimit.go`: the maximum, the batched prune statement, the server-facts query and godoc.
  - A new internal package for the shared limiter core.
  - `sqlstore/limiter*.go` and `pgx/limiter*.go`, and `redis` godoc only.
- **Migration:** `migrate/securitystate/20260926000000_security_state.sql` gets the storage parameter, if decision 1 takes it. It is still untagged, so it is edited in place.
- **Tests:**
  - `test/pg_ratelimit_*`: a chain built over each PostgreSQL factory, a prune racing records, `Verify` on non-UTF-8 databases and a temporary table.
  - `test/testutils*.go`: the restartable-server option, and the tests that use it.
- **API:**
  - A new prune batch-size option on both factories.
  - A new test-helper option.
  - A raised maximum.
  - No public signature changes.
- **Dependencies:** none.
