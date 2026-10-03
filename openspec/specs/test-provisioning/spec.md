# test-provisioning Specification

## Purpose

How the test module's helpers provision container-backed resources for tests: what each call isolates, what calls share, and how start-up is bounded. A test gets correct, isolated state at the lowest provisioning cost.

## Requirements

### Requirement: Every PostgreSQL call gets a database of its own
Each call of the PostgreSQL test helper SHALL return a database that no other call, in this or any other test process, can read or change. Rows, tables, functions, triggers, constraints and locks created through one call's database SHALL NOT be visible through another's.

#### Scenario: Two calls in one test
- **WHEN** one test calls the helper twice and creates a table with a row through the first database
- **THEN** the second database has neither the table nor the row

#### Scenario: Parallel tests truncate the same table
- **WHEN** two parallel tests migrate the same set and one truncates the sessions table while the other inserts a session
- **THEN** the other test still loads its session

### Requirement: A call's migration sets give the schema of a fresh application
A call that names migration sets SHALL receive a database whose schema and version tables are exactly those produced by applying those sets, in that order, to an empty database. A call that names none SHALL receive an empty database.

#### Scenario: Same sets, same schema
- **WHEN** a call names the security-state set and then the identity set
- **THEN** its database has the tables and version-table rows that applying both sets in that order to an empty database produces

#### Scenario: No sets
- **WHEN** a call names no migration set
- **THEN** its current schema has no tables

#### Scenario: Order matters
- **WHEN** one call names sets A then B and another names B then A
- **THEN** each database matches applying its own order to an empty database

### Requirement: Per-call teardown checks still run on the call's database
At the end of each call's test, every set the call applied SHALL be rolled back in reverse order. The finalize scripts SHALL then run, then the leftover-table check when it was requested, all on that call's database. A rollback, script or check failure SHALL fail that test. Afterwards the database SHALL be removed.

#### Scenario: A migration that forgets a table
- **WHEN** a call applies a set whose down migration leaves a table behind and requested the leftover-table check
- **THEN** that test fails and names the table

#### Scenario: Rollback of a clean set
- **WHEN** a call applies a set whose down migrations remove everything
- **THEN** the test passes and its database no longer exists afterwards

### Requirement: Calls in one test process share a server per image
Calls in one test process that resolve to the same PostgreSQL image SHALL share one server, started on the first such call. A call that resolves to a different image SHALL get a server running that image.

#### Scenario: Many calls, one server
- **WHEN** fifty tests in one package call the helper with the default image
- **THEN** one PostgreSQL container is started for that package's process

#### Scenario: Another image
- **WHEN** one call resolves to PostgreSQL 15 and another, in the same process, to PostgreSQL 18
- **THEN** each reports its own server version

#### Scenario: A call asks for a server of its own
- **WHEN** a call passes `WithTestPostgresOwnServer()`
- **THEN** it gets a server that no other call shares, and that server is removed when the call's test ends

### Requirement: Child test processes reuse their parent's servers
A test process started by another test process, to run a test in isolation, SHALL use the servers its parent already started for the same images instead of starting its own.

#### Scenario: Broken store variants
- **WHEN** a package's broken-variant check starts eleven child processes that each call the helper
- **THEN** no PostgreSQL container is started by any of them, and each child's database is still its own

### Requirement: A migration set that fails is never handed out half applied
When applying a call's migration sets fails, that call SHALL fail and name the failing set. No call SHALL receive a database where those sets are only partly applied. A later call naming the same sets SHALL try again from an empty database.

#### Scenario: Failing set
- **WHEN** a call names a set whose third migration fails
- **THEN** the call fails naming that set, and a second call naming the same set fails the same way rather than receiving the first two migrations

### Requirement: Concurrent first calls apply a migration set once
When several calls naming the same sets reach a server at once, the sets SHALL be applied to that server once, and every call SHALL still receive its own database.

#### Scenario: Parallel first use
- **WHEN** eight parallel tests are the first to name the security-state set on a server
- **THEN** the set's migrations run once on that server and the eight tests get eight distinct databases

### Requirement: Server tuning never changes what a test can observe
Settings applied to a shared server to make it faster SHALL change only durability against an operating-system crash. They SHALL NOT change transaction isolation, locking, constraint checking or error behaviour that a test can observe.

#### Scenario: Serialization conflict
- **WHEN** two serializable transactions on the shared server write skew against each other
- **THEN** one of them fails with a serialization error, as on a default server

### Requirement: Provisioned containers do not outlive the test run
Every container a helper starts SHALL be removed after the test process that started it exits, including servers shared by many calls. A container started for a single call SHALL be removed when that call's test ends.

#### Scenario: Process exit
- **WHEN** a test package's process finishes
- **THEN** no PostgreSQL container it started remains running shortly afterwards

### Requirement: An unavailable container runtime fails PostgreSQL tests in CI and skips them elsewhere
When no healthy container runtime is available, a call of the PostgreSQL test helper SHALL fail its test when the `CI` environment variable is set, and SHALL skip it otherwise. A server that failed to start SHALL fail every later call in that process with the same reason, without trying to start it again.

#### Scenario: CI without Docker
- **WHEN** a test calls the PostgreSQL helper with `CI` set and no Docker daemon
- **THEN** the test fails rather than skipping

#### Scenario: A server that cannot start
- **WHEN** the first call in a process cannot start its server and forty more calls follow
- **THEN** every one of them fails with the first call's reason, and no further start is attempted
