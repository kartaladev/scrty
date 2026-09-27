# store-conformance Specification

## Purpose

Defines what every security-state store implementation must prove, and how it proves it: shared behavioural suites, suites for durability, races, transactions and sealed columns, and a PostgreSQL test helper that verifies rollback. Backend parity is therefore tested rather than assumed, and consumers can hold their own stores to the same bar.

## Requirements

### Requirement: Every scrty store implementation passes the shared suites
scrty SHALL publish, in its test module, one behavioural suite for each security-state store contract. Every durable store scrty ships SHALL run the suite for its contract, on every supported backend, against a real PostgreSQL database. A behaviour that differs between backends SHALL fail the suite for the backend that differs.

#### Scenario: Backend diverges
- **WHEN** one backend's handoff store returns a consumed handoff's consumption time as zero while the other backends return it
- **THEN** the handoff store suite fails for that backend
- **AND** the failure names the suite case and the backend under test

#### Scenario: All backends conform
- **WHEN** the test gates run
- **THEN** each security-state store suite runs against each supported backend, and every run must pass for the gates to pass

### Requirement: In-memory defaults pass the behavioural suites
Every in-memory default store scrty ships for a security-state contract SHALL pass that contract's behavioural suite. The suites for durability, database races, transactions and sealed columns SHALL NOT be required of in-memory stores.

#### Scenario: In-memory one-time token store
- **WHEN** the one-time token suite runs against the in-memory default store
- **THEN** every case passes

### Requirement: Consumers can run the suites against their own stores
The suites SHALL be usable by a consumer who implements a security-state store contract themselves. A consumer's store that satisfies the contract SHALL pass, and one that violates it SHALL fail.

#### Scenario: Consumer's own store
- **WHEN** a consumer runs the one-time token suite against their own store backed by another database
- **AND** that store's consumption is a read followed by an unconditional write
- **THEN** the sequential cases can pass while the race suite fails with more than one successful consumption for some token

### Requirement: Required suite inputs cannot be skipped
A suite that needs an input from its caller (such as out-of-band database access, a way to begin a caller-owned transaction, or the connection pool width) SHALL fail immediately when that input is missing. It SHALL NOT skip, pass or silently run fewer cases.

#### Scenario: Missing out-of-band access
- **WHEN** the sealed-column suite is run without out-of-band database access
- **THEN** the suite fails, naming the missing input

### Requirement: Suites assert exact outcomes on isolated state
Each suite run SHALL use state isolated from every other suite run, and SHALL assert exact counts and exact records rather than lower bounds. Suites SHALL drive time through the store's clock, not by waiting.

#### Scenario: Deletion count is exact
- **WHEN** the suite for a store's expiry deletion plants two expired records and one live record, then deletes expired records
- **THEN** the suite asserts that exactly two records were deleted and the live record remains

#### Scenario: No waiting for expiry
- **WHEN** a suite tests that an expired flow cannot be completed
- **THEN** it advances the store's clock past the expiry instead of sleeping

### Requirement: The race suite proves atomic single use and unique inserts
For stores with single-use consumption or unique inserts, a race suite SHALL release many concurrent callers at once against many independent records. It SHALL require exactly one success per record. It SHALL fail when the connection pool it is given is narrower than the number of racers per record. The race suite SHALL be shown to fail against an implementation that reads before writing.

#### Scenario: Exactly one winner per record
- **WHEN** the race suite releases 8 consumers for each of 50 independent tokens at once
- **THEN** it passes only if every token has exactly one successful consumption

#### Scenario: TOTP step race
- **WHEN** the race suite releases 8 callers recording the same TOTP time step for each of 50 independent enrolments at once
- **THEN** it passes only if every enrolment has exactly one successful recording

#### Scenario: Pool too narrow
- **WHEN** the race suite is given a pool of 2 connections for 8 racers per record
- **THEN** the suite fails, stating that the pool cannot exercise the race

#### Scenario: Read-then-write implementation caught
- **WHEN** the race suite runs against a store variant whose consumption reads the record and then updates it unconditionally
- **THEN** the suite fails

### Requirement: The ambient-transaction suite proves transaction participation
Every durable store scrty ships SHALL pass an ambient-transaction suite. The suite SHALL show that:
- work performed inside a caller-owned transaction is rolled back and committed with it;
- a refusal inside the transaction leaves it usable;
- a configured transaction resolver is honoured;
- a transaction attached for another backend is ignored.

#### Scenario: Rollback discards store work
- **WHEN** the suite begins a caller-owned transaction, performs a store write inside it, and rolls back
- **THEN** the suite asserts, through a separate connection, that the write is absent

#### Scenario: Store bypasses the transaction
- **WHEN** the suite runs against a store variant that ignores the attached transaction
- **THEN** the suite fails

#### Scenario: Resolver honoured
- **WHEN** the suite configures the store with a resolver that returns the caller's transaction, without attaching it to the context, and rolls back after a write
- **THEN** the suite asserts that the write is absent

### Requirement: The sealed-column suite proves secrets are unusable at rest
Every durable store with sealed columns SHALL pass a sealed-column suite. Using out-of-band database access, the suite SHALL show that:
- the stored value, after undoing any text encoding, neither equals nor contains the plaintext;
- a sealed value copied into another record fails to open;
- reading with a keyring that lacks the sealing key is reported as an error, never as absence;
- a value re-sealed on read opens with a keyring holding only the active key.

The suite SHALL be shown to fail against a cipher that returns its input unchanged.

#### Scenario: Plaintext absent from the column
- **WHEN** an MFA secret `SENTINEL-TOTP` is enrolled and its column is read out of band and decoded
- **THEN** neither the stored text nor the decoded bytes equal or contain `SENTINEL-TOTP`

#### Scenario: Pass-through cipher caught
- **WHEN** the suite runs against a store configured with a cipher that returns its input unchanged
- **THEN** the suite fails

#### Scenario: Missing key is not absence
- **WHEN** an enrolment sealed under key `k1` is read through a store whose keyring does not contain `k1`
- **THEN** the read returns an error and does not report the user as not enrolled

### Requirement: The PostgreSQL test helper isolates tests and verifies rollback
The test module SHALL provide a helper that gives each call an isolated PostgreSQL database in a real PostgreSQL server. When asked, it SHALL apply a migration set. When migrations were applied, it SHALL at test cleanup roll them all the way back to zero, and SHALL fail the test when that rollback errors. Cleanup scripts registered with the helper SHALL run after the rollback, in the order they were declared. The helper SHALL offer a leftover-table check, run after the rollback and the cleanup scripts, that fails the test naming any table left behind other than the version tables of the sets it applied, and the security-state set's own test SHALL use it. The helper SHALL be usable only from test code.

#### Scenario: Isolated databases
- **WHEN** two tests each obtain a database from the helper and write a session with the same identifier
- **THEN** neither test sees the other's session

#### Scenario: Forgotten table in a rollback
- **WHEN** a migration set's rollback omits dropping one of its tables and a test uses the helper with that set
- **THEN** the test fails at cleanup, naming the table left behind

#### Scenario: Rollback error fails the test
- **WHEN** rolling back the migrations at cleanup returns an error
- **THEN** the test is reported as failed, not merely logged

#### Scenario: Native uuid round trip
- **WHEN** a library-owned identifier is written to a uuid column in a helper database and read back
- **THEN** the identifier read back equals the one written
