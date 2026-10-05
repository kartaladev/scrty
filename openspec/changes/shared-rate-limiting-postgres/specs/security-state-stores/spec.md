## MODIFIED Requirements

### Requirement: Stores join a transaction the caller attached
When a caller attaches its own transaction to the operation context through a backend's attach function, every store of that backend SHALL perform the operation inside that transaction. When no transaction is attached, the store SHALL use the database handle it was constructed with. The store SHALL NOT commit or roll back a transaction it did not open.

The shared PostgreSQL rate limiter is not a store under this requirement: it SHALL ignore an attached transaction, as `rate-limiting` requires.

#### Scenario: Rolled back with the caller
- **WHEN** a caller begins a transaction, attaches it, saves a session through a durable store, and rolls back
- **THEN** the session does not exist afterwards

#### Scenario: Committed with the caller
- **WHEN** a caller begins a transaction, attaches it, records a login attempt and consumes a one-time token, and commits
- **THEN** both the attempt and the consumption are visible afterwards

#### Scenario: No attached transaction
- **WHEN** a session is saved with no transaction attached
- **THEN** the session is visible to other connections immediately after the save returns

#### Scenario: The rate limiter stays outside the caller's transaction
- **WHEN** a caller attaches a transaction, records a failure through a PostgreSQL rate limiter and saves a session through a durable store, and rolls back
- **THEN** the session does not exist afterwards
- **AND** the recorded failure still counts
