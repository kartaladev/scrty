## MODIFIED Requirements

### Requirement: The ambient-transaction suite proves transaction participation
Every durable store scrty ships SHALL pass an ambient-transaction suite. The shared PostgreSQL rate limiter SHALL NOT run it, because it ignores the caller's transaction by design; the suite's documentation SHALL state that exclusion. The suite SHALL show that:
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

#### Scenario: Rate limiter excluded and the exclusion stated
- **WHEN** a reader looks for the shared PostgreSQL rate limiter among the ambient-transaction suite's runs
- **THEN** it is absent, and the suite's documentation names it as excluded and why
