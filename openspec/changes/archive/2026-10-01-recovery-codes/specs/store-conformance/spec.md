# Spec Delta

## MODIFIED Requirements

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

#### Scenario: Saved-code spend race
- **WHEN** the race suite releases 8 callers spending the same saved code for each of 50 independent users at once
- **THEN** it passes only if every code has exactly one successful spend

#### Scenario: Recovery completion race
- **WHEN** the race suite releases 8 completions and 8 cancellations for each of 50 independent pending recovery records at once
- **THEN** it passes only if every record has exactly one successful completion or cancellation


## ADDED Requirements

### Requirement: The recovery stores have behavioural suites
The test module SHALL publish a behavioural suite for the saved-recovery-code store contract and one for the recovery-record store contract. Every durable store of either contract that scrty ships SHALL run its suite, the race suite and the ambient-transaction suite on every supported backend, and the in-memory defaults SHALL run the behavioural suites. The saved-code suite SHALL show that replacing a set inside a caller's transaction that is rolled back leaves the previous set whole.

#### Scenario: Replacement rolled back with the caller
- **WHEN** the suite begins a caller-owned transaction, replaces a user's set inside it, and rolls back
- **THEN** the suite asserts, through a separate connection, that the previous set's unspent codes still match

#### Scenario: In-memory saved-code store
- **WHEN** the saved-code suite runs against the in-memory default store
- **THEN** every case passes
