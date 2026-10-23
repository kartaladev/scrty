# Spec Delta

## ADDED Requirements

### Requirement: The race suite proves bounded inserts
The race suite SHALL prove, for the one-time token store and the passkey credential store, that concurrent bounded inserts for one subject never take the count past the limit, that bounded inserts for different subjects do not block each other, and that a refused bounded insert writes nothing.

#### Scenario: Count-then-insert store
- **WHEN** the race suite runs against a store whose bounded insert counts and then inserts without a per-subject lock
- **THEN** the suite fails with more records than the limit for some subject

### Requirement: The isolation suite proves guarantees under a repeatable-read default
scrty's durable stores SHALL run, on every supported backend, the cases that decide outcomes by conditional writes and counters against a database whose default isolation is REPEATABLE READ: failure streaks, saved-code set replacement, identity provisioning and update, limiter records, and bounded inserts. Each case SHALL pass with the same outcome as at READ COMMITTED. Inside a caller's REPEATABLE READ transaction, an operation that refuses stronger isolations SHALL be shown to refuse.

#### Scenario: Store that inherits the database default
- **WHEN** a store begins its own transactions at the database default and the default is REPEATABLE READ
- **THEN** the isolation suite fails for the saved-code replacement and failure-streak cases

### Requirement: The enrolment suites prove generation-conditional writes
The enrolment suites SHALL prove that confirming an enrolment and recording an accepted time step are refused when they name an enrolment generation other than the current one, and when they name no generation.

#### Scenario: Store ignoring the generation
- **WHEN** the enrolment suite runs against a store whose confirmation ignores the named generation
- **THEN** the suite fails on the case that confirms naming a replaced generation
