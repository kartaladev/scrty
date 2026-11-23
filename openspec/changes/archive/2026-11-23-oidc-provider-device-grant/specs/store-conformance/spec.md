## ADDED Requirements

### Requirement: The device authorization store has a behavioural suite
The conformance suites SHALL cover the device authorization store, and every scrty adapter and the in-memory default SHALL pass them. The suite SHALL be exported for consumers' own stores. Its race cases SHALL prove that a claim, an approval or denial, a poll record and a spend each succeed exactly once under concurrency.

#### Scenario: Concurrent spends
- **WHEN** the race suite spends one approved device code from many goroutines against an adapter
- **THEN** exactly one spend succeeds, or the suite fails

#### Scenario: A consumer store judging expiry by its own clock
- **WHEN** a consumer's device authorization store answers a user-code lookup by comparing with its own clock, and the suite runs against it
- **THEN** the suite fails, naming the case

#### Scenario: A store accepting a record no durable store could hold
- **WHEN** a store's create accepts a record with an unknown state, an approval naming no grant family, or no client, and the suite runs against it
- **THEN** the suite fails, naming the case
