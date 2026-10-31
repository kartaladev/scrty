# Spec Delta

## MODIFIED Requirements

### Requirement: The default attempt store stays bounded
The default in-memory attempt store SHALL forget failures older than the longest retention its owning policy needs, sweeping as it is written to, and SHALL hold at most 100,000 identifiers by default, replaceable by an option. Constructing it with a capacity of zero or less SHALL fail with a configuration error, and SHALL NOT panic. Identifiers longer than 256 bytes SHALL be held by a digest. A hold SHALL never be forgotten before it lifts.

#### Scenario: Old failures are forgotten
- **WHEN** 50,000 distinct usernames each fail once, and the policy's window then passes with no further failures
- **THEN** the store holds none of them after its next write

#### Scenario: Consumer capacity
- **WHEN** the consumer sets the default store's capacity to 1,000,000
- **THEN** the store holds up to 1,000,000 identifiers

#### Scenario: Capacity of zero
- **WHEN** the consumer constructs the default store with a capacity of zero
- **THEN** construction fails with a configuration error and returns no store
