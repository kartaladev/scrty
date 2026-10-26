# Spec Delta

## MODIFIED Requirements

### Requirement: The in-memory store isolates stored records
When no store is configured, the manager SHALL use an in-memory store. That store SHALL hold its own copies of hashes and records, so mutating a slice passed in or returned cannot change stored state. It SHALL preserve an absent binding hash as absent, and it SHALL implement purging. Its time source SHALL default to the system clock and be replaceable by an option; constructing it with a nil time source, typed nil included, SHALL fail with a configuration error rather than keep the default. Any implementation of the token store contract SHALL be usable in its place.

#### Scenario: Returned hash is a copy
- **WHEN** a caller overwrites the bytes of a hash returned by the in-memory store and the record is read again
- **THEN** the stored hash is unchanged

#### Scenario: Consumer time source
- **WHEN** the in-memory store is constructed with a controlled time source, a record expires by that source, and purging runs
- **THEN** the expired record is purged with no real waiting

#### Scenario: Nil time source
- **WHEN** the in-memory store is constructed with a nil time source
- **THEN** construction fails with a configuration error and returns no store
