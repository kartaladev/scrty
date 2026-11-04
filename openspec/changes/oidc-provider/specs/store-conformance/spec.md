# Spec Delta

## ADDED Requirements

### Requirement: The provider stores have behavioural suites
The conformance suites SHALL cover every provider store, and every scrty adapter and in-memory default SHALL pass them. They SHALL be exported for consumers' own stores. The race suite SHALL prove:
- single use of codes, handles and assertion identifiers under concurrency;
- a revocation recorded before a grant is stored survives the store;
- a sign-in's end that races its code's exchange leaves the grant revoked.

#### Scenario: Consumer store fails the tombstone case
- **WHEN** a consumer's grant store lets a later write clear a grant's revoked mark, and the suite runs against it
- **THEN** the suite fails, naming the case

#### Scenario: Concurrent code spend
- **WHEN** the race suite spends one code from many goroutines against an adapter
- **THEN** exactly one spend succeeds, or the suite fails

### Requirement: Refresh token reuse is proved over scrty's own lineage stores
Reuse of a refresh token after its grace window SHALL be proved to revoke the whole grant over the in-memory lineage store and each scrty adapter's. It SHALL NOT be in the exported suite, because no consumer can supply a lineage store.

#### Scenario: Reuse after the grace window
- **WHEN** a superseded refresh token is presented after its grace window, on any scrty lineage store
- **THEN** the whole grant is revoked
