# Spec Delta

## ADDED Requirements

### Requirement: A persistent browser cookie choice survives a durable store
Durable session stores SHALL store and return unchanged a session's persistent-cookie mark. A session stored without it, including one stored before the mark existed, SHALL read back with it unset.

#### Scenario: Mark round trip across backends
- **WHEN** a session created with the persistent-cookie mark is saved through the store of one supported backend and loaded through another
- **THEN** it loads with the mark set

#### Scenario: Session stored before the migration
- **WHEN** a session row written before the persistent-cookie column existed is loaded after the migration
- **THEN** it loads with the mark unset
