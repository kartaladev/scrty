## MODIFIED Requirements

### Requirement: Durable stores exist for every security-state record on every supported backend
scrty SHALL provide a durable store for each security-state record type (sessions, signing keys, login attempts, consecutive login failure counts and holds, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes, recovery records, passkey credentials and passkey user handles) on each supported database access backend. Each durable store SHALL satisfy the same store contract as the in-memory default for that record type. A record written through one store instance SHALL be visible to every other store instance, on any supported backend, connected to the same database.

#### Scenario: State survives a process restart
- **WHEN** a session is saved through a durable store, the process exits, and a new store instance is created against the same database
- **THEN** loading the session through the new instance returns the saved session

#### Scenario: Another replica sees a consumption
- **WHEN** a one-time token is consumed through a store instance in one process
- **AND** a second process tries to consume the same token through its own store instance
- **THEN** the second consumption is refused

#### Scenario: Handoff subject round trip
- **WHEN** a handoff is inserted with user reference `Alice@Example.com`, provider, issuer, external session id and next location, and is found by its token id
- **THEN** every one of those values is returned exactly as inserted

#### Scenario: Backends share one schema
- **WHEN** an API key is inserted through the store of one supported backend
- **THEN** a store of a different supported backend, connected to the same database, finds that API key with every attribute equal

#### Scenario: Passkey seen by another backend
- **WHEN** a passkey credential is inserted through the store of one supported backend
- **THEN** a store of a different supported backend, connected to the same database, finds it by its credential ID with every attribute equal

#### Scenario: A hold seen by another backend
- **WHEN** an identifier becomes held through the attempt store of one supported backend
- **THEN** the attempt store of a different supported backend, connected to the same database, reads it as held with the same consecutive count
