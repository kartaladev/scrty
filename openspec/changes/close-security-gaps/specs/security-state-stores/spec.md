## ADDED Requirements

### Requirement: Durable session stores list a user's live sign-ins
Every durable session store SHALL list a user's live sign-ins as the `sessions` capability defines, answering from an index on the user reference so the cost does not grow with other users' sessions, and SHALL exclude expired and superseded members by the store's own time comparison.

#### Scenario: Listing across replicas
- **WHEN** a user signs in through two replicas sharing one PostgreSQL store
- **THEN** listing that user's sign-ins on either replica returns both

### Requirement: Sign-in metadata and key binding survive a durable store
A durable session store SHALL persist a session's sign-in metadata and key binding, return them unchanged on load, and SHALL NOT change the key binding on save. The metadata SHALL be stored as plain text, since it is not a secret; the key binding SHALL be stored as its thumbprint only.

#### Scenario: Bound session reloaded
- **WHEN** a session bound to DPoP key thumbprint `K`, with recorded metadata, is created in a durable store and loaded
- **THEN** the loaded session is bound to `K` and carries the same metadata
