# Spec Delta

## MODIFIED Requirements

### Requirement: A sealing store protects the provider ID token at rest
The library SHALL provide a store wrapper that seals a session's provider ID token with the configured cipher before it reaches the inner store, and opens it on load.
- The sealed value SHALL be bound to the session identifier, so it cannot be moved to another session.
- An empty ID token SHALL be stored unsealed.
- Every other field, and every other store operation, SHALL pass through unchanged.
- A value that cannot be opened SHALL fail the load with a session-unreadable error, distinct from not-found. The session SHALL NOT be returned with the token blanked.
- Loading SHALL NOT rewrite the record.
- A caller's session SHALL keep its plaintext token after saving.
- The cipher SHALL be given the context of the save or load it serves.
- An open that fails because of an outage SHALL fail the load as a store failure that wraps the cipher's error, and SHALL NOT match the session-unreadable error. An outage is an error that matches the context's cancellation or deadline, or one that matches the cipher-unavailable error, which a cipher uses to mark a failure to reach its keys. Every other open failure SHALL be the session-unreadable error.

#### Scenario: Sealed round trip
- **WHEN** a session with an ID token is saved through the sealing store and loaded
- **THEN** the inner store holds ciphertext for the token
- **AND** the loaded session carries the original token

#### Scenario: Value moved between sessions
- **WHEN** the sealed ID token of session A is copied into session B's record in the inner store and session B is loaded
- **THEN** the session-unreadable error is returned

#### Scenario: No rewrite on read
- **WHEN** a session sealed under a retired key is loaded successfully
- **THEN** the inner store receives no write

#### Scenario: Open abandoned when the context ends
- **WHEN** a session with an ID token is loaded and the cipher's open fails with the context's deadline error
- **THEN** the load fails with an error that wraps the deadline error
- **AND** the error does not match the session-unreadable error

#### Scenario: Consumer cipher marks an outage
- **WHEN** a session with an ID token is loaded through a consumer cipher whose open fails with an error that wraps the cipher-unavailable error
- **THEN** the load fails with an error that matches the cipher-unavailable error
- **AND** the error does not match the session-unreadable error

#### Scenario: An unmarked cipher failure stays unreadable
- **WHEN** a session with an ID token is loaded through a consumer cipher whose open fails with an error of its own that is neither a context error nor marked as an outage
- **THEN** the session-unreadable error is returned
