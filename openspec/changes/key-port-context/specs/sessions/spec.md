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

## ADDED Requirements

### Requirement: Creating a session can be completed by the caller before it is stored
The manager SHALL let a caller build a session, act on it, such as marking a pending challenge or issuing its credential, and only then store it, in the one write that creates it. A built session that has not been stored SHALL load nothing. When the caller's step fails, the creation SHALL fail with its error and SHALL store nothing. A creation with no caller's step SHALL behave as a creation does today.

#### Scenario: The caller's step fails at creation
- **WHEN** a caller builds a session for `u-1` and its step fails
- **THEN** the creation fails with the step's error
- **AND** the store holds no session for `u-1`

#### Scenario: A built session loads nothing until stored
- **WHEN** a caller builds a session and, inside its step, the session's identifier is loaded
- **THEN** the load reports the session as not found
- **AND** after the step succeeds and the session is stored, the identifier loads

### Requirement: A rotation with grace stores nothing when the caller cannot complete it
A rotation with a grace window SHALL let the caller act on the successor, such as issuing its credential, after it is built and before anything is stored. When that step fails, the rotation SHALL fail with its error and SHALL store, supersede and revoke nothing. A step that succeeds only after the window has closed SHALL likewise store nothing, and the rotation SHALL fail matching the context deadline error. The store SHALL still decide racing rotations.

#### Scenario: The caller's step fails
- **WHEN** a live session is rotated with a 30-second grace and the caller's step fails
- **THEN** the rotation fails with the step's error, and nothing is stored or superseded
- **AND** 31 seconds later the old identifier still loads, and no reuse is reported

#### Scenario: A losing rotation's step is discarded
- **WHEN** two rotations with grace of one session run concurrently and both callers' steps succeed
- **THEN** one rotation stores its successor, and the other's successor is never stored and loads nothing

#### Scenario: The window counts from before the caller's step
- **WHEN** a session is rotated at 10:00:00 with a 30-second grace, and the caller's step takes 5 seconds before it succeeds
- **THEN** the old identifier loads until 10:00:30 and is superseded after it

#### Scenario: A step that outlives the grace stores nothing
- **WHEN** a session is rotated at 10:00:00 with a 30-second grace, and the caller's step takes 31 seconds before it succeeds
- **THEN** the rotation fails with an error matching the context deadline error, and nothing is stored, superseded or revoked
- **AND** the old identifier still loads, no reuse is reported, and the session can be rotated again
