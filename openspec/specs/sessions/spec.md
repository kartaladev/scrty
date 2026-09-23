# sessions Specification

## Purpose

Keeps server-side sessions behind unguessable bearer identifiers, expires them on inactivity and at an absolute limit, and records how each was established and which challenges it still owes, in fields the library owns and apart from consumer data.

## Requirements

### Requirement: Session identifiers are unguessable
Each new session SHALL receive an identifier made from 32 bytes read from the operating system's cryptographically secure random source, encoded URL-safe without padding. If the random source fails, creation SHALL return an error wrapping that failure, and no session SHALL be stored.

#### Scenario: Identifier shape
- **WHEN** a session is created
- **THEN** its identifier is 43 URL-safe characters that decode to 32 bytes

#### Scenario: Distinct identifiers
- **WHEN** two sessions are created
- **THEN** their identifiers differ

#### Scenario: Random source failure
- **WHEN** the random source returns an error during creation
- **THEN** creation returns an error wrapping it
- **AND** the store receives no write

### Requirement: Sessions expire when idle and at an absolute limit
A new session SHALL receive:
- an idle deadline of creation time plus the idle timeout;
- an absolute deadline of creation time plus the absolute timeout.

A session SHALL be valid only while the current time is before both deadlines. The defaults SHALL be an idle timeout of 30 minutes and an absolute timeout of 12 hours, each replaceable by an option. Construction SHALL fail with a configuration error when either timeout is zero or negative.

#### Scenario: Default deadlines
- **WHEN** a session is created at 09:00 with default options
- **THEN** its idle deadline is 09:30 and its absolute deadline is 21:00

#### Scenario: Consumer timeouts
- **WHEN** the manager is configured with a 5-minute idle timeout and a 1-hour absolute timeout, and a session is created at 09:00
- **THEN** its idle deadline is 09:05 and its absolute deadline is 10:00

#### Scenario: Zero idle timeout
- **WHEN** a manager is constructed with a zero idle timeout
- **THEN** construction fails with a configuration error

### Requirement: Loading enforces existence and expiry
Loading an identifier with no stored session SHALL fail with a not-found error. Loading a session past either deadline SHALL fail with an expired error. Every store SHALL enforce both, so no caller can read a stale session.

#### Scenario: Unknown identifier
- **WHEN** an identifier that was never issued is loaded
- **THEN** the not-found error is returned

#### Scenario: Idle expiry
- **WHEN** a session created at 09:00 with a 30-minute idle timeout is loaded at 09:31 without activity
- **THEN** the expired error is returned

### Requirement: Activity extends the idle deadline
Recording activity on a valid session SHALL set its last-access time to now and its idle deadline to now plus the idle timeout, capped at the absolute deadline, and SHALL persist the change. Recording activity on an expired or unknown session SHALL fail with the expired or not-found error.

#### Scenario: Extension
- **WHEN** a session created at 09:00 with a 30-minute idle timeout records activity at 09:20
- **THEN** its idle deadline becomes 09:50

#### Scenario: Capped at the absolute deadline
- **WHEN** a session whose absolute deadline is 21:00 records activity at 20:50 with a 30-minute idle timeout
- **THEN** its idle deadline becomes 21:00

### Requirement: Saving an existing session never re-creates a deleted one
Creating a session SHALL insert a new record. Saving a changed session, including when activity is recorded, SHALL update only a record that still exists. If the record was deleted in the meantime, saving SHALL fail with the not-found error and SHALL NOT insert it again.

#### Scenario: Logout races activity
- **WHEN** a request loads a session, a concurrent logout deletes it, and the first request then records activity
- **THEN** recording activity fails with the not-found error
- **AND** loading the session afterwards returns the not-found error

### Requirement: The first factor is recorded in the creating write
The manager SHALL let a caller record, at creation, the kind of first factor the session was established with, and SHALL persist it in the same store write that creates the session. A session created without one SHALL report no first factor.

#### Scenario: Recorded at creation
- **WHEN** a session is created recording the password first factor and is then loaded
- **THEN** the loaded session reports the password first factor
- **AND** the store received exactly one write for the creation

#### Scenario: Not recorded
- **WHEN** a session is created without a first factor
- **THEN** it reports no first factor

### Requirement: Challenge state is kept apart from consumer data
A session SHALL carry, in fields that only the library writes:
- a second-factor state of none, pending or satisfied;
- a marker that a password change is pending.

The manager SHALL persist changes to these fields. They SHALL NOT be stored in, or read from, consumer data.

#### Scenario: MFA pending then satisfied
- **WHEN** a session's second-factor state is set to pending, saved, then set to satisfied and saved
- **THEN** loading the session reports the satisfied state

#### Scenario: Consumer data cannot forge state
- **WHEN** a consumer stores the entry `{"mfa": "satisfied"}` in the consumer data of a session whose second-factor state is pending
- **THEN** the session still reports the pending state

### Requirement: Consumer data is returned unchanged
A session SHALL carry a map of string keys to string values that belongs to the consumer. The library SHALL store and return it byte-for-byte, SHALL NOT read, add, rename or remove its entries, and SHALL NOT keep any library state in it.

#### Scenario: Round trip
- **WHEN** a session is saved with consumer data `{"tenant": "acme", "count": "07"}` and then loaded
- **THEN** the loaded consumer data is exactly `{"tenant": "acme", "count": "07"}`

#### Scenario: Library state is not in consumer data
- **WHEN** a session is created recording a first factor and has its second-factor state set to pending
- **THEN** its consumer data is empty

### Requirement: Sessions can be deleted singly, per user and when expired
The manager SHALL:
- delete a single session;
- delete every session of a user;
- count a user's unexpired sessions, excluding expired ones;
- delete every expired session, returning how many were removed.

The user reference SHALL be matched exactly as the consumer supplied it.

#### Scenario: Delete per user
- **WHEN** user `u-1` has three sessions and user `u-2` has one, and the sessions of `u-1` are deleted
- **THEN** no session of `u-1` loads
- **AND** the session of `u-2` still loads

#### Scenario: Count excludes expired
- **WHEN** user `u-1` has two valid sessions and one expired session
- **THEN** counting the active sessions of `u-1` returns 2

### Requirement: Federated sessions can be ended by their provider session
A session SHALL be able to record, at creation and in the same write, the identity provider name, the verified issuer, the provider's session identifier (which may be empty) and the provider's raw ID token.
- Deleting by provider session SHALL remove only sessions matching both the issuer and the provider session identifier.
- Deleting by user and issuer SHALL remove only that user's sessions from that issuer.

Both SHALL return the number removed. An empty issuer, or an empty provider session identifier for the session-scoped delete, SHALL delete nothing and SHALL NOT be an error.

#### Scenario: Scoped to one issuer
- **WHEN** two sessions carry provider session `s-1`, one from issuer `https://a` and one from issuer `https://b`, and sessions for `https://a` and `s-1` are deleted
- **THEN** one session is removed and the `https://b` session still loads

#### Scenario: Empty provider session identifier
- **WHEN** sessions for issuer `https://a` and an empty provider session identifier are deleted
- **THEN** nothing is removed, including sessions from `https://a` that recorded no provider session identifier

#### Scenario: Password sessions are spared
- **WHEN** user `u-1` has a password session and a session from issuer `https://a`, and the sessions of `u-1` from `https://a` are deleted
- **THEN** only the federated session is removed

### Requirement: An in-memory store is the default
When no store is configured, the manager SHALL use an in-memory store. That store SHALL:
- hold its own copies of records, so a caller mutating a returned session cannot change stored state;
- provide a housekeeping ticker that deletes expired sessions once per interval while started, and stops on request or when its context ends.

Starting and stopping SHALL be idempotent. The housekeeping interval SHALL default to one minute and be replaceable by an option. Without starting, expired sessions SHALL still never be returned, but SHALL stay in memory until deleted, and this SHALL be documented. Any implementation of the store contract SHALL be usable in its place.

#### Scenario: Caller mutation is isolated
- **WHEN** a loaded session's consumer data is modified by the caller without saving
- **THEN** loading the session again returns the stored data unchanged

#### Scenario: Housekeeping while started
- **WHEN** the store is started with a 10-second housekeeping interval and a session expires
- **THEN** within one interval the expired session is no longer held

#### Scenario: Double start and stop
- **WHEN** the store is started twice and stopped twice
- **THEN** no error or panic occurs and no ticker keeps running

#### Scenario: Consumer store
- **WHEN** the manager is configured with a consumer's store
- **THEN** every session operation is served by that store

### Requirement: A sealing store protects the provider ID token at rest
The library SHALL provide a store wrapper that seals a session's provider ID token with the configured cipher before it reaches the inner store, and opens it on load.
- The sealed value SHALL be bound to the session identifier, so it cannot be moved to another session.
- An empty ID token SHALL be stored unsealed.
- Every other field, and every other store operation, SHALL pass through unchanged.
- A value that cannot be opened SHALL fail the load with a session-unreadable error, distinct from not-found. The session SHALL NOT be returned with the token blanked.
- Loading SHALL NOT rewrite the record.
- A caller's session SHALL keep its plaintext token after saving.

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
