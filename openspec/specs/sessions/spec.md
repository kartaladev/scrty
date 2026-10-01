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
- a second-factor state of none, pending, enrolment-pending, satisfied or recovery-pending;
- a marker that the session entered a confined state, through the enrolment path or through an account recovery, recording the absolute deadline it held before it was marked;
- the time the session was produced by an account recovery, when it was;
- the generation of the enrolment the session began, when it began one;
- a marker that a password change is pending.

The manager SHALL persist changes to these fields. They SHALL NOT be stored in, or read from, consumer data. Adding the enrolment-pending and recovery-pending states SHALL NOT change how an already persisted state is read back.

#### Scenario: MFA pending then satisfied
- **WHEN** a session's second-factor state is set to pending, saved, then set to satisfied and saved
- **THEN** loading the session reports the satisfied state

#### Scenario: Enrolment state round trip
- **WHEN** a session's second-factor state is set to enrolment-pending with an enrolment generation, saved and loaded
- **THEN** the loaded session reports the enrolment-pending state, the enrolment-origin marker and the same generation

#### Scenario: Consumer data cannot forge state
- **WHEN** a consumer stores the entry `{"mfa": "satisfied"}` in the consumer data of a session whose second-factor state is pending
- **THEN** the session still reports the pending state

#### Scenario: Consumer data cannot clear the enrolment state
- **WHEN** a consumer stores the entry `{"mfa": "none"}` in the consumer data of an enrolment-only session
- **THEN** the session still reports the enrolment-pending state

#### Scenario: Recovery state round trip
- **WHEN** a session in the recovery-pending state, with recovery time 09:00, is saved and loaded
- **THEN** the loaded session reports the recovery-pending state, the confinement marker and the recovery time 09:00

#### Scenario: Consumer data cannot record a recovery
- **WHEN** a consumer stores the entry `{"recovered_at": "2026-01-01T00:00:00Z"}` in a session's consumer data
- **THEN** the session reports no recovery time

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
- run housekeeping that deletes expired sessions once per interval while started, and stops on request or when its context ends.

Housekeeping SHALL be paced by the store's time source, which defaults to the system clock and is replaceable by an option, so a controlled source runs housekeeping without real waiting. Each run SHALL start one interval after the previous run finishes. Starting and stopping SHALL be idempotent. The housekeeping interval SHALL default to one minute and be replaceable by an option. Without starting, expired sessions SHALL still never be returned, but SHALL stay in memory until deleted, and this SHALL be documented. Any implementation of the store contract SHALL be usable in its place.

#### Scenario: Caller mutation is isolated
- **WHEN** a loaded session's consumer data is modified by the caller without saving
- **THEN** loading the session again returns the stored data unchanged

#### Scenario: Housekeeping while started
- **WHEN** the store is started with a 10-second housekeeping interval and a session expires
- **THEN** within one interval the expired session is no longer held

#### Scenario: Housekeeping on a controlled time source
- **WHEN** a store with a controlled time source and a 10-second housekeeping interval is started, a session expires, and the source advances by 10 seconds
- **THEN** the expired session is no longer held, with no real waiting

#### Scenario: Double start and stop
- **WHEN** the store is started twice and stopped twice
- **THEN** no error or panic occurs and no housekeeping keeps running

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

### Requirement: The enrolment-only state lowers the absolute deadline, and the upgrade restores it
Marking a session enrolment-pending SHALL, in the same persisted change:
- set its absolute deadline to the earlier of its current absolute deadline and now plus the enrolment lifetime;
- set its idle deadline to no later than that absolute deadline;
- set the enrolment-origin marker, which records the absolute deadline the session held immediately before the mark.

No separate deadline SHALL be introduced for this state, so every store's loading, the concurrent-session count and the expiry sweep enforce it as they enforce any absolute deadline.

When a session carrying the enrolment-origin marker has its second factor satisfied, its absolute deadline SHALL be restored to the earlier of its creation time plus the absolute timeout and the deadline the marker recorded, and its idle deadline set to the earlier of now plus the idle timeout and that absolute deadline. The marker and the enrolment generation SHALL then be cleared. The restored absolute deadline SHALL never be later than creation time plus the absolute timeout, nor later than the deadline the session held before it was marked. A session already past its lowered deadline SHALL NOT be restored: the restore SHALL fail with the session-expired error and leave the session unchanged. Rotation SHALL then carry the restored deadlines over, as it carries every other field.

#### Scenario: Entered at login
- **WHEN** a session created at 09:00 with default timeouts is marked enrolment-pending at 09:00 with a 15-minute enrolment lifetime
- **THEN** its absolute deadline is 09:15 and its idle deadline is 09:15

#### Scenario: Entered mid-session near the end
- **WHEN** a session whose absolute deadline is 21:00 is marked enrolment-pending at 20:55 with a 15-minute enrolment lifetime
- **THEN** its absolute deadline stays 21:00

#### Scenario: Activity cannot extend the state
- **WHEN** an enrolment-only session marked at 09:00 with a 15-minute lifetime records activity at 09:14
- **THEN** its idle deadline is 09:15

#### Scenario: Restored on upgrade
- **WHEN** a session created at 09:00 with a 12-hour absolute timeout and a 30-minute idle timeout, marked enrolment-pending at 09:00, has its second factor satisfied at 09:09
- **THEN** its absolute deadline is 21:00 and its idle deadline is 09:39
- **AND** it no longer carries the enrolment-origin marker

#### Scenario: Restored mid-session deadline
- **WHEN** a session created at 08:00 with a 12-hour absolute timeout is marked enrolment-pending at 10:00 and has its second factor satisfied at 10:10
- **THEN** its absolute deadline is 20:00, the deadline it held before it was marked

#### Scenario: Restore never exceeds the deadline held before the mark
- **WHEN** a session created at 09:00 with a 12-hour absolute timeout, whose absolute deadline had been lowered to 10:00, is marked enrolment-pending at 09:30 and has its second factor satisfied at 09:35
- **THEN** its absolute deadline is 10:00

#### Scenario: An expired enrolment-only session is not revived
- **WHEN** a session marked enrolment-pending at 09:00 with a 15-minute lifetime has its deadlines restored at 09:20
- **THEN** the restore fails with the session-expired error
- **AND** the session's deadlines are unchanged

#### Scenario: Plain satisfaction is unchanged
- **WHEN** a session without the enrolment-origin marker, whose absolute deadline is 21:00, has its second factor satisfied
- **THEN** its absolute deadline stays 21:00

### Requirement: The recovery-pending state is confined like the enrolment-only state and keeps its recovery time
Marking a session recovery-pending SHALL, in the same persisted change:
- set its second-factor state to recovery-pending;
- record the recovery time;
- lower its absolute and idle deadlines and set the confinement marker exactly as marking it enrolment-pending does, using the recovery lifetime in place of the enrolment lifetime.

The deadlines SHALL be restored as the enrolment-only state's are, when the session leaves the state through a binding: when its second factor is satisfied at the MFA verify endpoint, or when a password change is resolved on it. A session past its lowered deadline SHALL NOT be restored. The recovery time SHALL be kept when the session leaves the state, and SHALL be carried over by rotation, as every other field is. Only the library SHALL write the recovery time.

#### Scenario: Entered at recovery
- **WHEN** a session is created at 09:00 with default timeouts and marked recovery-pending at 09:00 with a 15-minute recovery lifetime
- **THEN** its absolute deadline is 09:15, its idle deadline is 09:15, and its recovery time is 09:00

#### Scenario: Activity cannot extend the state
- **WHEN** a recovery-pending session marked at 09:00 with a 15-minute lifetime records activity at 09:14
- **THEN** its idle deadline is 09:15

#### Scenario: Restored by a password change
- **WHEN** a session created at 09:00 with a 12-hour absolute timeout, marked recovery-pending at 09:00, has a password change resolved at 09:05
- **THEN** its absolute deadline is 21:00, it no longer carries the confinement marker, and its recovery time is still 09:00

#### Scenario: Recovery time survives rotation
- **WHEN** a recovery-pending session with recovery time 09:00 enrols a second factor and is rotated at the verify endpoint
- **THEN** the rotated session reports the recovery time 09:00
