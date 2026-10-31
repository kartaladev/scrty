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
- an absolute deadline of creation time plus the absolute timeout, unless a lifetime was chosen for it at creation, in which case creation time plus that lifetime.

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
Recording activity on a valid session SHALL set its last-access time to now and its idle deadline to now plus the idle timeout, capped at the absolute deadline, and SHALL persist the change. Recording activity on an expired or unknown session SHALL fail with the expired or not-found error. When an activity interval is configured, recording activity SHALL persist nothing while less than that interval has passed since the session's last recorded access.

#### Scenario: Extension
- **WHEN** a session created at 09:00 with a 30-minute idle timeout records activity at 09:20
- **THEN** its idle deadline becomes 09:50

#### Scenario: Capped at the absolute deadline
- **WHEN** a session whose absolute deadline is 21:00 records activity at 20:50 with a 30-minute idle timeout
- **THEN** its idle deadline becomes 21:00

#### Scenario: Default writes on every activity
- **WHEN** a manager configured with no activity interval records activity on a session at 09:20 and again at 09:20:10
- **THEN** both are persisted, and the stored idle deadline is 09:50:10

#### Scenario: Consumer interval skips a recent write
- **WHEN** a manager configured with a 1-minute activity interval records activity at 09:20 on a session last accessed at 09:19:30
- **THEN** nothing is persisted, and the stored idle deadline stays 09:49:30

#### Scenario: Consumer interval writes once the interval has passed
- **WHEN** a manager configured with a 1-minute activity interval records activity at 09:20 on a session last accessed at 09:19
- **THEN** the last-access time 09:20 and the idle deadline 09:50 are persisted

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
- a marker that the second factor was met by the first factor itself, as a user-verified passkey login meets it;
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

#### Scenario: Consumer data cannot claim a passkey second factor
- **WHEN** a consumer stores the entry `{"mfa_at_first_factor": "true"}` in the consumer data of a session established by password
- **THEN** the session reports that its second factor was not met by the first factor

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
- delete every session of a user except one named session and, when that session belongs to a family, its family's current session, each pass deciding what it keeps and deletes atomically and the delete repeating until a pass removes nothing, returning how many were removed; a named session that belongs to another user, or does not exist, SHALL NOT stop the user's other sessions from being deleted and SHALL itself be left untouched; every other session of the named session's family, superseded ones included, SHALL be deleted;
- count a user's unexpired sessions, excluding expired ones;
- delete every expired session, returning how many were removed.

The user reference SHALL be matched exactly as the consumer supplied it.

#### Scenario: Delete per user
- **WHEN** user `u-1` has three sessions and user `u-2` has one, and the sessions of `u-1` are deleted
- **THEN** no session of `u-1` loads
- **AND** the session of `u-2` still loads

#### Scenario: Delete per user except one
- **WHEN** user `u-1` has sessions `s-1`, `s-2` and `s-3`, user `u-2` has one, and the sessions of `u-1` except `s-1` are deleted
- **THEN** 2 is returned, `s-1` still loads, `s-2` and `s-3` do not, and the session of `u-2` still loads

#### Scenario: The kept session is superseded inside its window
- **WHEN** `u-1`'s session O is renewed into S1 with a 30-second grace, `u-1` also holds an unrelated session T, and inside the window the sessions of `u-1` except O are deleted
- **THEN** O and S1 still load, and T does not

#### Scenario: The kept session is the current one
- **WHEN** `u-1`'s session O is renewed into S1 with a 30-second grace, and inside the window the sessions of `u-1` except S1 are deleted
- **THEN** S1 still loads, and O does not

#### Scenario: The kept session is another user's
- **WHEN** the sessions of `u-1` except `u-2`'s session are deleted
- **THEN** every session of `u-1` is deleted and `u-2`'s session still loads

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
- run housekeeping that deletes expired sessions once per interval while started, and stops at shutdown. Housekeeping SHALL carry the values of the context given to start, but SHALL NOT stop when that context is cancelled.

Housekeeping SHALL be paced by the store's time source, which defaults to the system clock and is replaceable by an option, so a controlled source runs housekeeping without real waiting. Each run SHALL start one interval after the previous run finishes. Starting a store whose housekeeping is running SHALL fail with an already-started error, and starting a store that has been shut down SHALL fail with an already-shut-down error. Shutdown SHALL be terminal and idempotent, SHALL wait for a run in progress to finish, but no longer than the context given to it allows, and SHALL return that context's error if it is done first. A later shutdown SHALL wait again under its own context. Shutdown SHALL end housekeeping only: a shut-down store SHALL keep saving, loading and deleting sessions. The housekeeping interval SHALL default to one minute and be replaceable by an option. Constructing the store with a housekeeping interval of zero or less, or with a nil time source, typed nil included, SHALL fail with a configuration error. Without starting, expired sessions SHALL still never be returned, but SHALL stay in memory until deleted, and this SHALL be documented. Any implementation of the store contract SHALL be usable in its place.

#### Scenario: Caller mutation is isolated
- **WHEN** a loaded session's consumer data is modified by the caller without saving
- **THEN** loading the session again returns the stored data unchanged

#### Scenario: Housekeeping while started
- **WHEN** the store is started with a 10-second housekeeping interval and a session expires
- **THEN** within one interval the expired session is no longer held

#### Scenario: Housekeeping on a controlled time source
- **WHEN** a store with a controlled time source and a 10-second housekeeping interval is started, a session expires, and the source advances by 10 seconds
- **THEN** the expired session is no longer held, with no real waiting

#### Scenario: Cancelled start context
- **WHEN** a store is started with a request context that is then cancelled, a session expires, and one housekeeping interval passes
- **THEN** the expired session is no longer held

#### Scenario: Double start and stop
- **WHEN** the store is started twice and shut down twice
- **THEN** the second start fails with the already-started error, both shutdowns return no error, and no housekeeping keeps running

#### Scenario: Start after shutdown
- **WHEN** the store is shut down and then started
- **THEN** start fails with the already-shut-down error and no housekeeping runs

#### Scenario: Store serves after shutdown
- **WHEN** a started store is shut down, and a session is then saved and loaded
- **THEN** the session is saved and loaded as before shutdown, and no housekeeping runs

#### Scenario: Invalid housekeeping configuration
- **WHEN** the store is constructed with a housekeeping interval of zero, or with a nil time source, typed nil included
- **THEN** construction fails with a configuration error and returns no store

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

When a session carrying the enrolment-origin marker has its second factor satisfied, its absolute deadline SHALL be restored to the deadline the marker recorded, and its idle deadline set to the earlier of now plus the idle timeout and that absolute deadline. The marker and the enrolment generation SHALL then be cleared. The restored absolute deadline SHALL never be later than the deadline the session held before it was marked, whatever lifetime the session was created or renewed with. A session already past its lowered deadline SHALL NOT be restored: the restore SHALL fail with the session-expired error and leave the session unchanged. Rotation SHALL then carry the restored deadlines over, as it carries every other field.

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

#### Scenario: A chosen lifetime survives the upgrade
- **WHEN** a session created at 09:00 with a chosen 30-day lifetime is marked enrolment-pending at 09:00 and has its second factor satisfied at 09:05
- **THEN** its absolute deadline is 09:00 thirty days after creation

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

### Requirement: A session whose second factor was met at login is created satisfied
The manager SHALL let a caller create a session whose second factor was met by the first factor. Such a session SHALL be created in the satisfied state, with its second-factor-satisfied time equal to its creation time and the met-by-first-factor marker set, all in the same store write that creates it. Rotating a session SHALL carry the marker over. A session created any other way SHALL report the marker unset, and the marker SHALL NOT be set by a later save.

#### Scenario: Created satisfied
- **WHEN** a session is created at 09:00 recording the `passkey` first factor with its second factor met at login, and then loaded
- **THEN** it reports the satisfied state, a satisfied time of 09:00 and the met-by-first-factor marker
- **AND** the store received exactly one write for the creation

#### Scenario: Rotation keeps the marker
- **WHEN** such a session is rotated
- **THEN** the rotated session still reports the marker and the satisfied time

#### Scenario: Verified second factor is not marked
- **WHEN** a password session's MFA challenge is resolved by the verify endpoint
- **THEN** it reports the satisfied state without the met-by-first-factor marker

### Requirement: Federated assurance is recorded in the creating write and kept apart from consumer data
The manager SHALL let a caller record, at creation, the `amr` values and `acr` a provider asserted, and SHALL persist them in the same store write that creates the session. They SHALL be held in fields only the library writes, SHALL be carried over when the session is rotated, and SHALL NOT be stored in, or read from, consumer data. Recording them SHALL NOT change the session's second-factor state or its met-by-first-factor marker. A session created without them SHALL report none.

#### Scenario: Recorded at creation
- **WHEN** a session is created recording the OIDC first factor, `amr` `["mfa"]` and `acr` `urn:corp:loa:2`, and is then loaded
- **THEN** the loaded session reports `amr` `["mfa"]` and `acr` `urn:corp:loa:2`
- **AND** its second-factor state is none and the met-by-first-factor marker is unset
- **AND** the store received exactly one write for the creation

#### Scenario: Rotation keeps the assurance
- **WHEN** such a session is rotated after resolving an MFA challenge
- **THEN** the rotated session still reports `amr` `["mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Consumer data cannot forge assurance
- **WHEN** a consumer stores the entry `{"amr": ["mfa"]}` in the consumer data of a session created without assurance
- **THEN** the session reports no `amr`

### Requirement: A session's absolute lifetime can be chosen at creation, up to a maximum
The manager SHALL let a caller choose, at creation, the absolute lifetime of one session. The lifetime SHALL be bounded by a lifetime maximum, which SHALL default to the absolute timeout and be replaceable by an option. Creating a session with a chosen lifetime that is zero, negative or above the maximum SHALL fail with a configuration error and store nothing; it SHALL NOT be shortened silently. Construction SHALL fail when the maximum is below the absolute timeout.

#### Scenario: Default maximum refuses a longer lifetime
- **WHEN** a manager with default options creates a session with a chosen 30-day lifetime
- **THEN** creation fails with a configuration error
- **AND** no session is stored

#### Scenario: Consumer maximum admits a remembered session
- **WHEN** a manager whose lifetime maximum is 30 days creates a session at 09:00 with a chosen 30-day lifetime
- **THEN** its absolute deadline is 09:00 thirty days later, and its idle deadline is no later than that

#### Scenario: Without a chosen lifetime the absolute timeout applies
- **WHEN** a manager whose lifetime maximum is 30 days creates a session at 09:00 without choosing a lifetime
- **THEN** its absolute deadline is 21:00

#### Scenario: Maximum below the absolute timeout
- **WHEN** a manager is constructed with a 12-hour absolute timeout and a 1-hour lifetime maximum
- **THEN** construction fails with a configuration error

### Requirement: An activity interval is bounded by the idle timeout
The activity interval SHALL default to zero, meaning every recorded activity is persisted. Construction SHALL fail with a configuration error when the interval is negative, or equal to or longer than the idle timeout. A persisted idle deadline SHALL never be later than the one a write on every activity would have produced.

#### Scenario: Interval as long as the idle timeout
- **WHEN** a manager is constructed with a 30-minute idle timeout and a 30-minute activity interval
- **THEN** construction fails with a configuration error

#### Scenario: A skipped write only brings expiry earlier
- **WHEN** a manager with a 30-minute idle timeout and a 1-minute activity interval records activity at 09:00 and 09:00:50, then none
- **THEN** the session expires at 09:30, not at 09:30:50

### Requirement: Recording activity changes only the activity fields
Persisting recorded activity SHALL write only the session's last-access time and idle deadline. It SHALL NOT change any other stored field, so a change another request saved to the same session in the meantime survives it. Recording activity on a superseded session SHALL persist nothing.

#### Scenario: A concurrent change survives an activity write
- **WHEN** request A loads a session, request B then marks the same session enrolment-pending, lowering its absolute deadline, and A then records activity
- **THEN** the stored session keeps B's lowered absolute deadline and enrolment-origin marker

#### Scenario: A superseded session is not extended
- **WHEN** a session superseded with a grace window ending at 09:01 records activity at 09:00:30
- **THEN** its stored deadlines are unchanged

### Requirement: Sessions belong to a family that rotation keeps
Every session SHALL belong to a family, identified by a library-generated, non-secret identifier, and SHALL record when the family was started. Creating a session SHALL start a new family at creation time. Every rotation, with or without a grace window and including rotation at second-factor verification, SHALL keep the family and its start time. The manager SHALL be able to revoke a family, deleting every session in it.

#### Scenario: A new sign-in starts a family
- **WHEN** two sessions are created for the same user
- **THEN** they belong to different families

#### Scenario: Rotation keeps the family
- **WHEN** a session is rotated, and its successor is rotated again
- **THEN** all three report the same family and family start time

#### Scenario: Revoking a family
- **WHEN** a family holding a superseded session and its live successor is revoked
- **THEN** loading either identifier returns the not-found error
- **AND** the user's sessions in other families are unaffected

### Requirement: Family identifiers come from a replaceable generator
By default a family identifier SHALL come from the library's time-ordered identifier generator on the manager's clock. A consumer MAY supply its own generator. Supplying a nil generator SHALL be a configuration error at construction.

#### Scenario: Consumer family identifier generator
- **WHEN** the manager is configured with a consumer generator, and a session is created
- **THEN** the session's family identifier is the one that generator returned

#### Scenario: Nil family identifier generator
- **WHEN** the manager is configured with a nil family identifier generator
- **THEN** construction fails with a configuration error

### Requirement: Rotation with a grace window keeps the old identifier usable until the window ends
The manager SHALL rotate a session with a grace window: it SHALL create a successor in the same family and mark the old session superseded, usable until the earlier of now plus the grace and its absolute deadline. Until then, loading the old identifier SHALL succeed. A grace that is negative or longer than 5 minutes SHALL be refused with a configuration error. Rotation without a grace window SHALL keep deleting the old identifier at once.

#### Scenario: Old identifier inside its window
- **WHEN** a session is rotated at 09:00 with a 30-second grace and its old identifier is loaded at 09:00:20
- **THEN** the load succeeds

#### Scenario: Window capped at the absolute deadline
- **WHEN** a session whose absolute deadline is 21:00 is rotated at 20:59:50 with a 30-second grace
- **THEN** the old identifier is usable only until 21:00

#### Scenario: Grace above the ceiling
- **WHEN** a session is rotated with a 10-minute grace
- **THEN** the rotation fails with a configuration error and nothing is stored

#### Scenario: Rotation without grace is unchanged
- **WHEN** a session is rotated without a grace window
- **THEN** loading the old identifier returns the not-found error

### Requirement: A superseded identifier inside its window is judged by its own deadlines
Inside its window, loading a superseded identifier SHALL succeed only while its own idle and absolute deadlines are unexpired; once either has passed, it SHALL fail with the session-expired error and SHALL NOT revoke the family.

#### Scenario: Idle deadline passed inside the window
- **WHEN** a session whose idle deadline is 09:00:10 is rotated at 09:00 with a 30-second grace, and its old identifier is loaded at 09:00:20
- **THEN** the load fails with the session-expired error, and the family is not revoked

### Requirement: Renewing a superseded identifier inside its window re-rotates
Rotating with a grace window an identifier that is already superseded and still inside its window SHALL issue a fresh successor in the same family, and SHALL supersede the previous successor with a window that has already ended. Any later presentation of that previous successor SHALL then be reuse. If the previous successor has itself been superseded, or is no longer stored, the re-rotation SHALL be reuse instead, so a family never holds two live heads.

#### Scenario: Lost response recovered inside the window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is rotated again at 09:00:10
- **THEN** a fresh successor S2 is returned
- **AND** loading S1 afterwards is treated as reuse

#### Scenario: Re-rotation after the successor was renewed
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, S1 is rotated into T at 09:00:05, and O is rotated again at 09:00:10
- **THEN** the rotation fails with the reused-session error and the family is revoked

### Requirement: A superseded identifier presented after its window revokes its family
Loading a superseded identifier at or after the end of its window SHALL be treated as reuse: the manager SHALL revoke the identifier's whole family and SHALL fail with a reused-session error that also matches the expired-session error. Superseded sessions SHALL be kept until their family's absolute deadline, so a late presentation is detected rather than reported as not found, whether or not the superseded session's own deadlines have passed.

#### Scenario: Reuse after the window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is loaded at 09:05
- **THEN** the load fails with the reused-session error, which also matches the expired-session error
- **AND** loading S1 afterwards returns the not-found error

#### Scenario: Detected long after the window
- **WHEN** a session with an absolute deadline of 21:00 is rotated at 09:00 with a 30-second grace, and its old identifier is presented at 18:00
- **THEN** the load fails with the reused-session error

#### Scenario: Detected after the session's own deadline
- **WHEN** a session with an absolute deadline of 10:00 under a family maximum ending at 21:00 is rotated at 09:00 with a 30-second grace, and its old identifier is presented at 12:00
- **THEN** the load fails with the reused-session error and the family is revoked

### Requirement: Reuse revocation completes when the presenting request is cancelled
The family revocation that detected reuse triggers SHALL complete even when the request that presented the identifier is cancelled.

#### Scenario: Presenting request cancelled
- **WHEN** a superseded identifier is presented after its window by a request that is cancelled once its session has been read
- **THEN** the family is revoked

### Requirement: Recovery while the successor is unused is opt-in
The manager SHALL record when a session is first loaded successfully. By default a superseded identifier presented after its window SHALL be reuse. With unused-successor recovery enabled, renewing such an identifier SHALL rotate it again as inside the window when its current successor has never been loaded and has not been superseded, decided atomically by the store; otherwise the renewal SHALL be reuse.

#### Scenario: Default treats a late retry as reuse
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, S1 is never presented, and O is rotated again the next day
- **THEN** the rotation fails with the reused-session error and the family is revoked

#### Scenario: Consumer recovery re-rotates an unused successor
- **WHEN** a manager with unused-successor recovery enabled, whose idle and absolute timeouts both outlast the next day, rotates O at 09:00 with a 30-second grace into S1, S1 is never presented, and O is renewed the next day
- **THEN** a fresh successor S2 is returned
- **AND** loading S1 afterwards is treated as reuse

#### Scenario: Recovery refuses once the successor was used
- **WHEN** a manager with unused-successor recovery enabled rotates O into S1, S1 is loaded, and O is renewed after its window
- **THEN** the renewal fails with the reused-session error and the family is revoked

### Requirement: Recovery never revives a session that has ended
With unused-successor recovery enabled, renewing a superseded identifier that still names a successor and whose own idle or absolute deadline has passed SHALL issue no successor. When its current successor is stored and has been presented or superseded, as the store reports, the renewal SHALL be reuse and SHALL revoke the family; otherwise it SHALL fail with the session-expired error and SHALL NOT revoke the family.

#### Scenario: Recovery refuses a session past its absolute deadline
- **WHEN** a manager with unused-successor recovery enabled rotates at 09:00, with a 30-second grace, a session O whose absolute deadline is 11:00, S1 is never presented, and O is renewed at 12:00
- **THEN** the renewal fails with the session-expired error
- **AND** the family is not revoked, and no successor is issued

#### Scenario: Recovery refuses a session past its idle deadline
- **WHEN** a manager with unused-successor recovery enabled and a 30-minute idle timeout rotates O at 09:00, with a 30-second grace, into S1, S1 is never presented, and O is renewed at 10:00
- **THEN** the renewal fails with the session-expired error, and no successor is issued

#### Scenario: An ended session whose successor was used is reuse
- **WHEN** a manager with unused-successor recovery enabled and a 30-minute idle timeout rotates O, last active at 09:00, at 09:10 with a 30-second grace into S1, S1 is loaded at 09:20, and O is renewed at 09:31
- **THEN** the renewal fails with the reused-session error, no successor is issued, and the family is revoked

#### Scenario: A knocked-out identifier is reuse whatever its own deadlines
- **WHEN** a manager with unused-successor recovery enabled rotates O into S1, O is renewed again inside its window into S2, and S1 is renewed after its own idle deadline
- **THEN** the renewal fails with the reused-session error, and the family is revoked

#### Scenario: An ended session whose unused successor is gone is expired
- **WHEN** a manager with unused-successor recovery enabled rotates O into S1, S1 is never presented and is no longer stored, and O is renewed after its window and after its own idle deadline
- **THEN** the renewal fails with the session-expired error, and nothing is revoked

### Requirement: Under recovery an ordinary late request is refused without revoking
With unused-successor recovery enabled, loading a superseded identifier after its window for anything but a renewal SHALL fail with a renewal-required error that matches the expired-session error, and SHALL NOT revoke the family.

#### Scenario: Consumer recovery refuses an ordinary late request without revoking
- **WHEN** a manager with unused-successor recovery enabled rotates O at 09:00 with a 30-second grace into S1, and O is loaded the next day
- **THEN** the load fails with the renewal-required error, which matches the expired-session error
- **AND** S1 still loads

### Requirement: A session records when the user last authenticated
Every session SHALL record the time the user last authenticated: the sign-in time at creation, refreshed when a second factor is satisfied. A renewal SHALL carry it over unchanged, because a renewal is not an authentication. A session's creation time SHALL be when that record was written.

#### Scenario: Renewal keeps the authentication time
- **WHEN** a session created at 09:00 is renewed at 15:00
- **THEN** the successor reports 09:00 as its authentication time and 15:00 as its creation time

#### Scenario: A second factor refreshes the authentication time
- **WHEN** a session signed in at 09:00 satisfies a second factor at 09:20
- **THEN** it reports 09:20 as its authentication time

### Requirement: Rotation at second-factor verification keeps the old identifier only in flight
Rotating without a grace window SHALL supersede the old session with a short in-flight window and then delete it. A load of the old identifier between the two writes SHALL return the old session as it was, its own deadlines included, and SHALL NOT be judged as reuse.

#### Scenario: Load between the writes
- **WHEN** a load of the old identifier runs after the strict rotation has superseded it and before it is deleted
- **THEN** the load returns the old session, and the family is not revoked

#### Scenario: Its own deadlines between the writes
- **WHEN** a session with an idle deadline of 09:30 and an absolute deadline of 10:00, in a family whose maximum ends at 21:00, is rotated without grace at 09:00, and its old identifier is loaded between the two writes
- **THEN** the loaded session reports 09:30 and 10:00 as its deadlines

### Requirement: A failed delete does not fail a second-factor rotation
When the delete after a rotation without a grace window fails, the rotation SHALL still return the successor, and the old identifier SHALL expire as a superseded session when its in-flight window ends.

#### Scenario: Delete fails
- **WHEN** the delete after a strict rotation fails
- **THEN** the rotation returns the successor, and the old identifier loads until its in-flight window ends

### Requirement: Rotation at second-factor verification refuses a superseded session
Rotating without a grace window a session that is superseded and still inside its window SHALL fail with the renewal-conflict error and SHALL write nothing, so the client retries with its current credential and the family keeps one live head. Past its window it SHALL be answered as loading it would be.

#### Scenario: Superseded session inside its window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is rotated without grace at 09:00:10
- **THEN** the rotation fails with the renewal-conflict error
- **AND** S1 still loads

### Requirement: Renewal carries the absolute deadline over unless a new lifetime is chosen, under a family maximum
By default a successor SHALL keep its predecessor's absolute deadline. A caller MAY choose a new lifetime when rotating with a grace window; the successor's absolute deadline SHALL then be now plus that lifetime, bounded by the family maximum. A lifetime above the lifetime maximum SHALL fail with a configuration error and store nothing.

#### Scenario: Default carries over
- **WHEN** a session whose absolute deadline is 21:00 is rotated with a grace window at 15:00
- **THEN** the successor's absolute deadline is 21:00

#### Scenario: Re-rotation carries over the session's own deadline
- **WHEN** a session created at 09:00 with a 1-hour lifetime, under a 30-day lifetime maximum, is rotated with a 30-second grace at 09:10, and its old identifier is rotated again at 09:10:10
- **THEN** the second successor's absolute deadline is 10:00

#### Scenario: Re-rotation keeps an enrolment confinement
- **WHEN** a session confined to enrolment until 09:15 is rotated with a grace window at 09:05, and its old identifier is rotated again inside the window
- **THEN** the second successor's absolute deadline is 09:15

#### Scenario: Consumer lifetime extends within the family maximum
- **WHEN** a manager with a 30-day lifetime maximum and a 90-day family maximum rotates, on day 20 of a family, a session with a chosen 30-day lifetime
- **THEN** the successor's absolute deadline is now plus 30 days

#### Scenario: Lifetime above the lifetime maximum
- **WHEN** a manager with a 30-day lifetime maximum rotates a session with a chosen 45-day lifetime
- **THEN** the rotation fails with a configuration error and nothing is stored

#### Scenario: Rotation at second-factor verification never extends
- **WHEN** a session whose absolute deadline is 21:00 is rotated at second-factor verification
- **THEN** the successor's absolute deadline is 21:00

### Requirement: The family maximum bounds every renewal
A renewed successor's absolute deadline SHALL never be later than its family start plus the family maximum; a deadline that would pass it SHALL be cut to end exactly there. The family maximum SHALL default to the lifetime maximum and SHALL be finite. Construction SHALL fail when it is below the lifetime maximum.

#### Scenario: Family maximum is the overall limit
- **WHEN** the same manager rotates, on day 80 of the family, a session with a chosen 30-day lifetime
- **THEN** the successor's absolute deadline is the family start plus 90 days

#### Scenario: Default family maximum allows no extension
- **WHEN** a manager with a 12-hour lifetime maximum and no family maximum renews, at 15:00, a session created at 09:00 with a chosen 12-hour lifetime
- **THEN** the successor's absolute deadline is 21:00

#### Scenario: Family maximum below the lifetime maximum
- **WHEN** a manager is constructed with a 30-day lifetime maximum and a 7-day family maximum
- **THEN** construction fails with a configuration error

### Requirement: Concurrent renewals of one identifier produce one successor
When two callers rotate the same identifier with a grace window at the same time, through one manager or through managers sharing one store, exactly one rotation SHALL succeed. The other SHALL fail with a renewal-conflict error and SHALL store nothing.

#### Scenario: Two replicas renew at once
- **WHEN** two managers sharing one store rotate the same identifier concurrently
- **THEN** one returns a successor and the other fails with the renewal-conflict error
- **AND** the family holds exactly one live successor

### Requirement: Detected reuse is reported to an optional observer
The manager SHALL accept an optional reuse observer. On detected reuse it SHALL call the observer synchronously, after the family is revoked, with the caller's context and a report of the user reference, the family identifier, when the presented identifier was superseded and the detection time. The report SHALL NOT carry any session identifier. A nil observer SHALL fail construction. Without an observer, reuse SHALL still be refused and revoked.

#### Scenario: Default without an observer
- **WHEN** reuse is detected by a manager with no observer
- **THEN** the family is revoked and the reused-session error is returned

#### Scenario: Consumer observer receives the report
- **WHEN** reuse is detected by a manager with an observer
- **THEN** the observer is called once, after the revocation, with the user reference and family identifier and no session identifier

#### Scenario: Nil observer
- **WHEN** a manager is constructed with a nil reuse observer
- **THEN** construction fails with a configuration error

### Requirement: A store result with no session is a missing session
When the session store returns no session and no error, every manager operation that loads a session SHALL treat it as a missing session, and SHALL NOT panic.

#### Scenario: Store returns nothing
- **WHEN** a session is loaded and the store returns no session and no error
- **THEN** the load fails with the session-not-found error

### Requirement: A session whose first use could not be recorded cannot later be recovered as unused
With unused-successor recovery enabled, when recording a session's first successful load fails, that load SHALL fail, so that a successor that was in fact used is never later judged unused. With recovery disabled, a failure to record first use SHALL NOT fail the load.

#### Scenario: First-use write fails with recovery enabled
- **WHEN** unused-successor recovery is enabled, successor S1 is loaded, and recording its first use fails
- **THEN** the load fails and S1 is not served with its first use unrecorded, and while S1 stays unpresented a later late renewal of its predecessor recovers S1 rather than being judged reuse

#### Scenario: First-use write fails with recovery disabled
- **WHEN** unused-successor recovery is disabled, a session is loaded, and recording its first use fails
- **THEN** the load succeeds
