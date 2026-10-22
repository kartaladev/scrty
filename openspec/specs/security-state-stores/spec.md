# security-state-stores Specification

## Purpose

Keeps scrty's security state (sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, flows and handoffs) in PostgreSQL. The three supported database access backends behave identically, stay correct under concurrency and across replicas, and join the caller's transactions.

## Requirements

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

### Requirement: Single-use consumption is atomic
Consuming a one-time token or an OIDC handoff SHALL be decided by a single conditional write on "not yet consumed". At most one consumption of a record SHALL ever succeed, however many callers race. An unknown record and an already-consumed record SHALL be refused with the same outcome. A refused consumption SHALL change nothing, and the time of the first successful consumption SHALL be kept.

#### Scenario: Concurrent consumers
- **WHEN** 8 callers try to consume the same unconsumed one-time token at the same time
- **THEN** exactly one consumption succeeds
- **AND** the other 7 are refused with the same outcome as for an unknown token

#### Scenario: Sequential second consumption
- **WHEN** a handoff is consumed at time T1 and consumed again at time T2
- **THEN** the second consumption is refused
- **AND** the stored consumption time remains T1

### Requirement: Flow completion checks its bindings within the consuming write
Completing an OIDC flow SHALL succeed at most once. The flow's provider, its state, its expiry and "not yet completed" SHALL all be evaluated within the same write. A completion whose provider or state does not match, whose state is empty, or whose flow has expired SHALL be refused with the same outcome as an unknown handle, and SHALL leave the flow exactly as it was.

#### Scenario: Wrong state does not burn a flow
- **WHEN** a flow begun with state `s1` is completed with state `attacker`
- **THEN** the completion is refused
- **AND** a later completion with state `s1` succeeds

#### Scenario: Wrong provider does not burn a flow
- **WHEN** a flow begun for provider `p1` is completed at provider `p2` with its correct state
- **THEN** the completion is refused
- **AND** a later completion at `p1` succeeds

#### Scenario: Expired flow
- **WHEN** a flow is completed after its expiry with its correct provider and state
- **THEN** the completion is refused with the same outcome as an unknown handle

#### Scenario: Concurrent completions
- **WHEN** 8 callers complete the same flow with its correct provider and state at the same time
- **THEN** exactly one completion succeeds

### Requirement: External identity link uniqueness is enforced by the write
Inserting an external identity link SHALL be refused with the "already exists" outcome when a link for the same provider, issuer and subject exists, including when the new link is identical. The stored link SHALL be left unchanged. Concurrent inserts for the same provider, issuer and subject SHALL result in exactly one stored link. The refusal SHALL never surface as a raw database error, and SHALL NOT contain the submitted values.

#### Scenario: Concurrent duplicate link
- **WHEN** two callers insert links for the same provider, issuer and subject, for different users, at the same time
- **THEN** exactly one insert succeeds
- **AND** the other is refused with the "already exists" outcome

#### Scenario: Refused insert does not overwrite
- **WHEN** a link exists for user `u1` and an insert for the same provider, issuer and subject names user `u2`
- **THEN** the insert is refused
- **AND** looking the link up returns user `u1`

#### Scenario: Error text carries no submitted values
- **WHEN** a link insert is refused because the link already exists
- **THEN** the error text contains neither the subject nor the user reference

### Requirement: Links can be deleted by user reference
Deleting external identity links by user reference SHALL remove every link belonging to that user reference, SHALL leave other users' links untouched, and SHALL return the number of links removed. An empty user reference SHALL delete nothing.

#### Scenario: All of one user's links removed
- **WHEN** user `u1` has links at two providers and user `u2` has one link, and links are deleted for `u1`
- **THEN** the deletion reports 2
- **AND** `u2`'s link still resolves

#### Scenario: Empty user reference
- **WHEN** links are deleted for user reference `""`
- **THEN** the deletion reports 0 and no link is removed

### Requirement: MFA enrolment confirmation is recorded once
An MFA enrolment SHALL start unconfirmed. Confirming it SHALL record the confirmation time and the confirming time step only if the enrolment is still unconfirmed, and SHALL report whether this call confirmed it. Confirming SHALL clear any emailed enrolment code outstanding on the enrolment, and SHALL NOT lower the recorded time step: where a device proof already recorded a later step, that step SHALL be kept. Storing a new pending enrolment SHALL replace an unconfirmed enrolment's secret, clear its accepted time step, start a new enrolment generation, and clear its device proof, its emailed code, that code's expiry and its attempt count. It SHALL be refused with the already-enrolled outcome when the user's enrolment is confirmed, leaving that enrolment unchanged. The check and the write SHALL be a single conditional write.

#### Scenario: First confirmation
- **WHEN** a new enrolment is confirmed at time T
- **THEN** the confirmation succeeds and the enrolment reads as confirmed at T

#### Scenario: Second confirmation
- **WHEN** a confirmed enrolment is confirmed again at time T2
- **THEN** the second confirmation is refused
- **AND** the recorded confirmation time is unchanged

#### Scenario: Pending enrolment replaced
- **WHEN** an unconfirmed enrolment exists and a new pending enrolment with a new secret is stored for the same user
- **THEN** the enrolment reads as unconfirmed with the new secret and no accepted time step

#### Scenario: Confirmed enrolment not replaced
- **WHEN** a confirmed enrolment exists and a new pending enrolment is stored for the same user
- **THEN** the store refuses it with the already-enrolled outcome
- **AND** the enrolment still reads as confirmed with its original secret

#### Scenario: A new pending enrolment starts a new generation
- **WHEN** a pending enrolment on generation G1 has its device proven with an emailed code, and a new pending enrolment on generation G2 is stored for the same user
- **THEN** the enrolment reads with generation G2, no device-proof time, no emailed code, no code expiry and no charged attempts

#### Scenario: Confirmation keeps a later device-proof step
- **WHEN** a pending enrolment's device is proven at step 1001 and the enrolment is then confirmed with step 1000
- **THEN** the confirmation succeeds and the recorded step is 1001
- **AND** the enrolment reads with no emailed code

### Requirement: A TOTP time step is accepted at most once, in increasing order
Recording an accepted TOTP time step for an enrolment SHALL succeed only when the enrolment is confirmed and the step is greater than the last accepted step. The check and the update SHALL be a single conditional write. Concurrent attempts to record the same step SHALL result in exactly one success. A refused attempt SHALL leave the last accepted step unchanged.

#### Scenario: Replayed step
- **WHEN** step 1000 is accepted and step 1000 is recorded again
- **THEN** the second attempt is refused

#### Scenario: Older step after a newer one
- **WHEN** step 1001 is accepted and step 1000 is then recorded
- **THEN** the attempt is refused and the last accepted step remains 1001

#### Scenario: Unconfirmed enrolment
- **WHEN** a step is recorded for an enrolment that has not been confirmed
- **THEN** the attempt is refused

#### Scenario: Concurrent verifications of one step
- **WHEN** 8 callers record step 1002 for the same enrolment at the same time
- **THEN** exactly one succeeds

### Requirement: User references are opaque and need no identity tables
Durable stores SHALL store user references as text, and SHALL return them byte for byte as supplied, without parsing, trimming, case-folding or validating them as identifiers. Durable stores SHALL NOT require any identity table to exist, SHALL NOT declare foreign keys to identity tables, and SHALL NOT join with them.

#### Scenario: Non-UUID user reference
- **WHEN** a session is saved for user reference `Alice@Example.COM ` (with trailing space) and loaded again
- **THEN** the loaded session's user reference is exactly `Alice@Example.COM `

#### Scenario: Consumer-owned identity
- **WHEN** only the security-state migrations have been applied to a database, and no users table exists
- **THEN** every durable store can create, read and delete its records

### Requirement: Consumer-owned session data is returned unchanged
Data a consumer attaches to a session SHALL be stored and returned with the same keys and values. The store SHALL NOT interpret, add or remove consumer keys.

#### Scenario: Session data round trip
- **WHEN** a session is saved with data `{"tenant": "t-9", "flags": "a,b", "": "empty key"}` and loaded
- **THEN** the loaded data equals `{"tenant": "t-9", "flags": "a,b", "": "empty key"}`

### Requirement: Session identifiers are never stored
Durable session stores SHALL NOT store a session's identifier. They SHALL store a one-way digest of it, and SHALL find, save and delete a session by the digest of the identifier they are given. A generated identifier SHALL be the table's primary key. Creating a session whose identifier's digest is already stored SHALL be refused, and SHALL leave the stored session unchanged.

#### Scenario: Identifier absent from the table
- **WHEN** a session with identifier `SESSION-SENTINEL` is created and every column of its row is read out of band
- **THEN** no column's value equals or contains `SESSION-SENTINEL`
- **AND** loading the session by `SESSION-SENTINEL` returns it

#### Scenario: Duplicate identifier
- **WHEN** a session is created with an identifier already in use
- **THEN** creation returns an error
- **AND** the existing session loads unchanged

#### Scenario: Save never re-creates a deleted session
- **WHEN** a session is loaded, then deleted, and the loaded copy is saved
- **THEN** saving returns the session-not-found error
- **AND** loading the session afterwards returns the session-not-found error

### Requirement: Empty federation values never match
Deleting sessions by external issuer and external session id, or by user and external issuer, SHALL return the number of sessions deleted, and SHALL delete nothing when a required issuer or session id argument is empty. It SHALL NOT match sessions whose federation values are empty. Matching by external session id SHALL always also require the issuer to match.

#### Scenario: Empty issuer deletes nothing
- **WHEN** unfederated sessions exist and sessions are deleted by external issuer `""` and external session id `sid-1`
- **THEN** no session is deleted

#### Scenario: Empty external session id deletes nothing
- **WHEN** a federated session exists for issuer `https://idp.example` whose provider issued no session id, and sessions are deleted by issuer `https://idp.example` and external session id `""`
- **THEN** no session is deleted

#### Scenario: Issuer participates in the match
- **WHEN** sessions exist from issuers A and B with the same external session id, and sessions are deleted by issuer A and that session id
- **THEN** only the session from issuer A is deleted

#### Scenario: Delete by user and issuer reports a count
- **WHEN** user `u1` has two sessions from issuer A and one from issuer B, and sessions are deleted for `u1` and issuer A
- **THEN** the deletion reports 2
- **AND** the session from issuer B remains

### Requirement: Library-owned records carry generated identifiers in native uuid columns
Durable stores SHALL identify each library-owned record by an identifier obtained from the store's configured generator, and SHALL store it in a native PostgreSQL uuid column. When no generator is configured, the default generator SHALL be used. A consumer-supplied generator's identifiers SHALL be stored exactly as returned. A generator error SHALL prevent the record from being created.

#### Scenario: Default generator
- **WHEN** a login attempt is recorded through a store with no generator configured
- **THEN** the stored row's primary key is a version 7 UUID in a uuid column

#### Scenario: Consumer generator
- **WHEN** a store is configured with a generator returning `00000000-0000-4000-8000-000000000001` and a login attempt is recorded
- **THEN** the stored attempt's primary key is `00000000-0000-4000-8000-000000000001`

#### Scenario: Generator failure
- **WHEN** the configured generator returns an error while a login attempt is being recorded
- **THEN** recording returns an error wrapping the generator's error
- **AND** no row is written

### Requirement: Session expiry uses the configured clock
Durable session stores SHALL decide expiry and count active sessions using the store's configured clock. When none is configured, the system clock SHALL be used. Stored times SHALL round-trip at microsecond precision.

#### Scenario: Consumer clock drives expiry
- **WHEN** a session store's clock reads 12:00 and a session whose idle expiry is 12:05 is loaded
- **THEN** the session loads
- **AND** the same load through a store whose clock reads 12:06 is refused as expired

#### Scenario: Microsecond round trip
- **WHEN** a token created at `2026-09-15T10:00:00.123456789Z` is stored and read back
- **THEN** its creation time equals `2026-09-15T10:00:00.123456Z`

### Requirement: Stores join a transaction the caller attached
When a caller attaches its own transaction to the operation context through a backend's attach function, every store of that backend SHALL perform the operation inside that transaction. When no transaction is attached, the store SHALL use the database handle it was constructed with. The store SHALL NOT commit or roll back a transaction it did not open.

The shared PostgreSQL rate limiter is not a store under this requirement: it SHALL ignore an attached transaction, as `rate-limiting` requires.

#### Scenario: Rolled back with the caller
- **WHEN** a caller begins a transaction, attaches it, saves a session through a durable store, and rolls back
- **THEN** the session does not exist afterwards

#### Scenario: Committed with the caller
- **WHEN** a caller begins a transaction, attaches it, records a login attempt and consumes a one-time token, and commits
- **THEN** both the attempt and the consumption are visible afterwards

#### Scenario: No attached transaction
- **WHEN** a session is saved with no transaction attached
- **THEN** the session is visible to other connections immediately after the save returns

#### Scenario: The rate limiter stays outside the caller's transaction
- **WHEN** a caller attaches a transaction, records a failure through a PostgreSQL rate limiter and saves a session through a durable store, and rolls back
- **THEN** the session does not exist afterwards
- **AND** the recorded failure still counts

### Requirement: A consumer transaction manager can supply the transaction
Each backend's stores SHALL accept a transaction resolver. When one is configured, the store SHALL ask the resolver for the current transaction instead of reading its own attachment, SHALL use the resolved transaction when the resolver reports one, and SHALL use its constructed handle otherwise.

#### Scenario: Resolver supplies the transaction
- **WHEN** a store is configured with a resolver that returns the consumer's transaction manager's current transaction, and an API key is inserted inside that manager's unit of work, which then rolls back
- **THEN** the API key does not exist afterwards

#### Scenario: Resolver reports no transaction
- **WHEN** a configured resolver reports no current transaction and an API key is inserted
- **THEN** the insert runs on the store's constructed handle and is visible immediately

### Requirement: Refusals and contained failures leave the caller's transaction usable
A refusal (already consumed, already exists, not found, bindings not met) inside a caller's transaction SHALL NOT make that transaction unusable. A store operation that performs more than one statement SHALL, on failure inside a caller's transaction, undo only its own statements and leave the transaction usable. Where a single statement fails for an unexpected database reason inside a caller's transaction, the transaction SHALL follow PostgreSQL's aborted-transaction semantics, and this limit SHALL be documented.

#### Scenario: Refusal then commit
- **WHEN** a caller in one transaction saves session S, attempts to consume an already-consumed token (refused), saves session T, and commits
- **THEN** the commit succeeds
- **AND** sessions S and T both exist

### Requirement: No transaction spans backends
A transaction attached through one backend SHALL be ignored by the stores of every other backend.

#### Scenario: Transaction attached for another backend
- **WHEN** a caller attaches a transaction through one backend and saves a session through a store of a different backend, then rolls the transaction back
- **THEN** the session saved through the other backend still exists

### Requirement: Wiring mistakes fail at construction
Constructing a durable store SHALL fail with a configuration error, before any database access, when the database handle is missing, when the database handle already reports a failure, or when an option is given a nil value.

#### Scenario: Missing handle
- **WHEN** a durable store is constructed with a nil database handle
- **THEN** construction returns a configuration error and no store

#### Scenario: Nil option value
- **WHEN** a durable store is constructed with a nil transaction resolver
- **THEN** construction returns a configuration error and no store

#### Scenario: A handle that already reports a failure
- **WHEN** a durable store is constructed with a database handle that already reports a failure
- **THEN** construction returns a configuration error that wraps that failure, and no store

### Requirement: Database failures are errors, never refusals or absence
When the database cannot answer a store operation, the store SHALL return an error that wraps the database error. It SHALL NOT report the failure as "not found", "not enrolled", "already consumed" or any other refusal or absence.

#### Scenario: Lookup fails
- **WHEN** reading an MFA enrolment fails because the database connection is lost
- **THEN** the read returns an error
- **AND** the read does not report that the user has no enrolment

#### Scenario: Consumption fails
- **WHEN** consuming a one-time token fails because the database is unavailable
- **THEN** the consumption returns an error that is not the "unknown or consumed" refusal

#### Scenario: The caller's transaction handle already carries a failure
- **WHEN** a store operation runs on a caller's transaction handle that already reports a failure, such as a transaction whose begin failed
- **THEN** the operation returns an error that wraps that failure
- **AND** it runs no statement, does not panic, and reports no refusal or absence

### Requirement: Enrolment device proof, completion and emailed-code attempts are decided by the write
Every durable MFA enrolment store SHALL implement the enrolment path's device-proof operations. Each operation SHALL be a single conditional write whose conditions are all checked by that write, SHALL report whether it changed the enrolment, and SHALL change nothing when it reports no change:
- **device proof** SHALL record the time step, the device-proof time, the emailed code and its expiry only where the user's enrolment is pending on the given generation, its device is not yet proven, and the step is later than the recorded step;
- **completion** SHALL mark the enrolment confirmed and clear its emailed code only where the enrolment is on the given generation, its device is proven and it is not yet confirmed;
- **charging an emailed-code attempt** SHALL increment the attempt count and report the count after the write only where the enrolment is pending on the given generation, its device is proven, its emailed code is outstanding and unexpired at the given time, and fewer than five attempts have been charged. A code is expired from its expiry instant onward: a charge at exactly that instant is refused.

An absent generation SHALL match no enrolment. Within one generation, the code's expiry SHALL be cleared only by storing a new pending enrolment, and the emailed code only by completion, confirmation or a new pending enrolment; neither SHALL be cleared when the code expires or runs out of attempts. Of any number of concurrent completions of one generation, exactly one SHALL succeed, and of any number of concurrent charges against one code, at most five SHALL succeed.

#### Scenario: Device proof on a stale generation
- **WHEN** a pending enrolment is on generation G2 and a device proof names generation G1
- **THEN** the proof is refused and the enrolment reads with no device-proof time

#### Scenario: Device proven twice
- **WHEN** a pending enrolment's device is proven at step 1000 and a second proof on the same generation names step 1001
- **THEN** the second proof is refused and the recorded step remains 1000

#### Scenario: A newer begin invalidates an earlier proof
- **WHEN** a device is proven on generation G1, a new pending enrolment on generation G2 is stored for the same user, and completion then names G1
- **THEN** the completion is refused
- **AND** the enrolment reads as unconfirmed

#### Scenario: Completion before device proof
- **WHEN** a pending enrolment on generation G1 whose device is not proven is completed on G1
- **THEN** the completion is refused and the enrolment reads as unconfirmed

#### Scenario: Concurrent completions of one generation
- **WHEN** 8 callers complete the same proven enrolment on its generation at the same time
- **THEN** exactly one succeeds

#### Scenario: Concurrent charges against one code
- **WHEN** 20 callers charge an attempt against the same outstanding emailed code at the same time
- **THEN** exactly five succeed
- **AND** the enrolment reads with five charged attempts and its emailed code still stored

#### Scenario: Expired code is not charged
- **WHEN** an emailed code whose expiry is 10:10 is charged at 10:11
- **THEN** the charge is refused and the attempt count is unchanged
- **AND** the enrolment still reads with its emailed code and its expiry

#### Scenario: Code charged at its expiry instant
- **WHEN** an emailed code whose expiry is 10:10 is charged at exactly 10:10
- **THEN** the charge is refused and the attempt count is unchanged

### Requirement: Enrolment-path session state survives a durable store
Durable session stores SHALL store and return unchanged a session's enrolment-pending and recovery-pending second-factor states, its confinement marker, its enrolment generation and its recovery time. The stored second-factor state SHALL keep the ordinal of every existing state, so a state stored before the enrolment-pending state was added reads back as the same state. A session without the marker SHALL read back with no marker and no generation, and a session never produced by a recovery SHALL read back with no recovery time.

#### Scenario: Enrolment-only session round trip
- **WHEN** a session in the enrolment-pending state, with enrolment-origin marker 21:00 and enrolment generation G1, is saved and loaded
- **THEN** it loads in the enrolment-pending state with marker 21:00 and generation G1

#### Scenario: Backends share the enrolment fields
- **WHEN** such a session is saved through the store of one supported backend
- **THEN** a store of a different supported backend, connected to the same database, loads it with the same state, marker and generation

#### Scenario: Unmarked session
- **WHEN** a session that was never marked enrolment-pending is saved and loaded
- **THEN** it loads with no enrolment-origin marker and no enrolment generation

#### Scenario: Marker cleared on upgrade
- **WHEN** an enrolment-only session is restored to a full session, saved and loaded
- **THEN** it loads with no enrolment-origin marker and no enrolment generation

#### Scenario: Recovery-pending session round trip
- **WHEN** a session in the recovery-pending state, with confinement marker 21:00 and recovery time 09:00, is saved through the store of one supported backend and loaded through another
- **THEN** it loads in the recovery-pending state with marker 21:00 and recovery time 09:00

### Requirement: Saved recovery codes are replaced as a set and spent by the write
A saved-recovery-code store SHALL keep, per user reference, the SHA-256 hashes of the user's codes, each with its creation time and, once spent, its spending time. It SHALL:
- **replace a user's set** in one operation that removes every code of the user and stores the new hashes, so a reader never sees a mix of the two sets, and a failure leaves the previous set whole. Replacements of one user's set that overlap in time SHALL take effect one after the other, so exactly one of the new sets remains. Inside a caller's transaction, a failure SHALL undo only this operation's own statements;
- **report whether an unspent code matches** a user and a hash, writing nothing;
- **spend a code** by one conditional write on "not yet spent", reporting whether this call spent it. A refused spend SHALL change nothing, and the first spending time SHALL be kept;
- **count a user's unspent codes**;
- **delete every code of a user**, returning how many were removed.

A hash SHALL match only within its own user's set. An unknown code and a spent code SHALL be refused with the same outcome. The in-memory store SHALL be the default, SHALL hold its own copies of hashes, and any implementation of the contract SHALL be usable in its place.

#### Scenario: Concurrent spends
- **WHEN** 8 callers spend the same unspent code at the same time
- **THEN** exactly one spend succeeds, and the other 7 are refused with the same outcome as for an unknown code

#### Scenario: Another user's hash
- **WHEN** user `u-1` holds a code whose hash is H, and a spend names user `u-2` and hash H
- **THEN** the spend is refused and `u-1`'s code stays unspent

#### Scenario: Replacement is whole
- **WHEN** a user holding 10 codes, 3 of them spent, has their set replaced by 10 new hashes
- **THEN** the user's unspent count is 10 and no old hash matches

#### Scenario: Overlapping replacements
- **WHEN** two replacements of `u-1`'s set, of 5 hashes each, overlap in time
- **THEN** `u-1` holds exactly 5 unspent codes afterwards, all from one of the two new sets

#### Scenario: Match writes nothing
- **WHEN** an unspent code is matched three times
- **THEN** each match succeeds and the store receives no write

### Requirement: Recovery records are completed or cancelled by the write
A recovery-record store SHALL keep, per recovery, an identifier, the user reference, the start time, the instant the recovery becomes completable, the proven and reported authenticators as the library supplied them, and the completion and cancellation times. It SHALL:
- insert a record, either pending or already completed;
- find a record by its identifier;
- **complete a record** by one conditional write that succeeds only while the record is neither completed nor cancelled and its completable instant has been reached, reporting whether this call completed it;
- **cancel a user's pending records**, and **cancel one record by its identifier**, each by one conditional write on "neither completed nor cancelled", reporting how many were cancelled;
- report the latest completion time among a user's records, or that there is none.

Of a racing completion and cancellation of one record, exactly one SHALL succeed. A refused completion or cancellation SHALL change nothing. The in-memory store SHALL be the default, and any implementation of the contract SHALL be usable in its place.

#### Scenario: Complete before the completable instant
- **WHEN** a pending record completable at 09:00 Thursday is completed at 08:59 Thursday
- **THEN** the completion is refused and the record stays pending

#### Scenario: Cancel then complete
- **WHEN** a pending record is cancelled and then completed after its completable instant
- **THEN** the completion is refused

#### Scenario: Racing complete and cancel
- **WHEN** 8 completions and 8 cancellations of the same pending record run at the same time after its completable instant
- **THEN** exactly one of the 16 succeeds

#### Scenario: Latest completion
- **WHEN** user `u-1` has records completed at 10:00 Monday and 11:00 Tuesday, and a pending one
- **THEN** the latest completion time reported for `u-1` is 11:00 Tuesday

### Requirement: Passkey credentials are unique, and their state changes are decided by the write
A passkey credential store SHALL keep, per credential, a library identifier and the user reference. It SHALL also keep:
- the credential ID and public key, as bytes;
- the signature counter;
- the backup-eligible and backup-state flags;
- the transports;
- the authenticator model identifier;
- the attestation format and statement, when recorded;
- the name;
- the creation and last-use times;
- the state: active, pending or suspended;
- the pending reasons;
- for a credential awaiting its emailed code, the sealed code, its expiry and the attempts charged.

It SHALL:
- **insert** a credential, refusing one whose credential ID is already stored, whatever its user, with a duplicate outcome decided by the write;
- **find** a credential by credential ID, and by library identifier within a user;
- **list** a user's credentials, and **count** them;
- **record an assertion** by one conditional write that sets the counter, the backup-state flag and the last-use time only where the credential is active and the stored counter is lower than the new one, or both are zero. It SHALL report whether this call recorded it;
- **suspend** a credential, and **clear one pending reason**, each by one conditional write on its current state, reporting whether this call changed it. Clearing the last pending reason SHALL make the credential active;
- **charge an emailed-code attempt** by one conditional write that succeeds only while the code is outstanding, unexpired and has fewer than five attempts charged;
- **rename** and **delete** a credential within a user, and **delete every credential of a user** awaiting saved codes;
- **delete every credential of a user**, returning how many were removed.

A refused write SHALL change nothing. The emailed code SHALL be sealed at rest with the store's cipher, which durable stores SHALL require at construction. A read that cannot open a sealed code SHALL be an error, never a missing code. The in-memory store SHALL be the default, SHALL hold its own copies of byte values, and any implementation of the contract SHALL be usable in its place.

#### Scenario: Duplicate credential ID
- **WHEN** a credential with ID C is stored for `u-1`, and another with ID C is inserted for `u-2`
- **THEN** the second insert is refused as a duplicate and `u-1`'s credential is unchanged

#### Scenario: Concurrent counter recordings
- **WHEN** 8 callers record counter 43 on the same credential whose stored counter is 42, at the same time
- **THEN** exactly one recording succeeds

#### Scenario: Counter going backwards is not recorded
- **WHEN** a recording of counter 41 is made on a credential whose stored counter is 42
- **THEN** it is refused and the stored counter is still 42

#### Scenario: Zero counters are recorded
- **WHEN** a recording of counter 0 is made on a credential whose stored counter is 0
- **THEN** it succeeds and the last-use time is updated

#### Scenario: Suspended credential is not recorded
- **WHEN** a recording is made on a suspended credential
- **THEN** it is refused and nothing changes

#### Scenario: Attempts bounded under concurrency
- **WHEN** 20 attempts are charged at the same time on a credential awaiting its emailed code
- **THEN** exactly five are charged

#### Scenario: Last reason cleared activates
- **WHEN** a credential pending on both its emailed code and saved codes has the emailed-code reason cleared and then the saved-code reason cleared
- **THEN** it is pending after the first clearing and active after the second

### Requirement: Passkey user handles are assigned once per user
A passkey user-handle store SHALL map each user reference to one handle, and each handle to one user reference. Assigning a handle SHALL be one write that stores the offered handle only when the user has none, and SHALL return the handle the user holds afterwards, whether newly stored or already present. Of concurrent assignments for one user, every caller SHALL receive the same handle. Looking a handle up SHALL return its user reference, or report that no user holds it. The in-memory store SHALL be the default.

#### Scenario: Concurrent assignment
- **WHEN** 8 callers assign different offered handles to `u-1`, who has none, at the same time
- **THEN** all 8 receive the same handle, and exactly one handle is stored for `u-1`

#### Scenario: Reverse lookup
- **WHEN** `u-1` holds handle H and H is looked up
- **THEN** the lookup returns `u-1`

### Requirement: A second factor met at the first factor survives a durable store
Durable session stores SHALL store and return unchanged a session's met-by-first-factor marker. A session stored without it SHALL read back with it unset.

#### Scenario: Marker round trip across backends
- **WHEN** a session created satisfied by a user-verified passkey login is saved through the store of one supported backend and loaded through another
- **THEN** it loads in the satisfied state with the marker set and the same satisfied time

#### Scenario: Unmarked session
- **WHEN** a password session that satisfied TOTP is saved and loaded
- **THEN** it loads with the marker unset

### Requirement: Asserted federated assurance survives a durable store
Durable handoff and session stores SHALL store and return unchanged the asserted `amr` values, in order, and the asserted `acr`. A record stored without them SHALL read back with an empty list and an empty `acr`. The values SHALL be stored unsealed.

#### Scenario: Handoff round trip across backends
- **WHEN** a handoff record carrying `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2` is stored through one supported backend and redeemed through another
- **THEN** the redeemed record carries `amr` `["pwd","mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Session round trip across backends
- **WHEN** a federated session recording `amr` `["mfa"]` and `acr` `urn:corp:loa:2` is saved through one supported backend and loaded through another
- **THEN** it loads with `amr` `["mfa"]` and `acr` `urn:corp:loa:2`

#### Scenario: Nothing asserted
- **WHEN** a password session is saved and loaded
- **THEN** it loads with an empty `amr` list and an empty `acr`

### Requirement: TOTP verification attempts are charged and given back by the write
Every MFA enrolment store SHALL keep, per enrolment, a verification attempt count and the end of its window. Charging an attempt SHALL be one conditional write, only on a confirmed enrolment: an ended window SHALL be replaced by one ending a window later, counting one; otherwise the count SHALL rise by one while below the given limit. A charge SHALL report its window's end. A give-back SHALL be one conditional write that lowers a positive count only while the enrolment's window end equals the one named.

A window has ended from its end instant onward. A refused charge or give-back SHALL change nothing. Storing a pending enrolment SHALL clear the count and the window. Of any number of concurrent charges against one enrolment within one window, at most the limit SHALL succeed. A sealing store SHALL pass both operations through unchanged.

#### Scenario: Concurrent charges against one enrolment
- **WHEN** 20 callers charge an attempt against the same confirmed enrolment at the same time, with a limit of 5
- **THEN** exactly five succeed
- **AND** the enrolment reads with five charged attempts

#### Scenario: The window ends at its end instant
- **WHEN** an enrolment holds five charged attempts in a window ending at 12:15, and an attempt is charged at exactly 12:15
- **THEN** the charge succeeds in a new window ending at 12:30, counting one

#### Scenario: Pending enrolment is not charged
- **WHEN** an attempt is charged against an enrolment that is not confirmed
- **THEN** the charge is refused and the enrolment is unchanged

#### Scenario: Give-back in the window it was charged in
- **WHEN** an attempt is charged in the window ending at 12:15 and given back naming 12:15
- **THEN** the give-back succeeds and the count falls by one

#### Scenario: Give-back after the window was replaced
- **WHEN** an attempt is charged in the window ending at 12:15, a later charge opens the window ending at 12:30, and the first attempt is given back naming 12:15
- **THEN** the give-back is refused and the count is unchanged

#### Scenario: Give-back at zero
- **WHEN** a give-back names the current window and the count is zero
- **THEN** it is refused and the count stays zero

#### Scenario: A new begin clears the count
- **WHEN** a confirmed enrolment holding three charged attempts is deleted, and a pending enrolment is then stored for the same user
- **THEN** the pending enrolment reads with no charged attempts and no window

### Requirement: Session activity is recorded by a narrow, conditional write
Durable session stores SHALL record activity by writing only the last-access time and idle deadline of the session with the given identifier, and only when the stored last-access time is not later than the threshold the caller gives and the session is not superseded. A record that is fresher or superseded SHALL be left unchanged without error. A missing record SHALL be the not-found error. Recording activity SHALL never insert a record.

#### Scenario: Fresher record left unchanged
- **WHEN** a stored session was last accessed at 09:19:30 and activity is recorded with a threshold of 09:19
- **THEN** no error is returned and the stored session is unchanged

#### Scenario: Record at the threshold written
- **WHEN** a stored session was last accessed at 09:19 and activity is recorded at 09:20 with a threshold of 09:19
- **THEN** the stored last-access time is 09:20

#### Scenario: Other fields untouched
- **WHEN** a session is loaded, its consumer data is changed and saved through a second copy, and activity is then recorded through the first copy
- **THEN** the stored consumer data is the saved change, and the last-access time is the recorded one

#### Scenario: Missing record
- **WHEN** activity is recorded for a session that was deleted
- **THEN** the not-found error is returned and no record is inserted

### Requirement: Session supersession is decided by the write
Durable session stores SHALL supersede a session in one atomic operation: mark the old record superseded with its window end and the new successor, only if its current successor is the one the caller observed; mark that previous successor, if any, superseded with a window that has ended; and insert the new successor. When the condition fails, the store SHALL write nothing and SHALL return the renewal-conflict error.

#### Scenario: Stale observation refused
- **WHEN** a session is superseded by S1, and a second supersession of it is attempted by a caller that observed no successor
- **THEN** the renewal-conflict error is returned
- **AND** no successor is inserted and the stored records are unchanged

#### Scenario: Successor stored with its family
- **WHEN** a session is superseded
- **THEN** the old record loads as superseded with its window end, and the successor loads in the same family with the same family start time

### Requirement: A superseded session is superseded again only through its observed successor
A session that is already superseded SHALL be superseded again only by a caller that observed its current successor; a caller that observed none SHALL get the renewal-conflict error with nothing written.

#### Scenario: Knocked-out successor renewed as if fresh
- **WHEN** session O is superseded by S1, O is superseded again observing S1 (so S1 is superseded with no successor), and S1 is then superseded by a caller that observed no successor
- **THEN** the renewal-conflict error is returned and nothing is written

### Requirement: Supersession refuses a successor that has moved on
When the caller observed a successor that has since been superseded or is no longer stored, or required an unpresented successor that has been presented, the store SHALL write nothing and SHALL return the successor-advanced error.

#### Scenario: Observed successor already superseded
- **WHEN** session O's successor S1 has itself been superseded, and O is superseded again observing S1
- **THEN** the store refuses with the successor-advanced error and writes nothing

#### Scenario: Unpresented successor required
- **WHEN** session O's successor S1 has been presented, and O is superseded again observing S1 and requiring an unpresented successor
- **THEN** the store refuses with the successor-advanced error and writes nothing

### Requirement: A supersession keeps retention apart from the session's own deadlines
A supersession SHALL give the session it supersedes a retention deadline, the latest time its family could still be live, and SHALL NOT change that session's own idle and absolute deadlines.

#### Scenario: Own deadlines unchanged by the supersession
- **WHEN** a session with an idle deadline of 09:30 and an absolute deadline of 10:00 is superseded at 09:00 with a retention deadline of 21:00
- **THEN** the store returns it with 09:30 and 10:00 as its deadlines, and 21:00 as its retention deadline

### Requirement: Superseded sessions are returned by load and kept by the sweep
Loading a superseded session SHALL return it with its supersession state and its own deadlines, whether or not its window or its own deadlines have ended, until its retention deadline passes. The expiry sweep SHALL delete a superseded session only once its retention deadline has passed. A superseded session with no retention deadline, written before the retention deadline existed, SHALL be judged by its own deadlines.

#### Scenario: Load past the window
- **WHEN** a session superseded at 09:00 with a window ending at 09:00:30 is loaded at 12:00 through the store
- **THEN** the store returns it, reporting it superseded at 09:00 with window end 09:00:30

#### Scenario: Load past its own deadlines
- **WHEN** a session with an absolute deadline of 10:00, superseded at 09:00 with a retention deadline of 21:00, is loaded through the store at 12:00
- **THEN** the store returns it

#### Scenario: Sweep keeps a superseded session
- **WHEN** a session is superseded at 09:00 with a retention deadline of 21:00, and expired sessions are swept at 12:00
- **THEN** the superseded session is not deleted

#### Scenario: Sweep deletes it after retention
- **WHEN** the same sessions are swept at 21:01
- **THEN** the superseded session is deleted

### Requirement: Saving a superseded session keeps its deadlines
Saving a superseded session SHALL NOT change its deadlines or its retention deadline, so a copy loaded before the supersession cannot change them.

#### Scenario: Stale save keeps the deadlines
- **WHEN** a copy of a session with an idle deadline of 09:30 is loaded, the session is then superseded with a retention deadline of 21:00, and the earlier copy, with its idle deadline changed to 09:45, is saved
- **THEN** the stored session still reports 09:30 as its idle deadline and 21:00 as its retention deadline

### Requirement: A supersession writes only the sessions it supersedes
A supersession SHALL write only the session it supersedes, its previous successor if there is one, and the new successor. It SHALL NOT rewrite any other session of the family, so its cost does not grow with the number of earlier renewals.

#### Scenario: Earlier superseded sessions untouched
- **WHEN** session O is superseded by S1, S1 by S2, and S2 by S3
- **THEN** O's stored deadlines and supersession state are exactly as S1's supersession left them

### Requirement: A family is revoked by one delete
Durable session stores SHALL delete every session of one family in one operation, superseded or not, expired or not, and SHALL return how many were removed. Sessions of other families, including other families of the same user, SHALL be unaffected. A revocation that names no family (the nil identifier) SHALL be refused with an error and SHALL delete nothing.

#### Scenario: Nil family refused
- **WHEN** two users each hold a session, and a revocation names the nil family
- **THEN** it fails with an error
- **AND** both sessions still load

#### Scenario: Family revoked
- **WHEN** a family holds a superseded session and two successors, and the user has a session in another family, and the family is revoked
- **THEN** the revocation reports 3
- **AND** the user's other session still loads

### Requirement: A session's first presentation is recorded once
Durable session stores SHALL record when a session was first loaded successfully, in a write that sets the time only when none is recorded. A later recording SHALL leave the first time unchanged. Recording the first presentation of a superseded session SHALL write nothing and SHALL return the superseded-session error.

#### Scenario: First time kept
- **WHEN** a session's first presentation is recorded at 09:00 and again at 09:05
- **THEN** the session reports its first presentation at 09:00

#### Scenario: Superseded session not marked
- **WHEN** a session is superseded, and its first presentation is then recorded
- **THEN** the superseded-session error is returned and no presentation time is stored

### Requirement: Session family and supersession state survive a durable store
Durable session stores SHALL persist and return a session's family identifier, family start time, supersession time, window end, retention deadline, successor and first-presentation time exactly as written, at microsecond precision. A session that was never superseded or presented SHALL report none. Saving a session SHALL NOT change any of them.

#### Scenario: Round trip
- **WHEN** a session is created, superseded, its successor first presented, and both are loaded
- **THEN** every family, supersession and presentation value reads back as written

#### Scenario: Save leaves them unchanged
- **WHEN** a superseded session's loaded copy has its consumer data changed and is saved
- **THEN** its supersession state reads back unchanged

### Requirement: Superseded sessions do not count as active
Counting a user's active sessions SHALL count only unexpired sessions that are not superseded, so one sign-in counts once however often it is renewed.

#### Scenario: Renewed sign-in counts once
- **WHEN** a session is renewed three times with a 30-second grace, and the user's active sessions are counted after every window has ended
- **THEN** the count is 1

### Requirement: Recording activity never stores an idle deadline past the stored absolute deadline
Recording activity SHALL store an idle deadline no later than the absolute deadline the record holds when it is written, even when the caller computed it from an older copy.

#### Scenario: Absolute deadline lowered by another request
- **WHEN** a session's stored absolute deadline is lowered to 09:15 after a request loaded it, and that request then records activity with an idle deadline of 09:31
- **THEN** the stored idle deadline is 09:15

### Requirement: Every stored session belongs to a family
Creating a session in a store, or inserting a supersession's successor, SHALL be refused with an error, and nothing SHALL be written, when the session belongs to no family (the nil family identifier) or carries no family start time (the zero time).

#### Scenario: Session with no family refused at creation
- **WHEN** a session whose family is the nil identifier is created through the store
- **THEN** the creation fails with an error and the session does not load

#### Scenario: Session with no family start time refused at creation
- **WHEN** a session with a family but a zero family start time is created through the store
- **THEN** the creation fails with an error and the session does not load

#### Scenario: Successor with no family start time refused
- **WHEN** a supersession's successor has a family but a zero family start time
- **THEN** the supersession fails with an error, the superseded session is unchanged, and the successor does not load

### Requirement: A supersession never lowers a retention deadline
A supersession SHALL NOT set a superseded session's retention deadline earlier than it was, and SHALL be refused with an error, writing nothing, when the retention deadline it gives is before its window's end.

#### Scenario: Retention before the window's end
- **WHEN** a session is superseded at 16:00 with a retention deadline of 15:00 and a window ending at 16:00:30
- **THEN** the supersession is refused and nothing is written

#### Scenario: A later supersession gives an earlier retention deadline
- **WHEN** a successor knocked out by a re-rotation already holds a retention deadline of 21:00, and the re-rotation gives a retention deadline of 18:00
- **THEN** the knocked-out successor keeps 21:00 as its retention deadline

### Requirement: Whether a superseded session's successor was used is read without writing
A store SHALL report, for a stored superseded session, whether its current successor (the session its successor digest names) is stored and has been presented or superseded. It SHALL report false when that successor is stored and unpresented, or is no longer stored, SHALL fail with the session-not-found error when the named session is not stored, and SHALL write nothing.

#### Scenario: Successor presented
- **WHEN** session O is superseded by S1, and S1's first presentation is recorded
- **THEN** the store reports that O's successor was used, and nothing is written

#### Scenario: Successor unused
- **WHEN** session O is superseded by S1, and S1 is never presented
- **THEN** the store reports that O's successor was not used

#### Scenario: Successor superseded
- **WHEN** session O is superseded by S1, and S1 is superseded by S2
- **THEN** the store reports that O's successor was used

#### Scenario: Successor no longer stored
- **WHEN** session O is superseded by S1, and S1 is deleted
- **THEN** the store reports that O's successor was not used

#### Scenario: Session not stored
- **WHEN** the store is asked about a session it does not hold
- **THEN** it fails with the session-not-found error

#### Scenario: Session past its retention deadline
- **WHEN** session O is superseded by S1 with a retention deadline of 21:00, S1 is presented, and the store is asked about O at 21:00 before any sweep
- **THEN** it fails with the session-not-found error, as loading O would

### Requirement: Deleting a user's sessions reaches a successor being written
Durable session stores SHALL delete, when deleting every session of a user, every session of a user except a named one, every session of a provider sign-in, or every session of a user signed in through one provider, a successor that a supersession of one of those sessions inserts while the delete runs, so no session the delete was asked to end survives as its successor. The memory store, which runs both under one lock, already does.

#### Scenario: Renewal committing during a sign-out everywhere
- **WHEN** a supersession of `u-1`'s session X, inserting successor Y, holds its write while every session of `u-1` is deleted, and the supersession commits before the delete finishes
- **THEN** neither X nor Y loads after the delete returns

#### Scenario: Renewal committing while other sessions are ended
- **WHEN** a supersession of `u-1`'s session X, inserting successor Y, holds its write while `u-1`'s sessions except an unrelated session K are deleted, and the supersession commits before the delete finishes
- **THEN** neither X nor Y loads, and K still loads

#### Scenario: Renewal committing during a provider sign-out
- **WHEN** a supersession of a session X of one provider sign-in, inserting successor Y, holds its write while every session of that provider sign-in is deleted, and the supersession commits before the delete finishes
- **THEN** neither X nor Y loads after the delete returns

### Requirement: Ending a user's other sessions keeps the presenting sign-in
Deleting every session of a user except a named one SHALL keep the named session and, when it belongs to a family, the family's current session, the one member not superseded, and SHALL delete every other session of the user, every other member of that family included. Each pass SHALL decide what it keeps and deletes atomically, so a renewal committing between a read and a delete cannot lose the successor, and the delete SHALL repeat until a pass removes nothing.

#### Scenario: Named session inside its renewal window
- **WHEN** `u-1`'s session O is superseded by S1 with a window still open, `u-1` holds an unrelated session T, and `u-1`'s sessions except O are deleted
- **THEN** O and S1 still load, T does not, and 1 is returned

#### Scenario: Named session is the family's current one
- **WHEN** `u-1`'s session O is superseded by S1 with a window still open, and `u-1`'s sessions except S1 are deleted
- **THEN** S1 still loads and O does not
