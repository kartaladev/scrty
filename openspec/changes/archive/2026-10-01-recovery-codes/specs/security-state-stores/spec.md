# Spec Delta

## MODIFIED Requirements

### Requirement: Durable stores exist for every security-state record on every supported backend
scrty SHALL provide a durable store for each security-state record type (sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes and recovery records) on each supported database access backend. Each durable store SHALL satisfy the same store contract as the in-memory default for that record type. A record written through one store instance SHALL be visible to every other store instance, on any supported backend, connected to the same database.

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


## ADDED Requirements

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
