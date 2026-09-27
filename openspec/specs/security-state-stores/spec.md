# security-state-stores Specification

## Purpose

Keeps scrty's security state (sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, flows and handoffs) in PostgreSQL. The three supported database access backends behave identically, stay correct under concurrency and across replicas, and join the caller's transactions.

## Requirements

### Requirement: Durable stores exist for every security-state record on every supported backend
scrty SHALL provide a durable store for each security-state record type (sessions, signing keys, login attempts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows and OIDC handoffs) on each supported database access backend. Each durable store SHALL satisfy the same store contract as the in-memory default for that record type. A record written through one store instance SHALL be visible to every other store instance, on any supported backend, connected to the same database.

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
An MFA enrolment SHALL start unconfirmed. Confirming it SHALL record the confirmation time and the confirming time step only if the enrolment is still unconfirmed, and SHALL report whether this call confirmed it. Storing a new pending enrolment SHALL replace an unconfirmed enrolment's secret and clear its accepted time step. It SHALL be refused with the already-enrolled outcome when the user's enrolment is confirmed, leaving that enrolment unchanged. The check and the write SHALL be a single conditional write.

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

#### Scenario: Rolled back with the caller
- **WHEN** a caller begins a transaction, attaches it, saves a session through a durable store, and rolls back
- **THEN** the session does not exist afterwards

#### Scenario: Committed with the caller
- **WHEN** a caller begins a transaction, attaches it, records a login attempt and consumes a one-time token, and commits
- **THEN** both the attempt and the consumption are visible afterwards

#### Scenario: No attached transaction
- **WHEN** a session is saved with no transaction attached
- **THEN** the session is visible to other connections immediately after the save returns

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
Constructing a durable store SHALL fail with a configuration error, before any database access, when the database handle is missing or when an option is given a nil value.

#### Scenario: Missing handle
- **WHEN** a durable store is constructed with a nil database handle
- **THEN** construction returns a configuration error and no store

#### Scenario: Nil option value
- **WHEN** a durable store is constructed with a nil transaction resolver
- **THEN** construction returns a configuration error and no store

### Requirement: Database failures are errors, never refusals or absence
When the database cannot answer a store operation, the store SHALL return an error that wraps the database error. It SHALL NOT report the failure as "not found", "not enrolled", "already consumed" or any other refusal or absence.

#### Scenario: Lookup fails
- **WHEN** reading an MFA enrolment fails because the database connection is lost
- **THEN** the read returns an error
- **AND** the read does not report that the user has no enrolment

#### Scenario: Consumption fails
- **WHEN** consuming a one-time token fails because the database is unavailable
- **THEN** the consumption returns an error that is not the "unknown or consumed" refusal
