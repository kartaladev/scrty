# Spec Delta

## ADDED Requirements

### Requirement: The manager reports each explicit end of a sign-in to its end observers
After each explicit end of sign-ins through the manager, it SHALL call every observer synchronously, in the order given. These ends SHALL be reported:
- a family revoked for reuse, and a family revoked;
- a session deleted, and a sign-in ended by its handle;
- a user's sessions deleted, with or without one kept, and a user's other sign-ins ended;
- sessions deleted by upstream session, or by user and upstream issuer.

#### Scenario: Family revoked for reuse
- **WHEN** a manager with an end observer detects reuse and revokes family `f-1` of user `u-1`
- **THEN** the observer is told, after the revocation, that `f-1` of `u-1` ended for reuse

#### Scenario: Upstream session named
- **WHEN** the manager deletes sessions by upstream issuer `https://idp.example.com` and upstream session `x-9`
- **THEN** the observer is told that issuer and session, with no user or family

### Requirement: The manager accepts any number of end observers
The manager SHALL accept any number of end observers, and a nil observer SHALL fail construction.

#### Scenario: Nil observer
- **WHEN** a manager is constructed with a nil end observer
- **THEN** construction fails with a configuration error

### Requirement: End reports survive a hang-up and a panic
The manager SHALL call each observer with a context keeping the caller's values and not its cancellation, so a client that hangs up cannot drop a report. A panic in one observer SHALL be recovered and logged without the report's contents, and the next observer SHALL still run.

#### Scenario: Caller hangs up
- **WHEN** the request ending a family is cancelled as the manager reports the end
- **THEN** the observer still receives a context that is not cancelled

#### Scenario: Observer panics
- **WHEN** the first of two observers panics
- **THEN** the second is still called, and the end is unchanged

### Requirement: An end report says what ended and why, without identifiers
The report SHALL name the cause, the user when known, the family when known, the family kept when one was kept, and the upstream issuer and session when the end was selected by them. It SHALL NOT carry any session identifier.

#### Scenario: User's other sessions deleted
- **WHEN** the manager deletes user `u-1`'s sessions except the one in family `f-2`
- **THEN** the report names `u-1` and the kept family `f-2`, and no session identifier

### Requirement: Expiry is not reported as an end
A session that reaches its idle or absolute deadline, and a session removed by the expiry sweep, SHALL NOT be reported to end observers. A store write that fails SHALL NOT be reported either.

#### Scenario: Sweep
- **WHEN** the expiry sweep deletes expired sessions
- **THEN** no end observer is called

#### Scenario: Failed deletion
- **WHEN** deleting a user's sessions fails in the store
- **THEN** the error is returned, and no end observer is called

### Requirement: A caller can ask whether a manager reports to an observer
The manager SHALL report whether it was built with a given end observer, comparing observers by identity. An observer whose value cannot be compared, such as a function, SHALL count as not the one asked about, and SHALL NOT panic. This lets a component that relies on being told refuse a manager that does not tell it.

#### Scenario: Observer wired
- **WHEN** a manager was built with observer `o`, and a caller asks whether it reports to `o`
- **THEN** the answer is yes

#### Scenario: Observer not wired
- **WHEN** a manager was built without observer `o`, and a caller asks whether it reports to `o`
- **THEN** the answer is no
