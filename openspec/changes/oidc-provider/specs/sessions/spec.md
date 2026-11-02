# Spec Delta

## ADDED Requirements

### Requirement: The manager reports each explicit end of a sign-in to its end observers
The manager SHALL accept any number of end observers, and a nil observer SHALL fail construction. After each explicit end of sign-ins through the manager, it SHALL call every observer synchronously, in the order given, with the caller's context. These ends SHALL be reported:
- a family revoked for reuse, and a family revoked;
- a session deleted;
- a user's sessions deleted, with or without one kept;
- sessions deleted by upstream session, or by user and upstream issuer.

#### Scenario: Family revoked for reuse
- **WHEN** a manager with an end observer detects reuse and revokes family `f-1` of user `u-1`
- **THEN** the observer is told, after the revocation, that `f-1` of `u-1` ended for reuse

#### Scenario: Nil observer
- **WHEN** a manager is constructed with a nil end observer
- **THEN** construction fails with a configuration error

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
The manager SHALL report whether it was built with a given end observer, comparing observers by identity. This lets a component that relies on being told refuse a manager that does not tell it.

#### Scenario: Observer wired
- **WHEN** a manager was built with observer `o`, and a caller asks whether it reports to `o`
- **THEN** the answer is yes

#### Scenario: Observer not wired
- **WHEN** a manager was built without observer `o`, and a caller asks whether it reports to `o`
- **THEN** the answer is no
