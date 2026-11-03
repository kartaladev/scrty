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
The report SHALL name the cause, the user when known, the family when known, the family kept when one was kept and could be read, and the upstream issuer and session when the end was selected by them. It SHALL NOT carry any session identifier.

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

### Requirement: An end observer can be added to a built manager
The manager SHALL let a component add an end observer after construction, so the chain can wire its own without the consumer doing so. A nil observer SHALL be refused with a configuration error. An added observer SHALL run after those given at construction, which SHALL still be called.

#### Scenario: Added beside an existing observer
- **WHEN** a manager built with observer `a` has observer `b` added, and a session is deleted
- **THEN** `a` and then `b` are told

#### Scenario: Nil observer added
- **WHEN** a nil observer is added
- **THEN** the call fails with a configuration error, and later ends are still reported

### Requirement: With no observer the manager reports nothing and reads nothing extra
A manager with no end observer SHALL report nothing, and deleting a session SHALL make no load it would not otherwise make.

#### Scenario: No observer
- **WHEN** no observer is configured and a session is deleted
- **THEN** nothing is reported and the session is not loaded first

### Requirement: Each ending call names its own cause
Each ending call SHALL report its own cause, so an observer can tell a logout from an ended sign-in, a revocation or a user-wide end. A user-wide or bulk end SHALL be one report, naming no family.

#### Scenario: Logout
- **WHEN** a session of user `u-1` is deleted at logout
- **THEN** the observer receives one report naming `u-1`, the session's family and the deleted cause

#### Scenario: Sign-in ended from another device
- **WHEN** user `u-1` ends one of their sign-ins from another device
- **THEN** the observer receives `u-1`, that sign-in's family and the ended-by-handle cause

#### Scenario: Every session of a user
- **WHEN** every session of a user is deleted
- **THEN** the observer receives one report naming the user, no family, and the user-sessions cause

#### Scenario: A provider's sessions of one user
- **WHEN** user `u-1`'s sessions from one identity provider are ended
- **THEN** the observer receives one report naming `u-1`, that issuer, no family, and the user-and-issuer cause

### Requirement: A kept session is reported by its family
Where an end spares one session, the report SHALL name that session's family as kept, never the session.

#### Scenario: Kept session named by family
- **WHEN** an observer is configured and every session of a user but one named session is deleted
- **THEN** the report names the kept session's family, and no session identifier

### Requirement: An observer cannot change an end's outcome
The observer SHALL be called only after the write succeeded, and a panicking observer SHALL NOT change the outcome of the call that ended the sessions.

#### Scenario: Observer panics while deleting
- **WHEN** the observer panics while a session is deleted
- **THEN** the deletion still succeeds
