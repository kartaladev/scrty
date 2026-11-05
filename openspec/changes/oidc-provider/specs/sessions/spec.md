# Spec Delta

## ADDED Requirements

### Requirement: An end that cannot say what it ends changes nothing
When a manager with an end observer must read a session to report an end, and that read fails for any reason other than the session being gone or expired, the manager SHALL return the failure and delete nothing. A manager with no observer SHALL NOT read for a report.

#### Scenario: Read fails before a deletion
- **WHEN** a manager with an end observer deletes session `s-1`, and reading `s-1` fails
- **THEN** the call fails, `s-1` is still stored, and no observer is told anything

#### Scenario: Read fails for the session being kept
- **WHEN** a manager with an end observer deletes user `u-1`'s sessions except `s-1`, and reading `s-1` fails
- **THEN** the call fails, and every session of `u-1` is still stored

#### Scenario: Session already gone
- **WHEN** a manager with an end observer deletes session `s-1`, which is no longer stored
- **THEN** the deletion proceeds, as it would with no observer

#### Scenario: A logout does not depend on the read
- **WHEN** a manager with an end observer logs out or revokes family `f-1` by its identifier, and reading sessions fails
- **THEN** the family is deleted and the observer is told, as neither reads a session

### Requirement: A caller can ask whether a manager reports to an observer
The manager SHALL answer whether it reports to a given end observer, comparing observers by identity. An observer whose value cannot be compared, such as a function, SHALL count as not the one asked about, and SHALL NOT panic. This lets a component that relies on being told refuse a manager that does not tell it.

#### Scenario: Observer wired
- **WHEN** a manager was built with observer `o`, and a caller asks whether it reports to `o`
- **THEN** the answer is yes

#### Scenario: Observer not wired
- **WHEN** a manager was built without observer `o`, and a caller asks whether it reports to `o`
- **THEN** the answer is no

## MODIFIED Requirements

### Requirement: An end report says what ended and why, without identifiers
The report SHALL name the cause, the user when known, the family when known, the family kept when one was kept and is still that user's, and the upstream issuer and session when the end was selected by them. It SHALL NOT carry any session identifier.

#### Scenario: User's other sessions deleted
- **WHEN** the manager deletes user `u-1`'s sessions except the one in family `f-2`
- **THEN** the report names `u-1` and the kept family `f-2`, and no session identifier
