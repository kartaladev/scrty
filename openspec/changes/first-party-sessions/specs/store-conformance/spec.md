## MODIFIED Requirements

### Requirement: The race suite proves atomic single use and unique inserts
For stores with single-use consumption or unique inserts, a race suite SHALL release many concurrent callers at once against many independent records. It SHALL require exactly one success per record. It SHALL fail when the connection pool it is given is narrower than the number of racers per record. The race suite SHALL be shown to fail against an implementation that reads before writing.

#### Scenario: Exactly one winner per record
- **WHEN** the race suite releases 8 consumers for each of 50 independent tokens at once
- **THEN** it passes only if every token has exactly one successful consumption

#### Scenario: TOTP step race
- **WHEN** the race suite releases 8 callers recording the same TOTP time step for each of 50 independent enrolments at once
- **THEN** it passes only if every enrolment has exactly one successful recording

#### Scenario: Pool too narrow
- **WHEN** the race suite is given a pool of 2 connections for 8 racers per record
- **THEN** the suite fails, stating that the pool cannot exercise the race

#### Scenario: Read-then-write implementation caught
- **WHEN** the race suite runs against a store variant whose consumption reads the record and then updates it unconditionally
- **THEN** the suite fails

#### Scenario: Saved-code spend race
- **WHEN** the race suite releases 8 callers spending the same saved code for each of 50 independent users at once
- **THEN** it passes only if every code has exactly one successful spend

#### Scenario: Recovery completion race
- **WHEN** the race suite releases 8 completions and 8 cancellations for each of 50 independent pending recovery records at once
- **THEN** it passes only if every record has exactly one successful completion or cancellation

#### Scenario: Passkey counter race
- **WHEN** the race suite releases 8 callers recording the same next counter for each of 50 independent passkey credentials at once
- **THEN** it passes only if every credential has exactly one successful recording

#### Scenario: Passkey credential ID race
- **WHEN** the race suite releases 8 inserts of the same credential ID, for different users, for each of 50 independent credential IDs at once
- **THEN** it passes only if every credential ID has exactly one stored credential

#### Scenario: Passkey user-handle race
- **WHEN** the race suite releases 8 handle assignments for each of 50 independent users who hold none, at once
- **THEN** it passes only if every user holds exactly one handle and every caller received it

#### Scenario: Session supersession race
- **WHEN** the race suite releases 8 supersessions of the same session, each having observed no successor, for each of 50 independent sessions at once
- **THEN** it passes only if every session has exactly one successor, and every other caller received the renewal-conflict error

#### Scenario: Read-then-write supersession caught
- **WHEN** the session supersession race runs against a store variant that reads the old record and then updates it unconditionally
- **THEN** the suite fails

## ADDED Requirements

### Requirement: The session suite covers activity, supersession and families
The session store suite SHALL cover, for every session store, the narrow activity write, supersession and its conflict, loading superseded sessions with their own deadlines, the sweep keeping them until their retention deadline, family revocation, deleting a user's other sessions while keeping the presenting sign-in, first-presentation recording, and the round trip of every family and supersession value. The in-memory default store SHALL pass it.

#### Scenario: Store that widens the activity write caught
- **WHEN** the session suite runs against a store variant whose activity write saves the whole record
- **THEN** the suite fails on the case that changes another field between load and activity

#### Scenario: In-memory default conforms
- **WHEN** the session suite runs against the in-memory default store
- **THEN** every activity, supersession and family case passes

### Requirement: The session suite covers reading whether a successor was used
The session store suite SHALL cover, for every session store, reading whether a superseded session's successor was used: presented, unused, superseded, no longer stored and not stored, and that the read writes nothing.

#### Scenario: Store that reads a gone successor as used caught
- **WHEN** the session suite runs against a store variant that reports a successor no longer stored as used
- **THEN** the suite fails on the case whose successor is no longer stored
