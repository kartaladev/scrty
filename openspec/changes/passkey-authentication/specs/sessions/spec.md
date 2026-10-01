# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

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
