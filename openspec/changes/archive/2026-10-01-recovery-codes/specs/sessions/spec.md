# Spec Delta

## MODIFIED Requirements

### Requirement: Challenge state is kept apart from consumer data
A session SHALL carry, in fields that only the library writes:
- a second-factor state of none, pending, enrolment-pending, satisfied or recovery-pending;
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

## ADDED Requirements

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
