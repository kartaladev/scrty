## ADDED Requirements

### Requirement: The enrolment-only state lowers the absolute deadline, and the upgrade restores it
Marking a session enrolment-pending SHALL, in the same persisted change:
- set its absolute deadline to the earlier of its current absolute deadline and now plus the enrolment lifetime;
- set its idle deadline to no later than that absolute deadline;
- set the enrolment-origin marker, which records the absolute deadline the session held immediately before the mark.

No separate deadline SHALL be introduced for this state, so every store's loading, the concurrent-session count and the expiry sweep enforce it as they enforce any absolute deadline.

When a session carrying the enrolment-origin marker has its second factor satisfied, its absolute deadline SHALL be restored to the earlier of its creation time plus the absolute timeout and the deadline the marker recorded, and its idle deadline set to the earlier of now plus the idle timeout and that absolute deadline. The marker and the enrolment generation SHALL then be cleared. The restored absolute deadline SHALL never be later than creation time plus the absolute timeout, nor later than the deadline the session held before it was marked. A session already past its lowered deadline SHALL NOT be restored: the restore SHALL fail with the session-expired error and leave the session unchanged. Rotation SHALL then carry the restored deadlines over, as it carries every other field.

#### Scenario: Entered at login
- **WHEN** a session created at 09:00 with default timeouts is marked enrolment-pending at 09:00 with a 15-minute enrolment lifetime
- **THEN** its absolute deadline is 09:15 and its idle deadline is 09:15

#### Scenario: Entered mid-session near the end
- **WHEN** a session whose absolute deadline is 21:00 is marked enrolment-pending at 20:55 with a 15-minute enrolment lifetime
- **THEN** its absolute deadline stays 21:00

#### Scenario: Activity cannot extend the state
- **WHEN** an enrolment-only session marked at 09:00 with a 15-minute lifetime records activity at 09:14
- **THEN** its idle deadline is 09:15

#### Scenario: Restored on upgrade
- **WHEN** a session created at 09:00 with a 12-hour absolute timeout and a 30-minute idle timeout, marked enrolment-pending at 09:00, has its second factor satisfied at 09:09
- **THEN** its absolute deadline is 21:00 and its idle deadline is 09:39
- **AND** it no longer carries the enrolment-origin marker

#### Scenario: Restored mid-session deadline
- **WHEN** a session created at 08:00 with a 12-hour absolute timeout is marked enrolment-pending at 10:00 and has its second factor satisfied at 10:10
- **THEN** its absolute deadline is 20:00, the deadline it held before it was marked

#### Scenario: Restore never exceeds the deadline held before the mark
- **WHEN** a session created at 09:00 with a 12-hour absolute timeout, whose absolute deadline had been lowered to 10:00, is marked enrolment-pending at 09:30 and has its second factor satisfied at 09:35
- **THEN** its absolute deadline is 10:00

#### Scenario: An expired enrolment-only session is not revived
- **WHEN** a session marked enrolment-pending at 09:00 with a 15-minute lifetime has its deadlines restored at 09:20
- **THEN** the restore fails with the session-expired error
- **AND** the session's deadlines are unchanged

#### Scenario: Plain satisfaction is unchanged
- **WHEN** a session without the enrolment-origin marker, whose absolute deadline is 21:00, has its second factor satisfied
- **THEN** its absolute deadline stays 21:00

## MODIFIED Requirements

### Requirement: Challenge state is kept apart from consumer data
A session SHALL carry, in fields that only the library writes:
- a second-factor state of none, pending, enrolment-pending or satisfied;
- a marker that the session entered the second-factor flow through the enrolment path, recording the absolute deadline it held before it was marked;
- the generation of the enrolment the session began, when it began one;
- a marker that a password change is pending.

The manager SHALL persist changes to these fields. They SHALL NOT be stored in, or read from, consumer data. Adding the enrolment-pending state SHALL NOT change how an already persisted none, pending or satisfied state is read back.

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
