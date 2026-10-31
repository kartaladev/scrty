# Spec Delta

## MODIFIED Requirements

### Requirement: A session records when the user last authenticated
Every session SHALL record the time the user last authenticated: the sign-in time at creation, refreshed when a second factor is satisfied and when the user re-authenticates the session. A renewal SHALL carry it over unchanged, because a renewal is not an authentication. A session's creation time SHALL be when that record was written.

#### Scenario: Renewal keeps the authentication time
- **WHEN** a session created at 09:00 is renewed at 15:00
- **THEN** the successor reports 09:00 as its authentication time and 15:00 as its creation time

#### Scenario: A second factor refreshes the authentication time
- **WHEN** a session signed in at 09:00 satisfies a second factor at 09:20
- **THEN** it reports 09:20 as its authentication time

#### Scenario: A re-authentication refreshes the authentication time
- **WHEN** a session signed in at 09:00 re-authenticates with its password at 11:00
- **THEN** its successor reports 11:00 as its authentication time

#### Scenario: Saving cannot refresh it
- **WHEN** a consumer changes a loaded session's authentication time and saves the session
- **THEN** the stored authentication time is unchanged

### Requirement: Rotation with a grace window keeps the old identifier usable until the window ends
The manager SHALL rotate a session with a grace window: it SHALL create a successor in the same family and mark the old session superseded, usable until the earlier of now plus the grace and its absolute deadline. Until then, loading the old identifier SHALL succeed. A grace that is negative or longer than 5 minutes SHALL be refused with a configuration error. Rotation without a grace window SHALL make the old identifier stop loading at once.

#### Scenario: Old identifier inside its window
- **WHEN** a session is rotated at 09:00 with a 30-second grace and its old identifier is loaded at 09:00:20
- **THEN** the load succeeds

#### Scenario: Window capped at the absolute deadline
- **WHEN** a session whose absolute deadline is 21:00 is rotated at 20:59:50 with a 30-second grace
- **THEN** the old identifier is usable only until 21:00

#### Scenario: Grace above the ceiling
- **WHEN** a session is rotated with a 10-minute grace
- **THEN** the rotation fails with a configuration error and nothing is stored

#### Scenario: Rotation without grace is unchanged
- **WHEN** a session is rotated without a grace window
- **THEN** loading the old identifier returns the not-found error

### Requirement: A superseded identifier presented after its window revokes its family
Loading a superseded identifier at or after the end of its window SHALL be treated as reuse: the manager SHALL revoke the identifier's whole family and SHALL fail with a reused-session error that also matches the expired-session error. Superseded sessions SHALL be kept until their family's absolute deadline, so a late presentation is detected rather than reported as not found, whether or not the superseded session's own deadlines have passed. A session rotated without grace SHALL be excluded: it is kept only until its in-flight window ends, and loading it is the not-found error.

#### Scenario: Reuse after the window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is loaded at 09:05
- **THEN** the load fails with the reused-session error, which also matches the expired-session error
- **AND** loading S1 afterwards returns the not-found error

#### Scenario: Detected long after the window
- **WHEN** a session with an absolute deadline of 21:00 is rotated at 09:00 with a 30-second grace, and its old identifier is presented at 18:00
- **THEN** the load fails with the reused-session error

#### Scenario: Detected after the session's own deadline
- **WHEN** a session with an absolute deadline of 10:00 under a family maximum ending at 21:00 is rotated at 09:00 with a 30-second grace, and its old identifier is presented at 12:00
- **THEN** the load fails with the reused-session error and the family is revoked

#### Scenario: A strictly rotated identifier after its window
- **WHEN** session O is rotated without grace at 09:00 into S1, and O is presented at 09:00:40 before the sweep has run
- **THEN** the load fails with the not-found error, and S1 still loads

## ADDED Requirements

### Requirement: One check decides whether a session authenticated within a window
The library SHALL offer one check of whether a session authenticated within a window at a given time: true when no more than the window has elapsed since its authentication time, inclusive. A time later than the given time SHALL count as no time elapsed. A session with no recorded authentication time SHALL never be within any window. Every freshness check the library makes SHALL use this check.

#### Scenario: Inside the window
- **WHEN** a session authenticated at 09:00 is checked against a 15-minute window at 09:10
- **THEN** it is within the window

#### Scenario: At the window's end
- **WHEN** it is checked at exactly 09:15
- **THEN** it is within the window

#### Scenario: Past the window
- **WHEN** it is checked at 09:15:01
- **THEN** it is not within the window

#### Scenario: Authentication time ahead of the clock
- **WHEN** a session whose authentication time is 09:00:05 is checked at 09:00:00, as when replicas' clocks disagree
- **THEN** it is within the window

#### Scenario: No recorded authentication time
- **WHEN** a session with a zero authentication time is checked against a 24-hour window
- **THEN** it is not within the window

### Requirement: Rotation at second-factor verification keeps the old session only until its in-flight window ends
Rotating without a grace window SHALL supersede the old session in one write, marked as rotated without grace, with a short in-flight window that is also its retention deadline, and SHALL NOT delete it. Loading the old identifier after that write SHALL fail with the not-found error, at any time, and SHALL NOT be judged as reuse. The old session SHALL keep its own deadlines while it is stored.

#### Scenario: The old identifier stops loading
- **WHEN** a session is rotated without grace and its old identifier is loaded at once
- **THEN** loading it fails with the not-found error, and the successor's family is not revoked

#### Scenario: Load after the write
- **WHEN** a load of the old identifier runs after the strict rotation has superseded it
- **THEN** the load fails with the not-found error, and the family is not revoked

#### Scenario: Retention ends with the window
- **WHEN** a session with an absolute deadline of 10:00, in a family whose maximum ends at 21:00, is rotated without grace at 09:00
- **THEN** the old session's retention deadline is the end of its in-flight window, 09:00:30, and its own deadlines are unchanged

#### Scenario: The old session is swept after its window
- **WHEN** a session is rotated without grace at 09:00:00 and the expiry sweep runs at 09:00:31
- **THEN** the old session is no longer stored

### Requirement: A strict rotation that lost a race is a renewal conflict, decided by the store
A rotation without grace or with a grace window of an identifier marked as rotated without grace SHALL fail with the renewal-conflict error inside its in-flight window, storing and revoking nothing, whichever manager sharing the store runs it; after the window it SHALL fail with the not-found error. Otherwise a missing session SHALL be the not-found error and an expired one the expired error.

#### Scenario: Two rotations at once
- **WHEN** two rotations without grace of one session run at once through one manager
- **THEN** one returns a successor and the other fails with the renewal-conflict error
- **AND** the family keeps exactly one live session and nothing is revoked

#### Scenario: Two managers sharing a store
- **WHEN** a session is rotated without grace at 09:00:00 through one manager, and its old identifier is rotated without grace at 09:00:10 through another manager sharing the store
- **THEN** the second rotation fails with the renewal-conflict error, and the first successor still loads

#### Scenario: A renewal that lost to a strict rotation
- **WHEN** a session is rotated without grace at 09:00:00, and its old identifier is rotated with a 10-second grace window at 09:00:05
- **THEN** the renewal fails with the renewal-conflict error and nothing is stored

#### Scenario: A rotation after the in-flight window
- **WHEN** a session is rotated without grace at 09:00:00 and its old identifier is rotated again at 09:00:31
- **THEN** it fails with the not-found error

#### Scenario: A revoked session
- **WHEN** a session whose family was revoked, and which was never rotated, is rotated without grace
- **THEN** it fails with the not-found error

## REMOVED Requirements

### Requirement: Rotation at second-factor verification keeps the old identifier only in flight
**Reason**: The old identifier no longer loads between a supersession and a delete: a rotation without grace now supersedes in one write, marked, and keeps the old session only until its in-flight window ends. Replaced by "Rotation at second-factor verification keeps the old session only until its in-flight window ends".
**Migration**: None for consumers. A request that carried the old identifier during a strict rotation now gets the not-found error, as it did once the old session was deleted.

### Requirement: A failed delete does not fail a second-factor rotation
**Reason**: A rotation without grace no longer deletes the old session; it supersedes it in one write and the expiry sweep removes it after its in-flight window, so there is no delete to fail.
**Migration**: None for consumers. A store write that fails during the supersession fails the rotation, as before.
