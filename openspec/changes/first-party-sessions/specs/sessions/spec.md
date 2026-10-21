## MODIFIED Requirements

### Requirement: Sessions expire when idle and at an absolute limit
A new session SHALL receive:
- an idle deadline of creation time plus the idle timeout;
- an absolute deadline of creation time plus the absolute timeout, unless a lifetime was chosen for it at creation, in which case creation time plus that lifetime.

A session SHALL be valid only while the current time is before both deadlines. The defaults SHALL be an idle timeout of 30 minutes and an absolute timeout of 12 hours, each replaceable by an option. Construction SHALL fail with a configuration error when either timeout is zero or negative.

#### Scenario: Default deadlines
- **WHEN** a session is created at 09:00 with default options
- **THEN** its idle deadline is 09:30 and its absolute deadline is 21:00

#### Scenario: Consumer timeouts
- **WHEN** the manager is configured with a 5-minute idle timeout and a 1-hour absolute timeout, and a session is created at 09:00
- **THEN** its idle deadline is 09:05 and its absolute deadline is 10:00

#### Scenario: Zero idle timeout
- **WHEN** a manager is constructed with a zero idle timeout
- **THEN** construction fails with a configuration error

### Requirement: Activity extends the idle deadline
Recording activity on a valid session SHALL set its last-access time to now and its idle deadline to now plus the idle timeout, capped at the absolute deadline, and SHALL persist the change. Recording activity on an expired or unknown session SHALL fail with the expired or not-found error. When an activity interval is configured, recording activity SHALL persist nothing while less than that interval has passed since the session's last recorded access.

#### Scenario: Extension
- **WHEN** a session created at 09:00 with a 30-minute idle timeout records activity at 09:20
- **THEN** its idle deadline becomes 09:50

#### Scenario: Capped at the absolute deadline
- **WHEN** a session whose absolute deadline is 21:00 records activity at 20:50 with a 30-minute idle timeout
- **THEN** its idle deadline becomes 21:00

#### Scenario: Default writes on every activity
- **WHEN** a manager configured with no activity interval records activity on a session at 09:20 and again at 09:20:10
- **THEN** both are persisted, and the stored idle deadline is 09:50:10

#### Scenario: Consumer interval skips a recent write
- **WHEN** a manager configured with a 1-minute activity interval records activity at 09:20 on a session last accessed at 09:19:30
- **THEN** nothing is persisted, and the stored idle deadline stays 09:49:30

#### Scenario: Consumer interval writes once the interval has passed
- **WHEN** a manager configured with a 1-minute activity interval records activity at 09:20 on a session last accessed at 09:19
- **THEN** the last-access time 09:20 and the idle deadline 09:50 are persisted

### Requirement: The enrolment-only state lowers the absolute deadline, and the upgrade restores it
Marking a session enrolment-pending SHALL, in the same persisted change:
- set its absolute deadline to the earlier of its current absolute deadline and now plus the enrolment lifetime;
- set its idle deadline to no later than that absolute deadline;
- set the enrolment-origin marker, which records the absolute deadline the session held immediately before the mark.

No separate deadline SHALL be introduced for this state, so every store's loading, the concurrent-session count and the expiry sweep enforce it as they enforce any absolute deadline.

When a session carrying the enrolment-origin marker has its second factor satisfied, its absolute deadline SHALL be restored to the deadline the marker recorded, and its idle deadline set to the earlier of now plus the idle timeout and that absolute deadline. The marker and the enrolment generation SHALL then be cleared. The restored absolute deadline SHALL never be later than the deadline the session held before it was marked, whatever lifetime the session was created or renewed with. A session already past its lowered deadline SHALL NOT be restored: the restore SHALL fail with the session-expired error and leave the session unchanged. Rotation SHALL then carry the restored deadlines over, as it carries every other field.

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

#### Scenario: A chosen lifetime survives the upgrade
- **WHEN** a session created at 09:00 with a chosen 30-day lifetime is marked enrolment-pending at 09:00 and has its second factor satisfied at 09:05
- **THEN** its absolute deadline is 09:00 thirty days after creation

#### Scenario: An expired enrolment-only session is not revived
- **WHEN** a session marked enrolment-pending at 09:00 with a 15-minute lifetime has its deadlines restored at 09:20
- **THEN** the restore fails with the session-expired error
- **AND** the session's deadlines are unchanged

#### Scenario: Plain satisfaction is unchanged
- **WHEN** a session without the enrolment-origin marker, whose absolute deadline is 21:00, has its second factor satisfied
- **THEN** its absolute deadline stays 21:00

## ADDED Requirements

### Requirement: A session's absolute lifetime can be chosen at creation, up to a maximum
The manager SHALL let a caller choose, at creation, the absolute lifetime of one session. The lifetime SHALL be bounded by a lifetime maximum, which SHALL default to the absolute timeout and be replaceable by an option. Creating a session with a chosen lifetime that is zero, negative or above the maximum SHALL fail with a configuration error and store nothing; it SHALL NOT be shortened silently. Construction SHALL fail when the maximum is below the absolute timeout.

#### Scenario: Default maximum refuses a longer lifetime
- **WHEN** a manager with default options creates a session with a chosen 30-day lifetime
- **THEN** creation fails with a configuration error
- **AND** no session is stored

#### Scenario: Consumer maximum admits a remembered session
- **WHEN** a manager whose lifetime maximum is 30 days creates a session at 09:00 with a chosen 30-day lifetime
- **THEN** its absolute deadline is 09:00 thirty days later, and its idle deadline is no later than that

#### Scenario: Without a chosen lifetime the absolute timeout applies
- **WHEN** a manager whose lifetime maximum is 30 days creates a session at 09:00 without choosing a lifetime
- **THEN** its absolute deadline is 21:00

#### Scenario: Maximum below the absolute timeout
- **WHEN** a manager is constructed with a 12-hour absolute timeout and a 1-hour lifetime maximum
- **THEN** construction fails with a configuration error

### Requirement: An activity interval is bounded by the idle timeout
The activity interval SHALL default to zero, meaning every recorded activity is persisted. Construction SHALL fail with a configuration error when the interval is negative, or equal to or longer than the idle timeout. A persisted idle deadline SHALL never be later than the one a write on every activity would have produced.

#### Scenario: Interval as long as the idle timeout
- **WHEN** a manager is constructed with a 30-minute idle timeout and a 30-minute activity interval
- **THEN** construction fails with a configuration error

#### Scenario: A skipped write only brings expiry earlier
- **WHEN** a manager with a 30-minute idle timeout and a 1-minute activity interval records activity at 09:00 and 09:00:50, then none
- **THEN** the session expires at 09:30, not at 09:30:50

### Requirement: Recording activity changes only the activity fields
Persisting recorded activity SHALL write only the session's last-access time and idle deadline. It SHALL NOT change any other stored field, so a change another request saved to the same session in the meantime survives it. Recording activity on a superseded session SHALL persist nothing.

#### Scenario: A concurrent change survives an activity write
- **WHEN** request A loads a session, request B then marks the same session enrolment-pending, lowering its absolute deadline, and A then records activity
- **THEN** the stored session keeps B's lowered absolute deadline and enrolment-origin marker

#### Scenario: A superseded session is not extended
- **WHEN** a session superseded with a grace window ending at 09:01 records activity at 09:00:30
- **THEN** its stored deadlines are unchanged

### Requirement: Sessions belong to a family that rotation keeps
Every session SHALL belong to a family, identified by a library-generated, non-secret identifier, and SHALL record when the family was started. Creating a session SHALL start a new family at creation time. Every rotation, with or without a grace window and including rotation at second-factor verification, SHALL keep the family and its start time. The manager SHALL be able to revoke a family, deleting every session in it.

#### Scenario: A new sign-in starts a family
- **WHEN** two sessions are created for the same user
- **THEN** they belong to different families

#### Scenario: Rotation keeps the family
- **WHEN** a session is rotated, and its successor is rotated again
- **THEN** all three report the same family and family start time

#### Scenario: Revoking a family
- **WHEN** a family holding a superseded session and its live successor is revoked
- **THEN** loading either identifier returns the not-found error
- **AND** the user's sessions in other families are unaffected

### Requirement: Family identifiers come from a replaceable generator
By default a family identifier SHALL come from the library's time-ordered identifier generator on the manager's clock. A consumer MAY supply its own generator. Supplying a nil generator SHALL be a configuration error at construction.

#### Scenario: Consumer family identifier generator
- **WHEN** the manager is configured with a consumer generator, and a session is created
- **THEN** the session's family identifier is the one that generator returned

#### Scenario: Nil family identifier generator
- **WHEN** the manager is configured with a nil family identifier generator
- **THEN** construction fails with a configuration error

### Requirement: Rotation with a grace window keeps the old identifier usable until the window ends
The manager SHALL rotate a session with a grace window: it SHALL create a successor in the same family and mark the old session superseded, usable until the earlier of now plus the grace and its absolute deadline. Until then, loading the old identifier SHALL succeed. A grace that is negative or longer than 5 minutes SHALL be refused with a configuration error. Rotation without a grace window SHALL keep deleting the old identifier at once.

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

### Requirement: Renewing a superseded identifier inside its window re-rotates
Rotating with a grace window an identifier that is already superseded and still inside its window SHALL issue a fresh successor in the same family, and SHALL supersede the previous successor with a window that has already ended. Any later presentation of that previous successor SHALL then be reuse. If the previous successor has itself been superseded, or is no longer stored, the re-rotation SHALL be reuse instead, so a family never holds two live heads.

#### Scenario: Lost response recovered inside the window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is rotated again at 09:00:10
- **THEN** a fresh successor S2 is returned
- **AND** loading S1 afterwards is treated as reuse

#### Scenario: Re-rotation after the successor was renewed
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, S1 is rotated into T at 09:00:05, and O is rotated again at 09:00:10
- **THEN** the rotation fails with the reused-session error and the family is revoked

### Requirement: A superseded identifier presented after its window revokes its family
Loading a superseded identifier at or after the end of its window SHALL be treated as reuse: the manager SHALL revoke the identifier's whole family and SHALL fail with a reused-session error that also matches the expired-session error. Superseded sessions SHALL be kept until their family's absolute deadline, so a late presentation is detected rather than reported as not found.

#### Scenario: Reuse after the window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is loaded at 09:05
- **THEN** the load fails with the reused-session error, which also matches the expired-session error
- **AND** loading S1 afterwards returns the not-found error

#### Scenario: Detected long after the window
- **WHEN** a session with an absolute deadline of 21:00 is rotated at 09:00 with a 30-second grace, and its old identifier is presented at 18:00
- **THEN** the load fails with the reused-session error

### Requirement: Recovery while the successor is unused is opt-in
The manager SHALL record when a session is first loaded successfully. By default a superseded identifier presented after its window SHALL be reuse. With unused-successor recovery enabled, renewing such an identifier SHALL rotate it again as inside the window when its current successor has never been loaded and has not been superseded, decided atomically by the store; otherwise the renewal SHALL be reuse.

#### Scenario: Default treats a late retry as reuse
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, S1 is never presented, and O is rotated again the next day
- **THEN** the rotation fails with the reused-session error and the family is revoked

#### Scenario: Consumer recovery re-rotates an unused successor
- **WHEN** a manager with unused-successor recovery enabled rotates O at 09:00 with a 30-second grace into S1, S1 is never presented, and O is renewed the next day
- **THEN** a fresh successor S2 is returned
- **AND** loading S1 afterwards is treated as reuse

#### Scenario: Recovery refuses once the successor was used
- **WHEN** a manager with unused-successor recovery enabled rotates O into S1, S1 is loaded, and O is renewed after its window
- **THEN** the renewal fails with the reused-session error and the family is revoked

### Requirement: Under recovery an ordinary late request is refused without revoking
With unused-successor recovery enabled, loading a superseded identifier after its window for anything but a renewal SHALL fail with a renewal-required error that matches the expired-session error, and SHALL NOT revoke the family.

#### Scenario: Consumer recovery refuses an ordinary late request without revoking
- **WHEN** a manager with unused-successor recovery enabled rotates O at 09:00 with a 30-second grace into S1, and O is loaded the next day
- **THEN** the load fails with the renewal-required error, which matches the expired-session error
- **AND** S1 still loads

### Requirement: A session records when the user last authenticated
Every session SHALL record the time the user last authenticated: the sign-in time at creation, refreshed when a second factor is satisfied. A renewal SHALL carry it over unchanged, because a renewal is not an authentication. A session's creation time SHALL be when that record was written.

#### Scenario: Renewal keeps the authentication time
- **WHEN** a session created at 09:00 is renewed at 15:00
- **THEN** the successor reports 09:00 as its authentication time and 15:00 as its creation time

#### Scenario: A second factor refreshes the authentication time
- **WHEN** a session signed in at 09:00 satisfies a second factor at 09:20
- **THEN** it reports 09:20 as its authentication time

### Requirement: Rotation at second-factor verification keeps the old identifier only in flight
Rotating without a grace window SHALL supersede the old session with a short in-flight window and then delete it. A load of the old identifier between the two writes SHALL return the old session as it was, and SHALL NOT be judged as reuse.

#### Scenario: Load between the writes
- **WHEN** a load of the old identifier runs after the strict rotation has superseded it and before it is deleted
- **THEN** the load returns the old session, and the family is not revoked

### Requirement: A failed delete does not fail a second-factor rotation
When the delete after a rotation without a grace window fails, the rotation SHALL still return the successor, and the old identifier SHALL expire as a superseded session when its in-flight window ends.

#### Scenario: Delete fails
- **WHEN** the delete after a strict rotation fails
- **THEN** the rotation returns the successor, and the old identifier loads until its in-flight window ends

### Requirement: Rotation at second-factor verification refuses a superseded session
Rotating without a grace window a session that is superseded and still inside its window SHALL fail with the renewal-conflict error and SHALL write nothing, so the client retries with its current credential and the family keeps one live head. Past its window it SHALL be answered as loading it would be.

#### Scenario: Superseded session inside its window
- **WHEN** session O is rotated at 09:00 with a 30-second grace into S1, and O is rotated without grace at 09:00:10
- **THEN** the rotation fails with the renewal-conflict error
- **AND** S1 still loads

### Requirement: Renewal carries the absolute deadline over unless a new lifetime is chosen, under a family maximum
By default a successor SHALL keep its predecessor's absolute deadline. A caller MAY choose a new lifetime when rotating with a grace window; the successor's absolute deadline SHALL then be now plus that lifetime, bounded by the family maximum. A lifetime above the lifetime maximum SHALL fail with a configuration error and store nothing.

#### Scenario: Default carries over
- **WHEN** a session whose absolute deadline is 21:00 is rotated with a grace window at 15:00
- **THEN** the successor's absolute deadline is 21:00

#### Scenario: Consumer lifetime extends within the family maximum
- **WHEN** a manager with a 30-day lifetime maximum and a 90-day family maximum rotates, on day 20 of a family, a session with a chosen 30-day lifetime
- **THEN** the successor's absolute deadline is now plus 30 days

#### Scenario: Lifetime above the lifetime maximum
- **WHEN** a manager with a 30-day lifetime maximum rotates a session with a chosen 45-day lifetime
- **THEN** the rotation fails with a configuration error and nothing is stored

#### Scenario: Rotation at second-factor verification never extends
- **WHEN** a session whose absolute deadline is 21:00 is rotated at second-factor verification
- **THEN** the successor's absolute deadline is 21:00

### Requirement: The family maximum bounds every renewal
A renewed successor's absolute deadline SHALL never be later than its family start plus the family maximum; a deadline that would pass it SHALL be cut to end exactly there. The family maximum SHALL default to the lifetime maximum and SHALL be finite. Construction SHALL fail when it is below the lifetime maximum.

#### Scenario: Family maximum is the overall limit
- **WHEN** the same manager rotates, on day 80 of the family, a session with a chosen 30-day lifetime
- **THEN** the successor's absolute deadline is the family start plus 90 days

#### Scenario: Default family maximum allows no extension
- **WHEN** a manager with a 12-hour lifetime maximum and no family maximum renews, at 15:00, a session created at 09:00 with a chosen 12-hour lifetime
- **THEN** the successor's absolute deadline is 21:00

#### Scenario: Family maximum below the lifetime maximum
- **WHEN** a manager is constructed with a 30-day lifetime maximum and a 7-day family maximum
- **THEN** construction fails with a configuration error

### Requirement: Concurrent renewals of one identifier produce one successor
When two callers rotate the same identifier with a grace window at the same time, through one manager or through managers sharing one store, exactly one rotation SHALL succeed. The other SHALL fail with a renewal-conflict error and SHALL store nothing.

#### Scenario: Two replicas renew at once
- **WHEN** two managers sharing one store rotate the same identifier concurrently
- **THEN** one returns a successor and the other fails with the renewal-conflict error
- **AND** the family holds exactly one live successor

### Requirement: Detected reuse is reported to an optional observer
The manager SHALL accept an optional reuse observer. On detected reuse it SHALL call the observer synchronously, after the family is revoked, with the caller's context and a report of the user reference, the family identifier, when the presented identifier was superseded and the detection time. The report SHALL NOT carry any session identifier. A nil observer SHALL fail construction. Without an observer, reuse SHALL still be refused and revoked.

#### Scenario: Default without an observer
- **WHEN** reuse is detected by a manager with no observer
- **THEN** the family is revoked and the reused-session error is returned

#### Scenario: Consumer observer receives the report
- **WHEN** reuse is detected by a manager with an observer
- **THEN** the observer is called once, after the revocation, with the user reference and family identifier and no session identifier

#### Scenario: Nil observer
- **WHEN** a manager is constructed with a nil reuse observer
- **THEN** construction fails with a configuration error
