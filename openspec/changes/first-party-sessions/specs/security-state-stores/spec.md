## ADDED Requirements

### Requirement: Session activity is recorded by a narrow, conditional write
Durable session stores SHALL record activity by writing only the last-access time and idle deadline of the session with the given identifier, and only when the stored last-access time is older than the threshold the caller gives and the session is not superseded. A record that is fresher or superseded SHALL be left unchanged without error. A missing record SHALL be the not-found error. Recording activity SHALL never insert a record.

#### Scenario: Fresher record left unchanged
- **WHEN** a stored session was last accessed at 09:19:30 and activity is recorded with a threshold of 09:19
- **THEN** no error is returned and the stored session is unchanged

#### Scenario: Other fields untouched
- **WHEN** a session is loaded, its consumer data is changed and saved through a second copy, and activity is then recorded through the first copy
- **THEN** the stored consumer data is the saved change, and the last-access time is the recorded one

#### Scenario: Missing record
- **WHEN** activity is recorded for a session that was deleted
- **THEN** the not-found error is returned and no record is inserted

### Requirement: Session supersession is decided by the write
Durable session stores SHALL supersede a session in one atomic operation: mark the old record superseded with its window end and the new successor, only if its current successor is the one the caller observed; mark that previous successor, if any, superseded with a window that has ended; and insert the new successor. When the condition fails, the store SHALL write nothing and SHALL return the renewal-conflict error.

#### Scenario: Stale observation refused
- **WHEN** a session is superseded by S1, and a second supersession of it is attempted by a caller that observed no successor
- **THEN** the renewal-conflict error is returned
- **AND** no successor is inserted and the stored records are unchanged

#### Scenario: Successor stored with its family
- **WHEN** a session is superseded
- **THEN** the old record loads as superseded with its window end, and the successor loads in the same family with the same family start time

### Requirement: Superseded sessions are returned by load and kept by the sweep
Loading a superseded session SHALL return it with its supersession state, whether or not its window has ended, while its idle and absolute deadlines are unexpired. A superseded session SHALL keep its family's absolute deadline as both of its deadlines, so the expiry sweep deletes it only when that deadline passes.

#### Scenario: Load past the window
- **WHEN** a session superseded at 09:00 with a window ending at 09:00:30 is loaded at 12:00 through the store
- **THEN** the store returns it, reporting it superseded at 09:00 with window end 09:00:30

#### Scenario: Sweep keeps a superseded session
- **WHEN** a session whose absolute deadline is 21:00 is superseded at 09:00, and expired sessions are swept at 12:00
- **THEN** the superseded session is not deleted

### Requirement: A family is revoked by one delete
Durable session stores SHALL delete every session of one family in one operation, superseded or not, expired or not, and SHALL return how many were removed. Sessions of other families, including other families of the same user, SHALL be unaffected.

#### Scenario: Family revoked
- **WHEN** a family holds a superseded session and two successors, and the user has a session in another family, and the family is revoked
- **THEN** the revocation reports 3
- **AND** the user's other session still loads

### Requirement: A session's first presentation is recorded once
Durable session stores SHALL record when a session was first loaded successfully, in a write that sets the time only when none is recorded. A later recording SHALL leave the first time unchanged.

#### Scenario: First time kept
- **WHEN** a session's first presentation is recorded at 09:00 and again at 09:05
- **THEN** the session reports its first presentation at 09:00

### Requirement: Session family and supersession state survive a durable store
Durable session stores SHALL persist and return a session's family identifier, family start time, supersession time, window end, successor and first-presentation time exactly as written, at microsecond precision. A session that was never superseded or presented SHALL report none. Saving a session SHALL NOT change any of them.

#### Scenario: Round trip
- **WHEN** a session is created, superseded, its successor first presented, and both are loaded
- **THEN** every family, supersession and presentation value reads back as written

#### Scenario: Save leaves them unchanged
- **WHEN** a superseded session's loaded copy has its consumer data changed and is saved
- **THEN** its supersession state reads back unchanged
