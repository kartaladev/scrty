## ADDED Requirements

### Requirement: Session activity is recorded by a narrow, conditional write
Durable session stores SHALL record activity by writing only the last-access time and idle deadline of the session with the given identifier, and only when the stored last-access time is not later than the threshold the caller gives and the session is not superseded. A record that is fresher or superseded SHALL be left unchanged without error. A missing record SHALL be the not-found error. Recording activity SHALL never insert a record.

#### Scenario: Fresher record left unchanged
- **WHEN** a stored session was last accessed at 09:19:30 and activity is recorded with a threshold of 09:19
- **THEN** no error is returned and the stored session is unchanged

#### Scenario: Record at the threshold written
- **WHEN** a stored session was last accessed at 09:19 and activity is recorded at 09:20 with a threshold of 09:19
- **THEN** the stored last-access time is 09:20

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

### Requirement: A superseded session is superseded again only through its observed successor
A session that is already superseded SHALL be superseded again only by a caller that observed its current successor; a caller that observed none SHALL get the renewal-conflict error with nothing written.

#### Scenario: Knocked-out successor renewed as if fresh
- **WHEN** session O is superseded by S1, O is superseded again observing S1 (so S1 is superseded with no successor), and S1 is then superseded by a caller that observed no successor
- **THEN** the renewal-conflict error is returned and nothing is written

### Requirement: Supersession refuses a successor that has moved on
When the caller observed a successor that has since been superseded or is no longer stored, or required an unpresented successor that has been presented, the store SHALL write nothing and SHALL return the successor-advanced error.

#### Scenario: Observed successor already superseded
- **WHEN** session O's successor S1 has itself been superseded, and O is superseded again observing S1
- **THEN** the store refuses with the successor-advanced error and writes nothing

#### Scenario: Unpresented successor required
- **WHEN** session O's successor S1 has been presented, and O is superseded again observing S1 and requiring an unpresented successor
- **THEN** the store refuses with the successor-advanced error and writes nothing

### Requirement: A supersession keeps retention apart from the session's own deadlines
A supersession SHALL give the session it supersedes a retention deadline, the latest time its family could still be live, and SHALL NOT change that session's own idle and absolute deadlines.

#### Scenario: Own deadlines unchanged by the supersession
- **WHEN** a session with an idle deadline of 09:30 and an absolute deadline of 10:00 is superseded at 09:00 with a retention deadline of 21:00
- **THEN** the store returns it with 09:30 and 10:00 as its deadlines, and 21:00 as its retention deadline

### Requirement: Superseded sessions are returned by load and kept by the sweep
Loading a superseded session SHALL return it with its supersession state and its own deadlines, whether or not its window or its own deadlines have ended, until its retention deadline passes. The expiry sweep SHALL delete a superseded session only once its retention deadline has passed. A superseded session with no retention deadline, written before the retention deadline existed, SHALL be judged by its own deadlines.

#### Scenario: Load past the window
- **WHEN** a session superseded at 09:00 with a window ending at 09:00:30 is loaded at 12:00 through the store
- **THEN** the store returns it, reporting it superseded at 09:00 with window end 09:00:30

#### Scenario: Load past its own deadlines
- **WHEN** a session with an absolute deadline of 10:00, superseded at 09:00 with a retention deadline of 21:00, is loaded through the store at 12:00
- **THEN** the store returns it

#### Scenario: Sweep keeps a superseded session
- **WHEN** a session is superseded at 09:00 with a retention deadline of 21:00, and expired sessions are swept at 12:00
- **THEN** the superseded session is not deleted

#### Scenario: Sweep deletes it after retention
- **WHEN** the same sessions are swept at 21:01
- **THEN** the superseded session is deleted

### Requirement: Saving a superseded session keeps its deadlines
Saving a superseded session SHALL NOT change its deadlines or its retention deadline, so a copy loaded before the supersession cannot change them.

#### Scenario: Stale save keeps the deadlines
- **WHEN** a copy of a session with an idle deadline of 09:30 is loaded, the session is then superseded with a retention deadline of 21:00, and the earlier copy, with its idle deadline changed to 09:45, is saved
- **THEN** the stored session still reports 09:30 as its idle deadline and 21:00 as its retention deadline

### Requirement: A supersession writes only the sessions it supersedes
A supersession SHALL write only the session it supersedes, its previous successor if there is one, and the new successor. It SHALL NOT rewrite any other session of the family, so its cost does not grow with the number of earlier renewals.

#### Scenario: Earlier superseded sessions untouched
- **WHEN** session O is superseded by S1, S1 by S2, and S2 by S3
- **THEN** O's stored deadlines and supersession state are exactly as S1's supersession left them

### Requirement: A family is revoked by one delete
Durable session stores SHALL delete every session of one family in one operation, superseded or not, expired or not, and SHALL return how many were removed. Sessions of other families, including other families of the same user, SHALL be unaffected. A revocation that names no family (the nil identifier) SHALL be refused with an error and SHALL delete nothing.

#### Scenario: Nil family refused
- **WHEN** two users each hold a session, and a revocation names the nil family
- **THEN** it fails with an error
- **AND** both sessions still load

#### Scenario: Family revoked
- **WHEN** a family holds a superseded session and two successors, and the user has a session in another family, and the family is revoked
- **THEN** the revocation reports 3
- **AND** the user's other session still loads

### Requirement: A session's first presentation is recorded once
Durable session stores SHALL record when a session was first loaded successfully, in a write that sets the time only when none is recorded. A later recording SHALL leave the first time unchanged. Recording the first presentation of a superseded session SHALL write nothing and SHALL return the superseded-session error.

#### Scenario: First time kept
- **WHEN** a session's first presentation is recorded at 09:00 and again at 09:05
- **THEN** the session reports its first presentation at 09:00

#### Scenario: Superseded session not marked
- **WHEN** a session is superseded, and its first presentation is then recorded
- **THEN** the superseded-session error is returned and no presentation time is stored

### Requirement: Session family and supersession state survive a durable store
Durable session stores SHALL persist and return a session's family identifier, family start time, supersession time, window end, retention deadline, successor and first-presentation time exactly as written, at microsecond precision. A session that was never superseded or presented SHALL report none. Saving a session SHALL NOT change any of them.

#### Scenario: Round trip
- **WHEN** a session is created, superseded, its successor first presented, and both are loaded
- **THEN** every family, supersession and presentation value reads back as written

#### Scenario: Save leaves them unchanged
- **WHEN** a superseded session's loaded copy has its consumer data changed and is saved
- **THEN** its supersession state reads back unchanged

### Requirement: Superseded sessions do not count as active
Counting a user's active sessions SHALL count only unexpired sessions that are not superseded, so one sign-in counts once however often it is renewed.

#### Scenario: Renewed sign-in counts once
- **WHEN** a session is renewed three times with a 30-second grace, and the user's active sessions are counted after every window has ended
- **THEN** the count is 1

### Requirement: Recording activity never stores an idle deadline past the stored absolute deadline
Recording activity SHALL store an idle deadline no later than the absolute deadline the record holds when it is written, even when the caller computed it from an older copy.

#### Scenario: Absolute deadline lowered by another request
- **WHEN** a session's stored absolute deadline is lowered to 09:15 after a request loaded it, and that request then records activity with an idle deadline of 09:31
- **THEN** the stored idle deadline is 09:15

### Requirement: Every stored session belongs to a family
Creating a session in a store, or inserting a supersession's successor, SHALL be refused with an error, and nothing SHALL be written, when the session belongs to no family (the nil family identifier).

#### Scenario: Session with no family refused at creation
- **WHEN** a session whose family is the nil identifier is created through the store
- **THEN** the creation fails with an error and the session does not load

### Requirement: A supersession never lowers a retention deadline
A supersession SHALL NOT set a superseded session's retention deadline earlier than it was, and SHALL be refused with an error, writing nothing, when the retention deadline it gives is before its window's end.

#### Scenario: Retention before the window's end
- **WHEN** a session is superseded at 16:00 with a retention deadline of 15:00 and a window ending at 16:00:30
- **THEN** the supersession is refused and nothing is written

#### Scenario: A later supersession gives an earlier retention deadline
- **WHEN** a successor knocked out by a re-rotation already holds a retention deadline of 21:00, and the re-rotation gives a retention deadline of 18:00
- **THEN** the knocked-out successor keeps 21:00 as its retention deadline

### Requirement: Ending a user's other sessions keeps the presenting sign-in
Deleting every session of a user except a named one SHALL keep the named session and, when it belongs to a family, the family's current session, the one member not superseded, and SHALL delete every other session of the user, every other member of that family included, in one atomic operation.

#### Scenario: Named session inside its renewal window
- **WHEN** `u-1`'s session O is superseded by S1 with a window still open, `u-1` holds an unrelated session T, and `u-1`'s sessions except O are deleted
- **THEN** O and S1 still load, T does not, and 1 is returned

#### Scenario: Named session is the family's current one
- **WHEN** `u-1`'s session O is superseded by S1 with a window still open, and `u-1`'s sessions except S1 are deleted
- **THEN** S1 still loads and O does not
