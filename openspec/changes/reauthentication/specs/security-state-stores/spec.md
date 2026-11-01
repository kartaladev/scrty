# Spec Delta

## ADDED Requirements

### Requirement: Session stores keep whether a supersession was a rotation without grace
Every session store SHALL record, with a supersession, whether the caller made it as a rotation without grace, and SHALL return that mark when the superseded session is loaded, until its retention deadline passes. Creating or saving a session SHALL NOT write the mark. Saving a session whose stored record carries the mark SHALL fail with the not-found error and write nothing. A session stored before the mark existed SHALL load unmarked.

#### Scenario: Mark returned on load
- **WHEN** a session is superseded as a rotation without grace and then loaded through the store
- **THEN** the store returns it superseded and marked as rotated without grace

#### Scenario: A grace supersession is unmarked
- **WHEN** a session is superseded with a grace window and then loaded through the store
- **THEN** the store returns it superseded and not marked

#### Scenario: Save does not write the mark
- **WHEN** a consumer sets the mark on a loaded, unsuperseded session and saves it
- **THEN** the stored session loads unmarked

#### Scenario: Saving a strictly rotated session is refused
- **WHEN** a copy of a session loaded before it was superseded as a rotation without grace is saved
- **THEN** the save fails with the not-found error and the stored record is unchanged

#### Scenario: Swept at its retention deadline
- **WHEN** a session marked as rotated without grace has a retention deadline of 09:00:30 and the sweep runs at 09:00:31
- **THEN** the session is no longer stored
