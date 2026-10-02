# Spec Delta

## MODIFIED Requirements

### Requirement: Sessions can be deleted singly, per user and when expired
The manager SHALL:
- delete a single session;
- delete every session of a user;
- delete every session of a user except one named session, in one atomic operation, returning how many were removed; a named session that belongs to another user, or does not exist, SHALL NOT stop the user's other sessions from being deleted and SHALL itself be left untouched;
- count a user's unexpired sessions, excluding expired ones;
- delete every expired session, returning how many were removed.

The user reference SHALL be matched exactly as the consumer supplied it.

#### Scenario: Delete per user
- **WHEN** user `u-1` has three sessions and user `u-2` has one, and the sessions of `u-1` are deleted
- **THEN** no session of `u-1` loads
- **AND** the session of `u-2` still loads

#### Scenario: Delete per user except one
- **WHEN** user `u-1` has sessions `s-1`, `s-2` and `s-3`, user `u-2` has one, and the sessions of `u-1` except `s-1` are deleted
- **THEN** 2 is returned, `s-1` still loads, `s-2` and `s-3` do not, and the session of `u-2` still loads

#### Scenario: The kept session is another user's
- **WHEN** the sessions of `u-1` except `u-2`'s session are deleted
- **THEN** every session of `u-1` is deleted and `u-2`'s session still loads

#### Scenario: Count excludes expired
- **WHEN** user `u-1` has two valid sessions and one expired session
- **THEN** counting the active sessions of `u-1` returns 2
