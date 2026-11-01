# Spec Delta

## ADDED Requirements

### Requirement: The security-state set adds the session strict-rotation mark
A new security-state migration SHALL add to the sessions table a non-null boolean mark of a supersession made as a rotation without grace, defaulting to false, and SHALL leave it false for every existing row. Rolling it back SHALL remove exactly that column.

#### Scenario: Column after applying
- **WHEN** the set has been applied
- **THEN** the sessions table has a non-null boolean strict-rotation column defaulting to false

#### Scenario: Existing rows unmarked
- **WHEN** the migration is applied to a database holding superseded and unsuperseded sessions created before it
- **THEN** each reads back through the stores as not rotated without grace

#### Scenario: An older writer's insert
- **WHEN** after the migration a session is inserted by a statement that does not name the column
- **THEN** the insert succeeds and the row is unmarked

#### Scenario: Rolled back
- **WHEN** the migration is rolled back
- **THEN** the sessions table has exactly the columns and indexes it had before it
