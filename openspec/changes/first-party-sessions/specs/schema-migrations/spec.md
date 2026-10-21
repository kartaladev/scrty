## ADDED Requirements

### Requirement: The security-state set adds session family and supersession columns
A new security-state migration SHALL add to the sessions table: a non-null uuid family identifier, indexed, defaulting to a generated identifier; a non-null family start time, defaulting to the insert time; nullable supersession time, window end, successor digest and first-presentation time, with no default. Existing rows SHALL be backfilled with their own primary key as family identifier and their creation time as family start. Rolling it back SHALL remove exactly those columns and the index.

#### Scenario: Columns after applying
- **WHEN** the set has been applied
- **THEN** the sessions table has a non-null uuid family column with an index, and a non-null family start column
- **AND** its supersession time, window end, successor digest and first-presentation columns are nullable with no default

#### Scenario: Populated table backfilled
- **WHEN** the migration is applied to a database holding sessions created before it
- **THEN** each existing session reads back through the stores as the sole member of a family whose identifier is its row's primary key, started at its creation time

#### Scenario: Rolled back
- **WHEN** the migration is rolled back
- **THEN** the sessions table has exactly the columns and indexes it had before it

#### Scenario: An older writer's insert
- **WHEN** after the migration a session is inserted by a statement that names neither family column
- **THEN** the insert succeeds, and the row has a family identifier and a family start time
