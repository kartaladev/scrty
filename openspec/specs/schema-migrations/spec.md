# schema-migrations Specification

## Purpose

Ships the security-state database schema as an embedded migration set in plain SQL with its own version table. Every migration applies atomically and rolls back completely, and consumers can run the set with goose or their own migration tool.

## Requirements

### Requirement: The security-state set creates only security-state tables
The security-state migration set SHALL create the tables for sessions, signing keys, login attempts, consecutive login failure counts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes, recovery records, passkey credentials, passkey user handles and shared rate-limit buckets. It SHALL create no identity tables, SHALL declare no foreign key to any table outside the set, SHALL store every library-owned primary key in a native uuid column (rate-limit buckets, which are keyed by namespace and key rather than by a library-owned identifier, excepted), and SHALL store every user reference in a text column. The set SHALL be embedded in the library as plain SQL, so applying it needs no files on disk.

#### Scenario: Fresh database
- **WHEN** the security-state set is applied to an empty database
- **THEN** the twenty-four security-state tables and the set's version table exist
- **AND** no users, roles, organizations, groups or privileges table exists

#### Scenario: Column types
- **WHEN** the set has been applied
- **THEN** every security-state table's primary key column has type uuid, except the rate-limit bucket table's
- **AND** every column holding a user reference has type text

#### Scenario: Single-use guards stay nullable
- **WHEN** the set has been applied
- **THEN** the consumption time columns of one-time tokens and handoffs, the completion time column of flows, the spending time column of saved recovery codes, and the completion and cancellation time columns of recovery records, are nullable and have no default

#### Scenario: Login attempt indexes
- **WHEN** the set has been applied
- **THEN** login attempts are indexed by login name and attempt time together
- **AND** separately by attempt time alone

#### Scenario: Saved codes are unique per user and hash
- **WHEN** the set has been applied
- **THEN** saved recovery codes are unique by user reference and hash together
- **AND** recovery records are indexed by user reference

#### Scenario: Passkey uniqueness
- **WHEN** the set has been applied
- **THEN** passkey credentials are unique by credential ID and indexed by user reference
- **AND** passkey user handles are unique by handle, and unique by user reference

#### Scenario: Session marker column
- **WHEN** the set has been applied
- **THEN** the sessions table has a non-null boolean column for the met-by-first-factor marker, defaulting to false

#### Scenario: Federated assurance columns
- **WHEN** the set has been applied
- **THEN** the sessions table and the OIDC handoffs table each have a non-null column for the asserted `amr` values, defaulting to an empty list, and a non-null text column for the asserted `acr`, defaulting to the empty string

#### Scenario: Consecutive failure counts
- **WHEN** the set has been applied
- **THEN** consecutive failure counts are unique per login name, and the time an identifier became held is nullable with no default

#### Scenario: Rate-limit bucket table
- **WHEN** the set has been applied
- **THEN** the rate-limit bucket table is a logged table keyed by namespace and key together
- **AND** it has no index other than that key
- **AND** it declares its own fill factor and autovacuum storage parameters

### Requirement: The set records its versions in its own version table
Applying the security-state set SHALL record its applied migrations in a version table used by no other migration set. By default the table SHALL be named `goose_security_state`. A consumer SHALL be able to use another name. Applying or rolling back another migration set SHALL NOT read or change this table.

#### Scenario: Default version table
- **WHEN** the set is applied with the default version table name
- **THEN** its applied versions are recorded in `goose_security_state`

#### Scenario: Consumer version table
- **WHEN** a consumer applies the set with version table name `auth_schema_versions`
- **THEN** its applied versions are recorded in `auth_schema_versions`
- **AND** no `goose_security_state` table is created

#### Scenario: Independent from the identity set
- **WHEN** both the security-state set and another migration set are applied, and the other set is rolled back to zero
- **THEN** every security-state table and its recorded versions remain

### Requirement: Migrations apply in order, once, and atomically
Applying the set SHALL run every pending migration in ascending version order. Applying an up-to-date database SHALL change nothing. Each migration SHALL be applied in its own transaction, so a migration that fails leaves none of its changes and no version record.

#### Scenario: Re-applying is a no-op
- **WHEN** the set is applied twice to the same database
- **THEN** the second application succeeds and changes no table or version record

#### Scenario: Failing migration leaves nothing
- **WHEN** a migration fails partway through its statements
- **THEN** applying returns an error
- **AND** none of that migration's statements took effect and its version is not recorded

### Requirement: Every migration can be rolled back, and full rollback leaves nothing behind
Every migration in the set SHALL have a rollback section that reverses exactly what its apply section created or changed. Rolling back to zero SHALL leave no table from the set, other than the version table. Rollback SHALL complete even when a table it drops no longer exists.

#### Scenario: Full rollback
- **WHEN** the set is applied and then rolled back to zero
- **THEN** no security-state table remains
- **AND** the version table records no applied version

#### Scenario: Table already dropped
- **WHEN** a test drops a security-state table to simulate an outage and the set is then rolled back to zero
- **THEN** the rollback succeeds

#### Scenario: A single migration's rollback
- **WHEN** only the rollback section of one migration is executed against a database migrated to the latest version
- **THEN** exactly the changes of that migration's apply section are removed

#### Scenario: Re-apply after rollback
- **WHEN** the set is rolled back to zero and applied again
- **THEN** applying succeeds and every security-state table exists

### Requirement: Consumers can run the set with goose or their own tool
The migration files SHALL be plain SQL in goose's annotated up/down format, and SHALL be readable from the library as embedded files. Running the files with goose SHALL produce every table, column and index the set defines, and any other tool that understands that format SHALL produce the same result as goose.

#### Scenario: Applied with goose directly
- **WHEN** a consumer applies the embedded files with goose, using their own version table name
- **THEN** every security-state table, column and index exists as the set defines it

#### Scenario: Rolled back with goose directly
- **WHEN** the same consumer rolls the files back to zero with goose
- **THEN** no security-state table remains

### Requirement: Released migrations are never edited, and later migrations apply to populated databases
After the first release, migration files SHALL NOT be edited, and schema changes SHALL be added as new migrations. Every added migration SHALL apply successfully to a database whose tables contain rows, and SHALL leave existing rows readable.

#### Scenario: New non-nullable column on a populated table
- **WHEN** a migration that adds a non-nullable column is applied to a database whose table already holds rows
- **THEN** the migration applies successfully
- **AND** the existing rows read back through the stores without error

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

### Requirement: The security-state set adds the session retention deadline
The same migration SHALL add a nullable retention deadline to the sessions table, with no default, and SHALL leave it null for every existing row. Rolling it back SHALL remove the column.

#### Scenario: Existing rows have none
- **WHEN** the migration is applied to a database holding sessions created before it
- **THEN** each existing session reads back with no retention deadline

### Requirement: The security-state set adds the session authentication time
The same migration SHALL add a non-null authentication time to the sessions table, defaulting to the insert time, and SHALL backfill each existing row with the later of its creation time and its second-factor satisfaction time. Rolling it back SHALL remove the column.

#### Scenario: Existing session backfilled
- **WHEN** the migration is applied to a session created at 09:00 whose second factor was satisfied at 09:20
- **THEN** the session reports 09:20 as its authentication time

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

### Requirement: The security-state set adds session sign-in metadata and key binding
The security-state migration set SHALL gain one new migration that adds nullable columns for a session's sign-in client address, user agent, key-binding kind, key-binding thumbprint and sealed CSRF token. It SHALL add no index, because listing a user's sessions uses the existing index on the user reference. It SHALL apply to a populated database without rewriting existing rows, leave existing sessions unbound and without metadata, and roll back completely. Released migrations SHALL NOT be edited.

#### Scenario: Populated database
- **WHEN** the new migration is applied to a database holding live sessions
- **THEN** every existing session still loads, unbound, without metadata and without a CSRF token

#### Scenario: Rollback
- **WHEN** the new migration is rolled back
- **THEN** the added columns are gone and the earlier migrations' schema is unchanged

### Requirement: The security-state set adds the provider's tables
The security-state migration set SHALL add one migration that creates the provider's tables: clients, pending requests, browser sessions, authorization codes, consents, grants, refresh-token lineages, opaque access tokens and client-assertion identifiers. It SHALL create an index for every lookup the stores make. Rolling it back SHALL drop exactly those tables. It SHALL apply to a database that already holds earlier migrations and their data.

#### Scenario: Apply to a populated database
- **WHEN** the migration is applied to a database with existing sessions
- **THEN** the provider's tables exist, and the sessions are unchanged

#### Scenario: Roll back
- **WHEN** the migration is rolled back
- **THEN** none of the provider's tables remains, and every other table is unchanged

### Requirement: The security-state set adds the device authorization table
The security-state migration set SHALL add one migration that creates the device authorization table, with an index for every lookup its store makes, adds to the grants table the grant's origin and whether it survives its sign-in's end, with defaults that keep existing rows' meaning. Rolling it back SHALL drop exactly what it added. It SHALL apply to a database that already holds the provider's tables and their data.

#### Scenario: Apply to a populated database
- **WHEN** the migration is applied to a database holding grants and pending requests
- **THEN** the device authorization table exists, existing grants read as code grants that end with their sign-in as before, and the pending requests are unchanged

#### Scenario: Roll back
- **WHEN** the migration is rolled back
- **THEN** the device authorization table and the added grant and pending-request columns no longer exist, and every other table and column is unchanged

### Requirement: The security-state set links pending requests to device authorizations
The same migration SHALL add to the pending-request table the device authorization a request was parked for and its claimed user code, both empty for existing rows, and its rollback SHALL drop them.

#### Scenario: Existing pending requests
- **WHEN** the migration is applied to a database holding pending requests
- **THEN** each existing pending request names no device authorization and holds no user code

### Requirement: Every relation the security-state set creates carries the scrty_ prefix
Once the security-state set is at its latest version, every table, index, index-backed constraint and sequence it created SHALL be named `scrty_` followed by its former name, within PostgreSQL's 63-byte limit. The prefix SHALL be fixed. The version table SHALL keep its default or consumer-chosen name. A consumer SHALL be able to apply the set in a schema of their own, which the stores find through `search_path`.

#### Scenario: Fresh database
- **WHEN** the security-state set is applied to an empty database
- **THEN** every table, index and sequence it created is named with the prefix `scrty_`, among them `scrty_sessions`, `scrty_rate_limit_buckets`, `scrty_op_device_authorizations` and `scrty_sessions_pkey`
- **AND** no table, index or sequence it created has a name without the prefix
- **AND** its applied versions are recorded in `goose_security_state`

#### Scenario: Consumer tables of the old names in the same schema
- **WHEN** the set has been applied to its latest version, and the consumer then creates their own tables `sessions` and `users` in the same schema
- **THEN** both tables are created
- **AND** the stores keep reading and writing only the prefixed tables

#### Scenario: Consumer schema
- **WHEN** a consumer applies the set in a schema of their own, `auth`, and connects with `search_path` set to `auth`
- **THEN** every prefixed table exists in `auth`
- **AND** every durable store and the shared rate limiter work against it, and the limiter's construction-time check passes

#### Scenario: Names fit the identifier limit
- **WHEN** the set has been applied
- **THEN** no name of a relation it created is longer than 63 bytes

### Requirement: The security-state set renames existing relations in place
The security-state set SHALL gain one migration that renames every relation the earlier migrations created to its `scrty_` name, without copying, rewriting or dropping data. It SHALL apply atomically, SHALL fail rather than wait unboundedly for a lock, and its rollback SHALL restore the previous names. Released migrations SHALL NOT be edited.

#### Scenario: Populated database
- **WHEN** the rename migration is applied to a database whose tables already hold sessions, signing keys, OIDC provider grants, device authorizations and rate-limit buckets
- **THEN** the migration succeeds
- **AND** every one of those rows reads back through the stores under the new names

#### Scenario: A table is held by another transaction
- **WHEN** another transaction holds a lock on the sessions table, and the rename migration is applied
- **THEN** applying fails within the bounded wait, about five seconds, with an error
- **AND** every relation keeps its previous name and the version is not recorded
- **AND** applying again once the lock is released succeeds

#### Scenario: The new name is already taken
- **WHEN** the schema already holds a relation named `scrty_sessions` that the set did not create, and the rename migration is applied
- **THEN** applying fails with an error
- **AND** every relation keeps its previous name, the existing `scrty_sessions` is unchanged, and the version is not recorded

#### Scenario: Rolling back the rename
- **WHEN** the set is at its latest version and only the rename migration is rolled back
- **THEN** every table, index, constraint and sequence has the name it had before the migration
- **AND** the tables, columns, indexes and constraints are otherwise identical to the schema before the migration

#### Scenario: Full rollback and re-apply
- **WHEN** the set is rolled back to zero and applied again
- **THEN** no relation from the set remains after the rollback
- **AND** after re-applying, every relation carries the prefix

### Requirement: The identity set adds the administration columns and tables
The identity migration set SHALL add one migration, after the prefix migration, that adds to users an email, its verification time, a deletion time and a version; to roles a display name, a description, labels and a version; to privileges a scope; and a profile attribute table. Every added relation SHALL carry the `scrty_` prefix.

#### Scenario: Apply to a populated database
- **WHEN** the migration is applied to a database holding users, roles and privileges
- **THEN** existing users have no email, are not deleted and have version 1, existing roles have an empty display name, description and labels and version 1, and existing privileges have scope `all`

#### Scenario: Prefix
- **WHEN** the migration has been applied
- **THEN** the attribute table and every index the migration creates carry the `scrty_` prefix

### Requirement: Live users' emails are unique, ignoring case
The same migration SHALL create a unique index over the lower-cased email of users that are not deleted and have an email. The migration SHALL apply in one transaction, so a database it cannot change, such as one where a consumer already added an `email` column to the users table, fails and keeps nothing the migration added.

#### Scenario: Consumer already added an email column
- **WHEN** the migration is applied to a database whose users table already has a consumer's `email` column
- **THEN** the migration fails, and no column, table or index it would add exists afterwards

### Requirement: The administration migration rolls back exactly what it added
Rolling the identity administration migration back SHALL drop exactly the columns, table and indexes it added, and SHALL leave every other relation and every row of the earlier tables as they were.

#### Scenario: Roll back
- **WHEN** the migration is rolled back on a database holding users with emails and attributes
- **THEN** the added columns, the attribute table and its indexes no longer exist, and each user's other columns are unchanged

### Requirement: The security-state set adds the selected-role column
The security-state migration set SHALL add one migration, after the prefix migration, that adds a nullable selected-role column to sessions and to the refresh-token lineage table, which keeps the sessions table's columns, empty for existing rows. Rolling it back SHALL drop exactly those columns.

#### Scenario: Existing sessions
- **WHEN** the migration is applied to a database holding sessions
- **THEN** every existing session has no selected role and is otherwise unchanged

#### Scenario: The lineage table keeps the sessions table's columns
- **WHEN** the migration is applied
- **THEN** the refresh-token lineage table has the same columns as the sessions table, including the selected-role column
