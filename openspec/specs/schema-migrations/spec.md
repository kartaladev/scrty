# schema-migrations Specification

## Purpose

Ships the security-state database schema as an embedded migration set in plain SQL with its own version table. Every migration applies atomically and rolls back completely, and consumers can run the set with goose or their own migration tool.

## Requirements

### Requirement: The security-state set creates only security-state tables
The security-state migration set SHALL create the tables for sessions, signing keys, login attempts, consecutive login failure counts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes, recovery records, passkey credentials, passkey user handles and shared rate-limit buckets. It SHALL create no identity tables, SHALL declare no foreign key to any table outside the set, SHALL store every library-owned primary key in a native uuid column (rate-limit buckets, which are keyed by namespace and key rather than by a library-owned identifier, excepted), and SHALL store every user reference in a text column. The set SHALL be embedded in the library as plain SQL, so applying it needs no files on disk.

#### Scenario: Fresh database
- **WHEN** the security-state set is applied to an empty database
- **THEN** the fifteen security-state tables and the set's version table exist
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
