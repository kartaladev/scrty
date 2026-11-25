# Spec Delta

## ADDED Requirements

### Requirement: The security-state set is one baseline migration
The security-state set SHALL consist of one baseline migration that creates every relation of the set directly under its `scrty_` name. It SHALL create no relation under an unprefixed name at any point, so it applies to a schema that already holds a consumer's `sessions` or `users` table. Later schema changes SHALL be added as new migrations after the baseline.

#### Scenario: Beside a consumer's tables of the same names
- **WHEN** the set is applied to a schema that already holds the consumer's own `sessions` and `users` tables
- **THEN** applying succeeds and every `scrty_` table exists
- **AND** the consumer's tables and their rows are unchanged

#### Scenario: One migration recorded
- **WHEN** the set is applied to an empty database
- **THEN** its version table records exactly one applied migration

### Requirement: The baseline produces the schema of the earlier chain
The schema the security-state baseline creates SHALL equal the schema the set's earlier migrations produced once all were applied: the same tables and their persistence and storage parameters, the same columns in the same order with their types, nullability, defaults and identity generation, the same index names and definitions, the same sequences, and the same constraint definitions. Only the names of constraints that no index backs MAY differ.

#### Scenario: Catalog equivalence
- **WHEN** the baseline is applied to an empty database
- **THEN** its tables, columns, indexes, sequences and constraint definitions match the recorded inventory of the earlier chain's final schema

### Requirement: The baseline does not adopt existing relations
The security-state baseline SHALL fail when the schema already holds any relation it creates, and SHALL then leave no relation of its own behind and record no applied version. It SHALL NOT detect or upgrade a database migrated by an earlier release; such a database is recreated.

#### Scenario: Relation already present
- **WHEN** the set is applied to a database that already holds a relation the baseline creates late in its order, such as `scrty_rate_limit_buckets`
- **THEN** applying fails
- **AND** none of the set's other relations exists and no version is recorded

## MODIFIED Requirements

### Requirement: The security-state set creates only security-state tables
The security-state migration set SHALL create the tables for sessions, signing keys, login attempts, consecutive login failure counts, MFA enrolments, API keys, one-time tokens, OIDC links, OIDC flows, OIDC handoffs, saved recovery codes, recovery records, passkey credentials, passkey user handles and shared rate-limit buckets. It SHALL create no identity tables, SHALL declare no foreign key to any table outside the set, SHALL store every library-owned primary key in a native uuid column (rate-limit buckets, which are keyed by namespace and key rather than by a library-owned identifier, excepted), and SHALL store every user reference in a text column. The set SHALL be embedded in the library as plain SQL, so applying it needs no files on disk.

#### Scenario: Fresh database
- **WHEN** the security-state set is applied to an empty database
- **THEN** the twenty-five security-state tables and the set's version table exist
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
Applying the security-state set SHALL record its applied migrations in a version table used by no other migration set. By default the table SHALL be named `scrty_state_migrate`. A consumer SHALL be able to use another name. Applying or rolling back another migration set SHALL NOT read or change this table.

#### Scenario: Default version table
- **WHEN** the set is applied with the default version table name
- **THEN** its applied versions are recorded in `scrty_state_migrate`

#### Scenario: Consumer version table
- **WHEN** a consumer applies the set with version table name `auth_schema_versions`
- **THEN** its applied versions are recorded in `auth_schema_versions`
- **AND** no `scrty_state_migrate` table is created

#### Scenario: Independent from the identity set
- **WHEN** both the security-state set and another migration set are applied, and the other set is rolled back to zero
- **THEN** every security-state table and its recorded versions remain

### Requirement: Released migrations are never edited, and later migrations apply to populated databases
From the release that introduces the baseline, migration files SHALL NOT be edited or removed, and schema changes SHALL be added as new migrations after the baseline. Every added migration SHALL apply successfully to a database whose tables contain rows, and SHALL leave existing rows readable.

#### Scenario: New non-nullable column on a populated table
- **WHEN** a migration that adds a non-nullable column is applied to a database whose table already holds rows
- **THEN** the migration applies successfully
- **AND** the existing rows read back through the stores without error

### Requirement: Every relation the security-state set creates carries the scrty_ prefix
Every table, index, index-backed constraint and sequence the security-state set creates SHALL be named with the `scrty_` prefix, within PostgreSQL's 63-byte limit. The prefix SHALL be fixed. The version table SHALL keep its default or consumer-chosen name. A consumer SHALL be able to apply the set in a schema of their own, which the stores find through `search_path`.

#### Scenario: Fresh database
- **WHEN** the security-state set is applied to an empty database
- **THEN** every table, index and sequence it created is named with the prefix `scrty_`, among them `scrty_sessions`, `scrty_rate_limit_buckets`, `scrty_op_device_authorizations` and `scrty_sessions_pkey`
- **AND** no table, index or sequence it created has a name without the prefix
- **AND** its applied versions are recorded in `scrty_state_migrate`

#### Scenario: Consumer tables of the old names in the same schema
- **WHEN** the set has been applied, and the consumer then creates their own tables `sessions` and `users` in the same schema
- **THEN** both tables are created
- **AND** the stores keep reading and writing only the prefixed tables

#### Scenario: Consumer schema
- **WHEN** a consumer applies the set in a schema of their own, `auth`, and connects with `search_path` set to `auth`
- **THEN** every prefixed table exists in `auth`
- **AND** every durable store and the shared rate limiter work against it, and the limiter's construction-time check passes

#### Scenario: Names fit the identifier limit
- **WHEN** the set has been applied
- **THEN** no name of a relation it created is longer than 63 bytes

### Requirement: Live users' emails are unique, ignoring case
The identity set SHALL create a unique index over the lower-cased email of users that are not deleted and have an email. The identity baseline SHALL apply in one transaction, so a database it cannot change fails and keeps nothing the baseline added.

#### Scenario: Consumer already added an email column
- **WHEN** the identity baseline is applied to a database that already holds a `scrty_users` table, such as one where a consumer created it with their own `email` column
- **THEN** the migration fails, and no column, table or index it would add exists afterwards

#### Scenario: Two live users differing only by case
- **WHEN** a user with email `Ana@example.com` exists, and another live user is stored with `ana@example.com`
- **THEN** the second write fails on the unique index

#### Scenario: A deleted user's email is free
- **WHEN** the user with email `ana@example.com` is deleted, and another user is stored with that email
- **THEN** the write succeeds

## REMOVED Requirements

### Requirement: The security-state set adds session family and supersession columns
**Reason**: The set is one baseline migration; there is no separate migration that adds these columns to existing rows.
**Migration**: The columns are part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain". A database migrated by an earlier release is recreated.

### Requirement: The security-state set adds the session retention deadline
**Reason**: The set is one baseline migration; there is no separate migration that adds this column.
**Migration**: The column is part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set adds the session authentication time
**Reason**: The set is one baseline migration; there is no backfill of existing rows.
**Migration**: The column is part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set adds the session strict-rotation mark
**Reason**: The set is one baseline migration; there is no separate migration that adds this column.
**Migration**: The column is part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set adds session sign-in metadata and key binding
**Reason**: The set is one baseline migration; there is no separate migration that adds these columns.
**Migration**: The columns are part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set adds the provider's tables
**Reason**: The set is one baseline migration; the provider's tables are created with the rest.
**Migration**: The tables are part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set adds the device authorization table
**Reason**: The set is one baseline migration; the device authorization table is created with the rest.
**Migration**: The table and columns are part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set links pending requests to device authorizations
**Reason**: The set is one baseline migration; there is no separate migration that adds these columns.
**Migration**: The columns are part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".

### Requirement: The security-state set renames existing relations in place
**Reason**: The baseline creates every relation under its `scrty_` name, so there is nothing to rename.
**Migration**: A database migrated by an earlier release is recreated before the baseline is applied.

### Requirement: The identity set adds the administration columns and tables
**Reason**: The identity set is one baseline migration that creates these columns and tables with the rest.
**Migration**: They are part of the identity baseline's schema, pinned by the identity set's equivalence requirement.

### Requirement: The administration migration rolls back exactly what it added
**Reason**: There is no separate administration migration to roll back; the identity baseline rolls back as a whole.
**Migration**: Rolling the identity set back to zero removes every identity relation.

### Requirement: The security-state set adds the selected-role column
**Reason**: The set is one baseline migration; there is no separate migration that adds this column.
**Migration**: The column is part of the baseline's schema, pinned by "The baseline produces the schema of the earlier chain".
