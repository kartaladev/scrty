# Spec Delta

## ADDED Requirements

### Requirement: The identity set is one baseline migration
The identity set SHALL consist of one baseline migration that creates every identity relation, the administration columns and tables included, directly under its `scrty_` name. It SHALL create no relation under an unprefixed name at any point, so it applies to a schema that already holds a consumer's `users` or `roles` table. Later schema changes SHALL be added as new migrations after the baseline.

#### Scenario: Beside a consumer's users table
- **WHEN** the identity set is applied to a schema that already holds the consumer's own `users` table with rows
- **THEN** applying succeeds and `scrty_users` exists
- **AND** the consumer's `users` table and its rows are unchanged

#### Scenario: One migration recorded
- **WHEN** the identity set is applied to an empty database
- **THEN** its version table records exactly one applied migration

### Requirement: The identity baseline produces the schema of the earlier chain
The schema the identity baseline creates SHALL equal the schema the identity set's earlier migrations produced once all were applied: the same tables, columns, column types, nullability and defaults, the same index names and definitions, the same sequences, and the same constraint definitions. Only the names of constraints that no index backs MAY differ.

#### Scenario: Catalog equivalence
- **WHEN** the identity baseline is applied to an empty database
- **THEN** its tables, columns, indexes, sequences and constraint definitions match the recorded inventory of the earlier chain's final schema

### Requirement: An identity database migrated by an earlier release is refused
The identity baseline SHALL fail, and change nothing, when the schema holds the earlier default version table `goose_identity` with an applied migration recorded in it, or already holds a relation the baseline creates. The error SHALL say that the database was migrated by an earlier release and must be recreated.

#### Scenario: Earlier history present
- **WHEN** the identity set is applied to a database whose `goose_identity` table records applied migrations
- **THEN** applying fails with an error naming an earlier release
- **AND** no identity relation is created and no version is recorded

#### Scenario: Relation already present
- **WHEN** the identity set is applied to a database that already holds `scrty_users`
- **THEN** applying fails
- **AND** no other identity relation is created and no version is recorded

## MODIFIED Requirements

### Requirement: Every relation the identity set creates carries the scrty_ prefix
Every table, index, index-backed constraint and sequence the identity set creates, the password history's identity sequence included, SHALL be named with the `scrty_` prefix. The identity version table SHALL keep its default or consumer-chosen name; its default SHALL be `scrty_identity_migrate`. A consumer may apply the set in a schema of their own, which the identity store finds through `search_path`.

#### Scenario: Identity set alone
- **WHEN** only the identity set is applied to an empty database
- **THEN** `scrty_users`, `scrty_roles`, `scrty_assigned_roles`, `scrty_organizations`, `scrty_groups`, `scrty_resource_privileges` and `scrty_password_history` exist
- **AND** no table, index or sequence the set created has a name without the prefix
- **AND** its applied versions are recorded in `scrty_identity_migrate`

#### Scenario: Consumer's own users table
- **WHEN** the identity set has been applied, and the consumer then creates their own `users` table in the same schema
- **THEN** the table is created
- **AND** the identity store keeps reading and writing only `scrty_users`

## REMOVED Requirements

### Requirement: The identity set renames existing relations in place, independently of security state
**Reason**: The identity baseline creates every relation under its `scrty_` name, so there is nothing to rename.
**Migration**: A database migrated by an earlier release is refused by the identity baseline and must be recreated.
