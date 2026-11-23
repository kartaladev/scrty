## ADDED Requirements

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
