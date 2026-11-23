## ADDED Requirements

### Requirement: Every relation the identity set creates carries the scrty_ prefix
Once the identity set is at its latest version, every table, index, index-backed constraint and sequence it created, the password history's identity sequence included, SHALL be named `scrty_` followed by its former name. The identity version table SHALL keep its default or consumer-chosen name. A consumer may apply the set in a schema of their own, which the identity store finds through `search_path`.

#### Scenario: Identity set alone
- **WHEN** only the identity set is applied to an empty database
- **THEN** `scrty_users`, `scrty_roles`, `scrty_assigned_roles`, `scrty_organizations`, `scrty_groups`, `scrty_resource_privileges` and `scrty_password_history` exist
- **AND** no table, index or sequence the set created has a name without the prefix
- **AND** its applied versions are recorded in `goose_identity`

#### Scenario: Consumer's own users table
- **WHEN** the identity set has been applied to its latest version, and the consumer then creates their own `users` table in the same schema
- **THEN** the table is created
- **AND** the identity store keeps reading and writing only `scrty_users`

### Requirement: The identity set renames existing relations in place, independently of security state
The identity set SHALL gain its own migration that renames every table, index and sequence the earlier identity migrations created to its `scrty_` name. It SHALL keep every row and the password history's sequence position, SHALL apply in its own transaction with a bounded lock wait, and SHALL roll back to the previous names. Applying or rolling back the identity rename SHALL NOT require, read or change the security-state set or its version table, and the reverse SHALL hold as well.

#### Scenario: Populated identity database
- **WHEN** the identity rename migration is applied to a database holding users, role grants and password history
- **THEN** every user, grant and history entry reads back through the identity store
- **AND** the next password history entry recorded is ordered after every existing one

#### Scenario: One set renamed, the other not yet
- **WHEN** the security-state set is at its latest version and the identity set is still at the version before its rename
- **THEN** every security-state store works
- **AND** applying the identity rename afterwards succeeds and changes no security-state relation

#### Scenario: Rolling back the identity rename
- **WHEN** only the identity rename migration is rolled back
- **THEN** every identity relation has its previous name
- **AND** every security-state relation and its version records are unchanged
