# Spec Delta

## ADDED Requirements

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
