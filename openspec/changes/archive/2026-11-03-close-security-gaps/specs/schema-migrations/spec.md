## ADDED Requirements

### Requirement: The security-state set adds session sign-in metadata and key binding
The security-state migration set SHALL gain one new migration that adds nullable columns for a session's sign-in client address, user agent, key-binding kind, key-binding thumbprint and sealed CSRF token. It SHALL add no index, because listing a user's sessions uses the existing index on the user reference. It SHALL apply to a populated database without rewriting existing rows, leave existing sessions unbound and without metadata, and roll back completely. Released migrations SHALL NOT be edited.

#### Scenario: Populated database
- **WHEN** the new migration is applied to a database holding live sessions
- **THEN** every existing session still loads, unbound, without metadata and without a CSRF token

#### Scenario: Rollback
- **WHEN** the new migration is rolled back
- **THEN** the added columns are gone and the earlier migrations' schema is unchanged
