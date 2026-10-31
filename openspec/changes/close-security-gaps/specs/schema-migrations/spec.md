## ADDED Requirements

### Requirement: A security-state migration adds session metadata, key binding and the user listing index
The security-state migration set SHALL gain one new migration that adds nullable columns for a session's sign-in client address, user agent and key-binding thumbprint, and an index supporting the listing of a user's sessions. It SHALL apply to a populated database without rewriting existing rows, leave existing sessions unbound and without metadata, and roll back completely. Released migrations SHALL NOT be edited.

#### Scenario: Populated database
- **WHEN** the new migration is applied to a database holding live sessions
- **THEN** every existing session still loads, unbound and without metadata

#### Scenario: Rollback
- **WHEN** the new migration is rolled back
- **THEN** the added columns and index are gone and the earlier migrations' schema is unchanged
