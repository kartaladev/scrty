## ADDED Requirements

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
