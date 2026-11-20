## ADDED Requirements

### Requirement: The security-state set adds the device authorization table
The security-state migration set SHALL add one migration that creates the device authorization table, with an index for every lookup its store makes, and adds to the grants table the grant's origin and whether it survives its sign-in's end, with defaults that keep existing rows' meaning. Rolling it back SHALL drop exactly what it added. It SHALL apply to a database that already holds the provider's tables and their data.

#### Scenario: Apply to a populated database
- **WHEN** the migration is applied to a database holding grants and pending requests
- **THEN** the device authorization table exists, existing grants read as code grants that end with their sign-in as before, and the pending requests are unchanged

#### Scenario: Roll back
- **WHEN** the migration is rolled back
- **THEN** the device authorization table and the added grant columns no longer exist, and every other table and column is unchanged
