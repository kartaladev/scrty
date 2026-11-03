# Spec Delta

## ADDED Requirements

### Requirement: The security-state set adds the provider's tables
The security-state migration set SHALL add one migration that creates the provider's tables: clients, pending requests, authorization codes, consents, grants, refresh-token lineages, opaque access tokens and client-assertion identifiers. It SHALL create indexes for every lookup the stores make, including grants by user, by user and client, and by sign-in. Rolling it back SHALL drop exactly those tables. It SHALL apply to a database that already holds earlier migrations and their data.

#### Scenario: Apply to a populated database
- **WHEN** the migration is applied to a database with existing sessions
- **THEN** the provider's tables exist, and the sessions are unchanged

#### Scenario: Roll back
- **WHEN** the migration is rolled back
- **THEN** none of the provider's tables remains, and every other table is unchanged
