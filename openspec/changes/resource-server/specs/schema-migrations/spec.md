## ADDED Requirements

### Requirement: The security-state set records how each sign-in was proved
The security-state migration set SHALL gain one new migration, after the folded baseline, that adds nullable columns for a sign-in's second-factor marker and federated evidence (provider, issuer, `amr`, `acr`) to grants, authorization codes and browser sessions. The migration SHALL apply to a populated database without rewriting existing rows and roll back completely. Released migrations SHALL NOT be edited.

#### Scenario: Populated database
- **WHEN** the new migration is applied to a database holding grants, codes and browser sessions
- **THEN** every existing record still loads, with no second-factor marker and no federated evidence

#### Scenario: Sign-in documents need no column
- **WHEN** the migration is applied
- **THEN** pending requests and device authorizations gain no column, and carry the values in their stored sign-in documents

#### Scenario: Rollback
- **WHEN** the new migration is rolled back
- **THEN** the added columns are gone and the baseline's schema is unchanged
