## ADDED Requirements

### Requirement: An issued token can carry a confirmation claim
When the caller supplies a key binding, the issued token SHALL carry a `cnf` claim: `jkt` with a DPoP key thumbprint, or `x5t#S256` with a certificate thumbprint, never both. Without a binding, the token SHALL carry no `cnf` claim. A verifier SHALL return the confirmation claim to its caller, and SHALL refuse a token whose `cnf` claim is malformed.

#### Scenario: DPoP-bound token
- **WHEN** a token is issued with DPoP key thumbprint `K`
- **THEN** its claims carry `cnf` `{"jkt": "K"}`

#### Scenario: Unbound token
- **WHEN** a token is issued with no binding
- **THEN** its claims carry no `cnf`
