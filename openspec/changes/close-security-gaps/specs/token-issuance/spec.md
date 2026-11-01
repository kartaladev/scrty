## ADDED Requirements

### Requirement: An issued token can carry a confirmation claim
When the caller supplies a key binding, the issued token SHALL carry a `cnf` claim: `jkt` with a DPoP key thumbprint, or `x5t#S256` with a certificate thumbprint, never both, each a base64url SHA-256 digest of 43 characters. Without a binding, the token SHALL carry no `cnf` claim. Issuing with both bindings, or with a malformed thumbprint, SHALL fail with a configuration error and produce no token. A verifier SHALL return the confirmation claim to its caller, and SHALL refuse a token whose `cnf` claim is not an object, is empty, or carries a malformed `jkt` or `x5t#S256`.

#### Scenario: DPoP-bound token
- **WHEN** a token is issued with DPoP key thumbprint `K`
- **THEN** its claims carry `cnf` `{"jkt": "K"}`

#### Scenario: Unbound token
- **WHEN** a token is issued with no binding
- **THEN** its claims carry no `cnf`

#### Scenario: Both bindings
- **WHEN** a token is issued with a DPoP thumbprint and a certificate thumbprint
- **THEN** issuing fails with a configuration error and no token is produced

#### Scenario: Malformed confirmation
- **WHEN** a correctly signed token carrying `cnf` `{"jkt": 7}` is verified
- **THEN** the verifier refuses it as invalid
