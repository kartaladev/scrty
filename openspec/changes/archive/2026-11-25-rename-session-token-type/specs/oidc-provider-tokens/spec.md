## MODIFIED Requirements

### Requirement: The subject of every provider token is the user's identifier
`sub` SHALL be the grant's user identifier in every token the provider issues, whatever subject mode the chain's session tokens use. The provider SHALL build its issuers from the key source it was given, and SHALL NOT take a session token generator.

#### Scenario: Chain reads usernames
- **WHEN** the chain's signed bearer and generators use the username subject, and user `u-1` named `ada` completes an authorization
- **THEN** the ID token's and access token's `sub` are `u-1`

#### Scenario: Username reassigned
- **WHEN** `ada` is renamed, and the name is given to another user, and the first user's grant is refreshed
- **THEN** the new ID token's `sub` is unchanged
