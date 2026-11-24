## MODIFIED Requirements

### Requirement: An active introspection answer describes the token
For an active token the introspection answer SHALL hold `active`, `scope`, `client_id`, `sub`, `exp`, `iat`, `iss`, `aud`, `token_type`, the confirmation claim when bound, and, for an access token, the `auth_time`, `acr` and `amr` of the sign-in behind its grant, as far as the grant records them.

#### Scenario: Active opaque token
- **WHEN** the client that holds an opaque access token introspects it
- **THEN** the answer holds `active` true with its `sub`, `scope`, `client_id` and `exp`

#### Scenario: Sign-in members
- **WHEN** a resource server's client introspects an access token whose grant was made by a sign-in with a password and TOTP
- **THEN** the answer holds that sign-in's `auth_time` and an `amr` naming both methods
