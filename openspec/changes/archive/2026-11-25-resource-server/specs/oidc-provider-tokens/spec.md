## ADDED Requirements

### Requirement: A sign-in records how it was proved, and its grants keep it
The sign-in a resume records SHALL carry whether the library verified a second factor in it and, for a federated sign-in, the federated evidence that login asserted (provider, issuer, `amr`, `acr`), taken only from the library's own record of the session, never from the consumer's sign-in assurance mapping or a request. Every grant made from that sign-in, by code or device exchange, SHALL keep them, and so SHALL every refresh of the grant.

#### Scenario: Consumer mapping claims a second factor
- **WHEN** a consumer's sign-in assurance mapping states `amr` `["mfa"]` for a password-only session, and the resumed sign-in makes a grant by code exchange
- **THEN** the grant records that no second factor was verified, whatever its `amr` says

#### Scenario: Federated sign-in
- **WHEN** a user signs in through OIDC provider `corp`, whose ID token asserted `amr` `["mfa"]`, and the sign-in makes a grant
- **THEN** the grant records the federated evidence `corp`, its issuer and `["mfa"]`

#### Scenario: Device grant
- **WHEN** a user approves a device authorization in a sign-in where the library verified TOTP, and the device exchanges its code
- **THEN** the device's grant records that a second factor was verified

#### Scenario: Refreshed grant
- **WHEN** that grant is refreshed
- **THEN** the refreshed grant still records it

## MODIFIED Requirements

### Requirement: An active introspection answer describes the token
For an active token the introspection answer SHALL hold `active`, `scope`, `client_id`, `sub`, `exp`, `iat`, `iss`, `aud`, `token_type`, the confirmation claim when bound, and, for an access token, the `auth_time`, `acr` and `amr` of the sign-in behind its grant, as far as the grant records them.

#### Scenario: Active opaque token
- **WHEN** the client that holds an opaque access token introspects it
- **THEN** the answer holds `active` true with its `sub`, `scope`, `client_id` and `exp`

#### Scenario: Sign-in members
- **WHEN** a resource server's client introspects an access token whose grant was made by a sign-in with a password and TOTP
- **THEN** the answer holds that sign-in's `auth_time` and the `amr` its grant records (`pwd` and `mfa` under the default sign-in assurance)
