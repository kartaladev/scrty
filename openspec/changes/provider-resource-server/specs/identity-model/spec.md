# Spec Delta

## MODIFIED Requirements

### Requirement: Principals distinguish human users from services
Every principal SHALL have a kind that is either a human user or a service. A principal whose kind was not set SHALL be a human user. Service principals SHALL carry their granted scopes. A human user's principal SHALL carry scopes only when the request was authenticated by an access token, and they SHALL then be exactly the scopes granted to that token.

#### Scenario: Default kind
- **WHEN** a principal is created without a kind
- **THEN** it reports that it is not a service

#### Scenario: Service principal
- **WHEN** a service principal is created with scope `reports:read`
- **THEN** it reports that it is a service and carries `reports:read`

#### Scenario: User authenticated by an access token
- **WHEN** a user's request is authenticated by a provider access token granted `openid employees:read`
- **THEN** the principal is a human user carrying exactly `openid` and `employees:read`

#### Scenario: User authenticated by a session
- **WHEN** a user's request is authenticated by a first-party bearer token or a session reference
- **THEN** the principal carries no scopes

### Requirement: First-factor kinds map to channels and exemptions
The library SHALL name the first-factor kinds `password`, `magic-link`, `oidc`, `basic`, `api-key`, `recovery`, `passkey` and `access-token`, and the channels `knowledge`, `email`, `authenticator-app`, `federated`, `machine` and `public-key`. It SHALL map kinds to channels as follows:
- `password` and `basic` report `knowledge`;
- `magic-link` reports `email`;
- `oidc` reports `federated`;
- `api-key` reports `machine`;
- `passkey` reports `public-key`, the channel of credentials an authenticator holds as a key pair and proves by signing a challenge;
- `recovery`, the kind of a session an account recovery produces, reports no channel, because the recovery rested on two proofs of different kinds rather than on one channel;
- `access-token`, the kind of a request authenticated by an access token the chain's own provider issued, reports no channel, because the token rests on the sign-in that made its grant rather than on a channel of its own.

The `authenticator-app` channel SHALL be the channel of second factors that use an authenticator app, such as TOTP, and `email` SHALL also be the channel of email-delivered second factors. The `public-key` channel SHALL also be the channel of the passkey second factor, so a passkey second factor after a passkey login is on the first factor's own channel. These kinds and channels SHALL be the complete vocabulary scrty uses. Other capabilities, including multi-factor authentication and security policy, SHALL reference these values and SHALL NOT define kinds or channels of their own.

Only `api-key` and `access-token` SHALL report themselves as exempt from an MFA requirement: an API key because it is a machine credential, and an access token because the requirement was judged at the sign-in that made its grant. `oidc`, `recovery` and `passkey` SHALL NOT be exempt. How a login on the `federated` channel meets an MFA requirement SHALL be decided by the federated-assurance rules of the `security-policy` capability, not by its kind. The empty kind and every kind the library does not name SHALL report no channel and SHALL NOT be exempt.

#### Scenario: Authenticator-app channel
- **WHEN** the channel vocabulary is listed
- **THEN** it contains `authenticator-app` for authenticator-app second factors such as TOTP
- **AND** no first-factor kind reports `authenticator-app`

#### Scenario: Password login
- **WHEN** the kind `password` is examined
- **THEN** it reports channel `knowledge` and is not exempt

#### Scenario: Exempt kinds
- **WHEN** the kinds `oidc` and `api-key` are examined
- **THEN** `api-key` reports `machine` and is exempt
- **AND** `oidc` reports `federated` and is not exempt

#### Scenario: Forgotten kind fails closed
- **WHEN** the empty kind is examined
- **THEN** it reports no channel and is not exempt

#### Scenario: Consumer-defined kind
- **WHEN** a consumer's kind `smart-card` is examined
- **THEN** it reports no channel and is not exempt

#### Scenario: Recovery kind
- **WHEN** the kind `recovery` is examined
- **THEN** it reports no channel and is not exempt

#### Scenario: Passkey kind
- **WHEN** the kind `passkey` is examined
- **THEN** it reports channel `public-key` and is not exempt

#### Scenario: Access-token kind
- **WHEN** the kind `access-token` is examined
- **THEN** it reports no channel and is exempt
