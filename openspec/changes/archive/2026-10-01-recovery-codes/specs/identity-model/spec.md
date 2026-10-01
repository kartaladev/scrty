# Spec Delta

## MODIFIED Requirements

### Requirement: First-factor kinds map to channels and exemptions
The library SHALL name the first-factor kinds `password`, `magic-link`, `oidc`, `basic`, `api-key` and `recovery`, and the channels `knowledge`, `email`, `authenticator-app`, `federated` and `machine`. It SHALL map kinds to channels as follows:
- `password` and `basic` report `knowledge`;
- `magic-link` reports `email`;
- `oidc` reports `federated`;
- `api-key` reports `machine`;
- `recovery`, the kind of a session an account recovery produces, reports no channel, because the recovery rested on two proofs of different kinds rather than on one channel.

The `authenticator-app` channel SHALL be the channel of second factors that use an authenticator app, such as TOTP, and `email` SHALL also be the channel of email-delivered second factors. These kinds and channels SHALL be the complete vocabulary scrty uses. Other capabilities, including multi-factor authentication and security policy, SHALL reference these values and SHALL NOT define kinds or channels of their own.

Only `oidc` and `api-key` SHALL report themselves as exempt from an MFA requirement. `recovery` SHALL NOT be exempt. The empty kind and every kind the library does not name SHALL report no channel and SHALL NOT be exempt.

#### Scenario: Authenticator-app channel
- **WHEN** the channel vocabulary is listed
- **THEN** it contains `authenticator-app` for authenticator-app second factors such as TOTP
- **AND** no first-factor kind reports `authenticator-app`

#### Scenario: Password login
- **WHEN** the kind `password` is examined
- **THEN** it reports channel `knowledge` and is not exempt

#### Scenario: Exempt kinds
- **WHEN** the kinds `oidc` and `api-key` are examined
- **THEN** `oidc` reports `federated` and is exempt
- **AND** `api-key` reports `machine` and is exempt

#### Scenario: Forgotten kind fails closed
- **WHEN** the empty kind is examined
- **THEN** it reports no channel and is not exempt

#### Scenario: Consumer-defined kind
- **WHEN** a consumer's kind `smart-card` is examined
- **THEN** it reports no channel and is not exempt

#### Scenario: Recovery kind
- **WHEN** the kind `recovery` is examined
- **THEN** it reports no channel and is not exempt
