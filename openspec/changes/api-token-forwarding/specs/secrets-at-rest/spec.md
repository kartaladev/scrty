# Spec Delta

## MODIFIED Requirements

### Requirement: Long-lived secrets are stored sealed
Durable stores SHALL seal signing-key private material, MFA secrets, the emailed MFA enrolment code, the provider ID token retained on sessions, and the provider access and refresh tokens retained on sessions for forwarding before writing them. The stored value, after undoing any text encoding, SHALL neither equal nor contain the plaintext. Sealing the same plaintext twice SHALL produce different stored values. Single-use OIDC flow values, handoff ID tokens and secrets stored only as one-way digests SHALL NOT be sealed.

The emailed enrolment code is short-lived, but it is sealed rather than digested: a six-digit code's plain digest is reversed by trying every value.

#### Scenario: Signing key column
- **WHEN** a signing key whose private material contains `PKCS8-SENTINEL` is stored and its column is read directly
- **THEN** the column's bytes do not contain `PKCS8-SENTINEL`
- **AND** loading the key through the store returns the original private material

#### Scenario: Encoded MFA secret column
- **WHEN** a user enrols with MFA secret `TOTP-SENTINEL`, and the stored column is read directly and decoded from its text encoding
- **THEN** neither the stored text nor the decoded bytes equal or contain `TOTP-SENTINEL`

#### Scenario: Emailed code column
- **WHEN** a device proof stores emailed code `042917`, and the stored column is read directly and decoded from its text encoding
- **THEN** neither the stored text nor the decoded bytes equal or contain `042917`
- **AND** reading the enrolment through the store returns `042917`

#### Scenario: Randomised sealing
- **WHEN** two users enrol with the same MFA secret
- **THEN** the two stored values differ

#### Scenario: Provider forwarding token columns
- **WHEN** a session holding provider access token `AT-SENTINEL` and refresh token `RT-SENTINEL` is stored, and its columns are read directly and decoded from their text encoding
- **THEN** no stored text or decoded bytes equal or contain either sentinel
- **AND** loading the session through the store returns both tokens
