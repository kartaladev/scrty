# Spec Delta

## MODIFIED Requirements

### Requirement: Bearer tokens are authenticated by a verifier
The bearer-token provider SHALL delegate token verification to the configured token verifier, and SHALL build the principal only from the verified claims. By default it SHALL read the subject as the principal's user identifier; when configured to use usernames, it SHALL read the subject as the principal's username, matching a generator configured the same way. A verification error SHALL be returned as an error that matches both the uniform authentication failure and the verifier's error. The result's identifier SHALL be the token's identifier. Constructing the provider without a verifier SHALL fail with a configuration error.

#### Scenario: Valid token
- **WHEN** a token the verifier accepts, with subject `u-1`, is presented to a default provider
- **THEN** the result's principal has user identifier `u-1`

#### Scenario: Consumer reads the subject as a username
- **WHEN** a token the verifier accepts, with subject `ada`, is presented to a provider configured to use usernames
- **THEN** the result's principal has username `ada`

#### Scenario: Rejected token
- **WHEN** the verifier rejects a token as expired
- **THEN** the returned error matches the uniform authentication failure and the verifier's expiry error

#### Scenario: Missing verifier
- **WHEN** a bearer-token provider is constructed without a verifier
- **THEN** construction fails with a configuration error
