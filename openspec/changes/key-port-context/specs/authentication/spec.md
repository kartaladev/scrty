# Spec Delta

## MODIFIED Requirements

### Requirement: Bearer tokens are authenticated by a verifier
The bearer-token provider SHALL delegate token verification to the configured token verifier, and SHALL build the principal only from the verified claims. A verification error that rejects the token as invalid SHALL be returned as an error that matches both the uniform authentication failure and the verifier's error. A failure to obtain the verification keys from the key source is a dependency failure, not a rejected token: it SHALL be returned with fixed library text that keeps the key source's error reachable, and SHALL NOT match the uniform authentication failure. The verifier SHALL be given the caller's context. The result's identifier SHALL be the token's identifier. Constructing the provider without a verifier SHALL fail with a configuration error.

#### Scenario: Valid token
- **WHEN** a token the verifier accepts, with subject `ada`, is presented
- **THEN** the result's principal is built from subject `ada`

#### Scenario: Rejected token
- **WHEN** the verifier rejects a token as expired
- **THEN** the returned error matches the uniform authentication failure and the verifier's expiry error

#### Scenario: Key source outage
- **WHEN** the verifier cannot obtain the verification keys because the key source fails
- **THEN** the returned error does not match the uniform authentication failure
- **AND** the key source's error is reachable from it

#### Scenario: Missing verifier
- **WHEN** a bearer-token provider is constructed without a verifier
- **THEN** construction fails with a configuration error
