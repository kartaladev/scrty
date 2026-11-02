# Spec Delta

## MODIFIED Requirements

### Requirement: Bearer tokens are authenticated by a verifier
The bearer-token provider SHALL delegate token verification to the configured token verifier, and SHALL build the principal only from the verified claims. By default it SHALL read the subject as the principal's user identifier; when configured to use usernames, it SHALL read the subject as the principal's username, matching a generator configured the same way. A verification error that rejects the token as invalid SHALL be returned as an error that matches both the uniform authentication failure and the verifier's error. A failure to obtain the verification keys from the key source is a dependency failure, not a rejected token: it SHALL be returned with fixed library text that keeps the key source's error reachable, and SHALL NOT match the uniform authentication failure. When the caller's own context has ended and the verification error is that context's error, or the cause it was cancelled with, the provider SHALL return an error that matches the context's error, with fixed library text of its own that does not report the verification keys as unavailable, and that does not match the uniform authentication failure. The verifier SHALL be given the caller's context. The result's identifier SHALL be the token's identifier. Constructing the provider without a verifier SHALL fail with a configuration error.

#### Scenario: Valid token
- **WHEN** a token the verifier accepts, with subject `u-1`, is presented to a default provider
- **THEN** the result's principal has user identifier `u-1`

#### Scenario: Consumer reads the subject as a username
- **WHEN** a token the verifier accepts, with subject `ada`, is presented to a provider configured to use usernames
- **THEN** the result's principal has username `ada`

#### Scenario: Rejected token
- **WHEN** the verifier rejects a token as expired
- **THEN** the returned error matches the uniform authentication failure and the verifier's expiry error

#### Scenario: Key source outage
- **WHEN** the verifier cannot obtain the verification keys because the key source fails
- **THEN** the returned error does not match the uniform authentication failure
- **AND** the key source's error is reachable from it

#### Scenario: Caller leaves during verification
- **WHEN** the caller's context is cancelled and the verifier fails with that cancellation
- **THEN** the returned error matches the context's cancellation
- **AND** it does not match the uniform authentication failure, and its text is not the text reported for a key source outage

#### Scenario: Caller leaves with a cause
- **WHEN** the caller's context is cancelled with a cause, and the verifier fails with that cause
- **THEN** the provider answers as for a caller that left, and its text is not the text reported for a key source outage

#### Scenario: Missing verifier
- **WHEN** a bearer-token provider is constructed without a verifier
- **THEN** construction fails with a configuration error
