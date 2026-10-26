# Spec Delta

## MODIFIED Requirements

### Requirement: Bearer tokens authenticate against a live session and a live user
When enabled, bearer token authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case. When the consumer opts in, it SHALL also accept a bare token with no scheme. Other requests SHALL pass through unchanged.

For each handled request it SHALL:
1. verify the token, refusing a failure with the authentication failure error and keeping the cause available for logging;
2. load the session the token names, refusing with the authentication-required error when the session is missing, expired or cannot be decrypted, and, when the session manager reports reuse of a superseded identifier, with a refusal that is identifiable both as the authentication-required error and as the reused-session error. Any other failure to load the session, such as a session store or cipher outage, is a dependency failure, not a refusal: it SHALL fail the request with the session manager's error and SHALL NOT be answered with the authentication-required error;
3. reload the user the token names, so roles are current, refusing with the authentication-required error when the user no longer exists. Any other failure to reload the user, such as a user store outage, is a dependency failure: it SHALL fail the request with the loader's error and SHALL NOT be answered with the authentication-required error;
4. add the principal, authentication result and session to the context;
5. evaluate the per-request policy phase, telling it whether the session has satisfied its second factor.

An undecryptable session SHALL also be logged at ERROR. A dependency failure while loading the session SHALL NOT be logged as an undecryptable session. A deny from the per-request phase SHALL refuse. A challenge from it SHALL mark the challenge pending on the session and continue, so the gate for that challenge enforces it. When the challenge is for enrolment and the session is not already enrolment-pending, the bearer SHALL save the marked session itself before continuing, because the enrolment gate refuses the request before the session-touch step runs; a failed save SHALL refuse the request. A challenge of a consumer kind declared with an enforcer SHALL be recorded on the exchange for that enforcer, and the request SHALL continue.

#### Scenario: Valid token
- **WHEN** a request carries a valid bearer token for a live session
- **THEN** the handler runs with the principal and session in the context

#### Scenario: Expired session
- **WHEN** a request carries a correctly signed token whose session has expired
- **THEN** it is refused with the authentication-required error

#### Scenario: Superseded identifier presented after its window
- **WHEN** a request carries a valid token naming a session superseded by a renewal whose window has ended
- **THEN** it is refused with an error identifiable as both the authentication-required and the reused-session error
- **AND** the session's family is revoked

#### Scenario: Session sealed under a retired key
- **WHEN** a token names a session that exists but cannot be decrypted
- **THEN** the request is refused with the authentication-required error and an ERROR record is written

#### Scenario: Tampered token
- **WHEN** a request carries a token whose signature does not verify
- **THEN** it is refused with the authentication failure error

#### Scenario: Password ages out mid-session
- **WHEN** the per-request phase challenges for a password change on a live session
- **THEN** the session is marked with a pending password-change challenge and the request continues to the next interceptor

#### Scenario: Consumer scheme
- **WHEN** the consumer sets the scheme to `Token` and a request carries `Authorization: token <valid>`
- **THEN** the request is authenticated

#### Scenario: Satisfied second factor per request
- **WHEN** a required user whose session has satisfied its second factor sends a request with a valid token
- **THEN** the per-request phase is told the second factor is satisfied, and the handler runs

#### Scenario: Enrolment marked mid-session
- **WHEN** the per-request phase challenges a live session for enrolment
- **THEN** the session is saved in the enrolment-pending state with its lowered deadline before the enrolment gate refuses the request

#### Scenario: Enrolment mark cannot be saved
- **WHEN** the per-request phase challenges for enrolment and saving the session fails
- **THEN** the request is refused

#### Scenario: Session store outage
- **WHEN** a request carries a valid bearer token and the session store fails to load the session with an error that is not a refusal
- **THEN** the request fails with an error wrapping the store's error, which the default status mapping answers with 500
- **AND** the error does not match the authentication-required error
- **AND** no undecryptable-session ERROR record is written

#### Scenario: User store outage
- **WHEN** a request carries a valid bearer token for a live session, and the user loader fails with an error that is not identifiable as "user not found"
- **THEN** the request fails with an error wrapping the loader's error, which the default status mapping answers with 500
- **AND** the error does not match the authentication-required error

#### Scenario: Session-reference bearer during a store outage
- **WHEN** session-reference authentication is enabled, a request carries a well-formed session identifier, and the session store fails to load it with an error that is not a refusal
- **THEN** the request fails with an error wrapping the store's error, and not with the authentication-required error
