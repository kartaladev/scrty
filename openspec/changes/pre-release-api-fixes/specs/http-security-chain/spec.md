# Spec Delta

## MODIFIED Requirements

### Requirement: Bearer tokens authenticate against a live session and a live user
When enabled, bearer token authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case. When the consumer opts in, it SHALL also accept a bare token with no scheme. Other requests SHALL pass through unchanged.

For each handled request it SHALL:
1. verify the token, refusing a token the verifier rejects as invalid with the authentication failure error and keeping the cause available for logging. A failure to obtain the verification keys from the key source is a dependency failure, not a refusal: it SHALL fail the request with fixed library text that keeps the key source's error reachable, and SHALL NOT be answered with the authentication failure error;
2. load the session the token names, refusing with the authentication-required error when the session is missing, expired or cannot be decrypted, and, when the session manager reports reuse of a superseded identifier, with a refusal that is identifiable both as the authentication-required error and as the reused-session error. Any other failure to load the session, such as a session store or cipher outage, is a dependency failure, not a refusal: it SHALL fail the request with fixed library text that keeps the session manager's error reachable, and SHALL NOT be answered with the authentication-required error;
3. reload the session's user, so roles are current: by default by the user reference the session records, refusing with the authentication-required error before any reload when the token's subject is not that reference; when configured to use usernames, by the username the token names. In either mode it SHALL refuse with the authentication-required error when the user no longer exists. Any other failure to reload the user, such as a user store outage, is a dependency failure: it SHALL fail the request with fixed library text that keeps the loader's error reachable, and SHALL NOT be answered with the authentication-required error;
4. add the principal, authentication result and session to the context;
5. evaluate the per-request policy phase, telling it whether the session has satisfied its second factor.

When the request's own context ends while the token is being verified, the session is loading or the user is reloading, the request SHALL fail with an error that matches that context's error. An error that matches the cause the context was cancelled with is that context's error too. It SHALL NOT be answered with the authentication failure error or the authentication-required error, and SHALL NOT be logged as a dependency failure, as a verification-key failure or as an undecryptable session.

An undecryptable session SHALL also be logged at ERROR. A dependency failure while loading the session SHALL NOT be logged as an undecryptable session. A deny from the per-request phase SHALL refuse. A challenge from it SHALL mark the challenge pending on the session and continue, so the gate for that challenge enforces it. When the challenge is for enrolment and the session is not already enrolment-pending, the bearer SHALL save the marked session itself before continuing, because the enrolment gate refuses the request before the session-touch step runs; a failed save SHALL refuse the request. A challenge of a consumer kind declared with an enforcer SHALL be recorded on the exchange for that enforcer, and the request SHALL continue.

The subject mode SHALL default to the user identifier, matching the token generator's default, and the consumer SHALL be able to configure usernames instead. Building a chain with signed bearer tokens SHALL fail with a configuration error when any token generator the chain is given reports a subject mode other than the bearer's.

#### Scenario: Valid token
- **WHEN** a request carries a valid bearer token for a live session
- **THEN** the handler runs with the principal and session in the context

#### Scenario: Default token reloads the session's user
- **WHEN** a default chain receives a valid token with subject `u-1` for a live session whose user reference is `u-1`, and that user's username is `alice`
- **THEN** the user is reloaded by the identifier `u-1`, not by username
- **AND** the handler runs with a principal whose user identifier is `u-1` and whose username is `alice`

#### Scenario: Subject is not the session's user
- **WHEN** a default chain receives a valid token with subject `u-2` naming a live session whose user reference is `u-1`
- **THEN** it is refused with the authentication-required error, no user is reloaded, and the handler does not run

#### Scenario: Consumer reads the subject as a username
- **WHEN** a chain configured to use usernames receives a valid token with subject `alice` for a live session of user `u-1`, whose username is `alice`
- **THEN** the user is reloaded by the username `alice`, and the handler runs with a principal whose user identifier is `u-1`

#### Scenario: Generator and bearer disagree on the subject
- **WHEN** a chain with signed bearer tokens in the default mode is built with a login token generator configured to use usernames
- **THEN** building the chain fails with a configuration error

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

#### Scenario: Key source outage during verification
- **WHEN** a request carries a correctly signed token, and the key source fails to supply the verification keys
- **THEN** the request fails with an error from which the key source's error is reachable, which the default status mapping answers with 500
- **AND** the error matches neither the authentication failure error nor the authentication-required error

#### Scenario: Session store outage
- **WHEN** a request carries a valid bearer token and the session store fails to load the session with an error that is not a refusal
- **THEN** the request fails with an error from which the store's error is reachable, whose text is fixed library text, and which the default status mapping answers with 500
- **AND** the error does not match the authentication-required error
- **AND** no undecryptable-session ERROR record is written

#### Scenario: User store outage
- **WHEN** a request carries a valid bearer token for a live session, and the user loader fails with an error that is not identifiable as "user not found"
- **THEN** the request fails with an error from which the loader's error is reachable, whose text is fixed library text, and which the default status mapping answers with 500
- **AND** the error does not match the authentication-required error

#### Scenario: Session-reference bearer during a store outage
- **WHEN** session-reference authentication is enabled, a request carries a well-formed session identifier, and the session store fails to load it with an error that is not a refusal
- **THEN** the request fails with an error from which the store's error is reachable, and not with the authentication-required error

#### Scenario: Client leaves while the session loads
- **WHEN** a request carries a valid bearer token, its context is cancelled, and the session load fails with that cancellation
- **THEN** the request fails with an error matching the context's cancellation
- **AND** the error does not match the authentication-required error
- **AND** no undecryptable-session or dependency-failure record is written at ERROR

#### Scenario: Client leaves while the token is verified
- **WHEN** a request carries a correctly signed bearer token, its context is cancelled, and verification fails with that cancellation
- **THEN** the request fails with an error matching the context's cancellation
- **AND** the error matches neither the authentication failure error nor the authentication-required error, and its text does not report the verification keys as unavailable
- **AND** no verification-key or dependency-failure record is written at ERROR

#### Scenario: Client leaves with a cause
- **WHEN** a request's context is cancelled with a cause of the server's own, and the session load, the user reload or verification fails with that cause
- **THEN** the request fails as a client that left: with the error of the context's ending, not as a dependency failure, and no dependency-failure, verification-key or undecryptable-session record is written at ERROR

### Requirement: A resolved session authenticates only its own, active user
Signed bearer tokens, session references and the renewal endpoint, including a late renewal, SHALL refuse with the authentication-required error when the reloaded user's identifier differs from the user reference the session records, or when the reloaded user is not active. A refused session SHALL NOT be revoked by the refusal; it authenticates again if its user is re-enabled before it expires. A reload that fails for any reason other than the user not being found is not this refusal: each of these paths answers it as a dependency failure, or, when the request's own context ended, with that context's error.

#### Scenario: Username reassigned to another user
- **WHEN** a chain configured to use usernames receives a signed bearer token naming user `u-1`'s session, and the username in the token now belongs to user `u-2`
- **THEN** the request is refused with the authentication-required error and the handler does not run

#### Scenario: Disabled user's live session
- **WHEN** a request carries a valid credential for a live session whose user has been disabled
- **THEN** it is refused with the authentication-required error

#### Scenario: Disabled user renews
- **WHEN** a disabled user's session posts to the renewal endpoint, inside or after the session's grace window
- **THEN** it is refused with the authentication-required error and no successor is created

#### Scenario: Re-enabled user
- **WHEN** a disabled user is re-enabled while their session is still live
- **THEN** that session authenticates again
