## ADDED Requirements

### Requirement: Every challenge a policy can raise has an enforcer
Chain assembly SHALL fail with a configuration error when a registered policy declares that it can raise a challenge kind and nothing registered in the chain enforces that kind. The built-in kinds SHALL be enforced as follows:
- a second-factor challenge, by the second-factor challenge interceptor;
- a password-change challenge, by the password-change gate;
- a second-factor enrolment challenge, by the enrolment interceptor.

A consumer that registers its own challenging policy and its own gate SHALL be able to declare, by an option, that the chain enforces a kind of its own. A policy that declares nothing SHALL be read as raising no challenge. There SHALL be no option that turns the check off. The error SHALL name the challenge kind and the missing enforcer.

A built-in kind SHALL count as enforced only when its own built-in interceptor is registered; another interceptor at the same slot SHALL NOT count. A challenge raised at runtime whose kind has no enforcer in the chain, such as one declared by a policy added to the engine after the chain was built, SHALL refuse the request with a configuration error; it SHALL NOT mark the session and let the request through. This SHALL hold in every phase that can raise a challenge and mark a session or let a request through, including pre-authentication, and a redemption flow SHALL refuse before its one-time credential is spent. A stateless request (basic) that raises a challenge after its credential is checked is refused with that challenge, as before, whatever the kind: nothing is marked and nothing gets through. A consumer kind raised in the per-request phase SHALL be recorded on the exchange for the consumer's declared gate.

#### Scenario: Another interceptor at the enrolment slot is not an enforcer
- **WHEN** the enrolment path is on in the policy, the chain has no enrolment interceptor, and a consumer interceptor is registered at `Before(OrderMFAChallenge)`
- **THEN** chain assembly fails naming the enrolment challenge

#### Scenario: Policy added after the chain was built
- **WHEN** a policy that raises the password-change challenge is added to the engine after the chain was built without the password-change gate, and a request triggers it
- **THEN** the request is refused with a configuration error and the handler does not run

#### Scenario: Password-age policy without its gate
- **WHEN** a chain registers the password-age policy and does not enable the password-change gate
- **THEN** assembly fails with a configuration error naming the password-change challenge

#### Scenario: Second factor without its interceptor
- **WHEN** a chain registers the second-factor challenge policy and does not enable the second-factor challenge interceptor
- **THEN** assembly fails with a configuration error naming the second-factor challenge

#### Scenario: Consumer kind declared
- **WHEN** a consumer registers a policy declaring a `terms-acceptance` challenge, registers its own gate, and declares that the chain enforces `terms-acceptance`
- **THEN** assembly succeeds

#### Scenario: Consumer kind undeclared
- **WHEN** a consumer registers a policy declaring a `terms-acceptance` challenge and declares no enforcer for it
- **THEN** assembly fails with a configuration error naming `terms-acceptance`

#### Scenario: Policy declaring nothing
- **WHEN** a consumer registers a policy that does not declare its challenge kinds
- **THEN** assembly does not fail on its account

## MODIFIED Requirements

### Requirement: Bearer tokens authenticate against a live session and a live user
When enabled, bearer token authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case. When the consumer opts in, it SHALL also accept a bare token with no scheme. Other requests SHALL pass through unchanged.

For each handled request it SHALL:
1. verify the token, refusing a failure with the authentication failure error and keeping the cause available for logging;
2. load the session the token names, refusing with the authentication-required error when the session is missing, expired or cannot be decrypted;
3. reload the user the token names, so roles are current, refusing with the authentication-required error when the user no longer exists;
4. add the principal, authentication result and session to the context;
5. evaluate the per-request policy phase, telling it whether the session has satisfied its second factor.

An undecryptable session SHALL also be logged at ERROR. A deny from the per-request phase SHALL refuse. A challenge from it SHALL mark the challenge pending on the session and continue, so the gate for that challenge enforces it. When the challenge is for enrolment and the session is not already enrolment-pending, the bearer SHALL save the marked session itself before continuing, because the enrolment gate refuses the request before the session-touch step runs; a failed save SHALL refuse the request. A challenge of a consumer kind declared with an enforcer SHALL be recorded on the exchange for that enforcer, and the request SHALL continue.

#### Scenario: Valid token
- **WHEN** a request carries a valid bearer token for a live session
- **THEN** the handler runs with the principal and session in the context

#### Scenario: Expired session
- **WHEN** a request carries a correctly signed token whose session has expired
- **THEN** it is refused with the authentication-required error

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

### Requirement: A pending password change blocks requests until resolved
When the password-change gate is enabled, every request that reaches it whose session carries a pending password-change challenge SHALL be refused, except the logout endpoint, wherever it is placed in the chain relative to the gate. The refusal SHALL be a password-change challenge error carrying the session, and the handler SHALL NOT run. A session with a pending password change SHALL always be able to log out, and logging out SHALL end that session. The consumer SHALL be able to register a resolve endpoint: a POST path together with the consumer's own function that performs the change. Requests to that endpoint SHALL pass the gate, and SHALL follow these rules:
- **No session:** a request without a session SHALL be refused with the authentication-required error.
- **Consumer function fails:** its error SHALL be the refusal.
- **Consumer function succeeds:** the pending marker SHALL be cleared and the session saved, and the consumer's function owns the response.

Without a resolve endpoint, only a new login clears the challenge.

#### Scenario: Pending password change
- **WHEN** a request carries a token for a session with a pending password-change challenge
- **THEN** it is refused with a password-change challenge error and the handler is not called

#### Scenario: Pending password change logs out
- **WHEN** a session with a pending password-change challenge posts to the logout endpoint
- **THEN** no password-change challenge error is returned
- **AND** the session is deleted, and its handle no longer loads

#### Scenario: Consumer logout path
- **WHEN** logout is configured with path `/auth/sign-out` and a session with a pending password-change challenge posts there
- **THEN** the session is deleted

#### Scenario: Consumer resolve endpoint
- **WHEN** the consumer registers `POST /account/password` with a function that changes the password successfully, and a session with the pending challenge calls it
- **THEN** the consumer's function runs, the marker is cleared and saved, and the next request on that session passes the gate

#### Scenario: Resolve without a session
- **WHEN** an unauthenticated request posts to the resolve endpoint
- **THEN** it is refused with the authentication-required error and the consumer's function does not run

### Requirement: Redemption flows plug into named seams
The chain SHALL provide the seams that interceptors from other capabilities use, without those interceptors being part of this capability:
- named slots for federated login, one-time link redemption, API keys, client certificates, second-factor enrolment and second-factor challenges, the enrolment slot immediately before the second-factor challenge slot;
- a login completion step;
- a source throttle step.

The login completion step SHALL be the one form login uses. It SHALL require the principal, first factor, submitted username and password change time as inputs, and SHALL accept additional session attributes that its caller wants recorded in the write that creates the session, such as a federated login's provider session. It SHALL behave identically for every first factor that uses it:
1. evaluate the post-authentication phase;
2. on a deny, refuse with the policy's reason;
3. create the session with its first factor and the caller's additional attributes, in one write;
4. mark and save any pending challenge before issuing the token, including, for an enrolment challenge, the enrolment-pending state and its lowered deadlines;
5. publish the authentication onto the request context;
6. refuse with a challenge error when a challenge is pending.

The source throttle step SHALL expose the check before guarded work and the failure recording after it, using the chain's client address, refusal rules and sampled logs.

#### Scenario: Another first factor reuses login completion
- **WHEN** a redemption interceptor added by another capability authenticates a user and hands the principal to the login completion step, and policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Enrolment challenge at login completion
- **WHEN** a magic-link redemption hands the login completion step a required, unenrolled user, and the enrolment path is on
- **THEN** the request is refused with an enrolment challenge error carrying a session in the enrolment-pending state and a token
- **AND** the session was saved in that state before the token was issued

#### Scenario: Federated attributes land in the creating write
- **WHEN** a federated login hands the login completion step a principal together with its provider, issuer and provider session id
- **THEN** the created session records them from its first write
- **AND** no later save of the session was needed to record them

#### Scenario: Plugin slot order
- **WHEN** an interceptor is registered at the one-time link slot
- **THEN** it runs after form login and before Basic authentication

#### Scenario: Enrolment gate runs before the second-factor gate
- **WHEN** an enrolment-only session requests the second-factor verify path
- **THEN** it is refused by the enrolment gate before the second-factor challenge interceptor runs
