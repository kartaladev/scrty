## MODIFIED Requirements

### Requirement: Bearer tokens authenticate against a live session and a live user
When enabled, bearer token authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case. When the consumer opts in, it SHALL also accept a bare token with no scheme. Other requests SHALL pass through unchanged.

For each handled request it SHALL:
1. verify the token, refusing a failure with the authentication failure error and keeping the cause available for logging;
2. load the session the token names, refusing with the authentication-required error when the session is missing, expired or cannot be decrypted, and, when the session manager reports reuse of a superseded identifier, with a refusal that is identifiable both as the authentication-required error and as the reused-session error;
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

### Requirement: Session activity is recorded after the handler
For every request that carries a session, the chain SHALL record the session's activity through the session manager after the handler and every inner interceptor have returned, including when an inner stage refused the request, so the idle deadline advances as the manager's activity interval allows. A failure to record activity SHALL NOT change the response or the error the chain returns.

#### Scenario: Activity recorded
- **WHEN** a request with a live session completes
- **THEN** the session's idle deadline has been advanced

#### Scenario: Store failure after the response
- **WHEN** advancing the deadline fails after the handler wrote 200
- **THEN** the client receives 200 and the chain returns no error

#### Scenario: Refused request still counts as activity
- **WHEN** a request with a live session is refused by a guard
- **THEN** the session's idle deadline is still advanced

#### Scenario: Consumer activity interval coalesces writes
- **WHEN** the chain's session manager has a 1-minute activity interval and two requests on one session complete 10 seconds apart, the first a minute after the last recorded access
- **THEN** the session's activity is persisted once

## ADDED Requirements

### Requirement: Session-reference bearers authenticate against a live session and a live user
When enabled, session-reference authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case, and SHALL treat the presented value as a session identifier with no signed token. It SHALL refuse a malformed value before any store lookup, load the session, reload its user by the user reference the session records, never by username, then publish and evaluate exactly as signed bearer tokens are.

#### Scenario: Live session reference
- **WHEN** a request carries `Authorization: Bearer <session identifier>` for a live session of a live user
- **THEN** the handler runs with the principal and session in the context

#### Scenario: Malformed reference refused without lookup
- **WHEN** a request carries a bearer value that is not a well-formed session identifier
- **THEN** it is refused with the authentication-required error and the session store is not called

#### Scenario: User reloaded by reference
- **WHEN** a session's user has been renamed since the session was created, and its old username now belongs to another user
- **THEN** the request authenticates as the session's own user

#### Scenario: Reused reference
- **WHEN** a request presents a session identifier superseded by a renewal whose window has ended
- **THEN** it is refused with an error identifiable as both the authentication-required and the reused-session error

#### Scenario: Consumer scheme
- **WHEN** the consumer sets the scheme to `Session` and a request carries `Authorization: session <live identifier>`
- **THEN** the request is authenticated

### Requirement: A chain runs one bearer mode
A chain SHALL enable at most one of signed bearer tokens and session-reference bearers. Enabling both SHALL fail construction with a configuration error. Signed bearer tokens SHALL remain the default mode; session-reference authentication SHALL be enabled only by the consumer.

#### Scenario: Both modes
- **WHEN** a chain is built with both signed bearer tokens and session-reference bearers enabled
- **THEN** construction fails with a configuration error

### Requirement: The session-reference mode issues session references
With session-reference authentication enabled, every chain endpoint that issues a credential, including login completion, second-factor verification, recovery completion and session renewal, SHALL issue the session's identifier as the credential. Giving such an endpoint a token generator while the mode is enabled SHALL fail construction with a configuration error.

#### Scenario: Login issues the reference
- **WHEN** a password login succeeds on a chain with session-reference authentication
- **THEN** the credential handed to the login responder is the new session's identifier, and a request bearing it authenticates

#### Scenario: Generator with the reference mode
- **WHEN** a chain enables session-reference authentication and gives the login endpoint a token generator
- **THEN** construction fails with a configuration error

### Requirement: The renewal endpoint rotates the presented session with a grace window
When enabled, the renewal endpoint SHALL answer `POST` on its path, `/session/renewal` by default, for an authenticated request with a session, by rotating that session with the grace window, 30 seconds by default. It SHALL answer through a responder, replaceable by the consumer, given the successor, the user and the renewal kind. The default SHALL be 200 with the credential and `Cache-Control: no-store`. Other requests SHALL pass through.

#### Scenario: Default renewal
- **WHEN** an authenticated session sends `POST /session/renewal`
- **THEN** the response is 200 with a credential for a successor, with `Cache-Control: no-store`
- **AND** the old credential still authenticates for 30 seconds

#### Scenario: Consumer path, grace and responder
- **WHEN** the consumer sets the path `/api/v1/session/renewal`, a 60-second grace and a responder, and an authenticated session posts to that path
- **THEN** the consumer's responder is called with the successor, the user and the kind fresh, and the old credential authenticates for 60 seconds

#### Scenario: Retry inside the window
- **WHEN** the old credential posts to the renewal path again inside its window
- **THEN** the responder is called with a further successor and the kind re-rotation

#### Scenario: Unauthenticated renewal
- **WHEN** a request without authentication posts to the renewal path
- **THEN** it is refused with the authentication-required error

#### Scenario: Lost race
- **WHEN** two renewals of the same session run concurrently
- **THEN** one succeeds and the other is refused with the renewal-conflict error

#### Scenario: Grace above the ceiling
- **WHEN** the renewal endpoint is configured with a 10-minute grace
- **THEN** construction fails with a configuration error

#### Scenario: Signed-token mode needs a generator
- **WHEN** the renewal endpoint is enabled on a chain with signed bearer tokens and no token generator
- **THEN** construction fails with a configuration error

### Requirement: The renewal endpoint can give the successor a new lifetime
By default a renewed successor SHALL keep its predecessor's absolute deadline. The consumer SHALL be able to supply a function of the request and the renewed session that chooses the successor's lifetime, bounded as the session capability requires: a choice above the lifetime maximum SHALL fail the renewal with a configuration error and store nothing, and a deadline past the family maximum SHALL be cut to it. The responder SHALL receive the successor with the deadline actually stored.

#### Scenario: Default carries over
- **WHEN** a session whose absolute deadline is 21:00 is renewed at 15:00 with no lifetime function
- **THEN** the successor's absolute deadline is 21:00

#### Scenario: Consumer lifetime
- **WHEN** the consumer's lifetime function returns 30 days, under a 30-day lifetime maximum and a 90-day family maximum, for a family started 10 days ago
- **THEN** the successor's absolute deadline is now plus 30 days

#### Scenario: Last renewal cut to the family maximum
- **WHEN** the same function returns 30 days for a family started 80 days ago under a 90-day family maximum
- **THEN** the responder receives a successor whose absolute deadline is the family start plus 90 days

### Requirement: Login can choose the session's lifetime
Password login SHALL accept a consumer function of the request and its parsed login parameters that returns the lifetime to give the new session, or none for the absolute timeout. With no function, every login SHALL receive the absolute timeout. A returned lifetime above the session manager's maximum SHALL fail the login with a configuration error, map to 500, and create no session.

#### Scenario: Default lifetime
- **WHEN** a password login succeeds on a chain with no lifetime function and a 12-hour absolute timeout
- **THEN** the session's absolute deadline is 12 hours after login

#### Scenario: Remembered login
- **WHEN** the consumer's function returns 30 days for logins whose parameters carry `remember` true, under a 30-day maximum, and such a login succeeds
- **THEN** the session's absolute deadline is 30 days after login

#### Scenario: Lifetime above the maximum
- **WHEN** the consumer's function returns 30 days under a 12-hour maximum
- **THEN** the login fails with a configuration error, mapping to 500, and no session is created

### Requirement: Consumer interceptors publish sessions and run the per-request phase as built-ins do
The chain SHALL let a consumer interceptor publish an authentication result together with its session, after which the session SHALL be readable from the request context and its activity SHALL be recorded as for a built-in. It SHALL also let the interceptor run the per-request policy phase with the same refusal and challenge handling bearer authentication applies, and SHALL refuse that phase unless the session and principal are the ones published.

#### Scenario: Published session is visible and touched
- **WHEN** a consumer interceptor publishes an authentication result and a live session, and the handler reads the session from the context
- **THEN** the handler receives that session, and its activity is recorded after the handler

#### Scenario: Per-request phase without matching publication
- **WHEN** a consumer interceptor runs the per-request phase for a session and principal it has not published
- **THEN** the phase refuses with the authentication-required error and runs no policy

#### Scenario: Per-request challenge handled as built-in
- **WHEN** a consumer interceptor runs the per-request phase for a session the policy challenges for enrolment
- **THEN** the session is saved enrolment-pending and the enrolment gate refuses the request, as for a bearer-authenticated request

### Requirement: The chain's session manager can be given explicitly
By default the chain records activity, and marks per-request challenges, through the session manager of the first enabled built-in that has one. A consumer MAY give the chain its session manager explicitly, which then takes precedence whatever the option order. A nil session manager SHALL be a configuration error.

#### Scenario: Consumer-only chain with its session manager
- **WHEN** the chain is given a session manager explicitly, its only authenticator is a consumer interceptor, and that interceptor publishes a live session
- **THEN** the session's activity is recorded after the handler

#### Scenario: Nil session manager
- **WHEN** the chain is given a nil session manager
- **THEN** construction fails with a configuration error

### Requirement: Logout ends the whole sign-in
When logout deletes a session, it SHALL revoke every session of that session's family, so logging out with an identifier inside its renewal window also ends the successor. A session that was never renewed is the only member of its family, so logout behaves exactly as before for it.

#### Scenario: Logout with the predecessor inside its window
- **WHEN** session O is renewed into S1 with a 30-second grace, and a request bearing O posts to the logout path inside the window
- **THEN** logout answers 200, and a later request bearing S1 is refused

### Requirement: A coalescing interval must be shorter than every idle timeout the policy enforces
A chain whose session manager coalesces activity writes SHALL fail construction with a configuration error when its policy engine enforces an idle timeout no longer than that interval, because the stored last-access time can be up to one interval stale.

#### Scenario: Idle policy shorter than the interval
- **WHEN** the chain's session manager coalesces activity over 10 minutes and its engine holds an idle-timeout policy of 5 minutes
- **THEN** construction fails with a configuration error

#### Scenario: Idle policy longer than the interval
- **WHEN** the same chain's idle-timeout policy is 15 minutes
- **THEN** the chain builds

### Requirement: A renewal does not refresh authentication for freshness checks
An endpoint that requires a recent authentication SHALL judge it by the session's authentication time, never by when the session was created or last renewed.

#### Scenario: Recovery codes after a renewal
- **WHEN** a session signed in at 09:00 is renewed at 15:00, and at 15:01 it asks to regenerate recovery codes under a 15-minute freshness window
- **THEN** the request is refused as needing reauthentication

### Requirement: Unknown session references are throttled per source
The session-reference bearer SHALL, by default, refuse a request before any store lookup when its source has recorded too many refused references within the window, and SHALL record a failure for the source whenever it refuses a presented reference: malformed, unknown, expired, reused, or whose user is gone. A policy refusal of a valid session SHALL NOT be recorded. The default SHALL be 100 failures per source per minute, in its own limiter namespace.

#### Scenario: Flood of unknown references
- **WHEN** one source presents 100 well-formed unknown references within a minute, and then a live one
- **THEN** the 101st request is refused without a store lookup

#### Scenario: Valid sessions spend nothing
- **WHEN** one source makes 1,000 requests with a live reference
- **THEN** none is refused by the guard

### Requirement: The session-reference guard's limiter is replaceable
A consumer SHALL be able to supply the session-reference bearer's limiter, and a shared limiter factory SHALL build it as it builds every guarded flow's.

#### Scenario: Consumer limiter
- **WHEN** the consumer gives the session-reference bearer its own limiter
- **THEN** the bearer's failures are recorded on that limiter

### Requirement: Renewals are throttled per family
The renewal endpoint SHALL, by default, count every renewal of a family and refuse a renewal with the renewal-throttled error, rotating nothing, when the family has renewed 10 times within 10 minutes. A consumer SHALL be able to supply its own limiter.

#### Scenario: Renewal loop
- **WHEN** a session's family renews 10 times within 10 minutes, and renews again
- **THEN** the 11th renewal is refused with the renewal-throttled error, and nothing is rotated

#### Scenario: Another family unaffected
- **WHEN** one family has reached the limit and another family of the same user renews
- **THEN** that renewal succeeds
