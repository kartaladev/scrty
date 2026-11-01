# Spec Delta

## MODIFIED Requirements

### Requirement: Bearer tokens authenticate against a live session and a live user
When enabled, bearer token authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case. When the consumer opts in, it SHALL also accept a bare token with no scheme. Other requests SHALL pass through unchanged.

For each handled request it SHALL:
1. verify the token, refusing a token the verifier rejects as invalid with the authentication failure error and keeping the cause available for logging. A failure to obtain the verification keys from the key source is a dependency failure, not a refusal: it SHALL fail the request with fixed library text that keeps the key source's error reachable, and SHALL NOT be answered with the authentication failure error;
2. load the session the token names, refusing with the authentication-required error when the session is missing, expired or cannot be decrypted, and, when the session manager reports reuse of a superseded identifier, with a refusal that is identifiable both as the authentication-required error and as the reused-session error. Any other failure to load the session, such as a session store or cipher outage, is a dependency failure, not a refusal: it SHALL fail the request with fixed library text that keeps the session manager's error reachable, and SHALL NOT be answered with the authentication-required error;
3. reload the user the token names, so roles are current, refusing with the authentication-required error when the user no longer exists. Any other failure to reload the user, such as a user store outage, is a dependency failure: it SHALL fail the request with fixed library text that keeps the loader's error reachable, and SHALL NOT be answered with the authentication-required error;
4. add the principal, authentication result and session to the context;
5. evaluate the per-request policy phase, telling it whether the session has satisfied its second factor.

When the request's own context ends while the token is being verified, the session is loading or the user is reloading, the request SHALL fail with an error that matches that context's error. An error that matches the cause the context was cancelled with is that context's error too. It SHALL NOT be answered with the authentication failure error or the authentication-required error, and SHALL NOT be logged as a dependency failure, as a verification-key failure or as an undecryptable session.

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

### Requirement: Form login authenticates, applies policy and opens a session
When enabled, form login SHALL answer POST requests on its login path, by default `/login`. Every other request SHALL pass through untouched. It SHALL:
1. read the username and password from form fields, `username` and `password` by default, or from a JSON object when the form yields neither and the request declares a JSON content type;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication policy phase before checking credentials, and refuse on a deny;
4. authenticate, recording a failed attempt on an authentication failure and clearing attempts on success, where a failure of that bookkeeping is logged and does not change the outcome;
5. evaluate the post-authentication policy phase, and refuse on a deny;
6. build a session recording the password first factor;
7. when the post-authentication phase challenged, mark the challenge pending on that session;
8. issue an access token for the session;
9. store the session, with any pending challenge, in one write, and only then hand out the token.

A failure to issue the token SHALL store no session, and SHALL fail the request as a dependency failure, not as a refusal. A challenge SHALL refuse with a challenge error carrying the kind, the pending session and the token. A success SHALL write the success response and SHALL NOT call the handler. By default the success response is a JSON document carrying the access token, an empty refresh token field and the session's idle expiry. The consumer SHALL be able to replace the success response writer, the login path and the field names.

#### Scenario: Successful login
- **WHEN** a user with no pending challenge posts correct credentials to the login path
- **THEN** a session is created, the response is a JSON document carrying an access token and the session's idle expiry, and the handler is not called

#### Scenario: Wrong password
- **WHEN** a user posts an incorrect password
- **THEN** the request is refused with the authentication failure error and a failed attempt is recorded

#### Scenario: Locked account is not probed
- **WHEN** the pre-authentication phase denies a locked account
- **THEN** the request is refused, its error identifiable as both the authentication failure and the account-locked refusal, and the account's password is never checked

#### Scenario: Login raises a challenge
- **WHEN** the post-authentication phase challenges for a second factor
- **THEN** the session is stored as pending before the token is handed out, and the request is refused with a challenge error carrying the second-factor kind, the session and the token

#### Scenario: Token cannot be issued
- **WHEN** a user posts correct credentials and the key source fails when the token is issued
- **THEN** the request fails with an error that matches neither the authentication failure error nor the authentication-required error
- **AND** no session is stored

#### Scenario: Consumer success response and field names
- **WHEN** the consumer sets the field names to `email` and `secret` and supplies their own success response writer
- **THEN** a login posting `email` and `secret` succeeds and writes the consumer's response

#### Scenario: Other methods pass through
- **WHEN** a GET request arrives on the login path
- **THEN** form login does not handle it and the request continues

### Requirement: The public key set is served
When enabled, the chain SHALL answer GET requests on the key set path, by default `/.well-known/jwks.json`. It SHALL respond 200 with a JSON content type and the current public verification keys as a JSON Web Key Set, and SHALL NOT call the handler. The response SHALL never contain private key material. The key set SHALL be obtained with the request's context. A failure to obtain the key set SHALL propagate as a dependency failure, with fixed library text that keeps the cause reachable. The consumer SHALL be able to change the path.

#### Scenario: Key set served
- **WHEN** a client requests the key set path
- **THEN** the response is 200 with a JSON Web Key Set of the current public keys and no private members

#### Scenario: The key set is obtained with the request's context
- **WHEN** a client requests the key set path under a request context carrying a value
- **THEN** the key set provider is asked with a context carrying that value

#### Scenario: Key set outage
- **WHEN** a client requests the key set path and the key set cannot be obtained
- **THEN** the request fails with an error from which the cause is reachable, which the default status mapping answers with 500

#### Scenario: Consumer path
- **WHEN** the consumer sets the path to `/keys`
- **THEN** the key set is served at `/keys` and `/.well-known/jwks.json` passes through

### Requirement: Redemption flows plug into named seams
The chain SHALL provide the seams that interceptors from other capabilities use, without those interceptors being part of this capability:
- named slots for federated login, one-time link redemption, API keys, client certificates, second-factor enrolment and second-factor challenges, the enrolment slot immediately before the second-factor challenge slot;
- a login completion step;
- a source throttle step.

The login completion step SHALL be the one form login uses. It SHALL require the principal, first factor, submitted username and password change time as inputs, and SHALL accept additional session attributes that its caller wants recorded in the write that creates the session, such as a federated login's provider session. It SHALL behave identically for every first factor that uses it:
1. evaluate the post-authentication phase;
2. on a deny, refuse with the policy's reason;
3. build the session with its first factor and the caller's additional attributes;
4. mark any pending challenge on it, including, for an enrolment challenge, the enrolment-pending state and its lowered deadlines;
5. issue the credential for the session;
6. when the caller spends a single-use credential, such as a one-time link or a handoff code, spend it only after the credential has been issued;
7. store the session, with any pending challenge and the caller's additional attributes, in one write, and only then hand out the credential;
8. publish the authentication onto the request context;
9. refuse with a challenge error when a challenge is pending.

A failure to issue the credential SHALL store no session, SHALL leave unspent anything the caller would have spent, and SHALL fail the request as a dependency failure, not as a refusal. A credential SHALL never be handed out for a session that was not stored.

The source throttle step SHALL expose the check before guarded work and the failure recording after it, using the chain's client address, refusal rules and sampled logs.

#### Scenario: Another first factor reuses login completion
- **WHEN** a redemption interceptor added by another capability authenticates a user and hands the principal to the login completion step, and policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Enrolment challenge at login completion
- **WHEN** a magic-link redemption hands the login completion step a required, unenrolled user, and the enrolment path is on
- **THEN** the request is refused with an enrolment challenge error carrying a session in the enrolment-pending state and a token
- **AND** the session was stored in that state before the token was handed out

#### Scenario: Credential cannot be issued at login completion
- **WHEN** a first factor hands the login completion step a principal, and the key source fails when the credential is issued
- **THEN** the request fails as a dependency failure, not as a refusal
- **AND** no session is stored, and anything the first factor would have spent stays unspent

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

### Requirement: The renewal endpoint rotates the presented session with a grace window
When enabled, the renewal endpoint SHALL answer `POST` on its path, `/session/renewal` by default, for an authenticated request with a session, by rotating that session with the grace window, 30 seconds by default. It SHALL answer through a responder, replaceable by the consumer, given the successor, the user and the renewal kind. The default SHALL be 200 with the credential and `Cache-Control: no-store`. Other requests SHALL pass through.

The successor's credential SHALL be issued before the rotation is stored. When it cannot be issued, the renewal SHALL fail as a dependency failure, not as a refusal, whatever the issuer's error wraps, and SHALL store, supersede and revoke nothing, so the presented credential keeps the standing it had. Every path that issues a credential SHALL answer an issuing failure so.

The endpoint's reload of the session's user SHALL refuse a user who no longer exists with the authentication-required error. Any other reload failure is a dependency failure: it SHALL fail the request with fixed library text that keeps the loader's error reachable, and SHALL NOT be answered with the authentication-required error. A reload the request's own context ended SHALL fail with an error that matches that context's error, and SHALL NOT be answered with the authentication-required error.

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

#### Scenario: Successor credential cannot be issued
- **WHEN** a live session posts to the renewal path in signed-token mode, and the key source fails when the successor's token is issued
- **THEN** the renewal fails as a dependency failure, not as a refusal, and nothing is superseded
- **AND** 31 seconds later the same credential still authenticates and renews, and no reuse is reported

#### Scenario: An issuer error that wraps a refusal is still a dependency failure
- **WHEN** the consumer's token generator fails with an error that wraps an error the default status mapping answers with 401, at renewal or at login
- **THEN** the default mapping answers 500, and the issuer's error stays reachable from the returned error

#### Scenario: User store outage at renewal
- **WHEN** a live session posts to the renewal path, and the user loader fails with an error that is not identifiable as "user not found"
- **THEN** the request fails with an error from which the loader's error is reachable, which the default status mapping answers with 500
- **AND** the error does not match the authentication-required error, and nothing is rotated

#### Scenario: Grace above the ceiling
- **WHEN** the renewal endpoint is configured with a 10-minute grace
- **THEN** construction fails with a configuration error

#### Scenario: Signed-token mode needs a generator
- **WHEN** the renewal endpoint is enabled on a chain with signed bearer tokens and no token generator
- **THEN** construction fails with a configuration error

### Requirement: Unknown session references are throttled per source
The session-reference bearer SHALL, by default, refuse a request before any store lookup when its source has recorded too many refused references within the window, and SHALL record a failure for the source whenever it refuses a presented reference: malformed, unknown, expired, unreadable, reused, or whose user is gone, is not the user the session records, or is not active. A policy refusal of a valid session SHALL NOT be recorded. A load that fails as a dependency failure, such as a session store, cipher or user store outage, and a load the request's own context ended, SHALL NOT be recorded, because no refusal was reached. The default SHALL be 100 failures per source per minute, in its own limiter namespace.

#### Scenario: Flood of unknown references
- **WHEN** one source presents 100 well-formed unknown references within a minute, and then a live one
- **THEN** the 101st request is refused without a store lookup

#### Scenario: Valid sessions spend nothing
- **WHEN** one source makes 1,000 requests with a live reference
- **THEN** none is refused by the guard

#### Scenario: An outage spends nothing
- **WHEN** one source presents a live reference 101 times within a minute while the session store fails every load with an error that is not a refusal
- **THEN** each request fails as a dependency failure, and none is refused by the guard

### Requirement: Refused late renewals count against the source
In the session-reference mode, a late credential let through to the renewal endpoint under unused-successor recovery, which the endpoint then refuses as expired, not found or reused, SHALL be recorded against its source as a refused reference is. One the endpoint renews SHALL NOT be recorded. One that fails as a dependency failure, or whose request's own context ended before the load reached a verdict, SHALL NOT be recorded. A load that reached a refusal SHALL be refused and recorded even when the request's own context has ended by then.

#### Scenario: Refused late renewals count against the source
- **WHEN** unused-successor recovery is on, and one source posts 100 late renewals within a minute that the endpoint refuses, and then another late renewal
- **THEN** the 101st request is refused without a store lookup

#### Scenario: A recovered late renewal spends nothing
- **WHEN** unused-successor recovery is on, and a late renewal of a session whose successor was never used is renewed
- **THEN** nothing is recorded against its source

#### Scenario: A late renewal during an outage spends nothing
- **WHEN** unused-successor recovery is on, and a late renewal fails because the session store fails with an error that is not a refusal
- **THEN** nothing is recorded against its source

#### Scenario: A refusal wins over a client that leaves
- **WHEN** unused-successor recovery is on, and the endpoint's load of a late renewal reports the session reused while the request's context has been cancelled
- **THEN** the renewal is refused with the authentication-required error, matching the reused-session error
- **AND** one failure is recorded against its source

### Requirement: A resolved session authenticates only its own, active user
Signed bearer tokens, session references and the renewal endpoint, including a late renewal, SHALL refuse with the authentication-required error when the reloaded user's identifier differs from the user reference the session records, or when the reloaded user is not active. A refused session SHALL NOT be revoked by the refusal; it authenticates again if its user is re-enabled before it expires. A reload that fails for any reason other than the user not being found is not this refusal: each of these paths answers it as a dependency failure, or, when the request's own context ended, with that context's error.

#### Scenario: Username reassigned to another user
- **WHEN** a signed bearer token names user `u-1`'s session, and the username in the token now belongs to user `u-2`
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
