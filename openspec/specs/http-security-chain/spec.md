# http-security-chain Specification

## Purpose

Puts scrty's authentication, session, policy and authorization decisions in front of an HTTP handler as one ordered, extensible interceptor chain that fails closed, reports wiring mistakes before traffic, and hands the handler everything it resolved.

## Requirements

### Requirement: Interceptors run in slot order around the handler
The chain SHALL run interceptors in ascending slot order, the lowest slot outermost and the downstream handler innermost. Interceptors registered at the same slot SHALL run in registration order. The library SHALL publish named slots for its built-in interceptors and for the interceptors other capabilities add, spaced so that the slots immediately before and after each named slot are free.

#### Scenario: Slot order
- **WHEN** interceptors are registered at slots 500, 100 and 300, in that order
- **THEN** a request passes through the slot 100 interceptor, then 300, then 500, then the handler

#### Scenario: Equal slots keep registration order
- **WHEN** two interceptors are registered at the same slot
- **THEN** the one registered first runs first

#### Scenario: Adjacent slots
- **WHEN** one interceptor is registered immediately before the bearer token slot and another immediately after it
- **THEN** the first runs before bearer token authentication and the second runs after it and before the next named slot

### Requirement: An interceptor continues, stops or acts after the handler
Each interceptor SHALL decide whether the request continues to the next interceptor. An interceptor that does not continue SHALL stop the request, and neither later interceptors nor the handler SHALL run. An interceptor that continues SHALL be able to act after everything inside it, including the handler, has returned. An error returned by any interceptor or later stage SHALL propagate outwards unchanged through every enclosing interceptor that does not handle it.

#### Scenario: Short-circuit
- **WHEN** an interceptor returns without continuing
- **THEN** no later interceptor runs and the handler is not called

#### Scenario: After the handler
- **WHEN** an interceptor continues and the handler then writes a response
- **THEN** the interceptor's post-handler step runs after the handler returns

#### Scenario: Error passes through
- **WHEN** an interceptor at slot 900 returns an error and the interceptors at lower slots do not handle it
- **THEN** the chain's caller receives that same error

### Requirement: Consumers register their own interceptors
A consumer SHALL be able to register any number of their own interceptors at any slot, including slots relative to a named slot. A consumer interceptor SHALL be able to do everything a built-in one can: read the request, add to the request context, write a response, stop the request and return an error.

#### Scenario: Consumer interceptor after authentication
- **WHEN** a consumer registers an audit interceptor immediately after the bearer token slot, and a request carries a valid bearer token
- **THEN** the audit interceptor observes the authenticated principal in the request context

#### Scenario: Consumer interceptor refuses
- **WHEN** a consumer interceptor returns its own error
- **THEN** the handler is not called and the error propagates to the error handling like any built-in refusal

### Requirement: Wiring mistakes fail at construction
Building a chain SHALL return a configuration error, and no usable chain, when the configuration cannot take effect. This SHALL include at least:
- an absent interceptor;
- an enabled built-in interceptor missing a dependency it needs, including a dependency that is present but holds a nil value;
- an absent rate-limiter factory, when the option is given;
- an absent refusal log reporter;
- a login body limit of zero or less;
- form login or HTTP Basic authentication enabled more than once;
- MFA enabled more than once;
- account recovery enabled more than once.

The error SHALL name the option and the dependency at fault. Every public option SHALL either take effect or be refused at construction.

#### Scenario: Missing dependency
- **WHEN** form login is enabled without a session manager
- **THEN** construction fails with an error naming form login and the missing session manager

#### Scenario: Nil value behind an interface
- **WHEN** bearer token authentication is given a user loader that is a nil pointer of a concrete type
- **THEN** construction fails instead of the first request panicking

#### Scenario: Absent interceptor
- **WHEN** a consumer registers an absent interceptor at any slot
- **THEN** construction fails

#### Scenario: Form login enabled twice
- **WHEN** a consumer enables form login twice, on two paths, each with its own limiter
- **THEN** construction fails with an error naming form login, because one chain has one form login and its password-login flow names one endpoint

#### Scenario: MFA enabled twice
- **WHEN** a consumer enables MFA twice on one chain, on two prefixes, each with its own methods
- **THEN** construction fails with an error naming MFA, because one chain offers one set of second-factor methods, and every method belongs in a single MFA configuration

#### Scenario: Account recovery enabled twice
- **WHEN** a consumer enables account recovery twice on one chain
- **THEN** construction fails with an error naming account recovery, because one chain has one account recovery

#### Scenario: Absent factory
- **WHEN** the chain is given a rate-limiter factory option holding a nil value
- **THEN** construction fails with an error naming the rate-limiter factory

### Requirement: The request context is derived, never replaced
The chain SHALL start from the incoming request's context, so values and cancellation set before the chain survive. Security state an interceptor adds SHALL be visible to every later interceptor and to the handler through the request context. That state is the authentication result, principal, session and authorizer. Calls an interceptor makes to scrty's cores SHALL receive the request's context.

#### Scenario: Principal reaches the handler
- **WHEN** a request authenticates with a valid bearer token
- **THEN** the handler reads the authenticated principal and its session from the request context

#### Scenario: Upstream value survives
- **WHEN** middleware before the chain stores a request identifier in the context
- **THEN** the handler still reads that request identifier

#### Scenario: Cancellation propagates inward
- **WHEN** the client cancels the request while an interceptor is waiting on a session lookup
- **THEN** the lookup observes the cancellation

### Requirement: Form login authenticates, applies policy and opens a session
When enabled, form login SHALL answer POST requests on its login path, by default `/login`. Every other request SHALL pass through untouched. It SHALL:
1. read the username and password from form fields, `username` and `password` by default, or from a JSON object when the form yields neither and the request declares a JSON content type;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication policy phase before checking credentials, and refuse on a deny;
4. authenticate, recording a failed attempt on an authentication failure and clearing attempts on success, where a failure of that bookkeeping is logged and does not change the outcome;
5. evaluate the post-authentication policy phase, and refuse on a deny;
6. create a session recording the password first factor;
7. when the post-authentication phase challenged, mark the challenge pending and save the session before issuing a token;
8. issue an access token.

A challenge SHALL refuse with a challenge error carrying the kind, the pending session and the token. A success SHALL write the success response and SHALL NOT call the handler. By default the success response is a JSON document carrying the access token, an empty refresh token field and the session's idle expiry. The consumer SHALL be able to replace the success response writer, the login path and the field names.

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
- **THEN** the session is saved as pending before the token is issued, and the request is refused with a challenge error carrying the second-factor kind, the session and the token

#### Scenario: Consumer success response and field names
- **WHEN** the consumer sets the field names to `email` and `secret` and supplies their own success response writer
- **THEN** a login posting `email` and `secret` succeeds and writes the consumer's response

#### Scenario: Other methods pass through
- **WHEN** a GET request arrives on the login path
- **THEN** form login does not handle it and the request continues

### Requirement: Login request bodies are bounded and malformed logins are client errors
Form login SHALL read at most a bounded number of request body bytes, 64 KiB by default. A body over the limit SHALL be refused with the request-too-large error without being parsed. A login with no credentials, or with a JSON body that cannot be decoded, SHALL be refused with the malformed-login error, and no authentication SHALL be attempted. The consumer SHALL be able to change the limit.

#### Scenario: Oversized body
- **WHEN** a JSON login body of 1 MiB arrives with the default limit
- **THEN** the request is refused with the request-too-large error and no authentication is attempted

#### Scenario: Missing credentials
- **WHEN** a login request carries neither form fields nor a JSON body
- **THEN** it is refused with the malformed-login error

#### Scenario: Raised limit
- **WHEN** the consumer sets the limit to 256 KiB and a 100 KiB login body arrives
- **THEN** the body is parsed normally

### Requirement: HTTP Basic authentication is stateless
When enabled, Basic authentication SHALL handle requests whose `Authorization` header starts with `Basic `, and SHALL pass other requests through unchanged. It SHALL:
1. refuse a header whose value is not valid base64 or has no `:` separator with the authentication failure error;
2. check the request's source against the password-login guard, and refuse a throttled or unattributable source;
3. evaluate the pre-authentication phase before checking credentials;
4. on a failed authentication, record a failed attempt, set a `WWW-Authenticate` Basic challenge header naming the realm (default `Restricted`), and refuse with the authentication failure error;
5. on success, evaluate the stateless-authentication policy phase, and continue with the principal in the context.

Every refusal answered 401 SHALL carry the `WWW-Authenticate` challenge header. It SHALL NOT create a session or issue a token. A challenge from the stateless-authentication phase SHALL refuse with a challenge error carrying no session and no token. The consumer SHALL be able to set the realm.

#### Scenario: Valid credentials
- **WHEN** a request carries correct Basic credentials
- **THEN** the handler runs with the principal in the context and no session is created

#### Scenario: Invalid credentials
- **WHEN** a request carries an incorrect Basic password
- **THEN** it is refused with the authentication failure error and the response carries a `WWW-Authenticate` header for the realm

#### Scenario: Consumer realm
- **WHEN** the consumer sets the realm to `internal-api` and credentials are refused
- **THEN** the `WWW-Authenticate` header names `internal-api`

#### Scenario: Stateless request needing a second factor
- **WHEN** the stateless-authentication phase requires a second factor for the user
- **THEN** the request is refused with that phase's reason, or with a challenge error carrying no session and no token

#### Scenario: Throttled source still challenged
- **WHEN** a Basic request arrives from a source the password-login guard throttles
- **THEN** it is refused with the throttled error and the response carries a `WWW-Authenticate` header for the realm

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

### Requirement: Logout ends the session
When enabled, logout SHALL answer POST requests on its path, by default `/logout`. It SHALL refuse a request with no authentication result with the authentication-required error. When the request carries a session, logout SHALL delete it, and a session that is already gone SHALL NOT be an error. A stateless authenticated request SHALL be answered without deleting anything. Logout SHALL NOT call the handler. The consumer SHALL be able to change the path.

Logout SHALL accept an optional end-session step. When one is configured and the deleted session records an identity provider, logout SHALL call it after the delete, with the deleted session and the request's optional `state` form value. When the step returns a URL, logout SHALL answer 200 with a JSON body carrying it as `end_session_url` and with `Cache-Control: no-store`. Otherwise logout SHALL answer 200 with an empty body. A failure of the step SHALL be logged and SHALL NOT fail the logout, because the session has already been deleted. With no step configured, logout SHALL behave exactly as it does without federated login.

#### Scenario: Logout
- **WHEN** an authenticated request posts to the logout path
- **THEN** its session is deleted, the response is 200 with an empty body, and a later request with the same token is refused

#### Scenario: Session already deleted
- **WHEN** two logout requests for the same session race and the second finds the session gone
- **THEN** the second is also answered 200

#### Scenario: Anonymous logout
- **WHEN** a request with no authentication posts to the logout path
- **THEN** it is refused with the authentication-required error

#### Scenario: Consumer path
- **WHEN** the consumer sets the logout path to `/session/end`
- **THEN** logout answers there and a POST to `/logout` passes through

#### Scenario: Federated session with an end-session step
- **WHEN** an end-session step is configured and a session that records provider `corp` is logged out, and the step returns `https://idp.example/logout?id_token_hint=...`
- **THEN** the session is deleted before the step is called
- **AND** the response is 200 with `end_session_url` equal to that URL and `Cache-Control: no-store`

#### Scenario: Password session with an end-session step
- **WHEN** an end-session step is configured and a session established by a password is logged out
- **THEN** the step is not called and the response is 200 with an empty body

#### Scenario: End-session step fails
- **WHEN** an end-session step is configured and returns an error for a federated session
- **THEN** the session is deleted, the error is logged, and the response is 200 with an empty body

### Requirement: Session activity is recorded after the handler
For every request that carries a session, the chain SHALL advance the session's idle deadline after the handler and every inner interceptor have returned, including when an inner stage refused the request. A failure to advance the deadline SHALL NOT change the response or the error the chain returns.

#### Scenario: Activity recorded
- **WHEN** a request with a live session completes
- **THEN** the session's idle deadline has been advanced

#### Scenario: Store failure after the response
- **WHEN** advancing the deadline fails after the handler wrote 200
- **THEN** the client receives 200 and the chain returns no error

#### Scenario: Refused request still counts as activity
- **WHEN** a request with a live session is refused by a guard
- **THEN** the session's idle deadline is still advanced

### Requirement: The public key set is served
When enabled, the chain SHALL answer GET requests on the key set path, by default `/.well-known/jwks.json`. It SHALL respond 200 with a JSON content type and the current public verification keys as a JSON Web Key Set, and SHALL NOT call the handler. The response SHALL never contain private key material. A failure to obtain the key set SHALL propagate as an error. The consumer SHALL be able to change the path.

#### Scenario: Key set served
- **WHEN** a client requests the key set path
- **THEN** the response is 200 with a JSON Web Key Set of the current public keys and no private members

#### Scenario: Consumer path
- **WHEN** the consumer sets the path to `/keys`
- **THEN** the key set is served at `/keys` and `/.well-known/jwks.json` passes through

### Requirement: Centralized authorization rules are enforced in the chain
The authorization stage SHALL always run, and SHALL add the authorizer to the request context so per-endpoint guards can use it. When the consumer configures rules, the first rule whose matcher accepts the request SHALL decide, using the `authorization` capability's requirements. A request that matches no rule SHALL be refused with the access-denied error. When no rules are configured, the stage SHALL NOT enforce anything centrally, and authorization is left to per-endpoint guards.

#### Scenario: First matching rule decides
- **WHEN** the rules are "`/admin/**` requires role ADMIN" then "any request is permitted", and a principal without ADMIN requests `/admin/users`
- **THEN** the request is refused with the access-denied error

#### Scenario: Unmatched request
- **WHEN** the only rule covers `/api/**` and a request arrives for `/other`
- **THEN** it is refused with the access-denied error

#### Scenario: Anonymous request to a protected rule
- **WHEN** an unauthenticated request matches a rule requiring authentication
- **THEN** it is refused with the authentication-required error

#### Scenario: Guards only
- **WHEN** the consumer configures no rules
- **THEN** every request reaches its route, and guards on that route can read the authorizer

### Requirement: Per-endpoint guards fail closed
Per-endpoint guards SHALL be able to require an authenticated principal, a set of resource privileges (any of, or all of) or ownership of a resource. They SHALL be enforced in addition to any centralized rule. A guard SHALL refuse without calling the route when any of these holds:
- no principal is present, refused with the authentication-required error;
- no authorizer is available, refused with the access-denied error;
- the resource identifier cannot be extracted, refused with the extractor's error;
- the authorizer refuses, refused with the authorizer's error.

A guard SHALL use the authorizer from the request context, falling back to the one it was built with.

#### Scenario: Missing privilege
- **WHEN** a route guarded by "any of read on admin/user" is called by a principal without that privilege
- **THEN** the route is not called and the request is refused with the access-denied error

#### Scenario: Guard on top of a permissive rule
- **WHEN** a centralized rule permits the request but the route's guard refuses it
- **THEN** the route is not called

#### Scenario: Identifier extraction fails
- **WHEN** an ownership guard's identifier extractor returns an error
- **THEN** the route is not called and the extractor's error is the refusal

### Requirement: The net/http chain attributes requests to the transport peer
The net/http integration SHALL attribute a request to the host part of its transport peer address, and SHALL NOT read any forwarding header. A peer address that is not in host and port form SHALL yield no client address. Forwarded-header resolution SHALL be available only through an integration whose framework holds a trusted proxy configuration.

#### Scenario: Spoofed header ignored
- **WHEN** a client connecting from 198.51.100.7 sends `X-Forwarded-For: 203.0.113.9`
- **THEN** the request is attributed to 198.51.100.7

#### Scenario: Peer without a port
- **WHEN** a request arrives over a transport whose peer address has no port
- **THEN** the request has no client address

### Requirement: An unattributable client address is refused, never pooled
A throttled flow SHALL refuse a request before its guarded work runs when the request's client address is any of:
- empty;
- not a single IP address;
- unspecified (`0.0.0.0`, `::`, or `::ffff:0.0.0.0`).

The refusal SHALL be the authentication failure error, so it reads to the client like any other failed attempt, and SHALL be logged at ERROR, naming the reason. Such requests SHALL never share a rate-limit bucket. A limiter that fails SHALL also refuse. A failed attempt SHALL be recorded even when the client disconnects before the response.

#### Scenario: Unix socket peer
- **WHEN** a request to a throttled flow arrives with client address `0.0.0.0`
- **THEN** it is refused with the authentication failure error, the guarded work does not run, and an ERROR record says the address is unspecified

#### Scenario: List-valued address
- **WHEN** an integration reports the client address `203.0.113.9, 198.51.100.7`
- **THEN** the request is refused and no bucket is keyed on that value

#### Scenario: Limiter failure
- **WHEN** the limiter returns an error while checking a source
- **THEN** the request is refused

#### Scenario: Client disconnects after guessing
- **WHEN** a client submits a wrong credential to a throttled flow and cancels the request before the response
- **THEN** the failure is still counted against its source

### Requirement: Chain refusal logs are sampled and summarised
The chain's own refusal log records SHALL be sampled per key per window, one minute by default. These are the throttled-source warning, the limiter failure and the unattributable-address errors. The keys SHALL be:
- the flow and canonical source for the throttled-source warning, so that addresses grouped into one source share one key;
- the flow alone for a limiter failure;
- the flow and reason for an unattributable address.

A throttled attempt SHALL produce one throttled-source record, not one from the guard and another from the chain. A written record SHALL carry the count suppressed before it when that count is non-zero. The sampler SHALL always have a reporter. By default the reporter writes one summary record naming the key and the suppressed count. The consumer SHALL be able to:
- change the interval, with zero or less disabling sampling;
- replace the reporter;
- flush pending counts, for example at shutdown.

Flushing the chain's refusal logs SHALL report the pending counts of every log sampler the chain holds, not only its own:
- the samplers of the interceptors it built, including the second-factor verification throttle, the enrolment path and every per-flow source guard (the chain builds each guard itself; a consumer supplies at most the limiter behind it);
- the samplers of every component it was given that can flush its refusal logs: the policies registered on its policy engine, the authenticators of form login and basic authentication, and the OIDC manager and handoff manager.

A component the consumer holds but never gave the chain is not reached, and the chain's documentation SHALL say so and name the components that flush otherwise.

The interval SHALL govern only the chain's own records. It SHALL NOT change which requests are refused, or how any other component samples its logs. A request that ended before the rate-limit check SHALL be logged at DEBUG, unsampled.

#### Scenario: Flood from one source
- **WHEN** one source is throttled 50 times within a minute
- **THEN** one warning is written for that source in that window

#### Scenario: Rotating within one IPv6 source
- **WHEN** 50 different addresses inside one throttled IPv6 /64 are refused within a minute
- **THEN** one throttled-source warning is written for that /64 in that window

#### Scenario: Sources do not suppress each other
- **WHEN** two sources are throttled in the same window
- **THEN** a warning is written for each

#### Scenario: Summary for a key that goes quiet
- **WHEN** a source is throttled 5 times in one window and not again
- **THEN** once its count ages out, the default reporter writes a summary record naming that source's key with a count of 4

#### Scenario: Consumer reporter and flush
- **WHEN** the consumer supplies a reporter that increments a metric, 3 records are suppressed, and the chain's refusal logs are flushed
- **THEN** the consumer's reporter receives the pending count of 3

#### Scenario: Sampling disabled
- **WHEN** the interval is set to zero and a source is throttled 5 times
- **THEN** five warnings are written

#### Scenario: One flush reaches the components
- **WHEN** a chain with form login, the second-factor verify endpoint, a magic-link source guard and OIDC login holds suppressed counts in the password authenticator, the verification throttle, the guard and the OIDC manager, and the chain's refusal logs are flushed
- **THEN** each of those components' reporters receives its pending count

#### Scenario: Registered policy flushed
- **WHEN** a second-factor policy registered on the chain's engine has suppressed refusals and the chain's refusal logs are flushed
- **THEN** the policy's reporter receives its pending count

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

### Requirement: A reused password at the resolve endpoint leaves the change owed
When the consumer's password-change function refuses a new password with the password-reused error, the resolve endpoint SHALL refuse the request with that error, SHALL NOT clear the pending password-change marker, and SHALL keep gating the session. The library SHALL NOT read the new password from the request itself. The reuse check runs only where the consumer's function calls the reuse guard.

#### Scenario: Reused password keeps the challenge pending
- **WHEN** a session with a pending password-change challenge posts to the consumer's resolve endpoint, and the consumer's function refuses the new password as reused through the reuse guard
- **THEN** the request is refused with the password-reused error, mapped to 422
- **AND** the next request on that session is still refused with a password-change challenge error

#### Scenario: Endpoint without a reuse guard
- **WHEN** the consumer's resolve function changes the password without calling a reuse guard, and the caller submits their current password as the new one
- **THEN** the change succeeds and the marker is cleared, because reuse checking is off unless the consumer enables it

### Requirement: An opt-in endpoint lists the methods a pending session can use
The chain SHALL offer an endpoint that lists the MFA methods the session's user can use. It SHALL be off by default, and SHALL exist only when the consumer enables it on the MFA slot. It SHALL answer GET requests to its path, `/mfa/methods` by default, and SHALL NOT read the URL query. It SHALL answer only a session whose MFA challenge is pending:
- a request with no session SHALL be refused as authentication required;
- a session that owes no MFA challenge, including a fully authenticated one, SHALL be refused as no MFA challenge pending;
- an enrolment-only session SHALL be refused by the enrolment gate like any other route.

The list SHALL come from the one function the security policies use to decide usability, so it can never disagree with the MFA challenge or the policies. A failed lookup SHALL be a refusal, never an empty list. By default the endpoint SHALL answer with a documented JSON body naming each method's name, channel and whether it has a begin step; a consumer SHALL be able to replace the response through a responder. The endpoint's path and responder SHALL be settable only inside the option that enables it, and an explicitly given empty path or absent responder SHALL be refused rather than read as the default. Chain assembly SHALL fail with a configuration error when the endpoint's path is empty or equals the logout path or a path under the MFA verify or begin prefixes.

#### Scenario: Off by default
- **WHEN** the MFA slot is enabled without the listing option and a pending session sends GET `/mfa/methods`
- **THEN** no listing is produced by the library

#### Scenario: Pending session lists its methods
- **WHEN** the listing is enabled, TOTP and `email-code` are configured, `u-1` is enrolled on TOTP only, and `u-1`'s pending session sends GET `/mfa/methods`
- **THEN** the response is the default JSON body listing `totp` only

#### Scenario: A full session is refused
- **WHEN** the listing is enabled and a session whose second factor is satisfied sends GET `/mfa/methods`
- **THEN** it is refused as no MFA challenge pending

#### Scenario: No session
- **WHEN** the listing is enabled and a request without a session sends GET `/mfa/methods`
- **THEN** it is refused as authentication required

#### Scenario: Lookup failure
- **WHEN** the listing is enabled and a method's enrolment lookup fails for a pending session
- **THEN** the request is refused with that failure and no list is written

#### Scenario: Consumer path and responder
- **WHEN** the listing is enabled with path `/account/mfa/methods` and a responder that writes its own document, and a pending session sends GET there
- **THEN** the consumer's responder writes the response with the same list

#### Scenario: Explicit empty path
- **WHEN** the listing is enabled with an explicitly empty path
- **THEN** construction fails with a configuration error

#### Scenario: Path collides with a verify path
- **WHEN** the listing path is set to `/mfa/verify/totp`
- **THEN** chain assembly fails with a configuration error

### Requirement: A recovery-pending session reaches only the binding endpoints and logout
When recovery is enabled, a request whose session is in the recovery-pending state SHALL be refused with a challenge error of the account-recovery kind carrying that session. The refusal SHALL come before the password-change gate, the enrolment gate, the MFA challenge gate and any interceptor after them run, whatever the request's method or path. These requests are exempt:
- a POST under an MFA enrolment prefix, when the enrolment path is enabled;
- a POST to the passkey registration begin, finish, saved-code confirm and emailed-code confirm paths, when passkey registration is enabled and the passkey MFA method is on the MFA slot, so a registered passkey can resolve the challenge the binding raises;
- a POST to the password-change resolve endpoint, when one is registered;
- the logout endpoint, wherever it is placed in the chain relative to the gate.

There SHALL be no option that lets further routes through. A capability that adds another way to bind an authenticator SHALL add its endpoint to this list in its own change. A recovery-pending session SHALL always be able to log out, and logging out SHALL end it.

The per-request policy phase SHALL still be evaluated for a recovery-pending session, and a deny SHALL refuse the request. A challenge it raises SHALL NOT be marked on the session: marking one would take the session out of the recovery-pending state without a binding.

#### Scenario: Protected route
- **WHEN** a recovery-pending session requests `/invoices`
- **THEN** it is refused with an account-recovery challenge error carrying the session, and the handler does not run

#### Scenario: Enrolment reachable
- **WHEN** the enrolment path is enabled and a recovery-pending session posts to `/mfa/enrol/begin/totp`
- **THEN** a pending enrolment is begun

#### Scenario: Passkey registration reachable
- **WHEN** passkey registration is enabled and a recovery-pending session posts to `/passkey/register/begin`
- **THEN** a registration challenge is issued

#### Scenario: Passkey registration without the passkey method
- **WHEN** passkey registration is enabled, the passkey MFA method is not on the MFA slot, and a recovery-pending session posts to `/passkey/register/begin`
- **THEN** it is refused with an account-recovery challenge error, and no registration challenge is issued

#### Scenario: Passkey listing not reachable
- **WHEN** a recovery-pending session sends a GET to `/passkey/credentials`
- **THEN** it is refused with an account-recovery challenge error

#### Scenario: Verify path is not reachable
- **WHEN** a recovery-pending session posts a code to `/mfa/verify/totp`
- **THEN** it is refused with an account-recovery challenge error and no code is verified

#### Scenario: Password change reachable
- **WHEN** the consumer registered `POST /account/password` as the resolve endpoint and a recovery-pending session posts there
- **THEN** the consumer's function runs

#### Scenario: Logout
- **WHEN** a recovery-pending session posts to the logout endpoint
- **THEN** the session is deleted, and its handle no longer loads

#### Scenario: Per-request challenge not marked
- **WHEN** a recovery-pending session of a user required to use MFA, whose enrolments were removed by the recovery, requests `/invoices`
- **THEN** the request is refused with an account-recovery challenge error
- **AND** the session is still in the recovery-pending state

### Requirement: A password change resolved on a recovery-pending session completes the recovery
When the consumer's function at the password-change resolve endpoint succeeds for a recovery-pending session, the chain SHALL restore the session's deadlines as the `sessions` capability defines, set its second-factor state to none, clear any pending password-change marker, and save it. The consumer's function SHALL own the response, as for any resolution. The session SHALL NOT be rotated, because it was created by the recovery for this caller and has no earlier holder. The documentation SHALL state this. The security policies SHALL then decide on the next request what the session owes, such as an MFA challenge or an enrolment. A failure of the consumer's function SHALL leave the session recovery-pending.

#### Scenario: Password route
- **WHEN** a recovery-pending session resolves a password change successfully, and then requests `/invoices`
- **THEN** the request reaches the handler, provided no policy challenges it

#### Scenario: Password route for a required user
- **WHEN** the same happens for a user required to use MFA with no usable enrolment, and the enrolment path is on
- **THEN** the next request is refused with an enrolment challenge

#### Scenario: Function fails
- **WHEN** the consumer's function fails for a recovery-pending session
- **THEN** its error is the refusal and the session stays recovery-pending

### Requirement: Recovery endpoints plug into the chain
Enabling recovery on the chain SHALL register the endpoints the `account-recovery` capability defines, each answering POST on its own path, except the code listing, which also answers GET:
- start: `/recovery/start`, only when issued codes are enabled;
- complete: `/recovery/complete`;
- finish: `/recovery/finish` and cancel: `/recovery/cancel`, only when a hold is configured;
- saved codes: `/recovery/codes`, only when saved codes are enabled.

Each path SHALL be replaceable by an option. The start and complete endpoints SHALL be guarded by the chain's source throttle step, each under a flow of its own, using the chain's client address, refusal rules and sampled logs, so an unattributable address is refused as for every throttled flow. Flushing the chain's refusal logs SHALL flush the recovery endpoints' samplers too. When a hold is configured, the chain's login completion step SHALL cancel the user's held recovery after the first factor succeeds and before the session is created, and a failure to cancel SHALL refuse the login.

#### Scenario: Consumer path
- **WHEN** the complete path is set to `/account/recover` and two valid proofs are posted there
- **THEN** the recovery succeeds

#### Scenario: Unattributable source
- **WHEN** a recovery is posted from client address `0.0.0.0`
- **THEN** it is refused with the authentication failure error and no proof is checked

#### Scenario: Magic-link login cancels a held recovery
- **WHEN** a recovery of `u-1` is held and `u-1` then signs in by magic link
- **THEN** the held recovery is cancelled

### Requirement: The cool-down guard runs after authentication
When the recovery cool-down is enabled, the chain SHALL register its guard after bearer authentication, so it sees the session's user. It SHALL act only on the requests the consumer marked, each marked by method and exact path. It SHALL let requests without a session through for later interceptors to decide.

#### Scenario: Unauthenticated marked request
- **WHEN** a request without a session posts to a marked route
- **THEN** the cool-down guard does not refuse it, and authorization decides

### Requirement: The login completion step records a second factor met at the first factor
The login completion step SHALL accept, as an input, the library's proof that the login's second factor was met at its first factor, and SHALL hand it to the post-authentication policy phase. When the proof holds, the step SHALL create the session in the satisfied second-factor state with the met-by-first-factor marker, in the write that creates the session, as the `sessions` capability defines. A challenge the phase still raises, such as a password change, SHALL be marked and refused as for any login. When the proof does not hold, the step SHALL behave exactly as before. Only the library's passkey login SHALL supply a proof that holds.

#### Scenario: Satisfied at creation
- **WHEN** the passkey login hands the login completion step a user-verified login of a required user enrolled on nothing else
- **THEN** the session is created satisfied and marked as met by the first factor, and its token is returned without a challenge

#### Scenario: Other challenges still apply
- **WHEN** the same login is for a user whose password is older than the password-age policy allows
- **THEN** the login is refused with a password-change challenge carrying a session that is satisfied and owes the password change

### Requirement: Passkey endpoints plug into the chain
Enabling passkeys on the chain SHALL register the endpoints the `passkey-authentication` capability defines. The registration, saved-code confirm, emailed-code confirm, listing, rename and remove endpoints SHALL run after bearer authentication. The recovery gate, the enrolment gate and the MFA challenge gate SHALL decide, as their own requirements state, which sessions reach them. The passwordless begin and finish endpoints, when enabled, SHALL run as a first factor at a named slot of their own, after the one-time link slot and before Basic authentication. They SHALL complete the login through the login completion step, and their begin SHALL be guarded by the chain's source throttle step under the flow `passkey-login`. Flushing the chain's refusal logs SHALL flush the passkey samplers too. The passkey MFA method SHALL be served by the MFA slot like any other challenge method, with no endpoint of its own.

#### Scenario: Passwordless login reaches login completion
- **WHEN** a passwordless finish authenticates `u-1` and the policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Unattributable source at passwordless begin
- **WHEN** a passwordless begin is posted from client address `0.0.0.0`
- **THEN** it is refused with the authentication failure error and no challenge is issued

#### Scenario: Registration needs bearer
- **WHEN** a request without a bearer credential posts to `/passkey/register/begin`
- **THEN** it is refused as authentication required

### Requirement: The login completion step carries federated assurance evidence
The login completion step SHALL accept the asserted `amr` and `acr` of a federated login, hand them to the post-authentication policy phase as library-minted federated assurance evidence, and record them on the session in the write that creates it. Per-request evaluation SHALL hand a federated session's stored assurance to the policies as the same evidence. The step SHALL NOT mark the second factor satisfied on that evidence. Only the library's OIDC redemption SHALL supply the values to the step.

#### Scenario: Evidence reaches policy at login
- **WHEN** an OIDC redemption hands the step a login asserting `amr` `["mfa"]` for a required user enrolled on nothing
- **THEN** the session is created with `amr` `["mfa"]` and second-factor state none, and its token is returned without a challenge

#### Scenario: Evidence reaches policy per request
- **WHEN** a request presents the token of a federated session holding `amr` `["mfa"]`, for a required user, while the provider accepts `mfa`
- **THEN** the request reaches the handler

### Requirement: Chain-level rate-limit settings reach every guard the chain builds
A rate-limiter factory configured on the chain SHALL be used for every limiter the chain builds, including those of the second-factor, enrolment, recovery and passkey components it constructs, unless that flow was given its own limiter. An IPv6 source prefix configured on the chain SHALL be used by every source guard the chain builds. With neither configured, every flow SHALL keep its in-memory default and the /64 prefix. The chain's IPv6 aggregate setting SHALL likewise be used by every source guard the chain builds.

#### Scenario: Chain prefix groups a wider allocation
- **WHEN** a chain configured with a 48-bit IPv6 prefix throttles a source from `2001:db8:1:1::1` on the API-key flow, and a request arrives from `2001:db8:1:2::1`
- **THEN** the second request is refused as throttled

#### Scenario: Chain factory reaches a flow
- **WHEN** a chain configured with a consumer's factory refuses a wrong API key
- **THEN** the failure is recorded through a limiter the factory built for the API-key flow

#### Scenario: Default prefix
- **WHEN** a chain with no prefix configured throttles `2001:db8:1:1::1` and a request arrives from `2001:db8:1:2::1`
- **THEN** the second request is not throttled

### Requirement: Chain source guards count an IPv6 aggregate by default
Every source guard the chain builds SHALL also count IPv6 sources by an aggregate prefix of /56, with a limit four times the flow's limit, over the flow's window, in a limiter of its own. A consumer SHALL be able to set the aggregate prefix and multiplier, or turn the aggregate off. When the source prefix is already /56 or wider and the aggregate was not set explicitly, the default aggregate SHALL be skipped. For a flow given its own limiter, the aggregate SHALL use that limiter's reported limit and window; when it reports none, the default aggregate SHALL be skipped for that flow with one warning at construction.

#### Scenario: Default aggregate
- **WHEN** a chain with default settings records 80 failed API-key attempts, 20 from each of `2001:db8:1:1::1`, `2001:db8:1:2::1`, `2001:db8:1:3::1` and `2001:db8:1:4::1`, and an attempt arrives from `2001:db8:1:5::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Consumer aggregate
- **WHEN** a chain configured with a /48 aggregate and a multiplier of 2 records 40 failed API-key attempts, 20 from each of `2001:db8:1:1::1` and `2001:db8:1:200::1`, and an attempt arrives from `2001:db8:1:300::1`
- **THEN** the attempt is refused as throttled

#### Scenario: Aggregate turned off
- **WHEN** a chain with the aggregate turned off records 80 failed API-key attempts from four /64s in one /56, and an attempt arrives from a fifth /64 in it
- **THEN** the attempt is not throttled

#### Scenario: Wide source prefix skips the default aggregate
- **WHEN** a chain is configured with a 48-bit IPv6 source prefix and no aggregate setting
- **THEN** construction succeeds and its guards count no aggregate

#### Scenario: Aggregate follows a consumer limiter
- **WHEN** a chain with default settings gives the API-key flow its own limiter allowing 200 failures per minute, and 200 failed API-key attempts arrive from one /64
- **THEN** none of them is throttled by the aggregate, whose limit is 800 per minute

#### Scenario: Consumer limiter that reports no policy
- **WHEN** a chain with default settings gives the API-key flow its own limiter that does not report its limit and window
- **THEN** construction succeeds, the API-key guard counts no aggregate, and one warning names the flow

### Requirement: Contradictory aggregate settings fail at construction
Building a chain SHALL fail with a configuration error, naming the aggregate option for a contradictory setting and the flow for a flow limiter's policy, when an explicitly set aggregate prefix is not wider than the chain's source prefix, is outside 1 to 127, or has a multiplier below 1, when the aggregate is both set and turned off, when an explicitly set aggregate applies to a flow whose own limiter reports no limit and window, when a flow's own limiter reports a limit below 1 or a window of zero or less, and when an aggregate's limit, the multiplier times the flow's limit, does not fit in an int.

#### Scenario: Aggregate no wider than the source
- **WHEN** a chain is configured with a 48-bit IPv6 source prefix and an explicit /56 aggregate
- **THEN** construction fails with an error naming the aggregate option

#### Scenario: Zero multiplier
- **WHEN** a chain is configured with an aggregate multiplier of 0
- **THEN** construction fails with an error naming the aggregate option

#### Scenario: Explicit aggregate over a limiter that reports no policy
- **WHEN** a chain configured with an explicit /48 aggregate gives the API-key flow its own limiter that does not report its limit and window
- **THEN** construction fails with an error naming the aggregate option and the API-key flow

#### Scenario: Consumer limiter reports an unusable policy
- **WHEN** a chain with default settings gives the API-key flow its own limiter that reports a limit of 0 and a window of 0
- **THEN** construction fails with an error naming the API-key flow, without asking the factory for an aggregate limiter

#### Scenario: Consumer limit too large for the default aggregate
- **WHEN** a chain with default settings gives the API-key flow its own limiter whose limit times 4 does not fit in an int
- **THEN** construction fails with an error naming the API-key flow and pointing to the options that turn the aggregate off or set it

### Requirement: Password login is throttled per source
Form login and Basic authentication SHALL share one source guard for the flow `password-login`, checked before the pre-authentication phase. By default its limiter SHALL come from the chain's limiter factory under namespace `password-login`, with a limit of 50 failures per 15 minutes. Authentication failures and account-locked refusals SHALL count against the source, and successes SHALL NOT. A consumer SHALL be able to give either endpoint its own limiter.

#### Scenario: Spraying one password across accounts
- **WHEN** one source posts a wrong password for 50 different usernames within 15 minutes and then posts for a 51st
- **THEN** the 51st request is refused as throttled, without the pre-authentication phase or the password being evaluated

#### Scenario: Form and Basic share the allowance
- **WHEN** one source fails 30 form logins and then 20 Basic authentications within 15 minutes, and makes one more form login
- **THEN** the form login is refused as throttled

#### Scenario: Successes spend nothing
- **WHEN** one source makes 100 successful form logins and 49 failed ones within 15 minutes, and then makes one more failed login
- **THEN** that request is not throttled

#### Scenario: Locked refusals count
- **WHEN** one source makes 50 form logins for a locked account within 15 minutes and then logs in as another user
- **THEN** that request is refused as throttled

#### Scenario: Consumer limiter
- **WHEN** form login is given its own limiter with a limit of 10
- **THEN** the eleventh failed login from one source within the limiter's window is refused as throttled, and Basic authentication keeps the default limiter

#### Scenario: Factory namespace
- **WHEN** a chain with a consumer's factory enables form login and Basic authentication
- **THEN** the factory is asked once for namespace `password-login`, with a limit of 50 and a window of 15 minutes

#### Scenario: Own limiter under a shared factory
- **WHEN** a chain with a shared limiter factory that refuses one namespace with two policies enables form login with its own limiter of 10 per minute and Basic with the default
- **THEN** construction succeeds, and form login's guard and IPv6 aggregate share no bucket with Basic's

#### Scenario: Unattributable source
- **WHEN** a form login arrives with no client address
- **THEN** it is refused as unattributable without the password being evaluated

### Requirement: A locked account's login refusal looks like a wrong password by default
When the pre-authentication phase denies with the account-locked refusal, form login and Basic authentication SHALL, by default, refuse with an error identifiable as both the authentication failure and the account-locked refusal, so the status mapping answers 401. Before refusing they SHALL spend the authenticator's decoy verification on the presented password. Basic SHALL set its challenge header. A consumer SHALL be able to opt in to disclosing the lock, which refuses with the account-locked refusal alone, answered 429, without the decoy and, for Basic, without the challenge header.

#### Scenario: Default response
- **WHEN** a form login for a locked account arrives and the consumer's error handling writes only the mapped status
- **THEN** the response is 401, as for a wrong password

#### Scenario: Equal password work
- **WHEN** a form login for a locked account arrives through an authenticator built on the password provider
- **THEN** one decoy verification is performed and the account's own password hash is not verified

#### Scenario: Disclosure chosen
- **WHEN** the chain is configured to disclose locks and a form login for a locked account arrives
- **THEN** the response is 429 and no decoy verification is performed

#### Scenario: Disclosed Basic lock
- **WHEN** the chain is configured to disclose locks and a Basic request for a locked account arrives
- **THEN** the response is 429 and carries no `WWW-Authenticate` header

#### Scenario: Authenticator without a decoy
- **WHEN** a chain enables form login with an authenticator that offers no decoy verification, or with a manager none of whose providers offers one, and locks are not disclosed
- **THEN** construction writes one warning that lock refusals may be told apart by their timing

### Requirement: Login failures are counted even when the client disconnects
Form login and Basic authentication SHALL record a failed attempt, and the source guard's failure, on a context from which the request's cancellation has been removed.

#### Scenario: Client disconnects after a wrong password
- **WHEN** a form login with a wrong password is refused and the request's context is cancelled before the attempt is recorded
- **THEN** the attempt store receives the failure on a context that is not cancelled

### Requirement: The chain reads time from one replaceable time source
The chain SHALL offer a time-source option, and SHALL use the system clock when none is configured. Every time the chain's built-in interceptors record, and every time check they make, SHALL come from that source. Every time-keeping component the chain builds for itself SHALL read the same source: the second-factor challenge state and its default store, the second-factor verification throttle, the source guards and the limiters the chain's default factory builds, and the account-recovery core. A dependency the consumer builds and hands to the chain SHALL keep its own time source, including a recovery core given its own time source. An absent time source, including a typed-nil one, SHALL fail construction.

#### Scenario: System clock by default
- **WHEN** a chain is built with no time-source option and a second-factor challenge is begun
- **THEN** the challenge's expiry is measured from the system time at begin

#### Scenario: Consumer time source drives the chain's own state
- **WHEN** a consumer configures the chain with a controlled time source, a signed-in user begins a second-factor challenge, and the source advances past the challenge's lifetime
- **THEN** answering the challenge is refused as expired, with no real waiting
- **AND** after the source also passes the challenge's issuance window, the chain's expiry task for that method removes the challenge

#### Scenario: A throttle window follows the chain's source
- **WHEN** a chain with a controlled time source and the default limiter factory refuses a source for exceeding its password-login failures, and the source advances past the window
- **THEN** a login from that source is no longer refused for throttling, with no real waiting

#### Scenario: The second-factor verification throttle follows the chain's source
- **WHEN** a chain with a controlled time source and no limiter of the consumer's for second-factor verification throttles a user after too many wrong codes, and the source advances past the throttle's window
- **THEN** the user may answer again, with no real waiting

#### Scenario: A consumer's dependency keeps its own source
- **WHEN** the chain has one controlled time source and the consumer's recovery core is given a different one
- **THEN** the recovery core's codes and holds expire on the recovery core's own source

#### Scenario: Absent time source
- **WHEN** the chain's time-source option is given a nil or typed-nil source
- **THEN** construction fails with a configuration error naming the option
