## Purpose

Puts scrty's authentication, session, policy and authorization decisions in front of an HTTP handler as one ordered, extensible interceptor chain that fails closed, reports wiring mistakes before traffic, and hands the handler everything it resolved.

## ADDED Requirements

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
- an absent rate limiter;
- an absent refusal log reporter;
- a login body limit of zero or less.

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
2. evaluate the pre-authentication policy phase before checking credentials, and refuse on a deny;
3. authenticate, recording a failed attempt on an authentication failure and clearing attempts on success, where a failure of that bookkeeping is logged and does not change the outcome;
4. evaluate the post-authentication policy phase, and refuse on a deny;
5. create a session recording the password first factor;
6. when the post-authentication phase challenged, mark the challenge pending and save the session before issuing a token;
7. issue an access token.

A challenge SHALL refuse with a challenge error carrying the kind, the pending session and the token. A success SHALL write the success response and SHALL NOT call the handler. By default the success response is a JSON document carrying the access token, an empty refresh token field and the session's idle expiry. The consumer SHALL be able to replace the success response writer, the login path and the field names.

#### Scenario: Successful login
- **WHEN** a user with no pending challenge posts correct credentials to the login path
- **THEN** a session is created, the response is a JSON document carrying an access token and the session's idle expiry, and the handler is not called

#### Scenario: Wrong password
- **WHEN** a user posts an incorrect password
- **THEN** the request is refused with the authentication failure error and a failed attempt is recorded

#### Scenario: Locked account is not probed
- **WHEN** the pre-authentication phase denies a locked account
- **THEN** the request is refused with the lockout reason and the password is never checked

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
2. evaluate the pre-authentication phase before checking credentials;
3. on a failed authentication, record a failed attempt, set a `WWW-Authenticate` Basic challenge header naming the realm (default `Restricted`), and refuse with the authentication failure error;
4. on success, evaluate the stateless-authentication policy phase, and continue with the principal in the context.

It SHALL NOT create a session or issue a token. A challenge from the stateless-authentication phase SHALL refuse with a challenge error carrying no session and no token. The consumer SHALL be able to set the realm.

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

### Requirement: Bearer tokens authenticate against a live session and a live user
When enabled, bearer token authentication SHALL handle requests whose `Authorization` header uses the configured scheme, `Bearer` by default, matched without regard to case. When the consumer opts in, it SHALL also accept a bare token with no scheme. Other requests SHALL pass through unchanged.

For each handled request it SHALL:
1. verify the token, refusing a failure with the authentication failure error and keeping the cause available for logging;
2. load the session the token names, refusing with the authentication-required error when the session is missing, expired or cannot be decrypted;
3. reload the user the token names, so roles are current, refusing with the authentication-required error when the user no longer exists;
4. add the principal, authentication result and session to the context;
5. evaluate the per-request policy phase.

An undecryptable session SHALL also be logged at ERROR. A deny from the per-request phase SHALL refuse. A challenge from it SHALL mark the challenge pending on the session and continue, so the gate for that challenge enforces it.

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

### Requirement: A pending password change blocks requests until resolved
When the password-change gate is enabled, every request that reaches it whose session carries a pending password-change challenge SHALL be refused. The refusal SHALL be a password-change challenge error carrying the session, and the handler SHALL NOT run. The consumer SHALL be able to register a resolve endpoint: a POST path together with the consumer's own function that performs the change. Requests to that endpoint SHALL pass the gate, and SHALL follow these rules:
- **No session:** a request without a session SHALL be refused with the authentication-required error.
- **Consumer function fails:** its error SHALL be the refusal.
- **Consumer function succeeds:** the pending marker SHALL be cleared and the session saved, and the consumer's function owns the response.

Without a resolve endpoint, only a new login clears the challenge.

#### Scenario: Pending password change
- **WHEN** a request carries a token for a session with a pending password-change challenge
- **THEN** it is refused with a password-change challenge error and the handler is not called

#### Scenario: Consumer resolve endpoint
- **WHEN** the consumer registers `POST /account/password` with a function that changes the password successfully, and a session with the pending challenge calls it
- **THEN** the consumer's function runs, the marker is cleared and saved, and the next request on that session passes the gate

#### Scenario: Resolve without a session
- **WHEN** an unauthenticated request posts to the resolve endpoint
- **THEN** it is refused with the authentication-required error and the consumer's function does not run

### Requirement: Logout ends the session
When enabled, logout SHALL answer POST requests on its path, by default `/logout`. It SHALL refuse a request with no authentication result with the authentication-required error. When the request carries a session, logout SHALL delete it, and a session that is already gone SHALL NOT be an error. A stateless authenticated request SHALL be answered without deleting anything. Logout SHALL answer 200 with an empty body and SHALL NOT call the handler. The consumer SHALL be able to change the path.

#### Scenario: Logout
- **WHEN** an authenticated request posts to the logout path
- **THEN** its session is deleted, the response is 200, and a later request with the same token is refused

#### Scenario: Session already deleted
- **WHEN** two logout requests for the same session race and the second finds the session gone
- **THEN** the second is also answered 200

#### Scenario: Anonymous logout
- **WHEN** a request with no authentication posts to the logout path
- **THEN** it is refused with the authentication-required error

#### Scenario: Consumer path
- **WHEN** the consumer sets the logout path to `/session/end`
- **THEN** logout answers there and a POST to `/logout` passes through

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
- the flow and source for the throttled-source warning;
- the flow alone for a limiter failure;
- the flow and reason for an unattributable address.

A written record SHALL carry the count suppressed before it when that count is non-zero. The sampler SHALL always have a reporter. By default the reporter writes one summary record naming the key and the suppressed count. The consumer SHALL be able to:
- change the interval, with zero or less disabling sampling;
- replace the reporter;
- flush pending counts, for example at shutdown.

The interval SHALL govern only the chain's own records. It SHALL NOT change which requests are refused, or how any other component samples its logs. A request that ended before the rate-limit check SHALL be logged at DEBUG, unsampled.

#### Scenario: Flood from one source
- **WHEN** one source is throttled 50 times within a minute
- **THEN** one warning is written for that source in that window

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

### Requirement: Redemption flows plug into named seams
The chain SHALL provide the seams that interceptors from other capabilities use, without those interceptors being part of this capability:
- named slots for federated login, one-time link redemption, API keys, client certificates and second-factor challenges;
- a login completion step;
- a source throttle step.

The login completion step SHALL be the one form login uses. It SHALL require the principal, first factor, submitted username and password change time as inputs, and SHALL behave identically for every first factor that uses it:
1. evaluate the post-authentication phase;
2. on a deny, refuse with the policy's reason;
3. create the session with its first factor;
4. mark and save any pending challenge before issuing the token;
5. publish the authentication onto the request context;
6. refuse with a challenge error when a challenge is pending.

The source throttle step SHALL expose the check before guarded work and the failure recording after it, using the chain's client address, refusal rules and sampled logs.

#### Scenario: Another first factor reuses login completion
- **WHEN** a redemption interceptor added by another capability authenticates a user and hands the principal to the login completion step, and policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Plugin slot order
- **WHEN** an interceptor is registered at the one-time link slot
- **THEN** it runs after form login and before Basic authentication
