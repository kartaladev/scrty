## MODIFIED Requirements

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

### Requirement: Redemption flows plug into named seams
The chain SHALL provide the seams that interceptors from other capabilities use, without those interceptors being part of this capability:
- named slots for federated login, one-time link redemption, API keys, client certificates and second-factor challenges;
- a login completion step;
- a source throttle step.

The login completion step SHALL be the one form login uses. It SHALL require the principal, first factor, submitted username and password change time as inputs, and SHALL accept additional session attributes that its caller wants recorded in the write that creates the session, such as a federated login's provider session. It SHALL behave identically for every first factor that uses it:
1. evaluate the post-authentication phase;
2. on a deny, refuse with the policy's reason;
3. create the session with its first factor and the caller's additional attributes, in one write;
4. mark and save any pending challenge before issuing the token;
5. publish the authentication onto the request context;
6. refuse with a challenge error when a challenge is pending.

The source throttle step SHALL expose the check before guarded work and the failure recording after it, using the chain's client address, refusal rules and sampled logs.

#### Scenario: Another first factor reuses login completion
- **WHEN** a redemption interceptor added by another capability authenticates a user and hands the principal to the login completion step, and policy requires a password change
- **THEN** the request is refused with a password-change challenge error carrying a pending session, exactly as form login would refuse it

#### Scenario: Federated attributes land in the creating write
- **WHEN** a federated login hands the login completion step a principal together with its provider, issuer and provider session id
- **THEN** the created session records them from its first write
- **AND** no later save of the session was needed to record them

#### Scenario: Plugin slot order
- **WHEN** an interceptor is registered at the one-time link slot
- **THEN** it runs after form login and before Basic authentication
